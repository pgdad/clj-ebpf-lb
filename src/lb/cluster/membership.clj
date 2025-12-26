(ns lb.cluster.membership
  "SWIM-style cluster membership management.

   Implements failure detection using:
   - Direct ping probes
   - Indirect ping-req through other members
   - Suspicion mechanism with timeout before declaring dead

   References:
   - SWIM: Scalable Weakly-consistent Infection-style Process Group Membership Protocol
   - Serf/Memberlist (HashiCorp) for practical implementation patterns"
  (:require [lb.cluster.protocol :as proto]
            [clojure.set :as set]
            [clojure.tools.logging :as log])
  (:import [java.util.concurrent Executors ScheduledExecutorService TimeUnit
            ConcurrentHashMap]))

;;; =============================================================================
;;; Membership State
;;; =============================================================================

(def ^:private membership-state
  "Cluster membership state.

   :node-id       - This node's unique identifier
   :local-node    - NodeInfo for this node
   :nodes         - Map of node-id -> NodeInfo (all known nodes)
   :alive         - Set of alive node IDs
   :suspected     - Map of node-id -> {:since timestamp :incarnation n}
   :dead          - Set of confirmed dead node IDs
   :incarnation   - This node's incarnation number
   :subscribers   - Vector of event callback functions
   :running?      - Whether membership is active"
  (atom {:node-id nil
         :local-node nil
         :nodes {}
         :alive #{}
         :suspected {}
         :dead #{}
         :incarnation 0
         :subscribers []
         :running? false}))

;;; =============================================================================
;;; Configuration
;;; =============================================================================

(def default-config
  "Default membership configuration."
  {:ping-interval-ms 1000       ; How often to ping random peer
   :ping-timeout-ms 500         ; How long to wait for ping response
   :ping-req-count 3            ; Number of peers for indirect ping
   :suspicion-mult 3            ; suspicion-timeout = suspicion-mult * ping-interval
   :dead-node-reclaim-ms 86400000}) ; 24h before dead node can rejoin with same ID

(defonce ^:private config (atom default-config))

(defn configure!
  "Update membership configuration."
  [new-config]
  (swap! config merge new-config))

;;; =============================================================================
;;; Event System
;;; =============================================================================

(defn subscribe!
  "Subscribe to membership events. Returns unsubscribe function."
  [callback]
  (swap! membership-state update :subscribers conj callback)
  (fn []
    (swap! membership-state update :subscribers
           (fn [subs] (filterv #(not= % callback) subs)))))

(defn- notify-subscribers!
  "Notify all subscribers of an event."
  [event]
  (doseq [callback (:subscribers @membership-state)]
    (try
      (callback event)
      (catch Exception e
        (log/error e "Error in membership event subscriber")))))

(defn- emit-event!
  "Create and emit a cluster event."
  [event-type node-id data]
  (let [event (proto/make-event event-type node-id data)]
    (log/debug "Membership event:" event-type "node:" node-id)
    (notify-subscribers! event)
    event))

;;; =============================================================================
;;; Node State Transitions
;;; =============================================================================

(defn- add-node!
  "Add a new node to the cluster."
  [node-info]
  (let [node-id (:node-id node-info)]
    (swap! membership-state
           (fn [state]
             (-> state
                 (assoc-in [:nodes node-id] node-info)
                 (update :alive conj node-id)
                 (update :suspected dissoc node-id)
                 (update :dead disj node-id))))
    (emit-event! :node-join node-id {:node-info node-info})
    node-info))

(defn- remove-node!
  "Remove a node from the cluster (graceful leave)."
  [node-id]
  (swap! membership-state
         (fn [state]
           (-> state
               (update :nodes dissoc node-id)
               (update :alive disj node-id)
               (update :suspected dissoc node-id)
               (update :dead disj node-id))))
  (emit-event! :node-leave node-id {}))

(defn- suspect-node!
  "Mark a node as suspected (may have failed)."
  [node-id incarnation]
  (let [now (System/currentTimeMillis)]
    (swap! membership-state
           (fn [state]
             (if (contains? (:alive state) node-id)
               (-> state
                   (update :alive disj node-id)
                   (assoc-in [:suspected node-id] {:since now :incarnation incarnation}))
               state)))
    (emit-event! :node-suspect node-id {:incarnation incarnation})))

(defn- confirm-alive!
  "Confirm a node is alive (refutes suspicion)."
  [node-id incarnation]
  (swap! membership-state
         (fn [state]
           (let [current-incarnation (get-in state [:nodes node-id :incarnation] 0)]
             (if (>= incarnation current-incarnation)
               (-> state
                   (update :alive conj node-id)
                   (update :suspected dissoc node-id)
                   (update :dead disj node-id)
                   (assoc-in [:nodes node-id :incarnation] incarnation)
                   (assoc-in [:nodes node-id :last-seen] (System/currentTimeMillis)))
               state))))
  (emit-event! :node-alive node-id {:incarnation incarnation}))

(defn- declare-dead!
  "Declare a node as dead (confirmed failure)."
  [node-id]
  (swap! membership-state
         (fn [state]
           (-> state
               (update :alive disj node-id)
               (update :suspected dissoc node-id)
               (update :dead conj node-id))))
  (emit-event! :node-dead node-id {}))

;;; =============================================================================
;;; Ping State Tracking
;;; =============================================================================

;; Track pending ping requests: seq-num -> {:target node-id :sent-at ms :indirect? bool}
(defonce ^:private pending-pings (ConcurrentHashMap.))

(defonce ^:private ping-seq (atom 0))

(defn- next-ping-seq
  "Get next ping sequence number."
  []
  (swap! ping-seq inc))

(defn- register-ping!
  "Register a pending ping."
  [seq-num target indirect?]
  (.put pending-pings seq-num
        {:target target :sent-at (System/currentTimeMillis) :indirect? indirect?}))

(defn- complete-ping!
  "Complete a pending ping, returns the ping info or nil."
  [seq-num]
  (.remove pending-pings seq-num))

(defn- get-pending-ping
  "Get a pending ping by sequence number."
  [seq-num]
  (.get pending-pings seq-num))

;;; =============================================================================
;;; SWIM Failure Detection
;;; =============================================================================

(defn- pick-random-peer
  "Pick a random alive peer (not self)."
  []
  (let [state @membership-state
        self (:node-id state)
        peers (disj (:alive state) self)]
    (when (seq peers)
      (rand-nth (vec peers)))))

(defn- pick-random-peers
  "Pick n random alive peers (not self, not excluded)."
  [n excluded]
  (let [state @membership-state
        self (:node-id state)
        peers (-> (:alive state)
                  (disj self)
                  (set/difference excluded))]
    (when (seq peers)
      (take n (shuffle (vec peers))))))

(defn- suspicion-timeout-ms
  "Calculate suspicion timeout."
  []
  (* (:suspicion-mult @config) (:ping-interval-ms @config)))

(defn- check-suspected-nodes!
  "Check if any suspected nodes should be declared dead."
  []
  (let [now (System/currentTimeMillis)
        timeout (suspicion-timeout-ms)
        state @membership-state]
    (doseq [[node-id {:keys [since]}] (:suspected state)]
      (when (> (- now since) timeout)
        (log/info "Node" node-id "confirmed dead after suspicion timeout")
        (declare-dead! node-id)))))

;;; =============================================================================
;;; Message Handlers (called by gossip layer)
;;; =============================================================================

(defn handle-ping!
  "Handle incoming ping message. Returns ping-ack message."
  [{:keys [sender payload]}]
  (let [state @membership-state]
    (when (:running? state)
      (confirm-alive! sender (get-in state [:nodes sender :incarnation] 0))
      (proto/ping-ack-message (:node-id state) sender (:seq payload)))))

(defn handle-ping-ack!
  "Handle incoming ping acknowledgment."
  [{:keys [sender payload]}]
  (let [seq-num (:seq payload)]
    (when-let [ping-info (complete-ping! seq-num)]
      (let [target (:target ping-info)]
        (confirm-alive! target
                        (get-in @membership-state [:nodes target :incarnation] 0))))))

(defn handle-ping-req!
  "Handle indirect ping request. Ping the target on behalf of requester."
  [{:keys [sender payload]} send-fn]
  (let [{:keys [target seq]} payload
        state @membership-state]
    (when (:running? state)
      (when-let [target-info (get-in state [:nodes target])]
        ;; Send ping to target, forward ack back to original sender
        (let [our-seq (next-ping-seq)]
          (register-ping! our-seq target true)
          (send-fn (:address target-info)
                   (proto/ping-message (:node-id state) target our-seq)))))))

(defn handle-join!
  "Handle node join message."
  [{:keys [sender payload]}]
  (let [{:keys [node-info]} payload]
    (when node-info
      (log/info "Node joining cluster:" sender)
      (add-node! node-info))))

(defn handle-leave!
  "Handle graceful node leave."
  [{:keys [sender]}]
  (log/info "Node leaving cluster:" sender)
  (remove-node! sender))

(defn handle-suspect!
  "Handle suspicion message about a node."
  [{:keys [payload]}]
  (let [{:keys [suspect incarnation]} payload
        state @membership-state]
    (when (and (not= suspect (:node-id state))
               (contains? (:alive state) suspect))
      (let [current-incarnation (get-in state [:nodes suspect :incarnation] 0)]
        (when (>= incarnation current-incarnation)
          (suspect-node! suspect incarnation))))))

(defn handle-alive!
  "Handle alive message (refutes suspicion)."
  [{:keys [sender payload]}]
  (let [{:keys [incarnation]} payload]
    (confirm-alive! sender incarnation)))

(defn handle-message!
  "Route a membership-related message to the appropriate handler."
  [msg send-fn]
  (case (:msg-type msg)
    :ping (handle-ping! msg)
    :ping-ack (handle-ping-ack! msg)
    :ping-req (handle-ping-req! msg send-fn)
    :join (handle-join! msg)
    :leave (handle-leave! msg)
    :suspect (handle-suspect! msg)
    :alive (handle-alive! msg)
    nil))

;;; =============================================================================
;;; Periodic Tasks
;;; =============================================================================

(defonce ^:private executor (atom nil))

(defn- probe-node!
  "Probe a single node with ping, falling back to indirect ping on timeout."
  [target send-fn]
  (let [state @membership-state
        target-info (get-in state [:nodes target])]
    (when target-info
      (let [seq-num (next-ping-seq)]
        (register-ping! seq-num target false)
        (send-fn (:address target-info)
                 (proto/ping-message (:node-id state) target seq-num))
        ;; Schedule timeout check
        (future
          (Thread/sleep (:ping-timeout-ms @config))
          (when-let [pending (get-pending-ping seq-num)]
            ;; Direct ping timed out, try indirect
            (let [intermediaries (pick-random-peers (:ping-req-count @config) #{target})]
              (if (seq intermediaries)
                (do
                  (log/debug "Direct ping to" target "timed out, trying indirect via" intermediaries)
                  (doseq [intermediary intermediaries]
                    (when-let [int-info (get-in @membership-state [:nodes intermediary])]
                      (send-fn (:address int-info)
                               (proto/ping-req-message (:node-id state) intermediary target seq-num)))))
                ;; No intermediaries available, suspect immediately
                (do
                  (complete-ping! seq-num)
                  (log/warn "No intermediaries available, suspecting" target)
                  (suspect-node! target (get-in @membership-state [:nodes target :incarnation] 0)))))))))))

(defn- failure-detection-tick!
  "One tick of the failure detection loop."
  [send-fn]
  (try
    (when (:running? @membership-state)
      ;; Check if any suspected nodes should be declared dead
      (check-suspected-nodes!)
      ;; Probe a random peer
      (when-let [target (pick-random-peer)]
        (probe-node! target send-fn)))
    (catch Exception e
      (log/error e "Error in failure detection tick"))))

(defn start-failure-detector!
  "Start the background failure detection loop."
  [send-fn]
  (when-not @executor
    (let [exec (Executors/newSingleThreadScheduledExecutor)]
      (reset! executor exec)
      (.scheduleAtFixedRate exec
                            #(failure-detection-tick! send-fn)
                            (:ping-interval-ms @config)
                            (:ping-interval-ms @config)
                            TimeUnit/MILLISECONDS)
      (log/info "Failure detector started with interval" (:ping-interval-ms @config) "ms"))))

(defn stop-failure-detector!
  "Stop the failure detection loop."
  []
  (when-let [exec @executor]
    (.shutdown exec)
    (reset! executor nil)
    (log/info "Failure detector stopped")))

;;; =============================================================================
;;; Public API
;;; =============================================================================

(defn init!
  "Initialize membership with this node's info."
  [node-id address & {:keys [metadata] :or {metadata {}}}]
  (let [local-node (proto/make-node-info node-id address metadata)]
    (reset! membership-state
            {:node-id node-id
             :local-node local-node
             :nodes {node-id local-node}
             :alive #{node-id}
             :suspected {}
             :dead #{}
             :incarnation 0
             :subscribers []
             :running? true})
    (log/info "Membership initialized for node" node-id "at" address)
    local-node))

(defn shutdown!
  "Shutdown membership and notify peers of graceful leave."
  [send-fn]
  (let [state @membership-state]
    (when (:running? state)
      ;; Send leave message to all alive peers
      (let [leave-msg (proto/leave-message (:node-id state))]
        (doseq [peer-id (disj (:alive state) (:node-id state))]
          (when-let [peer-info (get-in state [:nodes peer-id])]
            (try
              (send-fn (:address peer-info) leave-msg)
              (catch Exception e
                (log/debug "Failed to send leave to" peer-id))))))
      (stop-failure-detector!)
      (swap! membership-state assoc :running? false)
      (log/info "Membership shutdown complete"))))

(defn join-cluster!
  "Join a cluster by contacting seed nodes."
  [seeds send-fn]
  (let [state @membership-state
        join-msg (proto/join-message (:node-id state) (:local-node state))]
    (log/info "Joining cluster via seeds:" seeds)
    (doseq [seed seeds]
      (try
        (send-fn seed join-msg)
        (catch Exception e
          (log/warn "Failed to contact seed" seed ":" (.getMessage e)))))
    ;; Start failure detection after attempting to join
    (start-failure-detector! send-fn)))

(defn get-node-id
  "Get this node's ID."
  []
  (:node-id @membership-state))

(defn get-local-node
  "Get this node's info."
  []
  (:local-node @membership-state))

(defn get-alive-nodes
  "Get set of alive node IDs."
  []
  (:alive @membership-state))

(defn get-all-nodes
  "Get map of all known nodes (alive + suspected + dead)."
  []
  (:nodes @membership-state))

(defn get-node-info
  "Get NodeInfo for a specific node."
  [node-id]
  (get-in @membership-state [:nodes node-id]))

(defn is-alive?
  "Check if a node is considered alive."
  [node-id]
  (contains? (:alive @membership-state) node-id))

(defn is-suspected?
  "Check if a node is suspected."
  [node-id]
  (contains? (:suspected @membership-state) node-id))

(defn is-dead?
  "Check if a node is confirmed dead."
  [node-id]
  (contains? (:dead @membership-state) node-id))

(defn refute-suspicion!
  "Refute suspicion about this node by broadcasting alive message with incremented incarnation."
  [send-fn]
  (let [new-incarnation (swap! membership-state
                               (fn [state]
                                 (update state :incarnation inc)))]
    (let [state @membership-state
          alive-msg (proto/alive-message (:node-id state) (:incarnation state))]
      (doseq [peer-id (disj (:alive state) (:node-id state))]
        (when-let [peer-info (get-in state [:nodes peer-id])]
          (send-fn (:address peer-info) alive-msg))))))

(defn cluster-size
  "Get number of alive nodes in the cluster."
  []
  (count (:alive @membership-state)))

(defn membership-stats
  "Get membership statistics."
  []
  (let [state @membership-state]
    {:node-id (:node-id state)
     :alive-count (count (:alive state))
     :suspected-count (count (:suspected state))
     :dead-count (count (:dead state))
     :running? (:running? state)}))
