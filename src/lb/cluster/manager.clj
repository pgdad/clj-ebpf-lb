(ns lb.cluster.manager
  "Cluster manager - orchestrates membership, gossip, and state synchronization.

   This is the internal orchestration layer. Use lb.cluster namespace for the public API."
  (:require [lb.cluster.protocol :as proto]
            [lb.cluster.membership :as membership]
            [lb.cluster.gossip :as gossip]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Manager State
;;; =============================================================================

;; Manager state:
;; :status      - :stopped, :starting, :running, :stopping
;; :config      - Cluster configuration
;; :subscribers - Event subscribers
(defonce ^:private manager-state
  (atom {:status :stopped
         :config nil
         :subscribers []}))

;;; =============================================================================
;;; Configuration
;;; =============================================================================

(def default-cluster-config
  "Default cluster configuration."
  {:enabled false
   :node-id "auto"                    ; "auto" generates UUID-based ID
   :bind-address "0.0.0.0"
   :bind-port 7946
   :seeds []                          ; List of "ip:port" seed nodes

   ;; Gossip tuning
   :gossip-interval-ms 200
   :gossip-fanout 2
   :push-pull-interval-ms 10000
   :max-batch-size 100

   ;; Failure detection
   :ping-interval-ms 1000
   :ping-timeout-ms 500
   :ping-req-count 3
   :suspicion-mult 3

   ;; State sync
   :sync-health true
   :sync-circuit-breaker true
   :sync-drain true
   :sync-conntrack true})

(defn merge-config
  "Merge user config with defaults."
  [user-config]
  (merge default-cluster-config user-config))

;;; =============================================================================
;;; Event Subscription
;;; =============================================================================

(defn subscribe!
  "Subscribe to cluster events. Returns unsubscribe function."
  [callback]
  (swap! manager-state update :subscribers conj callback)
  ;; Also subscribe to membership events
  (let [unsub-membership (membership/subscribe! callback)]
    (fn []
      (swap! manager-state update :subscribers
             (fn [subs] (filterv #(not= % callback) subs)))
      (unsub-membership))))

(defn- notify-subscribers!
  "Notify all subscribers of an event."
  [event]
  (doseq [callback (:subscribers @manager-state)]
    (try
      (callback event)
      (catch Exception e
        (log/error e "Error in cluster event subscriber")))))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start the cluster manager."
  [config]
  (let [cfg (merge-config config)]
    (cond
      ;; Cluster disabled
      (not (:enabled cfg))
      (do
        (log/info "Cluster mode disabled")
        nil)

      ;; Already running
      (= :running (:status @manager-state))
      (do
        (log/warn "Cluster manager already running")
        nil)

      ;; Start the cluster
      :else
      (do
        (swap! manager-state assoc :status :starting :config cfg)
        (log/info "Starting cluster manager...")

        (try
          ;; Configure components
          (membership/configure!
            {:ping-interval-ms (:ping-interval-ms cfg)
             :ping-timeout-ms (:ping-timeout-ms cfg)
             :ping-req-count (:ping-req-count cfg)
             :suspicion-mult (:suspicion-mult cfg)})

          (gossip/configure!
            {:bind-address (:bind-address cfg)
             :bind-port (:bind-port cfg)
             :gossip-interval-ms (:gossip-interval-ms cfg)
             :gossip-fanout (:gossip-fanout cfg)
             :push-pull-interval-ms (:push-pull-interval-ms cfg)
             :max-batch-size (:max-batch-size cfg)})

          ;; Generate node ID if auto
          (let [node-id (if (= "auto" (:node-id cfg))
                          (proto/generate-node-id)
                          (:node-id cfg))
                address (str (:bind-address cfg) ":" (:bind-port cfg))]

            ;; Initialize membership
            (membership/init! node-id address)

            ;; Start gossip transport
            (gossip/start!)

            ;; Join cluster via seeds
            (when (seq (:seeds cfg))
              (membership/join-cluster! (:seeds cfg) gossip/send-message!))

            (swap! manager-state assoc :status :running)
            (log/info "Cluster manager started. Node ID:" node-id)

            ;; Emit started event
            (notify-subscribers! (proto/make-event :cluster-started node-id {:config cfg}))

            {:node-id node-id :address address})

          (catch Exception e
            (log/error e "Failed to start cluster manager")
            (swap! manager-state assoc :status :stopped)
            (throw e)))))))

(defn stop!
  "Stop the cluster manager."
  []
  (when (= :running (:status @manager-state))
    (swap! manager-state assoc :status :stopping)
    (log/info "Stopping cluster manager...")

    (try
      ;; Gracefully leave cluster
      (membership/shutdown! gossip/send-message!)

      ;; Stop gossip transport
      (gossip/stop!)

      (swap! manager-state assoc :status :stopped)
      (log/info "Cluster manager stopped")

      ;; Emit stopped event
      (notify-subscribers! (proto/make-event :cluster-stopped nil {}))

      (catch Exception e
        (log/error e "Error stopping cluster manager")
        (swap! manager-state assoc :status :stopped)))))

(defn running?
  "Check if cluster manager is running."
  []
  (= :running (:status @manager-state)))

;;; =============================================================================
;;; State Provider Management
;;; =============================================================================

(defn register-provider!
  "Register a state provider for synchronization."
  [provider]
  (gossip/register-state-provider! provider))

(defn unregister-provider!
  "Unregister a state provider."
  [type]
  (gossip/unregister-state-provider! type))

;;; =============================================================================
;;; State Broadcasting
;;; =============================================================================

(defn broadcast-state!
  "Broadcast a state change to the cluster."
  [state-type key value]
  (when (running?)
    (let [state (proto/make-syncable-state
                  state-type
                  key
                  value
                  (proto/next-version)
                  (membership/get-node-id))]
      (gossip/broadcast-state-change! state)
      state)))

(defn broadcast-states!
  "Broadcast multiple state changes to the cluster."
  [states]
  (when (running?)
    (gossip/broadcast-states! states)))

;;; =============================================================================
;;; Cluster Information
;;; =============================================================================

(defn get-node-id
  "Get this node's ID."
  []
  (membership/get-node-id))

(defn get-local-node
  "Get this node's info."
  []
  (membership/get-local-node))

(defn get-alive-nodes
  "Get set of alive node IDs."
  []
  (membership/get-alive-nodes))

(defn get-all-nodes
  "Get all known nodes."
  []
  (membership/get-all-nodes))

(defn cluster-size
  "Get number of alive nodes."
  []
  (membership/cluster-size))

(defn get-config
  "Get current cluster configuration."
  []
  (:config @manager-state))

;;; =============================================================================
;;; Statistics
;;; =============================================================================

(defn cluster-stats
  "Get cluster statistics."
  []
  (let [membership-stats (membership/membership-stats)
        gossip-stats (gossip/gossip-stats)]
    {:status (:status @manager-state)
     :membership membership-stats
     :gossip gossip-stats
     :config (:config @manager-state)}))

;;; =============================================================================
;;; Node Failure Callbacks
;;; =============================================================================

(defn on-node-failure!
  "Handle a node failure. Called by membership when node is confirmed dead."
  [node-id]
  (log/info "Handling node failure:" node-id)
  ;; Notify all state providers
  (doseq [[_ provider] (gossip/get-state-providers)]
    (try
      (proto/on-node-failure provider node-id)
      (catch Exception e
        (log/error e "Error in on-node-failure for provider")))))

;; Register membership callback
(defonce ^:private _membership-callback
  (membership/subscribe!
    (fn [event]
      (when (= :node-dead (:event-type event))
        (on-node-failure! (:node-id event))))))
