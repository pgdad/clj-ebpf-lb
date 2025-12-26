(ns lb.cluster.conntrack
  "Connection tracking synchronization for seamless failover.

   This namespace implements connection state replication across cluster nodes:
   - Owner node tracks connections where first packet arrived
   - Shadow entries stored on non-owner nodes for failover
   - On node failure, shadow entries promoted to active BPF entries

   Sync Strategy:
   - Batch updates for efficiency (every 100ms or 100 connections)
   - Delta sync: only changed entries since last gossip
   - Full sync on node join via push-pull
   - Conservative: shadow entries don't affect routing until failover"
  (:require [lb.cluster.protocol :as proto]
            [lb.cluster.membership :as membership]
            [lb.cluster.gossip :as gossip]
            [lb.conntrack :as conntrack]
            [lb.maps :as maps]
            [lb.util :as util]
            [clojure.tools.logging :as log])
  (:import [java.util.concurrent Executors ScheduledExecutorService TimeUnit
            ConcurrentHashMap LinkedBlockingQueue]))

;;; =============================================================================
;;; Configuration
;;; =============================================================================

(def default-config
  "Default conntrack sync configuration."
  {:batch-interval-ms 100     ; How often to send batched updates
   :batch-size 100            ; Max connections per batch
   :full-sync-on-join true    ; Full sync when new node joins
   :shadow-ttl-seconds 300})  ; How long to keep shadow entries

;;; =============================================================================
;;; State
;;; =============================================================================

;; Conntrack sync state
;; - :running? - Whether sync is active
;; - :config - Configuration
;; - :conntrack-map - Reference to BPF conntrack map
;; - :shadow-connections - ConcurrentHashMap of shadow connections by owner
;;   {owner-node-id -> {5-tuple-key -> connection-data}}
;; - :pending-updates - Queue of connections to broadcast
;; - :local-connections - Set of 5-tuple keys for locally owned connections
;; - :last-sync-version - Version number of last full sync
;; - :executor - Scheduled executor for batching
(defonce ^:private sync-state
  (atom {:running? false
         :config default-config
         :conntrack-map nil
         :shadow-connections nil
         :pending-updates nil
         :local-connections nil
         :last-sync-version 0
         :executor nil}))

;;; =============================================================================
;;; 5-Tuple Key Helpers
;;; =============================================================================

(defn- make-5tuple-key
  "Create a canonical 5-tuple key from connection data."
  [{:keys [src-ip dst-ip src-port dst-port protocol]}]
  [src-ip dst-ip src-port dst-port protocol])

(defn- tuple-key->map
  "Convert 5-tuple key back to map."
  [[src-ip dst-ip src-port dst-port protocol]]
  {:src-ip src-ip :dst-ip dst-ip :src-port src-port :dst-port dst-port :protocol protocol})

;;; =============================================================================
;;; Shadow Connection Management
;;; =============================================================================

(defn- get-shadow-connections
  "Get shadow connections from a specific owner."
  [owner-id]
  (when-let [^ConcurrentHashMap shadows (:shadow-connections @sync-state)]
    (when-let [owner-map (.get shadows owner-id)]
      (into {} owner-map))))

(defn- store-shadow-connection!
  "Store a shadow connection from a remote owner."
  [owner-id tuple-key conn-data]
  (when-let [^ConcurrentHashMap shadows (:shadow-connections @sync-state)]
    (let [owner-map (.computeIfAbsent shadows owner-id
                      (reify java.util.function.Function
                        (apply [_ _] (ConcurrentHashMap.))))]
      (.put owner-map tuple-key conn-data))))

(defn- remove-shadow-connection!
  "Remove a shadow connection."
  [owner-id tuple-key]
  (when-let [^ConcurrentHashMap shadows (:shadow-connections @sync-state)]
    (when-let [owner-map (.get shadows owner-id)]
      (.remove owner-map tuple-key))))

(defn- clear-owner-shadows!
  "Clear all shadow connections from a specific owner."
  [owner-id]
  (when-let [^ConcurrentHashMap shadows (:shadow-connections @sync-state)]
    (.remove shadows owner-id)))

(defn- count-shadow-connections
  "Get total count of shadow connections."
  []
  (if-let [^ConcurrentHashMap shadows (:shadow-connections @sync-state)]
    (reduce + (map #(.size %) (vals shadows)))
    0))

;;; =============================================================================
;;; Connection Serialization
;;; =============================================================================

(defn- serialize-connection
  "Serialize a connection for cluster sync."
  [conn]
  {:5tuple (make-5tuple-key conn)
   :nat {:orig-dst-ip (:orig-dst-ip conn)
         :orig-dst-port (:orig-dst-port conn)
         :nat-dst-ip (:nat-dst-ip conn)
         :nat-dst-port (:nat-dst-port conn)}
   :stats {:created-ns (:created-ns conn)
           :last-seen (:last-seen conn)
           :packets-fwd (:packets-fwd conn)
           :packets-rev (:packets-rev conn)
           :bytes-fwd (:bytes-fwd conn)
           :bytes-rev (:bytes-rev conn)}})

(defn- deserialize-connection
  "Deserialize a connection from cluster sync."
  [data]
  (let [[src-ip dst-ip src-port dst-port protocol] (:5tuple data)
        nat (:nat data)
        stats (:stats data)]
    {:src-ip src-ip
     :dst-ip dst-ip
     :src-port src-port
     :dst-port dst-port
     :protocol protocol
     :orig-dst-ip (:orig-dst-ip nat)
     :orig-dst-port (:orig-dst-port nat)
     :nat-dst-ip (:nat-dst-ip nat)
     :nat-dst-port (:nat-dst-port nat)
     :created-ns (:created-ns stats)
     :last-seen (:last-seen stats)
     :packets-fwd (:packets-fwd stats)
     :packets-rev (:packets-rev stats)
     :bytes-fwd (:bytes-fwd stats)
     :bytes-rev (:bytes-rev stats)}))

;;; =============================================================================
;;; Pending Updates Queue
;;; =============================================================================

(defn- queue-connection-update!
  "Queue a connection update for batched broadcast."
  [action conn]
  (when-let [^LinkedBlockingQueue queue (:pending-updates @sync-state)]
    (.offer queue {:action action :connection (serialize-connection conn) :timestamp (System/currentTimeMillis)})))

(defn- drain-pending-updates!
  "Drain all pending updates from the queue."
  []
  (when-let [^LinkedBlockingQueue queue (:pending-updates @sync-state)]
    (let [updates (java.util.ArrayList.)]
      (.drainTo queue updates)
      (vec updates))))

;;; =============================================================================
;;; Broadcasting
;;; =============================================================================

(defn- broadcast-batch!
  "Broadcast a batch of connection updates."
  [updates]
  (when (seq updates)
    (let [node-id (membership/get-node-id)
          creates (filter #(= :create (:action %)) updates)
          deletes (filter #(= :delete (:action %)) updates)]
      ;; Broadcast creates
      (when (seq creates)
        (let [state (proto/make-syncable-state
                      :conntrack
                      :batch
                      {:action :create-batch
                       :connections (mapv :connection creates)}
                      (proto/next-version)
                      node-id)]
          (gossip/broadcast-states! [state])))
      ;; Broadcast deletes
      (when (seq deletes)
        (let [state (proto/make-syncable-state
                      :conntrack
                      :batch
                      {:action :delete-batch
                       :connections (mapv :connection deletes)}
                      (proto/next-version)
                      node-id)]
          (gossip/broadcast-states! [state]))))))

(defn- do-batch-sync!
  "Process pending updates and broadcast them."
  []
  (try
    (when (:running? @sync-state)
      (let [updates (drain-pending-updates!)]
        (when (seq updates)
          (log/debug "Broadcasting" (count updates) "connection updates")
          (broadcast-batch! updates))))
    (catch Exception e
      (log/error e "Error in conntrack batch sync"))))

;;; =============================================================================
;;; State Provider Implementation
;;; =============================================================================

(defn- get-conntrack-sync-state
  "Get all local connections for sync."
  []
  (when-let [ct-map (:conntrack-map @sync-state)]
    (let [node-id (membership/get-node-id)]
      (for [conn (conntrack/get-all-connections ct-map)]
        (proto/make-syncable-state
          :conntrack
          (make-5tuple-key conn)
          (serialize-connection conn)
          (proto/next-version)
          node-id)))))

(defn- get-conntrack-digest
  "Get digest of local connection versions."
  []
  (when-let [ct-map (:conntrack-map @sync-state)]
    ;; Use connection count and hash as a simple digest
    (let [conns (conntrack/get-all-connections ct-map)
          count (count conns)]
      {[:conntrack :summary] (hash [count (System/currentTimeMillis)])})))

(defn- apply-conntrack-state!
  "Apply received connection states from cluster.
   Stores as shadow connections, not active BPF entries."
  [states]
  (let [results (atom {:applied 0 :rejected 0})
        node-id (membership/get-node-id)]
    (doseq [{:keys [key value source-node]} states]
      (when (not= source-node node-id)  ; Ignore our own
        (cond
          ;; Batch create
          (and (= key :batch) (= (:action value) :create-batch))
          (doseq [conn-data (:connections value)]
            (let [tuple-key (:5tuple conn-data)]
              (store-shadow-connection! source-node tuple-key conn-data)
              (swap! results update :applied inc)))

          ;; Batch delete
          (and (= key :batch) (= (:action value) :delete-batch))
          (doseq [conn-data (:connections value)]
            (let [tuple-key (:5tuple conn-data)]
              (remove-shadow-connection! source-node tuple-key)
              (swap! results update :applied inc)))

          ;; Single connection
          (vector? key)
          (do
            (store-shadow-connection! source-node key value)
            (swap! results update :applied inc))

          :else
          (swap! results update :rejected inc))))
    @results))

(defn- on-conntrack-node-failure!
  "Handle node failure - promote shadow connections to active."
  [failed-node-id]
  (log/info "Promoting shadow connections from failed node:" failed-node-id)
  (when-let [ct-map (:conntrack-map @sync-state)]
    (let [shadows (get-shadow-connections failed-node-id)
          promoted (atom 0)]
      (doseq [[tuple-key conn-data] shadows]
        (try
          (let [conn (deserialize-connection conn-data)
                key-map (tuple-key->map tuple-key)]
            ;; Only insert if not already present
            (when-not (maps/lookup-connection ct-map key-map)
              (maps/insert-connection ct-map
                key-map
                {:orig-dst-ip (:orig-dst-ip conn)
                 :orig-dst-port (:orig-dst-port conn)
                 :nat-dst-ip (:nat-dst-ip conn)
                 :nat-dst-port (:nat-dst-port conn)
                 :created-ns (:created-ns conn)
                 :last-seen (System/nanoTime)  ; Refresh timestamp
                 :packets-fwd (:packets-fwd conn)
                 :packets-rev (:packets-rev conn)
                 :bytes-fwd (:bytes-fwd conn)
                 :bytes-rev (:bytes-rev conn)})
              (swap! promoted inc)))
          (catch Exception e
            (log/warn "Failed to promote connection:" (.getMessage e)))))
      ;; Clear shadows after promotion
      (clear-owner-shadows! failed-node-id)
      (log/info "Promoted" @promoted "connections from" failed-node-id))))

(defn create-conntrack-provider
  "Create a conntrack state provider for cluster sync."
  []
  (reify proto/IStateProvider
    (provider-type [_] :conntrack)
    (get-sync-state [_] (get-conntrack-sync-state))
    (get-state-digest [_] (get-conntrack-digest))
    (apply-remote-state [_ states] (apply-conntrack-state! states))
    (on-node-failure [_ node-id] (on-conntrack-node-failure! node-id))))

;;; =============================================================================
;;; Connection Event Hooks
;;; =============================================================================

(defn on-connection-created!
  "Called when a new connection is created locally.
   Queues the connection for sync to cluster."
  [conn]
  (when (:running? @sync-state)
    (when-let [local-conns (:local-connections @sync-state)]
      (.add local-conns (make-5tuple-key conn)))
    (queue-connection-update! :create conn)))

(defn on-connection-deleted!
  "Called when a connection is deleted locally.
   Queues the deletion for sync to cluster."
  [conn]
  (when (:running? @sync-state)
    (when-let [local-conns (:local-connections @sync-state)]
      (.remove local-conns (make-5tuple-key conn)))
    (queue-connection-update! :delete conn)))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start conntrack synchronization.

   Args:
   - conntrack-map: BPF conntrack map reference
   - opts: Configuration options (see default-config)"
  [conntrack-map & {:as opts}]
  (when-not (:running? @sync-state)
    (let [cfg (merge default-config opts)
          executor (Executors/newSingleThreadScheduledExecutor)]
      (swap! sync-state assoc
             :running? true
             :config cfg
             :conntrack-map conntrack-map
             :shadow-connections (ConcurrentHashMap.)
             :pending-updates (LinkedBlockingQueue.)
             :local-connections (ConcurrentHashMap/newKeySet)
             :executor executor)

      ;; Schedule batch sync
      (.scheduleAtFixedRate executor
        #(do-batch-sync!)
        (:batch-interval-ms cfg)
        (:batch-interval-ms cfg)
        TimeUnit/MILLISECONDS)

      ;; Register provider
      (gossip/register-state-provider! (create-conntrack-provider))

      (log/info "Conntrack sync started")))
  true)

(defn stop!
  "Stop conntrack synchronization."
  []
  (when (:running? @sync-state)
    (swap! sync-state assoc :running? false)

    ;; Flush any pending updates
    (do-batch-sync!)

    ;; Stop executor
    (when-let [^ScheduledExecutorService executor (:executor @sync-state)]
      (.shutdown executor)
      (try
        (.awaitTermination executor 5 TimeUnit/SECONDS)
        (catch InterruptedException _)))

    ;; Unregister provider
    (gossip/unregister-state-provider! :conntrack)

    (swap! sync-state assoc
           :conntrack-map nil
           :shadow-connections nil
           :pending-updates nil
           :local-connections nil
           :executor nil)

    (log/info "Conntrack sync stopped"))
  true)

(defn running?
  "Check if conntrack sync is running."
  []
  (:running? @sync-state))

;;; =============================================================================
;;; Statistics
;;; =============================================================================

(defn sync-stats
  "Get conntrack sync statistics."
  []
  (let [state @sync-state]
    {:running? (:running? state)
     :local-connections (if-let [lc (:local-connections state)] (count lc) 0)
     :shadow-connections (count-shadow-connections)
     :pending-updates (if-let [q (:pending-updates state)] (.size q) 0)
     :shadow-owners (when-let [^ConcurrentHashMap shadows (:shadow-connections state)]
                      (vec (.keySet shadows)))}))

;;; =============================================================================
;;; Manual Sync Operations
;;; =============================================================================

(defn force-full-sync!
  "Force a full sync of all local connections to the cluster."
  []
  (when (:running? @sync-state)
    (when-let [ct-map (:conntrack-map @sync-state)]
      (let [connections (conntrack/get-all-connections ct-map)
            node-id (membership/get-node-id)]
        (log/info "Forcing full conntrack sync:" (count connections) "connections")
        (doseq [batch (partition-all 100 connections)]
          (let [state (proto/make-syncable-state
                        :conntrack
                        :batch
                        {:action :create-batch
                         :connections (mapv serialize-connection batch)}
                        (proto/next-version)
                        node-id)]
            (gossip/broadcast-states! [state])))
        (count connections)))))

(defn promote-all-shadows!
  "Manually promote all shadow connections to active BPF entries.
   Use with caution - may cause duplicate connections."
  []
  (when (:running? @sync-state)
    (when-let [^ConcurrentHashMap shadows (:shadow-connections @sync-state)]
      (let [promoted (atom 0)]
        (doseq [owner-id (vec (.keySet shadows))]
          (let [owner-shadows (get-shadow-connections owner-id)]
            (doseq [[_ conn-data] owner-shadows]
              (try
                (on-conntrack-node-failure! owner-id)
                (swap! promoted inc)
                (catch Exception e
                  (log/warn "Failed to promote:" (.getMessage e)))))))
        @promoted))))
