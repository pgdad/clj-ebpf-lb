(ns lb.cluster
  "Public API for distributed state sharing.

   This namespace provides the public interface for cluster functionality:
   - Cluster lifecycle (start!/stop!)
   - State broadcasting
   - Membership queries
   - Event subscription

   Configuration example:
   {:cluster
    {:enabled true
     :node-id \"auto\"
     :bind-address \"0.0.0.0\"
     :bind-port 7946
     :seeds [\"192.168.1.10:7946\" \"192.168.1.11:7946\"]
     :gossip-interval-ms 200
     :gossip-fanout 2
     :push-pull-interval-ms 10000
     :sync-health true
     :sync-circuit-breaker true
     :sync-drain true
     :sync-conntrack true}}"
  (:require [lb.cluster.manager :as manager]
            [lb.cluster.protocol :as proto]
            [lb.cluster.membership :as membership]
            [lb.cluster.gossip :as gossip]))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start cluster mode with the given configuration.

   Config options:
   :enabled              - Enable/disable cluster mode (default false)
   :node-id              - Node identifier, \"auto\" generates UUID (default \"auto\")
   :bind-address         - Address to bind gossip transport (default \"0.0.0.0\")
   :bind-port            - Port for gossip communication (default 7946)
   :seeds                - List of seed node addresses [\"ip:port\", ...]

   Gossip tuning:
   :gossip-interval-ms   - Gossip tick interval (default 200)
   :gossip-fanout        - Peers to gossip to per tick (default 2)
   :push-pull-interval-ms - Full state sync interval (default 10000)

   Failure detection:
   :ping-interval-ms     - Probe interval (default 1000)
   :ping-timeout-ms      - Probe timeout (default 500)
   :suspicion-mult       - Suspicion multiplier (default 3)

   State sync:
   :sync-health          - Sync health status (default true)
   :sync-circuit-breaker - Sync circuit breaker state (default true)
   :sync-drain           - Sync drain coordination (default true)
   :sync-conntrack       - Sync connection tracking (default true)

   Returns {:node-id <id> :address <addr>} on success, nil if disabled/already running."
  [config]
  (manager/start! config))

(defn stop!
  "Stop cluster mode, gracefully leaving the cluster."
  []
  (manager/stop!))

(defn running?
  "Check if cluster mode is running."
  []
  (manager/running?))

;;; =============================================================================
;;; State Provider Registration
;;; =============================================================================

(defn register-provider!
  "Register a state provider for synchronization.

   A state provider must implement lb.cluster.protocol/IStateProvider:
   - provider-type: Return keyword identifying provider (e.g., :health)
   - get-sync-state: Return vector of SyncableState records
   - get-state-digest: Return map of [type key] -> version
   - apply-remote-state: Apply received remote states
   - on-node-failure: Handle node failure (for failover)"
  [provider]
  (manager/register-provider! provider))

(defn unregister-provider!
  "Unregister a state provider by type."
  [type]
  (manager/unregister-provider! type))

;;; =============================================================================
;;; State Broadcasting
;;; =============================================================================

(defn broadcast!
  "Broadcast a state change to the cluster.

   Args:
   - state-type: Keyword identifying state type (e.g., :health, :circuit-breaker)
   - key: Unique identifier within state type (e.g., target-id)
   - value: State value (must be serializable as EDN)

   Returns the SyncableState record that was broadcast, or nil if cluster not running."
  [state-type key value]
  (manager/broadcast-state! state-type key value))

(defn broadcast-many!
  "Broadcast multiple state changes to the cluster.

   Args:
   - states: Vector of SyncableState records

   Use this for batch updates to reduce network overhead."
  [states]
  (manager/broadcast-states! states))

;;; =============================================================================
;;; Event Subscription
;;; =============================================================================

(defn subscribe!
  "Subscribe to cluster events.

   Callback receives ClusterEvent records with:
   - :event-type - One of: :node-join, :node-leave, :node-suspect, :node-alive,
                   :node-dead, :cluster-started, :cluster-stopped
   - :node-id - Node related to event (if applicable)
   - :timestamp - When event occurred
   - :data - Event-specific data

   Returns an unsubscribe function."
  [callback]
  (manager/subscribe! callback))

;;; =============================================================================
;;; Cluster Information
;;; =============================================================================

(defn node-id
  "Get this node's unique identifier."
  []
  (manager/get-node-id))

(defn local-node
  "Get this node's NodeInfo record."
  []
  (manager/get-local-node))

(defn alive-nodes
  "Get set of alive node IDs (including self)."
  []
  (manager/get-alive-nodes))

(defn all-nodes
  "Get map of all known nodes: node-id -> NodeInfo."
  []
  (manager/get-all-nodes))

(defn cluster-size
  "Get number of alive nodes in the cluster."
  []
  (manager/cluster-size))

(defn node-alive?
  "Check if a specific node is considered alive."
  [node-id]
  (membership/is-alive? node-id))

(defn node-suspected?
  "Check if a specific node is suspected of failure."
  [node-id]
  (membership/is-suspected? node-id))

(defn node-dead?
  "Check if a specific node is confirmed dead."
  [node-id]
  (membership/is-dead? node-id))

;;; =============================================================================
;;; Statistics
;;; =============================================================================

(defn stats
  "Get cluster statistics.

   Returns map with:
   - :status - :stopped, :starting, :running, :stopping
   - :membership - {:node-id, :alive-count, :suspected-count, :dead-count}
   - :gossip - {:running?, :provider-count, :config}
   - :config - Current cluster configuration"
  []
  (manager/cluster-stats))

;;; =============================================================================
;;; Protocol Re-exports (for convenience)
;;; =============================================================================

(def make-syncable-state
  "Create a SyncableState record.
   (make-syncable-state state-type key value version source-node)"
  proto/make-syncable-state)

(def next-version
  "Get next Lamport timestamp for versioning."
  proto/next-version)

(def IStateProvider
  "Protocol for state providers. Import from lb.cluster.protocol for implementation."
  proto/IStateProvider)
