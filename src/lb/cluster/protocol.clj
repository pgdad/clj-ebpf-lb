(ns lb.cluster.protocol
  "Protocol definitions and data types for distributed state sharing.

   This namespace defines the core abstractions:
   - NodeInfo: cluster member information
   - SyncableState: versioned state that can be synchronized
   - GossipMessage: messages exchanged between nodes
   - IStateProvider: protocol for modules that provide syncable state"
  (:require [clojure.tools.logging :as log])
  (:import [java.util UUID]))

;;; =============================================================================
;;; Node Information
;;; =============================================================================

(defrecord NodeInfo
  [node-id        ; String - unique identifier for this node
   address        ; String - "ip:port" for gossip communication
   incarnation    ; Long - monotonically increasing, used for conflict resolution
   join-time      ; Long - epoch millis when node joined
   last-seen      ; Long - epoch millis of last successful communication
   metadata])     ; Map - custom node metadata (e.g., datacenter, version)

(defn make-node-info
  "Create a new NodeInfo record."
  ([node-id address]
   (make-node-info node-id address {}))
  ([node-id address metadata]
   (let [now (System/currentTimeMillis)]
     (->NodeInfo node-id address 0 now now metadata))))

(defn generate-node-id
  "Generate a unique node ID."
  []
  (str "lb-" (subs (str (UUID/randomUUID)) 0 8)))

;;; =============================================================================
;;; Syncable State
;;; =============================================================================

(defrecord SyncableState
  [state-type    ; Keyword - :health, :circuit-breaker, :drain, :conntrack
   key           ; String - unique identifier within state type (e.g., target-id)
   value         ; Map - the actual state data
   version       ; Long - Lamport timestamp for ordering
   source-node   ; String - node ID that originated this update
   timestamp])   ; Long - wall-clock time for debugging/expiry

(defn make-syncable-state
  "Create a new SyncableState record."
  [state-type key value version source-node]
  (->SyncableState state-type key value version source-node (System/currentTimeMillis)))

(defn state-key
  "Generate a compound key for a SyncableState."
  [state]
  [(:state-type state) (:key state)])

(defn newer?
  "Check if state a is newer than state b based on version (Lamport timestamp)."
  [a b]
  (cond
    (nil? b) true
    (nil? a) false
    :else (> (:version a) (:version b))))

;;; =============================================================================
;;; Gossip Messages
;;; =============================================================================

(def message-types
  "Valid gossip message types."
  #{:push      ; Send state updates to peer
    :pull      ; Request state from peer
    :push-pull ; Bidirectional sync
    :ack       ; Acknowledge receipt
    :ping      ; Failure detection probe
    :ping-req  ; Indirect ping request
    :ping-ack  ; Response to ping
    :join      ; Node joining cluster
    :leave     ; Node gracefully leaving
    :suspect   ; Node suspected of failure
    :alive})   ; Node confirmed alive (refutes suspicion)

(defrecord GossipMessage
  [msg-type      ; Keyword - one of message-types
   sender        ; String - node ID of sender
   target        ; String - node ID of intended recipient (nil for broadcast)
   states        ; Vector of SyncableState - state updates
   digest        ; Map of [state-type key] -> version - for efficient sync
   payload])     ; Map - message-type-specific data

(defn make-message
  "Create a gossip message."
  ([msg-type sender]
   (make-message msg-type sender nil [] {} {}))
  ([msg-type sender target states digest payload]
   (->GossipMessage msg-type sender target states digest payload)))

(defn push-message
  "Create a push message with state updates."
  [sender states]
  (make-message :push sender nil states {} {}))

(defn pull-message
  "Create a pull message with state digest."
  [sender digest]
  (make-message :pull sender nil [] digest {}))

(defn push-pull-message
  "Create a push-pull message for bidirectional sync."
  [sender states digest]
  (make-message :push-pull sender nil states digest {}))

(defn ping-message
  "Create a ping message for failure detection."
  [sender target seq-num]
  (make-message :ping sender target [] {} {:seq seq-num}))

(defn ping-ack-message
  "Create a ping acknowledgment."
  [sender target seq-num]
  (make-message :ping-ack sender target [] {} {:seq seq-num}))

(defn ping-req-message
  "Create an indirect ping request."
  [sender intermediary target seq-num]
  (make-message :ping-req sender intermediary [] {} {:target target :seq seq-num}))

(defn join-message
  "Create a join message when node joins cluster."
  [sender node-info]
  (make-message :join sender nil [] {} {:node-info node-info}))

(defn leave-message
  "Create a leave message when node gracefully leaves."
  [sender]
  (make-message :leave sender nil [] {} {}))

(defn suspect-message
  "Create a suspect message when node may have failed."
  [sender suspect-node incarnation]
  (make-message :suspect sender nil [] {} {:suspect suspect-node :incarnation incarnation}))

(defn alive-message
  "Create an alive message to refute suspicion."
  [sender incarnation]
  (make-message :alive sender nil [] {} {:incarnation incarnation}))

;;; =============================================================================
;;; State Provider Protocol
;;; =============================================================================

(defprotocol IStateProvider
  "Protocol for modules that provide syncable state."

  (provider-type [this]
    "Return keyword identifying this provider type (e.g., :health, :circuit-breaker)")

  (get-sync-state [this]
    "Return current state as a vector of SyncableState records.
     Called periodically for anti-entropy sync.")

  (get-state-digest [this]
    "Return a digest map of [state-type key] -> version.
     Used for efficient delta sync.")

  (apply-remote-state [this states]
    "Apply received remote states. Called when gossip brings updates.
     Returns {:applied n :conflicts n :rejected n}.")

  (on-node-failure [this node-id]
    "Called when a cluster node is confirmed dead.
     Opportunity to promote shadow state, claim ownership, etc."))

;;; =============================================================================
;;; Cluster Events
;;; =============================================================================

(def event-types
  "Types of cluster events that can be subscribed to."
  #{:node-join
    :node-leave
    :node-suspect
    :node-alive
    :node-dead
    :state-sync
    :leader-change})

(defrecord ClusterEvent
  [event-type    ; Keyword - one of event-types
   node-id       ; String - node related to event (if applicable)
   timestamp     ; Long - when event occurred
   data])        ; Map - event-specific data

(defn make-event
  "Create a cluster event."
  [event-type node-id data]
  (->ClusterEvent event-type node-id (System/currentTimeMillis) data))

;;; =============================================================================
;;; Serialization Helpers
;;; =============================================================================

(defn node-info->map
  "Convert NodeInfo to a plain map for serialization."
  [node-info]
  (when node-info
    {:node-id (:node-id node-info)
     :address (:address node-info)
     :incarnation (:incarnation node-info)
     :join-time (:join-time node-info)
     :last-seen (:last-seen node-info)
     :metadata (:metadata node-info)}))

(defn map->node-info
  "Convert a plain map back to NodeInfo."
  [m]
  (when m
    (map->NodeInfo m)))

(defn syncable-state->map
  "Convert SyncableState to a plain map for serialization."
  [state]
  (when state
    {:state-type (:state-type state)
     :key (:key state)
     :value (:value state)
     :version (:version state)
     :source-node (:source-node state)
     :timestamp (:timestamp state)}))

(defn map->syncable-state
  "Convert a plain map back to SyncableState."
  [m]
  (when m
    (map->SyncableState m)))

(defn gossip-message->map
  "Convert GossipMessage to a plain map for serialization."
  [msg]
  (when msg
    {:msg-type (:msg-type msg)
     :sender (:sender msg)
     :target (:target msg)
     :states (mapv syncable-state->map (:states msg))
     :digest (:digest msg)
     :payload (:payload msg)}))

(defn map->gossip-message
  "Convert a plain map back to GossipMessage."
  [m]
  (when m
    (->GossipMessage
      (:msg-type m)
      (:sender m)
      (:target m)
      (mapv map->syncable-state (:states m))
      (:digest m)
      (:payload m))))

;;; =============================================================================
;;; Version Management (Lamport Timestamps)
;;; =============================================================================

(defonce ^:private lamport-clock (atom 0))

(defn next-version
  "Get next Lamport timestamp and increment clock."
  []
  (swap! lamport-clock inc))

(defn update-clock!
  "Update local clock based on received version (Lamport clock rule)."
  [received-version]
  (swap! lamport-clock (fn [local]
                         (inc (max local received-version)))))

(defn current-version
  "Get current Lamport timestamp without incrementing."
  []
  @lamport-clock)

(defn reset-clock!
  "Reset Lamport clock (for testing)."
  []
  (reset! lamport-clock 0))
