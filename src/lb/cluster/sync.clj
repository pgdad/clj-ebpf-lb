(ns lb.cluster.sync
  "State synchronization providers for cluster mode.

   This namespace provides IStateProvider implementations for:
   - Health status synchronization
   - Circuit breaker state synchronization
   - Drain coordination

   Each provider implements the protocol from lb.cluster.protocol."
  (:require [lb.cluster.protocol :as proto]
            [lb.cluster.gossip :as gossip]
            [lb.cluster.membership :as membership]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; State Version Tracking
;;; =============================================================================

;; Track local versions for each state key
(defonce ^:private state-versions (atom {}))

(defn- get-version
  "Get the current version for a state key."
  [[state-type key]]
  (get @state-versions [state-type key] 0))

(defn- update-version!
  "Update version for a state key, returns new version."
  [[state-type key]]
  (let [new-version (proto/next-version)]
    (swap! state-versions assoc [state-type key] new-version)
    new-version))

;;; =============================================================================
;;; Health State Provider
;;; =============================================================================

(defn create-health-provider
  "Create a health state provider.

   Args:
   - get-health-states-fn: (fn [] {target-id -> {:status :healthy/:unhealthy/:unknown
                                                  :last-check-time ms
                                                  :consecutive-successes n
                                                  :consecutive-failures n}})
   - apply-health-fn: (fn [target-id remote-state] ...) to apply remote health

   Returns an IStateProvider implementation."
  [get-health-states-fn apply-health-fn]
  (let [provider-state (atom {:shadow-states {}})] ; For failover
    (reify proto/IStateProvider
      (provider-type [_] :health)

      (get-sync-state [_]
        (let [node-id (membership/get-node-id)]
          (when node-id
            (for [[target-id health] (get-health-states-fn)]
              (proto/make-syncable-state
                :health
                target-id
                {:status (:status health)
                 :last-check-time (:last-check-time health)
                 :consecutive-successes (:consecutive-successes health)
                 :consecutive-failures (:consecutive-failures health)}
                (get-version [:health target-id])
                node-id)))))

      (get-state-digest [_]
        (into {}
          (for [[target-id _] (get-health-states-fn)]
            [[:health target-id] (get-version [:health target-id])])))

      (apply-remote-state [_ states]
        (let [results (atom {:applied 0 :rejected 0})]
          (doseq [{:keys [key value version source-node timestamp]} states]
            (let [local-version (get-version [:health key])]
              (if (> version local-version)
                ;; Remote is newer, apply it
                (do
                  (log/debug "Applying remote health for" key "from" source-node)
                  (try
                    (apply-health-fn key value)
                    (swap! state-versions assoc [:health key] version)
                    (proto/update-clock! version)
                    (swap! results update :applied inc)
                    (catch Exception e
                      (log/warn "Failed to apply remote health for" key ":" (.getMessage e))
                      (swap! results update :rejected inc)))
                  ;; Store in shadow for failover
                  (swap! provider-state assoc-in [:shadow-states source-node key] value))
                ;; Local is newer or same, reject
                (swap! results update :rejected inc))))
          @results))

      (on-node-failure [_ node-id]
        ;; Could promote shadow states from failed node if needed
        (log/debug "Health provider: node" node-id "failed")
        (swap! provider-state update :shadow-states dissoc node-id)))))

;;; =============================================================================
;;; Circuit Breaker State Provider
;;; =============================================================================

(defn create-circuit-breaker-provider
  "Create a circuit breaker state provider.

   Args:
   - get-cb-states-fn: (fn [] {target-id -> {:state :closed/:open/:half-open
                                              :error-rate float
                                              :last-transition ms}})
   - apply-cb-fn: (fn [target-id remote-state] ...) to apply remote CB state

   Returns an IStateProvider implementation.

   Conflict Resolution:
   - OPEN always wins (conservative, prevents thundering herd)
   - HALF-OPEN beats CLOSED (testing phase should propagate)
   - CLOSED only applies if remote is definitely newer"
  [get-cb-states-fn apply-cb-fn]
  (reify proto/IStateProvider
    (provider-type [_] :circuit-breaker)

    (get-sync-state [_]
      (let [node-id (membership/get-node-id)]
        (when node-id
          (for [[target-id cb] (get-cb-states-fn)]
            (proto/make-syncable-state
              :circuit-breaker
              target-id
              {:state (:state cb)
               :error-rate (:error-rate cb)
               :last-transition (:last-transition cb)}
              (get-version [:circuit-breaker target-id])
              node-id)))))

    (get-state-digest [_]
      (into {}
        (for [[target-id _] (get-cb-states-fn)]
          [[:circuit-breaker target-id] (get-version [:circuit-breaker target-id])])))

    (apply-remote-state [_ states]
      (let [results (atom {:applied 0 :rejected 0})]
        (doseq [{:keys [key value version source-node]} states]
          (let [remote-state (:state value)
                local-cb (get (get-cb-states-fn) key)
                local-state (:state local-cb)
                local-version (get-version [:circuit-breaker key])]
            (cond
              ;; Remote OPEN always wins - prevent thundering herd
              (= remote-state :open)
              (when (not= local-state :open)
                (log/info "Circuit breaker" key "opened by node" source-node)
                (try
                  (apply-cb-fn key value)
                  (swap! state-versions assoc [:circuit-breaker key] version)
                  (proto/update-clock! version)
                  (swap! results update :applied inc)
                  (catch Exception e
                    (log/warn "Failed to apply CB state for" key ":" (.getMessage e))
                    (swap! results update :rejected inc))))

              ;; Remote HALF-OPEN beats local CLOSED
              (and (= remote-state :half-open) (= local-state :closed))
              (do
                (log/debug "Circuit breaker" key "half-open from" source-node)
                (try
                  (apply-cb-fn key value)
                  (swap! state-versions assoc [:circuit-breaker key] version)
                  (proto/update-clock! version)
                  (swap! results update :applied inc)
                  (catch Exception e
                    (swap! results update :rejected inc))))

              ;; Remote CLOSED only if definitely newer
              (and (= remote-state :closed) (> version local-version))
              (do
                (log/debug "Circuit breaker" key "closed from" source-node)
                (try
                  (apply-cb-fn key value)
                  (swap! state-versions assoc [:circuit-breaker key] version)
                  (proto/update-clock! version)
                  (swap! results update :applied inc)
                  (catch Exception e
                    (swap! results update :rejected inc))))

              :else
              (swap! results update :rejected inc))))
        @results))

    (on-node-failure [_ node-id]
      ;; Circuit breaker doesn't need special failover handling
      (log/debug "Circuit breaker provider: node" node-id "failed"))))

;;; =============================================================================
;;; Drain State Provider
;;; =============================================================================

(defn create-drain-provider
  "Create a drain coordination state provider.

   Args:
   - get-drain-states-fn: (fn [] {target-id -> {:status :draining/:drained/:active
                                                 :start-time ms
                                                 :proxy-name str}})
   - apply-drain-fn: (fn [target-id remote-state] ...) to apply remote drain

   Returns an IStateProvider implementation.

   Conflict Resolution:
   - :draining wins over :active (active drain takes precedence)
   - :drained only if all nodes agree"
  [get-drain-states-fn apply-drain-fn]
  (reify proto/IStateProvider
    (provider-type [_] :drain)

    (get-sync-state [_]
      (let [node-id (membership/get-node-id)]
        (when node-id
          (for [[target-id drain] (get-drain-states-fn)]
            (proto/make-syncable-state
              :drain
              target-id
              {:status (:status drain)
               :start-time (:start-time drain)
               :proxy-name (:proxy-name drain)}
              (get-version [:drain target-id])
              node-id)))))

    (get-state-digest [_]
      (into {}
        (for [[target-id _] (get-drain-states-fn)]
          [[:drain target-id] (get-version [:drain target-id])])))

    (apply-remote-state [_ states]
      (let [results (atom {:applied 0 :rejected 0})]
        (doseq [{:keys [key value version source-node]} states]
          (let [remote-status (:status value)
                local-drain (get (get-drain-states-fn) key)
                local-status (:status local-drain)]
            (cond
              ;; Remote draining beats local active
              (and (= remote-status :draining)
                   (or (nil? local-status) (= local-status :active)))
              (do
                (log/info "Starting drain for" key "from node" source-node)
                (try
                  (apply-drain-fn key value)
                  (swap! state-versions assoc [:drain key] version)
                  (proto/update-clock! version)
                  (swap! results update :applied inc)
                  (catch Exception e
                    (log/warn "Failed to apply drain for" key ":" (.getMessage e))
                    (swap! results update :rejected inc))))

              ;; Remote drained - record but don't override local draining
              (= remote-status :drained)
              (do
                (log/debug "Drain complete for" key "from" source-node)
                (swap! results update :applied inc))

              :else
              (swap! results update :rejected inc))))
        @results))

    (on-node-failure [_ node-id]
      ;; When a node fails during drain, remaining nodes continue
      (log/debug "Drain provider: node" node-id "failed"))))

;;; =============================================================================
;;; Helper Functions
;;; =============================================================================

(defn broadcast-health-change!
  "Broadcast a health status change to the cluster."
  [target-id health-state]
  (let [version (update-version! [:health target-id])
        state (proto/make-syncable-state
                :health
                target-id
                {:status (:status health-state)
                 :last-check-time (:last-check-time health-state)
                 :consecutive-successes (:consecutive-successes health-state)
                 :consecutive-failures (:consecutive-failures health-state)}
                version
                (membership/get-node-id))]
    (gossip/broadcast-state-change! state)
    state))

(defn broadcast-circuit-open!
  "Immediately broadcast circuit breaker opening to prevent thundering herd."
  [target-id cb-state]
  (let [version (update-version! [:circuit-breaker target-id])
        state (proto/make-syncable-state
                :circuit-breaker
                target-id
                {:state :open
                 :error-rate (:error-rate cb-state)
                 :last-transition (System/currentTimeMillis)}
                version
                (membership/get-node-id))]
    ;; Broadcast to all, not just fanout - this is critical
    (gossip/broadcast-message! (proto/push-message (membership/get-node-id) [state]))
    state))

(defn broadcast-circuit-change!
  "Broadcast a circuit breaker state change."
  [target-id cb-state]
  (let [version (update-version! [:circuit-breaker target-id])
        state (proto/make-syncable-state
                :circuit-breaker
                target-id
                {:state (:state cb-state)
                 :error-rate (:error-rate cb-state)
                 :last-transition (:last-transition cb-state)}
                version
                (membership/get-node-id))]
    (gossip/broadcast-state-change! state)
    state))

(defn broadcast-drain-start!
  "Broadcast drain start to the cluster."
  [target-id proxy-name]
  (let [version (update-version! [:drain target-id])
        state (proto/make-syncable-state
                :drain
                target-id
                {:status :draining
                 :start-time (System/currentTimeMillis)
                 :proxy-name proxy-name}
                version
                (membership/get-node-id))]
    (gossip/broadcast-message! (proto/push-message (membership/get-node-id) [state]))
    state))

(defn broadcast-drain-complete!
  "Broadcast drain completion to the cluster."
  [target-id]
  (let [version (update-version! [:drain target-id])
        state (proto/make-syncable-state
                :drain
                target-id
                {:status :drained
                 :start-time nil
                 :proxy-name nil}
                version
                (membership/get-node-id))]
    (gossip/broadcast-state-change! state)
    state))
