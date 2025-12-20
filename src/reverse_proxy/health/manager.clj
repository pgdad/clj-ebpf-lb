(ns reverse-proxy.health.manager
  "Health check orchestration using virtual threads.
   Manages health state for all targets and triggers weight updates."
  (:require [clojure.tools.logging :as log]
            [reverse-proxy.health.checker :as checker]
            [reverse-proxy.health.weights :as weights]
            [reverse-proxy.util :as util]
            [reverse-proxy.config :as config])
  (:import [java.util.concurrent Executors ScheduledExecutorService TimeUnit]
           [java.util.concurrent.locks ReentrantLock]))

;;; =============================================================================
;;; Target Health State
;;; =============================================================================

(defrecord TargetHealth
  [target-id              ; "ip:port" string
   ip                     ; IP as u32
   port                   ; Port number
   status                 ; :healthy, :unhealthy, :unknown
   consecutive-successes  ; Count of consecutive successful checks
   consecutive-failures   ; Count of consecutive failed checks
   last-check-time        ; Epoch ms of last check
   last-latency-ms        ; Latency of last successful check
   last-error             ; Last error type (:timeout, :connection-refused, etc.)
   recovery-step          ; nil if stable, 0-3 during gradual recovery
   health-check-config])  ; HealthCheckConfig for this target

(defn make-target-health
  "Create initial health state for a target."
  [weighted-target default-config]
  (let [ip (:ip weighted-target)
        port (:port weighted-target)
        hc-config (or (:health-check weighted-target) default-config)]
    (->TargetHealth
      (checker/target-id ip port)
      ip
      port
      :unknown
      0
      0
      nil
      nil
      nil
      nil
      hc-config)))

;;; =============================================================================
;;; Proxy Health State
;;; =============================================================================

(defrecord ProxyHealth
  [proxy-name             ; Name of the proxy
   target-healths         ; Map of target-id -> TargetHealth
   original-weights       ; Original configured weights
   effective-weights      ; Current effective weights after health adjustments
   last-update-time       ; Last time weights were updated
   update-callback])      ; Function to call when weights change

;;; =============================================================================
;;; Health Manager State
;;; =============================================================================

;; Global health manager state:
;; {:running? boolean
;;  :executor ScheduledExecutorService
;;  :proxies {proxy-name -> ProxyHealth}
;;  :subscribers [fn...]}
(defonce ^:private manager-state
  (atom {:running? false
         :executor nil
         :proxies {}
         :subscribers []}))

;; Lock for coordinating state updates
(defonce ^:private state-lock (ReentrantLock.))

(defn- with-lock
  "Execute f while holding the state lock."
  [f]
  (.lock state-lock)
  (try
    (f)
    (finally
      (.unlock state-lock))))

;;; =============================================================================
;;; Health Status Transitions
;;; =============================================================================

(defn- transition-health
  "Transition target health based on check result.
   Returns updated TargetHealth."
  [target-health result]
  (let [{:keys [status consecutive-successes consecutive-failures
                health-check-config recovery-step]} target-health
        {:keys [healthy-threshold unhealthy-threshold]} health-check-config
        success? (:success? result)]
    (cond
      ;; Success case
      success?
      (let [new-successes (inc consecutive-successes)
            new-status (cond
                         ;; Already healthy - stay healthy
                         (= status :healthy) :healthy
                         ;; Reached threshold - become healthy
                         (>= new-successes healthy-threshold) :healthy
                         ;; Still unknown/unhealthy
                         :else status)
            ;; Start recovery if transitioning to healthy
            new-recovery (when (and (not= status :healthy) (= new-status :healthy))
                           0)]
        (assoc target-health
               :status new-status
               :consecutive-successes new-successes
               :consecutive-failures 0
               :last-check-time (System/currentTimeMillis)
               :last-latency-ms (:latency-ms result)
               :last-error nil
               :recovery-step (if (= new-status :healthy)
                                (when recovery-step
                                  (min 3 (inc recovery-step)))
                                new-recovery)))

      ;; Failure case
      :else
      (let [new-failures (inc consecutive-failures)
            new-status (cond
                         ;; Already unhealthy - stay unhealthy
                         (= status :unhealthy) :unhealthy
                         ;; Reached threshold - become unhealthy
                         (>= new-failures unhealthy-threshold) :unhealthy
                         ;; Still unknown/healthy
                         :else status)]
        (assoc target-health
               :status new-status
               :consecutive-successes 0
               :consecutive-failures new-failures
               :last-check-time (System/currentTimeMillis)
               :last-error (:error result)
               :recovery-step nil)))))  ; Reset recovery on failure

;;; =============================================================================
;;; Weight Update Logic
;;; =============================================================================

(defn- compute-health-statuses
  "Extract health statuses from target healths in order."
  [target-healths target-order]
  (mapv (fn [tid]
          (let [th (get target-healths tid)]
            (= :healthy (:status th))))
        target-order))

(defn- should-update-weights?
  "Check if weights need to be updated based on health changes."
  [proxy-health target-healths target-order]
  (let [current-effective (:effective-weights proxy-health)
        health-statuses (compute-health-statuses target-healths target-order)
        recovery-steps (mapv #(:recovery-step (get target-healths %)) target-order)
        new-effective (weights/apply-recovery-weights
                        (:original-weights proxy-health)
                        health-statuses
                        recovery-steps)]
    (when (weights/weights-changed? current-effective new-effective)
      new-effective)))

(defn- update-proxy-weights!
  "Update weights for a proxy and trigger callback."
  [proxy-name new-weights]
  (with-lock
    (fn []
      (let [proxy-health (get-in @manager-state [:proxies proxy-name])]
        (when proxy-health
          (let [callback (:update-callback proxy-health)
                targets (vals (:target-healths proxy-health))
                target-order (mapv :target-id targets)
                th-map (:target-healths proxy-health)]
            ;; Update state
            (swap! manager-state assoc-in [:proxies proxy-name :effective-weights] new-weights)
            (swap! manager-state assoc-in [:proxies proxy-name :last-update-time]
                   (System/currentTimeMillis))
            ;; Log the change
            (log/info "Updated weights for proxy" proxy-name ":"
                      (weights/format-weight-distribution
                        (mapv #(get th-map %) target-order)
                        new-weights))
            ;; Trigger callback
            (when callback
              (try
                (callback new-weights)
                (catch Exception e
                  (log/error e "Error in weight update callback for" proxy-name))))))))))

;;; =============================================================================
;;; Event Notification
;;; =============================================================================

(defrecord HealthEvent
  [type           ; :target-healthy, :target-unhealthy, :weights-updated
   proxy-name
   target-id
   timestamp
   details])

(defn- notify-subscribers!
  "Notify all subscribers of a health event."
  [event]
  (doseq [subscriber (:subscribers @manager-state)]
    (try
      (subscriber event)
      (catch Exception e
        (log/error e "Error in health event subscriber")))))

(defn- emit-health-event!
  "Emit a health state change event."
  [type proxy-name target-id details]
  (let [event (->HealthEvent type proxy-name target-id (System/currentTimeMillis) details)]
    (notify-subscribers! event)))

;;; =============================================================================
;;; Health Check Task
;;; =============================================================================

(defn- run-health-check!
  "Run a single health check for a target."
  [proxy-name target-id]
  ;; Skip if manager is not running (executor shutdown)
  (when (:running? @manager-state)
    (let [proxy-health (get-in @manager-state [:proxies proxy-name])
          target-health (get-in proxy-health [:target-healths target-id])]
      (when (and proxy-health target-health (:health-check-config target-health))
        (let [{:keys [ip port health-check-config status]} target-health
              result (checker/perform-check health-check-config ip port)
              updated (transition-health target-health result)
              status-changed? (not= status (:status updated))]
          ;; Update state
          (swap! manager-state assoc-in
                 [:proxies proxy-name :target-healths target-id] updated)
          ;; Emit event if status changed
          (when status-changed?
            (log/info "Target" target-id "status changed:" status "->" (:status updated)
                      (when-not (:success? result)
                        (str "(" (:error result) ")")))
            (emit-health-event!
              (if (= :healthy (:status updated)) :target-healthy :target-unhealthy)
              proxy-name
              target-id
              {:old-status status
               :new-status (:status updated)
               :error (:error result)}))
          ;; Check if weights need updating
          (let [proxy-health' (get-in @manager-state [:proxies proxy-name])
                target-healths (:target-healths proxy-health')
                target-order (vec (keys target-healths))]
            (when-let [new-weights (should-update-weights?
                                     proxy-health' target-healths target-order)]
              (update-proxy-weights! proxy-name new-weights)
              (emit-health-event!
                :weights-updated
                proxy-name
                nil
                {:weights new-weights}))))))))

;;; =============================================================================
;;; Scheduler Management
;;; =============================================================================

(defn- schedule-health-check!
  "Schedule a recurring health check for a target."
  [^ScheduledExecutorService executor proxy-name target-id interval-ms initial-delay-ms]
  (when (and executor (not (.isShutdown executor)))
    (.scheduleAtFixedRate
      executor
      (fn []
        (try
          (run-health-check! proxy-name target-id)
          (catch Exception e
            (log/error e "Error running health check for" target-id))))
      initial-delay-ms
      interval-ms
      TimeUnit/MILLISECONDS)))

(defn- compute-jittered-delay
  "Compute initial delay with jitter to avoid thundering herd."
  [index total interval-ms]
  (let [base-delay (/ (* index interval-ms) total)
        jitter (* interval-ms 0.1 (- (rand) 0.5))]
    (long (max 0 (+ base-delay jitter)))))

;;; =============================================================================
;;; Public API
;;; =============================================================================

(defn start!
  "Start the health check manager."
  []
  (with-lock
    (fn []
      (when-not (:running? @manager-state)
        (log/info "Starting health check manager")
        (let [executor (Executors/newSingleThreadScheduledExecutor)]
          (swap! manager-state assoc
                 :running? true
                 :executor executor))
        (log/info "Health check manager started")))))

(defn stop!
  "Stop the health check manager."
  []
  (with-lock
    (fn []
      (when (:running? @manager-state)
        (log/info "Stopping health check manager")
        (when-let [^ScheduledExecutorService executor (:executor @manager-state)]
          (.shutdownNow executor)
          (.awaitTermination executor 2 TimeUnit/SECONDS))
        (swap! manager-state assoc
               :running? false
               :executor nil
               :proxies {}
               :subscribers [])
        (log/info "Health check manager stopped")))))

(defn running?
  "Check if the health manager is running."
  []
  (:running? @manager-state))

(defn register-proxy!
  "Register a proxy for health checking.
   target-group: TargetGroup with targets to monitor
   default-config: Default HealthCheckConfig from settings
   update-callback: Function called with new weights when they change"
  [proxy-name target-group default-config update-callback]
  (with-lock
    (fn []
      (when (:running? @manager-state)
       (let [targets (:targets target-group)
             target-healths (into {}
                              (map (fn [t]
                                     (let [tid (checker/target-id (:ip t) (:port t))]
                                       [tid (make-target-health t default-config)]))
                                   targets))
             original-weights (mapv :weight targets)
             proxy-health (->ProxyHealth
                            proxy-name
                            target-healths
                            original-weights
                            original-weights  ; Start with original as effective
                            (System/currentTimeMillis)
                            update-callback)]
         ;; Store proxy health
         (swap! manager-state assoc-in [:proxies proxy-name] proxy-health)
         ;; Schedule health checks for each target
         (let [executor (:executor @manager-state)
               target-list (vec (keys target-healths))
               total (count target-list)]
           (doseq [[idx tid] (map-indexed vector target-list)]
             (let [th (get target-healths tid)
                   interval-ms (get-in th [:health-check-config :interval-ms] 10000)
                   delay-ms (compute-jittered-delay idx total interval-ms)]
               (when (:health-check-config th)
                 (schedule-health-check! executor proxy-name tid interval-ms delay-ms)))))
         (log/info "Registered proxy" proxy-name "with" (count targets) "targets for health checking"))))))

(defn unregister-proxy!
  "Unregister a proxy from health checking."
  [proxy-name]
  (with-lock
    #(do
       (swap! manager-state update :proxies dissoc proxy-name)
       (log/info "Unregistered proxy" proxy-name "from health checking"))))

(defn get-proxy-health
  "Get current health status for a proxy."
  [proxy-name]
  (when-let [proxy-health (get-in @manager-state [:proxies proxy-name])]
    {:proxy-name proxy-name
     :targets (mapv (fn [[tid th]]
                      {:target-id tid
                       :ip (util/u32->ip-string (:ip th))
                       :port (:port th)
                       :status (:status th)
                       :consecutive-successes (:consecutive-successes th)
                       :consecutive-failures (:consecutive-failures th)
                       :last-check-time (:last-check-time th)
                       :last-latency-ms (:last-latency-ms th)
                       :last-error (:last-error th)})
                    (:target-healths proxy-health))
     :original-weights (:original-weights proxy-health)
     :effective-weights (:effective-weights proxy-health)
     :last-update-time (:last-update-time proxy-health)}))

(defn get-all-health
  "Get health status for all registered proxies."
  []
  (mapv (fn [[name _]] (get-proxy-health name))
        (:proxies @manager-state)))

(defn subscribe!
  "Subscribe to health events. Returns unsubscribe function."
  [callback]
  (swap! manager-state update :subscribers conj callback)
  (fn []
    (swap! manager-state update :subscribers
           (fn [subs] (vec (remove #(= % callback) subs))))))

;;; =============================================================================
;;; Manual Override
;;; =============================================================================

(defn set-target-status!
  "Manually set a target's health status (for maintenance, testing)."
  [proxy-name target-id status]
  (with-lock
    (fn []
      (when-let [old-status (get-in @manager-state [:proxies proxy-name :target-healths target-id :status])]
        (swap! manager-state assoc-in
               [:proxies proxy-name :target-healths target-id :status] status)
        (log/info "Manually set" target-id "status to" status)
        ;; Emit event if status changed
        (when (not= old-status status)
          (emit-health-event!
            (if (= :healthy status) :target-healthy :target-unhealthy)
            proxy-name
            target-id
            {:old-status old-status :new-status status :manual true}))
        ;; Trigger weight recalculation
        (let [proxy-health (get-in @manager-state [:proxies proxy-name])
              target-healths (:target-healths proxy-health)
              target-order (vec (keys target-healths))]
          (when-let [new-weights (should-update-weights?
                                   proxy-health target-healths target-order)]
            (update-proxy-weights! proxy-name new-weights)))))))

(defn force-check!
  "Force an immediate health check for a target."
  [proxy-name target-id]
  (Thread/startVirtualThread
    #(run-health-check! proxy-name target-id)))
