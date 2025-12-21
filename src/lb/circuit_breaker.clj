(ns lb.circuit-breaker
  "Circuit breaker pattern for backend protection.

   Prevents cascade failures by automatically stopping traffic to backends
   that are experiencing high error rates, allowing them time to recover.

   State Machine:
   - CLOSED (normal): Traffic flows, errors are counted
   - OPEN (blocking): No traffic sent, waiting for timeout
   - HALF-OPEN (testing): Limited traffic to test recovery

   Transitions:
   - CLOSED -> OPEN: When error rate exceeds threshold
   - OPEN -> HALF-OPEN: After open-duration-ms timeout
   - HALF-OPEN -> CLOSED: After N consecutive successes
   - HALF-OPEN -> OPEN: On any failure"
  (:require [clojure.tools.logging :as log]
            [lb.health :as health]
            [lb.util :as util])
  (:import [lb.config CircuitBreakerConfig]))

;;; =============================================================================
;;; Data Types
;;; =============================================================================

(defrecord CircuitBreakerState
  [target-id             ; "ip:port" string
   proxy-name            ; Which proxy this target belongs to
   state                 ; :closed, :open, :half-open
   window-start          ; Epoch ms when current window started
   error-count           ; Errors in current window
   success-count         ; Successes in current window
   last-state-change     ; Epoch ms of last state transition
   open-until            ; Epoch ms when OPEN transitions to HALF-OPEN
   half-open-successes   ; Consecutive successes in half-open
   config])              ; CircuitBreakerConfig

;;; =============================================================================
;;; Global Circuit Breaker State
;;; =============================================================================

;; Global circuit breaker state atom.
;; {:circuits {}           ; Map of target-id -> CircuitBreakerState
;;  :running? false        ; Is circuit breaker system active
;;  :event-unsubscribe nil ; Function to unsubscribe from health events
;;  :watcher nil           ; Background watcher control {:thread :running :stop-fn}
;;  :update-weights-fn nil ; Function to update BPF map weights
;;  :subscribers []}       ; Callback functions for state change events
(defonce circuit-breaker-state
  (atom {:circuits {}
         :running? false
         :event-unsubscribe nil
         :watcher nil
         :update-weights-fn nil
         :subscribers []}))

;;; =============================================================================
;;; Target ID Helpers
;;; =============================================================================

(defn target-id
  "Create a target ID string from IP and port.
   IP can be a string or u32 value."
  [ip port]
  (let [ip-str (if (string? ip) ip (util/u32->ip-string ip))]
    (str ip-str ":" port)))

(defn parse-target-id
  "Parse a target ID string into {:ip :port}.
   Returns IP as u32 and port as int."
  [id]
  (let [[ip-str port-str] (clojure.string/split id #":")]
    {:ip (util/ip-string->u32 ip-str)
     :port (Integer/parseInt port-str)}))

;;; =============================================================================
;;; State Queries
;;; =============================================================================

(defn running?
  "Check if the circuit breaker system is running."
  []
  (:running? @circuit-breaker-state))

(defn get-circuit
  "Get circuit breaker state for a target."
  [target-id]
  (get-in @circuit-breaker-state [:circuits target-id]))

(defn get-all-circuits
  "Get all circuit breaker states."
  []
  (:circuits @circuit-breaker-state))

(defn circuit-open?
  "Check if a circuit is currently open (blocking traffic)."
  [target-id]
  (= :open (:state (get-circuit target-id))))

(defn circuit-half-open?
  "Check if a circuit is currently half-open (testing)."
  [target-id]
  (= :half-open (:state (get-circuit target-id))))

(defn get-circuit-states-for-proxy
  "Get circuit states for all targets in a proxy.
   Returns a map of target-id -> state keyword."
  [proxy-name]
  (into {}
        (filter (fn [[_ cb]] (= proxy-name (:proxy-name cb)))
                (:circuits @circuit-breaker-state))))

;;; =============================================================================
;;; Event Notification
;;; =============================================================================

(defrecord CircuitBreakerEvent
  [type           ; :circuit-opened, :circuit-closed, :circuit-half-opened
   proxy-name
   target-id
   timestamp      ; epoch-ms
   details])      ; Context-specific map (e.g., {:error-rate 0.55})

(defn- notify-subscribers!
  "Notify all subscribers of a circuit breaker event."
  [event]
  (doseq [subscriber (:subscribers @circuit-breaker-state)]
    (try
      (subscriber event)
      (catch Exception e
        (log/error e "Error in circuit breaker event subscriber")))))

(defn- emit-event!
  "Emit a circuit breaker state change event."
  [type proxy-name target-id details]
  (let [event (->CircuitBreakerEvent type proxy-name target-id
                                      (System/currentTimeMillis) details)]
    (log/info "Circuit breaker event:" type "for" target-id details)
    (notify-subscribers! event)))

(defn subscribe!
  "Subscribe to circuit breaker events. Returns unsubscribe function."
  [callback]
  (swap! circuit-breaker-state update :subscribers conj callback)
  (fn []
    (swap! circuit-breaker-state update :subscribers
           (fn [subs] (vec (remove #(= % callback) subs))))))

;;; =============================================================================
;;; Weight Updates
;;; =============================================================================

(defn- update-weights!
  "Trigger weight update for a proxy after circuit state change."
  [proxy-name]
  (when-let [update-fn (:update-weights-fn @circuit-breaker-state)]
    (try
      (update-fn proxy-name)
      (catch Exception e
        (log/error e "Error updating weights for proxy" proxy-name)))))

;;; =============================================================================
;;; State Transitions
;;; =============================================================================

(defn- update-circuit!
  "Update circuit breaker state for a target."
  [target-id new-state]
  (swap! circuit-breaker-state assoc-in [:circuits target-id] new-state))

(defn- transition-to-open!
  "Transition a circuit to OPEN state."
  [target-id error-rate]
  (let [cb (get-circuit target-id)
        now (System/currentTimeMillis)
        open-duration (get-in cb [:config :open-duration-ms])]
    (update-circuit! target-id
      (assoc cb
             :state :open
             :last-state-change now
             :open-until (+ now open-duration)
             :error-count 0
             :success-count 0
             :window-start now))
    (emit-event! :circuit-opened (:proxy-name cb) target-id
                 {:error-rate error-rate
                  :open-until (+ now open-duration)})
    (update-weights! (:proxy-name cb))))

(defn- transition-to-half-open!
  "Transition a circuit to HALF-OPEN state."
  [target-id]
  (let [cb (get-circuit target-id)
        now (System/currentTimeMillis)]
    (update-circuit! target-id
      (assoc cb
             :state :half-open
             :last-state-change now
             :half-open-successes 0))
    (emit-event! :circuit-half-opened (:proxy-name cb) target-id {})
    (update-weights! (:proxy-name cb))))

(defn- transition-to-closed!
  "Transition a circuit to CLOSED state."
  [target-id]
  (let [cb (get-circuit target-id)
        now (System/currentTimeMillis)]
    (update-circuit! target-id
      (assoc cb
             :state :closed
             :last-state-change now
             :window-start now
             :error-count 0
             :success-count 0
             :half-open-successes 0))
    (emit-event! :circuit-closed (:proxy-name cb) target-id {})
    (update-weights! (:proxy-name cb))))

;;; =============================================================================
;;; Error Rate Calculation
;;; =============================================================================

(defn- should-reset-window?
  "Check if the sliding window should be reset."
  [cb now]
  (let [window-size (get-in cb [:config :window-size-ms])
        window-age (- now (:window-start cb))]
    (>= window-age window-size)))

(defn- reset-window
  "Reset the sliding window for a circuit."
  [cb now]
  (assoc cb
         :window-start now
         :error-count 0
         :success-count 0))

(defn- calculate-error-rate
  "Calculate the error rate for a circuit."
  [cb]
  (let [total (+ (:error-count cb) (:success-count cb))]
    (if (zero? total)
      0.0
      (/ (double (:error-count cb)) total))))

(defn- should-trip?
  "Check if circuit should trip based on error rate."
  [cb]
  (let [{:keys [error-count success-count config]} cb
        {:keys [min-requests error-threshold-pct]} config
        total (+ error-count success-count)]
    (and (>= total min-requests)
         (>= (* 100 (calculate-error-rate cb)) error-threshold-pct))))

;;; =============================================================================
;;; Health Event Processing
;;; =============================================================================

(defn- handle-closed-event
  "Handle a health event when circuit is CLOSED."
  [target-id success?]
  (let [now (System/currentTimeMillis)
        cb (get-circuit target-id)
        ;; Reset window if expired
        cb (if (should-reset-window? cb now)
             (reset-window cb now)
             cb)
        ;; Update counts
        cb (if success?
             (update cb :success-count inc)
             (update cb :error-count inc))]
    (update-circuit! target-id cb)
    ;; Check if we should trip
    (when (should-trip? cb)
      (transition-to-open! target-id (calculate-error-rate cb)))))

(defn- handle-half-open-event
  "Handle a health event when circuit is HALF-OPEN."
  [target-id success?]
  (if success?
    ;; Success - increment counter, maybe close circuit
    (let [cb (get-circuit target-id)
          new-successes (inc (:half-open-successes cb))
          threshold (get-in cb [:config :half-open-requests])]
      (update-circuit! target-id (assoc cb :half-open-successes new-successes))
      (when (>= new-successes threshold)
        (transition-to-closed! target-id)))
    ;; Failure - back to open
    (transition-to-open! target-id 1.0)))

(defn- process-health-event
  "Process a health event and update circuit breaker state."
  [event]
  (let [{:keys [type target-id]} event
        success? (= type :target-healthy)]
    (when-let [cb (get-circuit target-id)]
      (case (:state cb)
        :closed     (handle-closed-event target-id success?)
        :half-open  (handle-half-open-event target-id success?)
        :open       nil))))  ; OPEN ignores events, waits for timeout

;;; =============================================================================
;;; Background Watcher
;;; =============================================================================

(defn- start-timeout-watcher!
  "Start background thread that transitions OPEN circuits to HALF-OPEN.
   Returns control map with :stop-fn."
  [check-interval-ms]
  (let [running (atom true)
        thread (Thread.
                 (fn []
                   (log/info "Circuit breaker timeout watcher started")
                   (while @running
                     (try
                       (let [now (System/currentTimeMillis)
                             circuits (:circuits @circuit-breaker-state)]
                         (doseq [[tid cb] circuits]
                           (when (and (= :open (:state cb))
                                      (>= now (:open-until cb)))
                             (log/debug "Circuit" tid "timeout elapsed, transitioning to half-open")
                             (transition-to-half-open! tid))))
                       (Thread/sleep check-interval-ms)
                       (catch InterruptedException _
                         (reset! running false))
                       (catch Exception e
                         (log/error e "Error in circuit breaker watcher"))))
                   (log/info "Circuit breaker timeout watcher stopped")))]
    (.setDaemon thread true)
    (.setName thread "circuit-breaker-watcher")
    (.start thread)
    {:thread thread
     :running running
     :stop-fn #(do (reset! running false)
                   (.interrupt thread)
                   (.join thread 2000))}))

(defn- stop-timeout-watcher!
  "Stop the background timeout watcher."
  []
  (when-let [watcher (:watcher @circuit-breaker-state)]
    (when-let [stop-fn (:stop-fn watcher)]
      (stop-fn))
    (swap! circuit-breaker-state assoc :watcher nil)))

;;; =============================================================================
;;; Registration
;;; =============================================================================

(defn register-target!
  "Register a target with circuit breaker tracking.
   Called when initializing a proxy with circuit breaker enabled."
  [proxy-name target-id ^CircuitBreakerConfig config]
  (let [now (System/currentTimeMillis)
        initial-state (->CircuitBreakerState
                        target-id
                        proxy-name
                        :closed
                        now              ; window-start
                        0                ; error-count
                        0                ; success-count
                        now              ; last-state-change
                        nil              ; open-until
                        0                ; half-open-successes
                        config)]
    (swap! circuit-breaker-state assoc-in [:circuits target-id] initial-state)
    (log/debug "Registered circuit breaker for target" target-id)))

(defn unregister-target!
  "Unregister a target from circuit breaker tracking."
  [target-id]
  (swap! circuit-breaker-state update :circuits dissoc target-id)
  (log/debug "Unregistered circuit breaker for target" target-id))

(defn register-proxy!
  "Register all targets in a proxy for circuit breaker tracking.
   target-group should be a TargetGroup record.
   config should be a CircuitBreakerConfig record."
  [proxy-name target-group ^CircuitBreakerConfig config]
  (when (:enabled config)
    (doseq [target (:targets target-group)]
      (let [tid (target-id (:ip target) (:port target))]
        (register-target! proxy-name tid config)))))

(defn unregister-proxy!
  "Unregister all targets for a proxy from circuit breaker tracking."
  [proxy-name]
  (let [circuits (:circuits @circuit-breaker-state)
        to-remove (filter (fn [[_ cb]] (= proxy-name (:proxy-name cb))) circuits)]
    (doseq [[tid _] to-remove]
      (unregister-target! tid))))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start the circuit breaker system.
   Must be called after health module is started."
  ([] (start! {}))
  ([{:keys [check-interval-ms] :or {check-interval-ms 1000}}]
   (when-not (running?)
     (log/info "Starting circuit breaker system")
     ;; Subscribe to health events
     (let [unsubscribe (health/subscribe! process-health-event)]
       (swap! circuit-breaker-state assoc
              :running? true
              :event-unsubscribe unsubscribe))
     ;; Start timeout watcher
     (let [watcher (start-timeout-watcher! check-interval-ms)]
       (swap! circuit-breaker-state assoc :watcher watcher))
     (log/info "Circuit breaker system started"))))

(defn stop!
  "Stop the circuit breaker system."
  []
  (when (running?)
    (log/info "Stopping circuit breaker system")
    ;; Stop timeout watcher
    (stop-timeout-watcher!)
    ;; Unsubscribe from health events
    (when-let [unsubscribe (:event-unsubscribe @circuit-breaker-state)]
      (unsubscribe))
    ;; Reset state
    (swap! circuit-breaker-state assoc
           :running? false
           :event-unsubscribe nil
           :circuits {}
           :subscribers [])
    (log/info "Circuit breaker system stopped")))

(defn init!
  "Initialize the circuit breaker system with update function.
   update-weights-fn: Function (proxy-name) -> nil that triggers weight recalculation"
  [update-weights-fn & {:keys [check-interval-ms] :or {check-interval-ms 1000}}]
  (swap! circuit-breaker-state assoc :update-weights-fn update-weights-fn)
  (start! {:check-interval-ms check-interval-ms}))

(defn shutdown!
  "Shutdown the circuit breaker system."
  []
  (stop!)
  (swap! circuit-breaker-state assoc :update-weights-fn nil))

;;; =============================================================================
;;; Manual Control
;;; =============================================================================

(defn force-open!
  "Manually force a circuit to OPEN state."
  [target-id]
  (when-let [cb (get-circuit target-id)]
    (when (not= :open (:state cb))
      (transition-to-open! target-id 1.0)
      true)))

(defn force-close!
  "Manually force a circuit to CLOSED state."
  [target-id]
  (when-let [cb (get-circuit target-id)]
    (when (not= :closed (:state cb))
      (transition-to-closed! target-id)
      true)))

(defn reset-circuit!
  "Reset a circuit to initial CLOSED state with zero counts."
  [target-id]
  (when-let [cb (get-circuit target-id)]
    (let [now (System/currentTimeMillis)]
      (update-circuit! target-id
        (assoc cb
               :state :closed
               :window-start now
               :error-count 0
               :success-count 0
               :last-state-change now
               :open-until nil
               :half-open-successes 0))
      true)))

;;; =============================================================================
;;; Status Display
;;; =============================================================================

(defn get-status
  "Get formatted status for all circuits."
  []
  (let [circuits (:circuits @circuit-breaker-state)]
    (mapv (fn [[tid cb]]
            {:target-id tid
             :proxy-name (:proxy-name cb)
             :state (:state cb)
             :error-count (:error-count cb)
             :success-count (:success-count cb)
             :error-rate (calculate-error-rate cb)
             :last-state-change (:last-state-change cb)})
          circuits)))

(defn print-status
  "Print formatted status for all circuits."
  []
  (let [circuits (get-status)]
    (if (empty? circuits)
      (println "No circuits registered")
      (do
        (println "\n=== Circuit Breaker Status ===")
        (doseq [c circuits]
          (println (format "  %s (%s): %s - errors: %d, successes: %d, rate: %.2f%%"
                           (:target-id c)
                           (:proxy-name c)
                           (name (:state c))
                           (:error-count c)
                           (:success-count c)
                           (* 100 (:error-rate c)))))
        (println)))))
