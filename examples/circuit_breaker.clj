;; Circuit Breaker Examples
;;
;; Demonstrates automatic failure detection and recovery for backends.
;; The circuit breaker pattern prevents cascade failures by stopping
;; traffic to unhealthy backends until they recover.
;;
;; Usage:
;;   sudo clojure -M:dev
;;   (load-file "examples/circuit_breaker.clj")
;;
;; Circuit breaker states:
;;   CLOSED    - Normal operation, traffic flowing
;;   OPEN      - Backend failing, traffic stopped
;;   HALF-OPEN - Testing if backend has recovered

(ns circuit-breaker
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.circuit-breaker :as cb]
            [lb.health.weights :as weights]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Example Configuration
;;; =============================================================================

(def example-config
  "Configuration with circuit breaker enabled"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target
     [{:ip "127.0.0.1" :port 9001 :weight 50}
      {:ip "127.0.0.1" :port 9002 :weight 50}]
     :health-check
     {:type :http
      :path "/health"
      :interval-ms 5000
      :timeout-ms 2000
      :healthy-threshold 2
      :unhealthy-threshold 3}}]
   :settings
   {:stats-enabled true
    :health-check-enabled true
    :circuit-breaker
    {:enabled true
     :error-threshold-pct 50      ; Trip when >50% requests fail
     :min-requests 10             ; Need at least 10 requests to evaluate
     :open-duration-ms 30000      ; Stay open for 30 seconds
     :half-open-requests 3        ; Need 3 successes to close
     :window-size-ms 60000}}})    ; 60 second sliding window

;;; =============================================================================
;;; State Machine Explanation
;;; =============================================================================

(defn explain-circuit-breaker
  "Explain how the circuit breaker works"
  []
  (println "
=== Circuit Breaker State Machine ===

  CLOSED (normal)
     |
     | error rate >= threshold
     v
  OPEN (blocking)
     |
     | timeout elapsed
     v
  HALF-OPEN (testing)
    /  \\
   /    \\
  v      v
CLOSED  OPEN
(success) (failure)

Configuration options:
  :error-threshold-pct  - Error percentage to trip (default 50%)
  :min-requests         - Minimum requests before evaluating (default 10)
  :open-duration-ms     - Time in OPEN before testing (default 30s)
  :half-open-requests   - Successes needed to close (default 3)
  :window-size-ms       - Sliding window for error rate (default 60s)
"))

;;; =============================================================================
;;; Basic Status Checking
;;; =============================================================================

(defn show-circuit-status
  "Show current circuit breaker status for all backends"
  []
  (println "\n=== Circuit Breaker Status ===")
  (let [status (cb/get-status)]
    (if (empty? status)
      (println "No circuits registered.")
      (doseq [circuit status]
        (let [{:keys [target-id proxy-name state error-count success-count]} circuit
              total (+ error-count success-count)
              error-rate (if (zero? total) 0.0 (* 100.0 (/ error-count total)))]
          (println (format "  %s (%s): %s"
                           target-id proxy-name (name state)))
          (println (format "    Requests: %d total (%d errors, %d successes)"
                           total error-count success-count))
          (println (format "    Error rate: %.1f%%" error-rate)))))))

(defn watch-circuits
  "Continuously monitor circuit breaker status.
   Press Ctrl+C to stop."
  []
  (println "\n=== Monitoring Circuit Breakers ===")
  (println "Press Ctrl+C to stop.\n")
  (loop []
    (let [status (cb/get-status)]
      (println (java.time.LocalTime/now))
      (if (empty? status)
        (println "  No circuits registered.")
        (doseq [{:keys [target-id state error-count success-count]} status]
          (println (format "  %s: %s (errors=%d, successes=%d)"
                           target-id (name state) error-count success-count))))
      (println "---")
      (Thread/sleep 2000)
      (recur))))

;;; =============================================================================
;;; Manual Control
;;; =============================================================================

(defn demo-manual-control
  "Demonstrate manual circuit control"
  []
  (println "\n=== Manual Control Demo ===")

  (let [target "127.0.0.1:9001"]
    ;; Check initial state
    (println "\n1. Initial state:")
    (println "   State:" (or (:state (cb/get-circuit target)) "not registered"))

    ;; Force open
    (println "\n2. Forcing circuit OPEN...")
    (cb/force-open! target)
    (println "   State:" (:state (cb/get-circuit target)))
    (println "   (Traffic stopped to this backend)")

    ;; Force close
    (Thread/sleep 1000)
    (println "\n3. Forcing circuit CLOSED...")
    (cb/force-close! target)
    (println "   State:" (:state (cb/get-circuit target)))
    (println "   (Traffic restored)")

    ;; Reset
    (println "\n4. Resetting circuit (clears counters)...")
    (cb/reset-circuit! target)
    (let [circuit (cb/get-circuit target)]
      (println "   State:" (:state circuit))
      (println "   Error count:" (:error-count circuit))
      (println "   Success count:" (:success-count circuit)))))

;;; =============================================================================
;;; Event Subscription
;;; =============================================================================

(defn demo-event-subscription
  "Demonstrate subscribing to circuit breaker events"
  []
  (println "\n=== Event Subscription Demo ===")
  (println "Subscribing to circuit breaker events...")

  (let [unsubscribe (cb/subscribe!
                      (fn [event]
                        (println (format "[%s] %s - %s"
                                         (java.time.LocalTime/now)
                                         (name (:type event))
                                         (:target-id event)))))]
    (println "Subscribed! Events will be printed as they occur.")
    (println "Run (demo-manual-control) to generate some events.")
    (println "Store the unsubscribe function to stop: (def unsub #'unsubscribe)")

    ;; Return the unsubscribe function
    unsubscribe))

;;; =============================================================================
;;; Weight Computation Examples
;;; =============================================================================

(defn show-weight-effects
  "Show how circuit breaker states affect traffic distribution"
  []
  (println "\n=== Weight Distribution Examples ===")

  (let [original [50 50]
        health [true true]
        drain [false false]]

    ;; All closed
    (println "\n1. All circuits CLOSED (normal):")
    (let [cb-states [:closed :closed]
          weights (weights/compute-all-weights original health drain cb-states)]
      (println "   Original weights: [50 50]")
      (println "   Effective weights:" (vec weights)))

    ;; One open
    (println "\n2. One circuit OPEN (blocking):")
    (let [cb-states [:closed :open]
          weights (weights/compute-all-weights original health drain cb-states)]
      (println "   Circuit states: [:closed :open]")
      (println "   Effective weights:" (vec weights))
      (println "   (All traffic goes to healthy backend)"))

    ;; One half-open
    (println "\n3. One circuit HALF-OPEN (testing):")
    (let [cb-states [:closed :half-open]
          weights (weights/compute-all-weights original health drain cb-states)]
      (println "   Circuit states: [:closed :half-open]")
      (println "   Effective weights:" (vec weights))
      (println "   (Half-open backend gets ~10% test traffic)"))

    ;; All open (graceful degradation)
    (println "\n4. All circuits OPEN (graceful degradation):")
    (let [cb-states [:open :open]
          weights (weights/compute-all-weights original health drain cb-states)]
      (println "   Circuit states: [:open :open]")
      (println "   Effective weights:" (vec weights))
      (println "   (Traffic continues to avoid total outage)"))))

;;; =============================================================================
;;; Simulated Failure Scenario
;;; =============================================================================

(defn simulate-failure-scenario
  "Walk through a failure and recovery scenario"
  []
  (println "\n=== Simulated Failure Scenario ===")
  (println "
This scenario walks through what happens when a backend fails and recovers.

Timeline:
  T+0s   : Backend healthy, circuit CLOSED
  T+10s  : Backend starts failing, errors accumulate
  T+20s  : Error threshold reached, circuit trips to OPEN
  T+50s  : Open duration expires, circuit moves to HALF-OPEN
  T+55s  : Backend recovered, test requests succeed
  T+60s  : Enough successes, circuit moves to CLOSED

Key behaviors:
  - During OPEN: No traffic to failing backend
  - During HALF-OPEN: ~10% test traffic
  - On recovery: Gradual traffic restoration

Configuration matters:
  - Higher error-threshold-pct = more tolerant of errors
  - Longer open-duration-ms = more time for backend to recover
  - Higher half-open-requests = more confidence before full restoration
"))

;;; =============================================================================
;;; API Reference
;;; =============================================================================

(defn show-circuit-breaker-api
  "Print available circuit breaker API functions"
  []
  (println "
=== Circuit Breaker API ===

Query status:
  (lb/get-circuit-status)               ; All circuits
  (lb/circuit-open? \"ip:port\")          ; Is circuit open?
  (lb/circuit-half-open? \"ip:port\")     ; Is circuit half-open?

Manual control:
  (lb/force-open-circuit! \"ip:port\")    ; Force circuit open
  (lb/force-close-circuit! \"ip:port\")   ; Force circuit closed
  (lb/reset-circuit! \"ip:port\")         ; Reset to initial state

Low-level access (lb.circuit-breaker namespace):
  (cb/get-circuit \"ip:port\")            ; Get circuit state map
  (cb/get-status)                         ; All circuits with details
  (cb/running?)                           ; Is system running?
  (cb/subscribe! callback)                ; Subscribe to events

Configuration (in settings map):
  :circuit-breaker
    {:enabled true
     :error-threshold-pct 50
     :min-requests 10
     :open-duration-ms 30000
     :half-open-requests 3
     :window-size-ms 60000}

Prometheus metrics:
  lb_circuit_breaker_state        ; 0=closed, 1=half-open, 2=open
  lb_circuit_breaker_error_rate   ; Current error rate (0.0-1.0)
"))

;;; =============================================================================
;;; Integration with Health Checks
;;; =============================================================================

(defn explain-health-integration
  "Explain how circuit breaker integrates with health checks"
  []
  (println "
=== Health Check Integration ===

The circuit breaker monitors health check results:

  Health Check Result   ->   Circuit Breaker Action
  ─────────────────────────────────────────────────
  :target-healthy       ->   Increment success count
  :target-unhealthy     ->   Increment error count

Error tracking:
  - Errors and successes counted in sliding window
  - Window resets after window-size-ms (default 60s)
  - Error rate = errors / (errors + successes)

Trip conditions:
  - Total requests >= min-requests
  - Error rate >= error-threshold-pct

Weight computation priority:
  1. Health check (unhealthy = 0 weight)
  2. Drain status (draining = 0 weight)
  3. Circuit breaker (open = 0, half-open = 10%)

All three systems work together for robust traffic management.
"))

;;; =============================================================================
;;; Main Demo
;;; =============================================================================

(defn -main
  "Run circuit breaker demos"
  []
  (if (lb/running?)
    (do
      (explain-circuit-breaker)
      (show-circuit-status)
      (show-weight-effects)
      (println "\n\nTo run other demos:")
      (println "  (demo-manual-control)")
      (println "  (demo-event-subscription)")
      (println "  (simulate-failure-scenario)")
      (println "  (watch-circuits)")
      (println "  (show-circuit-breaker-api)")
      (println "  (explain-health-integration)"))
    (println "
Load balancer not running. Initialize first:

  (def cfg (lb.config/parse-config examples.circuit-breaker/example-config))
  (lb/init! cfg)

Then run demos:
  (examples.circuit-breaker/-main)

When done:
  (lb/shutdown!)
")))

;;; =============================================================================
;;; Production Best Practices
;;; =============================================================================

(defn show-best-practices
  "Show production best practices for circuit breaker configuration"
  []
  (println "
=== Circuit Breaker Best Practices ===

1. Start Conservative
   Begin with higher thresholds and adjust based on observed behavior:
   {:error-threshold-pct 60
    :min-requests 20
    :open-duration-ms 60000}

2. Match Your SLOs
   If your SLO is 99.9% availability:
   - Set error-threshold-pct to 10-20%
   - Use shorter open-duration-ms for faster recovery

3. Consider Backend Recovery Time
   Set open-duration-ms based on how long backends typically
   need to recover (restart, scale up, etc.)

4. Use Prometheus Metrics
   Monitor circuit breaker state in Grafana:
   - Alert when circuits trip
   - Track error rates over time
   - Visualize recovery patterns

5. Test in Staging
   Deliberately fail backends to verify circuit breaker behavior
   before production deployment.

6. Combine with Health Checks
   Circuit breaker adds request-based failure detection
   on top of health check probing.

7. Plan for Graceful Degradation
   When all circuits open, traffic continues (degraded)
   rather than complete outage.
"))

;; Show usage on load
(println "
=== Circuit Breaker Examples Loaded ===

Quick start:
  (def cfg (lb.config/parse-config examples.circuit-breaker/example-config))
  (lb/init! cfg)
  (examples.circuit-breaker/-main)

Individual demos:
  (explain-circuit-breaker)
  (show-circuit-status)
  (demo-manual-control)
  (demo-event-subscription)
  (show-weight-effects)
  (simulate-failure-scenario)
  (watch-circuits)

References:
  (show-circuit-breaker-api)
  (explain-health-integration)
  (show-best-practices)
")
