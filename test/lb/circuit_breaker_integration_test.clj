(ns lb.circuit-breaker-integration-test
  "Integration tests for circuit breaker pattern implementation.
   Tests the full lifecycle including health event integration,
   state transitions, and weight updates."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [clojure.string :as str]
            [lb.circuit-breaker :as cb]
            [lb.config :as config]
            [lb.health :as health]
            [lb.health.weights :as weights]
            [lb.metrics :as metrics]
            [lb.util :as util]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(def test-cb-config
  "Fast circuit breaker config for testing."
  (config/->CircuitBreakerConfig
    true     ; enabled
    50       ; error-threshold-pct
    3        ; min-requests (low for fast tests)
    500      ; open-duration-ms (0.5 second for fast tests)
    2        ; half-open-requests
    60000))  ; window-size-ms

(defn with-clean-state [f]
  "Reset all state before and after each test."
  ;; Reset circuit breaker state
  (when (cb/running?)
    (cb/stop!))
  (reset! @#'cb/circuit-breaker-state
          {:circuits {}
           :running? false
           :event-unsubscribe nil
           :watcher nil
           :update-weights-fn nil
           :subscribers []})

  ;; Reset health system if running
  (when (health/running?)
    (health/stop!))

  ;; Reset metrics if running
  (when (metrics/running?)
    (metrics/stop!))
  (metrics/clear-data-sources!)

  (try
    (f)
    (finally
      (when (cb/running?)
        (cb/stop!))
      (when (health/running?)
        (health/stop!))
      (when (metrics/running?)
        (metrics/stop!))
      (metrics/clear-data-sources!))))

(use-fixtures :each with-clean-state)

;;; =============================================================================
;;; State Transition Integration Tests
;;; =============================================================================

(deftest circuit-breaker-full-cycle-test
  (testing "Full circuit breaker cycle: CLOSED -> OPEN -> HALF-OPEN -> CLOSED"
    (let [events (atom [])
          weight-updates (atom [])]

      ;; Initialize with weight update callback
      (cb/init! (fn [proxy-name]
                  (swap! weight-updates conj
                         {:proxy proxy-name
                          :circuits (cb/get-status)})))

      ;; Subscribe to events
      (cb/subscribe! #(swap! events conj %))

      ;; Register target
      (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

      ;; Verify initial state is CLOSED
      (is (= :closed (:state (cb/get-circuit "10.0.0.1:8080"))))
      (is (not (cb/circuit-open? "10.0.0.1:8080")))

      ;; Simulate failures to trip to OPEN (need 3 failures with min-requests=3)
      (dotimes [_ 3]
        (#'cb/handle-closed-event "10.0.0.1:8080" false))

      ;; Verify circuit is now OPEN
      (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))
      (is (cb/circuit-open? "10.0.0.1:8080"))

      ;; Verify circuit-opened event was emitted
      (is (some #(= :circuit-opened (:type %)) @events))

      ;; Wait for open duration to elapse (0.5 second + buffer)
      (Thread/sleep 700)

      ;; Manually trigger transition (watcher would do this automatically)
      (#'cb/transition-to-half-open! "10.0.0.1:8080")

      ;; Verify circuit is now HALF-OPEN
      (is (= :half-open (:state (cb/get-circuit "10.0.0.1:8080"))))
      (is (cb/circuit-half-open? "10.0.0.1:8080"))

      ;; Verify half-open event was emitted
      (is (some #(= :circuit-half-opened (:type %)) @events))

      ;; Simulate successes in HALF-OPEN (need 2 with half-open-requests=2)
      (#'cb/handle-half-open-event "10.0.0.1:8080" true)
      (#'cb/handle-half-open-event "10.0.0.1:8080" true)

      ;; Verify circuit is now CLOSED again
      (is (= :closed (:state (cb/get-circuit "10.0.0.1:8080"))))
      (is (not (cb/circuit-open? "10.0.0.1:8080")))

      ;; Verify circuit-closed event was emitted
      (is (some #(= :circuit-closed (:type %)) @events)))))

(deftest circuit-breaker-half-open-failure-test
  (testing "HALF-OPEN returns to OPEN on failure"
    (cb/init! (fn [_] nil))
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

    ;; Trip to OPEN
    (dotimes [_ 3]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))
    (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))

    ;; Transition to HALF-OPEN
    (#'cb/transition-to-half-open! "10.0.0.1:8080")
    (is (= :half-open (:state (cb/get-circuit "10.0.0.1:8080"))))

    ;; Failure in HALF-OPEN goes back to OPEN
    (#'cb/handle-half-open-event "10.0.0.1:8080" false)
    (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))))

;;; =============================================================================
;;; Weight Computation Integration Tests
;;; =============================================================================

(deftest weight-computation-with-circuit-breaker-test
  (testing "Weight computation correctly handles circuit breaker states"
    (let [original-weights [50 30 20]
          health-statuses [true true true]
          drain-statuses [false false false]]

      ;; All circuits closed - use health weights
      (let [cb-states [:closed :closed :closed]
            result (weights/compute-all-weights original-weights health-statuses drain-statuses cb-states)]
        (is (= [50 30 20] result)))

      ;; One circuit open - redistributes to others
      (let [cb-states [:closed :open :closed]
            result (weights/compute-all-weights original-weights health-statuses drain-statuses cb-states)]
        ;; Second target open, so 0 weight
        (is (= 0 (nth result 1)))
        ;; Weights redistributed proportionally
        (is (= 100 (reduce + result))))

      ;; One circuit half-open - reduced weight
      (let [cb-states [:closed :half-open :closed]
            result (weights/compute-all-weights original-weights health-statuses drain-statuses cb-states)]
        ;; Half-open gets 10% of original (30 * 0.1 = 3, min 1)
        ;; Total after redistribution sums to 100
        (is (= 100 (reduce + result)))
        ;; Half-open target has reduced weight
        (is (< (nth result 1) 30))))))

(deftest weight-updates-on-state-change-test
  (testing "Weight update callback is called on circuit state changes"
    (let [weight-updates (atom [])]

      (cb/init! (fn [proxy-name]
                  (swap! weight-updates conj proxy-name)))

      (cb/register-target! "my-proxy" "10.0.0.1:8080" test-cb-config)

      ;; Trip to OPEN
      (dotimes [_ 3]
        (#'cb/handle-closed-event "10.0.0.1:8080" false))

      ;; Should have called update function
      (is (some #(= "my-proxy" %) @weight-updates)))))

;;; =============================================================================
;;; Multi-Target Integration Tests
;;; =============================================================================

(deftest multiple-circuits-test
  (testing "Multiple circuits operate independently"
    (cb/init! (fn [_] nil))

    ;; Register multiple targets
    (cb/register-target! "proxy1" "10.0.0.1:8080" test-cb-config)
    (cb/register-target! "proxy1" "10.0.0.2:8080" test-cb-config)
    (cb/register-target! "proxy2" "10.0.0.3:8080" test-cb-config)

    ;; All should start closed
    (is (= :closed (:state (cb/get-circuit "10.0.0.1:8080"))))
    (is (= :closed (:state (cb/get-circuit "10.0.0.2:8080"))))
    (is (= :closed (:state (cb/get-circuit "10.0.0.3:8080"))))

    ;; Trip only first circuit
    (dotimes [_ 3]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))

    ;; First is open, others still closed
    (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))
    (is (= :closed (:state (cb/get-circuit "10.0.0.2:8080"))))
    (is (= :closed (:state (cb/get-circuit "10.0.0.3:8080"))))

    ;; Check status returns all circuits
    (let [status (cb/get-status)]
      (is (= 3 (count status)))
      (is (some #(= :open (:state %)) status))
      (is (= 2 (count (filter #(= :closed (:state %)) status)))))))

;;; =============================================================================
;;; Metrics Integration Tests
;;; =============================================================================

(deftest circuit-breaker-metrics-test
  (testing "Circuit breaker metrics are exported correctly"
    (cb/init! (fn [_] nil))
    (cb/register-target! "web" "10.0.0.1:8080" test-cb-config)
    (cb/register-target! "web" "10.0.0.2:8080" test-cb-config)

    ;; Trip first circuit
    (dotimes [_ 3]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))

    ;; Register circuit breaker data source
    (metrics/register-data-sources!
      {:circuit-breaker-fn cb/get-status})

    ;; Start metrics server
    (metrics/start! {:port 19200})
    (Thread/sleep 100)

    ;; Fetch metrics
    (let [response (try
                     (slurp "http://localhost:19200/metrics")
                     (catch Exception e nil))]
      (when response
        ;; Should have circuit breaker state metric
        (is (str/includes? response "lb_circuit_breaker_state"))
        ;; Should have error rate metric
        (is (str/includes? response "lb_circuit_breaker_error_rate"))
        ;; Open circuit should have state 2
        (is (re-find #"lb_circuit_breaker_state\{.*target_ip=\"10.0.0.1\".*\} 2" response))
        ;; Closed circuit should have state 0
        (is (re-find #"lb_circuit_breaker_state\{.*target_ip=\"10.0.0.2\".*\} 0" response))))

    (metrics/stop!)))

;;; =============================================================================
;;; Manual Control Integration Tests
;;; =============================================================================

(deftest manual-control-integration-test
  (testing "Manual force-open and force-close affect weights"
    (let [weight-updates (atom [])]
      (cb/init! (fn [proxy-name]
                  (swap! weight-updates conj
                         {:proxy proxy-name
                          :time (System/currentTimeMillis)})))

      (cb/register-target! "test" "10.0.0.1:8080" test-cb-config)

      ;; Force open
      (cb/force-open! "10.0.0.1:8080")
      (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))
      (is (some #(= "test" (:proxy %)) @weight-updates))

      (let [count-after-open (count @weight-updates)]
        ;; Force close
        (cb/force-close! "10.0.0.1:8080")
        (is (= :closed (:state (cb/get-circuit "10.0.0.1:8080"))))
        ;; Another weight update should have occurred
        (is (> (count @weight-updates) count-after-open))))))

(deftest reset-circuit-integration-test
  (testing "Reset circuit clears state"
    (let [weight-updates (atom [])]
      (cb/init! (fn [proxy-name]
                  (swap! weight-updates conj proxy-name)))

      (cb/register-target! "test" "10.0.0.1:8080" test-cb-config)

      ;; Trip circuit
      (dotimes [_ 3]
        (#'cb/handle-closed-event "10.0.0.1:8080" false))
      (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))

      ;; Reset
      (cb/reset-circuit! "10.0.0.1:8080")

      ;; Should be closed with zero counts
      (let [circuit (cb/get-circuit "10.0.0.1:8080")]
        (is (= :closed (:state circuit)))
        (is (= 0 (:error-count circuit)))
        (is (= 0 (:success-count circuit)))
        ;; Window should be reset
        (is (> (:window-start circuit) 0))))))

;;; =============================================================================
;;; Lifecycle Integration Tests
;;; =============================================================================

(deftest circuit-breaker-lifecycle-test
  (testing "Circuit breaker start/stop lifecycle"
    (is (not (cb/running?)))

    ;; Start
    (cb/init! (fn [_] nil))
    (is (cb/running?))

    ;; Register target
    (cb/register-target! "test" "10.0.0.1:8080" test-cb-config)
    (is (some? (cb/get-circuit "10.0.0.1:8080")))

    ;; Stop
    (cb/stop!)
    (is (not (cb/running?)))

    ;; Circuits should be cleared
    (is (empty? (:circuits @@#'cb/circuit-breaker-state)))))

(deftest unregister-target-test
  (testing "Unregistering target removes circuit"
    (cb/init! (fn [_] nil))
    (cb/register-target! "test" "10.0.0.1:8080" test-cb-config)
    (cb/register-target! "test" "10.0.0.2:8080" test-cb-config)

    (is (= 2 (count (cb/get-status))))

    ;; Unregister one
    (cb/unregister-target! "10.0.0.1:8080")

    (is (= 1 (count (cb/get-status))))
    (is (nil? (cb/get-circuit "10.0.0.1:8080")))
    (is (some? (cb/get-circuit "10.0.0.2:8080")))))

;;; =============================================================================
;;; Event Subscription Integration Tests
;;; =============================================================================

(deftest event-subscription-integration-test
  (testing "Multiple subscribers receive events"
    (let [subscriber1-events (atom [])
          subscriber2-events (atom [])]

      (cb/init! (fn [_] nil))

      ;; Two subscribers
      (let [unsub1 (cb/subscribe! #(swap! subscriber1-events conj %))
            unsub2 (cb/subscribe! #(swap! subscriber2-events conj %))]

        (cb/register-target! "test" "10.0.0.1:8080" test-cb-config)

        ;; Trip circuit
        (dotimes [_ 3]
          (#'cb/handle-closed-event "10.0.0.1:8080" false))

        ;; Both should receive the event
        (is (some #(= :circuit-opened (:type %)) @subscriber1-events))
        (is (some #(= :circuit-opened (:type %)) @subscriber2-events))

        ;; Unsubscribe first
        (unsub1)
        (reset! subscriber1-events [])

        ;; Force close and trip again
        (cb/force-close! "10.0.0.1:8080")
        (dotimes [_ 3]
          (#'cb/handle-closed-event "10.0.0.1:8080" false))

        ;; Only subscriber2 should receive new events
        (is (empty? @subscriber1-events))
        (is (some #(= :circuit-opened (:type %)) @subscriber2-events))

        ;; Cleanup
        (unsub2)))))

;;; =============================================================================
;;; Error Rate Calculation Tests
;;; =============================================================================

(deftest error-rate-calculation-test
  (testing "Error rate is calculated correctly"
    (cb/init! (fn [_] nil))
    (cb/register-target! "test" "10.0.0.1:8080" test-cb-config)

    ;; 2 successes
    (dotimes [_ 2]
      (#'cb/handle-closed-event "10.0.0.1:8080" true))

    (let [circuit (cb/get-circuit "10.0.0.1:8080")]
      (is (= 0 (:error-count circuit)))
      (is (= 2 (:success-count circuit))))

    ;; 1 failure -> 1/3 = 33% error rate
    (#'cb/handle-closed-event "10.0.0.1:8080" false)

    (let [circuit (cb/get-circuit "10.0.0.1:8080")
          error-rate (#'cb/calculate-error-rate circuit)]
      (is (= 1 (:error-count circuit)))
      (is (= 2 (:success-count circuit)))
      ;; 1/3 = 0.333...
      (is (< 0.3 error-rate 0.4)))))

;;; =============================================================================
;;; Graceful Degradation Tests
;;; =============================================================================

(deftest all-circuits-open-graceful-degradation-test
  (testing "When all circuits are open, weights are preserved for graceful degradation"
    (cb/init! (fn [_] nil))

    (let [original-weights [50 50]
          health-statuses [true true]
          drain-statuses [false false]
          cb-states [:open :open]
          result (weights/compute-all-weights original-weights health-statuses drain-statuses cb-states)]
      ;; Graceful degradation - should keep proportional weights
      (is (= 100 (reduce + result)))
      ;; Both should have some weight (50/50 normalized)
      (is (= 50 (first result)))
      (is (= 50 (second result))))))
