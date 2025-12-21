(ns lb.circuit-breaker-test
  "Unit tests for circuit breaker pattern implementation."
  (:require [clojure.test :refer :all]
            [lb.circuit-breaker :as cb]
            [lb.config :as config]
            [lb.health.weights :as weights]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(def test-cb-config
  (config/->CircuitBreakerConfig
    true     ; enabled
    50       ; error-threshold-pct
    5        ; min-requests
    1000     ; open-duration-ms (1 second for fast tests)
    2        ; half-open-requests
    60000))  ; window-size-ms

(defn with-clean-state [f]
  "Reset circuit breaker state before each test."
  (reset! @#'cb/circuit-breaker-state
          {:circuits {}
           :running? false
           :event-unsubscribe nil
           :watcher nil
           :update-weights-fn nil
           :subscribers []})
  (f)
  (reset! @#'cb/circuit-breaker-state
          {:circuits {}
           :running? false
           :event-unsubscribe nil
           :watcher nil
           :update-weights-fn nil
           :subscribers []}))

(use-fixtures :each with-clean-state)

;;; =============================================================================
;;; Target ID Tests
;;; =============================================================================

(deftest test-target-id
  (testing "Create target ID from IP and port"
    (is (= "10.0.0.1:8080" (cb/target-id "10.0.0.1" 8080)))
    (is (= "192.168.1.1:443" (cb/target-id "192.168.1.1" 443)))))

(deftest test-parse-target-id
  (testing "Parse target ID string"
    (let [parsed (cb/parse-target-id "10.0.0.1:8080")]
      (is (= 8080 (:port parsed)))
      ;; IP is stored as u32
      (is (number? (:ip parsed))))))

;;; =============================================================================
;;; State Query Tests
;;; =============================================================================

(deftest test-running?
  (testing "Circuit breaker not running initially"
    (is (false? (cb/running?))))

  (testing "Circuit breaker running after start"
    (swap! @#'cb/circuit-breaker-state assoc :running? true)
    (is (true? (cb/running?)))))

(deftest test-get-circuit
  (testing "Get non-existent circuit returns nil"
    (is (nil? (cb/get-circuit "10.0.0.1:8080"))))

  (testing "Get registered circuit returns state"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)
    (let [circuit (cb/get-circuit "10.0.0.1:8080")]
      (is (some? circuit))
      (is (= :closed (:state circuit)))
      (is (= "test-proxy" (:proxy-name circuit))))))

;;; =============================================================================
;;; Registration Tests
;;; =============================================================================

(deftest test-register-target
  (testing "Register a target for circuit breaker tracking"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)
    (let [circuit (cb/get-circuit "10.0.0.1:8080")]
      (is (some? circuit))
      (is (= :closed (:state circuit)))
      (is (= 0 (:error-count circuit)))
      (is (= 0 (:success-count circuit)))
      (is (= "test-proxy" (:proxy-name circuit))))))

(deftest test-unregister-target
  (testing "Unregister removes circuit"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)
    (is (some? (cb/get-circuit "10.0.0.1:8080")))
    (cb/unregister-target! "10.0.0.1:8080")
    (is (nil? (cb/get-circuit "10.0.0.1:8080")))))

;;; =============================================================================
;;; State Transition Tests
;;; =============================================================================

(deftest test-closed-to-open-transition
  (testing "Circuit trips to OPEN when error threshold exceeded"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

    ;; Simulate 6 failures (above min-requests of 5, 100% error rate > 50%)
    (dotimes [_ 6]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))

    (let [circuit (cb/get-circuit "10.0.0.1:8080")]
      (is (= :open (:state circuit))))))

(deftest test-threshold-not-met
  (testing "Circuit stays closed when below threshold"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

    ;; 2 failures, 4 successes = 33% error rate < 50% threshold
    (dotimes [_ 2]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))
    (dotimes [_ 4]
      (#'cb/handle-closed-event "10.0.0.1:8080" true))

    (let [circuit (cb/get-circuit "10.0.0.1:8080")]
      (is (= :closed (:state circuit)))
      (is (= 2 (:error-count circuit)))
      (is (= 4 (:success-count circuit))))))

(deftest test-min-requests-not-met
  (testing "Circuit stays closed when min-requests not met"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

    ;; 3 failures, but min-requests is 5
    (dotimes [_ 3]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))

    (let [circuit (cb/get-circuit "10.0.0.1:8080")]
      (is (= :closed (:state circuit))))))

(deftest test-half-open-to-closed-transition
  (testing "Circuit closes after successful requests in half-open"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

    ;; Trip to open
    (dotimes [_ 6]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))
    (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))

    ;; Manually transition to half-open
    (#'cb/transition-to-half-open! "10.0.0.1:8080")
    (is (= :half-open (:state (cb/get-circuit "10.0.0.1:8080"))))

    ;; 2 successes (half-open-requests threshold)
    (#'cb/handle-half-open-event "10.0.0.1:8080" true)
    (is (= :half-open (:state (cb/get-circuit "10.0.0.1:8080"))))
    (#'cb/handle-half-open-event "10.0.0.1:8080" true)

    (is (= :closed (:state (cb/get-circuit "10.0.0.1:8080"))))))

(deftest test-half-open-to-open-on-failure
  (testing "Circuit returns to open on failure in half-open"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

    ;; Trip to open
    (dotimes [_ 6]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))

    ;; Transition to half-open
    (#'cb/transition-to-half-open! "10.0.0.1:8080")
    (is (= :half-open (:state (cb/get-circuit "10.0.0.1:8080"))))

    ;; Failure in half-open -> back to open
    (#'cb/handle-half-open-event "10.0.0.1:8080" false)
    (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))))

;;; =============================================================================
;;; Manual Control Tests
;;; =============================================================================

(deftest test-force-open
  (testing "Force circuit to open state"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)
    (is (= :closed (:state (cb/get-circuit "10.0.0.1:8080"))))

    (cb/force-open! "10.0.0.1:8080")
    (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))))

(deftest test-force-close
  (testing "Force circuit to closed state"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

    ;; Trip to open
    (dotimes [_ 6]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))
    (is (= :open (:state (cb/get-circuit "10.0.0.1:8080"))))

    ;; Force close
    (cb/force-close! "10.0.0.1:8080")
    (is (= :closed (:state (cb/get-circuit "10.0.0.1:8080"))))))

(deftest test-reset-circuit
  (testing "Reset circuit clears all counts"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

    ;; Accumulate some counts (2 errors, 2 successes = 50%, won't trip with > threshold)
    (dotimes [_ 2]
      (#'cb/handle-closed-event "10.0.0.1:8080" false))
    (dotimes [_ 2]
      (#'cb/handle-closed-event "10.0.0.1:8080" true))

    (let [before (cb/get-circuit "10.0.0.1:8080")]
      (is (= 2 (:error-count before)))
      (is (= 2 (:success-count before))))

    (cb/reset-circuit! "10.0.0.1:8080")

    (let [after (cb/get-circuit "10.0.0.1:8080")]
      (is (= :closed (:state after)))
      (is (= 0 (:error-count after)))
      (is (= 0 (:success-count after))))))

;;; =============================================================================
;;; Event Subscription Tests
;;; =============================================================================

(deftest test-subscribe
  (testing "Subscribe to circuit breaker events"
    (let [events (atom [])]
      (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)

      ;; Subscribe
      (let [unsubscribe (cb/subscribe! #(swap! events conj %))]

        ;; Trip the circuit
        (dotimes [_ 6]
          (#'cb/handle-closed-event "10.0.0.1:8080" false))

        ;; Should have received :circuit-opened event
        (is (some #(= :circuit-opened (:type %)) @events))

        ;; Unsubscribe
        (unsubscribe)
        (reset! events [])

        ;; Transition to half-open - should not receive event
        (#'cb/transition-to-half-open! "10.0.0.1:8080")
        (is (empty? @events))))))

;;; =============================================================================
;;; Weight Computation Tests
;;; =============================================================================

(deftest test-compute-circuit-breaker-weights
  (testing "Open circuit gets zero weight"
    (let [health-weights [50 50]
          cb-states [:closed :open]
          original-weights [50 50]
          result (weights/compute-circuit-breaker-weights
                   health-weights cb-states original-weights)]
      (is (= 100 (first result)))
      (is (= 0 (second result)))))

  (testing "Half-open circuit gets reduced weight"
    (let [health-weights [50 50]
          cb-states [:closed :half-open]
          original-weights [50 50]
          result (weights/compute-circuit-breaker-weights
                   health-weights cb-states original-weights)]
      ;; Half-open gets 10% of 50 = 5
      ;; Total = 50 + 5 = 55, so closed gets 50/55*100 = 91, half-open gets 5/55*100 = 9
      (is (> (first result) (second result)))
      (is (pos? (second result)))))

  (testing "All closed uses health weights"
    (let [health-weights [60 40]
          cb-states [:closed :closed]
          original-weights [50 50]
          result (weights/compute-circuit-breaker-weights
                   health-weights cb-states original-weights)]
      (is (= 60 (first result)))
      (is (= 40 (second result)))))

  (testing "All open keeps health weights (graceful degradation)"
    (let [health-weights [60 40]
          cb-states [:open :open]
          original-weights [50 50]
          result (weights/compute-circuit-breaker-weights
                   health-weights cb-states original-weights)]
      ;; Graceful degradation - keeps health weights
      (is (= 60 (first result)))
      (is (= 40 (second result))))))

(deftest test-compute-all-weights
  (testing "Combined health, drain, and circuit breaker weights"
    (let [original [50 50]
          health [true true]
          drain [false false]
          cb [:closed :open]
          result (weights/compute-all-weights original health drain cb)]
      ;; Second target is open, should get 0
      (is (= 100 (first result)))
      (is (= 0 (second result)))))

  (testing "Drain takes precedence over circuit breaker"
    (let [original [50 50]
          health [true true]
          drain [true false]  ; First is draining
          cb [:closed :closed]
          result (weights/compute-all-weights original health drain cb)]
      ;; First target is draining, should get 0
      (is (= 0 (first result)))
      (is (= 100 (second result))))))

;;; =============================================================================
;;; Status Tests
;;; =============================================================================

(deftest test-get-status
  (testing "Get status for all circuits"
    (cb/register-target! "proxy1" "10.0.0.1:8080" test-cb-config)
    (cb/register-target! "proxy2" "10.0.0.2:8080" test-cb-config)

    (let [status (cb/get-status)]
      (is (= 2 (count status)))
      (is (every? #(contains? % :target-id) status))
      (is (every? #(contains? % :state) status)))))

(deftest test-circuit-open?
  (testing "Check if circuit is open"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)
    (is (false? (cb/circuit-open? "10.0.0.1:8080")))

    (cb/force-open! "10.0.0.1:8080")
    (is (true? (cb/circuit-open? "10.0.0.1:8080")))))

(deftest test-circuit-half-open?
  (testing "Check if circuit is half-open"
    (cb/register-target! "test-proxy" "10.0.0.1:8080" test-cb-config)
    (is (false? (cb/circuit-half-open? "10.0.0.1:8080")))

    (cb/force-open! "10.0.0.1:8080")
    (#'cb/transition-to-half-open! "10.0.0.1:8080")
    (is (true? (cb/circuit-half-open? "10.0.0.1:8080")))))
