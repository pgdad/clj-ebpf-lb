(ns lb.latency-test
  "Unit tests for latency tracking module."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [lb.latency :as latency]
            [lb.metrics.histograms :as histograms]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn reset-fixture [f]
  (latency/reset-histograms!)
  (f)
  (latency/reset-histograms!))

(use-fixtures :each reset-fixture)

;;; =============================================================================
;;; Record Latency Tests
;;; =============================================================================

(deftest record-latency-test
  (testing "Recording latency creates histogram"
    (latency/record-latency! "test-proxy" "10.0.0.1:8080" 0.5)
    (let [h (latency/get-histogram "test-proxy" "10.0.0.1:8080")]
      (is (some? h))
      (is (= 1 (:count h)))
      (is (= 0.5 (:sum h)))))

  (testing "Recording multiple latencies accumulates"
    (latency/record-latency! "test-proxy" "10.0.0.1:8080" 1.0)
    (latency/record-latency! "test-proxy" "10.0.0.1:8080" 2.0)
    (let [h (latency/get-histogram "test-proxy" "10.0.0.1:8080")]
      (is (= 3 (:count h)))  ; 1 from previous test + 2 new
      (is (= 3.5 (:sum h)))))  ; 0.5 + 1.0 + 2.0

  (testing "Different backends have separate histograms"
    (latency/record-latency! "test-proxy" "10.0.0.2:8080" 5.0)
    (let [h1 (latency/get-histogram "test-proxy" "10.0.0.1:8080")
          h2 (latency/get-histogram "test-proxy" "10.0.0.2:8080")]
      (is (some? h1))
      (is (some? h2))
      (is (not= (:count h1) (:count h2)))))

  (testing "Ignores invalid latencies"
    (let [before-count (:count (latency/get-histogram "test-proxy" "10.0.0.1:8080"))]
      (latency/record-latency! nil "10.0.0.1:8080" 1.0)
      (latency/record-latency! "test-proxy" nil 1.0)
      (latency/record-latency! "test-proxy" "10.0.0.1:8080" nil)
      (latency/record-latency! "test-proxy" "10.0.0.1:8080" -1.0)
      (latency/record-latency! "test-proxy" "10.0.0.1:8080" 0)
      (let [after-count (:count (latency/get-histogram "test-proxy" "10.0.0.1:8080"))]
        (is (= before-count after-count))))))

;;; =============================================================================
;;; Get Percentiles Tests
;;; =============================================================================

(deftest get-percentiles-test
  (testing "Returns nil for non-existent histogram"
    (is (nil? (latency/get-percentiles "nonexistent" "10.0.0.1:8080"))))

  (testing "Returns percentiles for existing histogram"
    (doseq [v [0.1 0.2 0.5 1.0 2.0 5.0]]
      (latency/record-latency! "perc-test" "10.0.0.1:8080" v))
    (let [stats (latency/get-percentiles "perc-test" "10.0.0.1:8080")]
      (is (some? stats))
      (is (contains? stats :p50))
      (is (contains? stats :p95))
      (is (contains? stats :p99))
      (is (contains? stats :mean))
      (is (contains? stats :count))
      (is (= 6 (:count stats))))))

;;; =============================================================================
;;; Get All Histograms Tests
;;; =============================================================================

(deftest get-all-histograms-test
  (testing "Returns empty map when no histograms"
    (latency/reset-histograms!)
    (is (empty? (latency/get-all-histograms))))

  (testing "Returns all recorded histograms"
    (latency/record-latency! "proxy1" "10.0.0.1:8080" 1.0)
    (latency/record-latency! "proxy2" "10.0.0.2:8080" 2.0)
    (let [all (latency/get-all-histograms)]
      (is (= 2 (count all)))
      (is (contains? all ["proxy1" "10.0.0.1:8080"]))
      (is (contains? all ["proxy2" "10.0.0.2:8080"])))))

;;; =============================================================================
;;; Metrics Integration Tests
;;; =============================================================================

(deftest get-histograms-for-metrics-test
  (testing "Converts target-id to ip:port format for metrics"
    (latency/record-latency! "web" "192.168.1.1:80" 0.5)
    (let [metrics (latency/get-histograms-for-metrics)]
      (is (= 1 (count metrics)))
      (is (contains? metrics ["web" "192.168.1.1" "80"])))))

;;; =============================================================================
;;; Status Tests
;;; =============================================================================

(deftest get-status-test
  (testing "Returns status with histogram count"
    (latency/reset-histograms!)
    (latency/record-latency! "status-test" "10.0.0.1:8080" 1.0)
    (let [status (latency/get-status)]
      (is (= 1 (:histogram-count status)))
      (is (contains? (:histograms status) ["status-test" "10.0.0.1:8080"])))))

;;; =============================================================================
;;; Reset Tests
;;; =============================================================================

(deftest reset-histograms-test
  (testing "Clears all histogram data"
    (latency/record-latency! "reset-test" "10.0.0.1:8080" 1.0)
    (is (= 1 (count (latency/get-all-histograms))))
    (latency/reset-histograms!)
    (is (empty? (latency/get-all-histograms)))))
