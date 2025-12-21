(ns lb.metrics-test
  "Unit tests for the Prometheus metrics system."
  (:require [clojure.test :refer [deftest testing is are use-fixtures]]
            [clojure.string :as str]
            [lb.metrics :as metrics]
            [lb.metrics.histograms :as histograms]
            [lb.metrics.collector :as collector]
            [lb.metrics.server :as server]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn metrics-cleanup-fixture
  "Clean up metrics state around tests."
  [f]
  (try
    (f)
    (finally
      (when (metrics/running?)
        (metrics/stop!))
      (metrics/clear-data-sources!)
      (metrics/reset-histograms!))))

(use-fixtures :each metrics-cleanup-fixture)

;;; =============================================================================
;;; Histogram Tests
;;; =============================================================================

(deftest histogram-creation-test
  (testing "Create histogram with default buckets"
    (let [h (histograms/new-histogram)]
      (is (some? h))
      (is (= 0 (:count h)))
      (is (= 0.0 (:sum h)))
      (is (= histograms/default-latency-buckets (:buckets h))))))

(deftest histogram-custom-buckets-test
  (testing "Create histogram with custom buckets"
    (let [custom-buckets [0.1 0.5 1.0 5.0]
          h (histograms/new-histogram custom-buckets)]
      (is (= custom-buckets (:buckets h))))))

(deftest histogram-observe-test
  (testing "Observe single value"
    (let [h (-> (histograms/new-histogram)
                (histograms/observe 0.05))]
      (is (= 1 (:count h)))
      (is (= 0.05 (:sum h)))))

  (testing "Observe multiple values"
    (let [h (-> (histograms/new-histogram)
                (histograms/observe 0.001)
                (histograms/observe 0.01)
                (histograms/observe 0.1)
                (histograms/observe 1.0))]
      (is (= 4 (:count h)))
      (is (< (Math/abs (- 1.111 (:sum h))) 0.0001)))))

(deftest histogram-bucket-counting-test
  (testing "Values are counted in correct buckets (cumulative)"
    (let [h (-> (histograms/new-histogram [0.1 0.5 1.0])
                (histograms/observe 0.05)   ; <= 0.1, 0.5, 1.0
                (histograms/observe 0.3)    ; <= 0.5, 1.0
                (histograms/observe 0.8)    ; <= 1.0
                (histograms/observe 2.0))   ; > 1.0 (only +Inf)
          counts (:counts h)]
      ;; Cumulative counts: bucket[0.1]=1, bucket[0.5]=2, bucket[1.0]=3
      (is (= [1 2 3] counts))
      (is (= 4 (:count h))))))

(deftest histogram-format-test
  (testing "Format histogram as Prometheus text"
    (let [h (-> (histograms/new-histogram [0.01 0.1 1.0])
                (histograms/observe 0.005)
                (histograms/observe 0.05))
          output (histograms/format-histogram h "test_latency" {:proxy "web"})]
      (is (str/includes? output "test_latency_bucket{proxy=\"web\",le=\"0.01\"} 1"))
      (is (str/includes? output "test_latency_bucket{proxy=\"web\",le=\"0.1\"} 2"))
      (is (str/includes? output "test_latency_bucket{proxy=\"web\",le=\"1.0\"} 2"))
      (is (str/includes? output "test_latency_bucket{proxy=\"web\",le=\"+Inf\"} 2"))
      (is (str/includes? output "test_latency_sum{proxy=\"web\"} 0.055"))
      (is (str/includes? output "test_latency_count{proxy=\"web\"} 2")))))

(deftest histogram-stats-test
  (testing "Get histogram statistics"
    (let [h (-> (histograms/new-histogram)
                (histograms/observe 0.1)
                (histograms/observe 0.2)
                (histograms/observe 0.3))
          stats (histograms/histogram-stats h)]
      (is (= 3 (:count stats)))
      ;; Use approximate comparison for floating point
      (is (< (Math/abs (- 0.6 (:sum stats))) 0.0001))
      (is (< (Math/abs (- 0.2 (:mean stats))) 0.0001)))))

;;; =============================================================================
;;; Collector Tests
;;; =============================================================================

(deftest collector-register-sources-test
  (testing "Register and clear data sources"
    (let [call-count (atom 0)
          test-fn (fn [] (swap! call-count inc) [])]
      (collector/register-sources! {:conntrack-fn test-fn})
      ;; Trigger collection to verify registration
      (collector/collect-all)
      (is (>= @call-count 1))
      (collector/clear-sources!)
      ;; Reset and verify clear works
      (reset! call-count 0)
      (collector/collect-all)
      (is (= 0 @call-count)))))

(deftest collector-health-latency-test
  (testing "Record health check latency"
    (collector/reset-histograms!)
    (collector/record-health-latency! "web-proxy" "10.0.0.1:8080" 0.015)
    (collector/record-health-latency! "web-proxy" "10.0.0.1:8080" 0.020)
    (collector/record-health-latency! "web-proxy" "10.0.0.2:8080" 0.010)

    (let [output (collector/collect-all)]
      (is (str/includes? output "lb_health_check_latency_seconds"))
      (is (str/includes? output "proxy_name=\"web-proxy\""))
      (is (str/includes? output "target_id=\"10.0.0.1:8080\"")))))

(deftest collector-collect-up-test
  (testing "Collect lb_up metric"
    (let [output (collector/collect-all)]
      (is (str/includes? output "# HELP lb_up"))
      (is (str/includes? output "# TYPE lb_up gauge"))
      (is (str/includes? output "lb_up 1")))))

(deftest collector-collect-info-test
  (testing "Collect lb_info metric"
    (let [output (collector/collect-all)]
      (is (str/includes? output "# HELP lb_info"))
      (is (str/includes? output "# TYPE lb_info gauge"))
      (is (str/includes? output "lb_info{version=")))))

;;; =============================================================================
;;; Server Tests
;;; =============================================================================

(deftest server-start-stop-test
  (testing "Start and stop metrics server"
    (is (not (server/running?)))
    (is (server/start! {:port 19090}))
    (is (server/running?))
    (is (server/stop!))
    (is (not (server/running?)))))

(deftest server-double-start-test
  (testing "Double start returns false"
    (is (server/start! {:port 19091}))
    (is (not (server/start! {:port 19091})))  ; Already running
    (server/stop!)))

(deftest server-double-stop-test
  (testing "Double stop returns false"
    (server/start! {:port 19092})
    (is (server/stop!))
    (is (not (server/stop!)))))  ; Already stopped

(deftest server-status-test
  (testing "Get server status"
    (is (nil? (server/get-status)))
    (server/start! {:port 19093 :path "/custom-metrics"})
    (let [status (server/get-status)]
      (is (:running status))
      (is (= 19093 (:port status)))
      (is (= "/custom-metrics" (:path status)))
      (is (= "http://localhost:19093/custom-metrics" (:url status))))
    (server/stop!)))

;;; =============================================================================
;;; Public API Tests
;;; =============================================================================

(deftest public-api-lifecycle-test
  (testing "Public API lifecycle functions"
    (is (not (metrics/running?)))
    (is (metrics/start! {:port 19094}))
    (is (metrics/running?))
    (let [status (metrics/get-status)]
      (is (some? status))
      (is (= 19094 (:port status))))
    (metrics/stop!)
    (is (not (metrics/running?)))))

(deftest public-api-data-sources-test
  (testing "Register data sources via public API"
    (let [health-called (atom false)]
      (metrics/register-data-sources!
        {:health-fn (fn []
                      (reset! health-called true)
                      [{:proxy-name "test"
                        :targets [{:target-id "1.2.3.4:80"
                                   :status :healthy}]}])})
      (metrics/collect-metrics)
      (is @health-called)
      (metrics/clear-data-sources!))))

(deftest public-api-histogram-test
  (testing "Record health check latency via public API"
    (metrics/reset-histograms!)
    (metrics/record-health-check-latency! "my-proxy" "10.0.0.1:443" 0.025)
    (let [output (metrics/collect-metrics)]
      (is (str/includes? output "lb_health_check_latency_seconds"))
      (is (str/includes? output "my-proxy")))))

;;; =============================================================================
;;; Prometheus Format Validation Tests
;;; =============================================================================

(deftest prometheus-format-test
  (testing "Output follows Prometheus text format"
    (let [output (metrics/collect-metrics)
          lines (str/split-lines output)]
      ;; Every metric should have HELP and TYPE
      (is (some #(str/starts-with? % "# HELP lb_up") lines))
      (is (some #(str/starts-with? % "# TYPE lb_up gauge") lines))
      ;; Metric values should be numbers
      (let [metric-lines (filter #(and (not (str/starts-with? % "#"))
                                        (not (str/blank? %))) lines)]
        (doseq [line metric-lines]
          ;; Should end with a number
          (is (re-matches #".*\s[\d.]+$" line)
              (str "Line should end with number: " line)))))))

(deftest label-escaping-test
  (testing "Labels are properly quoted"
    (metrics/register-data-sources!
      {:health-fn (fn []
                    [{:proxy-name "web-app"
                      :targets [{:target-id "10.0.0.1:8080"
                                 :status :healthy}]}])})
    (let [output (metrics/collect-metrics)]
      ;; Labels should be in key="value" format
      (is (re-find #"proxy_name=\"web-app\"" output)))))
