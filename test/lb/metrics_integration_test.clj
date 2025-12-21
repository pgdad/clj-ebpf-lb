(ns lb.metrics-integration-test
  "Integration tests for the Prometheus metrics HTTP endpoint."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [clojure.string :as str]
            [lb.metrics :as metrics]
            [lb.metrics.collector :as collector]
            [lb.util :as util])
  (:import [java.net URI URL HttpURLConnection]
           [java.io BufferedReader InputStreamReader]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(def ^:private test-port 19100)

(defn metrics-server-fixture
  "Start and stop metrics server for integration tests."
  [f]
  ;; Ensure clean state
  (when (metrics/running?)
    (metrics/stop!))
  (metrics/clear-data-sources!)
  (metrics/reset-histograms!)
  (try
    (f)
    (finally
      (when (metrics/running?)
        (metrics/stop!))
      (metrics/clear-data-sources!)
      (metrics/reset-histograms!))))

(use-fixtures :each metrics-server-fixture)

;;; =============================================================================
;;; HTTP Client Helper
;;; =============================================================================

(defn- http-get
  "Perform HTTP GET request and return {:status code :body string :headers map}."
  [url-str]
  (let [url (URL. url-str)
        conn ^HttpURLConnection (.openConnection url)]
    (try
      (.setRequestMethod conn "GET")
      (.setConnectTimeout conn 5000)
      (.setReadTimeout conn 5000)
      (let [status (.getResponseCode conn)
            content-type (.getHeaderField conn "Content-Type")
            body (with-open [reader (BufferedReader.
                                      (InputStreamReader.
                                        (if (< status 400)
                                          (.getInputStream conn)
                                          (.getErrorStream conn))))]
                   (str/join "\n" (line-seq reader)))]
        {:status status
         :body body
         :content-type content-type})
      (finally
        (.disconnect conn)))))

;;; =============================================================================
;;; Basic Endpoint Tests
;;; =============================================================================

(deftest metrics-endpoint-test
  (testing "Metrics endpoint returns 200 OK"
    (metrics/start! {:port test-port})
    (Thread/sleep 100)  ; Give server time to start
    (let [response (http-get (str "http://localhost:" test-port "/metrics"))]
      (is (= 200 (:status response)))
      (is (str/includes? (:content-type response) "text/plain"))
      (is (str/includes? (:body response) "lb_up")))))

(deftest health-endpoint-test
  (testing "Health endpoint returns 200 OK"
    (metrics/start! {:port (inc test-port)})
    (Thread/sleep 100)
    (let [response (http-get (str "http://localhost:" (inc test-port) "/health"))]
      (is (= 200 (:status response)))
      (is (= "OK" (:body response))))))

(deftest custom-path-test
  (testing "Custom metrics path works"
    (metrics/start! {:port (+ test-port 2) :path "/custom/prometheus"})
    (Thread/sleep 100)
    (let [response (http-get (str "http://localhost:" (+ test-port 2) "/custom/prometheus"))]
      (is (= 200 (:status response)))
      (is (str/includes? (:body response) "lb_up")))))

;;; =============================================================================
;;; Content Type Tests
;;; =============================================================================

(deftest content-type-test
  (testing "Content-Type is correct for Prometheus"
    (metrics/start! {:port (+ test-port 3)})
    (Thread/sleep 100)
    (let [response (http-get (str "http://localhost:" (+ test-port 3) "/metrics"))]
      ;; Prometheus expects this exact content type
      (is (str/includes? (:content-type response) "text/plain"))
      (is (str/includes? (:content-type response) "version=0.0.4")))))

;;; =============================================================================
;;; Metric Content Tests
;;; =============================================================================

(deftest basic-metrics-content-test
  (testing "Basic metrics are present"
    (metrics/start! {:port (+ test-port 4)})
    (Thread/sleep 100)
    (let [response (http-get (str "http://localhost:" (+ test-port 4) "/metrics"))
          body (:body response)]
      ;; lb_up should always be present
      (is (str/includes? body "# HELP lb_up"))
      (is (str/includes? body "# TYPE lb_up gauge"))
      (is (str/includes? body "lb_up 1"))
      ;; lb_info should always be present
      (is (str/includes? body "# HELP lb_info"))
      (is (str/includes? body "lb_info{version=")))))

(deftest health-metrics-test
  (testing "Health status metrics are exported"
    ;; Register mock health data
    (metrics/register-data-sources!
      {:health-fn (fn []
                    [{:proxy-name "web"
                      :targets [{:target-id "10.0.0.1:8080" :status :healthy}
                                {:target-id "10.0.0.2:8080" :status :unhealthy}]}])})
    (metrics/start! {:port (+ test-port 5)})
    (Thread/sleep 100)
    (let [response (http-get (str "http://localhost:" (+ test-port 5) "/metrics"))
          body (:body response)]
      (is (str/includes? body "# HELP lb_backend_health"))
      (is (str/includes? body "# TYPE lb_backend_health gauge"))
      ;; Healthy target should be 1
      (is (re-find #"lb_backend_health\{.*target_ip=\"10.0.0.1\".*\} 1" body))
      ;; Unhealthy target should be 0
      (is (re-find #"lb_backend_health\{.*target_ip=\"10.0.0.2\".*\} 0" body)))))

(deftest histogram-metrics-test
  (testing "Histogram metrics are exported correctly"
    ;; Record some latency observations
    (metrics/record-health-check-latency! "api" "192.168.1.1:443" 0.005)
    (metrics/record-health-check-latency! "api" "192.168.1.1:443" 0.015)
    (metrics/record-health-check-latency! "api" "192.168.1.1:443" 0.008)

    (metrics/start! {:port (+ test-port 6)})
    (Thread/sleep 100)
    (let [response (http-get (str "http://localhost:" (+ test-port 6) "/metrics"))
          body (:body response)]
      ;; Should have histogram HELP and TYPE
      (is (str/includes? body "# HELP lb_health_check_latency_seconds"))
      (is (str/includes? body "# TYPE lb_health_check_latency_seconds histogram"))
      ;; Should have bucket lines
      (is (str/includes? body "lb_health_check_latency_seconds_bucket{"))
      (is (str/includes? body "le=\"+Inf\""))
      ;; Should have sum and count
      (is (str/includes? body "lb_health_check_latency_seconds_sum{"))
      (is (str/includes? body "lb_health_check_latency_seconds_count{")))))

(deftest connection-metrics-test
  (testing "Connection metrics are exported when conntrack is available"
    ;; Register mock conntrack data
    (metrics/register-data-sources!
      {:conntrack-fn (fn []
                       ;; Return mock connection records
                       [{:nat-dst-ip (util/ip-string->u32 "10.0.0.1")
                         :nat-dst-port 8080
                         :bytes-fwd 1000
                         :bytes-rev 500
                         :packets-fwd 10
                         :packets-rev 5}
                        {:nat-dst-ip (util/ip-string->u32 "10.0.0.1")
                         :nat-dst-port 8080
                         :bytes-fwd 2000
                         :bytes-rev 1000
                         :packets-fwd 20
                         :packets-rev 10}])})
    (metrics/start! {:port (+ test-port 7)})
    (Thread/sleep 100)
    (let [response (http-get (str "http://localhost:" (+ test-port 7) "/metrics"))
          body (:body response)]
      ;; Should have connection metrics
      (is (str/includes? body "lb_connections_active"))
      (is (str/includes? body "lb_bytes_total"))
      (is (str/includes? body "lb_packets_total"))
      ;; Should have direction labels
      (is (str/includes? body "direction=\"forward\""))
      (is (str/includes? body "direction=\"reverse\"")))))

;;; =============================================================================
;;; Prometheus Scraping Simulation Tests
;;; =============================================================================

(deftest multiple-scrapes-test
  (testing "Multiple scrapes work correctly"
    (metrics/start! {:port (+ test-port 8)})
    (Thread/sleep 100)

    ;; Simulate multiple Prometheus scrapes
    (dotimes [_ 5]
      (let [response (http-get (str "http://localhost:" (+ test-port 8) "/metrics"))]
        (is (= 200 (:status response)))
        (is (str/includes? (:body response) "lb_up"))))

    ;; Record some latency between scrapes
    (metrics/record-health-check-latency! "test" "1.1.1.1:80" 0.01)

    (let [response (http-get (str "http://localhost:" (+ test-port 8) "/metrics"))]
      (is (str/includes? (:body response) "lb_health_check_latency_seconds")))))

;;; =============================================================================
;;; DNS Status Metrics Tests
;;; =============================================================================

(deftest dns-metrics-test
  (testing "DNS resolution status metrics are exported"
    (metrics/register-data-sources!
      {:dns-fn (fn []
                 {"web-proxy" {:targets {"api.example.com" {:consecutive-failures 0}
                                         "db.example.com" {:consecutive-failures 3}}}})})
    (metrics/start! {:port (+ test-port 9)})
    (Thread/sleep 100)
    (let [response (http-get (str "http://localhost:" (+ test-port 9) "/metrics"))
          body (:body response)]
      (is (str/includes? body "lb_dns_resolution_status"))
      ;; Successful resolution should be 1
      (is (re-find #"lb_dns_resolution_status\{.*hostname=\"api.example.com\".*\} 1" body))
      ;; Failed resolution should be 0
      (is (re-find #"lb_dns_resolution_status\{.*hostname=\"db.example.com\".*\} 0" body)))))

;;; =============================================================================
;;; Error Handling Tests
;;; =============================================================================

(deftest data-source-error-handling-test
  (testing "Errors in data sources don't crash metrics endpoint"
    (metrics/register-data-sources!
      {:conntrack-fn (fn [] (throw (ex-info "Simulated error" {})))
       :health-fn (fn []
                    [{:proxy-name "web"
                      :targets [{:target-id "1.2.3.4:80" :status :healthy}]}])})
    (metrics/start! {:port (+ test-port 10)})
    (Thread/sleep 100)
    ;; Should still return 200 with available metrics
    (let [response (http-get (str "http://localhost:" (+ test-port 10) "/metrics"))]
      (is (= 200 (:status response)))
      ;; Basic metrics should still work
      (is (str/includes? (:body response) "lb_up"))
      ;; Health metrics should still work despite conntrack error
      (is (str/includes? (:body response) "lb_backend_health")))))
