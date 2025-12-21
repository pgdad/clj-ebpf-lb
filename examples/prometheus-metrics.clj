;; Prometheus Metrics Export Example
;;
;; This file demonstrates how to use the Prometheus metrics export feature
;; for monitoring the load balancer with Prometheus, Grafana, or other tools.
;;
;; Run with:
;;   sudo clojure -M:dev
;;   (load-file "examples/prometheus-metrics.clj")
;;
;; Prerequisites:
;;   - None for standalone metrics server
;;   - Running load balancer for full integration

(ns examples.prometheus-metrics
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.metrics :as metrics]
            [lb.metrics.collector :as collector]
            [lb.metrics.histograms :as histograms]
            [lb.health :as health]
            [clojure.pprint :refer [pprint]]
            [clojure.string :as str])
  (:import [java.net URL HttpURLConnection]
           [java.io BufferedReader InputStreamReader]))

;; =============================================================================
;; 1. Standalone Metrics Server (No Load Balancer)
;; =============================================================================

(comment
  ;; Start the metrics server standalone - useful for testing
  (metrics/start! {:port 9090 :path "/metrics"})

  ;; Check if running
  (metrics/running?)
  ;; => true

  ;; Get server status
  (pprint (metrics/get-status))
  ;; => {:running true
  ;;     :port 9090
  ;;     :path "/metrics"
  ;;     :url "http://localhost:9090/metrics"}

  ;; Fetch metrics via HTTP (or use curl http://localhost:9090/metrics)
  (println (metrics/collect-metrics))
  ;; => # HELP lb_up Whether the load balancer is running (1=up, 0=down)
  ;;    # TYPE lb_up gauge
  ;;    lb_up 1
  ;;    ...

  ;; Stop the server
  (metrics/stop!))

;; =============================================================================
;; 2. Full Integration with Load Balancer
;; =============================================================================

(comment
  ;; Configuration with metrics enabled
  (def cfg
    {:proxies
     [{:name "web"
       :listen {:interfaces ["eth0"] :port 8080}
       :default-target
       [{:ip "10.0.0.1" :port 8080 :weight 50
         :health-check {:type :http :path "/health" :interval-ms 5000}}
        {:ip "10.0.0.2" :port 8080 :weight 50
         :health-check {:type :http :path "/health" :interval-ms 5000}}]}]
     :settings
     {:health-check-enabled true
      :metrics {:enabled true       ; Enable metrics
                :port 9090          ; Metrics port (default 9090)
                :path "/metrics"}}})  ; Endpoint path (default "/metrics")

  ;; Initialize - metrics server starts automatically
  (lb/init! (config/parse-config cfg))

  ;; The metrics endpoint is now available at http://localhost:9090/metrics
  ;; Prometheus can scrape this endpoint

  ;; Shutdown - metrics server stops automatically
  (lb/shutdown!))

;; =============================================================================
;; 3. Manual Data Source Registration
;; =============================================================================

(comment
  ;; You can register custom data sources for metrics collection
  ;; This is done automatically by lb/init! but can be done manually

  ;; Start metrics server
  (metrics/start! {:port 9090})

  ;; Register mock data sources (for testing)
  (metrics/register-data-sources!
    {:health-fn (fn []
                  ;; Return health status for all proxies
                  [{:proxy-name "web"
                    :targets [{:target-id "10.0.0.1:8080" :status :healthy}
                              {:target-id "10.0.0.2:8080" :status :unhealthy}]}])

     :conntrack-fn (fn []
                     ;; Return active connections
                     [{:nat-dst-ip 0x0A000001  ; 10.0.0.1
                       :nat-dst-port 8080
                       :bytes-fwd 50000
                       :bytes-rev 25000
                       :packets-fwd 100
                       :packets-rev 50}])

     :dns-fn (fn []
               ;; Return DNS resolution status
               {"web" {:targets {"backend.local" {:consecutive-failures 0}}}})})

  ;; Now metrics will include this data
  (println (metrics/collect-metrics))

  ;; Clear data sources
  (metrics/clear-data-sources!)
  (metrics/stop!))

;; =============================================================================
;; 4. Recording Health Check Latency
;; =============================================================================

(comment
  ;; Health check latency is recorded automatically when health checks run
  ;; You can also record manually for testing

  (metrics/start! {:port 9090})

  ;; Record some latency observations (in seconds, not milliseconds!)
  (metrics/record-health-check-latency! "web" "10.0.0.1:8080" 0.005)  ; 5ms
  (metrics/record-health-check-latency! "web" "10.0.0.1:8080" 0.008)  ; 8ms
  (metrics/record-health-check-latency! "web" "10.0.0.1:8080" 0.003)  ; 3ms
  (metrics/record-health-check-latency! "web" "10.0.0.2:8080" 0.015)  ; 15ms

  ;; View the histogram in metrics output
  (let [output (metrics/collect-metrics)]
    (doseq [line (str/split-lines output)]
      (when (str/includes? line "health_check_latency")
        (println line))))
  ;; Output includes bucket counts, sum, and count

  ;; Reset histograms if needed
  (metrics/reset-histograms!)
  (metrics/stop!))

;; =============================================================================
;; 5. Working with Histograms Directly
;; =============================================================================

(comment
  ;; The histogram implementation can be used independently

  ;; Create a new histogram with default buckets
  (def h (histograms/new-histogram))
  (pprint h)
  ;; => {:buckets [0.001 0.005 0.01 0.025 0.05 0.1 0.25 0.5 1.0 2.5 5.0 10.0]
  ;;     :counts [0 0 0 0 0 0 0 0 0 0 0 0]
  ;;     :sum 0.0
  ;;     :count 0}

  ;; Create with custom buckets
  (def h-custom (histograms/new-histogram [0.01 0.05 0.1 0.5 1.0]))

  ;; Observe values
  (def h2 (-> (histograms/new-histogram [0.01 0.05 0.1])
              (histograms/observe 0.005)   ; < 0.01
              (histograms/observe 0.03)    ; < 0.05
              (histograms/observe 0.08)    ; < 0.1
              (histograms/observe 0.2)))   ; > all buckets

  ;; Get statistics
  (pprint (histograms/histogram-stats h2))
  ;; => {:count 4
  ;;     :sum 0.315
  ;;     :mean 0.07875
  ;;     :p50 0.05
  ;;     :p95 0.1
  ;;     :p99 0.1}

  ;; Format as Prometheus text
  (println (histograms/format-histogram h2 "request_latency" {:service "api"}))
  ;; => request_latency_bucket{service="api",le="0.01"} 1
  ;;    request_latency_bucket{service="api",le="0.05"} 2
  ;;    request_latency_bucket{service="api",le="0.1"} 3
  ;;    request_latency_bucket{service="api",le="+Inf"} 4
  ;;    request_latency_sum{service="api"} 0.315
  ;;    request_latency_count{service="api"} 4
  )

;; =============================================================================
;; 6. HTTP Client for Fetching Metrics
;; =============================================================================

(defn fetch-metrics
  "Fetch metrics from the metrics endpoint."
  ([] (fetch-metrics "http://localhost:9090/metrics"))
  ([url]
   (let [conn (doto ^HttpURLConnection (.openConnection (URL. url))
                (.setRequestMethod "GET")
                (.setConnectTimeout 5000)
                (.setReadTimeout 5000))]
     (try
       (let [status (.getResponseCode conn)]
         (if (= 200 status)
           (with-open [reader (BufferedReader.
                                (InputStreamReader. (.getInputStream conn)))]
             {:status 200
              :body (str/join "\n" (line-seq reader))})
           {:status status :error "Non-200 response"}))
       (finally
         (.disconnect conn))))))

(defn parse-metric
  "Parse a single metric line into structured data."
  [line]
  (when-not (or (str/starts-with? line "#") (str/blank? line))
    (let [[metric-part value] (str/split line #" " 2)
          [name labels] (if (str/includes? metric-part "{")
                          (let [[n l] (str/split metric-part #"\{" 2)]
                            [n (str/replace l "}" "")])
                          [metric-part nil])]
      {:name name
       :labels (when labels
                 (->> (str/split labels #",")
                      (map #(let [[k v] (str/split % #"=" 2)]
                              [k (str/replace v "\"" "")]))
                      (into {})))
       :value (Double/parseDouble value)})))

(defn get-metric-value
  "Get a specific metric value from metrics output."
  [metrics-text metric-name & {:keys [labels]}]
  (->> (str/split-lines metrics-text)
       (map parse-metric)
       (filter some?)
       (filter #(= metric-name (:name %)))
       (filter #(if labels
                  (every? (fn [[k v]] (= v (get (:labels %) k))) labels)
                  true))
       first))

(comment
  ;; Start metrics server
  (metrics/start! {:port 9090})

  ;; Fetch and display metrics
  (let [{:keys [status body]} (fetch-metrics)]
    (when (= 200 status)
      (println body)))

  ;; Parse specific metric
  (let [{:keys [body]} (fetch-metrics)]
    (pprint (get-metric-value body "lb_up")))
  ;; => {:name "lb_up", :labels nil, :value 1.0}

  (metrics/stop!))

;; =============================================================================
;; 7. Prometheus Alerting Rules (Example)
;; =============================================================================

;; Example Prometheus alerting rules for the load balancer metrics:
;;
;; groups:
;; - name: lb_alerts
;;   rules:
;;   - alert: LoadBalancerDown
;;     expr: lb_up == 0
;;     for: 1m
;;     labels:
;;       severity: critical
;;     annotations:
;;       summary: "Load balancer is down"
;;
;;   - alert: BackendUnhealthy
;;     expr: lb_backend_health == 0
;;     for: 2m
;;     labels:
;;       severity: warning
;;     annotations:
;;       summary: "Backend {{ $labels.target_ip }}:{{ $labels.target_port }} is unhealthy"
;;
;;   - alert: HighHealthCheckLatency
;;     expr: histogram_quantile(0.95, rate(lb_health_check_latency_seconds_bucket[5m])) > 0.5
;;     for: 5m
;;     labels:
;;       severity: warning
;;     annotations:
;;       summary: "High health check latency for {{ $labels.proxy_name }}"
;;
;;   - alert: DNSResolutionFailed
;;     expr: lb_dns_resolution_status == 0
;;     for: 5m
;;     labels:
;;       severity: warning
;;     annotations:
;;       summary: "DNS resolution failed for {{ $labels.hostname }}"
;;
;;   - alert: AllBackendsUnhealthy
;;     expr: sum by (proxy_name) (lb_backend_health) == 0
;;     for: 1m
;;     labels:
;;       severity: critical
;;     annotations:
;;       summary: "All backends unhealthy for proxy {{ $labels.proxy_name }}"

;; =============================================================================
;; 8. Grafana Dashboard Query Examples
;; =============================================================================

;; Example Grafana/PromQL queries:
;;
;; Active connections per backend:
;;   lb_connections_active
;;
;; Total bytes transferred (rate per second):
;;   rate(lb_bytes_total[5m])
;;
;; Healthy backends count:
;;   sum(lb_backend_health)
;;
;; Health check latency p95:
;;   histogram_quantile(0.95, rate(lb_health_check_latency_seconds_bucket[5m]))
;;
;; Connection rate:
;;   rate(lb_connections_active[1m])
;;
;; Bytes per second by direction:
;;   sum by (direction) (rate(lb_bytes_total[5m]))

;; =============================================================================
;; 9. Complete Demo
;; =============================================================================

(defn run-demo
  "Run a complete demo of the metrics system."
  []
  (println "=== Prometheus Metrics Demo ===\n")

  ;; Start metrics server
  (println "1. Starting metrics server on port 9090...")
  (metrics/start! {:port 9090})
  (println "   Status:" (metrics/get-status))
  (println)

  ;; Register mock data
  (println "2. Registering mock data sources...")
  (metrics/register-data-sources!
    {:health-fn (fn []
                  [{:proxy-name "web"
                    :targets [{:target-id "10.0.0.1:8080" :status :healthy}
                              {:target-id "10.0.0.2:8080" :status :healthy}
                              {:target-id "10.0.0.3:8080" :status :unhealthy}]}])
     :dns-fn (fn []
               {"web" {:targets {"api.example.com" {:consecutive-failures 0}
                                 "db.example.com" {:consecutive-failures 2}}}})})
  (println "   Done.")
  (println)

  ;; Record some latency
  (println "3. Recording health check latencies...")
  (doseq [_ (range 50)]
    (metrics/record-health-check-latency! "web" "10.0.0.1:8080"
                                           (+ 0.003 (* 0.005 (rand))))
    (metrics/record-health-check-latency! "web" "10.0.0.2:8080"
                                           (+ 0.005 (* 0.010 (rand)))))
  (println "   Recorded 100 latency observations.")
  (println)

  ;; Fetch and display metrics
  (println "4. Fetching metrics from http://localhost:9090/metrics...")
  (Thread/sleep 100)
  (let [{:keys [status body]} (fetch-metrics)]
    (if (= 200 status)
      (do
        (println "\n--- Metrics Output ---")
        (println body)
        (println "--- End of Metrics ---\n"))
      (println "   Error fetching metrics:" status)))

  ;; Cleanup
  (println "5. Cleaning up...")
  (metrics/clear-data-sources!)
  (metrics/reset-histograms!)
  (metrics/stop!)
  (println "   Done.")
  (println "\n=== Demo Complete ==="))

(comment
  ;; Run the complete demo
  (run-demo)

  ;; Or test interactively:
  ;; 1. Start server: (metrics/start! {:port 9090})
  ;; 2. Open browser: http://localhost:9090/metrics
  ;; 3. Or use curl: curl http://localhost:9090/metrics
  ;; 4. Stop server: (metrics/stop!)
  )

(println "Prometheus metrics example loaded. See comments for usage patterns.")
(println "Run (run-demo) for a complete demonstration.")
