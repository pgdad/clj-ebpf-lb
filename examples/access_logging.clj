(ns access-logging
  "Example: Access Logging and Backend Latency Tracking

   This example demonstrates how to configure and use the access logging
   and backend latency tracking features for monitoring and debugging.

   Access logging writes connection events to stdout and a rotating log file.
   Backend latency tracking records per-backend connection durations as
   Prometheus histogram metrics."
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.latency :as latency]
            [lb.access-log :as access-log]))

;; =============================================================================
;; Configuration Examples
;; =============================================================================

(def config-with-access-log
  "Configuration with access logging enabled.
   Logs connection events in JSON format to both stdout and a rotating file."
  {:proxies
   [{:name "web"
     :listen {:interfaces ["lo"] :port 8080}
     :default-target [{:ip "127.0.0.1" :port 9001 :weight 50}
                      {:ip "127.0.0.1" :port 9002 :weight 50}]}]
   :settings
   {:stats-enabled true                ; Required for access logging
    :metrics {:enabled true            ; Required for latency histograms
              :port 9090
              :path "/metrics"}
    :access-log {:enabled true
                 :format :json         ; :json or :clf
                 :path "logs/access.log"
                 :max-file-size-mb 100  ; Rotate when file exceeds 100MB
                 :max-files 10          ; Keep up to 10 rotated files
                 :buffer-size 10000}}}) ; Async buffer for 10k entries

(def config-with-clf-format
  "Configuration using Common Log Format (CLF) style output.
   Familiar format for users coming from Apache/nginx."
  {:proxies
   [{:name "api"
     :listen {:interfaces ["eth0"] :port 443}
     :default-target {:ip "10.0.0.1" :port 8443}}]
   :settings
   {:stats-enabled true
    :metrics {:enabled true :port 9090}
    :access-log {:enabled true
                 :format :clf         ; Common Log Format style
                 :path "/var/log/lb/access.log"
                 :max-file-size-mb 500
                 :max-files 30}}})

(def config-minimal
  "Minimal configuration - just enable with defaults.
   Uses JSON format, logs to logs/access.log."
  {:proxies
   [{:name "minimal"
     :listen {:interfaces ["lo"] :port 8080}
     :default-target {:ip "127.0.0.1" :port 8000}}]
   :settings
   {:stats-enabled true
    :metrics {:enabled true :port 9090}
    :access-log {:enabled true}}})

;; =============================================================================
;; Log Format Examples
;; =============================================================================

;; JSON Format (default):
;; {"timestamp":"2025-01-15T10:30:45.123Z","event":"conn-closed",
;;  "src":{"ip":"192.168.1.100","port":54321},
;;  "dst":{"ip":"10.0.0.1","port":80},
;;  "backend":{"ip":"10.0.0.5","port":8080},
;;  "duration_ms":1523,"bytes_fwd":1024,"bytes_rev":4096,"protocol":"tcp"}

;; CLF Format:
;; 192.168.1.100 - - [15/Jan/2025:10:30:45 +0000] "CONN-CLOSED 10.0.0.1:80 -> 10.0.0.5:8080" 1024/4096 1523ms

;; =============================================================================
;; Prometheus Metrics Examples
;; =============================================================================

;; Backend latency histogram metrics are exposed at /metrics:

;; # HELP lb_backend_latency_seconds Backend connection latency in seconds
;; # TYPE lb_backend_latency_seconds histogram
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="0.001"} 5
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="0.005"} 15
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="0.01"} 28
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="0.025"} 45
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="0.05"} 67
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="0.1"} 89
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="0.25"} 95
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="0.5"} 98
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="1"} 99
;; lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="+Inf"} 100
;; lb_backend_latency_seconds_sum{proxy_name="web",target_ip="10.0.0.1",target_port="8080"} 45.678
;; lb_backend_latency_seconds_count{proxy_name="web",target_ip="10.0.0.1",target_port="8080"} 100

;; =============================================================================
;; Runtime API Examples
;; =============================================================================

(defn demo-latency-api
  "Demonstrate latency tracking API."
  []
  (println "=== Latency Tracking API Demo ===")

  ;; Check if latency tracking is running
  (println "Latency tracking running?" (latency/running?))

  ;; Get latency percentiles for a specific backend
  (when-let [stats (latency/get-percentiles "web" "10.0.0.1:8080")]
    (println "Backend 10.0.0.1:8080 latency:")
    (println "  p50:" (:p50 stats) "seconds")
    (println "  p95:" (:p95 stats) "seconds")
    (println "  p99:" (:p99 stats) "seconds")
    (println "  mean:" (:mean stats) "seconds")
    (println "  count:" (:count stats)))

  ;; Get all histograms
  (println "\nAll histograms:")
  (doseq [[[proxy-name target-id] h] (latency/get-all-histograms)]
    (println " " proxy-name "/" target-id ":" (:count h) "samples"))

  ;; Get latency tracking status
  (println "\nLatency tracking status:")
  (let [status (latency/get-status)]
    (println "  Running:" (:running? status))
    (println "  Histogram count:" (:histogram-count status))))

(defn demo-access-log-api
  "Demonstrate access log API."
  []
  (println "\n=== Access Logging API Demo ===")

  ;; Check if access logging is running
  (println "Access logging running?" (access-log/running?))

  ;; Get access log status
  (when (access-log/running?)
    (let [status (access-log/get-status)]
      (println "\nAccess log status:")
      (println "  Running:" (:running? status))
      (when-let [fw (:file-writer status)]
        (println "  Log path:" (:path fw))
        (println "  Current size:" (:current-size-bytes fw) "bytes")
        (println "  Max size:" (:max-size-bytes fw) "bytes")
        (println "  Percent full:" (format "%.1f%%" (:percent-full fw)))))))

;; =============================================================================
;; Usage Example
;; =============================================================================

(comment
  ;; Start the load balancer with access logging enabled
  (lb/init! (config/parse-config config-with-access-log))

  ;; Access logs will appear in stdout and logs/access.log
  ;; Backend latency metrics will be exposed at http://localhost:9090/metrics

  ;; Check status
  (demo-latency-api)
  (demo-access-log-api)

  ;; Flush access log buffers (useful before shutdown)
  (access-log/flush!)

  ;; Shutdown
  (lb/shutdown!)

  ;; Reset latency histograms (for testing/debugging)
  (latency/reset-histograms!)

  ;; Manual latency recording (for testing)
  (latency/record-latency! "test-proxy" "10.0.0.1:8080" 0.5)
  (latency/get-percentiles "test-proxy" "10.0.0.1:8080"))

;; =============================================================================
;; Configuration Reference
;; =============================================================================

;; Access Log Configuration Options:
;; ---------------------------------
;; :enabled           - Enable access logging (default: false)
;; :format            - Log format: :json or :clf (default: :json)
;; :path              - Log file path (default: "logs/access.log")
;; :max-file-size-mb  - Max file size before rotation (default: 100)
;; :max-files         - Max rotated files to keep (default: 10)
;; :buffer-size       - Async buffer size (default: 10000)
;;
;; Requirements:
;; - :stats-enabled must be true (for connection events)
;; - :metrics :enabled must be true (for latency histograms)
