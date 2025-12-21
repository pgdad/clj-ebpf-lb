;; Statistics and Monitoring Example
;;
;; This file demonstrates real-time statistics collection and monitoring.
;; Run with:
;;   sudo clojure -M:dev
;;   (load-file "examples/monitoring.clj")
;;
;; Prerequisites:
;;   - A running load balancer with stats-enabled: true
;;   - Traffic flowing through the load balancer

(ns monitoring
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.stats :as stats]
            [lb.conntrack :as conntrack]
            [clojure.core.async :as async :refer [<! <!! >!! go-loop]]
            [clojure.pprint :refer [pprint]]))

;; =============================================================================
;; 1. Basic Statistics Collection
;; =============================================================================

(comment
  ;; First, ensure the load balancer is running with stats enabled
  (def cfg (config/make-simple-config
             {:interface "eth0"
              :port 8888
              :target-ip "127.0.0.1"
              :target-port 8080
              :stats-enabled true}))  ; Important!

  (lb/init! cfg)

  ;; Verify stats are enabled
  (lb/stats-enabled?)
  ;; => true

  ;; Get aggregate connection statistics
  (pprint (lb/get-connection-stats))
  ;; => {:total-connections 10
  ;;     :total-packets-forward 1234
  ;;     :total-bytes-forward 567890
  ;;     :total-packets-reverse 1100
  ;;     :total-bytes-reverse 450000}
  )

;; =============================================================================
;; 2. Real-Time Event Streaming
;; =============================================================================

(comment
  ;; Start the stats event stream
  (lb/start-stats-stream!)

  ;; Subscribe to receive events
  (def event-channel (lb/subscribe-to-stats))

  ;; Read events as they come in
  (go-loop []
    (when-let [event (<! event-channel)]
      (println "Event:" (stats/format-event event))
      (recur)))

  ;; Generate some traffic, then stop
  (lb/stop-stats-stream!))

;; =============================================================================
;; 3. Connection Statistics by Source/Target
;; =============================================================================

(comment
  ;; Get statistics grouped by source IP
  (pprint (conntrack/stats-by-source
            (get-in (lb/get-state) [:maps :conntrack-map])))
  ;; => ({:source-ip "192.168.1.100"
  ;;      :connection-count 5
  ;;      :packets-forward 500
  ;;      :bytes-forward 50000
  ;;      :packets-reverse 450
  ;;      :bytes-reverse 45000}
  ;;     ...)

  ;; Get statistics grouped by target (backend)
  (pprint (conntrack/stats-by-target
            (get-in (lb/get-state) [:maps :conntrack-map])))
  ;; => ({:target-ip "10.0.0.1"
  ;;      :connection-count 8
  ;;      :packets-forward 800
  ;;      :bytes-forward 80000
  ;;      ...}
  ;;     ...)

  ;; Get statistics by protocol
  (pprint (conntrack/stats-by-protocol
            (get-in (lb/get-state) [:maps :conntrack-map])))
  ;; => ({:protocol :tcp, :connection-count 15, ...}
  ;;     {:protocol :udp, :connection-count 3, ...})
  )

;; =============================================================================
;; 4. Rate Calculation
;; =============================================================================

(defn start-rate-monitor
  "Start a rate monitor that prints stats every second."
  []
  (println "Starting rate monitor...")
  (lb/start-stats-stream!)
  (let [rate-calc (stats/create-rate-calculator :window-ms 1000)
        event-ch (lb/subscribe-to-stats)
        running (atom true)]

    ;; Forward events to rate calculator
    (go-loop []
      (when @running
        (when-let [event (<! event-ch)]
          (>!! (:channel rate-calc) event)
          (recur))))

    ;; Print rates every second
    (go-loop []
      (when @running
        (<! (async/timeout 1000))
        (let [{:keys [events-per-sec packets-per-sec bytes-per-sec]}
              (stats/get-current-rates rate-calc)]
          (println (format "Rates: %.1f events/s, %.1f pkts/s, %.1f bytes/s"
                           (double events-per-sec)
                           (double packets-per-sec)
                           (double bytes-per-sec))))
        (recur)))

    ;; Return control map
    {:stop-fn (fn []
                (reset! running false)
                (stats/stop-rate-calculator rate-calc)
                (lb/stop-stats-stream!)
                (println "Rate monitor stopped."))}))

(comment
  ;; Start monitoring
  (def monitor (start-rate-monitor))

  ;; Generate traffic: curl http://localhost:8888
  ;; Watch the rates update

  ;; Stop monitoring
  ((:stop-fn monitor)))

;; =============================================================================
;; 5. Statistics Aggregation
;; =============================================================================

(defn start-stats-aggregator
  "Start aggregating statistics for analysis."
  []
  (println "Starting stats aggregator...")
  (lb/start-stats-stream!)
  (let [aggregator (stats/create-stats-aggregator)
        event-ch (lb/subscribe-to-stats)
        running (atom true)]

    ;; Forward events to aggregator
    (go-loop []
      (when @running
        (when-let [event (<! event-ch)]
          (>!! (:channel aggregator) event)
          (recur))))

    {:aggregator aggregator
     :stop-fn (fn []
                (reset! running false)
                (stats/stop-stats-aggregator aggregator)
                (lb/stop-stats-stream!)
                (println "Aggregator stopped."))}))

(comment
  ;; Start aggregating
  (def agg (start-stats-aggregator))

  ;; Generate some traffic...

  ;; View aggregated stats
  (stats/print-aggregated-stats (:aggregator agg))
  ;; => Aggregated Statistics
  ;;    =====================
  ;;    Runtime:              45.3 seconds
  ;;    Total events:         127
  ;;    New connections:      42
  ;;    Closed connections:   35
  ;;    Packets (fwd/rev):    1234 / 1100
  ;;    Bytes (fwd/rev):      567890 / 450000
  ;;
  ;;    Top sources:
  ;;      192.168.1.100: 45 events, 50000 bytes
  ;;      192.168.1.101: 32 events, 35000 bytes
  ;;
  ;;    Top targets:
  ;;      10.0.0.1: 80 events, 75000 bytes
  ;;      10.0.0.2: 47 events, 40000 bytes

  ;; Reset stats
  (stats/reset-aggregated-stats (:aggregator agg))

  ;; Stop
  ((:stop-fn agg)))

;; =============================================================================
;; 6. Custom Event Processing
;; =============================================================================

(defn process-with-handlers
  "Process events with custom handlers."
  []
  (lb/start-stats-stream!)
  (let [event-ch (lb/subscribe-to-stats)]
    (stats/process-events-with-handlers event-ch
      {:on-new-conn
       (fn [event]
         (println "NEW CONNECTION:"
                  (format "%s:%d -> %s:%d"
                          (lb.util/u32->ip-string (:src-ip event))
                          (:src-port event)
                          (lb.util/u32->ip-string (:target-ip event))
                          (:target-port event))))

       :on-closed
       (fn [event]
         (println "CONNECTION CLOSED:"
                  (format "%s:%d (packets: %d/%d)"
                          (lb.util/u32->ip-string (:src-ip event))
                          (:src-port event)
                          (:packets-fwd event)
                          (:packets-rev event))))

       :on-any
       (fn [event]
         ;; Called for all events - useful for logging
         nil)})))

(comment
  ;; Start processing with handlers
  (process-with-handlers)

  ;; Generate traffic and watch the output

  ;; Stop
  (lb/stop-stats-stream!))

;; =============================================================================
;; 7. Dashboard-Style Monitor
;; =============================================================================

(defn run-dashboard
  "Run a simple text-based dashboard that updates every 2 seconds."
  []
  (println "Starting dashboard... (Ctrl+C to stop)")
  (let [running (atom true)]
    (future
      (while @running
        (print "\033[2J\033[H")  ; Clear screen
        (println "=== Load Balancer Dashboard ===")
        (println)
        (lb/print-status)
        (println)
        (println "--- Active Connections ---")
        (lb/print-connections)
        (println)
        (println "--- Connection Stats ---")
        (pprint (lb/get-connection-stats))
        (Thread/sleep 2000)))
    {:stop-fn #(reset! running false)}))

(comment
  (def dash (run-dashboard))
  ;; ... watch the dashboard update
  ((:stop-fn dash)))

(println "Monitoring example loaded. See comments for usage patterns.")
