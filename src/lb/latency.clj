(ns lb.latency
  "Backend latency tracking for the load balancer.
   Tracks connection lifetime (creation to close) as latency metric.
   Exposes per-backend histograms for Prometheus export."
  (:require [clojure.core.async :as async :refer [go-loop <! chan sliding-buffer close! tap]]
            [clojure.tools.logging :as log]
            [lb.metrics.histograms :as histograms]
            [lb.util :as util]
            [lb.stats :as stats]
            [lb.conntrack :as conntrack]))

;;; =============================================================================
;;; State
;;; =============================================================================

(defonce ^:private latency-state
  (atom {:running? false
         :histograms {}     ; {[proxy-name target-id] -> histogram}
         :event-chan nil
         :stats-stream nil}))

;;; =============================================================================
;;; Latency Recording
;;; =============================================================================

(defn record-latency!
  "Record a connection latency observation for a backend.
   latency-sec: connection duration in seconds"
  [proxy-name target-id latency-sec]
  (when (and proxy-name target-id (number? latency-sec) (pos? latency-sec))
    (let [key [proxy-name target-id]]
      (swap! latency-state update :histograms
             (fn [histograms]
               (update histograms key
                       (fn [h]
                         (histograms/observe
                           (or h (histograms/new-histogram))
                           latency-sec))))))))

(defn- calculate-duration-from-event
  "Calculate connection duration from a conn-closed event.
   Uses the event timestamp and estimates start time.
   Returns duration in seconds, or nil if cannot calculate."
  [event conntrack-map]
  (try
    ;; Try to get connection from conntrack for precise timing
    (when conntrack-map
      (let [conn-key {:src-ip (:src-ip event)
                      :dst-ip (:dst-ip event)
                      :src-port (:src-port event)
                      :dst-port (:dst-port event)
                      :protocol 6}  ; TCP
            conn (conntrack/get-connection conntrack-map conn-key)]
        (when conn
          (conntrack/connection-age-seconds conn))))
    (catch Exception e
      (log/debug e "Error calculating duration from conntrack")
      nil)))

(defn- handle-conn-closed
  "Handle a connection closed event for latency tracking."
  [event conntrack-map proxy-name]
  (when-let [duration-sec (calculate-duration-from-event event conntrack-map)]
    (let [target-id (str (util/u32->ip-string (:target-ip event))
                         ":" (:target-port event))]
      (record-latency! proxy-name target-id duration-sec))))

;;; =============================================================================
;;; Public API
;;; =============================================================================

(defn start!
  "Start latency tracking. Subscribes to stats event stream.

   Parameters:
     stats-stream: the stats event stream from lb.stats/create-event-stream
     conntrack-map: the connection tracking BPF map
     proxy-name: name of the proxy (used for metric labels)"
  [stats-stream conntrack-map proxy-name]
  (when-not (:running? @latency-state)
    (log/info "Starting latency tracking for proxy" proxy-name)
    (let [event-chan (stats/subscribe-to-stream stats-stream :buffer-size 1000)]
      (swap! latency-state assoc
             :running? true
             :event-chan event-chan
             :stats-stream stats-stream)

      ;; Start event processing loop
      (go-loop []
        (when-let [event (<! event-chan)]
          (when (= (:event-type event) :conn-closed)
            (try
              (handle-conn-closed event conntrack-map proxy-name)
              (catch Exception e
                (log/debug e "Error processing latency event"))))
          (recur)))

      (log/info "Latency tracking started"))))

(defn stop!
  "Stop latency tracking."
  []
  (when (:running? @latency-state)
    (log/info "Stopping latency tracking")
    (when-let [event-chan (:event-chan @latency-state)]
      (when-let [stream (:stats-stream @latency-state)]
        (stats/unsubscribe-from-stream stream event-chan)))
    (swap! latency-state assoc
           :running? false
           :event-chan nil
           :stats-stream nil)
    (log/info "Latency tracking stopped")))

(defn running?
  "Check if latency tracking is running."
  []
  (:running? @latency-state))

(defn get-histogram
  "Get latency histogram for a specific backend.
   Returns histogram map with :buckets :counts :sum :count, or nil if not found."
  [proxy-name target-id]
  (get-in @latency-state [:histograms [proxy-name target-id]]))

(defn get-all-histograms
  "Get all latency histograms.
   Returns map of [proxy-name target-id] -> histogram."
  []
  (:histograms @latency-state))

(defn get-percentiles
  "Get latency percentiles for a backend.
   Returns {:p50 :p95 :p99 :mean :count} or nil if no data."
  [proxy-name target-id]
  (when-let [h (get-histogram proxy-name target-id)]
    (histograms/histogram-stats h)))

(defn reset-histograms!
  "Reset all latency histogram data."
  []
  (swap! latency-state assoc :histograms {}))

(defn get-status
  "Get latency tracking status."
  []
  {:running? (:running? @latency-state)
   :histogram-count (count (:histograms @latency-state))
   :histograms (into {}
                     (for [[[proxy-name target-id] h] (:histograms @latency-state)]
                       [[proxy-name target-id]
                        {:count (:count h)
                         :mean (if (zero? (:count h)) 0.0 (/ (:sum h) (:count h)))}]))})

;;; =============================================================================
;;; Metrics Integration
;;; =============================================================================

(defn get-histograms-for-metrics
  "Get histograms in format suitable for metrics collector.
   Returns map of [proxy-name target-ip target-port] -> histogram."
  []
  (into {}
        (for [[[proxy-name target-id] h] (:histograms @latency-state)
              :let [[target-ip target-port] (clojure.string/split target-id #":")]]
          [[proxy-name target-ip target-port] h])))
