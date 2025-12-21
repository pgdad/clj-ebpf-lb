(ns lb.metrics
  "Prometheus metrics export for the load balancer.

   Provides an HTTP endpoint for Prometheus scraping with metrics:
   - lb_connections_active - Current active connections
   - lb_bytes_total - Bytes transferred (forward/reverse)
   - lb_packets_total - Packets transferred
   - lb_backend_health - Backend health status (0/1)
   - lb_health_check_latency_seconds - Health check latency histogram
   - lb_dns_resolution_status - DNS resolution status

   Usage:
     ;; In configuration
     :settings {:metrics {:enabled true :port 9090 :path \"/metrics\"}}

     ;; Programmatic usage
     (metrics/start! {:port 9090})
     (metrics/register-data-sources! {...})
     (metrics/stop!)"
  (:require [lb.metrics.server :as server]
            [lb.metrics.collector :as collector]
            [lb.metrics.histograms :as histograms]))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start the metrics HTTP server.

   config is a map with:
     :port - Port to listen on (default 9090)
     :path - Path for metrics endpoint (default \"/metrics\")

   Returns true if started successfully."
  [config]
  (server/start! config))

(defn stop!
  "Stop the metrics HTTP server."
  []
  (server/stop!))

(defn running?
  "Check if metrics server is running."
  []
  (server/running?))

(defn get-status
  "Get metrics server status.

   Returns nil if not running, or map with :port, :path, :url if running."
  []
  (server/get-status))

;;; =============================================================================
;;; Data Source Registration
;;; =============================================================================

(defn register-data-sources!
  "Register data source functions for metric collection.

   sources is a map with optional keys:
     :conntrack-fn - (fn [] connections) returns seq of Connection records
     :health-fn    - (fn [] health-status) returns health status for all proxies
     :stats-fn     - (fn [] stats) returns aggregated stats map
     :dns-fn       - (fn [] dns-status) returns DNS status for all proxies

   Example:
     (register-data-sources!
       {:conntrack-fn #(conntrack/get-all-connections conntrack-map)
        :health-fn #(health/get-all-status)
        :dns-fn #(dns/get-all-status)})"
  [sources]
  (collector/register-sources! sources))

(defn clear-data-sources!
  "Clear all registered data sources."
  []
  (collector/clear-sources!))

;;; =============================================================================
;;; Histogram Recording
;;; =============================================================================

(defn record-health-check-latency!
  "Record a health check latency observation.

   This should be called after each successful health check
   to build the latency histogram.

   proxy-name: name of the proxy
   target-id: target identifier (e.g., \"10.0.0.1:8080\")
   latency-seconds: latency in seconds (NOT milliseconds)"
  [proxy-name target-id latency-seconds]
  (collector/record-health-latency! proxy-name target-id latency-seconds))

(defn reset-histograms!
  "Reset all histogram data.

   Useful for testing or periodic reset if needed."
  []
  (collector/reset-histograms!))

;;; =============================================================================
;;; Direct Metric Access (for testing/debugging)
;;; =============================================================================

(defn collect-metrics
  "Collect all metrics and return as Prometheus text format.

   This is what the /metrics endpoint returns."
  []
  (collector/collect-all))

;;; =============================================================================
;;; Histogram Utilities (re-exported)
;;; =============================================================================

(def new-histogram histograms/new-histogram)
(def observe-histogram histograms/observe)
(def histogram-stats histograms/histogram-stats)
