(ns lb.metrics.collector
  "Collects and formats metrics in Prometheus text format.

   Gathers data from various sources:
   - Connection tracking (active connections, bytes, packets)
   - Health checking (backend health status, latency)
   - DNS resolution (resolution status)
   - Stats aggregator (totals)"
  (:require [lb.metrics.histograms :as histograms]
            [lb.util :as util]
            [clojure.string :as str]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; State
;;; =============================================================================

(defonce ^:private data-sources (atom {}))
(defonce ^:private health-latency-histograms (atom {}))

;;; =============================================================================
;;; Data Source Registration
;;; =============================================================================

(defn register-sources!
  "Register data source functions for metric collection.

   sources is a map with optional keys:
     :conntrack-fn - (fn [] connections) returns seq of Connection records
     :health-fn    - (fn [] health-status) returns health status for all proxies
     :stats-fn     - (fn [] stats) returns aggregated stats map
     :dns-fn       - (fn [] dns-status) returns DNS status for all proxies
     :proxies-fn   - (fn [] proxies) returns list of proxy configurations"
  [sources]
  (reset! data-sources sources))

(defn clear-sources!
  "Clear all registered data sources."
  []
  (reset! data-sources {}))

;;; =============================================================================
;;; Histogram Recording
;;; =============================================================================

(defn record-health-latency!
  "Record a health check latency observation.

   proxy-name: name of the proxy
   target-id: target identifier (e.g., \"10.0.0.1:8080\")
   latency-sec: latency in seconds"
  [proxy-name target-id latency-sec]
  (let [key [proxy-name target-id]]
    (swap! health-latency-histograms
           update key
           (fn [h]
             (histograms/observe (or h (histograms/new-histogram)) latency-sec)))))

(defn reset-histograms!
  "Reset all histogram data."
  []
  (reset! health-latency-histograms {}))

;;; =============================================================================
;;; Prometheus Format Helpers
;;; =============================================================================

(defn- format-labels
  "Format a map of labels as Prometheus label string."
  [labels]
  (if (empty? labels)
    ""
    (str "{"
         (->> labels
              (map (fn [[k v]] (str (name k) "=\"" v "\"")))
              (str/join ","))
         "}")))

(defn- format-metric-line
  "Format a single metric line with labels and value."
  [name labels value]
  (str name (format-labels labels) " " (double value)))

(defn- format-metric-family
  "Format a metric family with HELP and TYPE lines."
  [metric-name metric-type help-text lines]
  (when (seq lines)
    (str "# HELP " metric-name " " help-text "\n"
         "# TYPE " metric-name " " metric-type "\n"
         (str/join "\n" lines))))

;;; =============================================================================
;;; Individual Metric Collectors
;;; =============================================================================

(defn- collect-connections-active
  "Collect lb_connections_active gauge - current active connections by target."
  []
  (when-let [conntrack-fn (:conntrack-fn @data-sources)]
    (try
      (let [connections (conntrack-fn)
            ;; Group by NAT target
            by-target (->> connections
                           (group-by (fn [conn]
                                       [(util/u32->ip-string (:nat-dst-ip conn))
                                        (:nat-dst-port conn)]))
                           (map (fn [[[ip port] conns]]
                                  {:target_ip ip
                                   :target_port (str port)
                                   :count (count conns)})))]
        (format-metric-family
          "lb_connections_active"
          "gauge"
          "Current number of active connections per backend"
          (for [{:keys [target_ip target_port count]} by-target]
            (format-metric-line "lb_connections_active"
                                {:target_ip target_ip :target_port target_port}
                                count))))
      (catch Exception e
        (log/warn e "Error collecting lb_connections_active")
        nil))))

(defn- collect-bytes-total
  "Collect lb_bytes_total counter - total bytes transferred by target and direction."
  []
  (when-let [conntrack-fn (:conntrack-fn @data-sources)]
    (try
      (let [connections (conntrack-fn)
            ;; Group by NAT target
            by-target (->> connections
                           (group-by (fn [conn]
                                       [(util/u32->ip-string (:nat-dst-ip conn))
                                        (:nat-dst-port conn)]))
                           (map (fn [[[ip port] conns]]
                                  {:target_ip ip
                                   :target_port (str port)
                                   :bytes_fwd (reduce + 0 (map :bytes-fwd conns))
                                   :bytes_rev (reduce + 0 (map :bytes-rev conns))})))]
        (format-metric-family
          "lb_bytes_total"
          "counter"
          "Total bytes transferred"
          (concat
            (for [{:keys [target_ip target_port bytes_fwd]} by-target]
              (format-metric-line "lb_bytes_total"
                                  {:target_ip target_ip
                                   :target_port target_port
                                   :direction "forward"}
                                  bytes_fwd))
            (for [{:keys [target_ip target_port bytes_rev]} by-target]
              (format-metric-line "lb_bytes_total"
                                  {:target_ip target_ip
                                   :target_port target_port
                                   :direction "reverse"}
                                  bytes_rev)))))
      (catch Exception e
        (log/warn e "Error collecting lb_bytes_total")
        nil))))

(defn- collect-packets-total
  "Collect lb_packets_total counter - total packets transferred."
  []
  (when-let [conntrack-fn (:conntrack-fn @data-sources)]
    (try
      (let [connections (conntrack-fn)
            ;; Group by NAT target
            by-target (->> connections
                           (group-by (fn [conn]
                                       [(util/u32->ip-string (:nat-dst-ip conn))
                                        (:nat-dst-port conn)]))
                           (map (fn [[[ip port] conns]]
                                  {:target_ip ip
                                   :target_port (str port)
                                   :packets_fwd (reduce + 0 (map :packets-fwd conns))
                                   :packets_rev (reduce + 0 (map :packets-rev conns))})))]
        (format-metric-family
          "lb_packets_total"
          "counter"
          "Total packets transferred"
          (concat
            (for [{:keys [target_ip target_port packets_fwd]} by-target]
              (format-metric-line "lb_packets_total"
                                  {:target_ip target_ip
                                   :target_port target_port
                                   :direction "forward"}
                                  packets_fwd))
            (for [{:keys [target_ip target_port packets_rev]} by-target]
              (format-metric-line "lb_packets_total"
                                  {:target_ip target_ip
                                   :target_port target_port
                                   :direction "reverse"}
                                  packets_rev)))))
      (catch Exception e
        (log/warn e "Error collecting lb_packets_total")
        nil))))

(defn- collect-backend-health
  "Collect lb_backend_health gauge - backend health status (1=healthy, 0=unhealthy)."
  []
  (when-let [health-fn (:health-fn @data-sources)]
    (try
      (let [all-health (health-fn)
            lines (for [proxy-health all-health
                        :let [proxy-name (:proxy-name proxy-health)]
                        target (:targets proxy-health)
                        :let [target-id (:target-id target)
                              [ip port] (str/split target-id #":")
                              healthy? (= :healthy (:status target))]]
                    (format-metric-line "lb_backend_health"
                                        {:proxy_name proxy-name
                                         :target_ip ip
                                         :target_port (or port "0")}
                                        (if healthy? 1 0)))]
        (format-metric-family
          "lb_backend_health"
          "gauge"
          "Backend health status (1=healthy, 0=unhealthy)"
          lines))
      (catch Exception e
        (log/warn e "Error collecting lb_backend_health")
        nil))))

(defn- collect-dns-status
  "Collect lb_dns_resolution_status gauge - DNS resolution status."
  []
  (when-let [dns-fn (:dns-fn @data-sources)]
    (try
      (let [all-dns (dns-fn)
            lines (for [[proxy-name status] all-dns
                        [hostname target-status] (:targets status)
                        :let [failures (:consecutive-failures target-status)
                              healthy? (zero? failures)]]
                    (format-metric-line "lb_dns_resolution_status"
                                        {:proxy_name proxy-name
                                         :hostname hostname}
                                        (if healthy? 1 0)))]
        (when (seq lines)
          (format-metric-family
            "lb_dns_resolution_status"
            "gauge"
            "DNS resolution status (1=resolved, 0=failed)"
            lines)))
      (catch Exception e
        (log/warn e "Error collecting lb_dns_resolution_status")
        nil))))

(defn- collect-health-latency-histogram
  "Collect lb_health_check_latency_seconds histogram."
  []
  (let [histograms @health-latency-histograms]
    (when (seq histograms)
      (histograms/format-histogram-family
        histograms
        "lb_health_check_latency_seconds"
        "Health check latency in seconds"
        [:proxy_name :target_id]))))

(defn- collect-circuit-breaker-state
  "Collect lb_circuit_breaker_state gauge - circuit breaker state (0=closed, 1=half-open, 2=open)."
  []
  (when-let [cb-fn (:circuit-breaker-fn @data-sources)]
    (try
      (let [all-circuits (cb-fn)
            state->value {:closed 0 :half-open 1 :open 2}
            lines (for [circuit all-circuits
                        :let [{:keys [target-id proxy-name state error-rate]} circuit
                              [ip port] (str/split target-id #":")]]
                    (format-metric-line "lb_circuit_breaker_state"
                                        {:proxy_name proxy-name
                                         :target_ip ip
                                         :target_port (or port "0")}
                                        (get state->value state 0)))]
        (when (seq lines)
          (format-metric-family
            "lb_circuit_breaker_state"
            "gauge"
            "Circuit breaker state (0=closed, 1=half-open, 2=open)"
            lines)))
      (catch Exception e
        (log/warn e "Error collecting lb_circuit_breaker_state")
        nil))))

(defn- collect-circuit-breaker-error-rate
  "Collect lb_circuit_breaker_error_rate gauge - current error rate."
  []
  (when-let [cb-fn (:circuit-breaker-fn @data-sources)]
    (try
      (let [all-circuits (cb-fn)
            lines (for [circuit all-circuits
                        :let [{:keys [target-id proxy-name error-rate]} circuit
                              [ip port] (str/split target-id #":")]]
                    (format-metric-line "lb_circuit_breaker_error_rate"
                                        {:proxy_name proxy-name
                                         :target_ip ip
                                         :target_port (or port "0")}
                                        error-rate))]
        (when (seq lines)
          (format-metric-family
            "lb_circuit_breaker_error_rate"
            "gauge"
            "Circuit breaker error rate (0.0-1.0)"
            lines)))
      (catch Exception e
        (log/warn e "Error collecting lb_circuit_breaker_error_rate")
        nil))))

(defn- collect-info
  "Collect lb_info gauge - load balancer information."
  []
  (format-metric-family
    "lb_info"
    "gauge"
    "Load balancer information"
    [(format-metric-line "lb_info" {:version "0.5.0"} 1)]))

(defn- collect-up
  "Collect lb_up gauge - whether the load balancer is running."
  []
  (format-metric-family
    "lb_up"
    "gauge"
    "Whether the load balancer is running (1=up, 0=down)"
    [(format-metric-line "lb_up" {} 1)]))

;;; =============================================================================
;;; Main Collection Function
;;; =============================================================================

(defn collect-all
  "Collect all metrics and format as Prometheus text exposition format.

   Returns a string suitable for returning from /metrics endpoint."
  []
  (let [metrics [(collect-up)
                 (collect-info)
                 (collect-connections-active)
                 (collect-bytes-total)
                 (collect-packets-total)
                 (collect-backend-health)
                 (collect-dns-status)
                 (collect-health-latency-histogram)
                 (collect-circuit-breaker-state)
                 (collect-circuit-breaker-error-rate)]]
    (str (str/join "\n\n" (filter some? metrics)) "\n")))
