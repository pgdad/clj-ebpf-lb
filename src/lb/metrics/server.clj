(ns lb.metrics.server
  "HTTP server for Prometheus metrics endpoint.

   Provides a simple HTTP server using Java's built-in HttpServer
   that serves Prometheus-formatted metrics on a configurable endpoint."
  (:require [lb.metrics.collector :as collector]
            [clojure.tools.logging :as log])
  (:import [com.sun.net.httpserver HttpServer HttpHandler HttpExchange]
           [java.net InetSocketAddress]))

;;; =============================================================================
;;; State
;;; =============================================================================

(defonce ^:private server-state (atom nil))

;;; =============================================================================
;;; HTTP Handler
;;; =============================================================================

(defn- create-metrics-handler
  "Create HTTP handler for /metrics endpoint.

   Returns 200 OK with Prometheus text format on success,
   500 Internal Server Error on collection failure."
  []
  (reify HttpHandler
    (^void handle [_ ^HttpExchange exchange]
      (try
        (let [metrics-text (collector/collect-all)
              response-bytes (.getBytes metrics-text "UTF-8")
              headers (.getResponseHeaders exchange)]
          ;; Set Content-Type for Prometheus
          (.add headers "Content-Type" "text/plain; version=0.0.4; charset=utf-8")
          ;; Send response
          (.sendResponseHeaders exchange 200 (count response-bytes))
          (with-open [os (.getResponseBody exchange)]
            (.write os response-bytes)))
        (catch Exception e
          (log/error e "Error generating metrics")
          (try
            (let [error-msg "Internal Server Error"
                  error-bytes (.getBytes error-msg "UTF-8")]
              (.sendResponseHeaders exchange 500 (count error-bytes))
              (with-open [os (.getResponseBody exchange)]
                (.write os error-bytes)))
            (catch Exception _
              ;; Ignore errors while writing error response
              nil))))
      nil)))

(defn- create-health-handler
  "Create HTTP handler for /health or /ready endpoint.

   Returns 200 OK if metrics server is running."
  []
  (reify HttpHandler
    (^void handle [_ ^HttpExchange exchange]
      (let [response "OK"
            response-bytes (.getBytes response "UTF-8")]
        (.sendResponseHeaders exchange 200 (count response-bytes))
        (with-open [os (.getResponseBody exchange)]
          (.write os response-bytes)))
      nil)))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start the metrics HTTP server.

   config is a map with:
     :port - Port to listen on (default 9090)
     :path - Path for metrics endpoint (default \"/metrics\")

   Returns true if started successfully, false if already running."
  [{:keys [port path] :or {port 9090 path "/metrics"}}]
  (if @server-state
    (do
      (log/warn "Metrics server already running")
      false)
    (try
      (let [server (HttpServer/create (InetSocketAddress. (int port)) 0)]
        ;; Add metrics endpoint
        (.createContext server path (create-metrics-handler))
        ;; Add health endpoint
        (.createContext server "/health" (create-health-handler))
        ;; Use default executor (single-threaded)
        (.setExecutor server nil)
        ;; Start server
        (.start server)
        (reset! server-state {:server server :port port :path path})
        (log/info "Metrics server started on port" port "at" path)
        true)
      (catch Exception e
        (log/error e "Failed to start metrics server on port" port)
        false))))

(defn stop!
  "Stop the metrics HTTP server.

   Returns true if stopped successfully, false if not running."
  []
  (if-let [{:keys [^HttpServer server port]} @server-state]
    (do
      (.stop server 0)
      (reset! server-state nil)
      (log/info "Metrics server stopped (was on port" port ")")
      true)
    (do
      (log/debug "Metrics server not running")
      false)))

(defn running?
  "Check if metrics server is running."
  []
  (some? @server-state))

(defn get-status
  "Get metrics server status.

   Returns nil if not running, or map with :port and :path if running."
  []
  (when-let [{:keys [port path]} @server-state]
    {:running true
     :port port
     :path path
     :url (str "http://localhost:" port path)}))
