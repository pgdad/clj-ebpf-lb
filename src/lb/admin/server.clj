(ns lb.admin.server
  "HTTP server for Admin REST API.

   Provides a simple HTTP server using Java's built-in HttpServer
   that serves RESTful admin endpoints for runtime management."
  (:require [clojure.tools.logging :as log]
            [clojure.data.json :as json]
            [clojure.string :as str])
  (:import [com.sun.net.httpserver HttpServer HttpHandler HttpExchange]
           [java.net InetSocketAddress]
           [java.io InputStreamReader BufferedReader]))

;;; =============================================================================
;;; State
;;; =============================================================================

(defonce ^:private server-state (atom nil))

;;; =============================================================================
;;; Response Helpers
;;; =============================================================================

(defn- send-response
  "Send HTTP response with given status code and body."
  [^HttpExchange exchange status body]
  (let [response-bytes (.getBytes (str body) "UTF-8")
        headers (.getResponseHeaders exchange)]
    (.add headers "Content-Type" "application/json; charset=utf-8")
    (.sendResponseHeaders exchange status (count response-bytes))
    (with-open [os (.getResponseBody exchange)]
      (.write os response-bytes))))

(defn- success-response
  "Create a success JSON response."
  [data]
  (json/write-str {:success true :data data :error nil}))

(defn- error-response
  "Create an error JSON response."
  [code message]
  (json/write-str {:success false :data nil :error {:code code :message message}}))

(defn- send-success
  "Send success response with data."
  [^HttpExchange exchange data]
  (send-response exchange 200 (success-response data)))

(defn- send-error
  "Send error response."
  [^HttpExchange exchange status code message]
  (send-response exchange status (error-response code message)))

(defn- send-not-found
  "Send 404 Not Found response."
  [^HttpExchange exchange message]
  (send-error exchange 404 "NOT_FOUND" message))

(defn- send-method-not-allowed
  "Send 405 Method Not Allowed response."
  [^HttpExchange exchange]
  (let [headers (.getResponseHeaders exchange)]
    (.add headers "Allow" "GET, POST, DELETE"))
  (send-error exchange 405 "METHOD_NOT_ALLOWED" "Method not allowed"))

(defn- send-unauthorized
  "Send 401 Unauthorized response."
  [^HttpExchange exchange]
  (send-error exchange 401 "UNAUTHORIZED" "Invalid or missing API key"))

(defn- send-bad-request
  "Send 400 Bad Request response."
  [^HttpExchange exchange message]
  (send-error exchange 400 "BAD_REQUEST" message))

;;; =============================================================================
;;; Request Parsing
;;; =============================================================================

(defn- read-request-body
  "Read and parse JSON request body."
  [^HttpExchange exchange]
  (try
    (with-open [reader (BufferedReader. (InputStreamReader. (.getRequestBody exchange) "UTF-8"))]
      (let [body (slurp reader)]
        (when-not (str/blank? body)
          (json/read-str body :key-fn keyword))))
    (catch Exception e
      (log/debug "Failed to parse request body:" (.getMessage e))
      nil)))

(defn extract-path-params
  "Extract path parameters from a URL path based on a pattern.
   Pattern uses :param syntax for parameters.
   Example: (extract-path-params \"/api/v1/proxies/web\" \"/api/v1/proxies/:name\")
            => {:name \"web\"}"
  [path pattern]
  (let [path-parts (str/split path #"/")
        pattern-parts (str/split pattern #"/")]
    (when (= (count path-parts) (count pattern-parts))
      (reduce (fn [acc [p pat]]
                (if (str/starts-with? pat ":")
                  (assoc acc (keyword (subs pat 1)) p)
                  (if (= p pat)
                    acc
                    (reduced nil))))
              {}
              (map vector path-parts pattern-parts)))))

(defn- matches-pattern?
  "Check if a path matches a pattern with parameter placeholders."
  [path pattern]
  (some? (extract-path-params path pattern)))

;;; =============================================================================
;;; Authentication
;;; =============================================================================

(defn- authenticate
  "Check if request is authenticated.
   Returns true if no API key is configured or if provided key matches."
  [^HttpExchange exchange api-key]
  (if api-key
    (let [auth-header (.getFirst (.getRequestHeaders exchange) "X-API-Key")]
      (= auth-header api-key))
    true))

;;; =============================================================================
;;; CORS Support
;;; =============================================================================

(defn- add-cors-headers
  "Add CORS headers to response if allowed-origins is configured."
  [^HttpExchange exchange allowed-origins]
  (when (seq allowed-origins)
    (let [headers (.getResponseHeaders exchange)
          origin (.getFirst (.getRequestHeaders exchange) "Origin")]
      (when (some #(= % origin) allowed-origins)
        (.add headers "Access-Control-Allow-Origin" origin)
        (.add headers "Access-Control-Allow-Methods" "GET, POST, DELETE, OPTIONS")
        (.add headers "Access-Control-Allow-Headers" "Content-Type, X-API-Key")))))

;;; =============================================================================
;;; Router
;;; =============================================================================

(defn create-router
  "Create a router function that dispatches to handlers based on method and path.

   routes is a vector of route definitions:
   [{:method :get :pattern \"/api/v1/status\" :handler handler-fn}
    {:method :post :pattern \"/api/v1/proxies\" :handler handler-fn}
    {:method :delete :pattern \"/api/v1/proxies/:name\" :handler handler-fn}]

   Returns a function that takes (exchange) and returns:
   {:handler handler-fn :params {:name \"value\"}} or nil if no match."
  [routes]
  (fn [^HttpExchange exchange]
    (let [request-method (keyword (str/lower-case (.getRequestMethod exchange)))
          path (.getPath (.getRequestURI exchange))]
      (some (fn [{:keys [method pattern handler]}]
              (when (and (= request-method method)
                         (matches-pattern? path pattern))
                {:handler handler
                 :params (extract-path-params path pattern)}))
            routes))))

;;; =============================================================================
;;; HTTP Handler Factory
;;; =============================================================================

(defn create-admin-handler
  "Create the main HTTP handler for admin API.

   config is a map with:
     :api-key - Optional API key for authentication
     :allowed-origins - Optional list of CORS allowed origins
     :handlers - Handler module with all endpoint handlers
     :routes - Vector of route definitions"
  [{:keys [api-key allowed-origins routes]}]
  (let [router (create-router routes)]
    (reify HttpHandler
      (^void handle [_ ^HttpExchange exchange]
        (try
          ;; Add CORS headers if configured
          (add-cors-headers exchange allowed-origins)

          ;; Handle OPTIONS preflight
          (if (= "OPTIONS" (.getRequestMethod exchange))
            (do
              (.sendResponseHeaders exchange 204 -1))

            ;; Check authentication
            (if-not (authenticate exchange api-key)
              (send-unauthorized exchange)

              ;; Route request
              (if-let [{:keys [handler params]} (router exchange)]
                (try
                  (let [body (read-request-body exchange)
                        result (handler {:exchange exchange
                                        :params params
                                        :body body})]
                    (if (:error result)
                      (send-error exchange
                                  (or (:status result) 400)
                                  (or (:code result) "ERROR")
                                  (:error result))
                      (send-success exchange (:data result))))
                  (catch Exception e
                    (log/error e "Handler error")
                    (send-error exchange 500 "INTERNAL_ERROR" (.getMessage e))))

                ;; No matching route
                (send-not-found exchange "Endpoint not found"))))

          (catch Exception e
            (log/error e "Admin API error")
            (try
              (send-error exchange 500 "INTERNAL_ERROR" "Internal server error")
              (catch Exception _
                nil))))
        nil))))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start the admin HTTP server.

   config is a map with:
     :port - Port to listen on (default 8081)
     :api-key - Optional API key for authentication
     :allowed-origins - Optional list of CORS allowed origins
     :routes - Vector of route definitions

   Returns true if started successfully, false if already running."
  [{:keys [port api-key allowed-origins routes]
    :or {port 8081}}]
  (if @server-state
    (do
      (log/warn "Admin server already running")
      false)
    (try
      (let [server (HttpServer/create (InetSocketAddress. (int port)) 0)
            handler (create-admin-handler {:api-key api-key
                                           :allowed-origins allowed-origins
                                           :routes routes})]
        ;; Add API context
        (.createContext server "/api" handler)
        ;; Add health endpoint
        (.createContext server "/health"
          (reify HttpHandler
            (^void handle [_ ^HttpExchange exchange]
              (let [response "OK"
                    response-bytes (.getBytes response "UTF-8")]
                (.sendResponseHeaders exchange 200 (count response-bytes))
                (with-open [os (.getResponseBody exchange)]
                  (.write os response-bytes)))
              nil)))
        ;; Use default executor
        (.setExecutor server nil)
        ;; Start server
        (.start server)
        (reset! server-state {:server server
                              :port port
                              :api-key (some? api-key)
                              :allowed-origins allowed-origins})
        (log/info "Admin API server started on port" port)
        true)
      (catch Exception e
        (log/error e "Failed to start admin server on port" port)
        false))))

(defn stop!
  "Stop the admin HTTP server.

   Returns true if stopped successfully, false if not running."
  []
  (if-let [{:keys [^HttpServer server port]} @server-state]
    (do
      (.stop server 0)
      (reset! server-state nil)
      (log/info "Admin server stopped (was on port" port ")")
      true)
    (do
      (log/debug "Admin server not running")
      false)))

(defn running?
  "Check if admin server is running."
  []
  (some? @server-state))

(defn get-status
  "Get admin server status.

   Returns nil if not running, or map with status info if running."
  []
  (when-let [{:keys [port api-key allowed-origins]} @server-state]
    {:running true
     :port port
     :auth-enabled api-key
     :cors-enabled (some? (seq allowed-origins))
     :base-url (str "http://localhost:" port "/api/v1")}))
