(ns lb.admin
  "Public API for Admin HTTP REST server.

   This module provides a RESTful HTTP API for runtime management of the
   load balancer, enabling automation, scripting, and integration with
   orchestration tools without requiring REPL access.

   Configuration:
   ```clojure
   {:settings
    {:admin-api {:enabled true
                 :port 8081              ; HTTP port (default 8081)
                 :api-key \"secret-key\"  ; Optional API key auth
                 :allowed-origins nil}}} ; Optional CORS origins
   ```

   Example usage:
   ```bash
   # Get status
   curl http://localhost:8081/api/v1/status

   # List proxies
   curl http://localhost:8081/api/v1/proxies

   # Add a proxy
   curl -X POST http://localhost:8081/api/v1/proxies \\
     -H 'Content-Type: application/json' \\
     -d '{\"name\":\"web\",\"listen\":{\"interfaces\":[\"eth0\"],\"port\":80}}'

   # With API key authentication
   curl -H 'X-API-Key: secret-key' http://localhost:8081/api/v1/status
   ```"
  (:require [lb.admin.server :as server]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Lifecycle Functions
;;; =============================================================================

(defn start!
  "Start the admin HTTP server.

   config is an AdminApiConfig record or map with:
     :enabled - Whether to start the server
     :port - Port to listen on (default 8081)
     :api-key - Optional API key for authentication
     :allowed-origins - Optional list of CORS allowed origins

   Returns true if started successfully, false otherwise."
  [config]
  (if (:enabled config)
    (do
      (log/info "Starting admin API server...")
      ;; Require handlers dynamically to avoid cyclic dependency
      (require 'lb.admin.handlers)
      (let [routes (var-get (resolve 'lb.admin.handlers/routes))]
        (server/start! {:port (or (:port config) 8081)
                        :api-key (:api-key config)
                        :allowed-origins (:allowed-origins config)
                        :routes routes})))
    (do
      (log/debug "Admin API is disabled")
      false)))

(defn stop!
  "Stop the admin HTTP server.

   Returns true if stopped successfully, false if not running."
  []
  (server/stop!))

(defn running?
  "Check if admin server is running."
  []
  (server/running?))

(defn get-status
  "Get admin server status.

   Returns nil if not running, or map with:
     :running - true
     :port - Port number
     :auth-enabled - Whether API key auth is enabled
     :cors-enabled - Whether CORS is enabled
     :base-url - Base URL for API requests"
  []
  (server/get-status))
