(ns admin-api
  "Example: Admin HTTP REST API

   This example demonstrates how to configure and use the Admin HTTP API
   for runtime management of the load balancer without REPL access.

   The Admin API enables:
   - Automation and scripting of LB operations
   - Integration with orchestration tools (Kubernetes, Ansible, etc.)
   - Remote management via HTTP
   - Monitoring and health checks"
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.admin :as admin]))

;; =============================================================================
;; Configuration Examples
;; =============================================================================

(def config-with-admin-api
  "Configuration with admin API enabled."
  {:proxies
   [{:name "web"
     :listen {:interfaces ["lo"] :port 8080}
     :default-target [{:ip "127.0.0.1" :port 9001 :weight 50}
                      {:ip "127.0.0.1" :port 9002 :weight 50}]}]
   :settings
   {:stats-enabled true
    :admin-api {:enabled true
                :port 8081}}})

(def config-with-auth
  "Configuration with API key authentication."
  {:proxies
   [{:name "web"
     :listen {:interfaces ["eth0"] :port 80}
     :default-target {:ip "10.0.0.1" :port 8080}}]
   :settings
   {:admin-api {:enabled true
                :port 8081
                :api-key "my-secret-key-at-least-8-chars"}}})

(def config-with-cors
  "Configuration with CORS enabled for web dashboard access."
  {:proxies
   [{:name "api"
     :listen {:interfaces ["eth0"] :port 443}
     :default-target {:ip "10.0.0.1" :port 8443}}]
   :settings
   {:admin-api {:enabled true
                :port 8081
                :allowed-origins ["https://dashboard.example.com"
                                  "http://localhost:3000"]}}})

;; =============================================================================
;; Runtime API Examples
;; =============================================================================

(defn demo-admin-api
  "Demonstrate admin API usage from Clojure."
  []
  (println "=== Admin API Demo ===")

  ;; Check if admin API is running
  (println "Admin API running?" (admin/running?))

  ;; Get admin API status
  (when-let [status (admin/get-status)]
    (println "\nAdmin API Status:")
    (println "  Port:" (:port status))
    (println "  Auth enabled:" (:auth-enabled status))
    (println "  CORS enabled:" (:cors-enabled status))
    (println "  Base URL:" (:base-url status))))

;; =============================================================================
;; Usage Example (REPL)
;; =============================================================================

(comment
  ;; Start the load balancer with admin API
  (lb/init! (config/parse-config config-with-admin-api))

  ;; The admin API is now available at http://localhost:8081
  ;; See curl commands below for usage

  ;; Check admin API status
  (demo-admin-api)

  ;; Shutdown
  (lb/shutdown!))

;; =============================================================================
;; curl Command Examples
;; =============================================================================

;; The following curl commands can be used to interact with the Admin API.
;; Replace localhost:8081 with your server address if needed.

;; -----------------------------------------------------------------------------
;; Status & Info
;; -----------------------------------------------------------------------------

;; Get overall status
;; curl http://localhost:8081/api/v1/status

;; Get current configuration
;; curl http://localhost:8081/api/v1/config

;; -----------------------------------------------------------------------------
;; Proxy Management
;; -----------------------------------------------------------------------------

;; List all proxies
;; curl http://localhost:8081/api/v1/proxies

;; Get a specific proxy
;; curl http://localhost:8081/api/v1/proxies/web

;; Add a new proxy
;; curl -X POST http://localhost:8081/api/v1/proxies \
;;   -H "Content-Type: application/json" \
;;   -d '{
;;     "name": "api-gateway",
;;     "listen": {"interfaces": ["eth0"], "port": 8080},
;;     "default-target": {"ip": "10.0.0.1", "port": 8080}
;;   }'

;; Add a proxy with weighted backends
;; curl -X POST http://localhost:8081/api/v1/proxies \
;;   -H "Content-Type: application/json" \
;;   -d '{
;;     "name": "web-cluster",
;;     "listen": {"interfaces": ["eth0"], "port": 80},
;;     "default-target": [
;;       {"ip": "10.0.0.1", "port": 8080, "weight": 50},
;;       {"ip": "10.0.0.2", "port": 8080, "weight": 30},
;;       {"ip": "10.0.0.3", "port": 8080, "weight": 20}
;;     ]
;;   }'

;; Remove a proxy
;; curl -X DELETE http://localhost:8081/api/v1/proxies/api-gateway

;; -----------------------------------------------------------------------------
;; Source Route Management
;; -----------------------------------------------------------------------------

;; List source routes for a proxy
;; curl http://localhost:8081/api/v1/proxies/web/routes

;; Add a source route
;; curl -X POST http://localhost:8081/api/v1/proxies/web/routes \
;;   -H "Content-Type: application/json" \
;;   -d '{
;;     "source": "192.168.1.0/24",
;;     "target": {"ip": "10.0.0.5", "port": 8080}
;;   }'

;; Add a source route with weighted targets
;; curl -X POST http://localhost:8081/api/v1/proxies/web/routes \
;;   -H "Content-Type: application/json" \
;;   -d '{
;;     "source": "10.0.0.0/8",
;;     "targets": [
;;       {"ip": "10.0.0.10", "port": 8080, "weight": 70},
;;       {"ip": "10.0.0.11", "port": 8080, "weight": 30}
;;     ]
;;   }'

;; Remove a source route (URL encode the CIDR)
;; curl -X DELETE http://localhost:8081/api/v1/proxies/web/routes/192.168.1.0%2F24

;; -----------------------------------------------------------------------------
;; SNI Route Management
;; -----------------------------------------------------------------------------

;; List SNI routes for a proxy
;; curl http://localhost:8081/api/v1/proxies/web/sni-routes

;; Add an SNI route
;; curl -X POST http://localhost:8081/api/v1/proxies/web/sni-routes \
;;   -H "Content-Type: application/json" \
;;   -d '{
;;     "sni-hostname": "api.example.com",
;;     "target": {"ip": "10.0.0.20", "port": 8443}
;;   }'

;; Remove an SNI route
;; curl -X DELETE http://localhost:8081/api/v1/proxies/web/sni-routes/api.example.com

;; -----------------------------------------------------------------------------
;; Connection Management
;; -----------------------------------------------------------------------------

;; List active connections
;; curl http://localhost:8081/api/v1/connections

;; Get connection count
;; curl http://localhost:8081/api/v1/connections/count

;; Get connection statistics
;; curl http://localhost:8081/api/v1/connections/stats

;; Clear all connections
;; curl -X DELETE http://localhost:8081/api/v1/connections

;; -----------------------------------------------------------------------------
;; Health Status
;; -----------------------------------------------------------------------------

;; Get all health statuses
;; curl http://localhost:8081/api/v1/health

;; Get health status for a specific proxy
;; curl http://localhost:8081/api/v1/health/web

;; -----------------------------------------------------------------------------
;; Connection Draining
;; -----------------------------------------------------------------------------

;; Get all draining backends
;; curl http://localhost:8081/api/v1/drains

;; Start draining a backend
;; curl -X POST http://localhost:8081/api/v1/drains \
;;   -H "Content-Type: application/json" \
;;   -d '{
;;     "proxy": "web",
;;     "target": "10.0.0.1:8080",
;;     "timeout_ms": 60000
;;   }'

;; Cancel draining (requires proxy in body)
;; curl -X DELETE http://localhost:8081/api/v1/drains/10.0.0.1%3A8080 \
;;   -H "Content-Type: application/json" \
;;   -d '{"proxy": "web"}'

;; -----------------------------------------------------------------------------
;; Circuit Breaker
;; -----------------------------------------------------------------------------

;; Get all circuit breaker states
;; curl http://localhost:8081/api/v1/circuits

;; Force a circuit open
;; curl -X POST http://localhost:8081/api/v1/circuits/10.0.0.1%3A8080/open

;; Force a circuit closed
;; curl -X POST http://localhost:8081/api/v1/circuits/10.0.0.1%3A8080/close

;; Reset a circuit
;; curl -X POST http://localhost:8081/api/v1/circuits/10.0.0.1%3A8080/reset

;; -----------------------------------------------------------------------------
;; DNS Resolution
;; -----------------------------------------------------------------------------

;; Get all DNS resolution status
;; curl http://localhost:8081/api/v1/dns

;; Force DNS resolution for a hostname
;; curl -X POST http://localhost:8081/api/v1/dns/backend.example.com/resolve

;; -----------------------------------------------------------------------------
;; Load Balancing
;; -----------------------------------------------------------------------------

;; Get load balancing status
;; curl http://localhost:8081/api/v1/lb

;; Force weight update (for least-connections algorithm)
;; curl -X POST http://localhost:8081/api/v1/lb/update

;; -----------------------------------------------------------------------------
;; Rate Limiting
;; -----------------------------------------------------------------------------

;; Get rate limit configuration
;; curl http://localhost:8081/api/v1/rate-limits

;; Set source rate limit
;; curl -X POST http://localhost:8081/api/v1/rate-limits/source \
;;   -H "Content-Type: application/json" \
;;   -d '{"requests_per_sec": 100, "burst": 200}'

;; Set backend rate limit
;; curl -X POST http://localhost:8081/api/v1/rate-limits/backend \
;;   -H "Content-Type: application/json" \
;;   -d '{"requests_per_sec": 1000, "burst": 2000}'

;; Clear all rate limits
;; curl -X DELETE http://localhost:8081/api/v1/rate-limits

;; -----------------------------------------------------------------------------
;; Configuration Reload
;; -----------------------------------------------------------------------------

;; Reload configuration from file
;; curl -X POST http://localhost:8081/api/v1/reload

;; -----------------------------------------------------------------------------
;; Authentication (when API key is configured)
;; -----------------------------------------------------------------------------

;; All endpoints with API key authentication:
;; curl -H "X-API-Key: my-secret-key" http://localhost:8081/api/v1/status

;; =============================================================================
;; Response Format
;; =============================================================================

;; Success response:
;; {
;;   "success": true,
;;   "data": { ... },
;;   "error": null
;; }

;; Error response:
;; {
;;   "success": false,
;;   "data": null,
;;   "error": {
;;     "code": "NOT_FOUND",
;;     "message": "Proxy 'foo' not found"
;;   }
;; }

;; =============================================================================
;; Integration Examples
;; =============================================================================

;; Kubernetes readiness probe:
;; livenessProbe:
;;   httpGet:
;;     path: /health
;;     port: 8081
;;   initialDelaySeconds: 5
;;   periodSeconds: 10

;; Ansible task example:
;; - name: Add backend to load balancer
;;   uri:
;;     url: http://lb-admin:8081/api/v1/proxies/web/routes
;;     method: POST
;;     body_format: json
;;     body:
;;       source: "{{ backend_cidr }}"
;;       target:
;;         ip: "{{ backend_ip }}"
;;         port: "{{ backend_port }}"
;;     headers:
;;       X-API-Key: "{{ lb_api_key }}"

;; Shell script for draining:
;; #!/bin/bash
;; LB_HOST="localhost:8081"
;; BACKEND="10.0.0.1:8080"
;; PROXY="web"
;;
;; # Start drain
;; curl -X POST "${LB_HOST}/api/v1/drains" \
;;   -H "Content-Type: application/json" \
;;   -d "{\"proxy\":\"${PROXY}\",\"target\":\"${BACKEND}\",\"timeout_ms\":30000}"
;;
;; # Wait for drain
;; while true; do
;;   STATUS=$(curl -s "${LB_HOST}/api/v1/drains" | jq -r ".data[\"${BACKEND}\"]")
;;   if [ "$STATUS" == "null" ]; then
;;     echo "Drain complete"
;;     break
;;   fi
;;   sleep 5
;; done
