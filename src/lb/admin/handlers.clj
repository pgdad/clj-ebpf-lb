(ns lb.admin.handlers
  "Request handlers for Admin REST API endpoints.

   Each handler receives a request map with:
   - :exchange - The HttpExchange object
   - :params - Path parameters extracted from URL
   - :body - Parsed JSON request body (or nil)

   Each handler returns a result map with either:
   - {:data ...} for success
   - {:error \"message\" :code \"CODE\" :status 400} for errors"
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.util :as util]
            [lb.cluster :as cluster]
            [lb.cluster.conntrack :as cluster-conntrack]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Helper Functions
;;; =============================================================================

(defn- require-param
  "Check that a required parameter is present in body."
  [body param]
  (when-not (get body param)
    {:error (str "Missing required parameter: " (name param))
     :code "MISSING_PARAM"
     :status 400}))

(defn- with-running-check
  "Wrap handler to check if LB is running."
  [handler-fn]
  (fn [request]
    (if (lb/running?)
      (handler-fn request)
      {:error "Load balancer is not running"
       :code "NOT_RUNNING"
       :status 503})))

(defn- safe-call
  "Safely call a function, catching exceptions."
  [f & args]
  (try
    {:data (apply f args)}
    (catch clojure.lang.ExceptionInfo e
      {:error (.getMessage e)
       :code "OPERATION_FAILED"
       :status 400})
    (catch Exception e
      {:error (.getMessage e)
       :code "INTERNAL_ERROR"
       :status 500})))

;;; =============================================================================
;;; Status & Info Handlers
;;; =============================================================================

(defn handle-get-status
  "GET /api/v1/status - Get overall LB status"
  [_request]
  (if (lb/running?)
    {:data (lb/get-status)}
    {:data {:running false}}))

(defn handle-get-config
  "GET /api/v1/config - Get current configuration"
  [_request]
  (if-let [state (lb/get-state)]
    {:data (config/config->map (:config state))}
    {:error "No configuration available"
     :code "NO_CONFIG"
     :status 404}))

;;; =============================================================================
;;; Proxy Handlers
;;; =============================================================================

(defn handle-list-proxies
  "GET /api/v1/proxies - List all proxies"
  [_request]
  (if-let [state (lb/get-state)]
    {:data (mapv (fn [p]
                   {:name (:name p)
                    :listen {:interfaces (get-in p [:listen :interfaces])
                             :port (get-in p [:listen :port])}
                    :default-target (config/target-group->map (:default-target p))
                    :source-route-count (count (:source-routes p))
                    :sni-route-count (count (:sni-routes p))})
                 (get-in state [:config :proxies]))}
    {:error "No configuration available"
     :code "NO_CONFIG"
     :status 404}))

(defn handle-add-proxy
  "POST /api/v1/proxies - Add a new proxy"
  [{:keys [body]}]
  (if-let [err (require-param body :name)]
    err
    (if-let [err (require-param body :listen)]
      err
      (if-let [err (require-param body :default-target)]
        err
        (safe-call lb/add-proxy! body)))))

(defn handle-remove-proxy
  "DELETE /api/v1/proxies/:name - Remove a proxy"
  [{:keys [params]}]
  (let [name (:name params)]
    (safe-call lb/remove-proxy! name)))

(defn handle-get-proxy
  "GET /api/v1/proxies/:name - Get a specific proxy"
  [{:keys [params]}]
  (let [name (:name params)]
    (if-let [state (lb/get-state)]
      (if-let [proxy (first (filter #(= (:name %) name)
                                     (get-in state [:config :proxies])))]
        {:data {:name (:name proxy)
                :listen {:interfaces (get-in proxy [:listen :interfaces])
                         :port (get-in proxy [:listen :port])}
                :default-target (config/target-group->map (:default-target proxy))
                :source-routes (mapv (fn [sr]
                                       {:source (util/cidr->string {:ip (:source sr)
                                                                    :prefix-len (:prefix-len sr)})
                                        :target (config/target-group->map (:target-group sr))})
                                     (:source-routes proxy))
                :sni-routes (mapv (fn [sr]
                                    {:hostname (:hostname sr)
                                     :target (config/target-group->map (:target-group sr))})
                                  (:sni-routes proxy))}}
        {:error (str "Proxy '" name "' not found")
         :code "NOT_FOUND"
         :status 404})
      {:error "No configuration available"
       :code "NO_CONFIG"
       :status 404})))

;;; =============================================================================
;;; Route Handlers
;;; =============================================================================

(defn handle-list-source-routes
  "GET /api/v1/proxies/:name/routes - List source routes for a proxy"
  [{:keys [params]}]
  (let [name (:name params)]
    (if-let [state (lb/get-state)]
      (if-let [proxy (first (filter #(= (:name %) name)
                                     (get-in state [:config :proxies])))]
        {:data (mapv (fn [sr]
                       {:source (util/cidr->string {:ip (:source sr)
                                                    :prefix-len (:prefix-len sr)})
                        :target (config/target-group->map (:target-group sr))
                        :session-persistence (:session-persistence sr)})
                     (:source-routes proxy))}
        {:error (str "Proxy '" name "' not found")
         :code "NOT_FOUND"
         :status 404})
      {:error "No configuration available"
       :code "NO_CONFIG"
       :status 404})))

(defn handle-add-source-route
  "POST /api/v1/proxies/:name/routes - Add a source route"
  [{:keys [params body]}]
  (let [name (:name params)]
    (if-let [err (require-param body :source)]
      err
      (if (and (nil? (:target body)) (nil? (:targets body)))
        {:error "Missing required parameter: target or targets"
         :code "MISSING_PARAM"
         :status 400}
        (safe-call lb/add-source-route! name body)))))

(defn handle-remove-source-route
  "DELETE /api/v1/proxies/:name/routes/:source - Remove a source route"
  [{:keys [params]}]
  (let [name (:name params)
        source (:source params)]
    ;; URL decode and parse the source CIDR
    (let [decoded-source (java.net.URLDecoder/decode source "UTF-8")
          {:keys [ip prefix-len]} (util/resolve-to-ip decoded-source)]
      (if ip
        (safe-call lb/remove-source-route! name ip prefix-len)
        {:error (str "Invalid source CIDR: " decoded-source)
         :code "INVALID_PARAM"
         :status 400}))))

(defn handle-list-sni-routes
  "GET /api/v1/proxies/:name/sni-routes - List SNI routes for a proxy"
  [{:keys [params]}]
  (let [name (:name params)]
    (if-let [routes (lb/list-sni-routes name)]
      {:data routes}
      {:error (str "Proxy '" name "' not found or no SNI routes")
       :code "NOT_FOUND"
       :status 404})))

(defn handle-add-sni-route
  "POST /api/v1/proxies/:name/sni-routes - Add an SNI route"
  [{:keys [params body]}]
  (let [name (:name params)]
    (if-let [err (require-param body :sni-hostname)]
      err
      (if (and (nil? (:target body)) (nil? (:targets body)))
        {:error "Missing required parameter: target or targets"
         :code "MISSING_PARAM"
         :status 400}
        (safe-call lb/add-sni-route! name body)))))

(defn handle-remove-sni-route
  "DELETE /api/v1/proxies/:name/sni-routes/:hostname - Remove an SNI route"
  [{:keys [params]}]
  (let [name (:name params)
        hostname (:hostname params)]
    (safe-call lb/remove-sni-route! name hostname)))

;;; =============================================================================
;;; Connection Handlers
;;; =============================================================================

(defn handle-get-connections
  "GET /api/v1/connections - List active connections"
  [_request]
  {:data (lb/get-connections)})

(defn handle-get-connection-count
  "GET /api/v1/connections/count - Get connection count"
  [_request]
  {:data {:count (lb/get-connection-count)}})

(defn handle-get-connection-stats
  "GET /api/v1/connections/stats - Get connection statistics"
  [_request]
  {:data (lb/get-connection-stats)})

(defn handle-clear-connections
  "DELETE /api/v1/connections - Clear all connections"
  [_request]
  (safe-call lb/clear-connections!))

;;; =============================================================================
;;; Health Handlers
;;; =============================================================================

(defn handle-get-all-health
  "GET /api/v1/health - Get all health statuses"
  [_request]
  {:data (lb/get-all-health-status)})

(defn handle-get-proxy-health
  "GET /api/v1/health/:proxy - Get health status for a proxy"
  [{:keys [params]}]
  (let [proxy-name (:proxy params)]
    (if-let [status (lb/get-health-status proxy-name)]
      {:data status}
      {:error (str "Proxy '" proxy-name "' not found")
       :code "NOT_FOUND"
       :status 404})))

;;; =============================================================================
;;; Drain Handlers
;;; =============================================================================

(defn handle-get-drains
  "GET /api/v1/drains - Get all draining backends"
  [_request]
  {:data (lb/get-all-draining)})

(defn handle-add-drain
  "POST /api/v1/drains - Start draining a backend"
  [{:keys [body]}]
  (if-let [err (require-param body :proxy)]
    err
    (if-let [err (require-param body :target)]
      err
      (let [proxy-name (:proxy body)
            target (:target body)
            timeout-ms (get body :timeout_ms 30000)]
        (safe-call lb/drain-backend! proxy-name target timeout-ms)))))

(defn handle-remove-drain
  "DELETE /api/v1/drains/:target - Cancel draining for a backend"
  [{:keys [params body]}]
  (let [target (java.net.URLDecoder/decode (:target params) "UTF-8")
        proxy-name (:proxy body)]
    (if proxy-name
      (safe-call lb/undrain-backend! proxy-name target)
      {:error "Missing required parameter: proxy (in request body)"
       :code "MISSING_PARAM"
       :status 400})))

;;; =============================================================================
;;; Circuit Breaker Handlers
;;; =============================================================================

(defn handle-get-circuits
  "GET /api/v1/circuits - Get all circuit breaker states"
  [_request]
  {:data (lb/get-all-circuit-breaker-status)})

(defn handle-force-open-circuit
  "POST /api/v1/circuits/:target/open - Force circuit open"
  [{:keys [params]}]
  (let [target (java.net.URLDecoder/decode (:target params) "UTF-8")]
    (safe-call lb/force-circuit-open! target)))

(defn handle-force-close-circuit
  "POST /api/v1/circuits/:target/close - Force circuit close"
  [{:keys [params]}]
  (let [target (java.net.URLDecoder/decode (:target params) "UTF-8")]
    (safe-call lb/force-circuit-close! target)))

(defn handle-reset-circuit
  "POST /api/v1/circuits/:target/reset - Reset circuit"
  [{:keys [params]}]
  (let [target (java.net.URLDecoder/decode (:target params) "UTF-8")]
    (safe-call lb/reset-circuit! target)))

;;; =============================================================================
;;; DNS Handlers
;;; =============================================================================

(defn handle-get-dns-status
  "GET /api/v1/dns - Get all DNS resolution status"
  [_request]
  {:data (lb/get-all-dns-status)})

(defn handle-force-dns-resolve
  "POST /api/v1/dns/:hostname/resolve - Force DNS resolution"
  [{:keys [params]}]
  (let [hostname (:hostname params)]
    (safe-call lb/force-dns-resolve! hostname)))

;;; =============================================================================
;;; Load Balancing Handlers
;;; =============================================================================

(defn handle-get-lb-status
  "GET /api/v1/lb - Get load balancing status"
  [_request]
  {:data (lb/get-lb-status)})

(defn handle-force-lb-update
  "POST /api/v1/lb/update - Force load balancing weight update"
  [_request]
  (safe-call lb/force-lb-update!))

;;; =============================================================================
;;; Configuration Handlers
;;; =============================================================================

(defn handle-reload-config
  "POST /api/v1/reload - Reload configuration from file"
  [_request]
  (safe-call lb/reload-config!))

;;; =============================================================================
;;; Rate Limit Handlers
;;; =============================================================================

(defn handle-get-rate-limits
  "GET /api/v1/rate-limits - Get rate limit configuration"
  [_request]
  {:data (lb/get-rate-limit-config)})

(defn handle-set-source-rate-limit
  "POST /api/v1/rate-limits/source - Set source rate limit"
  [{:keys [body]}]
  (if-let [err (require-param body :requests_per_sec)]
    err
    (let [rps (:requests_per_sec body)
          burst (get body :burst rps)]
      (safe-call lb/set-source-rate-limit! rps burst))))

(defn handle-set-backend-rate-limit
  "POST /api/v1/rate-limits/backend - Set backend rate limit"
  [{:keys [body]}]
  (if-let [err (require-param body :requests_per_sec)]
    err
    (let [rps (:requests_per_sec body)
          burst (get body :burst rps)]
      (safe-call lb/set-backend-rate-limit! rps burst))))

(defn handle-clear-rate-limits
  "DELETE /api/v1/rate-limits - Clear all rate limits"
  [_request]
  (safe-call lb/clear-rate-limits!))

;;; =============================================================================
;;; Cluster Handlers
;;; =============================================================================

(defn handle-get-cluster-status
  "GET /api/v1/cluster/status - Get cluster status"
  [_request]
  (if (cluster/running?)
    {:data {:running true
            :node-id (cluster/node-id)
            :alive-nodes (vec (cluster/alive-nodes))
            :cluster-size (cluster/cluster-size)
            :local-node (cluster/local-node)
            :stats (cluster/stats)}}
    {:data {:running false}}))

(defn handle-get-cluster-sync-status
  "GET /api/v1/cluster/sync - Get cluster sync status"
  [_request]
  (if (cluster/running?)
    {:data {:conntrack (cluster-conntrack/sync-stats)
            :node-id (cluster/node-id)
            :running true}}
    {:data {:running false}}))

(defn handle-force-cluster-sync
  "POST /api/v1/cluster/sync - Force full cluster sync"
  [_request]
  (if (cluster/running?)
    (let [count (cluster-conntrack/force-full-sync!)]
      {:data {:synced-connections count
              :message (str "Forced sync of " count " connections")}})
    {:error "Cluster not running"
     :code "CLUSTER_NOT_RUNNING"
     :status 503}))

(defn handle-get-cluster-nodes
  "GET /api/v1/cluster/nodes - Get all cluster nodes"
  [_request]
  (if (cluster/running?)
    {:data {:nodes (cluster/all-nodes)
            :alive (vec (cluster/alive-nodes))
            :local-node-id (cluster/node-id)}}
    {:data {:nodes []}}))

;;; =============================================================================
;;; Route Definitions
;;; =============================================================================

(def routes
  "All API route definitions."
  [;; Status & Info
   {:method :get :pattern "/api/v1/status" :handler handle-get-status}
   {:method :get :pattern "/api/v1/config" :handler handle-get-config}

   ;; Proxies
   {:method :get :pattern "/api/v1/proxies" :handler handle-list-proxies}
   {:method :post :pattern "/api/v1/proxies" :handler handle-add-proxy}
   {:method :get :pattern "/api/v1/proxies/:name" :handler handle-get-proxy}
   {:method :delete :pattern "/api/v1/proxies/:name" :handler handle-remove-proxy}

   ;; Source Routes
   {:method :get :pattern "/api/v1/proxies/:name/routes" :handler handle-list-source-routes}
   {:method :post :pattern "/api/v1/proxies/:name/routes" :handler handle-add-source-route}
   {:method :delete :pattern "/api/v1/proxies/:name/routes/:source" :handler handle-remove-source-route}

   ;; SNI Routes
   {:method :get :pattern "/api/v1/proxies/:name/sni-routes" :handler handle-list-sni-routes}
   {:method :post :pattern "/api/v1/proxies/:name/sni-routes" :handler handle-add-sni-route}
   {:method :delete :pattern "/api/v1/proxies/:name/sni-routes/:hostname" :handler handle-remove-sni-route}

   ;; Connections
   {:method :get :pattern "/api/v1/connections" :handler handle-get-connections}
   {:method :get :pattern "/api/v1/connections/count" :handler handle-get-connection-count}
   {:method :get :pattern "/api/v1/connections/stats" :handler handle-get-connection-stats}
   {:method :delete :pattern "/api/v1/connections" :handler handle-clear-connections}

   ;; Health
   {:method :get :pattern "/api/v1/health" :handler handle-get-all-health}
   {:method :get :pattern "/api/v1/health/:proxy" :handler handle-get-proxy-health}

   ;; Drains
   {:method :get :pattern "/api/v1/drains" :handler handle-get-drains}
   {:method :post :pattern "/api/v1/drains" :handler handle-add-drain}
   {:method :delete :pattern "/api/v1/drains/:target" :handler handle-remove-drain}

   ;; Circuit Breaker
   {:method :get :pattern "/api/v1/circuits" :handler handle-get-circuits}
   {:method :post :pattern "/api/v1/circuits/:target/open" :handler handle-force-open-circuit}
   {:method :post :pattern "/api/v1/circuits/:target/close" :handler handle-force-close-circuit}
   {:method :post :pattern "/api/v1/circuits/:target/reset" :handler handle-reset-circuit}

   ;; DNS
   {:method :get :pattern "/api/v1/dns" :handler handle-get-dns-status}
   {:method :post :pattern "/api/v1/dns/:hostname/resolve" :handler handle-force-dns-resolve}

   ;; Load Balancing
   {:method :get :pattern "/api/v1/lb" :handler handle-get-lb-status}
   {:method :post :pattern "/api/v1/lb/update" :handler handle-force-lb-update}

   ;; Rate Limits
   {:method :get :pattern "/api/v1/rate-limits" :handler handle-get-rate-limits}
   {:method :post :pattern "/api/v1/rate-limits/source" :handler handle-set-source-rate-limit}
   {:method :post :pattern "/api/v1/rate-limits/backend" :handler handle-set-backend-rate-limit}
   {:method :delete :pattern "/api/v1/rate-limits" :handler handle-clear-rate-limits}

   ;; Configuration
   {:method :post :pattern "/api/v1/reload" :handler handle-reload-config}

   ;; Cluster
   {:method :get :pattern "/api/v1/cluster/status" :handler handle-get-cluster-status}
   {:method :get :pattern "/api/v1/cluster/sync" :handler handle-get-cluster-sync-status}
   {:method :post :pattern "/api/v1/cluster/sync" :handler handle-force-cluster-sync}
   {:method :get :pattern "/api/v1/cluster/nodes" :handler handle-get-cluster-nodes}])
