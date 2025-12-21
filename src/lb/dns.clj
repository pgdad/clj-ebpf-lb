(ns lb.dns
  "DNS-based backend resolution for dynamic environments.

   Provides:
   - DNS hostname support for backend targets
   - Periodic re-resolution with configurable intervals
   - Multiple A record expansion to weighted targets
   - Graceful failure handling with last-known-good fallback

   Usage:
     ;; In configuration
     :default-target {:host \"backend.local\" :port 8080 :dns-refresh-seconds 30}

     ;; Programmatic usage
     (dns/start!)
     (dns/register-target! \"proxy-name\" \"hostname\" config update-fn)
     (dns/get-status \"proxy-name\")
     (dns/stop!)"
  (:require [lb.dns.manager :as manager]
            [lb.dns.resolver :as resolver]))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start the DNS resolution daemon.
   Called automatically during load balancer init."
  []
  (manager/start!))

(defn stop!
  "Stop the DNS resolution daemon.
   Called automatically during load balancer shutdown."
  []
  (manager/stop!))

(defn running?
  "Check if the DNS resolution daemon is running."
  []
  (manager/running?))

;;; =============================================================================
;;; Target Registration
;;; =============================================================================

(defn register-target!
  "Register a DNS-backed target for periodic resolution.

   Parameters:
     proxy-name - Name of the proxy this target belongs to
     hostname - DNS hostname to resolve
     config - Map with:
       :port - Target port (required)
       :weight - Weight for this target (default 100)
       :dns-refresh-seconds - Refresh interval (default 30)
       :health-check - Optional health check config
     update-callback - Function called with (hostname target-group) when IPs change

   Returns true if registered successfully.

   Throws exception if initial DNS resolution fails (startup failure)."
  [proxy-name hostname config update-callback]
  (manager/register-dns-target! proxy-name hostname config update-callback))

(defn unregister-target!
  "Unregister a DNS target and stop its refresh task."
  [proxy-name hostname]
  (manager/unregister-dns-target! proxy-name hostname))

(defn unregister-proxy!
  "Unregister all DNS targets for a proxy."
  [proxy-name]
  (manager/unregister-proxy! proxy-name))

;;; =============================================================================
;;; Status
;;; =============================================================================

(defn get-status
  "Get DNS resolution status for a proxy.

   Returns map with:
     :proxy-name - Proxy name
     :targets - Map of hostname -> status including:
       :hostname, :port, :weight, :refresh-ms
       :last-ips, :last-resolved-at, :consecutive-failures"
  [proxy-name]
  (manager/get-dns-status proxy-name))

(defn get-all-status
  "Get DNS resolution status for all proxies."
  []
  (manager/get-all-dns-status))

(defn force-resolve!
  "Force immediate DNS re-resolution for a hostname.
   Useful for testing or manual refresh after DNS changes."
  [proxy-name hostname]
  (manager/force-resolve! proxy-name hostname))

;;; =============================================================================
;;; Events
;;; =============================================================================

(defn subscribe!
  "Subscribe to DNS events.

   Events have keys:
     :type - :dns-resolved or :dns-failed
     :proxy-name - Proxy name
     :hostname - Hostname that was resolved
     :timestamp - Event timestamp
     :data - Event-specific data

   Returns unsubscribe function."
  [callback]
  (manager/subscribe! callback))

;;; =============================================================================
;;; Direct Resolution (for testing/debugging)
;;; =============================================================================

(defn resolve-hostname
  "Resolve a hostname directly (bypass caching).
   Returns ResolveResult with :success?, :ips, :error-type, :message."
  [hostname]
  (resolver/resolve-hostname-all hostname 5000))

(defn resolve-all-ips
  "Resolve a hostname and return vector of IP strings, or nil on failure."
  [hostname]
  (let [result (resolve-hostname hostname)]
    (when (:success? result)
      (mapv lb.util/u32->ip-string (:ips result)))))
