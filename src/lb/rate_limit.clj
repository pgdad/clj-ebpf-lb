(ns lb.rate-limit
  "Rate limiting management for the load balancer.

   Provides per-source IP and per-backend rate limiting using a token bucket
   algorithm. Rate limits are configured via BPF maps and enforced in the
   XDP program.

   Token bucket parameters:
   - rate: tokens added per second (requests/sec)
   - burst: maximum tokens (handles traffic spikes)

   Rate limiting is disabled by default (rate = 0)."
  (:require [lb.maps :as maps]
            [lb.util :as util]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Rate Limit State
;;; =============================================================================

(defonce rate-limit-state
  (atom {:config-map nil
         :src-map nil
         :backend-map nil
         :source-config nil    ; {:rate N :burst M} or nil if disabled
         :backend-config nil}))

;;; =============================================================================
;;; Initialization
;;; =============================================================================

(defn init!
  "Initialize rate limiting with the given BPF maps.

   rate-limit-config-map: Array map for rate limit configuration
   rate-limit-src-map: LRU map for per-source buckets
   rate-limit-backend-map: LRU map for per-backend buckets"
  [rate-limit-config-map rate-limit-src-map rate-limit-backend-map]
  (log/info "Initializing rate limiting")
  (reset! rate-limit-state
          {:config-map rate-limit-config-map
           :src-map rate-limit-src-map
           :backend-map rate-limit-backend-map
           :source-config nil
           :backend-config nil}))

(defn shutdown!
  "Shutdown rate limiting and clear state."
  []
  (log/info "Shutting down rate limiting")
  (reset! rate-limit-state
          {:config-map nil
           :src-map nil
           :backend-map nil
           :source-config nil
           :backend-config nil}))

(defn initialized?
  "Check if rate limiting is initialized."
  []
  (some? (:config-map @rate-limit-state)))

;;; =============================================================================
;;; Configuration API
;;; =============================================================================

(defn set-source-rate-limit!
  "Set per-source IP rate limit.

   rate: requests per second allowed from each source IP
   burst: maximum burst size (defaults to 2x rate)

   Returns true if successful."
  [rate & {:keys [burst]}]
  (let [{:keys [config-map]} @rate-limit-state
        burst (or burst (* 2 rate))]
    (when-not config-map
      (throw (ex-info "Rate limiting not initialized" {})))
    (when (or (neg? rate) (neg? burst))
      (throw (ex-info "Rate and burst must be non-negative" {:rate rate :burst burst})))
    (log/info "Setting source rate limit: rate=" rate "/sec, burst=" burst)
    (maps/set-rate-limit-config config-map :source rate burst)
    (swap! rate-limit-state assoc :source-config {:rate rate :burst burst})
    true))

(defn set-backend-rate-limit!
  "Set per-backend rate limit.

   rate: requests per second allowed to each backend
   burst: maximum burst size (defaults to 2x rate)

   Returns true if successful."
  [rate & {:keys [burst]}]
  (let [{:keys [config-map]} @rate-limit-state
        burst (or burst (* 2 rate))]
    (when-not config-map
      (throw (ex-info "Rate limiting not initialized" {})))
    (when (or (neg? rate) (neg? burst))
      (throw (ex-info "Rate and burst must be non-negative" {:rate rate :burst burst})))
    (log/info "Setting backend rate limit: rate=" rate "/sec, burst=" burst)
    (maps/set-rate-limit-config config-map :backend rate burst)
    (swap! rate-limit-state assoc :backend-config {:rate rate :burst burst})
    true))

(defn disable-source-rate-limit!
  "Disable per-source rate limiting."
  []
  (let [{:keys [config-map]} @rate-limit-state]
    (when config-map
      (log/info "Disabling source rate limiting")
      (maps/disable-rate-limit config-map :source)
      (swap! rate-limit-state assoc :source-config nil)
      true)))

(defn disable-backend-rate-limit!
  "Disable per-backend rate limiting."
  []
  (let [{:keys [config-map]} @rate-limit-state]
    (when config-map
      (log/info "Disabling backend rate limiting")
      (maps/disable-rate-limit config-map :backend)
      (swap! rate-limit-state assoc :backend-config nil)
      true)))

(defn clear-rate-limits!
  "Disable all rate limiting."
  []
  (disable-source-rate-limit!)
  (disable-backend-rate-limit!))

;;; =============================================================================
;;; Status API
;;; =============================================================================

(defn get-source-rate-limit
  "Get current source rate limit configuration.
   Returns {:rate N :burst M} or nil if disabled."
  []
  (:source-config @rate-limit-state))

(defn get-backend-rate-limit
  "Get current backend rate limit configuration.
   Returns {:rate N :burst M} or nil if disabled."
  []
  (:backend-config @rate-limit-state))

(defn get-rate-limit-config
  "Get all rate limit configuration.
   Returns {:per-source {...} :per-backend {...}} or nils for disabled limits."
  []
  {:per-source (get-source-rate-limit)
   :per-backend (get-backend-rate-limit)})

(defn source-rate-limit-enabled?
  "Check if source rate limiting is enabled."
  []
  (some? (:source-config @rate-limit-state)))

(defn backend-rate-limit-enabled?
  "Check if backend rate limiting is enabled."
  []
  (some? (:backend-config @rate-limit-state)))

(defn rate-limiting-enabled?
  "Check if any rate limiting is enabled."
  []
  (or (source-rate-limit-enabled?)
      (backend-rate-limit-enabled?)))

;;; =============================================================================
;;; Convenience Functions
;;; =============================================================================

(defn configure-from-settings!
  "Configure rate limiting from settings map.

   settings: Map with optional :rate-limits key containing:
     {:per-source {:requests-per-sec N :burst M}
      :per-backend {:requests-per-sec N :burst M}}"
  [settings]
  (when-let [rate-limits (:rate-limits settings)]
    (when-let [{:keys [requests-per-sec burst]} (:per-source rate-limits)]
      (set-source-rate-limit! requests-per-sec :burst burst))
    (when-let [{:keys [requests-per-sec burst]} (:per-backend rate-limits)]
      (set-backend-rate-limit! requests-per-sec :burst burst))))

(defn print-rate-limit-status
  "Print current rate limit status."
  []
  (println "\n=== Rate Limit Status ===")
  (if (initialized?)
    (do
      (println "\nPer-Source Rate Limit:")
      (if-let [config (get-source-rate-limit)]
        (println (format "  Rate: %d/sec, Burst: %d" (:rate config) (:burst config)))
        (println "  Disabled"))
      (println "\nPer-Backend Rate Limit:")
      (if-let [config (get-backend-rate-limit)]
        (println (format "  Rate: %d/sec, Burst: %d" (:rate config) (:burst config)))
        (println "  Disabled")))
    (println "  Rate limiting not initialized")))
