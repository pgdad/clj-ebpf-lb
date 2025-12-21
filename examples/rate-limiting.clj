;; Rate Limiting Examples
;;
;; Demonstrates rate limiting to protect backends from overload and
;; prevent individual clients from consuming too many resources.
;;
;; Usage:
;;   sudo clojure -M:dev
;;   (load-file "examples/rate-limiting.clj")
;;
;; Rate limiting uses a token bucket algorithm:
;;   - rate: tokens added per second (sustained request rate)
;;   - burst: maximum tokens (handles temporary traffic spikes)
;;   - Requests are dropped when bucket is empty

(ns examples.rate-limiting
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.rate-limit :as rate-limit]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Example Configurations
;;; =============================================================================

(def basic-config
  "Basic configuration for rate limiting demos"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target {:ip "127.0.0.1" :port 9000}}]
   :settings
   {:stats-enabled true}})

(def rate-limited-config
  "Configuration with rate limits applied at startup"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target {:ip "127.0.0.1" :port 9000}}]
   :settings
   {:stats-enabled true
    ;; Rate limits applied automatically on init
    :rate-limits
    {:per-source {:requests-per-sec 100 :burst 200}
     :per-backend {:requests-per-sec 10000 :burst 15000}}}})

;;; =============================================================================
;;; Basic Rate Limiting
;;; =============================================================================

(defn demo-source-rate-limit
  "Demonstrate per-source IP rate limiting"
  []
  (println "\n=== Per-Source Rate Limiting Demo ===")
  (println "Limits requests from individual source IPs.\n")

  ;; Set a source rate limit
  (println "Setting source rate limit: 100 req/sec, burst 200...")
  (lb/set-source-rate-limit! 100)

  ;; Check status
  (let [config (lb/get-rate-limit-config)]
    (println "Source config:" (:per-source config)))

  ;; With custom burst
  (println "\nSetting custom burst (100 req/sec, burst 500)...")
  (lb/set-source-rate-limit! 100 :burst 500)

  (let [config (lb/get-rate-limit-config)]
    (println "Source config:" (:per-source config))))

(defn demo-backend-rate-limit
  "Demonstrate per-backend rate limiting"
  []
  (println "\n=== Per-Backend Rate Limiting Demo ===")
  (println "Protects backends from being overwhelmed.\n")

  ;; Set a backend rate limit
  (println "Setting backend rate limit: 10000 req/sec, burst 15000...")
  (lb/set-backend-rate-limit! 10000 :burst 15000)

  ;; Check status
  (let [config (lb/get-rate-limit-config)]
    (println "Backend config:" (:per-backend config))))

(defn demo-combined-limits
  "Demonstrate both rate limits together"
  []
  (println "\n=== Combined Rate Limiting Demo ===")
  (println "Using both source and backend limits provides defense in depth.\n")

  ;; Set both limits
  (lb/set-source-rate-limit! 100 :burst 200)
  (lb/set-backend-rate-limit! 10000 :burst 15000)

  ;; Check status
  (lb/print-rate-limit-status))

;;; =============================================================================
;;; Rate Limit Management
;;; =============================================================================

(defn demo-disable-limits
  "Demonstrate disabling rate limits"
  []
  (println "\n=== Disable Rate Limits Demo ===")

  ;; Set some limits first
  (lb/set-source-rate-limit! 100)
  (lb/set-backend-rate-limit! 10000)

  (println "Rate limits enabled:")
  (println "  Source enabled?" (rate-limit/source-rate-limit-enabled?))
  (println "  Backend enabled?" (rate-limit/backend-rate-limit-enabled?))

  ;; Disable source only
  (println "\nDisabling source rate limit...")
  (lb/disable-source-rate-limit!)
  (println "  Source enabled?" (rate-limit/source-rate-limit-enabled?))
  (println "  Backend enabled?" (rate-limit/backend-rate-limit-enabled?))

  ;; Clear all
  (println "\nClearing all rate limits...")
  (lb/clear-rate-limits!)
  (println "  Any enabled?" (lb/rate-limiting-enabled?)))

;;; =============================================================================
;;; Use Case Examples
;;; =============================================================================

(defn setup-api-protection
  "Example: Protect an API with appropriate limits.

   - Source limit: 100/sec prevents individual clients from abusing
   - Backend limit: 10000/sec protects backend capacity

   Usage: (setup-api-protection)"
  []
  (println "\n=== API Protection Setup ===")

  ;; Per-source: Prevent individual clients from overwhelming
  ;; 100 req/sec sustained, 200 burst for legitimate traffic spikes
  (lb/set-source-rate-limit! 100 :burst 200)
  (println "Source rate limit: 100/sec, burst 200")
  (println "  -> Each client IP limited to 100 req/sec")

  ;; Per-backend: Protect backend capacity
  ;; 10000 req/sec matches backend processing capability
  (lb/set-backend-rate-limit! 10000 :burst 15000)
  (println "Backend rate limit: 10000/sec, burst 15000")
  (println "  -> Total traffic to backend limited to 10000 req/sec")

  (println "\nRate limiting configured for API protection."))

(defn setup-ddos-protection
  "Example: More aggressive limits for DDoS scenarios.

   - Tight source limits prevent any single source from overwhelming
   - Lower burst prevents traffic spikes from saturating

   Usage: (setup-ddos-protection)"
  []
  (println "\n=== DDoS Protection Setup ===")

  ;; Very tight per-source limits
  (lb/set-source-rate-limit! 10 :burst 20)
  (println "Source rate limit: 10/sec, burst 20")
  (println "  -> Aggressive limiting of individual sources")

  ;; Keep backend limit reasonable
  (lb/set-backend-rate-limit! 5000 :burst 7500)
  (println "Backend rate limit: 5000/sec, burst 7500")
  (println "  -> Reduced backend load under attack")

  (println "\nDDoS protection enabled."))

(defn setup-generous-limits
  "Example: Generous limits for trusted environments.

   - Higher source limits for internal services
   - Backend limit only as safety net

   Usage: (setup-generous-limits)"
  []
  (println "\n=== Generous Limits Setup ===")

  ;; High source limit for trusted clients
  (lb/set-source-rate-limit! 1000 :burst 5000)
  (println "Source rate limit: 1000/sec, burst 5000")
  (println "  -> Generous limits for trusted sources")

  ;; Backend limit as safety net
  (lb/set-backend-rate-limit! 50000 :burst 75000)
  (println "Backend rate limit: 50000/sec, burst 75000")
  (println "  -> High limit, mainly as safety net")

  (println "\nGenerous limits configured."))

;;; =============================================================================
;;; Helper Functions
;;; =============================================================================

(defn show-rate-limit-api
  "Print available rate limit API functions"
  []
  (println "
=== Rate Limiting API ===

Set rate limits:
  (lb/set-source-rate-limit! rate)
  (lb/set-source-rate-limit! rate :burst burst)
  (lb/set-backend-rate-limit! rate)
  (lb/set-backend-rate-limit! rate :burst burst)

Disable rate limits:
  (lb/disable-source-rate-limit!)
  (lb/disable-backend-rate-limit!)
  (lb/clear-rate-limits!)               ; Disable both

Check status:
  (lb/rate-limiting-enabled?)           ; => true/false
  (lb/get-rate-limit-config)            ; => {:per-source {...} :per-backend {...}}
  (lb/print-rate-limit-status)          ; Print formatted status

Token bucket parameters:
  rate  - Tokens added per second (sustained request rate)
  burst - Maximum tokens (default: 2x rate)
          Higher burst allows temporary traffic spikes

Configuration via settings:
  {:settings
   {:rate-limits
    {:per-source {:requests-per-sec 100 :burst 200}
     :per-backend {:requests-per-sec 10000 :burst 15000}}}}
"))

;;; =============================================================================
;;; Main Demo
;;; =============================================================================

(defn -main
  "Run all demos. Requires load balancer to be initialized first."
  []
  (if (lb/running?)
    (do
      (show-rate-limit-api)
      (demo-source-rate-limit)
      (Thread/sleep 500)
      (demo-backend-rate-limit)
      (Thread/sleep 500)
      (demo-combined-limits)
      (Thread/sleep 500)
      (demo-disable-limits)
      (println "\n\nTo run use case examples:")
      (println "  (setup-api-protection)")
      (println "  (setup-ddos-protection)")
      (println "  (setup-generous-limits)"))
    (println "
Load balancer not running. Initialize first:

  (def cfg (lb.config/parse-config examples.rate-limiting/basic-config))
  (lb/init! cfg)

Or with rate limits pre-configured:

  (def cfg (lb.config/parse-config examples.rate-limiting/rate-limited-config))
  (lb/init! cfg)

Then run demos:
  (examples.rate-limiting/-main)

When done:
  (lb/shutdown!)
")))

;; Show usage on load
(println "
=== Rate Limiting Examples Loaded ===

Quick start:
  (def cfg (lb.config/parse-config examples.rate-limiting/basic-config))
  (lb/init! cfg)
  (examples.rate-limiting/-main)

Individual demos:
  (demo-source-rate-limit)
  (demo-backend-rate-limit)
  (demo-combined-limits)
  (demo-disable-limits)

Use case examples:
  (setup-api-protection)
  (setup-ddos-protection)
  (setup-generous-limits)

API reference:
  (show-rate-limit-api)
")
