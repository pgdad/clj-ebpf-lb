;; Session Persistence (Sticky Sessions) Examples
;;
;; Demonstrates session persistence using source IP hashing to route
;; the same client consistently to the same backend server.
;;
;; Usage:
;;   sudo clojure -M:dev
;;   (load-file "examples/session_persistence.clj")
;;
;; Session persistence is useful for stateful applications where
;; client sessions need backend affinity (e.g., shopping carts,
;; login sessions, WebSocket connections).

(ns session-persistence
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.util :as util]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Example Configurations
;;; =============================================================================

(def example-config-sticky
  "Configuration with session persistence enabled.
   Same source IP always routes to same backend."
  {:proxies
   [{:name "sticky-api"
     :listen {:interfaces ["lo"] :port 8000}
     :session-persistence true  ; Enable sticky sessions
     :default-target
     [{:ip "127.0.0.1" :port 9001 :weight 50}
      {:ip "127.0.0.1" :port 9002 :weight 50}]
     :health-check
     {:type :tcp
      :interval-ms 5000
      :timeout-ms 2000}}]
   :settings
   {:stats-enabled true
    :health-check-enabled true}})

(def example-config-random
  "Configuration with default random load balancing.
   Requests are distributed randomly based on weights."
  {:proxies
   [{:name "random-api"
     :listen {:interfaces ["lo"] :port 8000}
     ;; session-persistence defaults to false
     :default-target
     [{:ip "127.0.0.1" :port 9001 :weight 50}
      {:ip "127.0.0.1" :port 9002 :weight 50}]}]
   :settings
   {:stats-enabled true}})

(def example-config-source-routes
  "Configuration with per-route session persistence.
   Different source networks can have different stickiness settings."
  {:proxies
   [{:name "mixed-api"
     :listen {:interfaces ["lo"] :port 8000}
     :session-persistence false  ; Default target uses random
     :default-target
     [{:ip "127.0.0.1" :port 9001 :weight 50}
      {:ip "127.0.0.1" :port 9002 :weight 50}]
     :source-routes
     [;; Internal network uses sticky sessions
      {:source "10.0.0.0/8"
       :target {:ip "127.0.0.1" :port 9003}
       :session-persistence true}
      ;; VPN network uses random
      {:source "172.16.0.0/12"
       :target {:ip "127.0.0.1" :port 9004}
       :session-persistence false}]}]})

;;; =============================================================================
;;; Algorithm Explanation
;;; =============================================================================

(defn explain-session-persistence
  "Explain how session persistence works"
  []
  (println "
=== Session Persistence (Sticky Sessions) ===

Algorithm:
  Routes clients consistently to the same backend using source IP hashing.
  Same client IP always selects the same backend (unless weights change).

How it works:
  1. XDP program extracts source IP from incoming packet
  2. Computes hash: (source_ip * FNV_PRIME) % 100
  3. Uses hash value to select backend from cumulative weights
  4. Same IP always produces same hash, thus same backend

Hash formula:
  selection_value = (source_ip * 2654435761) % 100

Example with 50/50 weights:
  Backend A: weight 50, cumulative weight 50
  Backend B: weight 50, cumulative weight 100

  IP 192.168.1.100 -> hash 37 -> Backend A (37 < 50)
  IP 192.168.1.101 -> hash 84 -> Backend B (84 >= 50)
  IP 192.168.1.100 -> hash 37 -> Backend A (always same)

Configuration:
  {:proxies
   [{:name \"my-service\"
     :listen {:interfaces [\"eth0\"] :port 8080}
     :session-persistence true  ; Enable sticky sessions
     :default-target
     [{:ip \"10.0.0.1\" :port 8080 :weight 50}
      {:ip \"10.0.0.2\" :port 8080 :weight 50}]}]}

Per-route configuration:
  {:source-routes
   [{:source \"10.0.0.0/8\"
     :target {:ip \"10.0.0.1\" :port 8080}
     :session-persistence true}]}
"))

;;; =============================================================================
;;; Hash Demonstration
;;; =============================================================================

(defn compute-selection
  "Compute which backend a source IP would select.
   Uses same formula as XDP program."
  [source-ip weights]
  (let [ip (util/ip-string->u32 source-ip)
        fnv-prime (unchecked-int 2654435761)
        product (unchecked-multiply (unchecked-int ip) fnv-prime)
        selection (mod (Math/abs product) 100)
        cumulative (reductions + weights)]
    (loop [idx 0 remaining cumulative]
      (if (empty? remaining)
        idx
        (if (< selection (first remaining))
          idx
          (recur (inc idx) (rest remaining)))))))

(defn demo-hash-selection
  "Demonstrate how different source IPs select backends"
  []
  (println "\n=== Source IP Hash Selection Demo ===\n")
  (let [weights [50 50]
        test-ips ["192.168.1.100" "192.168.1.101" "192.168.1.102"
                  "10.0.0.1" "10.0.0.2" "172.16.0.1"]]
    (println "Weights: [50, 50] (Backend A=50%, Backend B=50%)\n")
    (doseq [ip test-ips]
      (let [backend (compute-selection ip weights)]
        (println (format "  %s -> Backend %s"
                         ip
                         (if (zero? backend) "A" "B")))))
    (println "\nSame IP always selects same backend.")))

(defn demo-weight-impact
  "Demonstrate how weights affect sticky session distribution"
  []
  (println "\n=== Weight Impact on Distribution ===\n")
  (let [test-ips (for [a (range 10) b (range 25)]
                   (format "192.168.%d.%d" a b))]
    (doseq [weights [[50 50] [70 30] [90 10]]]
      (let [selections (map #(compute-selection % weights) test-ips)
            a-count (count (filter zero? selections))
            b-count (count (filter pos? selections))]
        (println (format "Weights %s: Backend A=%d%%, Backend B=%d%%"
                         weights
                         (int (* 100 (/ a-count (count test-ips))))
                         (int (* 100 (/ b-count (count test-ips))))))))))

;;; =============================================================================
;;; Use Cases
;;; =============================================================================

(defn show-use-cases
  "Show common use cases for session persistence"
  []
  (println "
=== When to Use Session Persistence ===

Good use cases:
  - Shopping cart applications (cart stored in backend memory)
  - User login sessions (session stored in backend)
  - WebSocket connections (stateful connection to specific server)
  - Gaming servers (player state on specific server)
  - File upload/download (resumable operations)

When NOT to use:
  - Stateless microservices (no benefit, reduces distribution)
  - Short-lived requests (overhead without benefit)
  - When backends have unequal capacity (may overload some)
  - During canary deployments (need controlled traffic split)

Considerations:
  - Backend failure: clients will fail until health check removes backend
  - Scaling: new backends won't get existing client traffic
  - Weights: changing weights affects hash-to-backend mapping
  - NAT: clients behind NAT will all route to same backend
"))

;;; =============================================================================
;;; Best Practices
;;; =============================================================================

(defn show-best-practices
  "Show production best practices"
  []
  (println "
=== Session Persistence Best Practices ===

1. Combine with Health Checks
   Session persistence respects health status.
   Unhealthy backends are excluded from selection.
   Clients will be remapped when their backend fails.

2. Use Consistent Weights
   Changing weights remaps clients to different backends.
   Plan weight changes carefully in production.

3. Consider Backend Capacity
   Clients behind NAT all route to same backend.
   This can cause uneven load in certain networks.

4. Plan for Failures
   When a backend fails, its clients are redistributed.
   Ensure application handles session regeneration gracefully.

5. Monitor Distribution
   Use Prometheus metrics to verify even distribution.
   Alert if one backend has significantly more connections.

6. Gradual Rollouts
   For canary deployments, consider using source-routes
   with session-persistence only for stable traffic.
"))

;;; =============================================================================
;;; Main Demo
;;; =============================================================================

(defn -main
  "Run session persistence demos"
  []
  (println "\n=== Session Persistence Examples Loaded ===")
  (explain-session-persistence)
  (demo-hash-selection)
  (println "\nTo start load balancer with sticky sessions:")
  (println "  (def cfg (config/parse-config session-persistence/example-config-sticky))")
  (println "  (lb/init! cfg)")
  (println "\nTo start with random load balancing:")
  (println "  (def cfg (config/parse-config session-persistence/example-config-random))")
  (println "  (lb/init! cfg)")
  (println "\nOther demos:")
  (println "  (demo-weight-impact)")
  (println "  (show-use-cases)")
  (println "  (show-best-practices)"))

;; Show usage on load
(println "
=== Session Persistence Examples Loaded ===

Quick start:
  ;; Initialize with sticky sessions
  (def cfg (config/parse-config session-persistence/example-config-sticky))
  (lb/init! cfg)

  ;; Test from different source IPs
  ;; (same IP should always hit same backend)

  (lb/shutdown!)

Demos:
  (session-persistence/-main)
  (explain-session-persistence)
  (demo-hash-selection)
  (demo-weight-impact)
  (show-use-cases)
  (show-best-practices)
")
