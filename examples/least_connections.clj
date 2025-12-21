;; Least Connections Load Balancing Examples
;;
;; Demonstrates the least-connections algorithm which routes new connections
;; to the backend with the fewest active connections.
;;
;; Usage:
;;   sudo clojure -M:dev
;;   (load-file "examples/least_connections.clj")
;;
;; The algorithm dynamically adjusts backend weights based on current
;; connection counts, ensuring even load distribution.

(ns least-connections
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.lb-manager :as lb-manager]
            [lb.conntrack :as conntrack]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Example Configuration
;;; =============================================================================

(def example-config-least-connections
  "Configuration with least-connections load balancing enabled"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target
     [{:ip "127.0.0.1" :port 9001 :weight 50}
      {:ip "127.0.0.1" :port 9002 :weight 50}]
     :health-check
     {:type :tcp
      :interval-ms 5000
      :timeout-ms 2000}}]
   :settings
   {:stats-enabled true
    :health-check-enabled true
    :load-balancing
    {:algorithm :least-connections  ; Route to backend with fewest connections
     :weighted true                  ; Factor in configured weights
     :update-interval-ms 1000}}})   ; Update weights every second

(def example-config-weighted-random
  "Configuration with default weighted-random load balancing"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target
     [{:ip "127.0.0.1" :port 9001 :weight 50}
      {:ip "127.0.0.1" :port 9002 :weight 50}]}]
   :settings
   {:stats-enabled true
    :load-balancing
    {:algorithm :weighted-random}}})

;;; =============================================================================
;;; Algorithm Explanation
;;; =============================================================================

(defn explain-least-connections
  "Explain how least-connections load balancing works"
  []
  (println "
=== Least Connections Load Balancing ===

Algorithm:
  Routes new connections to the backend with the fewest active connections.
  This ensures even load distribution when requests have varying durations.

How it works:
  1. Background daemon scans connection tracking every update-interval-ms
  2. Counts active connections per backend
  3. Computes new weights: fewer connections = higher weight
  4. Pushes updated weights to BPF maps

Weight computation (weighted mode):
  capacity_i = original_weight_i / (1 + connections_i)
  effective_weight_i = capacity_i / sum(all_capacities) * 100

Example:
  Original weights: [50, 50]
  Connection counts: [10, 50]

  Backend A: 50 / (1 + 10) = 4.55
  Backend B: 50 / (1 + 50) = 0.98
  Total: 5.53

  Effective weights: [82, 18]
  (Backend A gets ~82% of new connections)

Configuration:
  {:settings
   {:load-balancing
    {:algorithm :least-connections
     :weighted true           ; Factor in original weights
     :update-interval-ms 1000 ; Update frequency
    }}}

Weighted vs Pure mode:
  :weighted true  - Higher capacity backends get more traffic
  :weighted false - Pure least-connections, ignores original weights
"))

;;; =============================================================================
;;; Status Checking
;;; =============================================================================

(defn show-lb-status
  "Show current load balancing status"
  []
  (println "\n=== Load Balancing Status ===")
  (let [status (lb/get-lb-status)]
    (println "  Running:" (:running? status))
    (println "  Algorithm:" (name (:algorithm status)))
    (println "  Weighted:" (:weighted status))
    (println "  Update interval:" (:update-interval-ms status) "ms")
    (println "  Registered proxies:" (:registered-proxies status))
    (when (:last-update status)
      (println "  Last update:" (java.util.Date. (:last-update status))))))

(defn show-connection-distribution
  "Show current connection counts per backend"
  []
  (println "\n=== Connection Distribution ===")
  (if (lb/running?)
    (lb.core/with-lb-state [state]
      (let [conntrack-map (get-in state [:maps :conntrack-map])
            stats (conntrack/stats-by-target conntrack-map)]
        (if (empty? stats)
          (println "  No active connections")
          (doseq [{:keys [target-ip connection-count]} stats]
            (println (format "  %s: %d connections" target-ip connection-count))))))
    (println "  Load balancer not running")))

(defn watch-connections
  "Continuously monitor connection distribution.
   Press Ctrl+C to stop."
  []
  (println "\n=== Monitoring Connection Distribution ===")
  (println "Press Ctrl+C to stop.\n")
  (loop []
    (when (lb/running?)
      (lb.core/with-lb-state [state]
        (let [conntrack-map (get-in state [:maps :conntrack-map])
              stats (conntrack/stats-by-target conntrack-map)
              lb-status (lb/get-lb-status)]
          (println (java.time.LocalTime/now) "-" (name (:algorithm lb-status)))
          (if (empty? stats)
            (println "  No connections")
            (doseq [{:keys [target-ip connection-count]} stats]
              (println (format "  %s: %d" target-ip connection-count))))
          (println "---")))
      (Thread/sleep 2000)
      (recur))))

;;; =============================================================================
;;; Weight Computation Demo
;;; =============================================================================

(defn demo-weight-computation
  "Demonstrate how weights are computed based on connection counts"
  []
  (require '[lb.lb-algorithm :as algo])
  (require '[lb.health.weights :as weights])
  (println "\n=== Weight Computation Demo ===")

  (println "\n1. Equal connections:")
  (let [original [50 50]
        conns [10 10]
        result ((resolve 'lb.lb-algorithm/compute-least-conn-weights)
                original conns true)]
    (println "   Original weights:" original)
    (println "   Connection counts:" conns)
    (println "   Effective weights:" (vec result)))

  (println "\n2. Unequal connections (fewest wins):")
  (let [original [50 50]
        conns [10 50]
        result ((resolve 'lb.lb-algorithm/compute-least-conn-weights)
                original conns true)]
    (println "   Original weights:" original)
    (println "   Connection counts:" conns)
    (println "   Effective weights:" (vec result)))

  (println "\n3. Zero connections (gets all traffic):")
  (let [original [50 50]
        conns [0 20]
        result ((resolve 'lb.lb-algorithm/compute-least-conn-weights)
                original conns true)]
    (println "   Original weights:" original)
    (println "   Connection counts:" conns)
    (println "   Effective weights:" (vec result)))

  (println "\n4. Weighted mode (respects capacity):")
  (let [original [70 30]
        conns [10 10]
        result ((resolve 'lb.lb-algorithm/compute-least-conn-weights)
                original conns true)]
    (println "   Original weights:" original "(70% capacity on first)")
    (println "   Connection counts:" conns)
    (println "   Effective weights:" (vec result)))

  (println "\n5. Pure mode (ignores original weights):")
  (let [original [70 30]
        conns [10 10]
        result ((resolve 'lb.lb-algorithm/compute-least-conn-weights)
                original conns false)]
    (println "   Original weights:" original)
    (println "   Connection counts:" conns)
    (println "   Effective weights:" (vec result) "(equal because same conns)")))

;;; =============================================================================
;;; API Reference
;;; =============================================================================

(defn show-lb-api
  "Print available load balancing API functions"
  []
  (println "
=== Load Balancing API ===

Query status:
  (lb/get-lb-algorithm)        ; Current algorithm (:weighted-random or :least-connections)
  (lb/get-lb-status)           ; Full status map
  (lb/lb-least-connections?)   ; Is least-connections enabled?

Force update:
  (lb/force-lb-update!)        ; Trigger immediate weight recalculation

Configuration (in settings map):
  :load-balancing
    {:algorithm :least-connections  ; or :weighted-random (default)
     :weighted true                  ; Factor in original weights
     :update-interval-ms 1000}       ; Update frequency (100-10000)

Prometheus metrics:
  lb_algorithm                  ; 0=weighted-random, 1=least-connections
  lb_backend_connections        ; Connection count per backend
"))

;;; =============================================================================
;;; Comparison Demo
;;; =============================================================================

(defn explain-algorithm-comparison
  "Explain the difference between weighted-random and least-connections"
  []
  (println "
=== Algorithm Comparison ===

Weighted Random (default):
  - Uses configured weights directly
  - Random selection based on weight percentages
  - Best for: Uniform request patterns, stateless backends
  - Pros: Zero overhead, predictable distribution
  - Cons: Doesn't adapt to request duration variance

Least Connections:
  - Dynamically adjusts weights based on connection counts
  - Routes to backend with most available capacity
  - Best for: Variable request durations, long-lived connections
  - Pros: Adapts to real load, prevents overload
  - Cons: Small overhead (1-10ms/cycle), requires connection tracking

When to use least-connections:
  - Database connection pools
  - WebSocket servers
  - Long-polling endpoints
  - Streaming media
  - Mixed workloads with varying request times

When to use weighted-random:
  - Simple HTTP APIs
  - Short-lived requests
  - Stateless microservices
  - When you need explicit traffic ratios
"))

;;; =============================================================================
;;; Main Demo
;;; =============================================================================

(defn -main
  "Run least-connections demos"
  []
  (if (lb/running?)
    (do
      (explain-least-connections)
      (show-lb-status)
      (show-connection-distribution)
      (println "\n\nTo run other demos:")
      (println "  (demo-weight-computation)")
      (println "  (watch-connections)")
      (println "  (show-lb-api)")
      (println "  (explain-algorithm-comparison)"))
    (println "
Load balancer not running. Initialize first:

  ;; For least-connections:
  (def cfg (lb.config/parse-config least-connections/example-config-least-connections))
  (lb/init! cfg)

  ;; For weighted-random:
  (def cfg (lb.config/parse-config least-connections/example-config-weighted-random))
  (lb/init! cfg)

Then run demos:
  (least-connections/-main)

When done:
  (lb/shutdown!)
")))

;;; =============================================================================
;;; Best Practices
;;; =============================================================================

(defn show-best-practices
  "Show production best practices for least-connections"
  []
  (println "
=== Least Connections Best Practices ===

1. Tune Update Interval
   Start with 1000ms (default). Decrease for faster adaptation,
   increase to reduce CPU overhead.

   High traffic: 500ms
   Moderate: 1000ms
   Low traffic: 2000-5000ms

2. Use Weighted Mode
   Keep :weighted true to respect backend capacity differences.
   A 2x weight means 2x capacity to handle connections.

3. Combine with Health Checks
   Least-connections integrates with health checking:
   - Unhealthy backends get 0 weight
   - Weights are recomputed after health changes

4. Monitor with Prometheus
   Track lb_backend_connections to see distribution.
   Alert if one backend has significantly more connections.

5. Consider Connection Draining
   When removing backends, drain connections gracefully.
   Least-connections will naturally shift traffic away.

6. Test Under Load
   Simulate realistic workloads to verify even distribution.
   Long-running requests should show the benefit most clearly.
"))

;; Show usage on load
(println "
=== Least Connections Examples Loaded ===

Quick start:
  ;; Initialize with least-connections
  (def cfg (lb.config/parse-config least-connections/example-config-least-connections))
  (lb/init! cfg)
  (least-connections/-main)

Individual demos:
  (explain-least-connections)
  (demo-weight-computation)
  (show-lb-status)
  (show-connection-distribution)
  (watch-connections)

References:
  (show-lb-api)
  (explain-algorithm-comparison)
  (show-best-practices)
")
