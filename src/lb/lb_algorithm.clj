(ns lb.lb-algorithm
  "Load balancing algorithm implementations.
   Provides weight computation for different load balancing strategies:
   - weighted-random: Original configured weights (default)
   - least-connections: Route to backends with fewer active connections"
  (:require [clojure.tools.logging :as log]
            [lb.health.weights :as weights]))

;;; =============================================================================
;;; Connection Counting
;;; =============================================================================

(defn count-connections-by-backend
  "Count active connections per backend from conntrack stats.

   conntrack-stats: Result of (conntrack/stats-by-target conntrack-map)
                    A sequence of {:target-ip \"x.x.x.x\" :connection-count n}

   Returns map of ip-string -> connection-count."
  [conntrack-stats]
  (->> conntrack-stats
       (map (fn [{:keys [target-ip connection-count]}]
              [target-ip connection-count]))
       (into {})))

(defn get-backend-connections
  "Get connection count for a specific backend.
   Returns 0 if backend not found in connection map."
  [conn-counts-map ip-string]
  (get conn-counts-map ip-string 0))

;;; =============================================================================
;;; Least Connections Weight Computation
;;; =============================================================================

(defn compute-least-conn-weights
  "Compute weights for least-connections algorithm.
   Backends with fewer connections get higher weights.

   original-weights: Vector of configured weights [w1 w2 ...]
   conn-counts: Vector of connection counts [c1 c2 ...] (same order as weights)
   weighted?: If true, factor in original weights (capacity-aware)
              If false, pure least-connections (ignore original weights)

   Formula for weighted mode:
     capacity_i = original_weight_i / (1 + connections_i)
     effective_weight_i = capacity_i / sum(all_capacities) * 100

   Formula for pure mode:
     inverse_i = 1 / (1 + connections_i)
     effective_weight_i = inverse_i / sum(all_inverses) * 100

   Returns vector of effective weights summing to 100."
  [original-weights conn-counts weighted?]
  (let [;; Compute inverse scores (higher = more available capacity)
        inverse-scores (mapv (fn [w c]
                               (if weighted?
                                 ;; Capacity-aware: factor in configured weight
                                 (/ (double w) (inc c))
                                 ;; Pure least-connections: just inverse of connections
                                 (/ 1.0 (inc c))))
                             original-weights conn-counts)
        total (reduce + inverse-scores)]
    (if (zero? total)
      ;; Fallback to original weights if something went wrong
      original-weights
      ;; Normalize to 100 and ensure proper rounding
      (weights/fix-weight-rounding
        (mapv #(int (Math/round (* 100.0 (/ % total)))) inverse-scores)))))

;;; =============================================================================
;;; Algorithm Selection
;;; =============================================================================

(defn compute-algorithm-weights
  "Compute weights based on the selected algorithm.

   algorithm: :weighted-random or :least-connections
   original-weights: Vector of configured weights
   conn-counts: Vector of connection counts (ignored for weighted-random)
   weighted?: Factor in original weights for least-connections

   Returns vector of effective weights."
  [algorithm original-weights conn-counts weighted?]
  (case algorithm
    :weighted-random original-weights
    :least-connections (compute-least-conn-weights original-weights conn-counts weighted?)
    ;; Default to original weights for unknown algorithms
    original-weights))

;;; =============================================================================
;;; Full Weight Computation Pipeline
;;; =============================================================================

(defn compute-effective-weights
  "Compute final weights considering algorithm + health + drain + circuit-breaker.

   This is the main entry point for weight computation.

   algorithm: :weighted-random or :least-connections
   original-weights: Vector of configured weights
   conn-counts: Vector of connection counts per backend
   health-statuses: Vector of booleans (true = healthy)
   drain-statuses: Vector of booleans (true = draining)
   cb-states: Vector of circuit breaker states (:closed, :open, :half-open, nil)
   weighted?: Factor in original weights for least-connections

   Returns vector of final effective weights summing to 100."
  [algorithm original-weights conn-counts health-statuses drain-statuses cb-states weighted?]
  (let [;; Step 1: Apply algorithm-specific weight computation
        algo-weights (compute-algorithm-weights algorithm original-weights conn-counts weighted?)
        ;; Step 2: Apply health and drain status
        health-drain-weights (weights/compute-drain-weights algo-weights health-statuses drain-statuses)]
    ;; Step 3: Apply circuit breaker overlay
    (weights/compute-circuit-breaker-weights health-drain-weights cb-states original-weights)))

;;; =============================================================================
;;; Utility Functions
;;; =============================================================================

(defn weights-differ?
  "Check if two weight vectors are different.
   Used to determine if BPF map update is needed."
  [weights1 weights2]
  (not= weights1 weights2))

(defn format-weight-change
  "Format a weight change for logging."
  [target-ips old-weights new-weights]
  (clojure.string/join ", "
    (map (fn [ip old new]
           (if (= old new)
             (format "%s: %d%%" ip new)
             (format "%s: %d%% -> %d%%" ip old new)))
         target-ips old-weights new-weights)))
