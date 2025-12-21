(ns lb.health.weights
  "Weight redistribution logic for health-aware load balancing.
   Computes effective weights based on target health status."
  (:require [clojure.tools.logging :as log]
            [lb.util :as util]
            [lb.config :as config]))

;;; =============================================================================
;;; Weight Calculation
;;; =============================================================================

(defn redistribute-weights
  "Redistribute weights among healthy targets proportionally.

   Original weights: [50, 30, 20] with targets A, B, C
   If B is unhealthy: A gets 50/(50+20)*100 = 71%, C gets 20/(50+20)*100 = 29%
   Effective weights: [71, 0, 29]

   Returns a vector of effective weights (same length as original).
   Unhealthy targets get weight 0."
  [original-weights health-statuses]
  (let [;; Build pairs of [weight, healthy?]
        weight-health (map vector original-weights health-statuses)
        ;; Sum of healthy weights
        healthy-sum (reduce + 0 (map first (filter second weight-health)))]
    (if (zero? healthy-sum)
      ;; All targets unhealthy - keep original weights (graceful degradation)
      (do
        (log/warn "All targets unhealthy, keeping original weights for graceful degradation")
        original-weights)
      ;; Redistribute proportionally
      (mapv (fn [[weight healthy?]]
              (if healthy?
                (int (Math/round (* 100.0 (/ weight healthy-sum))))
                0))
            weight-health))))

(defn fix-weight-rounding
  "Ensure weights sum to exactly 100 by adjusting the largest weight.
   This handles rounding errors from redistribute-weights."
  [weights]
  (let [total (reduce + weights)]
    (cond
      (= total 100) weights
      (empty? weights) weights
      :else
      (let [;; Find index of largest non-zero weight
            indexed (map-indexed vector weights)
            max-idx (first (reduce (fn [[max-i max-w :as best] [i w]]
                                     (if (> w max-w) [i w] best))
                                   (first indexed)
                                   (rest indexed)))
            diff (- 100 total)]
        (update weights max-idx + diff)))))

(defn compute-effective-weights
  "Compute effective weights based on health statuses.
   Returns vector of weights summing to 100, with unhealthy targets at 0."
  [original-weights health-statuses]
  (-> (redistribute-weights original-weights health-statuses)
      (fix-weight-rounding)))

;;; =============================================================================
;;; Cumulative Weights
;;; =============================================================================

(defn weights->cumulative
  "Convert individual weights to cumulative weights.
   Example: [50, 30, 20] -> [50, 80, 100]"
  [weights]
  (vec (reductions + weights)))

;;; =============================================================================
;;; Target Group Updates
;;; =============================================================================

(defn update-target-group-weights
  "Create a new TargetGroup with updated effective weights.
   Preserves original targets but updates cumulative weights for routing.

   target-group: Original TargetGroup record
   health-statuses: Vector of booleans (true = healthy)

   Returns a new TargetGroup with updated cumulative-weights."
  [target-group health-statuses]
  (let [targets (:targets target-group)
        original-weights (mapv :weight targets)
        effective-weights (compute-effective-weights original-weights health-statuses)
        cumulative (weights->cumulative effective-weights)
        ;; Create new targets with effective weights
        updated-targets (mapv (fn [target eff-weight]
                                (assoc target :effective-weight eff-weight))
                              targets effective-weights)]
    (-> target-group
        (assoc :targets updated-targets)
        (assoc :cumulative-weights cumulative)
        (assoc :effective-weights effective-weights))))

;;; =============================================================================
;;; Gradual Recovery
;;; =============================================================================

(def recovery-steps
  "Steps for gradual weight recovery: 25%, 50%, 75%, 100%"
  [0.25 0.50 0.75 1.0])

(defn compute-recovery-weight
  "Compute the recovery weight for a target based on recovery step.
   recovery-step: 0-3 indicating progress through recovery-steps"
  [original-weight recovery-step]
  (if (>= recovery-step (count recovery-steps))
    original-weight
    (int (Math/round (* original-weight (nth recovery-steps recovery-step))))))

(defn apply-recovery-weights
  "Apply gradual recovery weights for recently recovered targets.

   original-weights: Vector of configured weights
   health-statuses: Vector of booleans (true = healthy)
   recovery-steps: Vector of integers (nil for healthy targets, 0-3 for recovering)

   Returns vector of effective weights with recovery scaling applied."
  [original-weights health-statuses recovery-progress]
  (let [;; First compute base effective weights
        base-weights (compute-effective-weights original-weights health-statuses)
        ;; Apply recovery scaling to recovering targets
        scaled-weights (mapv (fn [base-weight recovery-step healthy?]
                               (cond
                                 (not healthy?) 0
                                 (nil? recovery-step) base-weight
                                 :else (compute-recovery-weight base-weight recovery-step)))
                             base-weights recovery-progress health-statuses)
        ;; Redistribute what's left from reduced recovery weights
        total (reduce + scaled-weights)
        scale-factor (if (zero? total) 0.0 (/ 100.0 total))]
    (fix-weight-rounding
      (mapv #(int (Math/round (double (* % scale-factor)))) scaled-weights))))

;;; =============================================================================
;;; Weight Comparison
;;; =============================================================================

(defn weights-changed?
  "Check if effective weights have changed from current cumulative weights.
   Returns true if an update is needed."
  [current-cumulative new-cumulative]
  (not= current-cumulative new-cumulative))

;;; =============================================================================
;;; Debug/Display
;;; =============================================================================

(defn format-weight-distribution
  "Format weight distribution for logging."
  [targets effective-weights]
  (clojure.string/join ", "
    (map (fn [t w]
           (str (util/u32->ip-string (:ip t)) ":" (:port t) " -> " w "%"))
         targets effective-weights)))

;;; =============================================================================
;;; Drain-Aware Weight Computation
;;; =============================================================================

(defn compute-drain-weights
  "Compute effective weights with draining targets excluded.

   original-weights: Vector of configured weights
   health-statuses: Vector of booleans (true = healthy)
   drain-statuses: Vector of booleans (true = draining)

   A target receives traffic only if healthy AND NOT draining.
   Returns vector of effective weights with draining targets at 0."
  [original-weights health-statuses drain-statuses]
  (let [;; Active = healthy AND NOT draining
        active-statuses (mapv (fn [healthy? draining?]
                                (and healthy? (not draining?)))
                              health-statuses drain-statuses)]
    (compute-effective-weights original-weights active-statuses)))

;;; =============================================================================
;;; Circuit Breaker Weight Computation
;;; =============================================================================

(def half-open-weight-fraction
  "Fraction of original weight to use when circuit is half-open."
  0.10)

(defn compute-circuit-breaker-weights
  "Apply circuit breaker state to weights.

   health-weights: Vector of health-adjusted weights (from health system)
   cb-states: Vector of circuit breaker states (:closed, :open, :half-open, or nil)
   original-weights: Vector of original configured weights

   Returns vector of final effective weights:
   - :open -> 0 (no traffic)
   - :half-open -> 10% of original weight (test traffic)
   - :closed or nil -> use health weight

   If all circuits are open, returns health weights for graceful degradation."
  [health-weights cb-states original-weights]
  (let [;; Apply circuit breaker state to each weight
        with-cb (mapv (fn [health-w cb-state orig-w]
                        (case cb-state
                          :open 0
                          :half-open (max 1 (int (Math/round (* orig-w half-open-weight-fraction))))
                          :closed health-w
                          nil health-w  ; No circuit breaker for this target
                          health-w))    ; Default fallback
                      health-weights cb-states original-weights)
        ;; Check if any circuits are not open
        has-active? (some pos? with-cb)]
    (if (not has-active?)
      ;; All circuits open - graceful degradation, use health weights
      (do
        (log/warn "All circuits open, keeping health weights for graceful degradation")
        health-weights)
      ;; Normalize to sum to 100
      (let [total (reduce + with-cb)]
        (if (zero? total)
          health-weights
          (fix-weight-rounding
            (mapv #(if (zero? %)
                     0
                     (int (Math/round (* 100.0 (/ % total)))))
                  with-cb)))))))

(defn compute-all-weights
  "Compute final weights considering health, drain, and circuit breaker states.

   original-weights: Vector of configured weights
   health-statuses: Vector of booleans (true = healthy)
   drain-statuses: Vector of booleans (true = draining)
   cb-states: Vector of circuit breaker states (:closed, :open, :half-open, or nil)

   Returns vector of final effective weights."
  [original-weights health-statuses drain-statuses cb-states]
  (let [;; First compute drain-aware health weights
        health-weights (compute-drain-weights original-weights health-statuses drain-statuses)]
    ;; Then apply circuit breaker overlay
    (compute-circuit-breaker-weights health-weights cb-states original-weights)))
