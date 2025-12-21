(ns lb.metrics.histograms
  "Histogram implementation for Prometheus metrics.

   Provides cumulative bucket histograms compatible with Prometheus format."
  (:require [clojure.string :as str]))

;;; =============================================================================
;;; Default Buckets
;;; =============================================================================

(def default-latency-buckets
  "Default bucket boundaries for latency measurements (in seconds).
   Covers 1ms to 10s range with fine granularity for sub-100ms."
  [0.001 0.005 0.01 0.025 0.05 0.1 0.25 0.5 1.0 2.5 5.0 10.0])

;;; =============================================================================
;;; Histogram Data Structure
;;; =============================================================================

(defn new-histogram
  "Create a new histogram with the given bucket boundaries.

   Returns a map with:
     :buckets - vector of bucket upper bounds
     :counts  - vector of cumulative counts per bucket
     :sum     - running sum of all observations
     :count   - total number of observations"
  ([] (new-histogram default-latency-buckets))
  ([buckets]
   {:buckets (vec buckets)
    :counts (vec (repeat (count buckets) 0))
    :sum 0.0
    :count 0}))

(defn observe
  "Record an observation in the histogram.

   Updates all buckets where the observation is <= the bucket boundary
   (cumulative histogram as required by Prometheus)."
  [histogram value]
  (let [buckets (:buckets histogram)
        ;; Find which buckets this value falls into (cumulative)
        bucket-updates (mapv #(if (<= value %) 1 0) buckets)]
    (-> histogram
        (update :sum + value)
        (update :count inc)
        (update :counts #(mapv + % bucket-updates)))))

(defn merge-histograms
  "Merge two histograms with the same bucket boundaries."
  [h1 h2]
  (when (= (:buckets h1) (:buckets h2))
    {:buckets (:buckets h1)
     :counts (mapv + (:counts h1) (:counts h2))
     :sum (+ (:sum h1) (:sum h2))
     :count (+ (:count h1) (:count h2))}))

;;; =============================================================================
;;; Prometheus Format
;;; =============================================================================

(defn- format-labels
  "Format a map of labels as Prometheus label string."
  [labels]
  (if (empty? labels)
    ""
    (str "{"
         (->> labels
              (map (fn [[k v]] (str (name k) "=\"" v "\"")))
              (str/join ","))
         "}")))

(defn- format-labels-with-le
  "Format labels including the 'le' (less than or equal) bucket label."
  [labels le-value]
  (let [le-str (if (= le-value "+Inf") "+Inf" (str (double le-value)))
        all-labels (assoc labels :le le-str)]
    (str "{"
         (->> all-labels
              (map (fn [[k v]] (str (name k) "=\"" v "\"")))
              (str/join ","))
         "}")))

(defn format-histogram
  "Format a histogram as Prometheus exposition format.

   Returns a string with _bucket, _sum, and _count lines."
  [histogram metric-name labels]
  (let [{:keys [buckets counts sum count]} histogram
        base-labels labels
        ;; Bucket lines
        bucket-lines (map-indexed
                       (fn [idx bucket]
                         (str metric-name "_bucket"
                              (format-labels-with-le base-labels bucket)
                              " " (nth counts idx)))
                       buckets)
        ;; +Inf bucket (equals total count)
        inf-line (str metric-name "_bucket"
                      (format-labels-with-le base-labels "+Inf")
                      " " count)
        ;; Sum line
        sum-line (str metric-name "_sum"
                      (format-labels base-labels)
                      " " (format "%.6f" (double sum)))
        ;; Count line
        count-line (str metric-name "_count"
                        (format-labels base-labels)
                        " " count)]
    (str/join "\n" (concat bucket-lines [inf-line sum-line count-line]))))

(defn format-histogram-family
  "Format a family of histograms (same metric, different label combinations).

   histogram-map: map of label-values -> histogram
   metric-name: the base metric name
   help-text: description for HELP line
   label-keys: ordered vector of label keys (e.g., [:proxy_name :target_id])"
  [histogram-map metric-name help-text label-keys]
  (when (seq histogram-map)
    (let [lines (for [[label-values histogram] histogram-map
                      :let [labels (if (sequential? label-values)
                                     (zipmap label-keys label-values)
                                     {(first label-keys) label-values})]]
                  (format-histogram histogram metric-name labels))]
      (str "# HELP " metric-name " " help-text "\n"
           "# TYPE " metric-name " histogram\n"
           (str/join "\n" lines)))))

;;; =============================================================================
;;; Utility Functions
;;; =============================================================================

(defn get-percentile
  "Estimate a percentile from histogram data.
   Note: This is an approximation based on bucket boundaries."
  [histogram percentile]
  (let [{:keys [buckets counts count]} histogram
        target-count (* (/ percentile 100.0) count)]
    (loop [idx 0]
      (if (>= idx (clojure.core/count buckets))
        (last buckets)
        (if (>= (nth counts idx) target-count)
          (nth buckets idx)
          (recur (inc idx)))))))

(defn histogram-stats
  "Get basic statistics from a histogram."
  [histogram]
  {:count (:count histogram)
   :sum (:sum histogram)
   :mean (if (zero? (:count histogram))
           0.0
           (/ (:sum histogram) (:count histogram)))
   :p50 (get-percentile histogram 50)
   :p95 (get-percentile histogram 95)
   :p99 (get-percentile histogram 99)})
