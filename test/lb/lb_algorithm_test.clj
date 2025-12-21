(ns lb.lb-algorithm-test
  "Unit tests for lb-algorithm namespace.
   Tests weight computation for least-connections load balancing."
  (:require [clojure.test :refer [deftest testing is]]
            [lb.lb-algorithm :as algo]))

;;; =============================================================================
;;; Connection Counting Tests
;;; =============================================================================

(deftest count-connections-by-backend-test
  (testing "Counts connections from conntrack stats"
    (let [stats [{:target-ip "10.0.0.1" :connection-count 5}
                 {:target-ip "10.0.0.2" :connection-count 10}
                 {:target-ip "10.0.0.3" :connection-count 3}]
          result (algo/count-connections-by-backend stats)]
      (is (= {"10.0.0.1" 5 "10.0.0.2" 10 "10.0.0.3" 3} result))))

  (testing "Empty stats returns empty map"
    (is (= {} (algo/count-connections-by-backend []))))

  (testing "Single backend"
    (let [stats [{:target-ip "10.0.0.1" :connection-count 100}]
          result (algo/count-connections-by-backend stats)]
      (is (= {"10.0.0.1" 100} result)))))

(deftest get-backend-connections-test
  (testing "Returns connection count for known backend"
    (is (= 5 (algo/get-backend-connections {"10.0.0.1" 5} "10.0.0.1"))))

  (testing "Returns 0 for unknown backend"
    (is (= 0 (algo/get-backend-connections {"10.0.0.1" 5} "10.0.0.2")))))

;;; =============================================================================
;;; Least Connections Weight Computation Tests
;;; =============================================================================

(deftest compute-least-conn-weights-equal-connections-test
  (testing "Equal connections distributes weights equally"
    (let [original [50 50]
          conn-counts [10 10]
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= 100 (reduce + result)))
      (is (= [50 50] result))))

  (testing "Equal connections with unequal original weights (weighted mode)"
    (let [original [70 30]
          conn-counts [10 10]
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= 100 (reduce + result)))
      ;; Higher original weight should result in higher effective weight
      (is (> (first result) (second result)))))

  (testing "Equal connections ignores original weights (pure mode)"
    (let [original [70 30]
          conn-counts [10 10]
          result (algo/compute-least-conn-weights original conn-counts false)]
      (is (= 100 (reduce + result)))
      ;; In pure mode, equal connections = equal weights
      (is (= [50 50] result)))))

(deftest compute-least-conn-weights-unequal-connections-test
  (testing "Backend with fewer connections gets higher weight (weighted mode)"
    (let [original [50 50]
          conn-counts [5 20]  ; First backend has 5 conns, second has 20
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= 100 (reduce + result)))
      ;; Backend with 5 connections should have higher weight than backend with 20
      (is (> (first result) (second result)))))

  (testing "Backend with fewer connections gets higher weight (pure mode)"
    (let [original [50 50]
          conn-counts [5 20]
          result (algo/compute-least-conn-weights original conn-counts false)]
      (is (= 100 (reduce + result)))
      (is (> (first result) (second result)))))

  (testing "Backend with zero connections gets highest weight"
    (let [original [50 50]
          conn-counts [0 10]
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= 100 (reduce + result)))
      ;; Backend with 0 connections should dominate
      (is (> (first result) (second result))))))

(deftest compute-least-conn-weights-three-backends-test
  (testing "Three backends with varying connections"
    (let [original [33 33 34]
          conn-counts [5 10 20]
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= 100 (reduce + result)))
      ;; Weights should be in descending order (fewest connections = highest weight)
      (is (> (first result) (second result)))
      (is (> (second result) (nth result 2))))))

(deftest compute-least-conn-weights-zero-connections-test
  (testing "All backends have zero connections"
    (let [original [50 50]
          conn-counts [0 0]
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= 100 (reduce + result)))
      ;; With zero connections, should fall back to original weight ratio
      (is (= [50 50] result))))

  (testing "All backends have zero connections with unequal original (weighted mode)"
    (let [original [70 30]
          conn-counts [0 0]
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= 100 (reduce + result)))
      ;; Should maintain original weight ratio
      (is (= [70 30] result)))))

;;; =============================================================================
;;; Algorithm Selection Tests
;;; =============================================================================

(deftest compute-algorithm-weights-test
  (testing "weighted-random returns original weights"
    (let [original [50 50]
          conn-counts [5 20]
          result (algo/compute-algorithm-weights :weighted-random original conn-counts true)]
      (is (= original result))))

  (testing "least-connections computes based on connections"
    (let [original [50 50]
          conn-counts [5 20]
          result (algo/compute-algorithm-weights :least-connections original conn-counts true)]
      (is (not= original result))
      (is (> (first result) (second result)))))

  (testing "Unknown algorithm returns original weights"
    (let [original [50 50]
          conn-counts [5 20]
          result (algo/compute-algorithm-weights :unknown original conn-counts true)]
      (is (= original result)))))

;;; =============================================================================
;;; Full Weight Computation Pipeline Tests
;;; =============================================================================

(deftest compute-effective-weights-basic-test
  (testing "All healthy, no drain, all circuits closed"
    (let [original [50 50]
          conn-counts [5 20]
          health [true true]
          drain [false false]
          cb [:closed :closed]
          result (algo/compute-effective-weights
                   :least-connections original conn-counts health drain cb true)]
      (is (= 100 (reduce + result)))
      ;; Backend with fewer connections should have higher weight
      (is (> (first result) (second result)))))

  (testing "weighted-random ignores connection counts"
    (let [original [50 50]
          conn-counts [5 20]
          health [true true]
          drain [false false]
          cb [:closed :closed]
          result (algo/compute-effective-weights
                   :weighted-random original conn-counts health drain cb true)]
      (is (= 100 (reduce + result)))
      (is (= [50 50] result)))))

(deftest compute-effective-weights-with-health-test
  (testing "Unhealthy backend gets zero weight"
    (let [original [50 50]
          conn-counts [5 20]
          health [true false]  ; Second backend unhealthy
          drain [false false]
          cb [:closed :closed]
          result (algo/compute-effective-weights
                   :least-connections original conn-counts health drain cb true)]
      (is (= 100 (reduce + result)))
      ;; Unhealthy backend should have 0 weight
      (is (= 100 (first result)))
      (is (= 0 (second result))))))

(deftest compute-effective-weights-with-drain-test
  (testing "Draining backend gets zero weight"
    (let [original [50 50]
          conn-counts [5 20]
          health [true true]
          drain [false true]  ; Second backend draining
          cb [:closed :closed]
          result (algo/compute-effective-weights
                   :least-connections original conn-counts health drain cb true)]
      (is (= 100 (reduce + result)))
      ;; Draining backend should have 0 weight
      (is (= 100 (first result)))
      (is (= 0 (second result))))))

(deftest compute-effective-weights-with-circuit-breaker-test
  (testing "Open circuit gets zero weight"
    (let [original [50 50]
          conn-counts [5 20]
          health [true true]
          drain [false false]
          cb [:closed :open]  ; Second circuit open
          result (algo/compute-effective-weights
                   :least-connections original conn-counts health drain cb true)]
      (is (= 100 (reduce + result)))
      ;; Open circuit should redirect traffic to other backend
      (is (= 100 (first result)))
      (is (= 0 (second result)))))

  (testing "Half-open circuit gets reduced weight"
    (let [original [50 50]
          conn-counts [10 10]  ; Equal connections
          health [true true]
          drain [false false]
          cb [:closed :half-open]  ; Second circuit half-open
          result (algo/compute-effective-weights
                   :least-connections original conn-counts health drain cb true)]
      (is (= 100 (reduce + result)))
      ;; Half-open should get some traffic but less than closed
      (is (> (first result) (second result)))
      (is (> (second result) 0)))))

;;; =============================================================================
;;; Utility Function Tests
;;; =============================================================================

(deftest weights-differ-test
  (testing "Different weights returns true"
    (is (algo/weights-differ? [50 50] [60 40])))

  (testing "Same weights returns false"
    (is (not (algo/weights-differ? [50 50] [50 50]))))

  (testing "Empty vectors returns false"
    (is (not (algo/weights-differ? [] [])))))

(deftest format-weight-change-test
  (testing "Formats weight changes with arrows"
    (let [result (algo/format-weight-change
                   ["10.0.0.1" "10.0.0.2"]
                   [50 50]
                   [60 40])]
      (is (clojure.string/includes? result "10.0.0.1"))
      (is (clojure.string/includes? result "10.0.0.2"))
      (is (clojure.string/includes? result "->"))))

  (testing "Unchanged weights show only current value"
    (let [result (algo/format-weight-change
                   ["10.0.0.1"]
                   [50]
                   [50])]
      (is (clojure.string/includes? result "50%"))
      (is (not (clojure.string/includes? result "->"))))))

;;; =============================================================================
;;; Edge Cases
;;; =============================================================================

(deftest edge-cases-test
  (testing "Single backend"
    (let [original [100]
          conn-counts [50]
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= [100] result))))

  (testing "Very large connection counts"
    (let [original [50 50]
          conn-counts [1000000 1]
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= 100 (reduce + result)))
      ;; Backend with 1 connection should get almost all traffic
      (is (< (first result) 5))
      (is (> (second result) 95))))

  (testing "Eight backends (max supported)"
    (let [original (vec (repeat 8 12))  ; 12 * 8 = 96, need to adjust
          original (assoc original 0 16)  ; 16 + 7*12 = 100
          conn-counts [1 2 3 4 5 6 7 8]
          result (algo/compute-least-conn-weights original conn-counts true)]
      (is (= 100 (reduce + result)))
      ;; Weights should decrease as connections increase
      (is (apply >= result)))))
