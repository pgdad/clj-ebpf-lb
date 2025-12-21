(ns lb.drain-test
  "Tests for connection draining functionality."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [lb.drain :as drain]
            [lb.config :as config]
            [lb.health.weights :as weights]
            [lb.util :as util]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn reset-drain-state-fixture
  "Reset drain state before and after each test."
  [f]
  (reset! drain/drain-state {:draining {}
                              :watcher nil
                              :callbacks {}
                              :conntrack-map nil
                              :update-weights-fn nil})
  (try
    (f)
    (finally
      (drain/shutdown!))))

(use-fixtures :each reset-drain-state-fixture)

;;; =============================================================================
;;; Unit Tests - Target ID Helpers
;;; =============================================================================

(deftest target-id-test
  (testing "target-id creates correct ID string"
    (is (= "10.0.0.1:8080" (drain/target-id "10.0.0.1" 8080)))
    (is (= "10.0.0.1:8080" (drain/target-id (util/ip-string->u32 "10.0.0.1") 8080)))))

(deftest parse-target-id-test
  (testing "parse-target-id parses ID string correctly"
    (let [parsed (drain/parse-target-id "10.0.0.1:8080")]
      (is (= (util/ip-string->u32 "10.0.0.1") (:ip parsed)))
      (is (= 8080 (:port parsed))))))

(deftest normalize-target-test
  (testing "normalize-target handles various formats"
    (is (= "10.0.0.1:8080" (drain/normalize-target "10.0.0.1:8080")))
    (is (= "10.0.0.1:8080" (drain/normalize-target {:ip "10.0.0.1" :port 8080})))
    (is (= "10.0.0.1:8080" (drain/normalize-target {:ip (util/ip-string->u32 "10.0.0.1") :port 8080})))))

;;; =============================================================================
;;; Unit Tests - Drain State Management
;;; =============================================================================

(deftest draining?-test
  (testing "draining? returns false when not draining"
    (is (false? (drain/draining? "10.0.0.1:8080"))))

  (testing "draining? returns true when draining"
    ;; Manually add a drain entry
    (swap! drain/drain-state assoc-in [:draining "10.0.0.1:8080"]
           (drain/->DrainState "10.0.0.1:8080" "test" (System/currentTimeMillis)
                               30000 50 5 :draining))
    (is (true? (drain/draining? "10.0.0.1:8080")))))

(deftest get-drain-status-test
  (testing "get-drain-status returns nil when not draining"
    (is (nil? (drain/get-drain-status "10.0.0.1:8080"))))

  (testing "get-drain-status returns status map when draining"
    (let [start-time (System/currentTimeMillis)]
      (swap! drain/drain-state assoc-in [:draining "10.0.0.1:8080"]
             (drain/->DrainState "10.0.0.1:8080" "test" start-time
                                 30000 50 5 :draining))
      (let [status (drain/get-drain-status "10.0.0.1:8080")]
        (is (some? status))
        (is (= "10.0.0.1:8080" (:target-id status)))
        (is (= "test" (:proxy-name status)))
        (is (= :draining (:status status)))
        (is (= 30000 (:timeout-ms status)))
        (is (= 50 (:original-weight status)))
        (is (= 5 (:initial-connections status)))
        (is (>= (:elapsed-ms status) 0))))))

(deftest get-all-draining-test
  (testing "get-all-draining returns empty seq when nothing draining"
    (is (empty? (drain/get-all-draining))))

  (testing "get-all-draining returns all draining backends"
    (swap! drain/drain-state assoc-in [:draining "10.0.0.1:8080"]
           (drain/->DrainState "10.0.0.1:8080" "test1" (System/currentTimeMillis)
                               30000 50 5 :draining))
    (swap! drain/drain-state assoc-in [:draining "10.0.0.2:8080"]
           (drain/->DrainState "10.0.0.2:8080" "test2" (System/currentTimeMillis)
                               60000 30 3 :draining))
    (let [draining (drain/get-all-draining)]
      (is (= 2 (count draining)))
      (is (some #(= "10.0.0.1:8080" (:target-id %)) draining))
      (is (some #(= "10.0.0.2:8080" (:target-id %)) draining)))))

;;; =============================================================================
;;; Unit Tests - Weight Computation
;;; =============================================================================

(deftest compute-drain-weights-test
  (testing "compute-drain-weights excludes draining targets"
    (let [original [50 30 20]
          health [true true true]
          drain [false true false]  ; middle target draining
          result (weights/compute-drain-weights original health drain)]
      ;; Middle target should be 0, others redistributed
      (is (= 0 (nth result 1)))
      ;; 50/(50+20) = 71.4%, 20/(50+20) = 28.6%
      (is (= 71 (nth result 0)))
      (is (= 29 (nth result 2)))
      (is (= 100 (reduce + result)))))

  (testing "compute-drain-weights handles healthy and draining"
    (let [original [50 30 20]
          health [true false true]   ; middle unhealthy
          drain [true false false]   ; first draining
          result (weights/compute-drain-weights original health drain)]
      ;; First is draining, middle is unhealthy, only third active
      (is (= 0 (nth result 0)))
      (is (= 0 (nth result 1)))
      (is (= 100 (nth result 2)))))

  (testing "compute-drain-weights all draining returns original (graceful degradation)"
    (let [original [50 30 20]
          health [true true true]
          drain [true true true]
          result (weights/compute-drain-weights original health drain)]
      ;; All draining - graceful degradation keeps original
      (is (= original result)))))

;;; =============================================================================
;;; Unit Tests - DrainState Record
;;; =============================================================================

(deftest drain-state-record-test
  (testing "DrainState record creation"
    (let [state (drain/->DrainState "10.0.0.1:8080" "web" 123456789
                                     30000 50 10 :draining)]
      (is (= "10.0.0.1:8080" (:target-id state)))
      (is (= "web" (:proxy-name state)))
      (is (= 123456789 (:started-at state)))
      (is (= 30000 (:timeout-ms state)))
      (is (= 50 (:original-weight state)))
      (is (= 10 (:initial-conn-count state)))
      (is (= :draining (:status state))))))

;;; =============================================================================
;;; Unit Tests - Format Functions
;;; =============================================================================

(deftest format-drain-status-test
  (testing "format-drain-status produces readable output"
    (let [status {:target-id "10.0.0.1:8080"
                  :status :draining
                  :current-connections 3
                  :initial-connections 10
                  :elapsed-ms 5000
                  :timeout-ms 30000}
          formatted (drain/format-drain-status status)]
      (is (string? formatted))
      (is (clojure.string/includes? formatted "10.0.0.1:8080"))
      (is (clojure.string/includes? formatted "draining"))
      (is (clojure.string/includes? formatted "3/10")))))

;;; =============================================================================
;;; Integration Tests - Drain with Mock Conntrack
;;; =============================================================================

;; Note: Full integration tests require root and real BPF maps
;; These tests use mocked conntrack for basic validation

(deftest drain-backend-validation-test
  (testing "drain-backend! throws when not initialized"
    (let [target-group (config/make-weighted-target-group
                         [{:ip "10.0.0.1" :port 8080 :weight 50}
                          {:ip "10.0.0.2" :port 8080 :weight 50}])]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Drain module not initialized"
                            (drain/drain-backend! "test" target-group "10.0.0.1:8080"))))))

(deftest drain-backend-already-draining-test
  (testing "drain-backend! throws when already draining"
    ;; Initialize with mock - set conntrack-map to non-nil to pass initialization check
    (swap! drain/drain-state assoc :conntrack-map :mock)
    (swap! drain/drain-state assoc :update-weights-fn (fn [_ _] nil))
    (swap! drain/drain-state assoc-in [:draining "10.0.0.1:8080"]
           (drain/->DrainState "10.0.0.1:8080" "test" (System/currentTimeMillis)
                               30000 50 5 :draining))

    (let [target-group (config/make-weighted-target-group
                         [{:ip "10.0.0.1" :port 8080 :weight 50}
                          {:ip "10.0.0.2" :port 8080 :weight 50}])]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Target is already draining"
                            (drain/drain-backend! "test" target-group "10.0.0.1:8080"))))))

(deftest drain-backend-target-not-found-test
  (testing "drain-backend! throws when target not in group"
    ;; Initialize with mock - set conntrack-map to non-nil
    (swap! drain/drain-state assoc :conntrack-map :mock)
    (swap! drain/drain-state assoc :update-weights-fn (fn [_ _] nil))
    (let [target-group (config/make-weighted-target-group
                         [{:ip "10.0.0.1" :port 8080 :weight 50}
                          {:ip "10.0.0.2" :port 8080 :weight 50}])]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Target not found"
                            (drain/drain-backend! "test" target-group "10.0.0.99:9999"))))))

(deftest undrain-backend-not-draining-test
  (testing "undrain-backend! returns false when not draining"
    (drain/init! nil (fn [_ _] nil))
    (let [target-group (config/make-weighted-target-group
                         [{:ip "10.0.0.1" :port 8080 :weight 50}
                          {:ip "10.0.0.2" :port 8080 :weight 50}])]
      (is (false? (drain/undrain-backend! "test" target-group "10.0.0.1:8080"))))))

;;; =============================================================================
;;; Config Spec Tests
;;; =============================================================================

(deftest drain-config-specs-test
  (testing "drain settings specs validate correctly"
    (let [valid-config {:proxies
                        [{:name "web"
                          :listen {:interfaces ["eth0"] :port 80}
                          :default-target {:ip "10.0.0.1" :port 8080}}]
                        :settings
                        {:default-drain-timeout-ms 30000
                         :drain-check-interval-ms 1000}}
          result (config/validate-config valid-config)]
      (is (:valid result))))

  (testing "drain settings with invalid timeout"
    (let [invalid-config {:proxies
                          [{:name "web"
                            :listen {:interfaces ["eth0"] :port 80}
                            :default-target {:ip "10.0.0.1" :port 8080}}]
                          :settings
                          {:default-drain-timeout-ms 500  ; Too low (< 1000)
                           :drain-check-interval-ms 1000}}
          result (config/validate-config invalid-config)]
      (is (not (:valid result)))))

  (testing "parse-settings includes drain defaults"
    (let [settings (config/parse-settings {})]
      (is (= 30000 (:default-drain-timeout-ms settings)))
      (is (= 1000 (:drain-check-interval-ms settings))))))
