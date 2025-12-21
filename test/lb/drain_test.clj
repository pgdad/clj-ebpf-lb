(ns lb.drain-test
  "Tests for connection draining functionality."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [lb.drain :as drain]
            [lb.config :as config]
            [lb.health.weights :as weights]
            [lb.maps :as maps]
            [lb.conntrack :as conntrack]
            [lb.util :as util]
            [lb.test-util :refer [when-root]]
            [clj-ebpf.core :as bpf]))

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

;;; =============================================================================
;;; Integration Test Helpers - Mock Connection Tracking
;;; =============================================================================

;; We use a mock connection counter for integration tests because:
;; 1. Per-CPU BPF map updates from userspace have complex requirements
;; 2. The drain logic is what we're testing, not BPF map I/O
;; 3. BPF map reading is tested in other integration tests

;; Global atom for mock connections - accessible across threads
(def mock-connections
  "Mock connection counts by target IP. Map of ip-string -> count."
  (atom {}))

(defn mock-get-connections-for-target
  "Mock implementation of get-connections-for-target."
  [_conntrack-map target-id]
  (let [{:keys [ip]} (drain/parse-target-id target-id)
        ip-str (util/u32->ip-string ip)]
    (get @mock-connections ip-str 0)))

(defn set-mock-connections!
  "Set the mock connection count for a target IP."
  [ip-str count]
  (swap! mock-connections assoc ip-str count))

(defn clear-mock-connections!
  "Clear all mock connections."
  []
  (reset! mock-connections {}))

(defmacro with-mock-connections
  "Run body with mocked connection counting.
   Redefines drain/get-connections-for-target to use mock data."
  [& body]
  `(do
     (clear-mock-connections!)
     (with-redefs [drain/get-connections-for-target mock-get-connections-for-target]
       (try
         ~@body
         (finally
           (clear-mock-connections!))))))

;;; =============================================================================
;;; Integration Tests - Drain Lifecycle with Mock Connections
;;; =============================================================================

(deftest drain-lifecycle-completes-when-connections-close-test
  (testing "Drain completes when all connections close"
    (with-mock-connections
      (let [callback-results (atom [])
            target-group (config/make-weighted-target-group
                           [{:ip "10.1.1.1" :port 8080 :weight 50}
                            {:ip "10.1.1.2" :port 8080 :weight 50}])]

        ;; Set initial mock connections
        (set-mock-connections! "10.1.1.1" 2)

        ;; Initialize drain module with fast check interval
        (drain/init! :mock-conntrack-map
                     (fn [_ _] nil)
                     :check-interval-ms 50)

        ;; Start draining
        (drain/drain-backend! "test" target-group "10.1.1.1:8080"
                              :timeout-ms 5000
                              :on-complete #(swap! callback-results conj %))

        (is (drain/draining? "10.1.1.1:8080"))

        ;; Verify initial connection count
        (let [status (drain/get-drain-status "10.1.1.1:8080")]
          (is (= 2 (:initial-connections status))))

        ;; Remove connections (simulating connections closing)
        (set-mock-connections! "10.1.1.1" 0)

        ;; Wait for drain watcher to detect completion
        (Thread/sleep 200)

        ;; Verify drain completed
        (is (not (drain/draining? "10.1.1.1:8080")))
        (is (= [:completed] @callback-results))

        (drain/shutdown!)))))

(deftest drain-lifecycle-timeout-test
  (testing "Drain times out when connections remain"
    (with-mock-connections
      (let [callback-results (atom [])
            target-group (config/make-weighted-target-group
                           [{:ip "10.1.1.1" :port 8080 :weight 50}
                            {:ip "10.1.1.2" :port 8080 :weight 50}])]

        ;; Set mock connection that won't be removed
        (set-mock-connections! "10.1.1.1" 1)

        ;; Initialize with fast check interval
        (drain/init! :mock-conntrack-map
                     (fn [_ _] nil)
                     :check-interval-ms 50)

        ;; Start draining with very short timeout
        (drain/drain-backend! "test" target-group "10.1.1.1:8080"
                              :timeout-ms 200
                              :on-complete #(swap! callback-results conj %))

        ;; Wait for timeout
        (Thread/sleep 400)

        ;; Verify timeout occurred
        (is (not (drain/draining? "10.1.1.1:8080")))
        (is (= [:timeout] @callback-results))

        (drain/shutdown!)))))

(deftest drain-lifecycle-wait-for-drain-test
  (testing "wait-for-drain! blocks until completion"
    (with-mock-connections
      (let [target-group (config/make-weighted-target-group
                           [{:ip "10.1.1.1" :port 8080 :weight 100}])]

        ;; Set initial mock connection
        (set-mock-connections! "10.1.1.1" 1)

        ;; Initialize with fast check interval
        (drain/init! :mock-conntrack-map
                     (fn [_ _] nil)
                     :check-interval-ms 50)

        ;; Start draining
        (drain/drain-backend! "test" target-group "10.1.1.1:8080"
                              :timeout-ms 5000)

        ;; Remove connection in a separate thread after a delay
        (future
          (Thread/sleep 100)
          (set-mock-connections! "10.1.1.1" 0))

        ;; Wait synchronously
        (let [result (drain/wait-for-drain! "10.1.1.1:8080")]
          (is (= :completed result)))

        (drain/shutdown!)))))

(deftest drain-lifecycle-undrain-restores-traffic-test
  (testing "undrain-backend! restores traffic"
    (with-mock-connections
      (let [weight-updates (atom [])
            target-group (config/make-weighted-target-group
                           [{:ip "10.1.1.1" :port 8080 :weight 50}
                            {:ip "10.1.1.2" :port 8080 :weight 50}])]

        ;; Initialize
        (drain/init! :mock-conntrack-map
                     (fn [proxy-name new-tg]
                       (swap! weight-updates conj
                              {:proxy proxy-name
                               :weights (:effective-weights new-tg)}))
                     :check-interval-ms 100)

        ;; Start draining
        (drain/drain-backend! "test" target-group "10.1.1.1:8080"
                              :timeout-ms 30000)

        ;; Verify weight was set to 0
        (is (= 1 (count @weight-updates)))
        (let [first-update (first @weight-updates)]
          (is (= "test" (:proxy first-update)))
          ;; First target (draining) should have weight 0
          (is (= 0 (first (:weights first-update))))
          ;; Second target should have weight 100 (redistributed)
          (is (= 100 (second (:weights first-update)))))

        ;; Undrain
        (is (true? (drain/undrain-backend! "test" target-group "10.1.1.1:8080")))
        (is (not (drain/draining? "10.1.1.1:8080")))

        ;; Verify weights were restored
        (is (= 2 (count @weight-updates)))
        (let [second-update (second @weight-updates)]
          ;; Both should now have their original weights (50 each)
          (is (= [50 50] (:weights second-update))))

        (drain/shutdown!)))))

(deftest drain-lifecycle-cancelled-on-shutdown-test
  (testing "Active drains are cancelled on shutdown"
    (with-mock-connections
      (let [callback-results (atom [])
            target-group (config/make-weighted-target-group
                           [{:ip "10.1.1.1" :port 8080 :weight 50}
                            {:ip "10.1.1.2" :port 8080 :weight 50}])]

        ;; Set mock connection so drain won't complete naturally
        (set-mock-connections! "10.1.1.1" 1)

        ;; Initialize
        (drain/init! :mock-conntrack-map (fn [_ _] nil) :check-interval-ms 100)

        ;; Start draining
        (drain/drain-backend! "test" target-group "10.1.1.1:8080"
                              :timeout-ms 60000
                              :on-complete #(swap! callback-results conj %))

        (is (drain/draining? "10.1.1.1:8080"))

        ;; Shutdown
        (drain/shutdown!)

        ;; Verify drain was cancelled
        (is (not (drain/draining? "10.1.1.1:8080")))
        (is (= [:cancelled] @callback-results))))))

(deftest drain-lifecycle-multiple-backends-test
  (testing "Multiple backends can be drained simultaneously"
    (with-mock-connections
      (let [callback-results (atom {})
            target-group (config/make-weighted-target-group
                           [{:ip "10.1.1.1" :port 8080 :weight 34}
                            {:ip "10.1.1.2" :port 8080 :weight 33}
                            {:ip "10.1.1.3" :port 8080 :weight 33}])]

        ;; Set mock connections to first two backends
        (set-mock-connections! "10.1.1.1" 1)
        (set-mock-connections! "10.1.1.2" 1)

        ;; Initialize
        (drain/init! :mock-conntrack-map (fn [_ _] nil) :check-interval-ms 50)

        ;; Start draining both
        (drain/drain-backend! "test" target-group "10.1.1.1:8080"
                              :timeout-ms 5000
                              :on-complete #(swap! callback-results assoc "10.1.1.1:8080" %))
        (drain/drain-backend! "test" target-group "10.1.1.2:8080"
                              :timeout-ms 5000
                              :on-complete #(swap! callback-results assoc "10.1.1.2:8080" %))

        (is (drain/draining? "10.1.1.1:8080"))
        (is (drain/draining? "10.1.1.2:8080"))
        (is (= 2 (count (drain/get-all-draining))))

        ;; Remove all connections
        (set-mock-connections! "10.1.1.1" 0)
        (set-mock-connections! "10.1.1.2" 0)

        ;; Wait for completion
        (Thread/sleep 200)

        ;; Verify both completed
        (is (= :completed (get @callback-results "10.1.1.1:8080")))
        (is (= :completed (get @callback-results "10.1.1.2:8080")))
        (is (empty? (drain/get-all-draining)))

        (drain/shutdown!)))))

(deftest drain-lifecycle-status-tracking-test
  (testing "Drain status is tracked correctly throughout lifecycle"
    (with-mock-connections
      (let [target-group (config/make-weighted-target-group
                           [{:ip "10.1.1.1" :port 8080 :weight 100}])]

        ;; Set initial mock connections
        (set-mock-connections! "10.1.1.1" 3)

        ;; Initialize
        (drain/init! :mock-conntrack-map (fn [_ _] nil) :check-interval-ms 50)

        ;; Start draining
        (drain/drain-backend! "test" target-group "10.1.1.1:8080"
                              :timeout-ms 10000)

        ;; Check initial status
        (let [status (drain/get-drain-status "10.1.1.1:8080")]
          (is (= "10.1.1.1:8080" (:target-id status)))
          (is (= "test" (:proxy-name status)))
          (is (= :draining (:status status)))
          (is (= 3 (:initial-connections status)))
          (is (= 3 (:current-connections status)))
          (is (< (:elapsed-ms status) 1000)))

        ;; Reduce connections
        (set-mock-connections! "10.1.1.1" 2)
        (Thread/sleep 100)

        ;; Check updated status
        (let [status (drain/get-drain-status "10.1.1.1:8080")]
          (is (= 3 (:initial-connections status)))
          (is (= 2 (:current-connections status))))

        ;; Remove remaining connections
        (set-mock-connections! "10.1.1.1" 0)

        ;; Wait for completion
        (Thread/sleep 200)

        ;; Drain should be complete
        (is (nil? (drain/get-drain-status "10.1.1.1:8080")))

        (drain/shutdown!)))))

;;; =============================================================================
;;; Integration Tests - Real BPF Maps (requires root)
;;; =============================================================================

(deftest ^:integration drain-with-real-conntrack-map-test
  (when-root
    (testing "Drain module initialization with real conntrack map"
      (let [conntrack-map (maps/create-conntrack-map {:max-connections 1000})]
        (try
          (let [weight-updates (atom [])]
            (drain/init! conntrack-map
                         (fn [proxy-name tg]
                           (swap! weight-updates conj {:proxy proxy-name :tg tg}))
                         :check-interval-ms 100)

            ;; Verify initialization
            (is (some? (:conntrack-map @drain/drain-state)))
            (is (some? (:update-weights-fn @drain/drain-state)))

            (drain/shutdown!))
          (finally
            (bpf/close-map conntrack-map)))))))
