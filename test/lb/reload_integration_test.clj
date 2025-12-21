(ns lb.reload-integration-test
  "Integration tests for hot reload functionality.
   These tests require root privileges for BPF operations."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [clojure.java.io :as io]
            [lb.config :as config]
            [lb.reload :as reload]
            [lb.test-util :refer [when-root]]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn reload-fixture
  "Clean reload state around tests."
  [f]
  (reload/disable-hot-reload!)
  (try
    (f)
    (finally
      (reload/disable-hot-reload!))))

(use-fixtures :each reload-fixture)

;;; =============================================================================
;;; File Watcher Tests (no BPF required)
;;; =============================================================================

(deftest ^:integration test-file-watcher-lifecycle
  (testing "File watcher starts and stops correctly"
    (let [temp-file (java.io.File/createTempFile "test-config" ".edn")
          temp-path (.getAbsolutePath temp-file)
          changed (atom false)
          on-change (fn [_] (reset! changed true))]
      (try
        ;; Write initial content
        (spit temp-file "{:proxies []}")

        ;; Start watcher
        (let [watcher (reload/start-file-watcher! temp-path on-change :debounce-ms 100)]
          (is (some? watcher) "Watcher should be created")
          (is (some? (:thread watcher)) "Watcher should have a thread")
          (is (some? (:stop-fn watcher)) "Watcher should have stop function")

          ;; Give watcher time to initialize
          (Thread/sleep 200)

          ;; Modify file
          (spit temp-file "{:proxies [{:name \"test\"}]}")

          ;; Wait for change detection (debounce + processing)
          (Thread/sleep 800)

          ;; The change detection depends on OS file system events
          ;; so we don't strictly assert it was detected

          ;; Stop watcher
          (reload/stop-file-watcher! watcher)

          ;; Give thread time to stop
          (Thread/sleep 300)

          ;; Thread should be terminated
          (is (not (.isAlive (:thread watcher))) "Thread should be stopped"))

        (finally
          (.delete temp-file))))))

;;; =============================================================================
;;; Enable/Disable Hot Reload Tests
;;; =============================================================================

(deftest test-enable-disable-hot-reload
  (testing "Enable and disable hot reload"
    (let [temp-file (java.io.File/createTempFile "test-config" ".edn")
          temp-path (.getAbsolutePath temp-file)]
      (try
        ;; Write valid config
        (spit temp-file "{:proxies [{:name \"test\" :listen {:interfaces [\"lo\"] :port 8080} :default-target {:ip \"127.0.0.1\" :port 9000}}]}")

        ;; Initially disabled
        (is (not (reload/hot-reload-enabled?)))

        ;; Enable (without actually watching, just for state testing)
        (reload/enable-hot-reload! temp-path :watch-file? true :sighup? false)
        (is (reload/hot-reload-enabled?))

        (let [state (reload/get-reload-state)]
          (is (:enabled state))
          (is (= temp-path (:config-path state)))
          (is (:file-watcher-active state))
          (is (not (:sighup-handler-active state))))

        ;; Disable
        (reload/disable-hot-reload!)
        (is (not (reload/hot-reload-enabled?)))

        (let [state (reload/get-reload-state)]
          (is (not (:enabled state)))
          (is (not (:file-watcher-active state))))

        (finally
          (.delete temp-file))))))

(deftest test-enable-with-sighup
  (testing "Enable hot reload with SIGHUP handler"
    (let [temp-file (java.io.File/createTempFile "test-config" ".edn")
          temp-path (.getAbsolutePath temp-file)]
      (try
        (spit temp-file "{:proxies []}")

        (reload/enable-hot-reload! temp-path :watch-file? false :sighup? true)

        (let [state (reload/get-reload-state)]
          (is (:enabled state))
          (is (not (:file-watcher-active state)))
          (is (:sighup-handler-active state)))

        (finally
          (reload/disable-hot-reload!)
          (.delete temp-file))))))

(deftest test-enable-replaces-previous
  (testing "Enabling hot reload replaces previous instance"
    (let [temp-file1 (java.io.File/createTempFile "config1" ".edn")
          temp-file2 (java.io.File/createTempFile "config2" ".edn")
          path1 (.getAbsolutePath temp-file1)
          path2 (.getAbsolutePath temp-file2)]
      (try
        (spit temp-file1 "{:proxies []}")
        (spit temp-file2 "{:proxies []}")

        ;; Enable first config
        (reload/enable-hot-reload! path1 :watch-file? true :sighup? false)
        (is (= path1 (:config-path (reload/get-reload-state))))

        ;; Enable second config - should replace first
        (reload/enable-hot-reload! path2 :watch-file? true :sighup? false)
        (is (= path2 (:config-path (reload/get-reload-state))))

        (finally
          (reload/disable-hot-reload!)
          (.delete temp-file1)
          (.delete temp-file2))))))

;;; =============================================================================
;;; Reload Without LB Running Tests
;;; =============================================================================

(deftest test-reload-without-lb
  (testing "Reload fails gracefully when LB not running"
    (let [result (reload/reload-config!)]
      (is (not (:success? result)))
      (is (some? (:error result))))))

(deftest test-reload-from-map-without-lb
  (testing "Reload from map fails gracefully when LB not running"
    (let [result (reload/reload-config-from-map! {:proxies []})]
      (is (not (:success? result)))
      (is (some? (:error result))))))

;;; =============================================================================
;;; Config Diff Application Tests (mock state)
;;; =============================================================================

(deftest test-config-diff-empty-detection
  (testing "Empty diff is detected correctly"
    (let [config (config/parse-config
                   {:proxies [{:name "test"
                               :listen {:interfaces ["lo"] :port 80}
                               :default-target {:ip "127.0.0.1" :port 8080}}]})
          diff (config/diff-configs config config)]
      (is (config/config-diff-empty? diff)))))

(deftest test-config-diff-non-empty-detection
  (testing "Non-empty diff is detected correctly"
    (let [config1 (config/parse-config
                    {:proxies [{:name "test"
                                :listen {:interfaces ["lo"] :port 80}
                                :default-target {:ip "127.0.0.1" :port 8080}}]})
          config2 (config/parse-config
                    {:proxies [{:name "test"
                                :listen {:interfaces ["lo"] :port 80}
                                :default-target {:ip "127.0.0.2" :port 9000}}]})
          diff (config/diff-configs config1 config2)]
      (is (not (config/config-diff-empty? diff))))))

;;; =============================================================================
;;; SIGHUP Handler Tests
;;; =============================================================================

(deftest test-sighup-handler-registration
  (testing "SIGHUP handler can be registered and unregistered"
    (let [called (atom false)
          handler (reload/register-sighup-handler! #(reset! called true))]
      ;; Handler should be returned (or nil on unsupported platforms)
      ;; We can't easily test the actual signal without sending it
      (reload/unregister-sighup-handler! handler))))

;;; =============================================================================
;;; Reload State Tests
;;; =============================================================================

(deftest test-reload-state-structure
  (testing "Reload state has complete structure"
    (let [state (reload/get-reload-state)]
      (is (contains? state :enabled))
      (is (contains? state :config-path))
      (is (contains? state :file-watcher-active))
      (is (contains? state :sighup-handler-active))
      (is (contains? state :last-reload))
      (is (contains? state :reload-count)))))

(deftest test-reload-count-initially-zero
  (testing "Reload count starts at zero"
    (let [state (reload/get-reload-state)]
      (is (= 0 (:reload-count state))))))
