(ns lb.session-persistence-integration-test
  "Integration tests for session persistence (sticky sessions).
   These tests require root privileges and BPF support."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [lb.core :as lb]
            [lb.config :as config]
            [lb.maps :as maps]
            [lb.util :as util]
            [lb.test-util :refer [when-root root?]]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn cleanup-fixture [f]
  (when (lb/running?)
    (lb/shutdown!))
  (f)
  (when (lb/running?)
    (lb/shutdown!)))

(use-fixtures :each cleanup-fixture)

;;; =============================================================================
;;; Configuration Tests
;;; =============================================================================

(deftest session-persistence-config-integration-test
  (when-root
    (testing "Configuration with session-persistence parses correctly"
      (let [cfg {:proxies
                 [{:name "sticky-api"
                   :listen {:interfaces ["lo"] :port 9090}
                   :session-persistence true
                   :default-target
                   [{:ip "127.0.0.1" :port 9001 :weight 50}
                    {:ip "127.0.0.1" :port 9002 :weight 50}]}]}
            parsed (config/parse-config cfg)]
        (is parsed)
        (is (true? (:session-persistence (first (:proxies parsed)))))))))

(deftest session-persistence-source-route-integration-test
  (when-root
    (testing "Source route with session-persistence parses correctly"
      (let [cfg {:proxies
                 [{:name "test"
                   :listen {:interfaces ["lo"] :port 9090}
                   :default-target {:ip "127.0.0.1" :port 9001}
                   :source-routes
                   [{:source "10.0.0.0/8"
                     :target {:ip "127.0.0.1" :port 9002}
                     :session-persistence true}]}]}
            parsed (config/parse-config cfg)
            source-route (first (:source-routes (first (:proxies parsed))))]
        (is parsed)
        (is (true? (:session-persistence source-route)))))))

;;; =============================================================================
;;; Map Flag Tests
;;; =============================================================================

(deftest session-persistence-flag-encoding-test
  (testing "Session persistence flag is set in encoded route value"
    (let [target-group (config/make-weighted-target-group
                         [{:ip "10.0.0.1" :port 8080 :weight 50}
                          {:ip "10.0.0.2" :port 8080 :weight 50}])
          ;; Encode without flag
          no-sp-bytes (util/encode-weighted-route-value target-group 0)
          no-sp-decoded (util/decode-weighted-route-value no-sp-bytes)
          ;; Encode with session-persistence flag
          sp-bytes (util/encode-weighted-route-value target-group util/FLAG-SESSION-PERSISTENCE)
          sp-decoded (util/decode-weighted-route-value sp-bytes)]
      ;; Verify flags are different
      (is (= 0 (:flags no-sp-decoded)))
      (is (= util/FLAG-SESSION-PERSISTENCE (:flags sp-decoded)))
      ;; Verify bit is set
      (is (pos? (bit-and (:flags sp-decoded) util/FLAG-SESSION-PERSISTENCE))))))

(deftest session-persistence-combined-flags-test
  (testing "Session persistence flag can be combined with other flags"
    (let [target-group (config/make-single-target-group "10.0.0.1" 8080)
          stats-flag 0x0002
          combined-flags (bit-or util/FLAG-SESSION-PERSISTENCE stats-flag)
          encoded (util/encode-weighted-route-value target-group combined-flags)
          decoded (util/decode-weighted-route-value encoded)]
      (is (= combined-flags (:flags decoded)))
      ;; Both flags should be set
      (is (pos? (bit-and (:flags decoded) util/FLAG-SESSION-PERSISTENCE)))
      (is (pos? (bit-and (:flags decoded) stats-flag))))))

;;; =============================================================================
;;; Load Balancer Init Tests (require root)
;;; =============================================================================

(deftest ^:integration session-persistence-lb-init-test
  (when-root
    (testing "Load balancer initializes with session-persistence enabled"
      (let [cfg (config/parse-config
                  {:proxies
                   [{:name "sticky-lb"
                     :listen {:interfaces ["lo"] :port 19090}
                     :session-persistence true
                     :default-target
                     [{:ip "127.0.0.1" :port 9001 :weight 50}
                      {:ip "127.0.0.1" :port 9002 :weight 50}]}]})]
        (try
          (lb/init! cfg)
          (is (lb/running?))
          ;; Verify the config is stored
          (let [stored-cfg (:config (lb/get-state))
                proxy-cfg (first (:proxies stored-cfg))]
            (is (true? (:session-persistence proxy-cfg))))
          (finally
            (lb/shutdown!)))))))
