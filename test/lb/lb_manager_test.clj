(ns lb.lb-manager-test
  "Tests for lb-manager namespace.
   Tests the background daemon for least-connections load balancing."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [lb.lb-manager :as lb-manager]
            [lb.config :as config]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn cleanup-fixture [f]
  ;; Ensure manager is stopped before and after tests
  (when (lb-manager/running?)
    (lb-manager/stop!))
  (f)
  (when (lb-manager/running?)
    (lb-manager/stop!)))

(use-fixtures :each cleanup-fixture)

;;; =============================================================================
;;; Lifecycle Tests
;;; =============================================================================

(deftest lifecycle-test
  (testing "Manager starts with least-connections algorithm"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections
                       :weighted true
                       :update-interval-ms 1000})]
      ;; Start requires a mock conntrack map, use nil for basic test
      (is (lb-manager/start! nil lb-config))
      (is (lb-manager/running?))
      (lb-manager/stop!)
      (is (not (lb-manager/running?)))))

  (testing "Manager does not start with weighted-random algorithm"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :weighted-random})]
      (is (not (lb-manager/start! nil lb-config)))
      (is (not (lb-manager/running?))))))

(deftest get-algorithm-test
  (testing "Returns :weighted-random when not running"
    (is (= :weighted-random (lb-manager/get-algorithm))))

  (testing "Returns :least-connections when running with least-connections"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections})]
      (lb-manager/start! nil lb-config)
      (is (= :least-connections (lb-manager/get-algorithm)))
      (lb-manager/stop!))))

;;; =============================================================================
;;; Status Tests
;;; =============================================================================

(deftest get-status-test
  (testing "Status when not running"
    (let [status (lb-manager/get-status)]
      (is (false? (:running? status)))
      (is (= :weighted-random (:algorithm status)))
      (is (= 0 (:registered-proxies status)))))

  (testing "Status when running"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections
                       :weighted true
                       :update-interval-ms 500})]
      (lb-manager/start! nil lb-config)
      (let [status (lb-manager/get-status)]
        (is (true? (:running? status)))
        (is (= :least-connections (:algorithm status)))
        (is (true? (:weighted status)))
        (is (= 500 (:update-interval-ms status))))
      (lb-manager/stop!))))

;;; =============================================================================
;;; Proxy Registration Tests
;;; =============================================================================

(deftest proxy-registration-test
  (testing "Register and unregister proxy"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections})
          target-group (config/make-single-target-group "10.0.0.1" 8080)]
      (lb-manager/start! nil lb-config)

      ;; Register proxy
      (lb-manager/register-proxy! "test-proxy" target-group ["eth0"] 80 nil)
      (let [status (lb-manager/get-status)]
        (is (= 1 (:registered-proxies status)))
        (is (some #{"test-proxy"} (:proxy-names status))))

      ;; Unregister proxy
      (lb-manager/unregister-proxy! "test-proxy")
      (let [status (lb-manager/get-status)]
        (is (= 0 (:registered-proxies status))))

      (lb-manager/stop!)))

  (testing "Register multiple proxies"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections})
          tg1 (config/make-single-target-group "10.0.0.1" 8080)
          tg2 (config/make-single-target-group "10.0.0.2" 8080)]
      (lb-manager/start! nil lb-config)

      (lb-manager/register-proxy! "proxy1" tg1 ["eth0"] 80 nil)
      (lb-manager/register-proxy! "proxy2" tg2 ["eth0"] 81 nil)

      (let [status (lb-manager/get-status)]
        (is (= 2 (:registered-proxies status))))

      (lb-manager/stop!))))

;;; =============================================================================
;;; Proxy Info Tests
;;; =============================================================================

(deftest get-proxy-info-test
  (testing "Get info for registered proxy"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections})
          target-group (config/make-weighted-target-group
                         [{:ip "10.0.0.1" :port 8080 :weight 60}
                          {:ip "10.0.0.2" :port 8080 :weight 40}])]
      (lb-manager/start! nil lb-config)
      (lb-manager/register-proxy! "test-proxy" target-group ["eth0"] 80 nil)

      (let [info (lb-manager/get-proxy-info "test-proxy")]
        (is (= "test-proxy" (:proxy-name info)))
        (is (= 2 (count (:targets info))))
        (is (= "10.0.0.1" (:ip (first (:targets info)))))
        (is (= 8080 (:port (first (:targets info)))))
        (is (= 60 (:configured-weight (first (:targets info))))))

      (lb-manager/stop!)))

  (testing "Get info for unregistered proxy returns nil"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections})]
      (lb-manager/start! nil lb-config)
      (is (nil? (lb-manager/get-proxy-info "nonexistent")))
      (lb-manager/stop!))))

;;; =============================================================================
;;; Force Update Tests
;;; =============================================================================

(deftest force-update-test
  (testing "Force update when not running returns nil"
    (is (nil? (lb-manager/force-update!))))

  (testing "Force update when running returns true"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections})]
      (lb-manager/start! nil lb-config)
      (is (true? (lb-manager/force-update!)))
      (lb-manager/stop!))))

;;; =============================================================================
;;; Update Target Group Tests
;;; =============================================================================

(deftest update-proxy-target-group-test
  (testing "Update target group for registered proxy"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections})
          tg1 (config/make-single-target-group "10.0.0.1" 8080)
          tg2 (config/make-single-target-group "10.0.0.2" 9090)]
      (lb-manager/start! nil lb-config)
      (lb-manager/register-proxy! "test-proxy" tg1 ["eth0"] 80 nil)

      ;; Initial state
      (let [info (lb-manager/get-proxy-info "test-proxy")]
        (is (= "10.0.0.1" (:ip (first (:targets info))))))

      ;; Update target group
      (lb-manager/update-proxy-target-group! "test-proxy" tg2)

      ;; Updated state
      (let [info (lb-manager/get-proxy-info "test-proxy")]
        (is (= "10.0.0.2" (:ip (first (:targets info))))))

      (lb-manager/stop!)))

  (testing "Update target group for unregistered proxy does nothing"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections})
          tg (config/make-single-target-group "10.0.0.1" 8080)]
      (lb-manager/start! nil lb-config)
      ;; Should not throw
      (lb-manager/update-proxy-target-group! "nonexistent" tg)
      (lb-manager/stop!))))

;;; =============================================================================
;;; Connection Counts Tests
;;; =============================================================================

(deftest get-connection-counts-test
  (testing "Returns nil when no conntrack map"
    (let [lb-config (config/parse-load-balancing-config
                      {:algorithm :least-connections})]
      (lb-manager/start! nil lb-config)
      ;; With nil conntrack-map, should return nil
      (is (nil? (lb-manager/get-connection-counts)))
      (lb-manager/stop!))))
