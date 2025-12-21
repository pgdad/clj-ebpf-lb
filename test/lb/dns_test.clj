(ns lb.dns-test
  "Unit tests for DNS resolution and target handling.
   These tests don't require BPF/root privileges."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [lb.config :as config]
            [lb.dns :as dns]
            [lb.dns.resolver :as resolver]
            [lb.dns.manager :as manager]
            [lb.util :as util]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn dns-manager-fixture
  "Ensure clean DNS manager state around tests."
  [f]
  (when (dns/running?)
    (dns/stop!))
  (try
    (f)
    (finally
      (when (dns/running?)
        (dns/stop!)))))

(use-fixtures :each dns-manager-fixture)

;;; =============================================================================
;;; Resolver Tests
;;; =============================================================================

(deftest resolve-hostname-all-test
  (testing "Resolve a well-known hostname"
    ;; Note: This test requires network access
    (let [result (resolver/resolve-hostname-all "localhost" 5000)]
      (is (:success? result))
      (is (vector? (:ips result)))
      (is (>= (count (:ips result)) 1)))))

(deftest resolve-hostname-failure-test
  (testing "Resolving invalid hostname fails gracefully"
    (let [result (resolver/resolve-hostname-all "this.hostname.does.not.exist.invalid" 5000)]
      (is (not (:success? result)))
      (is (= :unknown-host (:error-type result))))))

(deftest distribute-weight-test
  (testing "Distribute weight evenly among targets"
    (is (= [34 33 33] (resolver/distribute-weight 100 3)))
    (is (= [50 50] (resolver/distribute-weight 100 2)))
    (is (= [100] (resolver/distribute-weight 100 1)))
    (is (= [25 25 25 25] (resolver/distribute-weight 100 4))))

  (testing "Distribute non-100 weight"
    (is (= [30 30] (resolver/distribute-weight 60 2)))
    (is (= [17 17 16] (resolver/distribute-weight 50 3))))

  (testing "Edge cases"
    (is (= [] (resolver/distribute-weight 100 0)))
    (is (= [1 1 1] (resolver/distribute-weight 3 3)))))

(deftest expand-to-weighted-targets-test
  (testing "Expand IPs to weighted targets"
    (let [ips [167772161 167772162]  ; 10.0.0.1, 10.0.0.2
          targets (resolver/expand-to-weighted-targets ips 8080 100 nil)]
      (is (= 2 (count targets)))
      (is (= 8080 (:port (first targets))))
      (is (= 50 (:weight (first targets))))
      (is (= 50 (:weight (second targets))))))

  (testing "Single IP gets full weight"
    (let [ips [167772161]
          targets (resolver/expand-to-weighted-targets ips 8080 100 nil)]
      (is (= 1 (count targets)))
      (is (= 100 (:weight (first targets)))))))

(deftest ips-changed-test
  (testing "Detect IP changes"
    (is (resolver/ips-changed? [1 2 3] [1 2 4]))
    (is (resolver/ips-changed? [1 2] [1 2 3]))
    (is (resolver/ips-changed? [1 2 3] [1 2]))
    (is (resolver/ips-changed? [] [1])))

  (testing "Order doesn't matter"
    (is (not (resolver/ips-changed? [1 2 3] [3 2 1])))
    (is (not (resolver/ips-changed? [1 2] [2 1]))))

  (testing "No change"
    (is (not (resolver/ips-changed? [1 2 3] [1 2 3])))
    (is (not (resolver/ips-changed? [] [])))))

;;; =============================================================================
;;; Config DNS Target Tests
;;; =============================================================================

(deftest dns-target-detection-test
  (testing "Detect DNS target by :host key"
    (is (config/dns-target? {:host "backend.local" :port 8080}))
    (is (not (config/dns-target? {:ip "10.0.0.1" :port 8080})))
    (is (not (config/dns-target? nil)))
    (is (not (config/dns-target? "string")))))

(deftest parse-dns-weighted-target-test
  (testing "Parse DNS weighted target"
    (let [target (config/parse-dns-weighted-target
                   {:host "backend.local" :port 8080 :weight 50 :dns-refresh-seconds 60})]
      (is (= "backend.local" (:host target)))
      (is (= 8080 (:port target)))
      (is (= 50 (:weight target)))
      (is (= 60 (:dns-refresh-seconds target)))))

  (testing "Parse DNS target with defaults"
    (let [target (config/parse-dns-weighted-target
                   {:host "backend.local" :port 8080})]
      (is (= 100 (:weight target)))
      (is (= 30 (:dns-refresh-seconds target))))))

(deftest parse-target-group-with-dns-test
  (testing "Parse target group with DNS target returns DNSTargetGroup"
    (let [tg (config/parse-target-group
               {:host "backend.local" :port 8080}
               "test")]
      (is (config/dns-target-group? tg))
      (is (= 1 (count (:dns-targets tg))))
      (is (= "backend.local" (get-in tg [:dns-targets 0 :host])))))

  (testing "Parse mixed targets"
    (let [tg (config/parse-target-group
               [{:ip "10.0.0.1" :port 8080 :weight 50}
                {:host "backend.local" :port 8080 :weight 50}]
               "test")]
      (is (config/dns-target-group? tg))
      (is (= 1 (count (:dns-targets tg))))
      (is (= 1 (count (:static-targets tg))))))

  (testing "Parse static targets returns TargetGroup"
    (let [tg (config/parse-target-group
               {:ip "10.0.0.1" :port 8080}
               "test")]
      (is (not (config/dns-target-group? tg)))
      (is (instance? lb.config.TargetGroup tg)))))

;;; =============================================================================
;;; Manager Lifecycle Tests
;;; =============================================================================

(deftest manager-lifecycle-test
  (testing "Manager starts and stops"
    (is (not (dns/running?)))
    (dns/start!)
    (is (dns/running?))
    (dns/stop!)
    (is (not (dns/running?)))))

(deftest manager-double-start-test
  (testing "Double start is safe"
    (dns/start!)
    (dns/start!)  ; Should not throw
    (is (dns/running?))
    (dns/stop!)))

(deftest manager-double-stop-test
  (testing "Double stop is safe"
    (dns/start!)
    (dns/stop!)
    (dns/stop!)  ; Should not throw
    (is (not (dns/running?)))))

;;; =============================================================================
;;; Manager Registration Tests (with mocked resolution)
;;; =============================================================================

(deftest manager-register-requires-running-test
  (testing "Registration requires manager to be running"
    (is (thrown? clojure.lang.ExceptionInfo
                 (dns/register-target! "test-proxy" "backend.local"
                                       {:port 8080} (fn [_ _]))))))

(deftest manager-register-with-localhost-test
  (testing "Register localhost target"
    (dns/start!)
    (let [callback-called (atom false)
          callback (fn [hostname tg]
                     (reset! callback-called true))]
      (dns/register-target! "test-proxy" "localhost"
                            {:port 8080 :weight 100 :dns-refresh-seconds 60}
                            callback)
      ;; Initial callback should have been called
      (is @callback-called)
      ;; Check status
      (let [status (dns/get-status "test-proxy")]
        (is (some? status))
        (is (= "test-proxy" (:proxy-name status)))
        (is (contains? (:targets status) "localhost")))
      ;; Cleanup
      (dns/unregister-target! "test-proxy" "localhost"))))

(deftest manager-unregister-test
  (testing "Unregister removes target"
    (dns/start!)
    (dns/register-target! "test-proxy" "localhost"
                          {:port 8080} (fn [_ _]))
    (dns/unregister-target! "test-proxy" "localhost")
    (is (nil? (dns/get-status "test-proxy")))))

(deftest manager-unregister-proxy-test
  (testing "Unregister proxy removes all targets"
    (dns/start!)
    (dns/register-target! "test-proxy" "localhost"
                          {:port 8080} (fn [_ _]))
    (dns/unregister-proxy! "test-proxy")
    (is (nil? (dns/get-status "test-proxy")))))

;;; =============================================================================
;;; Utility Tests
;;; =============================================================================

(deftest util-resolve-hostname-all-test
  (testing "resolve-hostname-all returns vector"
    (let [ips (util/resolve-hostname-all "localhost")]
      (is (vector? ips))
      (is (>= (count ips) 1))
      (is (every? integer? ips)))))

(deftest util-is-ip-string-test
  (testing "Detect IP strings"
    (is (util/is-ip-string? "10.0.0.1"))
    (is (util/is-ip-string? "192.168.1.1"))
    (is (util/is-ip-string? "0.0.0.0"))
    (is (util/is-ip-string? "255.255.255.255")))

  (testing "Reject non-IP strings"
    (is (not (util/is-ip-string? "backend.local")))
    (is (not (util/is-ip-string? "10.0.0")))
    (is (not (util/is-ip-string? "10.0.0.1.2")))
    (is (not (util/is-ip-string? nil)))
    (is (not (util/is-ip-string? 123)))))

;;; =============================================================================
;;; Direct Resolution Tests
;;; =============================================================================

(deftest direct-resolve-test
  (testing "Direct resolve function"
    (let [result (dns/resolve-hostname "localhost")]
      (is (:success? result))
      (is (vector? (:ips result))))))

(deftest resolve-all-ips-test
  (testing "resolve-all-ips returns IP strings"
    (let [ips (dns/resolve-all-ips "localhost")]
      (is (vector? ips))
      (is (every? string? ips))
      (is (every? #(re-matches #"\d+\.\d+\.\d+\.\d+" %) ips)))))
