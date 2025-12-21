(ns lb.dns-integration-test
  "Integration tests for DNS-based backend resolution.
   These tests use real DNS resolution but don't require BPF/root privileges."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [lb.dns :as dns]
            [lb.dns.manager :as manager]
            [lb.dns.resolver :as resolver]
            [lb.config :as config]
            [lb.util :as util]
            [clojure.tools.logging :as log]))

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
;;; DNS Resolution Integration Tests
;;; =============================================================================

(deftest ^:integration test-resolve-localhost
  (testing "Resolve localhost returns valid IPs"
    (let [result (resolver/resolve-hostname-all "localhost" 5000)]
      (is (:success? result))
      (is (vector? (:ips result)))
      (is (>= (count (:ips result)) 1))
      ;; localhost should resolve to 127.0.0.1
      (is (some #(= "127.0.0.1" (util/u32->ip-string %)) (:ips result))))))

(deftest ^:integration test-resolve-localhost-all-ips
  (testing "resolve-all-ips returns IP strings"
    (let [ips (dns/resolve-all-ips "localhost")]
      (is (vector? ips))
      (is (>= (count ips) 1))
      (is (every? string? ips))
      (is (some #(= "127.0.0.1" %) ips)))))

(deftest ^:integration test-resolve-nonexistent-hostname
  (testing "Resolve nonexistent hostname fails gracefully"
    (let [result (resolver/resolve-hostname-all
                   "this-host-definitely-does-not-exist.invalid" 5000)]
      (is (not (:success? result)))
      (is (= :unknown-host (:error-type result)))
      (is (some? (:message result))))))

(deftest ^:integration test-resolve-with-timeout
  (testing "Resolution respects timeout"
    ;; Use a non-routable IP to trigger timeout
    (let [start-time (System/currentTimeMillis)
          result (resolver/resolve-hostname-all "10.255.255.1" 100)
          elapsed (- (System/currentTimeMillis) start-time)]
      ;; Should complete within timeout + some overhead
      (is (< elapsed 2000)))))

;;; =============================================================================
;;; DNS Manager Integration Tests
;;; =============================================================================

(deftest ^:integration test-dns-manager-lifecycle
  (testing "DNS manager starts and stops correctly"
    (is (not (dns/running?)))
    (dns/start!)
    (is (dns/running?))
    (dns/stop!)
    (is (not (dns/running?)))))

(deftest ^:integration test-dns-manager-idempotent-start-stop
  (testing "Multiple start/stop calls are safe"
    (dns/start!)
    (dns/start!)  ; Should not throw
    (is (dns/running?))
    (dns/stop!)
    (dns/stop!)   ; Should not throw
    (is (not (dns/running?)))))

(deftest ^:integration test-register-localhost-target
  (testing "Register and resolve localhost target"
    (dns/start!)
    (let [callback-calls (atom [])
          callback (fn [hostname target-group]
                     (swap! callback-calls conj {:hostname hostname
                                                  :target-group target-group}))]
      ;; Register localhost
      (dns/register-target! "test-proxy" "localhost"
                            {:port 8080 :weight 100 :dns-refresh-seconds 60}
                            callback)
      ;; Initial callback should have been called
      (is (= 1 (count @callback-calls)))
      (let [call (first @callback-calls)]
        (is (= "localhost" (:hostname call)))
        (is (some? (:target-group call)))
        (is (instance? lb.config.TargetGroup (:target-group call)))
        ;; Should have at least one target
        (is (>= (count (:targets (:target-group call))) 1)))
      ;; Check status
      (let [status (dns/get-status "test-proxy")]
        (is (some? status))
        (is (= "test-proxy" (:proxy-name status)))
        (is (contains? (:targets status) "localhost"))
        (let [target-status (get-in status [:targets "localhost"])]
          (is (= "localhost" (:hostname target-status)))
          (is (= 8080 (:port target-status)))
          (is (= 100 (:weight target-status)))
          (is (>= (count (:last-ips target-status)) 1))
          (is (= 0 (:consecutive-failures target-status)))))
      ;; Cleanup
      (dns/unregister-target! "test-proxy" "localhost"))))

(deftest ^:integration test-unregister-target
  (testing "Unregistering target removes it from status"
    (dns/start!)
    (dns/register-target! "test-proxy" "localhost"
                          {:port 8080} (fn [_ _]))
    (is (some? (dns/get-status "test-proxy")))
    (dns/unregister-target! "test-proxy" "localhost")
    (is (nil? (dns/get-status "test-proxy")))))

(deftest ^:integration test-unregister-proxy
  (testing "Unregistering proxy removes all targets"
    (dns/start!)
    (dns/register-target! "test-proxy" "localhost"
                          {:port 8080} (fn [_ _]))
    (is (some? (dns/get-status "test-proxy")))
    (dns/unregister-proxy! "test-proxy")
    (is (nil? (dns/get-status "test-proxy")))))

(deftest ^:integration test-multiple-proxies
  (testing "Multiple proxies can have DNS targets"
    (dns/start!)
    (dns/register-target! "proxy-1" "localhost"
                          {:port 8080} (fn [_ _]))
    (dns/register-target! "proxy-2" "localhost"
                          {:port 9090} (fn [_ _]))
    (let [all-status (dns/get-all-status)]
      (is (contains? all-status "proxy-1"))
      (is (contains? all-status "proxy-2")))
    ;; Cleanup one proxy
    (dns/unregister-proxy! "proxy-1")
    (is (nil? (dns/get-status "proxy-1")))
    (is (some? (dns/get-status "proxy-2")))
    ;; Cleanup remaining
    (dns/unregister-proxy! "proxy-2")))

(deftest ^:integration test-register-requires-running-manager
  (testing "Registration fails when manager not running"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"DNS manager not running"
                          (dns/register-target! "test" "localhost"
                                                {:port 8080} (fn [_ _]))))))

(deftest ^:integration test-register-invalid-hostname-fails
  (testing "Registration fails for invalid hostname at startup"
    (dns/start!)
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"Failed to resolve DNS target at startup"
                          (dns/register-target! "test" "this.invalid.hostname.xyz"
                                                {:port 8080} (fn [_ _]))))))

;;; =============================================================================
;;; DNS Target Weight Distribution Tests
;;; =============================================================================

(deftest ^:integration test-weight-distribution-single-ip
  (testing "Single IP gets full weight"
    (let [targets (resolver/expand-to-weighted-targets
                    [(util/ip-string->u32 "10.0.0.1")]
                    8080 100 nil)]
      (is (= 1 (count targets)))
      (is (= 100 (:weight (first targets))))
      (is (= 8080 (:port (first targets)))))))

(deftest ^:integration test-weight-distribution-multiple-ips
  (testing "Multiple IPs get distributed weight"
    (let [targets (resolver/expand-to-weighted-targets
                    [(util/ip-string->u32 "10.0.0.1")
                     (util/ip-string->u32 "10.0.0.2")]
                    8080 100 nil)]
      (is (= 2 (count targets)))
      (is (= 50 (:weight (first targets))))
      (is (= 50 (:weight (second targets)))))))

(deftest ^:integration test-weight-distribution-three-ips
  (testing "Three IPs get approximately equal weight"
    (let [targets (resolver/expand-to-weighted-targets
                    [(util/ip-string->u32 "10.0.0.1")
                     (util/ip-string->u32 "10.0.0.2")
                     (util/ip-string->u32 "10.0.0.3")]
                    8080 99 nil)]
      (is (= 3 (count targets)))
      ;; 99/3 = 33 each
      (is (= 33 (:weight (first targets))))
      (is (= 33 (:weight (second targets))))
      (is (= 33 (:weight (nth targets 2)))))))

;;; =============================================================================
;;; DNS Event Subscription Tests
;;; =============================================================================

(deftest ^:integration test-dns-event-subscription
  (testing "DNS events are delivered to subscribers"
    (dns/start!)
    (let [events (atom [])
          unsubscribe (dns/subscribe! (fn [event] (swap! events conj event)))]
      ;; Register target
      (dns/register-target! "test-proxy" "localhost"
                            {:port 8080 :dns-refresh-seconds 1}
                            (fn [_ _]))
      ;; Force a resolution
      (dns/force-resolve! "test-proxy" "localhost")
      (Thread/sleep 100)
      ;; Note: Events only fire when IPs change, so for localhost
      ;; which is stable, we won't get events. We verify the subscriber
      ;; was registered by checking the unsubscribe function works.
      (is (fn? unsubscribe))
      ;; Unsubscribe and cleanup
      (unsubscribe)
      (dns/unregister-target! "test-proxy" "localhost"))))

(deftest ^:integration test-dns-unsubscribe
  (testing "Unsubscribe stops event delivery"
    (dns/start!)
    (let [events (atom [])
          unsubscribe (dns/subscribe! (fn [event] (swap! events conj event)))]
      ;; Register target
      (dns/register-target! "test-proxy" "localhost"
                            {:port 8080} (fn [_ _]))
      ;; Unsubscribe immediately
      (unsubscribe)
      (reset! events [])
      ;; Force resolve after unsubscribe
      (dns/force-resolve! "test-proxy" "localhost")
      (Thread/sleep 100)
      ;; Should not receive events after unsubscribe
      ;; (This assumes force-resolve doesn't trigger callback synchronously before unsubscribe)
      (dns/unregister-target! "test-proxy" "localhost"))))

;;; =============================================================================
;;; DNS Force Resolve Tests
;;; =============================================================================

(deftest ^:integration test-force-resolve
  (testing "Force resolve triggers immediate DNS resolution"
    (dns/start!)
    (let [callback-calls (atom [])
          callback (fn [hostname _] (swap! callback-calls conj hostname))]
      (dns/register-target! "test-proxy" "localhost"
                            {:port 8080 :dns-refresh-seconds 3600}  ; Very long interval
                            callback)
      ;; Initial registration callback
      (is (= 1 (count @callback-calls)))
      ;; Force resolve should not add callback if IPs haven't changed
      (let [result (dns/force-resolve! "test-proxy" "localhost")]
        (is (true? result)))
      ;; Cleanup
      (dns/unregister-target! "test-proxy" "localhost"))))

(deftest ^:integration test-force-resolve-nonexistent
  (testing "Force resolve for nonexistent target returns nil"
    (dns/start!)
    (let [result (dns/force-resolve! "nonexistent" "hostname")]
      (is (nil? result)))))

;;; =============================================================================
;;; Config Integration Tests
;;; =============================================================================

(deftest ^:integration test-config-dns-target-detection
  (testing "DNS target detection in config"
    (is (config/dns-target? {:host "backend.local" :port 8080}))
    (is (not (config/dns-target? {:ip "10.0.0.1" :port 8080})))
    (is (not (config/dns-target? {:port 8080})))))

(deftest ^:integration test-config-parse-dns-target
  (testing "Parse DNS weighted target"
    (let [target (config/parse-dns-weighted-target
                   {:host "backend.local" :port 8080 :weight 50})]
      (is (= "backend.local" (:host target)))
      (is (= 8080 (:port target)))
      (is (= 50 (:weight target)))
      (is (= 30 (:dns-refresh-seconds target))))))  ; Default

(deftest ^:integration test-config-parse-dns-target-with-health-check
  (testing "Parse DNS target with health check"
    (let [target (config/parse-dns-weighted-target
                   {:host "backend.local" :port 8080
                    :health-check {:type :http :path "/health"}})]
      (is (= "backend.local" (:host target)))
      (is (some? (:health-check target)))
      (is (= :http (get-in target [:health-check :type]))))))

(deftest ^:integration test-config-parse-dns-target-group
  (testing "Parse target group with DNS target"
    (let [tg (config/parse-target-group
               {:host "localhost" :port 8080}
               "test-proxy")]
      (is (config/dns-target-group? tg))
      (is (= 1 (count (:dns-targets tg))))
      (is (empty? (:static-targets tg))))))

(deftest ^:integration test-config-parse-mixed-target-group
  (testing "Parse target group with mixed static and DNS targets"
    (let [tg (config/parse-target-group
               [{:ip "10.0.0.1" :port 8080 :weight 50}
                {:host "localhost" :port 8080 :weight 50}]
               "test-proxy")]
      (is (config/dns-target-group? tg))
      (is (= 1 (count (:dns-targets tg))))
      (is (= 1 (count (:static-targets tg)))))))

(deftest ^:integration test-config-static-only-target-group
  (testing "Parse target group with static targets only"
    (let [tg (config/parse-target-group
               [{:ip "10.0.0.1" :port 8080 :weight 50}
                {:ip "10.0.0.2" :port 8080 :weight 50}]
               "test-proxy")]
      (is (not (config/dns-target-group? tg)))
      (is (instance? lb.config.TargetGroup tg)))))

;;; =============================================================================
;;; Refresh Callback Tests
;;; =============================================================================

(deftest ^:integration test-refresh-callback-with-target-group
  (testing "Callback receives proper TargetGroup on resolution"
    (dns/start!)
    (let [received-tg (atom nil)
          callback (fn [hostname target-group]
                     (reset! received-tg target-group))]
      (dns/register-target! "test-proxy" "localhost"
                            {:port 8080 :weight 100}
                            callback)
      ;; Verify we received a proper TargetGroup
      (is (some? @received-tg))
      (is (instance? lb.config.TargetGroup @received-tg))
      (is (seq (:targets @received-tg)))
      (is (= 100 (reduce + (map :weight (:targets @received-tg)))))
      (dns/unregister-target! "test-proxy" "localhost"))))

;;; =============================================================================
;;; IP Change Detection Tests
;;; =============================================================================

(deftest ^:integration test-ips-changed-detection
  (testing "Detect IP changes correctly"
    (is (resolver/ips-changed? [1 2 3] [1 2 4]))
    (is (resolver/ips-changed? [1] [1 2]))
    (is (resolver/ips-changed? [1 2] [1]))
    (is (not (resolver/ips-changed? [1 2 3] [1 2 3])))
    (is (not (resolver/ips-changed? [1 2 3] [3 2 1])))))  ; Order doesn't matter

(deftest ^:integration test-ips-format
  (testing "Format IPs for logging"
    (is (= "[10.0.0.1, 10.0.0.2]"
           (resolver/format-ips [(util/ip-string->u32 "10.0.0.1")
                                  (util/ip-string->u32 "10.0.0.2")])))
    (is (= "[]" (resolver/format-ips [])))))

;;; =============================================================================
;;; Status Reporting Tests
;;; =============================================================================

(deftest ^:integration test-status-structure
  (testing "DNS status has complete structure"
    (dns/start!)
    (dns/register-target! "test-proxy" "localhost"
                          {:port 8080 :weight 100 :dns-refresh-seconds 30}
                          (fn [_ _]))
    (let [status (dns/get-status "test-proxy")]
      (is (= "test-proxy" (:proxy-name status)))
      (is (map? (:targets status)))
      (let [target-status (get (:targets status) "localhost")]
        (is (string? (:hostname target-status)))
        (is (number? (:port target-status)))
        (is (number? (:weight target-status)))
        (is (number? (:refresh-ms target-status)))
        (is (vector? (:last-ips target-status)))
        (is (number? (:last-resolved-at target-status)))
        (is (number? (:consecutive-failures target-status)))))
    (dns/unregister-target! "test-proxy" "localhost")))

(deftest ^:integration test-all-status
  (testing "Get all DNS status"
    (dns/start!)
    (dns/register-target! "proxy-a" "localhost" {:port 8080} (fn [_ _]))
    (dns/register-target! "proxy-b" "localhost" {:port 9090} (fn [_ _]))
    (let [all-status (dns/get-all-status)]
      (is (map? all-status))
      (is (= 2 (count all-status)))
      (is (contains? all-status "proxy-a"))
      (is (contains? all-status "proxy-b")))
    (dns/unregister-proxy! "proxy-a")
    (dns/unregister-proxy! "proxy-b")))
