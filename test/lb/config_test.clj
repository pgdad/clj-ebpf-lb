(ns lb.config-test
  "Tests for configuration management."
  (:require [clojure.test :refer [deftest testing is are]]
            [lb.config :as config]
            [lb.util :as util]))

;;; =============================================================================
;;; Configuration Parsing Tests
;;; =============================================================================

(deftest parse-target-test
  (testing "Parse target specification"
    (let [target (config/parse-target {:ip "10.0.0.1" :port 8080})]
      (is (= 0x0A000001 (:ip target)))
      (is (= 8080 (:port target))))))

(deftest parse-listen-test
  (testing "Parse listen specification"
    (let [listen (config/parse-listen {:interfaces ["eth0" "eth1"] :port 80})]
      (is (= ["eth0" "eth1"] (:interfaces listen)))
      (is (= 80 (:port listen))))))

(deftest parse-source-route-test
  (testing "Parse source route with CIDR"
    (let [route (config/parse-source-route
                  {:source "192.168.1.0/24"
                   :target {:ip "10.0.0.1" :port 8080}}
                  "test-proxy")]
      (is (= 0xC0A80100 (:source route)))
      (is (= 24 (:prefix-len route)))
      ;; target is now a TargetGroup
      (is (= 0x0A000001 (get-in route [:target-group :targets 0 :ip])))))

  (testing "Parse source route with single IP"
    (let [route (config/parse-source-route
                  {:source "192.168.1.100"
                   :target {:ip "10.0.0.2" :port 9000}}
                  "test-proxy")]
      (is (= 32 (:prefix-len route))))))

(deftest parse-proxy-config-test
  (testing "Parse complete proxy configuration"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "test-proxy"
                       :listen {:interfaces ["eth0"] :port 80}
                       :default-target {:ip "10.0.0.1" :port 8080}
                       :source-routes
                       [{:source "192.168.1.0/24"
                         :target {:ip "10.0.0.2" :port 8080}}]})]
      (is (= "test-proxy" (:name proxy-cfg)))
      (is (= 80 (get-in proxy-cfg [:listen :port])))
      (is (= 1 (count (:source-routes proxy-cfg)))))))

(deftest parse-settings-test
  (testing "Parse settings with defaults"
    (let [settings (config/parse-settings {})]
      (is (= false (:stats-enabled settings)))
      (is (= 300 (:connection-timeout-sec settings)))
      (is (= 100000 (:max-connections settings)))))

  (testing "Parse settings with custom values"
    (let [settings (config/parse-settings
                     {:stats-enabled true
                      :connection-timeout-sec 600
                      :max-connections 50000})]
      (is (= true (:stats-enabled settings)))
      (is (= 600 (:connection-timeout-sec settings)))
      (is (= 50000 (:max-connections settings))))))

;;; =============================================================================
;;; Configuration Validation Tests
;;; =============================================================================

(deftest validate-config-valid-test
  (testing "Valid configuration passes validation"
    (let [config-map {:proxies
                      [{:name "test"
                        :listen {:interfaces ["eth0"] :port 80}
                        :default-target {:ip "10.0.0.1" :port 8080}}]
                      :settings {:stats-enabled false}}
          result (config/validate-config config-map)]
      (is (:valid result))
      (is (some? (:config result))))))

(deftest validate-config-invalid-test
  (testing "Missing required fields fails validation"
    (let [result (config/validate-config {:proxies []})]
      (is (not (:valid result)))))

  (testing "Invalid port fails validation"
    (let [config-map {:proxies
                      [{:name "test"
                        :listen {:interfaces ["eth0"] :port 70000}  ; invalid
                        :default-target {:ip "10.0.0.1" :port 8080}}]}
          result (config/validate-config config-map)]
      (is (not (:valid result))))))

;;; =============================================================================
;;; Configuration Modification Tests
;;; =============================================================================

(deftest add-proxy-test
  (testing "Add proxy to configuration"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "existing"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}}]})
          new-proxy {:name "new-proxy"
                     :listen {:interfaces ["eth1"] :port 443}
                     :default-target {:ip "10.0.0.2" :port 8443}}
          updated (config/add-proxy config new-proxy)]
      (is (= 2 (count (:proxies updated))))
      (is (some #(= "new-proxy" (:name %)) (:proxies updated))))))

(deftest add-proxy-duplicate-test
  (testing "Adding duplicate proxy name throws"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "existing"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}}]})
          duplicate {:name "existing"
                     :listen {:interfaces ["eth1"] :port 443}
                     :default-target {:ip "10.0.0.2" :port 8443}}]
      (is (thrown? Exception (config/add-proxy config duplicate))))))

(deftest remove-proxy-test
  (testing "Remove proxy from configuration"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "keep"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}}
                     {:name "remove"
                      :listen {:interfaces ["eth1"] :port 443}
                      :default-target {:ip "10.0.0.2" :port 8443}}]})
          updated (config/remove-proxy config "remove")]
      (is (= 1 (count (:proxies updated))))
      (is (= "keep" (get-in updated [:proxies 0 :name]))))))

(deftest get-proxy-test
  (testing "Get proxy by name"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "first"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}}
                     {:name "second"
                      :listen {:interfaces ["eth1"] :port 443}
                      :default-target {:ip "10.0.0.2" :port 8443}}]})]
      (is (= "first" (:name (config/get-proxy config "first"))))
      (is (= "second" (:name (config/get-proxy config "second"))))
      (is (nil? (config/get-proxy config "nonexistent"))))))

(deftest add-source-route-to-proxy-test
  (testing "Add source route to proxy"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}
                      :source-routes []}]})
          route {:source "192.168.1.0/24"
                 :target {:ip "10.0.0.2" :port 8080}}
          updated (config/add-source-route-to-proxy config "test" route)
          proxy (config/get-proxy updated "test")]
      (is (= 1 (count (:source-routes proxy)))))))

(deftest remove-source-route-from-proxy-test
  (testing "Remove source route from proxy"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}
                      :source-routes
                      [{:source "192.168.1.0/24"
                        :target {:ip "10.0.0.2" :port 8080}}
                       {:source "192.168.2.0/24"
                        :target {:ip "10.0.0.3" :port 8080}}]}]})
          src-ip (util/ip-string->u32 "192.168.1.0")
          updated (config/remove-source-route-from-proxy config "test" src-ip 24)
          proxy (config/get-proxy updated "test")]
      (is (= 1 (count (:source-routes proxy)))))))

;;; =============================================================================
;;; Configuration Conversion Tests
;;; =============================================================================

(deftest config->map-roundtrip-test
  (testing "Config to map roundtrip"
    (let [original {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}
                      :source-routes
                      [{:source "192.168.1.0/24"
                        :target {:ip "10.0.0.2" :port 8080}}]}]
                    :settings
                    {:stats-enabled true
                     :connection-timeout-sec 300
                     :max-connections 100000}}
          parsed (config/parse-config original)
          converted (config/config->map parsed)]
      (is (= "test" (get-in converted [:proxies 0 :name])))
      (is (= 80 (get-in converted [:proxies 0 :listen :port])))
      (is (= true (get-in converted [:settings :stats-enabled]))))))

;;; =============================================================================
;;; Simple Config Creation Tests
;;; =============================================================================

(deftest make-simple-config-test
  (testing "Create simple configuration"
    (let [config (config/make-simple-config
                   {:name "simple"
                    :interface "eth0"
                    :port 80
                    :target-ip "10.0.0.1"
                    :target-port 8080})]
      (is (= 1 (count (:proxies config))))
      (is (= "simple" (get-in config [:proxies 0 :name])))
      (is (= 80 (get-in config [:proxies 0 :listen :port]))))))

(deftest make-simple-config-defaults-test
  (testing "Simple config uses defaults"
    (let [config (config/make-simple-config {})]
      (is (= "default" (get-in config [:proxies 0 :name])))
      (is (= 80 (get-in config [:proxies 0 :listen :port])))
      (is (= false (get-in config [:settings :stats-enabled]))))))

;;; =============================================================================
;;; Format Tests
;;; =============================================================================

(deftest format-config-test
  (testing "Format config produces non-empty string"
    (let [config (config/make-simple-config {:name "test"})
          formatted (config/format-config config)]
      (is (string? formatted))
      (is (pos? (count formatted)))
      (is (clojure.string/includes? formatted "test")))))

;;; =============================================================================
;;; Weighted Load Balancing Tests
;;; =============================================================================

(deftest validate-weights-single-target-test
  (testing "Single target with no weight is valid"
    (is (nil? (config/validate-weights [{:ip "10.0.0.1" :port 8080}]))))

  (testing "Single target with weight=100 is valid"
    (is (nil? (config/validate-weights [{:ip "10.0.0.1" :port 8080 :weight 100}]))))

  (testing "Single target with any weight is valid (ignored)"
    (is (nil? (config/validate-weights [{:ip "10.0.0.1" :port 8080 :weight 50}])))))

(deftest validate-weights-multiple-targets-test
  (testing "Two targets with weights summing to 100 is valid"
    (is (nil? (config/validate-weights
                [{:ip "10.0.0.1" :port 8080 :weight 50}
                 {:ip "10.0.0.2" :port 8080 :weight 50}]))))

  (testing "Three targets with weights summing to 100 is valid"
    (is (nil? (config/validate-weights
                [{:ip "10.0.0.1" :port 8080 :weight 50}
                 {:ip "10.0.0.2" :port 8080 :weight 30}
                 {:ip "10.0.0.3" :port 8080 :weight 20}]))))

  (testing "Eight targets (max) with weights summing to 100 is valid"
    (is (nil? (config/validate-weights
                (mapv #(hash-map :ip (str "10.0.0." %) :port 8080 :weight (if (= % 8) 37 9))
                      (range 1 9)))))))

(deftest validate-weights-invalid-test
  (testing "Two targets with weights summing to 120 is invalid"
    (is (= "Weights must sum to 100, got 120"
           (config/validate-weights
             [{:ip "10.0.0.1" :port 8080 :weight 60}
              {:ip "10.0.0.2" :port 8080 :weight 60}]))))

  (testing "Two targets with weights summing to 80 is invalid"
    (is (= "Weights must sum to 100, got 80"
           (config/validate-weights
             [{:ip "10.0.0.1" :port 8080 :weight 40}
              {:ip "10.0.0.2" :port 8080 :weight 40}]))))

  (testing "Two targets with missing weight is invalid"
    (is (= "All targets must have explicit weights when multiple targets are specified"
           (config/validate-weights
             [{:ip "10.0.0.1" :port 8080 :weight 50}
              {:ip "10.0.0.2" :port 8080}])))))

(deftest compute-cumulative-weights-test
  (testing "Compute cumulative weights for single target"
    (let [targets [(config/->WeightedTarget 0 8080 100 nil nil)]]
      (is (= [100] (config/compute-cumulative-weights targets)))))

  (testing "Compute cumulative weights for multiple targets"
    (let [targets [(config/->WeightedTarget 0 8080 50 nil nil)
                   (config/->WeightedTarget 1 8080 30 nil nil)
                   (config/->WeightedTarget 2 8080 20 nil nil)]]
      (is (= [50 80 100] (config/compute-cumulative-weights targets))))))

(deftest parse-weighted-target-test
  (testing "Parse weighted target with explicit weight"
    (let [target (config/parse-weighted-target {:ip "10.0.0.1" :port 8080 :weight 75})]
      (is (= 0x0A000001 (:ip target)))
      (is (= 8080 (:port target)))
      (is (= 75 (:weight target)))))

  (testing "Parse weighted target without weight defaults to 100"
    (let [target (config/parse-weighted-target {:ip "10.0.0.1" :port 8080})]
      (is (= 100 (:weight target)))))

  (testing "Parse weighted target with proxy-protocol"
    (let [target (config/parse-weighted-target {:ip "10.0.0.1" :port 8080 :proxy-protocol :v2})]
      (is (= :v2 (:proxy-protocol target)))))

  (testing "Parse weighted target without proxy-protocol is nil"
    (let [target (config/parse-weighted-target {:ip "10.0.0.1" :port 8080})]
      (is (nil? (:proxy-protocol target))))))

(deftest parse-target-group-test
  (testing "Parse single target to target group"
    (let [tg (config/parse-target-group {:ip "10.0.0.1" :port 8080} "test")]
      (is (= 1 (count (:targets tg))))
      (is (= [100] (:cumulative-weights tg)))))

  (testing "Parse multiple weighted targets to target group"
    (let [tg (config/parse-target-group
               [{:ip "10.0.0.1" :port 8080 :weight 50}
                {:ip "10.0.0.2" :port 8080 :weight 30}
                {:ip "10.0.0.3" :port 8080 :weight 20}]
               "test")]
      (is (= 3 (count (:targets tg))))
      (is (= [50 80 100] (:cumulative-weights tg))))))

(deftest parse-target-group-validation-test
  (testing "Parsing multiple targets with invalid weights throws"
    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Weight validation failed"
          (config/parse-target-group
            [{:ip "10.0.0.1" :port 8080 :weight 60}
             {:ip "10.0.0.2" :port 8080 :weight 60}]
            "test")))))

(deftest parse-weighted-proxy-config-test
  (testing "Parse proxy with weighted default-target"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "weighted-proxy"
                       :listen {:interfaces ["eth0"] :port 80}
                       :default-target
                       [{:ip "10.0.0.1" :port 8080 :weight 70}
                        {:ip "10.0.0.2" :port 8080 :weight 30}]})]
      (is (= "weighted-proxy" (:name proxy-cfg)))
      (is (= 2 (count (get-in proxy-cfg [:default-target :targets]))))
      (is (= [70 100] (get-in proxy-cfg [:default-target :cumulative-weights])))))

  (testing "Parse proxy with backward-compatible single default-target"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "single-proxy"
                       :listen {:interfaces ["eth0"] :port 80}
                       :default-target {:ip "10.0.0.1" :port 8080}})]
      (is (= 1 (count (get-in proxy-cfg [:default-target :targets]))))
      (is (= [100] (get-in proxy-cfg [:default-target :cumulative-weights]))))))

(deftest parse-weighted-source-routes-test
  (testing "Parse source route with weighted targets"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "test"
                       :listen {:interfaces ["eth0"] :port 80}
                       :default-target {:ip "10.0.0.1" :port 8080}
                       :source-routes
                       [{:source "192.168.1.0/24"
                         :targets [{:ip "10.0.1.1" :port 8080 :weight 70}
                                   {:ip "10.0.1.2" :port 8080 :weight 30}]}]})]
      (let [route (first (:source-routes proxy-cfg))
            tg (:target-group route)]
        (is (= 2 (count (:targets tg))))
        (is (= [70 100] (:cumulative-weights tg))))))

  (testing "Parse source route with single target (backward compatible)"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "test"
                       :listen {:interfaces ["eth0"] :port 80}
                       :default-target {:ip "10.0.0.1" :port 8080}
                       :source-routes
                       [{:source "192.168.1.0/24"
                         :target {:ip "10.0.1.1" :port 8080}}]})]
      (let [route (first (:source-routes proxy-cfg))
            tg (:target-group route)]
        (is (= 1 (count (:targets tg))))))))

(deftest make-weighted-target-group-test
  (testing "Create weighted target group from specs"
    (let [tg (config/make-weighted-target-group
               [{:ip "10.0.0.1" :port 8080 :weight 60}
                {:ip "10.0.0.2" :port 8080 :weight 40}])]
      (is (= 2 (count (:targets tg))))
      (is (= [60 100] (:cumulative-weights tg)))))

  (testing "Creating invalid weighted target group throws"
    (is (thrown?
          clojure.lang.ExceptionInfo
          (config/make-weighted-target-group
            [{:ip "10.0.0.1" :port 8080 :weight 50}
             {:ip "10.0.0.2" :port 8080}])))))

;;; =============================================================================
;;; IPv6 Configuration Tests
;;; =============================================================================

(deftest ipv6-address-detection-test
  (testing "IPv6 addresses are detected correctly"
    (is (util/ipv6? "2001:db8::1"))
    (is (util/ipv6? "::1"))
    (is (util/ipv6? "fe80::1")))

  (testing "IPv4 addresses are not detected as IPv6"
    (is (not (util/ipv6? "192.168.1.1")))
    (is (not (util/ipv6? "10.0.0.1")))))

(deftest ipv6-source-route-test
  (testing "Parse source route with IPv6 CIDR"
    (let [route (config/parse-source-route
                  {:source "2001:db8::/32"
                   :target {:ip "10.0.0.1" :port 8080}}
                  "test-proxy")]
      ;; For IPv6 source routes, source is stored as bytes
      (is (= :ipv6 (util/address-family "2001:db8::")))
      (is (= 32 (:prefix-len route)))))

  (testing "Parse source route with IPv6 single IP"
    (let [route (config/parse-source-route
                  {:source "2001:db8::1"
                   :target {:ip "10.0.0.2" :port 9000}}
                  "test-proxy")]
      ;; Single IPv6 address should have /128 prefix
      (is (= 128 (:prefix-len route))))))

(deftest ipv6-proxy-config-test
  (testing "Parse proxy with IPv6 source routes"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "ipv6-proxy"
                       :listen {:interfaces ["eth0"] :port 80}
                       :default-target {:ip "10.0.0.1" :port 8080}
                       :source-routes
                       [{:source "2001:db8::/32"
                         :target {:ip "10.0.0.2" :port 8080}}
                        {:source "fe80::/10"
                         :target {:ip "10.0.0.3" :port 8080}}]})]
      (is (= "ipv6-proxy" (:name proxy-cfg)))
      (is (= 2 (count (:source-routes proxy-cfg))))))

  (testing "Parse proxy with mixed IPv4 and IPv6 source routes"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "dual-stack-proxy"
                       :listen {:interfaces ["eth0"] :port 80}
                       :default-target {:ip "10.0.0.1" :port 8080}
                       :source-routes
                       [{:source "192.168.1.0/24"
                         :target {:ip "10.0.0.2" :port 8080}}
                        {:source "2001:db8::/32"
                         :target {:ip "10.0.0.3" :port 8080}}]})]
      (is (= 2 (count (:source-routes proxy-cfg)))))))

(deftest ipv6-validate-config-test
  (testing "Valid IPv6 configuration passes validation"
    (let [config-map {:proxies
                      [{:name "test"
                        :listen {:interfaces ["eth0"] :port 80}
                        :default-target {:ip "10.0.0.1" :port 8080}
                        :source-routes
                        [{:source "2001:db8::/32"
                          :target {:ip "10.0.0.2" :port 8080}}]}]
                      :settings {:stats-enabled false}}
          result (config/validate-config config-map)]
      (is (:valid result))
      (is (some? (:config result))))))
