(ns reverse-proxy.config-test
  "Tests for configuration management."
  (:require [clojure.test :refer [deftest testing is are]]
            [reverse-proxy.config :as config]
            [reverse-proxy.util :as util]))

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
                   :target {:ip "10.0.0.1" :port 8080}})]
      (is (= 0xC0A80100 (:source route)))
      (is (= 24 (:prefix-len route)))
      (is (= 0x0A000001 (get-in route [:target :ip])))))

  (testing "Parse source route with single IP"
    (let [route (config/parse-source-route
                  {:source "192.168.1.100"
                   :target {:ip "10.0.0.2" :port 9000}})]
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
