(ns lb.sni-test
  "Tests for SNI (Server Name Indication) routing functionality."
  (:require [clojure.test :refer [deftest testing is are]]
            [clojure.spec.alpha :as s]
            [lb.config :as config]
            [lb.util :as util]))

;;; =============================================================================
;;; Hostname Hashing Tests
;;; =============================================================================

(deftest fnv1a-64-test
  (testing "FNV-1a hash produces consistent results"
    ;; Empty string - offset basis (0xcbf29ce484222325 as signed long)
    (is (= (unchecked-long 0xcbf29ce484222325) (util/fnv1a-64 (byte-array 0))))

    ;; Single byte
    (let [a-hash (util/fnv1a-64 (.getBytes "a" "UTF-8"))]
      (is (integer? a-hash))
      (is (not= 0 a-hash)))

    ;; Deterministic - same input = same output
    (is (= (util/fnv1a-64 (.getBytes "test.example.com" "UTF-8"))
           (util/fnv1a-64 (.getBytes "test.example.com" "UTF-8"))))))

(deftest hostname->hash-test
  (testing "Hostname hashing is case-insensitive"
    (is (= (util/hostname->hash "example.com")
           (util/hostname->hash "EXAMPLE.COM")))
    (is (= (util/hostname->hash "api.Example.COM")
           (util/hostname->hash "API.EXAMPLE.COM")))
    (is (= (util/hostname->hash "Test.Host.Name")
           (util/hostname->hash "test.host.name"))))

  (testing "Different hostnames produce different hashes"
    (is (not= (util/hostname->hash "api.example.com")
              (util/hostname->hash "web.example.com")))
    (is (not= (util/hostname->hash "example.com")
              (util/hostname->hash "example.org")))))

(deftest encode-sni-key-test
  (testing "SNI key encoding produces 8 bytes"
    (let [hash (util/hostname->hash "example.com")
          key-bytes (util/encode-sni-key hash)]
      (is (= 8 (alength key-bytes)))))

  (testing "SNI key roundtrip"
    (let [hash (util/hostname->hash "api.example.com")
          key-bytes (util/encode-sni-key hash)
          decoded (util/decode-sni-key key-bytes)]
      (is (= hash (:hostname-hash decoded))))))

;;; =============================================================================
;;; SNI Route Configuration Parsing Tests
;;; =============================================================================

(deftest parse-sni-route-test
  (testing "Parse SNI route with single target"
    (let [route (config/parse-sni-route
                  {:sni-hostname "api.example.com"
                   :target {:ip "10.0.0.1" :port 8443}}
                  "test-proxy")]
      (is (= "api.example.com" (:hostname route)))
      (is (integer? (:hostname-hash route)))
      (is (= 0x0A000001 (get-in route [:target-group :targets 0 :ip])))
      (is (= 8443 (get-in route [:target-group :targets 0 :port])))))

  (testing "Parse SNI route with weighted targets"
    (let [route (config/parse-sni-route
                  {:sni-hostname "web.example.com"
                   :targets [{:ip "10.0.0.1" :port 8443 :weight 70}
                             {:ip "10.0.0.2" :port 8443 :weight 30}]}
                  "test-proxy")]
      (is (= "web.example.com" (:hostname route)))
      (is (= 2 (count (get-in route [:target-group :targets]))))
      (is (= [70 100] (get-in route [:target-group :cumulative-weights])))))

  (testing "Hostname is lowercased"
    (let [route (config/parse-sni-route
                  {:sni-hostname "API.EXAMPLE.COM"
                   :target {:ip "10.0.0.1" :port 8443}}
                  "test-proxy")]
      (is (= "api.example.com" (:hostname route))))))

;;; =============================================================================
;;; Proxy Config with SNI Routes Tests
;;; =============================================================================

(deftest parse-proxy-with-sni-routes-test
  (testing "Parse proxy config with SNI routes"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "https-gateway"
                       :listen {:interfaces ["eth0"] :port 443}
                       :default-target {:ip "10.0.0.1" :port 8443}
                       :sni-routes
                       [{:sni-hostname "api.example.com"
                         :target {:ip "10.0.1.1" :port 8443}}
                        {:sni-hostname "web.example.com"
                         :targets [{:ip "10.0.2.1" :port 8443 :weight 70}
                                   {:ip "10.0.2.2" :port 8443 :weight 30}]}]})]
      (is (= "https-gateway" (:name proxy-cfg)))
      (is (= 2 (count (:sni-routes proxy-cfg))))
      (is (= "api.example.com" (get-in proxy-cfg [:sni-routes 0 :hostname])))
      (is (= "web.example.com" (get-in proxy-cfg [:sni-routes 1 :hostname])))))

  (testing "Proxy config without SNI routes has empty vector"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "simple"
                       :listen {:interfaces ["eth0"] :port 80}
                       :default-target {:ip "10.0.0.1" :port 8080}})]
      (is (= [] (:sni-routes proxy-cfg))))))

;;; =============================================================================
;;; SNI Route Management Tests
;;; =============================================================================

(deftest add-sni-route-to-proxy-test
  (testing "Add SNI route to proxy"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 443}
                      :default-target {:ip "10.0.0.1" :port 8443}}]})
          route {:sni-hostname "api.example.com"
                 :target {:ip "10.0.1.1" :port 8443}}
          updated (config/add-sni-route-to-proxy config "test" route)
          proxy (config/get-proxy updated "test")]
      (is (= 1 (count (:sni-routes proxy))))
      (is (= "api.example.com" (get-in proxy [:sni-routes 0 :hostname]))))))

(deftest add-duplicate-sni-route-test
  (testing "Adding duplicate SNI hostname throws"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 443}
                      :default-target {:ip "10.0.0.1" :port 8443}
                      :sni-routes
                      [{:sni-hostname "api.example.com"
                        :target {:ip "10.0.1.1" :port 8443}}]}]})
          duplicate {:sni-hostname "api.example.com"
                     :target {:ip "10.0.2.1" :port 8443}}]
      (is (thrown-with-msg?
            clojure.lang.ExceptionInfo
            #"SNI route for this hostname already exists"
            (config/add-sni-route-to-proxy config "test" duplicate))))))

(deftest remove-sni-route-from-proxy-test
  (testing "Remove SNI route from proxy"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 443}
                      :default-target {:ip "10.0.0.1" :port 8443}
                      :sni-routes
                      [{:sni-hostname "api.example.com"
                        :target {:ip "10.0.1.1" :port 8443}}
                       {:sni-hostname "web.example.com"
                        :target {:ip "10.0.2.1" :port 8443}}]}]})
          updated (config/remove-sni-route-from-proxy config "test" "api.example.com")
          proxy (config/get-proxy updated "test")]
      (is (= 1 (count (:sni-routes proxy))))
      (is (= "web.example.com" (get-in proxy [:sni-routes 0 :hostname])))))

  (testing "Remove is case-insensitive"
    (let [config (config/parse-config
                   {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 443}
                      :default-target {:ip "10.0.0.1" :port 8443}
                      :sni-routes
                      [{:sni-hostname "api.example.com"
                        :target {:ip "10.0.1.1" :port 8443}}]}]})
          updated (config/remove-sni-route-from-proxy config "test" "API.EXAMPLE.COM")
          proxy (config/get-proxy updated "test")]
      (is (= 0 (count (:sni-routes proxy)))))))

;;; =============================================================================
;;; SNI Route Serialization Tests
;;; =============================================================================

(deftest sni-route->map-test
  (testing "Convert SNI route to map (single target)"
    (let [route (config/parse-sni-route
                  {:sni-hostname "api.example.com"
                   :target {:ip "10.0.0.1" :port 8443}}
                  "test")
          route-map (config/sni-route->map route)]
      (is (= "api.example.com" (:sni-hostname route-map)))
      (is (contains? route-map :target))
      (is (not (contains? route-map :targets)))
      (is (= "10.0.0.1" (get-in route-map [:target :ip])))))

  (testing "Convert SNI route to map (weighted targets)"
    (let [route (config/parse-sni-route
                  {:sni-hostname "web.example.com"
                   :targets [{:ip "10.0.0.1" :port 8443 :weight 50}
                             {:ip "10.0.0.2" :port 8443 :weight 50}]}
                  "test")
          route-map (config/sni-route->map route)]
      (is (= "web.example.com" (:sni-hostname route-map)))
      (is (contains? route-map :targets))
      (is (not (contains? route-map :target)))
      (is (= 2 (count (:targets route-map)))))))

(deftest config-roundtrip-with-sni-test
  (testing "Config with SNI routes roundtrip"
    (let [original {:proxies
                    [{:name "https-gateway"
                      :listen {:interfaces ["eth0"] :port 443}
                      :default-target {:ip "10.0.0.1" :port 8443}
                      :sni-routes
                      [{:sni-hostname "api.example.com"
                        :target {:ip "10.0.1.1" :port 8443}}]}]
                    :settings
                    {:stats-enabled false
                     :connection-timeout-sec 300
                     :max-connections 100000}}
          parsed (config/parse-config original)
          converted (config/config->map parsed)]
      (is (= 1 (count (get-in converted [:proxies 0 :sni-routes]))))
      (is (= "api.example.com"
             (get-in converted [:proxies 0 :sni-routes 0 :sni-hostname]))))))

;;; =============================================================================
;;; Format Tests
;;; =============================================================================

(deftest format-proxy-with-sni-routes-test
  (testing "Format proxy includes SNI routes"
    (let [proxy-cfg (config/parse-proxy-config
                      {:name "https-gateway"
                       :listen {:interfaces ["eth0"] :port 443}
                       :default-target {:ip "10.0.0.1" :port 8443}
                       :sni-routes
                       [{:sni-hostname "api.example.com"
                         :target {:ip "10.0.1.1" :port 8443}}]})
          formatted (config/format-proxy proxy-cfg)]
      (is (clojure.string/includes? formatted "SNI routes"))
      (is (clojure.string/includes? formatted "api.example.com")))))

;;; =============================================================================
;;; Hostname Validation Tests
;;; =============================================================================

(deftest sni-hostname-spec-test
  (testing "Valid SNI hostnames"
    (are [hostname] (s/valid? ::config/sni-hostname hostname)
      "example.com"
      "api.example.com"
      "my-service.example.com"
      "a.b.c.d.example.com"
      "test123.example.com"
      "x"
      "ab"))

  (testing "Invalid SNI hostnames"
    (are [hostname] (not (s/valid? ::config/sni-hostname hostname))
      ""                              ; empty
      "-invalid.com"                  ; starts with hyphen
      ".example.com"                  ; starts with dot
      "example.com.")))
