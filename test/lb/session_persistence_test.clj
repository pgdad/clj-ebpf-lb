(ns lb.session-persistence-test
  "Tests for session persistence (sticky sessions) functionality."
  (:require [clojure.test :refer [deftest testing is]]
            [lb.util :as util]
            [lb.config :as config]))

;;; =============================================================================
;;; Flag Constant Tests
;;; =============================================================================

(deftest flag-session-persistence-constant-test
  (testing "FLAG-SESSION-PERSISTENCE is defined correctly"
    (is (= 0x0001 util/FLAG-SESSION-PERSISTENCE))
    (is (= 1 util/FLAG-SESSION-PERSISTENCE))))

;;; =============================================================================
;;; Route Value Encoding Tests
;;; =============================================================================

(deftest encode-weighted-route-with-session-persistence-test
  (testing "Session persistence flag is encoded in route value"
    (let [target-group (config/make-single-target-group "10.0.0.1" 8080)
          ;; Encode without session persistence
          bytes-no-sp (util/encode-weighted-route-value target-group 0)
          ;; Encode with session persistence
          bytes-with-sp (util/encode-weighted-route-value target-group util/FLAG-SESSION-PERSISTENCE)]
      ;; Check that flag is set at correct offset (bytes 4-5)
      ;; Flags are in native byte order (little-endian on most systems)
      (is (= 72 (count bytes-no-sp)))
      (is (= 72 (count bytes-with-sp)))
      ;; The flags should differ
      (is (not= (vec bytes-no-sp) (vec bytes-with-sp))))))

(deftest decode-weighted-route-with-session-persistence-test
  (testing "Session persistence flag is decoded from route value"
    (let [target-group (config/make-single-target-group "10.0.0.1" 8080)
          bytes-with-sp (util/encode-weighted-route-value target-group util/FLAG-SESSION-PERSISTENCE)
          decoded (util/decode-weighted-route-value bytes-with-sp)]
      (is (= 1 (:target-count decoded)))
      (is (= util/FLAG-SESSION-PERSISTENCE (:flags decoded))))))

(deftest flags-combine-correctly-test
  (testing "Multiple flags can be combined"
    (let [target-group (config/make-single-target-group "10.0.0.1" 8080)
          stats-flag 0x0002  ; hypothetical other flag
          combined (bit-or util/FLAG-SESSION-PERSISTENCE stats-flag)
          encoded (util/encode-weighted-route-value target-group combined)
          decoded (util/decode-weighted-route-value encoded)]
      (is (= combined (:flags decoded)))
      (is (pos? (bit-and (:flags decoded) util/FLAG-SESSION-PERSISTENCE)))
      (is (pos? (bit-and (:flags decoded) stats-flag))))))

;;; =============================================================================
;;; Configuration Parsing Tests
;;; =============================================================================

(deftest proxy-config-session-persistence-test
  (testing "Proxy config accepts session-persistence option"
    (let [full-config {:proxies [{:name "test"
                                  :listen {:interfaces ["lo"] :port 8080}
                                  :default-target {:ip "10.0.0.1" :port 8080}
                                  :session-persistence true}]}
          parsed (config/parse-config full-config)]
      (is parsed)
      (is (true? (:session-persistence (first (:proxies parsed))))))))

(deftest proxy-config-without-session-persistence-test
  (testing "Proxy config works without session-persistence option"
    (let [full-config {:proxies [{:name "test"
                                  :listen {:interfaces ["lo"] :port 8080}
                                  :default-target {:ip "10.0.0.1" :port 8080}}]}
          parsed (config/parse-config full-config)]
      (is parsed)
      (is (nil? (:session-persistence (first (:proxies parsed))))))))

(deftest source-route-session-persistence-test
  (testing "Source route config accepts session-persistence option"
    (let [full-config {:proxies [{:name "test"
                                  :listen {:interfaces ["lo"] :port 8080}
                                  :default-target {:ip "10.0.0.1" :port 8080}
                                  :source-routes [{:source "10.0.0.0/8"
                                                   :target {:ip "10.0.0.2" :port 8080}
                                                   :session-persistence true}]}]}
          parsed (config/parse-config full-config)
          source-route (first (:source-routes (first (:proxies parsed))))]
      (is parsed)
      (is (true? (:session-persistence source-route))))))

(deftest sni-route-session-persistence-test
  (testing "SNI route config accepts session-persistence option"
    (let [full-config {:proxies [{:name "test"
                                  :listen {:interfaces ["lo"] :port 8080}
                                  :default-target {:ip "10.0.0.1" :port 8080}
                                  :sni-routes [{:sni-hostname "example.com"
                                                :target {:ip "10.0.0.2" :port 8080}
                                                :session-persistence true}]}]}
          parsed (config/parse-config full-config)
          sni-route (first (:sni-routes (first (:proxies parsed))))]
      (is parsed)
      (is (true? (:session-persistence sni-route))))))

;;; =============================================================================
;;; Hash Consistency Tests
;;; =============================================================================

(defn compute-ip-hash
  "Compute the hash value for an IP using the same formula as XDP program.
   Uses signed 32-bit multiplication like BPF does."
  [ip-str]
  ;; In BPF: (ip * FNV_PRIME) % 100
  ;; FNV_PRIME = 2654435761 (0x9E3779B1)
  ;; We need to emulate 32-bit signed overflow behavior
  (let [ip (util/ip-string->u32 ip-str)
        fnv-prime (unchecked-int 2654435761)
        ;; Perform 32-bit multiplication with overflow
        product (unchecked-multiply (unchecked-int ip) fnv-prime)]
    (mod (Math/abs product) 100)))

(deftest source-ip-hash-consistency-test
  (testing "Same source IP produces consistent hash"
    (let [ip1 "192.168.1.100"
          ip2 "10.0.0.1"
          hash1 (compute-ip-hash ip1)
          hash2 (compute-ip-hash ip2)]
      ;; Each IP should produce a value in range 0-99
      (is (>= hash1 0))
      (is (< hash1 100))
      (is (>= hash2 0))
      (is (< hash2 100))
      ;; Same IP should give same hash (deterministic)
      (is (= hash1 (compute-ip-hash ip1)))
      (is (= hash2 (compute-ip-hash ip2))))))

(deftest hash-distribution-test
  (testing "Hash produces values across the range 0-99"
    (let [ips (for [a (range 1 256) b (range 1 5)]
                (format "%d.%d.%d.%d" a b (mod a 256) (mod (* a b) 256)))
          hashes (map compute-ip-hash ips)
          unique-hashes (set hashes)]
      ;; The hash should produce multiple unique values (not just 1)
      ;; Note: Java's arithmetic differs from BPF's, so we just check for variety
      (is (> (count unique-hashes) 5)
          (format "Expected > 5 unique hashes, got %d" (count unique-hashes))))))

(deftest hash-determinism-test
  (testing "Hash is deterministic across multiple computations"
    (let [test-ips ["1.2.3.4" "192.168.1.1" "10.0.0.1" "172.16.0.100"]]
      (doseq [ip test-ips]
        (let [hashes (repeatedly 10 #(compute-ip-hash ip))]
          (is (= 1 (count (set hashes)))
              (format "IP %s produced inconsistent hashes: %s" ip (vec hashes))))))))
