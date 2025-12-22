(ns lb.proxy-protocol-test
  "Tests for PROXY protocol v2 support."
  (:require [clojure.test :refer [deftest testing is are]]
            [lb.util :as util]
            [lb.config :as config])
  (:import [java.nio ByteBuffer ByteOrder]))

;;; =============================================================================
;;; PROXY Protocol v2 Header Encoding Tests
;;; =============================================================================

(deftest proxy-v2-signature-test
  (testing "PROXY v2 signature is 12 bytes"
    (is (= 12 (alength util/PROXY-V2-SIGNATURE))))

  (testing "PROXY v2 signature bytes are correct"
    (let [sig util/PROXY-V2-SIGNATURE
          expected [0x0D 0x0A 0x0D 0x0A 0x00 0x0D 0x0A 0x51 0x55 0x49 0x54 0x0A]]
      (doseq [i (range 12)]
        (is (= (nth expected i) (bit-and (aget sig i) 0xFF))
            (format "Byte %d should be 0x%02X" i (nth expected i)))))))

(deftest proxy-v2-header-size-test
  (testing "IPv4 header size is 28 bytes"
    (is (= 28 util/PROXY-V2-HEADER-SIZE-IPV4)))

  (testing "IPv6 header size is 52 bytes"
    (is (= 52 util/PROXY-V2-HEADER-SIZE-IPV6)))

  (testing "proxy-v2-header-size returns correct values"
    (is (= 28 (util/proxy-v2-header-size :ipv4)))
    (is (= 52 (util/proxy-v2-header-size :ipv6)))))

(deftest encode-proxy-v2-header-ipv4-test
  (testing "IPv4 header encoding produces 28 bytes"
    (let [src-ip (util/ip-string->u32 "192.168.1.100")
          dst-ip (util/ip-string->u32 "10.0.0.1")
          header (util/encode-proxy-v2-header-ipv4 src-ip 12345 dst-ip 80)]
      (is (= 28 (alength header)))))

  (testing "IPv4 header starts with signature"
    (let [header (util/encode-proxy-v2-header-ipv4
                   (util/ip-string->u32 "192.168.1.100") 12345
                   (util/ip-string->u32 "10.0.0.1") 80)
          sig util/PROXY-V2-SIGNATURE]
      (doseq [i (range 12)]
        (is (= (aget sig i) (aget header i))
            (format "Signature byte %d mismatch" i)))))

  (testing "IPv4 header contains correct version/command"
    (let [header (util/encode-proxy-v2-header-ipv4
                   (util/ip-string->u32 "192.168.1.100") 12345
                   (util/ip-string->u32 "10.0.0.1") 80)]
      ;; Byte 12 is version/command: 0x21 (version 2, PROXY command)
      (is (= 0x21 (bit-and (aget header 12) 0xFF)))))

  (testing "IPv4 header contains correct family/protocol"
    (let [header (util/encode-proxy-v2-header-ipv4
                   (util/ip-string->u32 "192.168.1.100") 12345
                   (util/ip-string->u32 "10.0.0.1") 80)]
      ;; Byte 13 is family/protocol: 0x11 (AF_INET + STREAM)
      (is (= 0x11 (bit-and (aget header 13) 0xFF)))))

  (testing "IPv4 header contains correct address length"
    (let [header (util/encode-proxy-v2-header-ipv4
                   (util/ip-string->u32 "192.168.1.100") 12345
                   (util/ip-string->u32 "10.0.0.1") 80)
          buf (ByteBuffer/wrap header)]
      (.order buf ByteOrder/BIG_ENDIAN)
      (.position buf 14)
      ;; Length should be 12 (4+4+2+2)
      (is (= 12 (.getShort buf)))))

  (testing "IPv4 header round-trip encoding"
    ;; Test via encode/decode round-trip
    (let [src-ip (util/ip-string->u32 "192.168.1.100")
          dst-ip (util/ip-string->u32 "10.0.0.1")
          src-port 12345
          dst-port 80
          header (util/encode-proxy-v2-header-ipv4 src-ip src-port dst-ip dst-port)
          decoded (util/decode-proxy-v2-header header)]
      (is (some? decoded) "Should decode successfully")
      (is (= :ipv4 (:family decoded)))
      (is (= :tcp (:protocol decoded)))
      ;; Compare as unsigned - src-ip may be a long already, and (:src-ip decoded) is also a long
      (is (= (bit-and src-ip 0xFFFFFFFF) (bit-and (:src-ip decoded) 0xFFFFFFFF))
          "Source IP should match")
      (is (= (bit-and dst-ip 0xFFFFFFFF) (bit-and (:dst-ip decoded) 0xFFFFFFFF))
          "Dest IP should match")
      (is (= src-port (:src-port decoded)))
      (is (= dst-port (:dst-port decoded))))))

(deftest encode-proxy-v2-header-ipv6-test
  (testing "IPv6 header encoding produces 52 bytes"
    (let [src-ip (util/ipv6-string->bytes "2001:db8::1")
          dst-ip (util/ipv6-string->bytes "2001:db8::2")
          header (util/encode-proxy-v2-header-ipv6 src-ip 12345 dst-ip 80)]
      (is (= 52 (alength header)))))

  (testing "IPv6 header contains correct family/protocol"
    (let [header (util/encode-proxy-v2-header-ipv6
                   (util/ipv6-string->bytes "2001:db8::1") 12345
                   (util/ipv6-string->bytes "2001:db8::2") 80)]
      ;; Byte 13 is family/protocol: 0x21 (AF_INET6 + STREAM)
      (is (= 0x21 (bit-and (aget header 13) 0xFF)))))

  (testing "IPv6 header contains correct address length"
    (let [header (util/encode-proxy-v2-header-ipv6
                   (util/ipv6-string->bytes "2001:db8::1") 12345
                   (util/ipv6-string->bytes "2001:db8::2") 80)
          buf (ByteBuffer/wrap header)]
      (.order buf ByteOrder/BIG_ENDIAN)
      (.position buf 14)
      ;; Length should be 36 (16+16+2+2)
      (is (= 36 (.getShort buf))))))

(deftest decode-proxy-v2-header-test
  (testing "Decode IPv4 header"
    (let [src-ip (util/ip-string->u32 "192.168.1.100")
          dst-ip (util/ip-string->u32 "10.0.0.1")
          src-port 12345
          dst-port 80
          header (util/encode-proxy-v2-header-ipv4 src-ip src-port dst-ip dst-port)
          decoded (util/decode-proxy-v2-header header)]
      (is (some? decoded) "Decode should return non-nil for valid header")
      (is (= :ipv4 (:family decoded)))
      (is (= :tcp (:protocol decoded)))
      ;; Compare as unsigned 32-bit values
      (is (= (bit-and src-ip 0xFFFFFFFF) (bit-and (:src-ip decoded) 0xFFFFFFFF)))
      (is (= (bit-and dst-ip 0xFFFFFFFF) (bit-and (:dst-ip decoded) 0xFFFFFFFF)))
      (is (= src-port (:src-port decoded)))
      (is (= dst-port (:dst-port decoded)))))

  (testing "Decode IPv6 header"
    (let [src-ip (util/ipv6-string->bytes "2001:db8::1")
          dst-ip (util/ipv6-string->bytes "2001:db8::100")
          src-port 54321
          dst-port 443
          header (util/encode-proxy-v2-header-ipv6 src-ip src-port dst-ip dst-port)
          decoded (util/decode-proxy-v2-header header)]
      (is (some? decoded) "Decode should return non-nil for valid header")
      (is (= :ipv6 (:family decoded)))
      (is (= :tcp (:protocol decoded)))
      (is (= src-port (:src-port decoded)))
      (is (= dst-port (:dst-port decoded)))))

  (testing "Decode invalid header"
    (let [invalid (byte-array 28)]
      (is (nil? (util/decode-proxy-v2-header invalid))))

    (let [too-short (byte-array 10)]
      (is (nil? (util/decode-proxy-v2-header too-short))))))

;;; =============================================================================
;;; Configuration Tests
;;; =============================================================================

(deftest proxy-protocol-config-test
  (testing "WeightedTarget record includes proxy-protocol field"
    (let [target (config/->WeightedTarget
                   (util/ip-string->u32 "10.0.0.1")
                   8080
                   100
                   nil
                   :v2)]
      (is (= :v2 (:proxy-protocol target)))))

  (testing "Parse weighted target with proxy-protocol"
    (let [target-map {:ip "10.0.0.1" :port 8080 :weight 50 :proxy-protocol :v2}
          target (config/parse-weighted-target target-map nil)]
      (is (= :v2 (:proxy-protocol target)))
      (is (= 50 (:weight target)))))

  (testing "Parse weighted target without proxy-protocol"
    (let [target-map {:ip "10.0.0.1" :port 8080 :weight 75}
          target (config/parse-weighted-target target-map nil)]
      (is (nil? (:proxy-protocol target)))
      (is (= 75 (:weight target)))))

  (testing "Valid config with proxy-protocol targets"
    (let [config-map {:proxies
                      [{:name "test"
                        :listen {:interfaces ["lo"] :port 8080}
                        :default-target
                        [{:ip "10.0.0.1" :port 80 :weight 50 :proxy-protocol :v2}
                         {:ip "10.0.0.2" :port 80 :weight 50}]}]}
          result (config/validate-config config-map)]
      ;; validate-config returns {:valid true, :config ...} on success
      (is (:valid result) "Config with proxy-protocol should be valid")
      (is (some? (:config result))))))

;;; =============================================================================
;;; Conntrack Value with PROXY Fields Tests
;;; =============================================================================

(deftest conntrack-proxy-fields-test
  (testing "Conntrack value size is 128 bytes"
    (is (= 128 util/CONNTRACK-VALUE-UNIFIED-SIZE)))

  (testing "PROXY field offsets are correct"
    (is (= 96 util/CONNTRACK-PROXY-OFFSET))
    (is (= 96 util/CONNTRACK-CONN-STATE-OFFSET))
    (is (= 97 util/CONNTRACK-PROXY-FLAGS-OFFSET))
    (is (= 100 util/CONNTRACK-SEQ-OFFSET-OFFSET))
    (is (= 104 util/CONNTRACK-ORIG-CLIENT-IP-OFFSET))
    (is (= 120 util/CONNTRACK-ORIG-CLIENT-PORT-OFFSET)))

  (testing "TCP connection state constants"
    (is (= 0 util/CONN-STATE-NEW))
    (is (= 1 util/CONN-STATE-SYN-SENT))
    (is (= 2 util/CONN-STATE-SYN-RECV))
    (is (= 3 util/CONN-STATE-ESTABLISHED)))

  (testing "PROXY flag constants"
    (is (= 0x01 util/PROXY-FLAG-ENABLED))
    (is (= 0x02 util/PROXY-FLAG-HEADER-INJECTED))))

(deftest conntrack-value-encoding-with-proxy-test
  (testing "Encode conntrack value with PROXY fields"
    (let [value {:orig-dst-ip (util/ip-string->bytes16 "10.0.0.1")
                 :orig-dst-port 80
                 :nat-dst-ip (util/ip-string->bytes16 "192.168.1.100")
                 :nat-dst-port 8080
                 :last-seen-ns 1234567890
                 :packets-fwd 100
                 :packets-rev 50
                 :bytes-fwd 10000
                 :bytes-rev 5000
                 :conn-state util/CONN-STATE-ESTABLISHED
                 :proxy-flags (bit-or util/PROXY-FLAG-ENABLED util/PROXY-FLAG-HEADER-INJECTED)
                 :seq-offset 28
                 :orig-client-ip (util/ip-string->bytes16 "203.0.113.42")
                 :orig-client-port 54321}
          encoded (util/encode-conntrack-value-unified value)]
      (is (= 128 (alength encoded)))

      ;; Decode and verify
      (let [decoded (util/decode-conntrack-value-unified encoded)]
        (is (= util/CONN-STATE-ESTABLISHED (:conn-state decoded)))
        (is (= 3 (:proxy-flags decoded))) ; 0x01 | 0x02 = 0x03
        (is (= 28 (:seq-offset decoded)))
        (is (= 54321 (:orig-client-port decoded))))))

  (testing "Round-trip encoding preserves all fields"
    (let [orig {:orig-dst-ip (util/ip-string->bytes16 "10.0.0.1")
                :orig-dst-port 443
                :nat-dst-ip (util/ip-string->bytes16 "192.168.1.1")
                :nat-dst-port 8443
                :last-seen-ns 9999999999
                :packets-fwd 1000
                :packets-rev 900
                :bytes-fwd 100000
                :bytes-rev 90000
                :conn-state util/CONN-STATE-SYN-RECV
                :proxy-flags util/PROXY-FLAG-ENABLED
                :seq-offset 0
                :orig-client-ip (util/ip-string->bytes16 "1.2.3.4")
                :orig-client-port 12345}
          encoded (util/encode-conntrack-value-unified orig)
          decoded (util/decode-conntrack-value-unified encoded)]
      (is (= (:orig-dst-port orig) (:orig-dst-port decoded)))
      (is (= (:nat-dst-port orig) (:nat-dst-port decoded)))
      (is (= (:conn-state orig) (:conn-state decoded)))
      (is (= (:proxy-flags orig) (:proxy-flags decoded)))
      (is (= (:seq-offset orig) (:seq-offset decoded)))
      (is (= (:orig-client-port orig) (:orig-client-port decoded))))))

;;; =============================================================================
;;; Route Value Flag Tests
;;; =============================================================================

(deftest route-value-flags-test
  (testing "FLAG-PROXY-PROTOCOL-V2 constant exists"
    (is (= 0x0004 util/FLAG-PROXY-PROTOCOL-V2)))

  (testing "Flags are distinct"
    (let [flags [util/FLAG-SESSION-PERSISTENCE
                 util/FLAG-PROXY-PROTOCOL-V2]]
      (is (= (count flags) (count (distinct flags)))))))
