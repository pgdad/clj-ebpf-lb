(ns lb.util-test
  "Tests for utility functions."
  (:require [clojure.test :refer [deftest testing is are]]
            [lb.util :as util]))

;;; =============================================================================
;;; IP Address Conversion Tests
;;; =============================================================================

(deftest ip-string->u32-test
  (testing "Convert IP string to u32"
    (is (= 0xC0A80101 (util/ip-string->u32 "192.168.1.1")))
    (is (= 0x0A000001 (util/ip-string->u32 "10.0.0.1")))
    (is (= 0x7F000001 (util/ip-string->u32 "127.0.0.1")))
    (is (= 0x00000000 (util/ip-string->u32 "0.0.0.0")))
    (is (= 0xFFFFFFFF (util/ip-string->u32 "255.255.255.255")))))

(deftest ip-string->u32-invalid-test
  (testing "Invalid IP strings throw exceptions"
    (is (thrown? Exception (util/ip-string->u32 "192.168.1")))
    (is (thrown? Exception (util/ip-string->u32 "192.168.1.256")))
    (is (thrown? Exception (util/ip-string->u32 "not-an-ip")))))

(deftest u32->ip-string-test
  (testing "Convert u32 to IP string"
    (is (= "192.168.1.1" (util/u32->ip-string 0xC0A80101)))
    (is (= "10.0.0.1" (util/u32->ip-string 0x0A000001)))
    (is (= "127.0.0.1" (util/u32->ip-string 0x7F000001)))
    (is (= "0.0.0.0" (util/u32->ip-string 0x00000000)))
    (is (= "255.255.255.255" (util/u32->ip-string 0xFFFFFFFF)))))

(deftest ip-roundtrip-test
  (testing "IP conversion roundtrip"
    (doseq [ip ["192.168.1.1" "10.0.0.1" "172.16.0.100" "8.8.8.8"]]
      (is (= ip (-> ip util/ip-string->u32 util/u32->ip-string))))))

;;; =============================================================================
;;; CIDR Parsing Tests
;;; =============================================================================

(deftest parse-cidr-test
  (testing "Parse CIDR notation"
    (is (= {:ip 0xC0A80100 :prefix-len 24}
           (util/parse-cidr "192.168.1.0/24")))
    (is (= {:ip 0x0A000000 :prefix-len 8}
           (util/parse-cidr "10.0.0.0/8")))
    (is (= {:ip 0xAC100000 :prefix-len 12}
           (util/parse-cidr "172.16.0.0/12")))))

(deftest parse-cidr-single-ip-test
  (testing "Single IP treated as /32"
    (is (= {:ip 0xC0A80101 :prefix-len 32}
           (util/parse-cidr "192.168.1.1")))))

(deftest parse-cidr-invalid-test
  (testing "Invalid prefix length"
    (is (thrown? Exception (util/parse-cidr "192.168.1.0/33")))
    (is (thrown? Exception (util/parse-cidr "192.168.1.0/-1")))))

(deftest cidr->string-test
  (testing "CIDR to string conversion"
    (is (= "192.168.1.0/24"
           (util/cidr->string {:ip 0xC0A80100 :prefix-len 24})))
    (is (= "10.0.0.1/32"
           (util/cidr->string {:ip 0x0A000001 :prefix-len 32})))))

(deftest ip-in-cidr?-test
  (testing "IP in CIDR range check"
    (let [cidr (util/parse-cidr "192.168.1.0/24")]
      (is (util/ip-in-cidr? (util/ip-string->u32 "192.168.1.1") cidr))
      (is (util/ip-in-cidr? (util/ip-string->u32 "192.168.1.255") cidr))
      (is (not (util/ip-in-cidr? (util/ip-string->u32 "192.168.2.1") cidr)))
      (is (not (util/ip-in-cidr? (util/ip-string->u32 "10.0.0.1") cidr)))))

  (testing "/0 matches everything"
    (let [cidr {:ip 0 :prefix-len 0}]
      (is (util/ip-in-cidr? (util/ip-string->u32 "1.2.3.4") cidr))
      (is (util/ip-in-cidr? (util/ip-string->u32 "255.255.255.255") cidr)))))

;;; =============================================================================
;;; Port Validation Tests
;;; =============================================================================

(deftest port-valid?-test
  (testing "Valid ports"
    (is (util/port-valid? 1))
    (is (util/port-valid? 80))
    (is (util/port-valid? 443))
    (is (util/port-valid? 8080))
    (is (util/port-valid? 65535)))

  (testing "Invalid ports"
    (is (not (util/port-valid? 0)))
    (is (not (util/port-valid? -1)))
    (is (not (util/port-valid? 65536)))
    (is (not (util/port-valid? "80")))))

;;; =============================================================================
;;; Binary Encoding Tests
;;; =============================================================================

(deftest encode-lpm-key-test
  (testing "LPM key encoding"
    (let [key-bytes (util/encode-lpm-key 24 0xC0A80100)]
      (is (= 8 (count key-bytes)))
      (is (= {:prefix-len 24 :ip 0xC0A80100}
             (util/decode-lpm-key key-bytes))))))

(deftest encode-listen-key-test
  (testing "Listen key encoding"
    (let [key-bytes (util/encode-listen-key 2 80)]
      (is (= 8 (count key-bytes)))
      (is (= {:ifindex 2 :port 80}
             (util/decode-listen-key key-bytes))))))

(deftest encode-route-value-test
  (testing "Route value encoding"
    (let [value-bytes (util/encode-route-value 0x0A000001 8080 1)]
      (is (= 8 (count value-bytes)))
      (is (= {:target-ip 0x0A000001 :target-port 8080 :flags 1}
             (util/decode-route-value value-bytes))))))

(deftest encode-conntrack-key-test
  (testing "Conntrack key encoding"
    (let [key {:src-ip 0xC0A80101
               :dst-ip 0x0A000001
               :src-port 12345
               :dst-port 80
               :protocol 6}
          key-bytes (util/encode-conntrack-key key)]
      (is (= 16 (count key-bytes)))
      (let [decoded (util/decode-conntrack-key key-bytes)]
        (is (= 0xC0A80101 (:src-ip decoded)))
        (is (= 0x0A000001 (:dst-ip decoded)))
        (is (= 12345 (:src-port decoded)))
        (is (= 80 (:dst-port decoded)))
        (is (= 6 (:protocol decoded)))))))

(deftest encode-stats-event-test
  (testing "Stats event encoding roundtrip"
    (let [event {:event-type :new-conn
                 :timestamp 1234567890
                 :src-ip 0xC0A80101
                 :dst-ip 0x0A000001
                 :src-port 12345
                 :dst-port 80
                 :target-ip 0x0A000002
                 :target-port 8080
                 :packets-fwd 100
                 :bytes-fwd 50000
                 :packets-rev 95
                 :bytes-rev 48000}
          event-bytes (util/encode-stats-event event)
          decoded (util/decode-stats-event event-bytes)]
      (is (= 64 (count event-bytes)))
      (is (= :new-conn (:event-type decoded)))
      (is (= 1234567890 (:timestamp decoded)))
      (is (= 0xC0A80101 (:src-ip decoded)))
      (is (= 100 (:packets-fwd decoded))))))

;;; =============================================================================
;;; Interface Utilities Tests
;;; =============================================================================

(deftest list-interfaces-test
  (testing "List interfaces returns a collection"
    (let [interfaces (util/list-interfaces)]
      (is (coll? interfaces))
      ;; lo should exist on any Linux system
      (is (some #(= "lo" %) interfaces)))))

(deftest get-interface-index-test
  (testing "Get loopback interface index"
    (let [lo-index (util/get-interface-index "lo")]
      (is (integer? lo-index))
      (is (pos? lo-index))))

  (testing "Non-existent interface returns nil"
    (is (nil? (util/get-interface-index "nonexistent-iface-xyz")))))

;;; =============================================================================
;;; Constants Tests
;;; =============================================================================

(deftest protocol-constants-test
  (testing "Protocol constants are correct"
    (is (= 6 util/IPPROTO-TCP))
    (is (= 17 util/IPPROTO-UDP))
    (is (= 1 util/IPPROTO-ICMP))))

(deftest xdp-constants-test
  (testing "XDP return codes are correct"
    (is (= 0 util/XDP-ABORTED))
    (is (= 1 util/XDP-DROP))
    (is (= 2 util/XDP-PASS))
    (is (= 3 util/XDP-TX))
    (is (= 4 util/XDP-REDIRECT))))

;;; =============================================================================
;;; Weighted Route Encoding Tests
;;; =============================================================================

(deftest weighted-route-constants-test
  (testing "Weighted route constants are correct"
    (is (= 8 util/WEIGHTED-ROUTE-HEADER-SIZE))
    (is (= 8 util/WEIGHTED-ROUTE-TARGET-SIZE))
    (is (= 8 util/WEIGHTED-ROUTE-MAX-TARGETS))
    (is (= 72 util/WEIGHTED-ROUTE-MAX-SIZE))))

(deftest encode-weighted-route-single-target-test
  (testing "Single target encoding"
    (let [target-group {:targets [{:ip 0x0A000001 :port 8080 :weight 100}]
                        :cumulative-weights [100]}
          encoded (util/encode-weighted-route-value target-group 0)]
      (is (= util/WEIGHTED-ROUTE-MAX-SIZE (count encoded)))
      (let [decoded (util/decode-weighted-route-value encoded)]
        (is (= 1 (:target-count decoded)))
        (is (= 0 (:flags decoded)))
        (is (= 1 (count (:targets decoded))))
        (is (= 0x0A000001 (get-in decoded [:targets 0 :ip])))
        (is (= 8080 (get-in decoded [:targets 0 :port])))
        (is (= 100 (get-in decoded [:targets 0 :cumulative-weight])))))))

(deftest encode-weighted-route-multiple-targets-test
  (testing "Multiple targets encoding"
    (let [target-group {:targets [{:ip 0x0A000001 :port 8080 :weight 50}
                                  {:ip 0x0A000002 :port 8080 :weight 30}
                                  {:ip 0x0A000003 :port 8080 :weight 20}]
                        :cumulative-weights [50 80 100]}
          encoded (util/encode-weighted-route-value target-group 1)]
      (is (= util/WEIGHTED-ROUTE-MAX-SIZE (count encoded)))
      (let [decoded (util/decode-weighted-route-value encoded)]
        (is (= 3 (:target-count decoded)))
        (is (= 1 (:flags decoded)))
        (is (= 3 (count (:targets decoded))))
        ;; Check all targets
        (is (= 0x0A000001 (get-in decoded [:targets 0 :ip])))
        (is (= 8080 (get-in decoded [:targets 0 :port])))
        (is (= 50 (get-in decoded [:targets 0 :cumulative-weight])))
        (is (= 0x0A000002 (get-in decoded [:targets 1 :ip])))
        (is (= 80 (get-in decoded [:targets 1 :cumulative-weight])))
        (is (= 0x0A000003 (get-in decoded [:targets 2 :ip])))
        (is (= 100 (get-in decoded [:targets 2 :cumulative-weight])))))))

(deftest encode-weighted-route-max-targets-test
  (testing "Maximum 8 targets encoding"
    (let [targets (for [i (range 8)]
                    {:ip (+ 0x0A000001 i) :port (+ 8080 i) :weight (if (= i 7) 16 12)})
          cumulative (reductions + (map :weight targets))
          target-group {:targets (vec targets)
                        :cumulative-weights (vec cumulative)}
          encoded (util/encode-weighted-route-value target-group 0)]
      (is (= util/WEIGHTED-ROUTE-MAX-SIZE (count encoded)))
      (let [decoded (util/decode-weighted-route-value encoded)]
        (is (= 8 (:target-count decoded)))
        (is (= 8 (count (:targets decoded))))
        ;; Verify first and last targets
        (is (= 0x0A000001 (get-in decoded [:targets 0 :ip])))
        (is (= 8080 (get-in decoded [:targets 0 :port])))
        (is (= 0x0A000008 (get-in decoded [:targets 7 :ip])))
        (is (= 8087 (get-in decoded [:targets 7 :port])))
        (is (= 100 (get-in decoded [:targets 7 :cumulative-weight])))))))

(deftest encode-weighted-route-roundtrip-test
  (testing "Encoding roundtrip preserves all data"
    (doseq [num-targets [1 2 3 4 5 6 7 8]]
      (let [weights (if (= num-targets 1)
                      [100]
                      (let [base-weight (quot 100 num-targets)
                            remainder (rem 100 num-targets)]
                        (concat (repeat (dec num-targets) base-weight)
                                [(+ base-weight remainder)])))
            targets (vec (for [[i w] (map-indexed vector weights)]
                           {:ip (+ 0xC0A80101 i) :port (+ 3000 i) :weight w}))
            cumulative (vec (reductions + weights))
            target-group {:targets targets :cumulative-weights cumulative}
            encoded (util/encode-weighted-route-value target-group 42)
            decoded (util/decode-weighted-route-value encoded)]
        (is (= num-targets (:target-count decoded))
            (str "Failed for " num-targets " targets"))
        (is (= 42 (:flags decoded)))
        (is (= num-targets (count (:targets decoded))))))))

(deftest weighted-route-value-size-test
  (testing "Value size calculation"
    (is (= util/WEIGHTED-ROUTE-MAX-SIZE (util/weighted-route-value-size)))))

;;; =============================================================================
;;; IPv6 Address Detection Tests
;;; =============================================================================

(deftest ipv6?-test
  (testing "Valid IPv6 addresses"
    (is (util/ipv6? "2001:db8::1"))
    (is (util/ipv6? "::1"))
    (is (util/ipv6? "::"))
    (is (util/ipv6? "fe80::1"))
    (is (util/ipv6? "2001:db8:cafe:babe::1"))
    (is (util/ipv6? "2001:0db8:0000:0000:0000:0000:0000:0001")))

  (testing "Non-IPv6 addresses"
    (is (not (util/ipv6? "192.168.1.1")))
    (is (not (util/ipv6? "10.0.0.1")))
    (is (not (util/ipv6? "not-an-ip")))
    (is (not (util/ipv6? "")))))

(deftest ipv4?-test
  (testing "Valid IPv4 addresses"
    (is (util/ipv4? "192.168.1.1"))
    (is (util/ipv4? "10.0.0.1"))
    (is (util/ipv4? "0.0.0.0"))
    (is (util/ipv4? "255.255.255.255")))

  (testing "Non-IPv4 addresses"
    (is (not (util/ipv4? "2001:db8::1")))
    (is (not (util/ipv4? "::1")))
    (is (not (util/ipv4? "not-an-ip")))
    (is (not (util/ipv4? "")))))

(deftest address-family-test
  (testing "IPv4 detection"
    (is (= :ipv4 (util/address-family "192.168.1.1")))
    (is (= :ipv4 (util/address-family "10.0.0.1"))))

  (testing "IPv6 detection"
    (is (= :ipv6 (util/address-family "2001:db8::1")))
    (is (= :ipv6 (util/address-family "::1")))
    (is (= :ipv6 (util/address-family "::"))))

  (testing "Unknown addresses"
    (is (nil? (util/address-family "not-an-ip")))
    (is (nil? (util/address-family "")))))

;;; =============================================================================
;;; IPv6 Address Conversion Tests
;;; =============================================================================

(deftest ipv6-string->bytes-test
  (testing "Full IPv6 address"
    (let [bytes (util/ipv6-string->bytes "2001:0db8:0000:0000:0000:0000:0000:0001")]
      (is (= 16 (count bytes)))
      (is (= 0x20 (bit-and 0xFF (aget bytes 0))))
      (is (= 0x01 (bit-and 0xFF (aget bytes 1))))
      (is (= 0x0d (bit-and 0xFF (aget bytes 2))))
      (is (= 0xb8 (bit-and 0xFF (aget bytes 3))))
      (is (= 0x00 (bit-and 0xFF (aget bytes 14))))
      (is (= 0x01 (bit-and 0xFF (aget bytes 15))))))

  (testing "Compressed IPv6 address"
    (let [bytes (util/ipv6-string->bytes "2001:db8::1")]
      (is (= 16 (count bytes)))
      (is (= 0x20 (bit-and 0xFF (aget bytes 0))))
      (is (= 0x01 (bit-and 0xFF (aget bytes 1))))
      (is (= 0x0d (bit-and 0xFF (aget bytes 2))))
      (is (= 0xb8 (bit-and 0xFF (aget bytes 3))))
      ;; Middle should be zeros
      (doseq [i (range 4 14)]
        (is (= 0 (bit-and 0xFF (aget bytes i)))))
      (is (= 0x00 (bit-and 0xFF (aget bytes 14))))
      (is (= 0x01 (bit-and 0xFF (aget bytes 15))))))

  (testing "Loopback address"
    (let [bytes (util/ipv6-string->bytes "::1")]
      (is (= 16 (count bytes)))
      (doseq [i (range 15)]
        (is (= 0 (bit-and 0xFF (aget bytes i)))))
      (is (= 0x01 (bit-and 0xFF (aget bytes 15))))))

  (testing "All zeros"
    (let [bytes (util/ipv6-string->bytes "::")]
      (is (= 16 (count bytes)))
      (doseq [i (range 16)]
        (is (= 0 (bit-and 0xFF (aget bytes i)))))))

  (testing "Link-local address"
    (let [bytes (util/ipv6-string->bytes "fe80::1")]
      (is (= 16 (count bytes)))
      (is (= 0xfe (bit-and 0xFF (aget bytes 0))))
      (is (= 0x80 (bit-and 0xFF (aget bytes 1)))))))

(deftest bytes->ipv6-string-test
  (testing "Full address roundtrip"
    (let [original "2001:db8::1"
          bytes (util/ipv6-string->bytes original)
          result (util/bytes->ipv6-string bytes)]
      ;; Result should be equivalent (may be in different format)
      (is (= (vec (util/ipv6-string->bytes result))
             (vec bytes)))))

  (testing "Loopback roundtrip"
    (let [bytes (util/ipv6-string->bytes "::1")
          result (util/bytes->ipv6-string bytes)]
      (is (= (vec (util/ipv6-string->bytes result))
             (vec bytes)))))

  (testing "All zeros roundtrip"
    (let [bytes (util/ipv6-string->bytes "::")
          result (util/bytes->ipv6-string bytes)]
      (is (= (vec (util/ipv6-string->bytes result))
             (vec bytes))))))

(deftest ipv6-roundtrip-test
  (testing "IPv6 conversion roundtrip preserves address"
    (doseq [ipv6 ["2001:db8::1"
                  "::1"
                  "::"
                  "fe80::1"
                  "2001:db8:cafe:babe:1234:5678:90ab:cdef"]]
      (let [bytes (util/ipv6-string->bytes ipv6)
            result (util/bytes->ipv6-string bytes)
            result-bytes (util/ipv6-string->bytes result)]
        (is (= (vec bytes) (vec result-bytes))
            (str "Roundtrip failed for " ipv6))))))

;;; =============================================================================
;;; Unified IP Format Tests (16-byte)
;;; =============================================================================

(deftest ip-string->bytes16-ipv4-test
  (testing "IPv4 addresses padded to 16 bytes"
    (let [bytes (util/ip-string->bytes16 "192.168.1.1")]
      (is (= 16 (count bytes)))
      ;; First 12 bytes are zeros (IPv4-compatible prefix)
      (doseq [i (range 12)]
        (is (= 0 (bit-and 0xFF (aget bytes i)))
            (str "Byte " i " should be zero")))
      ;; Last 4 bytes are the IPv4 address
      (is (= 192 (bit-and 0xFF (aget bytes 12))))
      (is (= 168 (bit-and 0xFF (aget bytes 13))))
      (is (= 1 (bit-and 0xFF (aget bytes 14))))
      (is (= 1 (bit-and 0xFF (aget bytes 15)))))))

(deftest ip-string->bytes16-ipv6-test
  (testing "IPv6 addresses are 16 bytes"
    (let [bytes (util/ip-string->bytes16 "2001:db8::1")]
      (is (= 16 (count bytes)))
      (is (= 0x20 (bit-and 0xFF (aget bytes 0))))
      (is (= 0x01 (bit-and 0xFF (aget bytes 1))))
      (is (= 0x01 (bit-and 0xFF (aget bytes 15)))))))

(deftest bytes16->ip-string-test
  (testing "IPv4 embedded in 16 bytes"
    (let [bytes (util/ip-string->bytes16 "192.168.1.1")
          result (util/bytes16->ip-string bytes)]
      (is (= "192.168.1.1" result))))

  (testing "IPv6 16 bytes"
    (let [bytes (util/ip-string->bytes16 "2001:db8::1")
          result (util/bytes16->ip-string bytes)]
      ;; Result should be valid IPv6
      (is (util/ipv6? result))
      ;; Should round-trip to same bytes
      (is (= (vec bytes) (vec (util/ip-string->bytes16 result)))))))

(deftest unified-ip-roundtrip-test
  (testing "IPv4 roundtrip through unified format"
    (doseq [ip ["192.168.1.1" "10.0.0.1" "172.16.0.100" "8.8.8.8"]]
      (is (= ip (-> ip util/ip-string->bytes16 util/bytes16->ip-string))
          (str "Failed for " ip))))

  (testing "IPv6 roundtrip through unified format"
    (doseq [ip ["2001:db8::1" "::1" "fe80::1"]]
      (let [bytes (util/ip-string->bytes16 ip)
            result (util/bytes16->ip-string bytes)]
        (is (= (vec bytes) (vec (util/ip-string->bytes16 result)))
            (str "Failed for " ip))))))

;;; =============================================================================
;;; Unified CIDR Parsing Tests
;;; =============================================================================

(deftest parse-cidr-unified-ipv4-test
  (testing "IPv4 CIDR with unified format"
    (let [result (util/parse-cidr-unified "192.168.1.0/24")]
      (is (= :ipv4 (:af result)))
      (is (= 24 (:prefix-len result)))
      (is (= 16 (count (:ip result))))
      ;; First 12 bytes should be zeros
      (doseq [i (range 12)]
        (is (= 0 (bit-and 0xFF (aget (:ip result) i)))))
      ;; Last 4 bytes should be 192.168.1.0
      (is (= 192 (bit-and 0xFF (aget (:ip result) 12))))
      (is (= 168 (bit-and 0xFF (aget (:ip result) 13))))
      (is (= 1 (bit-and 0xFF (aget (:ip result) 14))))
      (is (= 0 (bit-and 0xFF (aget (:ip result) 15)))))))

(deftest parse-cidr-unified-ipv6-test
  (testing "IPv6 CIDR with unified format"
    (let [result (util/parse-cidr-unified "2001:db8::/32")]
      (is (= :ipv6 (:af result)))
      (is (= 32 (:prefix-len result)))
      (is (= 16 (count (:ip result))))
      (is (= 0x20 (bit-and 0xFF (aget (:ip result) 0))))
      (is (= 0x01 (bit-and 0xFF (aget (:ip result) 1))))
      (is (= 0x0d (bit-and 0xFF (aget (:ip result) 2))))
      (is (= 0xb8 (bit-and 0xFF (aget (:ip result) 3))))))

  (testing "IPv6 single IP treated as /128"
    (let [result (util/parse-cidr-unified "2001:db8::1")]
      (is (= :ipv6 (:af result)))
      (is (= 128 (:prefix-len result))))))

(deftest cidr-unified->string-test
  (testing "IPv4 CIDR to string"
    (let [cidr (util/parse-cidr-unified "192.168.1.0/24")
          result (util/cidr-unified->string cidr)]
      (is (= "192.168.1.0/24" result))))

  (testing "IPv6 CIDR to string"
    (let [cidr (util/parse-cidr-unified "2001:db8::/32")
          result (util/cidr-unified->string cidr)]
      ;; Should contain the prefix length
      (is (clojure.string/ends-with? result "/32"))
      ;; Should round-trip the IP correctly
      (let [reparsed (util/parse-cidr-unified result)]
        (is (= (vec (:ip cidr)) (vec (:ip reparsed))))))))

;;; =============================================================================
;;; Unified Key Encoding Tests
;;; =============================================================================

(deftest unified-constants-test
  (testing "Unified key size constants"
    (is (= 20 util/LPM-KEY-UNIFIED-SIZE))
    (is (= 40 util/CONNTRACK-KEY-UNIFIED-SIZE))
    (is (= 128 util/CONNTRACK-VALUE-UNIFIED-SIZE))  ; Extended for PROXY protocol
    (is (= 168 util/WEIGHTED-ROUTE-UNIFIED-MAX-SIZE))))

(deftest encode-lpm-key-unified-test
  (testing "IPv4 LPM key encoding"
    (let [ip-bytes (util/ip-string->bytes16 "192.168.1.0")
          key-bytes (util/encode-lpm-key-unified 24 ip-bytes)]
      (is (= 20 (count key-bytes)))
      (let [decoded (util/decode-lpm-key-unified key-bytes)]
        (is (= 24 (:prefix-len decoded)))
        (is (= (vec ip-bytes) (vec (:ip decoded)))))))

  (testing "IPv6 LPM key encoding"
    (let [ip-bytes (util/ip-string->bytes16 "2001:db8::")
          key-bytes (util/encode-lpm-key-unified 32 ip-bytes)]
      (is (= 20 (count key-bytes)))
      (let [decoded (util/decode-lpm-key-unified key-bytes)]
        (is (= 32 (:prefix-len decoded)))
        (is (= (vec ip-bytes) (vec (:ip decoded))))))))

(deftest encode-conntrack-key-unified-test
  (testing "IPv4 conntrack key encoding"
    (let [src-bytes (util/ip-string->bytes16 "192.168.1.100")
          dst-bytes (util/ip-string->bytes16 "10.0.0.1")
          key {:src-ip src-bytes
               :dst-ip dst-bytes
               :src-port 12345
               :dst-port 80
               :protocol 6}
          key-bytes (util/encode-conntrack-key-unified key)]
      (is (= 40 (count key-bytes)))
      (let [decoded (util/decode-conntrack-key-unified key-bytes)]
        (is (= (vec src-bytes) (vec (:src-ip decoded))))
        (is (= (vec dst-bytes) (vec (:dst-ip decoded))))
        (is (= 12345 (:src-port decoded)))
        (is (= 80 (:dst-port decoded)))
        (is (= 6 (:protocol decoded))))))

  (testing "IPv6 conntrack key encoding"
    (let [src-bytes (util/ip-string->bytes16 "2001:db8::1")
          dst-bytes (util/ip-string->bytes16 "2001:db8::2")
          key {:src-ip src-bytes
               :dst-ip dst-bytes
               :src-port 54321
               :dst-port 443
               :protocol 6}
          key-bytes (util/encode-conntrack-key-unified key)]
      (is (= 40 (count key-bytes)))
      (let [decoded (util/decode-conntrack-key-unified key-bytes)]
        (is (= (vec src-bytes) (vec (:src-ip decoded))))
        (is (= (vec dst-bytes) (vec (:dst-ip decoded))))
        (is (= 54321 (:src-port decoded)))
        (is (= 443 (:dst-port decoded)))
        (is (= 6 (:protocol decoded)))))))

(deftest encode-conntrack-value-unified-test
  (testing "Conntrack value with basic fields"
    (let [orig-ip (util/ip-string->bytes16 "10.0.0.1")
          nat-ip (util/ip-string->bytes16 "192.168.1.1")
          value {:orig-dst-ip orig-ip
                 :orig-dst-port 8080
                 :nat-dst-ip nat-ip
                 :nat-dst-port 9080
                 :created-ns 1000
                 :last-seen 2000
                 :packets-fwd 100
                 :packets-rev 50
                 :bytes-fwd 10000
                 :bytes-rev 5000}
          encoded (util/encode-conntrack-value-unified value)]
      (is (= 128 (count encoded)))
      (let [decoded (util/decode-conntrack-value-unified encoded)]
        (is (= (vec orig-ip) (vec (:orig-dst-ip decoded))))
        (is (= 8080 (:orig-dst-port decoded)))
        (is (= (vec nat-ip) (vec (:nat-dst-ip decoded))))
        (is (= 9080 (:nat-dst-port decoded)))
        (is (= 1000 (:created-ns decoded)))
        (is (= 2000 (:last-seen decoded)))
        (is (= 100 (:packets-fwd decoded)))
        (is (= 50 (:packets-rev decoded)))
        (is (= 10000 (:bytes-fwd decoded)))
        (is (= 5000 (:bytes-rev decoded)))
        ;; PROXY fields default to zero
        (is (= 0 (:conn-state decoded)))
        (is (= 0 (:proxy-flags decoded)))
        (is (= 0 (:seq-offset decoded))))))

  (testing "Conntrack value with PROXY protocol fields"
    (let [orig-ip (util/ip-string->bytes16 "10.0.0.1")
          nat-ip (util/ip-string->bytes16 "192.168.1.1")
          client-ip (util/ip-string->bytes16 "203.0.113.50")
          value {:orig-dst-ip orig-ip
                 :orig-dst-port 8080
                 :nat-dst-ip nat-ip
                 :nat-dst-port 9080
                 :created-ns 1000
                 :last-seen 2000
                 :packets-fwd 100
                 :packets-rev 50
                 :bytes-fwd 10000
                 :bytes-rev 5000
                 :conn-state util/CONN-STATE-ESTABLISHED
                 :proxy-flags (bit-or util/PROXY-FLAG-ENABLED util/PROXY-FLAG-HEADER-INJECTED)
                 :seq-offset 28
                 :orig-client-ip client-ip
                 :orig-client-port 45678}
          encoded (util/encode-conntrack-value-unified value)]
      (is (= 128 (count encoded)))
      (let [decoded (util/decode-conntrack-value-unified encoded)]
        (is (= util/CONN-STATE-ESTABLISHED (:conn-state decoded)))
        (is (= 3 (:proxy-flags decoded)))  ; ENABLED | HEADER-INJECTED
        (is (= 28 (:seq-offset decoded)))
        (is (= (vec client-ip) (vec (:orig-client-ip decoded))))
        (is (= 45678 (:orig-client-port decoded)))))))

(deftest encode-weighted-route-value-unified-test
  (testing "Single IPv4 target unified encoding"
    (let [target-group {:targets [{:ip (util/ip-string->bytes16 "10.0.0.1")
                                   :port 8080
                                   :weight 100}]
                        :cumulative-weights [100]}
          encoded (util/encode-weighted-route-value-unified target-group 0)]
      (is (= util/WEIGHTED-ROUTE-UNIFIED-MAX-SIZE (count encoded)))
      (let [decoded (util/decode-weighted-route-value-unified encoded)]
        (is (= 1 (:target-count decoded)))
        (is (= 0 (:flags decoded)))
        (is (= 1 (count (:targets decoded))))
        (is (= "10.0.0.1"
               (util/bytes16->ip-string (get-in decoded [:targets 0 :ip]))))
        (is (= 8080 (get-in decoded [:targets 0 :port])))
        (is (= 100 (get-in decoded [:targets 0 :cumulative-weight]))))))

  (testing "Multiple IPv6 targets unified encoding"
    (let [target-group {:targets [{:ip (util/ip-string->bytes16 "2001:db8::1")
                                   :port 8080
                                   :weight 50}
                                  {:ip (util/ip-string->bytes16 "2001:db8::2")
                                   :port 8080
                                   :weight 30}
                                  {:ip (util/ip-string->bytes16 "2001:db8::3")
                                   :port 8080
                                   :weight 20}]
                        :cumulative-weights [50 80 100]}
          encoded (util/encode-weighted-route-value-unified target-group 1)]
      (is (= util/WEIGHTED-ROUTE-UNIFIED-MAX-SIZE (count encoded)))
      (let [decoded (util/decode-weighted-route-value-unified encoded)]
        (is (= 3 (:target-count decoded)))
        (is (= 1 (:flags decoded)))
        (is (= 3 (count (:targets decoded))))
        ;; Verify targets are IPv6
        (let [first-ip (util/bytes16->ip-string (get-in decoded [:targets 0 :ip]))]
          (is (util/ipv6? first-ip))))))

  (testing "Mixed IPv4 and IPv6 targets"
    (let [target-group {:targets [{:ip (util/ip-string->bytes16 "10.0.0.1")
                                   :port 8080
                                   :weight 50}
                                  {:ip (util/ip-string->bytes16 "2001:db8::1")
                                   :port 8080
                                   :weight 50}]
                        :cumulative-weights [50 100]}
          encoded (util/encode-weighted-route-value-unified target-group 0)]
      (is (= util/WEIGHTED-ROUTE-UNIFIED-MAX-SIZE (count encoded)))
      (let [decoded (util/decode-weighted-route-value-unified encoded)]
        (is (= 2 (:target-count decoded)))
        ;; First target is IPv4
        (is (= "10.0.0.1"
               (util/bytes16->ip-string (get-in decoded [:targets 0 :ip]))))
        ;; Second target is IPv6
        (let [second-ip (util/bytes16->ip-string (get-in decoded [:targets 1 :ip]))]
          (is (util/ipv6? second-ip)))))))

(deftest encode-listen-key-unified-test
  (testing "IPv4 listen key encoding"
    (let [key-bytes (util/encode-listen-key-unified 2 80 :ipv4)]
      (is (= 8 (count key-bytes)))
      (let [decoded (util/decode-listen-key-unified key-bytes)]
        (is (= 2 (:ifindex decoded)))
        (is (= 80 (:port decoded)))
        (is (= :ipv4 (:af decoded))))))

  (testing "IPv6 listen key encoding"
    (let [key-bytes (util/encode-listen-key-unified 3 443 :ipv6)]
      (is (= 8 (count key-bytes)))
      (let [decoded (util/decode-listen-key-unified key-bytes)]
        (is (= 3 (:ifindex decoded)))
        (is (= 443 (:port decoded)))
        (is (= :ipv6 (:af decoded)))))))

;;; =============================================================================
;;; PROXY Protocol v2 Encoding Tests
;;; =============================================================================

(deftest proxy-v2-constants-test
  (testing "PROXY v2 header sizes"
    (is (= 28 util/PROXY-V2-HEADER-SIZE-IPV4))
    (is (= 52 util/PROXY-V2-HEADER-SIZE-IPV6))
    (is (= 12 (count util/PROXY-V2-SIGNATURE)))))

(deftest encode-proxy-v2-header-ipv4-test
  (testing "Encode IPv4 PROXY v2 header"
    (let [src-ip (util/ip-string->u32 "192.168.1.100")
          dst-ip (util/ip-string->u32 "10.0.0.1")
          header (util/encode-proxy-v2-header-ipv4 src-ip 12345 dst-ip 8080)]
      (is (= 28 (count header)))
      ;; Check signature at beginning
      (is (java.util.Arrays/equals
            (byte-array (take 12 header))
            util/PROXY-V2-SIGNATURE))
      ;; Decode and verify
      (let [decoded (util/decode-proxy-v2-header header)]
        (is (some? decoded))
        (is (= 2 (:version decoded)))
        (is (= 1 (:command decoded)))
        (is (= :ipv4 (:family decoded)))
        (is (= :tcp (:protocol decoded)))
        (is (= src-ip (:src-ip decoded)))
        (is (= dst-ip (:dst-ip decoded)))
        (is (= 12345 (:src-port decoded)))
        (is (= 8080 (:dst-port decoded)))))))

(deftest encode-proxy-v2-header-ipv6-test
  (testing "Encode IPv6 PROXY v2 header"
    (let [src-ip (util/ipv6-string->bytes "2001:db8::1")
          dst-ip (util/ipv6-string->bytes "2001:db8::2")
          header (util/encode-proxy-v2-header-ipv6 src-ip 54321 dst-ip 443)]
      (is (= 52 (count header)))
      ;; Check signature at beginning
      (is (java.util.Arrays/equals
            (byte-array (take 12 header))
            util/PROXY-V2-SIGNATURE))
      ;; Decode and verify
      (let [decoded (util/decode-proxy-v2-header header)]
        (is (some? decoded))
        (is (= 2 (:version decoded)))
        (is (= 1 (:command decoded)))
        (is (= :ipv6 (:family decoded)))
        (is (= :tcp (:protocol decoded)))
        (is (java.util.Arrays/equals src-ip (:src-ip decoded)))
        (is (java.util.Arrays/equals dst-ip (:dst-ip decoded)))
        (is (= 54321 (:src-port decoded)))
        (is (= 443 (:dst-port decoded)))))))

(deftest decode-proxy-v2-header-invalid-test
  (testing "Invalid headers return nil"
    (is (nil? (util/decode-proxy-v2-header (byte-array 10))))
    (is (nil? (util/decode-proxy-v2-header (byte-array 28))))
    (is (nil? (util/decode-proxy-v2-header (byte-array (repeat 28 0)))))))

(deftest proxy-v2-header-size-test
  (testing "Header size helper"
    (is (= 28 (util/proxy-v2-header-size :ipv4)))
    (is (= 52 (util/proxy-v2-header-size :ipv6)))))
