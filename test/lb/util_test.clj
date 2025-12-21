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
