(ns lb.nat-e2e-test
  "End-to-end tests for the NAT path.
   Tests XDP DNAT and TC SNAT programs with map operations."
  (:require [clojure.test :refer :all]
            [lb.maps :as maps]
            [lb.util :as util]
            [lb.conntrack :as conntrack]
            [lb.programs.xdp-ingress :as xdp]
            [lb.programs.tc-egress :as tc]
            [lb.test-util :refer [when-root]]
            [clj-ebpf.core :as bpf]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(def test-config
  "Test configuration with smaller map sizes."
  {:max-routes 100
   :max-listen-ports 10
   :max-connections 1000})

;;; =============================================================================
;;; Resource Management Macros
;;; =============================================================================

(defmacro with-bpf-maps
  "Create multiple BPF maps and ensure they are closed after use.

   Example:
     (with-bpf-maps [listen-map (maps/create-listen-map {:max-listen-ports 10})
                     conntrack-map (maps/create-conntrack-map {:max-connections 100})]
       ;; Use maps
       (do-tests))"
  [bindings & body]
  (if (empty? bindings)
    `(do ~@body)
    (let [[binding expr & rest-bindings] bindings]
      `(let [~binding ~expr]
         (try
           (with-bpf-maps [~@rest-bindings]
             ~@body)
           (finally
             (bpf/close-map ~binding)))))))

;;; =============================================================================
;;; Program Assembly Tests
;;; =============================================================================

(deftest test-xdp-program-assembly
  (testing "XDP DNAT program assembles without errors"
    (let [bytecode (xdp/build-xdp-ingress-program nil)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))
      ;; Each instruction is 8 bytes
      (is (zero? (mod (count bytecode) 8)))))

  (testing "XDP DNAT program with listen map"
    (let [bytecode (xdp/build-xdp-dnat-program 999 nil nil nil nil nil nil)]
      (is (bytes? bytecode))
      (is (> (count bytecode) 200)))) ; Should have substantial instructions

  (testing "XDP DNAT program with conntrack map"
    (let [bytecode (xdp/build-xdp-dnat-program 999 nil nil 888 nil nil nil)]
      (is (bytes? bytecode))
      ;; With conntrack, should be larger
      (is (>= (/ (count bytecode) 8) 250)))))

(deftest test-tc-program-assembly
  (testing "TC SNAT program assembles without errors"
    (let [bytecode (tc/build-tc-egress-program nil)]
      (is (bytes? bytecode))
      (is (pos? (count bytecode)))
      (is (zero? (mod (count bytecode) 8)))))

  (testing "TC SNAT program with conntrack map"
    (let [bytecode (tc/build-tc-snat-program 888)]
      (is (bytes? bytecode))
      (is (>= (/ (count bytecode) 8) 140)))))

;;; =============================================================================
;;; Conntrack Key/Value Encoding Tests
;;; =============================================================================

(deftest test-conntrack-key-encoding
  (testing "Conntrack key encodes to 16 bytes"
    (let [key {:src-ip (util/ip-string->u32 "192.168.1.100")
               :dst-ip (util/ip-string->u32 "10.0.0.1")
               :src-port 54321
               :dst-port 80
               :protocol 6}
          encoded (util/encode-conntrack-key key)]
      (is (= 16 (count encoded)))))

  (testing "Conntrack key round-trips correctly"
    (let [key {:src-ip (util/ip-string->u32 "192.168.1.100")
               :dst-ip (util/ip-string->u32 "10.0.0.1")
               :src-port 54321
               :dst-port 80
               :protocol 6}
          encoded (util/encode-conntrack-key key)
          decoded (util/decode-conntrack-key encoded)]
      (is (= (:src-ip key) (:src-ip decoded)))
      (is (= (:dst-ip key) (:dst-ip decoded)))
      (is (= (:src-port key) (:src-port decoded)))
      (is (= (:dst-port key) (:dst-port decoded)))
      (is (= (:protocol key) (:protocol decoded))))))

(deftest test-conntrack-value-encoding
  (testing "Conntrack value encodes to 128 bytes"
    (let [value {:orig-dst-ip (util/ip-string->u32 "10.0.0.1")
                 :orig-dst-port 80
                 :nat-dst-ip (util/ip-string->u32 "10.1.1.5")
                 :nat-dst-port 8080
                 :created-ns 1000000000000
                 :last-seen 1000000500000
                 :packets-fwd 100
                 :packets-rev 95
                 :bytes-fwd 15000
                 :bytes-rev 12000}
          encoded (util/encode-conntrack-value value)]
      (is (= 128 (count encoded)))))

  (testing "Conntrack value round-trips correctly"
    (let [value {:orig-dst-ip (util/ip-string->u32 "10.0.0.1")
                 :orig-dst-port 80
                 :nat-dst-ip (util/ip-string->u32 "10.1.1.5")
                 :nat-dst-port 8080
                 :created-ns 1000000000000
                 :last-seen 1000000500000
                 :packets-fwd 100
                 :packets-rev 95
                 :bytes-fwd 15000
                 :bytes-rev 12000}
          encoded (util/encode-conntrack-value value)
          decoded (util/decode-conntrack-value encoded)]
      (is (= (:orig-dst-ip value) (:orig-dst-ip decoded)))
      (is (= (:orig-dst-port value) (:orig-dst-port decoded)))
      (is (= (:nat-dst-ip value) (:nat-dst-ip decoded)))
      (is (= (:nat-dst-port value) (:nat-dst-port decoded)))
      (is (= (:created-ns value) (:created-ns decoded)))
      (is (= (:last-seen value) (:last-seen decoded)))
      (is (= (:packets-fwd value) (:packets-fwd decoded)))
      (is (= (:packets-rev value) (:packets-rev decoded)))
      (is (= (:bytes-fwd value) (:bytes-fwd decoded)))
      (is (= (:bytes-rev value) (:bytes-rev decoded))))))

;;; =============================================================================
;;; Listen Map Key/Value Encoding Tests
;;; =============================================================================

(deftest test-listen-key-encoding
  (testing "Listen key encodes to 8 bytes"
    (let [ifindex 1
          port 80
          encoded (util/encode-listen-key ifindex port)]
      (is (= 8 (count encoded)))))

  (testing "Listen key round-trips correctly"
    (let [ifindex 2
          port 443
          encoded (util/encode-listen-key ifindex port)
          decoded (util/decode-listen-key encoded)]
      (is (= ifindex (:ifindex decoded)))
      (is (= port (:port decoded))))))

(deftest test-route-value-encoding
  (testing "Route value encodes to 8 bytes"
    (let [target-ip (util/ip-string->u32 "10.1.1.5")
          target-port 8080
          flags 0
          encoded (util/encode-route-value target-ip target-port flags)]
      (is (= 8 (count encoded)))))

  (testing "Route value round-trips correctly"
    (let [target-ip (util/ip-string->u32 "10.1.1.5")
          target-port 8080
          flags 1
          encoded (util/encode-route-value target-ip target-port flags)
          decoded (util/decode-route-value encoded)]
      (is (= target-ip (:target-ip decoded)))
      (is (= target-port (:target-port decoded)))
      (is (= flags (:flags decoded))))))

;;; =============================================================================
;;; Connection Helper Tests
;;; =============================================================================

(deftest test-connection-time-helpers
  (testing "connection-expired? returns true for old connections"
    (let [current-ns 2000000000000  ; 2000 seconds
          conn (conntrack/map->Connection
                 {:src-ip 0 :dst-ip 0 :src-port 0 :dst-port 0 :protocol 6
                  :orig-dst-ip 0 :orig-dst-port 0
                  :nat-dst-ip 0 :nat-dst-port 0
                  :created-ns 1000000000000  ; 1000 seconds
                  :last-seen 1000000000000   ; 1000 seconds (idle for 1000s)
                  :packets-fwd 0 :packets-rev 0
                  :bytes-fwd 0 :bytes-rev 0})
          timeout-ns (* 300 1000000000)]  ; 300 seconds
      (is (conntrack/connection-expired? conn current-ns timeout-ns))))

  (testing "connection-expired? returns false for recent connections"
    (let [current-ns 2000000000000  ; 2000 seconds
          conn (conntrack/map->Connection
                 {:src-ip 0 :dst-ip 0 :src-port 0 :dst-port 0 :protocol 6
                  :orig-dst-ip 0 :orig-dst-port 0
                  :nat-dst-ip 0 :nat-dst-port 0
                  :created-ns 1900000000000  ; 1900 seconds
                  :last-seen 1990000000000   ; 1990 seconds (idle for 10s)
                  :packets-fwd 0 :packets-rev 0
                  :bytes-fwd 0 :bytes-rev 0})
          timeout-ns (* 300 1000000000)]  ; 300 seconds
      (is (not (conntrack/connection-expired? conn current-ns timeout-ns)))))

  (testing "connection-age-seconds calculates correctly"
    (let [current-ns 2000000000000  ; 2000 seconds
          conn (conntrack/map->Connection
                 {:src-ip 0 :dst-ip 0 :src-port 0 :dst-port 0 :protocol 6
                  :orig-dst-ip 0 :orig-dst-port 0
                  :nat-dst-ip 0 :nat-dst-port 0
                  :created-ns 1500000000000  ; 1500 seconds
                  :last-seen 1900000000000
                  :packets-fwd 0 :packets-rev 0
                  :bytes-fwd 0 :bytes-rev 0})]
      (is (= 500.0 (conntrack/connection-age-seconds conn current-ns)))))

  (testing "connection-idle-seconds calculates correctly"
    (let [current-ns 2000000000000  ; 2000 seconds
          conn (conntrack/map->Connection
                 {:src-ip 0 :dst-ip 0 :src-port 0 :dst-port 0 :protocol 6
                  :orig-dst-ip 0 :orig-dst-port 0
                  :nat-dst-ip 0 :nat-dst-port 0
                  :created-ns 1500000000000
                  :last-seen 1900000000000  ; 1900 seconds
                  :packets-fwd 0 :packets-rev 0
                  :bytes-fwd 0 :bytes-rev 0})]
      (is (= 100.0 (conntrack/connection-idle-seconds conn current-ns))))))

;;; =============================================================================
;;; Format Duration Tests
;;; =============================================================================

(deftest test-format-duration
  (testing "Formats seconds correctly"
    (is (= "5.0s" (conntrack/format-duration 5.0)))
    (is (= "59.9s" (conntrack/format-duration 59.9))))

  (testing "Formats minutes correctly"
    (is (= "1.0m" (conntrack/format-duration 60.0)))
    (is (= "5.5m" (conntrack/format-duration 330.0))))

  (testing "Formats hours correctly"
    (is (= "1.0h" (conntrack/format-duration 3600.0)))
    (is (= "2.5h" (conntrack/format-duration 9000.0))))

  (testing "Handles nil"
    (is (= "N/A" (conntrack/format-duration nil)))))

;;; =============================================================================
;;; NAT Simulation Tests (without actual BPF)
;;; =============================================================================

(deftest test-nat-data-flow-simulation
  (testing "Simulated DNAT creates correct conntrack entry"
    ;; Simulate what XDP DNAT would create
    (let [;; Original packet: client -> proxy
          src-ip (util/ip-string->u32 "192.168.1.100")
          dst-ip (util/ip-string->u32 "10.0.0.1")  ; proxy VIP
          src-port 54321
          dst-port 80
          protocol 6  ; TCP

          ;; NAT target (from listen map lookup)
          nat-dst-ip (util/ip-string->u32 "10.1.1.5")  ; backend
          nat-dst-port 8080

          ;; Conntrack key (5-tuple of original packet)
          key {:src-ip src-ip
               :dst-ip dst-ip
               :src-port src-port
               :dst-port dst-port
               :protocol protocol}

          ;; Conntrack value (NAT mapping + stats)
          current-ns (System/nanoTime)
          value {:orig-dst-ip dst-ip
                 :orig-dst-port dst-port
                 :nat-dst-ip nat-dst-ip
                 :nat-dst-port nat-dst-port
                 :created-ns current-ns
                 :last-seen current-ns
                 :packets-fwd 1
                 :packets-rev 0
                 :bytes-fwd 100
                 :bytes-rev 0}

          ;; Encode and decode
          key-bytes (util/encode-conntrack-key key)
          value-bytes (util/encode-conntrack-value value)
          decoded-key (util/decode-conntrack-key key-bytes)
          decoded-value (util/decode-conntrack-value value-bytes)]

      (is (= src-ip (:src-ip decoded-key)))
      (is (= dst-ip (:dst-ip decoded-key)))
      (is (= dst-ip (:orig-dst-ip decoded-value)))
      (is (= nat-dst-ip (:nat-dst-ip decoded-value)))
      (is (= 1 (:packets-fwd decoded-value)))
      (is (= 0 (:packets-rev decoded-value)))))

  (testing "Simulated TC SNAT lookup and reverse NAT"
    ;; Simulate what TC SNAT would do on reply packet
    (let [;; Reply packet: backend -> client
          ;; Note: src/dst are swapped from original
          reply-src-ip (util/ip-string->u32 "10.1.1.5")   ; backend
          reply-dst-ip (util/ip-string->u32 "192.168.1.100")  ; client
          reply-src-port 8080
          reply-dst-port 54321
          protocol 6

          ;; Build reverse key (swap src/dst to match original conntrack entry)
          reverse-key {:src-ip reply-dst-ip  ; client (was orig src)
                       :dst-ip (util/ip-string->u32 "10.0.0.1")  ; proxy VIP (was orig dst)
                       :src-port reply-dst-port  ; client port (was orig src-port)
                       :dst-port 80  ; proxy port (was orig dst-port)
                       :protocol protocol}

          ;; This would be found in conntrack map
          ;; Value tells us: orig-dst-ip=proxy, which becomes new src
          conntrack-value {:orig-dst-ip (util/ip-string->u32 "10.0.0.1")
                           :orig-dst-port 80
                           :nat-dst-ip (util/ip-string->u32 "10.1.1.5")
                           :nat-dst-port 8080
                           :created-ns 0
                           :last-seen 0
                           :packets-fwd 5
                           :packets-rev 4
                           :bytes-fwd 500
                           :bytes-rev 400}

          ;; SNAT rewrite: src becomes orig-dst (proxy address)
          new-src-ip (:orig-dst-ip conntrack-value)
          new-src-port (:orig-dst-port conntrack-value)]

      (is (= (util/ip-string->u32 "10.0.0.1") new-src-ip))
      (is (= 80 new-src-port))

      ;; After SNAT, packet is: proxy:80 -> client:54321
      ;; Which is correct - appears to come from the proxy
      )))

;;; =============================================================================
;;; Integration Test (requires root, skipped by default)
;;; =============================================================================

(deftest ^:integration test-full-nat-path-with-maps
  ;; This test requires root privileges to create BPF maps
  ;; Run with: sudo clojure -M:test
  (when-root
    (testing "Full NAT path with real BPF maps"
      ;; Use with-bpf-maps for automatic cleanup
      (with-bpf-maps [listen-map (maps/create-listen-map test-config)
                      conntrack-map (maps/create-conntrack-map test-config)]
        ;; Add a listen port entry
        (maps/add-listen-port listen-map 1 80
          {:ip (util/ip-string->u32 "10.1.1.5") :port 8080})

        ;; Verify it was added
        (let [entries (maps/list-listen-ports listen-map)]
          (is (= 1 (count entries)))
          (when (seq entries)
            (let [entry (first entries)
                  route (:route entry)
                  first-target (first (:targets route))]
              (is (= 1 (:ifindex (:listen entry))))
              (is (= 80 (:port (:listen entry))))
              (is (= 1 (:target-count route)))
              (is (= (util/ip-string->u32 "10.1.1.5") (:ip first-target)))
              (is (= 8080 (:port first-target))))))

        ;; Build programs with real map FDs
        (let [xdp-bytecode (xdp/build-xdp-ingress-program
                            {:listen-map listen-map
                             :conntrack-map conntrack-map})
              tc-bytecode (tc/build-tc-egress-program
                            {:conntrack-map conntrack-map})]
          (is (bytes? xdp-bytecode))
          (is (bytes? tc-bytecode))
          (is (> (count xdp-bytecode) 0))
          (is (> (count tc-bytecode) 0))
          ;; Verify instruction counts
          (is (>= (/ (count xdp-bytecode) 8) 250) "XDP should have 250+ instructions")
          (is (>= (/ (count tc-bytecode) 8) 140) "TC should have 140+ instructions"))))))

;;; =============================================================================
;;; Run All Tests
;;; =============================================================================

(defn run-all-nat-tests []
  (clojure.test/run-tests 'lb.nat-e2e-test))
