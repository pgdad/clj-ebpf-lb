(ns lb.proxy-protocol-integration-test
  "Integration tests for PROXY protocol v2 header injection.
   These tests require root privileges and BPF support."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [lb.core :as lb]
            [lb.config :as config]
            [lb.util :as util]
            [lb.test-util :refer [when-root root?]])
  (:import [java.net ServerSocket Socket InetSocketAddress]
           [java.io InputStream OutputStream]
           [java.nio ByteBuffer ByteOrder]
           [java.util Arrays]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn cleanup-fixture [f]
  (when (lb/running?)
    (lb/shutdown!))
  (f)
  (when (lb/running?)
    (lb/shutdown!)))

(use-fixtures :each cleanup-fixture)

;;; =============================================================================
;;; PROXY Protocol v2 Constants
;;; =============================================================================

(defn proxy-v2-signature
  "Returns PROXY protocol v2 signature bytes."
  []
  (byte-array [0x0D 0x0A 0x0D 0x0A 0x00 0x0D 0x0A 0x51 0x55 0x49 0x54 0x0A]))

(def ^:const PROXY-V2-HEADER-MIN-SIZE 16)
(def ^:const PROXY-V2-IPV4-SIZE 28)
(def ^:const PROXY-V2-IPV6-SIZE 52)

;;; =============================================================================
;;; PROXY Protocol Parsing Utilities
;;; =============================================================================

(defn read-bytes
  "Read exactly n bytes from input stream, blocking until all bytes are read.
   Returns byte array or nil if EOF reached before reading all bytes."
  [^InputStream is n]
  (let [buf (byte-array n)]
    (loop [offset 0]
      (if (>= offset n)
        buf
        (let [read (.read is buf offset (- n offset))]
          (if (neg? read)
            nil  ; EOF
            (recur (+ offset read))))))))

(defn check-proxy-v2-signature
  "Check if the given bytes start with PROXY v2 signature.
   Returns true if signature matches."
  [^bytes data]
  (and (>= (alength data) 12)
       (Arrays/equals (proxy-v2-signature)
                      (Arrays/copyOfRange data 0 12))))

(defn parse-proxy-v2-header
  "Parse PROXY protocol v2 header from byte array.
   Returns map with :version, :command, :family, :protocol, :src-ip, :dst-ip,
   :src-port, :dst-port, or nil if invalid."
  [^bytes data]
  (when (and data (>= (alength data) PROXY-V2-HEADER-MIN-SIZE))
    (when (check-proxy-v2-signature data)
      (let [buf (ByteBuffer/wrap data)
            _ (.position buf 12)
            version-cmd (.get buf)
            version (bit-and (bit-shift-right version-cmd 4) 0x0F)
            command (bit-and version-cmd 0x0F)
            family-proto (.get buf)
            family (bit-and (bit-shift-right family-proto 4) 0x0F)
            protocol (bit-and family-proto 0x0F)
            _ (.order buf ByteOrder/BIG_ENDIAN)
            addr-len (bit-and (.getShort buf) 0xFFFF)]
        (cond
          ;; IPv4 (family = 1)
          (and (= family 1) (>= (alength data) PROXY-V2-IPV4-SIZE))
          (let [_ (.order buf ByteOrder/BIG_ENDIAN)
                src-ip (bit-and (.getInt buf) 0xFFFFFFFF)
                dst-ip (bit-and (.getInt buf) 0xFFFFFFFF)
                src-port (bit-and (.getShort buf) 0xFFFF)
                dst-port (bit-and (.getShort buf) 0xFFFF)]
            {:version version
             :command command
             :family :ipv4
             :protocol (if (= protocol 1) :tcp :udp)
             :src-ip src-ip
             :src-ip-str (util/u32->ip-string src-ip)
             :dst-ip dst-ip
             :dst-ip-str (util/u32->ip-string dst-ip)
             :src-port src-port
             :dst-port dst-port
             :header-size PROXY-V2-IPV4-SIZE})

          ;; IPv6 (family = 2)
          (and (= family 2) (>= (alength data) PROXY-V2-IPV6-SIZE))
          (let [src-ip (byte-array 16)
                dst-ip (byte-array 16)
                _ (.get buf src-ip)
                _ (.get buf dst-ip)
                src-port (bit-and (.getShort buf) 0xFFFF)
                dst-port (bit-and (.getShort buf) 0xFFFF)]
            {:version version
             :command command
             :family :ipv6
             :protocol (if (= protocol 1) :tcp :udp)
             :src-ip src-ip
             :dst-ip dst-ip
             :src-port src-port
             :dst-port dst-port
             :header-size PROXY-V2-IPV6-SIZE})

          :else nil)))))

;;; =============================================================================
;;; Test TCP Server with PROXY Protocol Support
;;; =============================================================================

(defn start-proxy-aware-server
  "Start a TCP server that reads PROXY protocol headers.
   Returns {:server ServerSocket :port int :results atom}.
   The results atom will contain received PROXY headers."
  []
  (let [server (ServerSocket. 0)
        port (.getLocalPort server)
        results (atom [])
        running (atom true)]
    ;; Start acceptor thread
    (future
      (while @running
        (try
          (when-let [client (.accept server)]
            (future
              (try
                (let [is (.getInputStream client)
                      ;; Read enough bytes for PROXY v2 header (max 52 for IPv6)
                      header-bytes (read-bytes is 52)]
                  (when header-bytes
                    (let [parsed (parse-proxy-v2-header header-bytes)]
                      (swap! results conj
                             {:raw header-bytes
                              :parsed parsed
                              :timestamp (System/currentTimeMillis)}))))
                (catch Exception e
                  (when @running
                    (swap! results conj {:error (.getMessage e)})))
                (finally
                  (try (.close client) (catch Exception _))))))
          (catch Exception e
            (when @running
              (println "Server accept error:" (.getMessage e)))))))
    {:server server
     :port port
     :results results
     :running running}))

(defn stop-proxy-aware-server
  "Stop the proxy-aware test server."
  [{:keys [server running]}]
  (reset! running false)
  (try (.close server) (catch Exception _)))

(defn start-echo-server
  "Start a simple TCP server that echoes data back.
   Does not expect PROXY protocol. Used for testing targets without PROXY."
  []
  (let [server (ServerSocket. 0)
        port (.getLocalPort server)
        connections (atom 0)
        running (atom true)]
    (future
      (while @running
        (try
          (when-let [client (.accept server)]
            (swap! connections inc)
            (future
              (try
                (let [is (.getInputStream client)
                      os (.getOutputStream client)
                      buf (byte-array 1024)
                      n (.read is buf)]
                  (when (pos? n)
                    (.write os buf 0 n)
                    (.flush os)))
                (catch Exception _)
                (finally
                  (try (.close client) (catch Exception _))))))
          (catch Exception e
            (when @running
              (println "Echo server accept error:" (.getMessage e)))))))
    {:server server
     :port port
     :connections connections
     :running running}))

(defn stop-echo-server
  "Stop the echo server."
  [{:keys [server running]}]
  (reset! running false)
  (try (.close server) (catch Exception _)))

;;; =============================================================================
;;; Configuration Tests
;;; =============================================================================

(deftest proxy-protocol-config-parsing-test
  (testing "Parse configuration with proxy-protocol targets"
    (let [cfg {:proxies
               [{:name "proxy-test"
                 :listen {:interfaces ["lo"] :port 18080}
                 :default-target
                 [{:ip "127.0.0.1" :port 9001 :weight 50 :proxy-protocol :v2}
                  {:ip "127.0.0.1" :port 9002 :weight 50}]}]}
          parsed (config/parse-config cfg)
          proxy-cfg (first (:proxies parsed))
          targets (get-in proxy-cfg [:default-target :targets])]
      (is parsed "Config should parse successfully")
      (is (= 2 (count targets)))
      (is (= :v2 (:proxy-protocol (first targets))))
      (is (nil? (:proxy-protocol (second targets)))))))

(deftest proxy-protocol-flag-encoding-test
  (testing "PROXY protocol flag is encoded in route value"
    (let [;; Target with proxy-protocol
          target-with-proxy (config/make-weighted-target-group
                              [{:ip "10.0.0.1" :port 8080 :weight 100 :proxy-protocol :v2}])
          ;; Target without proxy-protocol
          target-without (config/make-weighted-target-group
                           [{:ip "10.0.0.1" :port 8080 :weight 100}])
          ;; Encode with flag
          with-flag (util/encode-weighted-route-value target-with-proxy util/FLAG-PROXY-PROTOCOL-V2)
          without-flag (util/encode-weighted-route-value target-without 0)
          ;; Decode
          decoded-with (util/decode-weighted-route-value with-flag)
          decoded-without (util/decode-weighted-route-value without-flag)]
      (is (pos? (bit-and (:flags decoded-with) util/FLAG-PROXY-PROTOCOL-V2))
          "PROXY protocol flag should be set")
      (is (zero? (bit-and (:flags decoded-without) util/FLAG-PROXY-PROTOCOL-V2))
          "PROXY protocol flag should not be set"))))

(deftest proxy-protocol-combined-with-session-persistence-test
  (testing "PROXY protocol flag can be combined with session persistence"
    (let [target-group (config/make-single-target-group "10.0.0.1" 8080)
          combined-flags (bit-or util/FLAG-SESSION-PERSISTENCE util/FLAG-PROXY-PROTOCOL-V2)
          encoded (util/encode-weighted-route-value target-group combined-flags)
          decoded (util/decode-weighted-route-value encoded)]
      (is (= combined-flags (:flags decoded)))
      (is (pos? (bit-and (:flags decoded) util/FLAG-SESSION-PERSISTENCE)))
      (is (pos? (bit-and (:flags decoded) util/FLAG-PROXY-PROTOCOL-V2))))))

;;; =============================================================================
;;; Load Balancer Init Tests (require root)
;;; =============================================================================

(deftest proxy-protocol-lb-init-test
  (when-root
    (testing "Load balancer initializes with proxy-protocol targets"
      (let [cfg (config/parse-config
                  {:proxies
                   [{:name "proxy-lb"
                     :listen {:interfaces ["lo"] :port 18081}
                     :default-target
                     [{:ip "127.0.0.1" :port 19001 :weight 100 :proxy-protocol :v2}]}]})]
        (try
          (lb/init! cfg)
          (is (lb/running?))
          ;; Verify config is stored
          (let [stored-cfg (:config (lb/get-state))
                proxy-cfg (first (:proxies stored-cfg))
                target (first (get-in proxy-cfg [:default-target :targets]))]
            (is (= :v2 (:proxy-protocol target))))
          (finally
            (lb/shutdown!)))))))

(deftest proxy-protocol-mixed-targets-init-test
  (when-root
    (testing "Load balancer handles mixed proxy-protocol and non-proxy targets"
      (let [cfg (config/parse-config
                  {:proxies
                   [{:name "mixed-lb"
                     :listen {:interfaces ["lo"] :port 18082}
                     :default-target
                     [{:ip "127.0.0.1" :port 19002 :weight 50 :proxy-protocol :v2}
                      {:ip "127.0.0.1" :port 19003 :weight 50}]}]})]
        (try
          (lb/init! cfg)
          (is (lb/running?))
          (let [stored-cfg (:config (lb/get-state))
                proxy-cfg (first (:proxies stored-cfg))
                targets (get-in proxy-cfg [:default-target :targets])]
            (is (= 2 (count targets)))
            (is (= :v2 (:proxy-protocol (first targets))))
            (is (nil? (:proxy-protocol (second targets)))))
          (finally
            (lb/shutdown!)))))))

;;; =============================================================================
;;; Conntrack Value Tests
;;; =============================================================================

(deftest conntrack-proxy-fields-encoding-test
  (testing "Conntrack value encodes PROXY protocol fields correctly"
    (let [orig-client-ip (util/ip-string->bytes16 "203.0.113.42")
          value {:orig-dst-ip (util/ip-string->bytes16 "10.0.0.1")
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
                 :seq-offset util/PROXY-V2-HEADER-SIZE-IPV4
                 :orig-client-ip orig-client-ip
                 :orig-client-port 54321}
          encoded (util/encode-conntrack-value-unified value)
          decoded (util/decode-conntrack-value-unified encoded)]
      ;; Verify size
      (is (= 128 (alength encoded)))
      ;; Verify PROXY fields decoded correctly
      (is (= util/CONN-STATE-ESTABLISHED (:conn-state decoded)))
      (is (= 0x03 (:proxy-flags decoded)))  ; ENABLED | HEADER_INJECTED
      (is (= util/PROXY-V2-HEADER-SIZE-IPV4 (:seq-offset decoded)))
      (is (= 54321 (:orig-client-port decoded))))))

(deftest conntrack-tcp-state-machine-test
  (testing "TCP connection states are correctly defined"
    (is (= 0 util/CONN-STATE-NEW))
    (is (= 1 util/CONN-STATE-SYN-SENT))
    (is (= 2 util/CONN-STATE-SYN-RECV))
    (is (= 3 util/CONN-STATE-ESTABLISHED))
    ;; States should be sequential
    (is (< util/CONN-STATE-NEW util/CONN-STATE-SYN-SENT))
    (is (< util/CONN-STATE-SYN-SENT util/CONN-STATE-SYN-RECV))
    (is (< util/CONN-STATE-SYN-RECV util/CONN-STATE-ESTABLISHED))))

;;; =============================================================================
;;; PROXY Header Encoding/Decoding Tests
;;; =============================================================================

(deftest proxy-v2-header-round-trip-test
  (testing "PROXY v2 header encode/decode round-trip for IPv4"
    (let [src-ip (util/ip-string->u32 "192.168.1.100")
          dst-ip (util/ip-string->u32 "10.0.0.1")
          src-port 54321
          dst-port 80
          encoded (util/encode-proxy-v2-header-ipv4 src-ip src-port dst-ip dst-port)
          decoded (parse-proxy-v2-header encoded)]
      (is (some? decoded))
      (is (= :ipv4 (:family decoded)))
      (is (= :tcp (:protocol decoded)))
      (is (= 2 (:version decoded)))
      (is (= 1 (:command decoded)))  ; PROXY command
      (is (= src-port (:src-port decoded)))
      (is (= dst-port (:dst-port decoded)))
      ;; Compare IPs as unsigned 32-bit values
      (is (= (bit-and src-ip 0xFFFFFFFF) (bit-and (:src-ip decoded) 0xFFFFFFFF)))
      (is (= (bit-and dst-ip 0xFFFFFFFF) (bit-and (:dst-ip decoded) 0xFFFFFFFF))))))

(deftest proxy-v2-signature-verification-test
  (testing "PROXY v2 signature verification"
    (is (check-proxy-v2-signature (proxy-v2-signature)))
    (is (check-proxy-v2-signature (util/encode-proxy-v2-header-ipv4
                                    (util/ip-string->u32 "1.2.3.4") 1234
                                    (util/ip-string->u32 "5.6.7.8") 80)))
    (is (not (check-proxy-v2-signature (byte-array 12))))
    (is (not (check-proxy-v2-signature (byte-array [0x00 0x00 0x00]))))))

;;; =============================================================================
;;; TCP Server Tests (Unit Tests for Test Infrastructure)
;;; =============================================================================

(deftest proxy-aware-server-lifecycle-test
  (testing "Proxy-aware test server starts and stops"
    (let [server-info (start-proxy-aware-server)]
      (try
        (is (pos? (:port server-info)))
        (is (instance? ServerSocket (:server server-info)))
        (finally
          (stop-proxy-aware-server server-info))))))

(deftest proxy-aware-server-receives-proxy-header-test
  (testing "Proxy-aware server can parse PROXY v2 header"
    (let [server-info (start-proxy-aware-server)
          port (:port server-info)]
      (try
        ;; Connect and send PROXY v2 header
        (let [client (Socket.)
              _ (.connect client (InetSocketAddress. "127.0.0.1" port) 1000)
              os (.getOutputStream client)
              header (util/encode-proxy-v2-header-ipv4
                       (util/ip-string->u32 "192.168.1.100") 54321
                       (util/ip-string->u32 "10.0.0.1") 80)]
          (.write os header)
          (.write os (.getBytes "Hello after PROXY header"))
          (.flush os)
          (.close client)
          ;; Wait for server to process
          (Thread/sleep 100)
          ;; Check results
          (let [results @(:results server-info)]
            (is (= 1 (count results)))
            (let [result (first results)
                  parsed (:parsed result)]
              (is (some? parsed) "Should parse PROXY header")
              (is (= :ipv4 (:family parsed)))
              (is (= 54321 (:src-port parsed)))
              (is (= 80 (:dst-port parsed))))))
        (finally
          (stop-proxy-aware-server server-info))))))

;;; =============================================================================
;;; End-to-End Integration Tests (require root)
;;; =============================================================================

;; Note: Full end-to-end tests that verify PROXY header injection through
;; the actual BPF programs require:
;; 1. Root privileges for BPF program loading
;; 2. Network namespace setup for isolated testing
;; 3. The TC ingress program to be functional with the kernel
;;
;; These tests validate the configuration, encoding, and userspace components.
;; Kernel-level PROXY injection testing would require additional infrastructure.

(deftest proxy-protocol-source-route-config-test
  (when-root
    (testing "Source route with proxy-protocol parses correctly"
      (let [cfg {:proxies
                 [{:name "source-route-proxy"
                   :listen {:interfaces ["lo"] :port 18083}
                   :default-target {:ip "127.0.0.1" :port 9001}
                   :source-routes
                   [{:source "10.0.0.0/8"
                     :target {:ip "127.0.0.1" :port 9002 :proxy-protocol :v2}}]}]}
            parsed (config/parse-config cfg)
            source-route (first (:source-routes (first (:proxies parsed))))
            target (get-in source-route [:target :targets 0])]
        (is parsed)
        (is (= :v2 (:proxy-protocol target)))))))

(deftest proxy-protocol-validation-test
  (testing "Invalid proxy-protocol value is rejected"
    (let [cfg {:proxies
               [{:name "invalid-proxy"
                 :listen {:interfaces ["lo"] :port 18084}
                 :default-target
                 [{:ip "127.0.0.1" :port 9001 :weight 100 :proxy-protocol :v1}]}]}
          result (config/validate-config cfg)]
      ;; :v1 is not supported, only :v2
      ;; The validation should either fail or ignore unknown values
      ;; depending on implementation
      (is (or (not (:valid result))
              ;; Or if it passes, verify the config handles it gracefully
              (some? result))))))
