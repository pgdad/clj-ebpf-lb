(ns lb.util
  "Utility functions for IP address conversion, CIDR parsing, and binary encoding.
   Supports both IPv4 and IPv6 addresses with unified 16-byte internal format."
  (:require [clojure.string :as str])
  (:import [java.nio ByteBuffer ByteOrder]
           [java.net InetAddress Inet4Address Inet6Address UnknownHostException]))

;;; =============================================================================
;;; IP Address Conversion
;;; =============================================================================

(defn ip-string->u32
  "Convert dotted-decimal IP string to network byte order u32.
   Example: \"192.168.1.1\" => 0xC0A80101 (3232235777)"
  [ip-str]
  (let [octets (str/split ip-str #"\.")
        _ (when (not= 4 (count octets))
            (throw (ex-info "Invalid IP address format" {:ip ip-str})))
        bytes (mapv #(let [n (Integer/parseInt %)]
                       (when (or (< n 0) (> n 255))
                         (throw (ex-info "Invalid IP octet" {:ip ip-str :octet %})))
                       n)
                    octets)]
    (bit-or (bit-shift-left (nth bytes 0) 24)
            (bit-shift-left (nth bytes 1) 16)
            (bit-shift-left (nth bytes 2) 8)
            (nth bytes 3))))

(defn u32->ip-string
  "Convert network byte order u32 to dotted-decimal IP string.
   Example: 0xC0A80101 => \"192.168.1.1\""
  [n]
  (format "%d.%d.%d.%d"
          (bit-and (unsigned-bit-shift-right n 24) 0xFF)
          (bit-and (unsigned-bit-shift-right n 16) 0xFF)
          (bit-and (unsigned-bit-shift-right n 8) 0xFF)
          (bit-and n 0xFF)))

(defn ip->bytes
  "Convert IP u32 to byte array (4 bytes, big-endian).
   Handles unsigned u32 values that may exceed Integer/MAX_VALUE."
  [ip-u32]
  (let [buf (ByteBuffer/allocate 4)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putInt buf (unchecked-int ip-u32))
    (.array buf)))

(defn bytes->ip
  "Convert 4-byte array to IP u32."
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (.getInt buf)))

;;; =============================================================================
;;; IPv6 Address Conversion
;;; =============================================================================

(defn ipv6?
  "Check if string is an IPv6 address (contains colon)."
  [ip-str]
  (and (string? ip-str) (str/includes? ip-str ":")))

(defn ipv4?
  "Check if string is an IPv4 address (dotted decimal, no colons)."
  [ip-str]
  (and (string? ip-str)
       (re-matches #"\d+\.\d+\.\d+\.\d+" ip-str)))

(defn address-family
  "Determine address family from IP string.
   Returns :ipv4, :ipv6, or nil if invalid."
  [ip-str]
  (cond
    (ipv4? ip-str) :ipv4
    (ipv6? ip-str) :ipv6
    :else nil))

(defn ipv6-string->bytes
  "Convert IPv6 string to 16-byte array.
   Uses Java's InetAddress for robust parsing (handles all IPv6 formats).
   Example: \"2001:db8::1\" => [32 1 13 184 0 0 0 0 0 0 0 0 0 0 0 1]"
  [^String ipv6-str]
  (try
    (let [addr (InetAddress/getByName ipv6-str)]
      (when-not (instance? Inet6Address addr)
        (throw (ex-info "Not an IPv6 address" {:ip ipv6-str})))
      (.getAddress addr))
    (catch Exception e
      (throw (ex-info "Invalid IPv6 address" {:ip ipv6-str} e)))))

(defn bytes->ipv6-string
  "Convert 16-byte array to IPv6 string.
   Example: [32 1 13 184 0 0 0 0 0 0 0 0 0 0 0 1] => \"2001:db8::1\""
  [^bytes b]
  (when (not= 16 (alength b))
    (throw (ex-info "Invalid IPv6 byte array length" {:length (alength b)})))
  (let [addr (InetAddress/getByAddress b)]
    (.getHostAddress addr)))

(defn ipv4-bytes->bytes16
  "Pad 4-byte IPv4 address to 16 bytes with zero prefix.
   Format: 00:00:00:00:00:00:00:00:00:00:00:00:AA:BB:CC:DD"
  [^bytes ipv4-bytes]
  (let [result (byte-array 16)]
    ;; First 12 bytes are zero (already initialized)
    ;; Copy IPv4 bytes to last 4 bytes
    (System/arraycopy ipv4-bytes 0 result 12 4)
    result))

(defn u32->bytes16
  "Convert IPv4 u32 to 16-byte unified format."
  [ip-u32]
  (ipv4-bytes->bytes16 (ip->bytes ip-u32)))

(defn ip-string->bytes16
  "Parse IPv4 or IPv6 string to unified 16-byte format.
   IPv4: padded with 12 zero bytes prefix
   IPv6: native 16 bytes"
  [ip-str]
  (if (ipv6? ip-str)
    (ipv6-string->bytes ip-str)
    (u32->bytes16 (ip-string->u32 ip-str))))

(defn bytes16->ip-string
  "Convert unified 16-byte format back to IP string.
   Detects IPv4 (zero-prefixed) vs IPv6."
  [^bytes b]
  (when (not= 16 (alength b))
    (throw (ex-info "Invalid unified IP byte array length" {:length (alength b)})))
  ;; Check if it's an IPv4-mapped address (first 12 bytes are zero)
  (let [is-ipv4 (every? zero? (take 12 b))]
    (if is-ipv4
      ;; Extract last 4 bytes as IPv4
      (let [ipv4-bytes (byte-array 4)]
        (System/arraycopy b 12 ipv4-bytes 0 4)
        (u32->ip-string (bytes->ip ipv4-bytes)))
      ;; Full IPv6 address
      (bytes->ipv6-string b))))

(defn bytes16->address-family
  "Determine address family from unified 16-byte format.
   Returns :ipv4 if first 12 bytes are zero, :ipv6 otherwise."
  [^bytes b]
  (if (every? zero? (take 12 b))
    :ipv4
    :ipv6))

(defn bytes16-zero?
  "Check if unified 16-byte address is all zeros."
  [^bytes b]
  (every? zero? b))

;;; =============================================================================
;;; CIDR Parsing
;;; =============================================================================

(defn parse-cidr
  "Parse CIDR notation string to {:ip <u32> :prefix-len <int>}.
   Supports both CIDR (e.g., \"192.168.1.0/24\") and single IP (e.g., \"192.168.1.1\").
   Single IPs are treated as /32."
  [cidr-str]
  (if (str/includes? cidr-str "/")
    (let [[ip-part prefix-part] (str/split cidr-str #"/")
          prefix-len (Integer/parseInt prefix-part)]
      (when (or (< prefix-len 0) (> prefix-len 32))
        (throw (ex-info "Invalid prefix length" {:cidr cidr-str :prefix prefix-len})))
      {:ip (ip-string->u32 ip-part)
       :prefix-len prefix-len})
    {:ip (ip-string->u32 cidr-str)
     :prefix-len 32}))

(defn cidr->string
  "Convert {:ip <u32> :prefix-len <int>} back to CIDR string."
  [{:keys [ip prefix-len]}]
  (str (u32->ip-string ip) "/" prefix-len))

(defn ip-in-cidr?
  "Check if an IP address (u32) falls within a CIDR range."
  [ip-u32 {:keys [ip prefix-len]}]
  (if (= prefix-len 0)
    true  ; /0 matches everything
    (let [mask (bit-shift-left 0xFFFFFFFF (- 32 prefix-len))]
      (= (bit-and ip-u32 mask)
         (bit-and ip mask)))))

(defn parse-cidr-unified
  "Parse CIDR notation string for IPv4 or IPv6.
   Returns {:ip <16-byte-array> :prefix-len <int> :af <:ipv4|:ipv6>}

   Examples:
     \"192.168.1.0/24\"      => {:ip <bytes16> :prefix-len 24 :af :ipv4}
     \"2001:db8::/32\"       => {:ip <bytes16> :prefix-len 32 :af :ipv6}
     \"192.168.1.1\"         => {:ip <bytes16> :prefix-len 32 :af :ipv4}
     \"2001:db8::1\"         => {:ip <bytes16> :prefix-len 128 :af :ipv6}"
  [cidr-str]
  (let [[ip-part prefix-part] (if (str/includes? cidr-str "/")
                                 (str/split cidr-str #"/")
                                 [cidr-str nil])
        af (address-family ip-part)
        _ (when-not af
            (throw (ex-info "Invalid IP address" {:cidr cidr-str})))
        max-prefix (if (= af :ipv6) 128 32)
        default-prefix max-prefix
        prefix-len (if prefix-part
                     (let [p (Integer/parseInt prefix-part)]
                       (when (or (< p 0) (> p max-prefix))
                         (throw (ex-info "Invalid prefix length"
                                        {:cidr cidr-str :prefix p :max max-prefix})))
                       p)
                     default-prefix)]
    {:ip (ip-string->bytes16 ip-part)
     :prefix-len prefix-len
     :af af}))

(defn cidr-unified->string
  "Convert unified CIDR {:ip <bytes16> :prefix-len :af} back to string."
  [{:keys [ip prefix-len]}]
  (str (bytes16->ip-string ip) "/" prefix-len))

;;; =============================================================================
;;; Hostname Resolution
;;; =============================================================================

(defn resolve-hostname
  "Resolve hostname to IP address (u32).
   Returns nil if resolution fails."
  [hostname]
  (try
    (-> (InetAddress/getByName hostname)
        (.getAddress)
        (bytes->ip))
    (catch UnknownHostException _
      nil)))

(defn resolve-hostname-all
  "Resolve hostname to ALL A records (not just first).
   Returns vector of u32 IPs, or nil if resolution fails.

   This is useful for DNS-based load balancing where a hostname
   may resolve to multiple backend IPs."
  [hostname]
  (try
    (let [addresses (InetAddress/getAllByName hostname)]
      (mapv (fn [^InetAddress addr]
              (bytes->ip (.getAddress addr)))
            addresses))
    (catch UnknownHostException _
      nil)))

(defn resolve-hostname-bytes16
  "Resolve hostname to 16-byte unified format.
   Works for both IPv4 and IPv6 hostnames.
   Returns nil if resolution fails."
  [hostname]
  (try
    (let [addr (InetAddress/getByName hostname)
          raw-bytes (.getAddress addr)]
      (if (= 4 (alength raw-bytes))
        (ipv4-bytes->bytes16 raw-bytes)
        raw-bytes))
    (catch UnknownHostException _
      nil)))

(defn resolve-hostname-all-bytes16
  "Resolve hostname to ALL records in unified 16-byte format.
   Returns vector of 16-byte arrays, or nil if resolution fails."
  [hostname]
  (try
    (let [addresses (InetAddress/getAllByName hostname)]
      (mapv (fn [^InetAddress addr]
              (let [raw-bytes (.getAddress addr)]
                (if (= 4 (alength raw-bytes))
                  (ipv4-bytes->bytes16 raw-bytes)
                  raw-bytes)))
            addresses))
    (catch UnknownHostException _
      nil)))

(defn is-ip-string?
  "Check if a string looks like an IPv4 address."
  [s]
  (boolean (and (string? s) (re-matches #"\d+\.\d+\.\d+\.\d+" s))))

(defn resolve-to-ip
  "Resolve a source specification to IP.
   Accepts: IP string, CIDR string, or hostname.
   Returns {:ip <u32> :prefix-len <int>} or nil on failure."
  [source-spec]
  (cond
    ;; IPv6 address or CIDR - use unified format
    (ipv6? source-spec)
    (parse-cidr-unified source-spec)

    ;; IPv4 address or CIDR
    (re-matches #"\d+\.\d+\.\d+\.\d+(/\d+)?" source-spec)
    (parse-cidr source-spec)

    ;; Try hostname resolution
    :else
    (when-let [ip (resolve-hostname source-spec)]
      {:ip ip :prefix-len 32})))

;;; =============================================================================
;;; Port Utilities
;;; =============================================================================

(defn port-valid?
  "Check if port number is valid (1-65535)."
  [port]
  (and (integer? port) (>= port 1) (<= port 65535)))

(defn port->u16
  "Convert port to unsigned 16-bit value."
  [port]
  (bit-and port 0xFFFF))

;;; =============================================================================
;;; Binary Encoding for eBPF Maps
;;; =============================================================================

(defn encode-lpm-key
  "Encode LPM trie key: {prefix_len (4 bytes) + ip (4 bytes)}.
   Total: 8 bytes."
  [prefix-len ip-u32]
  (let [buf (ByteBuffer/allocate 8)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putInt buf (unchecked-int prefix-len))
    (.putInt buf (unchecked-int ip-u32))
    (.array buf)))

(defn decode-lpm-key
  "Decode LPM trie key from byte array."
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/BIG_ENDIAN)
    {:prefix-len (.getInt buf)
     :ip (Integer/toUnsignedLong (.getInt buf))}))

(defn encode-listen-key
  "Encode listen map key: {ifindex (4 bytes) + port (2 bytes) + padding (2 bytes)}.
   Total: 8 bytes (aligned).
   Uses native byte order for ifindex, but BIG_ENDIAN for port to match
   raw packet bytes that XDP loads with ldx :h."
  [ifindex port]
  (let [buf (ByteBuffer/allocate 8)]
    (.order buf (ByteOrder/nativeOrder))
    (.putInt buf (unchecked-int ifindex))
    ;; Port must be in network byte order (big-endian) to match packet bytes
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putShort buf (unchecked-short port))
    (.order buf (ByteOrder/nativeOrder))
    (.putShort buf (short 0))  ; padding
    (.array buf)))

(defn decode-listen-key
  "Decode listen map key from byte array."
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf (ByteOrder/nativeOrder))
    (let [ifindex (.getInt buf)]
      ;; Port is stored in network byte order (big-endian)
      (.order buf ByteOrder/BIG_ENDIAN)
      {:ifindex ifindex
       :port (bit-and (.getShort buf) 0xFFFF)})))

(defn encode-route-value
  "Encode route value: {target_ip (4 bytes) + target_port (2 bytes) + flags (2 bytes)}.
   Total: 8 bytes.
   IP and port are stored in NETWORK byte order (big-endian) because XDP writes
   them directly to packet headers which are in network byte order.
   Flags remain in native order since they're only used internally."
  [target-ip target-port flags]
  (let [buf (ByteBuffer/allocate 8)]
    ;; IP and port in network byte order for direct packet writes
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putInt buf (unchecked-int target-ip))
    (.putShort buf (unchecked-short target-port))
    ;; Flags in native order
    (.order buf (ByteOrder/nativeOrder))
    (.putShort buf (unchecked-short flags))
    (.array buf)))

(defn decode-route-value
  "Decode route value from byte array."
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    ;; IP and port in network byte order
    (.order buf ByteOrder/BIG_ENDIAN)
    (let [ip (Integer/toUnsignedLong (.getInt buf))
          port (bit-and (.getShort buf) 0xFFFF)]
      ;; Flags in native order
      (.order buf (ByteOrder/nativeOrder))
      {:target-ip ip
       :target-port port
       :flags (bit-and (.getShort buf) 0xFFFF)})))

;;; =============================================================================
;;; Weighted Route Encoding (for load balancing)
;;; =============================================================================

;; Weighted route value format (max 72 bytes for IPv4):
;;
;; Header (8 bytes):
;;   target_count: u8 (1-8)
;;   reserved: u8[3]
;;   flags: u16
;;   reserved: u16
;;
;; Per target (8 bytes each, max 8):
;;   ip: u32 (network byte order)
;;   port: u16 (network byte order)
;;   cumulative_weight: u16 (0-100)
;;
;; Total: 8 + (8 × N) bytes, max 72 bytes

(def ^:const WEIGHTED-ROUTE-HEADER-SIZE 8)
(def ^:const WEIGHTED-ROUTE-TARGET-SIZE 8)
(def ^:const WEIGHTED-ROUTE-MAX-TARGETS 8)
(def ^:const WEIGHTED-ROUTE-MAX-SIZE
  (+ WEIGHTED-ROUTE-HEADER-SIZE (* WEIGHTED-ROUTE-MAX-TARGETS WEIGHTED-ROUTE-TARGET-SIZE)))

;;; =============================================================================
;;; Unified (IPv4/IPv6) Key/Value Sizes
;;; =============================================================================

;; Unified LPM key: 20 bytes (prefix_len(4) + ip(16))
(def ^:const LPM-KEY-UNIFIED-SIZE 20)

;; Unified listen key: 8 bytes (ifindex(4) + port(2) + af(1) + pad(1))
(def ^:const LISTEN-KEY-UNIFIED-SIZE 8)

;; Unified conntrack key: 40 bytes
;; (src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2) + protocol(1) + pad(3))
(def ^:const CONNTRACK-KEY-UNIFIED-SIZE 40)

;; Unified conntrack value: 96 bytes
;; (orig_dst_ip(16) + orig_dst_port(2) + pad(2) + nat_dst_ip(16) + nat_dst_port(2) + pad(2) + counters(56))
(def ^:const CONNTRACK-VALUE-UNIFIED-SIZE 96)

;; Unified weighted route target: 20 bytes (ip(16) + port(2) + weight(2))
(def ^:const WEIGHTED-ROUTE-TARGET-UNIFIED-SIZE 20)

;; Unified weighted route value: 168 bytes (header(8) + 8 * 20)
(def ^:const WEIGHTED-ROUTE-UNIFIED-MAX-SIZE
  (+ WEIGHTED-ROUTE-HEADER-SIZE (* WEIGHTED-ROUTE-MAX-TARGETS WEIGHTED-ROUTE-TARGET-UNIFIED-SIZE)))

;; Route flags (stored in header bytes 4-5)
(def ^:const FLAG-SESSION-PERSISTENCE 0x0001)

(defn encode-weighted-route-value
  "Encode weighted route value for BPF map.
   target-group is a TargetGroup record with :targets and :cumulative-weights.
   flags is optional (default 0).

   Format (max 72 bytes):
   - Header (8 bytes): target_count(1) + reserved(3) + flags(2) + reserved(2)
   - Per target (8 bytes each): ip(4) + port(2) + cumulative_weight(2)

   IP and port are stored in network byte order for direct packet writes."
  ([target-group] (encode-weighted-route-value target-group 0))
  ([target-group flags]
   (let [targets (:targets target-group)
         cumulative-weights (:cumulative-weights target-group)
         target-count (count targets)
         _ (when (> target-count WEIGHTED-ROUTE-MAX-TARGETS)
             (throw (ex-info "Too many targets" {:count target-count :max WEIGHTED-ROUTE-MAX-TARGETS})))
         ;; Always allocate max size for consistent map value size
         buf (ByteBuffer/allocate WEIGHTED-ROUTE-MAX-SIZE)]

     ;; Header: target_count (1 byte)
     (.order buf ByteOrder/BIG_ENDIAN)
     (.put buf (unchecked-byte target-count))
     ;; Reserved (3 bytes)
     (.put buf (byte 0))
     (.put buf (byte 0))
     (.put buf (byte 0))
     ;; Flags (2 bytes) in native order
     (.order buf (ByteOrder/nativeOrder))
     (.putShort buf (unchecked-short flags))
     ;; Reserved (2 bytes)
     (.putShort buf (short 0))

     ;; Per-target entries
     (.order buf ByteOrder/BIG_ENDIAN)
     (doseq [[target cumulative-weight] (map vector targets cumulative-weights)]
       (.putInt buf (unchecked-int (:ip target)))
       (.putShort buf (unchecked-short (:port target)))
       (.putShort buf (unchecked-short cumulative-weight)))

     ;; Zero-fill remaining target slots
     (dotimes [_ (- WEIGHTED-ROUTE-MAX-TARGETS target-count)]
       (.putLong buf 0))

     (.array buf))))

(defn decode-weighted-route-value
  "Decode weighted route value from byte array (72 bytes).
   Returns {:target-count :flags :targets} where targets is a vector of
   {:ip :port :cumulative-weight} maps."
  [^bytes b]
  (when (< (alength b) WEIGHTED-ROUTE-MAX-SIZE)
    (throw (ex-info "Buffer too small for weighted route" {:size (alength b) :expected WEIGHTED-ROUTE-MAX-SIZE})))
  (let [buf (ByteBuffer/wrap b)]
    ;; Header
    (.order buf ByteOrder/BIG_ENDIAN)
    (let [target-count (bit-and (.get buf) 0xFF)
          _ (.get buf)  ; reserved
          _ (.get buf)  ; reserved
          _ (.get buf)  ; reserved
          ;; Flags in native order
          _ (.order buf (ByteOrder/nativeOrder))
          flags (bit-and (.getShort buf) 0xFFFF)
          _ (.getShort buf)  ; reserved
          ;; Targets in network byte order
          _ (.order buf ByteOrder/BIG_ENDIAN)
          targets (vec (for [_ (range target-count)]
                         (let [ip (Integer/toUnsignedLong (.getInt buf))
                               port (bit-and (.getShort buf) 0xFFFF)
                               cumulative-weight (bit-and (.getShort buf) 0xFFFF)]
                           {:ip ip
                            :port port
                            :cumulative-weight cumulative-weight})))]
      {:target-count target-count
       :flags flags
       :targets targets})))

(defn weighted-route-value-size
  "Return the fixed size of weighted route values (72 bytes).
   All weighted routes use the same size for BPF map compatibility."
  []
  WEIGHTED-ROUTE-MAX-SIZE)

;;; =============================================================================
;;; Unified Key/Value Encoding (IPv4/IPv6 support)
;;; =============================================================================

(defn encode-lpm-key-unified
  "Encode unified LPM trie key: {prefix_len (4 bytes) + ip (16 bytes)}.
   Total: 20 bytes.
   ip-bytes16 must be a 16-byte array in unified format."
  [prefix-len ^bytes ip-bytes16]
  (when (not= 16 (alength ip-bytes16))
    (throw (ex-info "IP must be 16 bytes" {:length (alength ip-bytes16)})))
  (let [buf (ByteBuffer/allocate LPM-KEY-UNIFIED-SIZE)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putInt buf (unchecked-int prefix-len))
    (.put buf ip-bytes16)
    (.array buf)))

(defn decode-lpm-key-unified
  "Decode unified LPM trie key from byte array.
   Returns {:prefix-len :ip (16-byte array) :af}."
  [^bytes b]
  (when (< (alength b) LPM-KEY-UNIFIED-SIZE)
    (throw (ex-info "Buffer too small for LPM key" {:size (alength b)})))
  (let [buf (ByteBuffer/wrap b)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        prefix-len (.getInt buf)
        ip-bytes (byte-array 16)]
    (.get buf ip-bytes)
    {:prefix-len prefix-len
     :ip ip-bytes
     :af (bytes16->address-family ip-bytes)}))

(defn encode-listen-key-unified
  "Encode unified listen map key: {ifindex (4 bytes) + port (2 bytes) + af (1 byte) + pad (1 byte)}.
   Total: 8 bytes (same size as before, but includes address family).
   af is :ipv4 or :ipv6."
  [ifindex port af]
  (let [buf (ByteBuffer/allocate LISTEN-KEY-UNIFIED-SIZE)
        af-byte (case af :ipv4 4 :ipv6 6 4)]
    (.order buf (ByteOrder/nativeOrder))
    (.putInt buf (unchecked-int ifindex))
    ;; Port must be in network byte order (big-endian) to match packet bytes
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putShort buf (unchecked-short port))
    ;; Address family and padding
    (.put buf (unchecked-byte af-byte))
    (.put buf (byte 0))  ; padding
    (.array buf)))

(defn decode-listen-key-unified
  "Decode unified listen map key from byte array."
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf (ByteOrder/nativeOrder))
    (let [ifindex (.getInt buf)]
      ;; Port is stored in network byte order (big-endian)
      (.order buf ByteOrder/BIG_ENDIAN)
      (let [port (bit-and (.getShort buf) 0xFFFF)
            af-byte (bit-and (.get buf) 0xFF)]
        {:ifindex ifindex
         :port port
         :af (case af-byte 4 :ipv4 6 :ipv6 :ipv4)}))))

(defn encode-conntrack-key-unified
  "Encode unified connection tracking 5-tuple key.
   {src_ip (16) + dst_ip (16) + src_port (2) + dst_port (2) + protocol (1) + padding (3)}
   Total: 40 bytes (aligned).
   src-ip and dst-ip must be 16-byte arrays."
  [{:keys [src-ip dst-ip src-port dst-port protocol]}]
  (let [buf (ByteBuffer/allocate CONNTRACK-KEY-UNIFIED-SIZE)]
    ;; IPs in network byte order (already big-endian as bytes)
    (.order buf ByteOrder/BIG_ENDIAN)
    (.put buf ^bytes src-ip)
    (.put buf ^bytes dst-ip)
    (.putShort buf (unchecked-short src-port))
    (.putShort buf (unchecked-short dst-port))
    (.put buf (unchecked-byte protocol))
    (.put buf (byte 0))  ; padding
    (.putShort buf (short 0))  ; padding
    (.array buf)))

(defn decode-conntrack-key-unified
  "Decode unified connection tracking key from byte array."
  [^bytes b]
  (when (< (alength b) CONNTRACK-KEY-UNIFIED-SIZE)
    (throw (ex-info "Buffer too small for conntrack key" {:size (alength b)})))
  (let [buf (ByteBuffer/wrap b)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        src-ip (byte-array 16)
        dst-ip (byte-array 16)]
    (.get buf src-ip)
    (.get buf dst-ip)
    {:src-ip src-ip
     :dst-ip dst-ip
     :src-port (bit-and (.getShort buf) 0xFFFF)
     :dst-port (bit-and (.getShort buf) 0xFFFF)
     :protocol (bit-and (.get buf) 0xFF)
     :af (bytes16->address-family src-ip)}))

(defn encode-conntrack-value-unified
  "Encode unified connection tracking value.
   {orig_dst_ip (16) + orig_dst_port (2) + padding (2) + nat_dst_ip (16) + nat_dst_port (2) + padding (2) +
    created_ns (8) + last_seen_ns (8) + packets_fwd (8) + packets_rev (8) + bytes_fwd (8) + bytes_rev (8)}
   Total: 96 bytes.
   IPs in network byte order, counters in native order."
  [{:keys [orig-dst-ip orig-dst-port nat-dst-ip nat-dst-port
           created-ns last-seen packets-fwd packets-rev bytes-fwd bytes-rev]}]
  (let [buf (ByteBuffer/allocate CONNTRACK-VALUE-UNIFIED-SIZE)
        zero-ip (byte-array 16)]
    ;; IPs in network byte order
    (.order buf ByteOrder/BIG_ENDIAN)
    (.put buf ^bytes (or orig-dst-ip zero-ip))
    (.putShort buf (unchecked-short (or orig-dst-port 0)))
    (.putShort buf (short 0))  ; padding
    (.put buf ^bytes (or nat-dst-ip zero-ip))
    (.putShort buf (unchecked-short (or nat-dst-port 0)))
    (.putShort buf (short 0))  ; padding
    ;; Counters in native order (written by XDP/TC directly)
    (.order buf (ByteOrder/nativeOrder))
    (.putLong buf (or created-ns 0))
    (.putLong buf (or last-seen 0))
    (.putLong buf (or packets-fwd 0))
    (.putLong buf (or packets-rev 0))
    (.putLong buf (or bytes-fwd 0))
    (.putLong buf (or bytes-rev 0))
    (.array buf)))

(defn decode-conntrack-value-unified
  "Decode unified connection tracking value from byte array (96 bytes)."
  [^bytes b]
  (when (< (alength b) CONNTRACK-VALUE-UNIFIED-SIZE)
    (throw (ex-info "Buffer too small for conntrack value" {:size (alength b)})))
  (let [buf (ByteBuffer/wrap b)
        orig-dst-ip (byte-array 16)
        nat-dst-ip (byte-array 16)]
    ;; IPs in network byte order
    (.order buf ByteOrder/BIG_ENDIAN)
    (.get buf orig-dst-ip)
    (let [orig-dst-port (bit-and (.getShort buf) 0xFFFF)
          _ (.getShort buf)]  ; padding
      (.get buf nat-dst-ip)
      (let [nat-dst-port (bit-and (.getShort buf) 0xFFFF)
            _ (.getShort buf)]  ; padding
        ;; Counters in native order
        (.order buf (ByteOrder/nativeOrder))
        {:orig-dst-ip orig-dst-ip
         :orig-dst-port orig-dst-port
         :nat-dst-ip nat-dst-ip
         :nat-dst-port nat-dst-port
         :created-ns (.getLong buf)
         :last-seen (.getLong buf)
         :packets-fwd (.getLong buf)
         :packets-rev (.getLong buf)
         :bytes-fwd (.getLong buf)
         :bytes-rev (.getLong buf)
         :af (bytes16->address-family orig-dst-ip)}))))

(defn encode-weighted-route-value-unified
  "Encode unified weighted route value for BPF map.
   target-group has :targets with :ip as 16-byte arrays, and :cumulative-weights.
   flags is optional (default 0).

   Format (max 168 bytes):
   - Header (8 bytes): target_count(1) + reserved(3) + flags(2) + reserved(2)
   - Per target (20 bytes each): ip(16) + port(2) + cumulative_weight(2)

   IP bytes are stored in network byte order (big-endian)."
  ([target-group] (encode-weighted-route-value-unified target-group 0))
  ([target-group flags]
   (let [targets (:targets target-group)
         cumulative-weights (:cumulative-weights target-group)
         target-count (count targets)
         _ (when (> target-count WEIGHTED-ROUTE-MAX-TARGETS)
             (throw (ex-info "Too many targets" {:count target-count :max WEIGHTED-ROUTE-MAX-TARGETS})))
         ;; Always allocate max size for consistent map value size
         buf (ByteBuffer/allocate WEIGHTED-ROUTE-UNIFIED-MAX-SIZE)]

     ;; Header: target_count (1 byte)
     (.order buf ByteOrder/BIG_ENDIAN)
     (.put buf (unchecked-byte target-count))
     ;; Reserved (3 bytes)
     (.put buf (byte 0))
     (.put buf (byte 0))
     (.put buf (byte 0))
     ;; Flags (2 bytes) in native order
     (.order buf (ByteOrder/nativeOrder))
     (.putShort buf (unchecked-short flags))
     ;; Reserved (2 bytes)
     (.putShort buf (short 0))

     ;; Per-target entries
     (.order buf ByteOrder/BIG_ENDIAN)
     (doseq [[target cumulative-weight] (map vector targets cumulative-weights)]
       (let [ip-bytes (:ip target)]
         (.put buf ^bytes ip-bytes)  ; 16-byte IP
         (.putShort buf (unchecked-short (:port target)))
         (.putShort buf (unchecked-short cumulative-weight))))

     ;; Zero-fill remaining target slots (20 bytes each)
     (dotimes [_ (- WEIGHTED-ROUTE-MAX-TARGETS target-count)]
       (.put buf (byte-array WEIGHTED-ROUTE-TARGET-UNIFIED-SIZE)))

     (.array buf))))

(defn decode-weighted-route-value-unified
  "Decode unified weighted route value from byte array (168 bytes).
   Returns {:target-count :flags :targets} where targets is a vector of
   {:ip <16-byte-array> :port :cumulative-weight} maps."
  [^bytes b]
  (when (< (alength b) WEIGHTED-ROUTE-UNIFIED-MAX-SIZE)
    (throw (ex-info "Buffer too small for unified weighted route"
                   {:size (alength b) :expected WEIGHTED-ROUTE-UNIFIED-MAX-SIZE})))
  (let [buf (ByteBuffer/wrap b)]
    ;; Header
    (.order buf ByteOrder/BIG_ENDIAN)
    (let [target-count (bit-and (.get buf) 0xFF)
          _ (.get buf)  ; reserved
          _ (.get buf)  ; reserved
          _ (.get buf)  ; reserved
          ;; Flags in native order
          _ (.order buf (ByteOrder/nativeOrder))
          flags (bit-and (.getShort buf) 0xFFFF)
          _ (.getShort buf)  ; reserved
          ;; Targets in network byte order
          _ (.order buf ByteOrder/BIG_ENDIAN)
          targets (vec (for [_ (range target-count)]
                         (let [ip-bytes (byte-array 16)]
                           (.get buf ip-bytes)
                           {:ip ip-bytes
                            :port (bit-and (.getShort buf) 0xFFFF)
                            :cumulative-weight (bit-and (.getShort buf) 0xFFFF)})))]
      {:target-count target-count
       :flags flags
       :targets targets})))

(defn weighted-route-unified-value-size
  "Return the fixed size of unified weighted route values (168 bytes)."
  []
  WEIGHTED-ROUTE-UNIFIED-MAX-SIZE)

;;; =============================================================================
;;; SNI Hostname Hashing (for TLS SNI-based routing)
;;; =============================================================================

(def ^:const FNV1A-64-OFFSET-BASIS 0xcbf29ce484222325)
(def ^:const FNV1A-64-PRIME 0x00000100000001B3)

(defn fnv1a-64
  "Compute FNV-1a 64-bit hash of a byte array.
   This is a fast, non-cryptographic hash suitable for hash table lookups."
  ^long [^bytes data]
  (loop [hash (unchecked-long FNV1A-64-OFFSET-BASIS)
         i 0]
    (if (>= i (alength data))
      hash
      (let [b (bit-and (aget data i) 0xFF)
            hash-xor (bit-xor hash b)
            hash-mul (unchecked-multiply hash-xor FNV1A-64-PRIME)]
        (recur hash-mul (inc i))))))

(defn hostname->hash
  "Hash a hostname for SNI map lookup using FNV-1a 64-bit.
   Hostname is lowercased before hashing for case-insensitive matching."
  ^long [^String hostname]
  (fnv1a-64 (.getBytes (.toLowerCase hostname) "UTF-8")))

(def ^:const SNI-KEY-SIZE 8)

(defn encode-sni-key
  "Encode SNI map key from hostname hash.
   Key: hostname_hash (8 bytes) = 8 bytes total.
   Uses native byte order for efficient lookup."
  [hostname-hash]
  (let [buf (ByteBuffer/allocate SNI-KEY-SIZE)]
    (.order buf (ByteOrder/nativeOrder))
    (.putLong buf (unchecked-long hostname-hash))
    (.array buf)))

(defn decode-sni-key
  "Decode SNI map key from byte array."
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf (ByteOrder/nativeOrder))
    {:hostname-hash (.getLong buf)}))

(defn encode-conntrack-key
  "Encode connection tracking 5-tuple key.
   {src_ip (4) + dst_ip (4) + src_port (2) + dst_port (2) + protocol (1) + padding (3)}
   Total: 16 bytes (aligned).
   XDP stores packet values (network byte order) directly, so we use big-endian
   to match packet byte layout."
  [{:keys [src-ip dst-ip src-port dst-port protocol]}]
  (let [buf (ByteBuffer/allocate 16)]
    ;; IPs and ports in network byte order to match packet bytes
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putInt buf (unchecked-int src-ip))
    (.putInt buf (unchecked-int dst-ip))
    (.putShort buf (unchecked-short src-port))
    (.putShort buf (unchecked-short dst-port))
    (.put buf (unchecked-byte protocol))
    (.put buf (byte 0))  ; padding
    (.putShort buf (short 0))  ; padding
    (.array buf)))

(defn decode-conntrack-key
  "Decode connection tracking key from byte array."
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    ;; IPs and ports stored in network byte order
    (.order buf ByteOrder/BIG_ENDIAN)
    {:src-ip (Integer/toUnsignedLong (.getInt buf))
     :dst-ip (Integer/toUnsignedLong (.getInt buf))
     :src-port (bit-and (.getShort buf) 0xFFFF)
     :dst-port (bit-and (.getShort buf) 0xFFFF)
     :protocol (bit-and (.get buf) 0xFF)}))

(defn encode-conntrack-value
  "Encode connection tracking value.
   {orig_dst_ip (4) + orig_dst_port (2) + padding (2) + nat_dst_ip (4) + nat_dst_port (2) + padding (2) +
    created_ns (8) + last_seen_ns (8) + packets_fwd (8) + packets_rev (8) + bytes_fwd (8) + bytes_rev (8)}
   Total: 64 bytes.
   IPs and ports in network byte order (from packet), counters in native order."
  [{:keys [orig-dst-ip orig-dst-port nat-dst-ip nat-dst-port
           created-ns last-seen packets-fwd packets-rev bytes-fwd bytes-rev]}]
  (let [buf (ByteBuffer/allocate 64)]
    ;; IPs and ports in network byte order
    (.order buf ByteOrder/BIG_ENDIAN)
    (.putInt buf (unchecked-int (or orig-dst-ip 0)))
    (.putShort buf (unchecked-short (or orig-dst-port 0)))
    (.putShort buf (short 0))  ; padding
    (.putInt buf (unchecked-int (or nat-dst-ip 0)))
    (.putShort buf (unchecked-short (or nat-dst-port 0)))
    (.putShort buf (short 0))  ; padding
    ;; Counters in native order (written by XDP/TC directly)
    (.order buf (ByteOrder/nativeOrder))
    (.putLong buf (or created-ns 0))
    (.putLong buf (or last-seen 0))
    (.putLong buf (or packets-fwd 0))
    (.putLong buf (or packets-rev 0))
    (.putLong buf (or bytes-fwd 0))
    (.putLong buf (or bytes-rev 0))
    (.array buf)))

(defn decode-conntrack-value
  "Decode connection tracking value from byte array (64 bytes)."
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    ;; IPs and ports in network byte order
    (.order buf ByteOrder/BIG_ENDIAN)
    (let [orig-dst-ip (Integer/toUnsignedLong (.getInt buf))
          orig-dst-port (bit-and (.getShort buf) 0xFFFF)
          _ (.getShort buf)  ; padding
          nat-dst-ip (Integer/toUnsignedLong (.getInt buf))
          nat-dst-port (bit-and (.getShort buf) 0xFFFF)
          _ (.getShort buf)]  ; padding
      ;; Counters in native order
      (.order buf (ByteOrder/nativeOrder))
      (let [created-ns (.getLong buf)
            last-seen (.getLong buf)
            packets-fwd (.getLong buf)
            packets-rev (.getLong buf)
            bytes-fwd (.getLong buf)
            bytes-rev (.getLong buf)]
        {:orig-dst-ip orig-dst-ip
         :orig-dst-port orig-dst-port
         :nat-dst-ip nat-dst-ip
         :nat-dst-port nat-dst-port
         :created-ns created-ns
         :last-seen last-seen
         :packets-fwd packets-fwd
         :packets-rev packets-rev
         :bytes-fwd bytes-fwd
         :bytes-rev bytes-rev}))))

(defn encode-stats-event
  "Encode a stats event for ring buffer.
   {event_type (1) + padding (3) + timestamp (8) + src_ip (4) + dst_ip (4) +
    src_port (2) + dst_port (2) + target_ip (4) + target_port (2) + padding (2) +
    packets_fwd (8) + bytes_fwd (8) + packets_rev (8) + bytes_rev (8)}
   Total: 64 bytes."
  [{:keys [event-type timestamp src-ip dst-ip src-port dst-port
           target-ip target-port packets-fwd bytes-fwd packets-rev bytes-rev]}]
  (let [buf (ByteBuffer/allocate 64)
        event-code (case event-type
                     :new-conn 1
                     :conn-closed 2
                     :periodic-stats 3
                     0)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (.put buf (unchecked-byte event-code))
    (.put buf (byte 0))
    (.putShort buf (short 0))  ; padding
    (.putLong buf (or timestamp 0))
    (.putInt buf (unchecked-int (or src-ip 0)))
    (.putInt buf (unchecked-int (or dst-ip 0)))
    (.putShort buf (unchecked-short (or src-port 0)))
    (.putShort buf (unchecked-short (or dst-port 0)))
    (.putInt buf (unchecked-int (or target-ip 0)))
    (.putShort buf (unchecked-short (or target-port 0)))
    (.putShort buf (short 0))  ; padding
    (.putLong buf (or packets-fwd 0))
    (.putLong buf (or bytes-fwd 0))
    (.putLong buf (or packets-rev 0))
    (.putLong buf (or bytes-rev 0))
    (.array buf)))

(defn decode-stats-event
  "Decode stats event from ring buffer."
  [^bytes b]
  (let [buf (ByteBuffer/wrap b)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (let [event-code (bit-and (.get buf) 0xFF)
          _ (.get buf)  ; padding
          _ (.getShort buf)  ; padding
          timestamp (.getLong buf)
          src-ip (Integer/toUnsignedLong (.getInt buf))
          dst-ip (Integer/toUnsignedLong (.getInt buf))
          src-port (bit-and (.getShort buf) 0xFFFF)
          dst-port (bit-and (.getShort buf) 0xFFFF)
          target-ip (Integer/toUnsignedLong (.getInt buf))
          target-port (bit-and (.getShort buf) 0xFFFF)
          _ (.getShort buf)  ; padding
          packets-fwd (.getLong buf)
          bytes-fwd (.getLong buf)
          packets-rev (.getLong buf)
          bytes-rev (.getLong buf)]
      {:event-type (case event-code
                     1 :new-conn
                     2 :conn-closed
                     3 :periodic-stats
                     :unknown)
       :timestamp timestamp
       :src-ip src-ip
       :dst-ip dst-ip
       :src-port src-port
       :dst-port dst-port
       :target-ip target-ip
       :target-port target-port
       :packets-fwd packets-fwd
       :bytes-fwd bytes-fwd
       :packets-rev packets-rev
       :bytes-rev bytes-rev})))

;;; =============================================================================
;;; Network Interface Utilities
;;; =============================================================================

(defn get-interface-index
  "Get interface index by name using /sys/class/net.
   Returns nil if interface not found."
  [iface-name]
  (try
    (let [path (str "/sys/class/net/" iface-name "/ifindex")]
      (Integer/parseInt (str/trim (slurp path))))
    (catch Exception _
      nil)))

(defn list-interfaces
  "List all network interface names."
  []
  (try
    (let [net-dir (java.io.File. "/sys/class/net")]
      (when (.isDirectory net-dir)
        (vec (.list net-dir))))
    (catch Exception _
      [])))

;;; =============================================================================
;;; Protocol Constants
;;; =============================================================================

(def ETH-P-IP 0x0800)
(def ETH-P-IPV6 0x86DD)
(def ETH-P-ARP 0x0806)

(def IPPROTO-ICMP 1)
(def IPPROTO-TCP 6)
(def IPPROTO-UDP 17)
(def IPPROTO-ICMPV6 58)

(def ETH-HLEN 14)
(def IP-HLEN-MIN 20)
(def IPV6-HLEN 40)
(def TCP-HLEN-MIN 20)
(def UDP-HLEN 8)

;; XDP return codes
(def XDP-ABORTED 0)
(def XDP-DROP 1)
(def XDP-PASS 2)
(def XDP-TX 3)
(def XDP-REDIRECT 4)

;; TC return codes
(def TC-ACT-OK 0)
(def TC-ACT-SHOT 2)
(def TC-ACT-REDIRECT 7)
