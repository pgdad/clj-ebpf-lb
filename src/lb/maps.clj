(ns lb.maps
  "eBPF map management for the load balancer.
   Provides functions to create, operate on, and close all required maps."
  (:require [clj-ebpf.core :as bpf]
            [lb.util :as util]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Map Configuration Constants
;;; =============================================================================

(def default-config
  "Default configuration for map creation."
  {:max-routes 10000           ; Maximum source routes (LPM entries)
   :max-listen-ports 256       ; Maximum listen port configurations
   :max-connections 100000     ; Maximum concurrent connections
   :max-sni-routes 1000        ; Maximum SNI-based routes
   :max-rate-limit-src 65536   ; Maximum tracked source IPs for rate limiting
   :max-rate-limit-backend 1024 ; Maximum tracked backends for rate limiting
   :ringbuf-size (* 256 1024)  ; 256KB ring buffer for stats
   :settings-entries 16})      ; Number of settings slots

;;; =============================================================================
;;; Map Creation
;;; =============================================================================

(defn create-config-map
  "Create LPM trie map for source IP -> target routing with weighted load balancing.
   Key: {prefix_len (4 bytes) + ip (4 bytes)} = 8 bytes
   Value: Weighted route format (72 bytes):
     Header (8 bytes): target_count(1) + reserved(3) + flags(2) + reserved(2)
     Per target (8 bytes each, max 8): ip(4) + port(2) + cumulative_weight(2)"
  [{:keys [max-routes] :or {max-routes (:max-routes default-config)}}]
  (log/info "Creating config LPM trie map with max-entries:" max-routes)
  ;; Use create-map directly to get identity serializers for byte arrays
  (bpf/create-map {:map-type :lpm-trie
                   :key-size 8
                   :value-size util/WEIGHTED-ROUTE-MAX-SIZE  ; 72 bytes
                   :max-entries max-routes
                   :map-flags 1  ; BPF_F_NO_PREALLOC required for LPM
                   :map-name "proxy_config"}))

(defn create-listen-map
  "Create hash map for listen interface/port -> default target with weighted load balancing.
   Key: {ifindex (4 bytes) + port (2 bytes) + padding (2 bytes)} = 8 bytes
   Value: Weighted route format (72 bytes):
     Header (8 bytes): target_count(1) + reserved(3) + flags(2) + reserved(2)
     Per target (8 bytes each, max 8): ip(4) + port(2) + cumulative_weight(2)"
  [{:keys [max-listen-ports] :or {max-listen-ports (:max-listen-ports default-config)}}]
  (log/info "Creating listen hash map with max-entries:" max-listen-ports)
  ;; Use create-map directly to get identity serializers for byte arrays
  (bpf/create-map {:map-type :hash
                   :key-size 8
                   :value-size util/WEIGHTED-ROUTE-MAX-SIZE  ; 72 bytes
                   :max-entries max-listen-ports
                   :map-name "proxy_listen"}))

(defn create-conntrack-map
  "Create per-CPU hash map for connection tracking.
   Using per-CPU variant for lock-free concurrent access.
   Key: 5-tuple (16 bytes aligned)
   Value: conntrack state (128 bytes):
     Bytes 0-63: NAT and stats fields
       orig_dst_ip(4) + orig_dst_port(2) + pad(2) + nat_dst_ip(4) + nat_dst_port(2) + pad(2) +
       created_ns(8) + last_seen_ns(8) + packets_fwd(8) + packets_rev(8) + bytes_fwd(8) + bytes_rev(8)
     Bytes 64-95: Reserved for unified format compatibility
     Bytes 96-127: PROXY protocol fields
       conn_state(1) + proxy_flags(1) + pad(2) + seq_offset(4) +
       orig_client_ip(16) + orig_client_port(2) + pad(6)

   Note: XDP program only writes first 64 bytes; TC ingress reads PROXY fields at offset 96+."
  [{:keys [max-connections] :or {max-connections (:max-connections default-config)}}]
  (log/info "Creating conntrack per-CPU hash map with max-entries:" max-connections)
  ;; Use create-map directly to get identity serializers for byte arrays
  ;; Note: For per-CPU maps, the actual value size is value-size * num-cpus
  ;; Value size is 128 bytes to support PROXY protocol fields accessed by TC ingress
  (bpf/create-map {:map-type :percpu-hash
                   :key-size 16
                   :value-size 128
                   :max-entries max-connections
                   :map-name "proxy_conntrack"}))

(defn create-settings-map
  "Create array map for global settings.
   Index 0: stats enabled (0/1)
   Index 1: connection timeout (seconds)
   Index 2: reserved
   ...
   Note: Using default 4-byte values since clj-ebpf array maps
   use integer serializers."
  [{:keys [settings-entries] :or {settings-entries (:settings-entries default-config)}}]
  (log/info "Creating settings array map with" settings-entries "entries")
  (bpf/create-array-map settings-entries
    :map-name "proxy_settings"))

(defn create-stats-ringbuf
  "Create ring buffer for streaming statistics events.
   Size must be a power of 2."
  [{:keys [ringbuf-size] :or {ringbuf-size (:ringbuf-size default-config)}}]
  (log/info "Creating stats ring buffer with size:" ringbuf-size)
  (bpf/create-map {:map-type :ringbuf
                   :key-size 0
                   :value-size 0
                   :max-entries ringbuf-size
                   :map-name "proxy_stats"}))

(defn create-sni-map
  "Create hash map for TLS SNI hostname -> target routing with weighted load balancing.
   Key: hostname_hash (8 bytes) - FNV-1a 64-bit hash of lowercase hostname
   Value: Weighted route format (72 bytes):
     Header (8 bytes): target_count(1) + reserved(3) + flags(2) + reserved(2)
     Per target (8 bytes each, max 8): ip(4) + port(2) + cumulative_weight(2)"
  [{:keys [max-sni-routes] :or {max-sni-routes (:max-sni-routes default-config)}}]
  (log/info "Creating SNI hash map with max-entries:" max-sni-routes)
  (bpf/create-map {:map-type :hash
                   :key-size util/SNI-KEY-SIZE  ; 8 bytes
                   :value-size util/WEIGHTED-ROUTE-MAX-SIZE  ; 72 bytes
                   :max-entries max-sni-routes
                   :map-name "proxy_sni"}))

;;; =============================================================================
;;; Rate Limit Maps
;;; =============================================================================

;; Rate limit bucket structure (16 bytes):
;;   tokens (8 bytes) - current token count (scaled by 1000)
;;   last_update (8 bytes) - last update timestamp in nanoseconds
(def ^:const RATE-BUCKET-SIZE 16)

;; Rate limit config structure (16 bytes):
;;   rate (8 bytes) - tokens per second (scaled by 1000)
;;   burst (8 bytes) - max tokens (scaled by 1000)
(def ^:const RATE-CONFIG-SIZE 16)

;; Config map indices
(def ^:const RATE-LIMIT-CONFIG-SRC 0)
(def ^:const RATE-LIMIT-CONFIG-BACKEND 1)

(defn create-rate-limit-config-map
  "Create array map for rate limit configuration.
   Index 0: per-source rate limit config
   Index 1: per-backend rate limit config
   Each entry is 16 bytes: rate(8) + burst(8)"
  [_opts]
  (log/info "Creating rate limit config array map")
  (bpf/create-map {:map-type :array
                   :key-size 4
                   :value-size RATE-CONFIG-SIZE
                   :max-entries 2
                   :map-name "rate_limit_config"}))

(defn create-rate-limit-src-map
  "Create LRU per-CPU hash map for per-source IP rate limiting.
   Key: source IP (4 bytes)
   Value: rate bucket (16 bytes): tokens(8) + last_update(8)
   Using LRU for automatic eviction of stale entries."
  [{:keys [max-rate-limit-src] :or {max-rate-limit-src (:max-rate-limit-src default-config)}}]
  (log/info "Creating rate limit source LRU map with max-entries:" max-rate-limit-src)
  (bpf/create-map {:map-type :lru-percpu-hash
                   :key-size 4
                   :value-size RATE-BUCKET-SIZE
                   :max-entries max-rate-limit-src
                   :map-name "rate_limit_src"}))

(defn create-rate-limit-backend-map
  "Create LRU per-CPU hash map for per-backend rate limiting.
   Key: backend IP:port (8 bytes): ip(4) + port(2) + pad(2)
   Value: rate bucket (16 bytes): tokens(8) + last_update(8)
   Using LRU for automatic eviction of stale entries."
  [{:keys [max-rate-limit-backend] :or {max-rate-limit-backend (:max-rate-limit-backend default-config)}}]
  (log/info "Creating rate limit backend LRU map with max-entries:" max-rate-limit-backend)
  (bpf/create-map {:map-type :lru-percpu-hash
                   :key-size 8
                   :value-size RATE-BUCKET-SIZE
                   :max-entries max-rate-limit-backend
                   :map-name "rate_limit_backend"}))

;;; =============================================================================
;;; Unified Map Creation (IPv4/IPv6 Support)
;;; =============================================================================

(defn create-config-map-unified
  "Create unified LPM trie map for source IP -> target routing (IPv4/IPv6).
   Key: {prefix_len (4 bytes) + ip (16 bytes)} = 20 bytes
   Value: Unified weighted route format (168 bytes):
     Header (8 bytes): target_count(1) + reserved(3) + flags(2) + reserved(2)
     Per target (20 bytes each, max 8): ip(16) + port(2) + cumulative_weight(2)"
  [{:keys [max-routes] :or {max-routes (:max-routes default-config)}}]
  (log/info "Creating unified config LPM trie map with max-entries:" max-routes)
  (bpf/create-map {:map-type :lpm-trie
                   :key-size util/LPM-KEY-UNIFIED-SIZE  ; 20 bytes
                   :value-size util/WEIGHTED-ROUTE-UNIFIED-MAX-SIZE  ; 168 bytes
                   :max-entries max-routes
                   :map-flags 1  ; BPF_F_NO_PREALLOC required for LPM
                   :map-name "proxy_config_v6"}))

(defn create-listen-map-unified
  "Create unified hash map for listen interface/port -> default target (IPv4/IPv6).
   Key: {ifindex (4 bytes) + port (2 bytes) + af (1 byte) + pad (1 byte)} = 8 bytes
   Value: Unified weighted route format (168 bytes)"
  [{:keys [max-listen-ports] :or {max-listen-ports (:max-listen-ports default-config)}}]
  (log/info "Creating unified listen hash map with max-entries:" max-listen-ports)
  (bpf/create-map {:map-type :hash
                   :key-size util/LISTEN-KEY-UNIFIED-SIZE  ; 8 bytes
                   :value-size util/WEIGHTED-ROUTE-UNIFIED-MAX-SIZE  ; 168 bytes
                   :max-entries max-listen-ports
                   :map-name "proxy_listen_v6"}))

(defn create-conntrack-map-unified
  "Create unified per-CPU hash map for connection tracking (IPv4/IPv6).
   Key: 5-tuple (40 bytes): src_ip(16) + dst_ip(16) + ports(4) + proto(1) + pad(3)
   Value: conntrack state (96 bytes):
     orig_dst_ip(16) + orig_dst_port(2) + pad(2) + nat_dst_ip(16) + nat_dst_port(2) + pad(2) +
     created_ns(8) + last_seen_ns(8) + packets_fwd(8) + packets_rev(8) + bytes_fwd(8) + bytes_rev(8)"
  [{:keys [max-connections] :or {max-connections (:max-connections default-config)}}]
  (log/info "Creating unified conntrack per-CPU hash map with max-entries:" max-connections)
  (bpf/create-map {:map-type :percpu-hash
                   :key-size util/CONNTRACK-KEY-UNIFIED-SIZE  ; 40 bytes
                   :value-size util/CONNTRACK-VALUE-UNIFIED-SIZE  ; 96 bytes
                   :max-entries max-connections
                   :map-name "proxy_conntrack_v6"}))

(defn create-sni-map-unified
  "Create unified hash map for TLS SNI hostname -> target routing (IPv4/IPv6).
   Key: hostname_hash (8 bytes) - FNV-1a 64-bit hash of lowercase hostname
   Value: Unified weighted route format (168 bytes)"
  [{:keys [max-sni-routes] :or {max-sni-routes (:max-sni-routes default-config)}}]
  (log/info "Creating unified SNI hash map with max-entries:" max-sni-routes)
  (bpf/create-map {:map-type :hash
                   :key-size util/SNI-KEY-SIZE  ; 8 bytes (same as before)
                   :value-size util/WEIGHTED-ROUTE-UNIFIED-MAX-SIZE  ; 168 bytes
                   :max-entries max-sni-routes
                   :map-name "proxy_sni_v6"}))

(defn create-rate-limit-src-map-unified
  "Create unified LRU per-CPU hash map for per-source IP rate limiting (IPv4/IPv6).
   Key: source IP (16 bytes)
   Value: rate bucket (16 bytes): tokens(8) + last_update(8)"
  [{:keys [max-rate-limit-src] :or {max-rate-limit-src (:max-rate-limit-src default-config)}}]
  (log/info "Creating unified rate limit source LRU map with max-entries:" max-rate-limit-src)
  (bpf/create-map {:map-type :lru-percpu-hash
                   :key-size 16  ; 16-byte unified IP
                   :value-size RATE-BUCKET-SIZE
                   :max-entries max-rate-limit-src
                   :map-name "rate_limit_src_v6"}))

(defn create-rate-limit-backend-map-unified
  "Create unified LRU per-CPU hash map for per-backend rate limiting (IPv4/IPv6).
   Key: backend IP:port (20 bytes): ip(16) + port(2) + pad(2)
   Value: rate bucket (16 bytes): tokens(8) + last_update(8)"
  [{:keys [max-rate-limit-backend] :or {max-rate-limit-backend (:max-rate-limit-backend default-config)}}]
  (log/info "Creating unified rate limit backend LRU map with max-entries:" max-rate-limit-backend)
  (bpf/create-map {:map-type :lru-percpu-hash
                   :key-size 20  ; ip(16) + port(2) + pad(2)
                   :value-size RATE-BUCKET-SIZE
                   :max-entries max-rate-limit-backend
                   :map-name "rate_limit_backend_v6"}))

(defn create-all-maps-unified
  "Create all unified maps for IPv4/IPv6 dual-stack support.
   Returns a map of {:config-map :listen-map :sni-map :conntrack-map :settings-map
                     :stats-ringbuf :rate-limit-config-map :rate-limit-src-map
                     :rate-limit-backend-map}"
  ([]
   (create-all-maps-unified {}))
  ([opts]
   (let [config (merge default-config opts)]
     {:config-map (create-config-map-unified config)
      :listen-map (create-listen-map-unified config)
      :sni-map (create-sni-map-unified config)
      :conntrack-map (create-conntrack-map-unified config)
      :settings-map (create-settings-map config)  ; Same as before
      :stats-ringbuf (create-stats-ringbuf config)  ; Same as before
      :rate-limit-config-map (create-rate-limit-config-map config)  ; Same as before
      :rate-limit-src-map (create-rate-limit-src-map-unified config)
      :rate-limit-backend-map (create-rate-limit-backend-map-unified config)})))

(defn create-all-maps
  "Create all maps required for the reverse proxy.
   Returns a map of {:config-map :listen-map :sni-map :conntrack-map :settings-map
                     :stats-ringbuf :rate-limit-config-map :rate-limit-src-map
                     :rate-limit-backend-map}"
  ([]
   (create-all-maps {}))
  ([opts]
   (let [config (merge default-config opts)]
     {:config-map (create-config-map config)
      :listen-map (create-listen-map config)
      :sni-map (create-sni-map config)
      :conntrack-map (create-conntrack-map config)
      :settings-map (create-settings-map config)
      :stats-ringbuf (create-stats-ringbuf config)
      :rate-limit-config-map (create-rate-limit-config-map config)
      :rate-limit-src-map (create-rate-limit-src-map config)
      :rate-limit-backend-map (create-rate-limit-backend-map config)})))

(defn close-all-maps
  "Close all maps and release resources."
  [{:keys [config-map listen-map sni-map conntrack-map settings-map stats-ringbuf
           rate-limit-config-map rate-limit-src-map rate-limit-backend-map]}]
  (log/info "Closing all eBPF maps")
  (when config-map (bpf/close-map config-map))
  (when listen-map (bpf/close-map listen-map))
  (when sni-map (bpf/close-map sni-map))
  (when conntrack-map (bpf/close-map conntrack-map))
  (when settings-map (bpf/close-map settings-map))
  (when stats-ringbuf (bpf/close-map stats-ringbuf))
  (when rate-limit-config-map (bpf/close-map rate-limit-config-map))
  (when rate-limit-src-map (bpf/close-map rate-limit-src-map))
  (when rate-limit-backend-map (bpf/close-map rate-limit-backend-map)))

;;; =============================================================================
;;; Config Map Operations (LPM Trie - Source Routing)
;;; =============================================================================

(defn add-source-route
  "Add a source IP/CIDR route to the config map.
   DEPRECATED: Use add-source-route-weighted for weighted load balancing.
   source: {:ip <u32> :prefix-len <int>}
   target: {:ip <u32> :port <int>}
   flags: optional flags (default 1 = enabled)"
  [config-map {:keys [ip prefix-len]} {:keys [ip port] :as target} & {:keys [flags] :or {flags 1}}]
  ;; Convert single target to weighted format for compatibility
  (let [target-group {:targets [{:ip (:ip target) :port port :weight 100}]
                      :cumulative-weights [100]}
        key-bytes (util/encode-lpm-key prefix-len ip)
        value-bytes (util/encode-weighted-route-value target-group flags)]
    (log/debug "Adding source route:" (util/u32->ip-string ip) "/" prefix-len
               "-> " (util/u32->ip-string (:ip target)) ":" port)
    (bpf/map-update config-map key-bytes value-bytes)))

(defn add-source-route-weighted
  "Add a source IP/CIDR route with weighted targets to the config map.
   source: {:ip <u32> :prefix-len <int>}
   target-group: TargetGroup record with :targets and :cumulative-weights
   flags: optional flags (default 1 = enabled)
   session-persistence: if true, enables sticky sessions based on source IP hash"
  [config-map {:keys [ip prefix-len]} target-group & {:keys [flags session-persistence] :or {flags 1}}]
  (let [effective-flags (cond-> flags
                          session-persistence (bit-or util/FLAG-SESSION-PERSISTENCE))
        key-bytes (util/encode-lpm-key prefix-len ip)
        value-bytes (util/encode-weighted-route-value target-group effective-flags)
        targets (:targets target-group)]
    (log/debug "Adding weighted source route:" (util/u32->ip-string ip) "/" prefix-len
               "->" (count targets) "targets"
               (when session-persistence "(session-persistence)"))
    (bpf/map-update config-map key-bytes value-bytes)))

(defn remove-source-route
  "Remove a source IP/CIDR route from the config map."
  [config-map {:keys [ip prefix-len]}]
  (let [key-bytes (util/encode-lpm-key prefix-len ip)]
    (log/debug "Removing source route:" (util/u32->ip-string ip) "/" prefix-len)
    (bpf/map-delete config-map key-bytes)))

(defn lookup-source-route
  "Look up a source IP in the config map (exact match on prefix-len + IP).
   Returns weighted route data with :target-count, :flags, and :targets."
  [config-map {:keys [ip prefix-len]}]
  (let [key-bytes (util/encode-lpm-key prefix-len ip)]
    (when-let [value-bytes (bpf/map-lookup config-map key-bytes)]
      (util/decode-weighted-route-value value-bytes))))

(defn list-source-routes
  "List all source routes in the config map.
   Returns a sequence of {:source {...} :route {...}} maps with weighted target data."
  [config-map]
  (->> (bpf/map-entries config-map)
       (map (fn [[k v]]
              {:source (util/decode-lpm-key k)
               :route (util/decode-weighted-route-value v)}))))

;;; =============================================================================
;;; Listen Map Operations (Hash - Listen Port Config)
;;; =============================================================================

(defn add-listen-port
  "Configure a listen interface/port with its default target.
   DEPRECATED: Use add-listen-port-weighted for weighted load balancing.
   ifindex: network interface index
   listen-port: listen port number
   target: {:ip <u32> :port <int>}
   flags: bit flags (bit 0 = stats enabled)"
  [listen-map ifindex listen-port {:keys [ip port] :as target} & {:keys [flags] :or {flags 0}}]
  ;; Convert single target to weighted format for compatibility
  (let [target-group {:targets [{:ip ip :port port :weight 100}]
                      :cumulative-weights [100]}
        key-bytes (util/encode-listen-key ifindex listen-port)
        value-bytes (util/encode-weighted-route-value target-group flags)]
    (log/debug "Adding listen port: ifindex=" ifindex "port=" listen-port
               "-> " (util/u32->ip-string ip) ":" port)
    (bpf/map-update listen-map key-bytes value-bytes)))

(defn add-listen-port-weighted
  "Configure a listen interface/port with weighted targets.
   ifindex: network interface index
   listen-port: listen port number
   target-group: TargetGroup record with :targets and :cumulative-weights
   flags: bit flags (bit 0 = stats enabled)
   session-persistence: if true, enables sticky sessions based on source IP hash"
  [listen-map ifindex listen-port target-group & {:keys [flags session-persistence] :or {flags 0}}]
  (let [effective-flags (cond-> flags
                          session-persistence (bit-or util/FLAG-SESSION-PERSISTENCE))
        key-bytes (util/encode-listen-key ifindex listen-port)
        value-bytes (util/encode-weighted-route-value target-group effective-flags)
        targets (:targets target-group)]
    (log/debug "Adding weighted listen port: ifindex=" ifindex "port=" listen-port
               "->" (count targets) "targets"
               (when session-persistence "(session-persistence)"))
    (bpf/map-update listen-map key-bytes value-bytes)))

(defn remove-listen-port
  "Remove a listen interface/port configuration."
  [listen-map ifindex port]
  (let [key-bytes (util/encode-listen-key ifindex port)]
    (log/debug "Removing listen port: ifindex=" ifindex "port=" port)
    (bpf/map-delete listen-map key-bytes)))

(defn lookup-listen-port
  "Look up configuration for a listen interface/port.
   Returns weighted route data with :target-count, :flags, and :targets."
  [listen-map ifindex port]
  (let [key-bytes (util/encode-listen-key ifindex port)]
    (when-let [value-bytes (bpf/map-lookup listen-map key-bytes)]
      (util/decode-weighted-route-value value-bytes))))

(defn list-listen-ports
  "List all configured listen ports.
   Returns a sequence of {:listen {...} :route {...}} maps with weighted target data."
  [listen-map]
  (->> (bpf/map-entries listen-map)
       (map (fn [[k v]]
              {:listen (util/decode-listen-key k)
               :route (util/decode-weighted-route-value v)}))))

;;; =============================================================================
;;; SNI Map Operations (Hash - TLS SNI-based Routing)
;;; =============================================================================

(defn add-sni-route
  "Add an SNI hostname route with weighted targets to the SNI map.
   hostname: TLS SNI hostname (will be lowercased)
   target-group: TargetGroup record with :targets and :cumulative-weights
   flags: optional flags (default 1 = enabled)
   session-persistence: if true, enables sticky sessions based on source IP hash"
  [sni-map hostname target-group & {:keys [flags session-persistence] :or {flags 1}}]
  (let [effective-flags (cond-> flags
                          session-persistence (bit-or util/FLAG-SESSION-PERSISTENCE))
        normalized-hostname (clojure.string/lower-case hostname)
        hostname-hash (util/hostname->hash normalized-hostname)
        key-bytes (util/encode-sni-key hostname-hash)
        value-bytes (util/encode-weighted-route-value target-group effective-flags)
        targets (:targets target-group)]
    (log/debug "Adding SNI route:" normalized-hostname
               "(hash:" hostname-hash ")->" (count targets) "targets"
               (when session-persistence "(session-persistence)"))
    (bpf/map-update sni-map key-bytes value-bytes)))

(defn remove-sni-route
  "Remove an SNI hostname route from the SNI map."
  [sni-map hostname]
  (let [normalized-hostname (clojure.string/lower-case hostname)
        hostname-hash (util/hostname->hash normalized-hostname)
        key-bytes (util/encode-sni-key hostname-hash)]
    (log/debug "Removing SNI route:" normalized-hostname)
    (bpf/map-delete sni-map key-bytes)))

(defn lookup-sni-route
  "Look up an SNI hostname in the SNI map.
   Returns weighted route data with :target-count, :flags, and :targets."
  [sni-map hostname]
  (let [normalized-hostname (clojure.string/lower-case hostname)
        hostname-hash (util/hostname->hash normalized-hostname)
        key-bytes (util/encode-sni-key hostname-hash)]
    (when-let [value-bytes (bpf/map-lookup sni-map key-bytes)]
      (util/decode-weighted-route-value value-bytes))))

(defn list-sni-routes
  "List all SNI routes in the SNI map.
   Returns a sequence of {:hostname-hash <long> :route {...}} maps.
   Note: Original hostnames are not stored in the map, only their hashes."
  [sni-map]
  (->> (bpf/map-entries sni-map)
       (map (fn [[k v]]
              {:hostname-hash (:hostname-hash (util/decode-sni-key k))
               :route (util/decode-weighted-route-value v)}))))

;;; =============================================================================
;;; Connection Tracking Map Operations
;;; =============================================================================

(defn lookup-connection
  "Look up a connection by its 5-tuple."
  [conntrack-map five-tuple]
  (let [key-bytes (util/encode-conntrack-key five-tuple)]
    (when-let [values (bpf/map-lookup conntrack-map key-bytes)]
      ;; Per-CPU map returns a vector of values, one per CPU
      ;; Aggregate them
      (if (vector? values)
        (reduce (fn [acc v]
                  (let [decoded (util/decode-conntrack-value v)]
                    {:orig-dst-ip (:orig-dst-ip decoded)
                     :orig-dst-port (:orig-dst-port decoded)
                     :nat-dst-ip (:nat-dst-ip decoded)
                     :nat-dst-port (:nat-dst-port decoded)
                     :last-seen (max (:last-seen acc) (:last-seen decoded))
                     :packets-fwd (+ (:packets-fwd acc) (:packets-fwd decoded))
                     :bytes-fwd (+ (:bytes-fwd acc) (:bytes-fwd decoded))
                     :packets-rev (+ (:packets-rev acc) (:packets-rev decoded))
                     :bytes-rev (+ (:bytes-rev acc) (:bytes-rev decoded))}))
                {:last-seen 0 :packets-fwd 0 :bytes-fwd 0 :packets-rev 0 :bytes-rev 0}
                values)
        (util/decode-conntrack-value values)))))

(defn delete-connection
  "Delete a connection from the tracking map."
  [conntrack-map five-tuple]
  (let [key-bytes (util/encode-conntrack-key five-tuple)]
    (bpf/map-delete conntrack-map key-bytes)))

(defn insert-connection
  "Insert or update a connection in the tracking map.
   Used for cluster failover - promotes shadow connections to active.

   five-tuple: {:src-ip :dst-ip :src-port :dst-port :protocol}
   value: {:orig-dst-ip :orig-dst-port :nat-dst-ip :nat-dst-port
           :created-ns :last-seen :packets-fwd :packets-rev :bytes-fwd :bytes-rev}"
  [conntrack-map five-tuple value]
  (let [key-bytes (util/encode-conntrack-key five-tuple)
        value-bytes (util/encode-conntrack-value value)]
    (bpf/map-update conntrack-map key-bytes value-bytes)))

(defn list-connections
  "List all active connections."
  [conntrack-map]
  (->> (bpf/map-entries conntrack-map)
       (map (fn [[k v]]
              {:key (util/decode-conntrack-key k)
               :value (if (vector? v)
                        ;; Per-CPU: aggregate
                        (reduce (fn [acc val-bytes]
                                  (let [d (util/decode-conntrack-value val-bytes)]
                                    (-> acc
                                        (update :packets-fwd + (:packets-fwd d))
                                        (update :bytes-fwd + (:bytes-fwd d))
                                        (update :packets-rev + (:packets-rev d))
                                        (update :bytes-rev + (:bytes-rev d))
                                        (update :last-seen max (:last-seen d)))))
                                {:orig-dst-ip 0 :orig-dst-port 0
                                 :nat-dst-ip 0 :nat-dst-port 0
                                 :last-seen 0 :packets-fwd 0 :bytes-fwd 0
                                 :packets-rev 0 :bytes-rev 0}
                                v)
                        (util/decode-conntrack-value v))}))))

(defn clear-stale-connections
  "Remove connections that haven't been seen within the timeout period.
   timeout-ns: timeout in nanoseconds"
  [conntrack-map current-time-ns timeout-ns]
  (let [cutoff (- current-time-ns timeout-ns)
        stale (->> (list-connections conntrack-map)
                   (filter #(< (get-in % [:value :last-seen]) cutoff))
                   (map :key))]
    (doseq [key stale]
      (delete-connection conntrack-map key))
    (count stale)))

;;; =============================================================================
;;; Settings Map Operations
;;; =============================================================================

(def ^:const SETTING-STATS-ENABLED 0)
(def ^:const SETTING-CONN-TIMEOUT 1)
(def ^:const SETTING-MAX-CONNS 2)

;; Note: clj-ebpf array maps use integer serializers by default,
;; so we pass integers directly rather than byte arrays.

(defn set-setting
  "Set a global setting by index."
  [settings-map index value]
  ;; clj-ebpf array maps expect integers for key and value
  (bpf/map-update settings-map index (int value)))

(defn get-setting
  "Get a global setting by index."
  [settings-map index]
  ;; clj-ebpf array maps return integers
  (bpf/map-lookup settings-map index))

(defn enable-stats
  "Enable statistics collection in eBPF program."
  [settings-map]
  (log/info "Enabling statistics collection")
  (set-setting settings-map SETTING-STATS-ENABLED 1))

(defn disable-stats
  "Disable statistics collection in eBPF program."
  [settings-map]
  (log/info "Disabling statistics collection")
  (set-setting settings-map SETTING-STATS-ENABLED 0))

(defn stats-enabled?
  "Check if statistics collection is enabled."
  [settings-map]
  (= 1 (get-setting settings-map SETTING-STATS-ENABLED)))

(defn set-connection-timeout
  "Set connection timeout in seconds."
  [settings-map timeout-seconds]
  (log/info "Setting connection timeout to" timeout-seconds "seconds")
  (set-setting settings-map SETTING-CONN-TIMEOUT timeout-seconds))

(defn get-connection-timeout
  "Get connection timeout in seconds."
  [settings-map]
  (get-setting settings-map SETTING-CONN-TIMEOUT))

;;; =============================================================================
;;; Map File Descriptor Access
;;; =============================================================================

(defn map-fd
  "Get the raw file descriptor for a map.
   This is needed when building eBPF programs that reference maps."
  [m]
  ;; The actual implementation depends on how clj-ebpf exposes map FDs
  ;; Try different approaches based on what the map object looks like
  (cond
    ;; If it's a number, assume it's already an FD
    (number? m) m
    ;; If it's a map with an :fd key
    (and (map? m) (:fd m)) (:fd m)
    ;; If clj-ebpf provides a get-fd function
    (fn? (resolve 'clj-ebpf.core/get-fd)) ((resolve 'clj-ebpf.core/get-fd) m)
    ;; If the map object has a method to get the fd
    (instance? clojure.lang.ILookup m) (or (:fd m) (:file-descriptor m) m)
    :else (throw (ex-info "Cannot get file descriptor from map" {:map m :type (type m)}))))

;;; =============================================================================
;;; Rate Limit Map Operations
;;; =============================================================================

(def ^:const TOKEN-SCALE 1000)  ; Scale factor for token values (allows sub-token precision)

(defn encode-array-key
  "Encode an array map index as a 4-byte key.
   BPF array maps use u32 keys, which need to be encoded as bytes
   when using byte array values."
  [index]
  (let [buf (java.nio.ByteBuffer/allocate 4)]
    (.order buf java.nio.ByteOrder/LITTLE_ENDIAN)
    (.putInt buf (int index))
    (.array buf)))

(defn encode-rate-config
  "Encode rate limit configuration to bytes.
   rate: tokens per second
   burst: max tokens (burst size)
   Returns 16-byte buffer: rate(8) + burst(8)"
  [rate burst]
  (let [buf (java.nio.ByteBuffer/allocate RATE-CONFIG-SIZE)]
    (.order buf java.nio.ByteOrder/LITTLE_ENDIAN)
    (.putLong buf (* (long rate) TOKEN-SCALE))   ; rate scaled
    (.putLong buf (* (long burst) TOKEN-SCALE))  ; burst scaled
    (.array buf)))

(defn decode-rate-config
  "Decode rate limit configuration from bytes.
   Returns {:rate <tokens/sec> :burst <max-tokens>}"
  [bytes]
  (when bytes
    (let [buf (java.nio.ByteBuffer/wrap bytes)]
      (.order buf java.nio.ByteOrder/LITTLE_ENDIAN)
      {:rate (quot (.getLong buf) TOKEN-SCALE)
       :burst (quot (.getLong buf) TOKEN-SCALE)})))

(defn set-rate-limit-config
  "Set rate limit configuration.
   config-map: the rate_limit_config array map
   limit-type: :source or :backend
   rate: tokens per second
   burst: max tokens (burst size)"
  [config-map limit-type rate burst]
  (let [index (case limit-type
                :source RATE-LIMIT-CONFIG-SRC
                :backend RATE-LIMIT-CONFIG-BACKEND)
        key (encode-array-key index)
        value (encode-rate-config rate burst)]
    (log/info "Setting" (name limit-type) "rate limit: rate=" rate "/sec, burst=" burst)
    (bpf/map-update config-map key value)))

(defn get-rate-limit-config
  "Get rate limit configuration.
   config-map: the rate_limit_config array map
   limit-type: :source or :backend
   Returns {:rate <tokens/sec> :burst <max-tokens>} or nil if not set"
  [config-map limit-type]
  (let [index (case limit-type
                :source RATE-LIMIT-CONFIG-SRC
                :backend RATE-LIMIT-CONFIG-BACKEND)
        key (encode-array-key index)]
    (when-let [bytes (bpf/map-lookup config-map key)]
      (decode-rate-config bytes))))

(defn disable-rate-limit
  "Disable rate limiting by setting rate to 0.
   config-map: the rate_limit_config array map
   limit-type: :source or :backend"
  [config-map limit-type]
  (log/info "Disabling" (name limit-type) "rate limiting")
  (set-rate-limit-config config-map limit-type 0 0))

(defn rate-limit-enabled?
  "Check if rate limiting is enabled for the given type."
  [config-map limit-type]
  (when-let [config (get-rate-limit-config config-map limit-type)]
    (pos? (:rate config))))

;;; =============================================================================
;;; Unified Map Operations (IPv4/IPv6 Support)
;;; =============================================================================

(defn add-source-route-unified
  "Add a source IP/CIDR route with weighted targets to the unified config map.
   source: {:ip <16-byte-array> :prefix-len <int>}
   target-group: TargetGroup record with :targets (having :ip as 16-byte arrays) and :cumulative-weights
   flags: optional flags (default 1 = enabled)
   session-persistence: if true, enables sticky sessions based on source IP hash"
  [config-map {:keys [ip prefix-len]} target-group & {:keys [flags session-persistence] :or {flags 1}}]
  (let [effective-flags (cond-> flags
                          session-persistence (bit-or util/FLAG-SESSION-PERSISTENCE))
        key-bytes (util/encode-lpm-key-unified prefix-len ip)
        value-bytes (util/encode-weighted-route-value-unified target-group effective-flags)
        targets (:targets target-group)]
    (log/debug "Adding unified source route:" (util/bytes16->ip-string ip) "/" prefix-len
               "->" (count targets) "targets"
               (when session-persistence "(session-persistence)"))
    (bpf/map-update config-map key-bytes value-bytes)))

(defn remove-source-route-unified
  "Remove a source IP/CIDR route from the unified config map."
  [config-map {:keys [ip prefix-len]}]
  (let [key-bytes (util/encode-lpm-key-unified prefix-len ip)]
    (log/debug "Removing unified source route:" (util/bytes16->ip-string ip) "/" prefix-len)
    (bpf/map-delete config-map key-bytes)))

(defn lookup-source-route-unified
  "Look up a source IP in the unified config map.
   Returns unified weighted route data with :target-count, :flags, and :targets (with :ip as 16-byte arrays)."
  [config-map {:keys [ip prefix-len]}]
  (let [key-bytes (util/encode-lpm-key-unified prefix-len ip)]
    (when-let [value-bytes (bpf/map-lookup config-map key-bytes)]
      (util/decode-weighted-route-value-unified value-bytes))))

(defn list-source-routes-unified
  "List all source routes in the unified config map.
   Returns a sequence of {:source {...} :route {...}} maps with unified IP addresses."
  [config-map]
  (->> (bpf/map-entries config-map)
       (map (fn [[k v]]
              {:source (util/decode-lpm-key-unified k)
               :route (util/decode-weighted-route-value-unified v)}))))

(defn add-listen-port-unified
  "Configure a listen interface/port with weighted targets for unified maps.
   ifindex: network interface index
   listen-port: listen port number
   af: address family (:ipv4 or :ipv6)
   target-group: TargetGroup record with :targets (having :ip as 16-byte arrays) and :cumulative-weights
   flags: bit flags (bit 0 = stats enabled)
   session-persistence: if true, enables sticky sessions based on source IP hash"
  [listen-map ifindex listen-port af target-group & {:keys [flags session-persistence] :or {flags 0}}]
  (let [effective-flags (cond-> flags
                          session-persistence (bit-or util/FLAG-SESSION-PERSISTENCE))
        key-bytes (util/encode-listen-key-unified ifindex listen-port af)
        value-bytes (util/encode-weighted-route-value-unified target-group effective-flags)
        targets (:targets target-group)]
    (log/debug "Adding unified listen port: ifindex=" ifindex "port=" listen-port "af=" af
               "->" (count targets) "targets"
               (when session-persistence "(session-persistence)"))
    (bpf/map-update listen-map key-bytes value-bytes)))

(defn remove-listen-port-unified
  "Remove a listen interface/port configuration from unified map."
  [listen-map ifindex port af]
  (let [key-bytes (util/encode-listen-key-unified ifindex port af)]
    (log/debug "Removing unified listen port: ifindex=" ifindex "port=" port "af=" af)
    (bpf/map-delete listen-map key-bytes)))

(defn lookup-listen-port-unified
  "Look up configuration for a listen interface/port in unified map.
   Returns unified weighted route data."
  [listen-map ifindex port af]
  (let [key-bytes (util/encode-listen-key-unified ifindex port af)]
    (when-let [value-bytes (bpf/map-lookup listen-map key-bytes)]
      (util/decode-weighted-route-value-unified value-bytes))))

(defn list-listen-ports-unified
  "List all configured listen ports in unified map.
   Returns a sequence of {:listen {...} :route {...}} maps with address family."
  [listen-map]
  (->> (bpf/map-entries listen-map)
       (map (fn [[k v]]
              {:listen (util/decode-listen-key-unified k)
               :route (util/decode-weighted-route-value-unified v)}))))

(defn add-sni-route-unified
  "Add an SNI hostname route with unified weighted targets.
   hostname: TLS SNI hostname (will be lowercased)
   target-group: TargetGroup record with :targets (having :ip as 16-byte arrays) and :cumulative-weights
   flags: optional flags (default 1 = enabled)
   session-persistence: if true, enables sticky sessions based on source IP hash"
  [sni-map hostname target-group & {:keys [flags session-persistence] :or {flags 1}}]
  (let [effective-flags (cond-> flags
                          session-persistence (bit-or util/FLAG-SESSION-PERSISTENCE))
        normalized-hostname (clojure.string/lower-case hostname)
        hostname-hash (util/hostname->hash normalized-hostname)
        key-bytes (util/encode-sni-key hostname-hash)
        value-bytes (util/encode-weighted-route-value-unified target-group effective-flags)
        targets (:targets target-group)]
    (log/debug "Adding unified SNI route:" normalized-hostname
               "(hash:" hostname-hash ")->" (count targets) "targets"
               (when session-persistence "(session-persistence)"))
    (bpf/map-update sni-map key-bytes value-bytes)))

(defn lookup-sni-route-unified
  "Look up an SNI hostname in the unified SNI map.
   Returns unified weighted route data."
  [sni-map hostname]
  (let [normalized-hostname (clojure.string/lower-case hostname)
        hostname-hash (util/hostname->hash normalized-hostname)
        key-bytes (util/encode-sni-key hostname-hash)]
    (when-let [value-bytes (bpf/map-lookup sni-map key-bytes)]
      (util/decode-weighted-route-value-unified value-bytes))))

(defn list-sni-routes-unified
  "List all SNI routes in the unified SNI map.
   Returns a sequence of {:hostname-hash <long> :route {...}} maps."
  [sni-map]
  (->> (bpf/map-entries sni-map)
       (map (fn [[k v]]
              {:hostname-hash (:hostname-hash (util/decode-sni-key k))
               :route (util/decode-weighted-route-value-unified v)}))))

(defn lookup-connection-unified
  "Look up a connection by its unified 5-tuple (with 16-byte IPs)."
  [conntrack-map five-tuple]
  (let [key-bytes (util/encode-conntrack-key-unified five-tuple)]
    (when-let [values (bpf/map-lookup conntrack-map key-bytes)]
      ;; Per-CPU map returns a vector of values, one per CPU
      ;; Aggregate them
      (if (vector? values)
        (let [zero-ip (byte-array 16)]
          (reduce (fn [acc v]
                    (let [decoded (util/decode-conntrack-value-unified v)]
                      {:orig-dst-ip (if (util/bytes16-zero? (:orig-dst-ip decoded))
                                     (:orig-dst-ip acc)
                                     (:orig-dst-ip decoded))
                       :orig-dst-port (max (:orig-dst-port acc) (:orig-dst-port decoded))
                       :nat-dst-ip (if (util/bytes16-zero? (:nat-dst-ip decoded))
                                    (:nat-dst-ip acc)
                                    (:nat-dst-ip decoded))
                       :nat-dst-port (max (:nat-dst-port acc) (:nat-dst-port decoded))
                       :last-seen (max (:last-seen acc) (:last-seen decoded))
                       :packets-fwd (+ (:packets-fwd acc) (:packets-fwd decoded))
                       :bytes-fwd (+ (:bytes-fwd acc) (:bytes-fwd decoded))
                       :packets-rev (+ (:packets-rev acc) (:packets-rev decoded))
                       :bytes-rev (+ (:bytes-rev acc) (:bytes-rev decoded))}))
                  {:orig-dst-ip zero-ip :orig-dst-port 0
                   :nat-dst-ip zero-ip :nat-dst-port 0
                   :last-seen 0 :packets-fwd 0 :bytes-fwd 0 :packets-rev 0 :bytes-rev 0}
                  values))
        (util/decode-conntrack-value-unified values)))))

(defn delete-connection-unified
  "Delete a connection from the unified tracking map."
  [conntrack-map five-tuple]
  (let [key-bytes (util/encode-conntrack-key-unified five-tuple)]
    (bpf/map-delete conntrack-map key-bytes)))

(defn list-connections-unified
  "List all active connections in unified map."
  [conntrack-map]
  (->> (bpf/map-entries conntrack-map)
       (map (fn [[k v]]
              {:key (util/decode-conntrack-key-unified k)
               :value (if (vector? v)
                        ;; Per-CPU: aggregate
                        (let [zero-ip (byte-array 16)]
                          (reduce (fn [acc val-bytes]
                                    (let [d (util/decode-conntrack-value-unified val-bytes)]
                                      (-> acc
                                          (update :packets-fwd + (:packets-fwd d))
                                          (update :bytes-fwd + (:bytes-fwd d))
                                          (update :packets-rev + (:packets-rev d))
                                          (update :bytes-rev + (:bytes-rev d))
                                          (update :last-seen max (:last-seen d))
                                          (assoc :orig-dst-ip (if (util/bytes16-zero? (:orig-dst-ip acc))
                                                                (:orig-dst-ip d)
                                                                (:orig-dst-ip acc)))
                                          (assoc :nat-dst-ip (if (util/bytes16-zero? (:nat-dst-ip acc))
                                                               (:nat-dst-ip d)
                                                               (:nat-dst-ip acc))))))
                                  {:orig-dst-ip zero-ip :orig-dst-port 0
                                   :nat-dst-ip zero-ip :nat-dst-port 0
                                   :last-seen 0 :packets-fwd 0 :bytes-fwd 0
                                   :packets-rev 0 :bytes-rev 0}
                                  v))
                        (util/decode-conntrack-value-unified v))}))))
