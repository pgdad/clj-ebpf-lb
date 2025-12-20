(ns reverse-proxy.maps
  "eBPF map management for the reverse proxy.
   Provides functions to create, operate on, and close all required maps."
  (:require [clj-ebpf.core :as bpf]
            [reverse-proxy.util :as util]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Map Configuration Constants
;;; =============================================================================

(def default-config
  "Default configuration for map creation."
  {:max-routes 10000           ; Maximum source routes (LPM entries)
   :max-listen-ports 256       ; Maximum listen port configurations
   :max-connections 100000     ; Maximum concurrent connections
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
   Value: conntrack state (64 bytes):
     orig_dst_ip(4) + orig_dst_port(2) + pad(2) + nat_dst_ip(4) + nat_dst_port(2) + pad(2) +
     created_ns(8) + last_seen_ns(8) + packets_fwd(8) + packets_rev(8) + bytes_fwd(8) + bytes_rev(8)"
  [{:keys [max-connections] :or {max-connections (:max-connections default-config)}}]
  (log/info "Creating conntrack per-CPU hash map with max-entries:" max-connections)
  ;; Use create-map directly to get identity serializers for byte arrays
  ;; Note: For per-CPU maps, the actual value size is value-size * num-cpus
  (bpf/create-map {:map-type :percpu-hash
                   :key-size 16
                   :value-size 64
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

(defn create-all-maps
  "Create all maps required for the reverse proxy.
   Returns a map of {:config-map :listen-map :conntrack-map :settings-map :stats-ringbuf}"
  ([]
   (create-all-maps {}))
  ([opts]
   (let [config (merge default-config opts)]
     {:config-map (create-config-map config)
      :listen-map (create-listen-map config)
      :conntrack-map (create-conntrack-map config)
      :settings-map (create-settings-map config)
      :stats-ringbuf (create-stats-ringbuf config)})))

(defn close-all-maps
  "Close all maps and release resources."
  [{:keys [config-map listen-map conntrack-map settings-map stats-ringbuf]}]
  (log/info "Closing all eBPF maps")
  (when config-map (bpf/close-map config-map))
  (when listen-map (bpf/close-map listen-map))
  (when conntrack-map (bpf/close-map conntrack-map))
  (when settings-map (bpf/close-map settings-map))
  (when stats-ringbuf (bpf/close-map stats-ringbuf)))

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
   flags: optional flags (default 1 = enabled)"
  [config-map {:keys [ip prefix-len]} target-group & {:keys [flags] :or {flags 1}}]
  (let [key-bytes (util/encode-lpm-key prefix-len ip)
        value-bytes (util/encode-weighted-route-value target-group flags)
        targets (:targets target-group)]
    (log/debug "Adding weighted source route:" (util/u32->ip-string ip) "/" prefix-len
               "->" (count targets) "targets")
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
   flags: bit flags (bit 0 = stats enabled)"
  [listen-map ifindex listen-port target-group & {:keys [flags] :or {flags 0}}]
  (let [key-bytes (util/encode-listen-key ifindex listen-port)
        value-bytes (util/encode-weighted-route-value target-group flags)
        targets (:targets target-group)]
    (log/debug "Adding weighted listen port: ifindex=" ifindex "port=" listen-port
               "->" (count targets) "targets")
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
