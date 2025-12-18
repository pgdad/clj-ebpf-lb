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
  "Create LPM trie map for source IP -> target routing.
   Key: {prefix_len (4 bytes) + ip (4 bytes)} = 8 bytes
   Value: {target_ip (4 bytes) + target_port (2 bytes) + flags (2 bytes)} = 8 bytes"
  [{:keys [max-routes] :or {max-routes (:max-routes default-config)}}]
  (log/info "Creating config LPM trie map with max-entries:" max-routes)
  (bpf/create-lpm-trie-map
    {:key-size 8
     :value-size 8
     :max-entries max-routes
     :map-name "proxy_config"}))

(defn create-listen-map
  "Create hash map for listen interface/port -> default target.
   Key: {ifindex (4 bytes) + port (2 bytes) + padding (2 bytes)} = 8 bytes
   Value: {target_ip (4 bytes) + target_port (2 bytes) + flags (2 bytes)} = 8 bytes"
  [{:keys [max-listen-ports] :or {max-listen-ports (:max-listen-ports default-config)}}]
  (log/info "Creating listen hash map with max-entries:" max-listen-ports)
  (bpf/create-hash-map
    {:key-size 8
     :value-size 8
     :max-entries max-listen-ports
     :map-name "proxy_listen"}))

(defn create-conntrack-map
  "Create per-CPU hash map for connection tracking.
   Using per-CPU variant for lock-free concurrent access.
   Key: 5-tuple (16 bytes aligned)
   Value: conntrack state (56 bytes)"
  [{:keys [max-connections] :or {max-connections (:max-connections default-config)}}]
  (log/info "Creating conntrack per-CPU hash map with max-entries:" max-connections)
  (bpf/create-percpu-hash-map
    {:key-size 16
     :value-size 56
     :max-entries max-connections
     :map-name "proxy_conntrack"}))

(defn create-settings-map
  "Create array map for global settings.
   Index 0: stats enabled (0/1)
   Index 1: connection timeout (seconds)
   Index 2: reserved
   ..."
  [{:keys [settings-entries] :or {settings-entries (:settings-entries default-config)}}]
  (log/info "Creating settings array map with" settings-entries "entries")
  (bpf/create-array-map
    {:value-size 8  ; 64-bit values
     :max-entries settings-entries
     :map-name "proxy_settings"}))

(defn create-stats-ringbuf
  "Create ring buffer for streaming statistics events.
   Size must be a power of 2."
  [{:keys [ringbuf-size] :or {ringbuf-size (:ringbuf-size default-config)}}]
  (log/info "Creating stats ring buffer with size:" ringbuf-size)
  (bpf/create-ringbuf-map
    {:size ringbuf-size
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
   source: {:ip <u32> :prefix-len <int>}
   target: {:ip <u32> :port <int>}
   flags: optional flags (default 1 = enabled)"
  [config-map {:keys [ip prefix-len]} {:keys [ip port] :as target} & {:keys [flags] :or {flags 1}}]
  (let [key-bytes (util/encode-lpm-key prefix-len ip)
        value-bytes (util/encode-route-value (:ip target) port flags)]
    (log/debug "Adding source route:" (util/u32->ip-string ip) "/" prefix-len
               "-> " (util/u32->ip-string (:ip target)) ":" port)
    (bpf/map-update config-map key-bytes value-bytes)))

(defn remove-source-route
  "Remove a source IP/CIDR route from the config map."
  [config-map {:keys [ip prefix-len]}]
  (let [key-bytes (util/encode-lpm-key prefix-len ip)]
    (log/debug "Removing source route:" (util/u32->ip-string ip) "/" prefix-len)
    (bpf/map-delete config-map key-bytes)))

(defn lookup-source-route
  "Look up a source IP in the config map (exact match on prefix-len + IP)."
  [config-map {:keys [ip prefix-len]}]
  (let [key-bytes (util/encode-lpm-key prefix-len ip)]
    (when-let [value-bytes (bpf/map-lookup config-map key-bytes)]
      (util/decode-route-value value-bytes))))

(defn list-source-routes
  "List all source routes in the config map."
  [config-map]
  (->> (bpf/map-entries config-map)
       (map (fn [[k v]]
              {:source (util/decode-lpm-key k)
               :target (util/decode-route-value v)}))))

;;; =============================================================================
;;; Listen Map Operations (Hash - Listen Port Config)
;;; =============================================================================

(defn add-listen-port
  "Configure a listen interface/port with its default target.
   ifindex: network interface index
   port: listen port number
   target: {:ip <u32> :port <int>}
   flags: bit flags (bit 0 = stats enabled)"
  [listen-map ifindex port {:keys [ip port] :as target} & {:keys [flags] :or {flags 0}}]
  (let [key-bytes (util/encode-listen-key ifindex port)
        value-bytes (util/encode-route-value (:ip target) (:port target) flags)]
    (log/debug "Adding listen port: ifindex=" ifindex "port=" port
               "-> " (util/u32->ip-string (:ip target)) ":" (:port target))
    (bpf/map-update listen-map key-bytes value-bytes)))

(defn remove-listen-port
  "Remove a listen interface/port configuration."
  [listen-map ifindex port]
  (let [key-bytes (util/encode-listen-key ifindex port)]
    (log/debug "Removing listen port: ifindex=" ifindex "port=" port)
    (bpf/map-delete listen-map key-bytes)))

(defn lookup-listen-port
  "Look up configuration for a listen interface/port."
  [listen-map ifindex port]
  (let [key-bytes (util/encode-listen-key ifindex port)]
    (when-let [value-bytes (bpf/map-lookup listen-map key-bytes)]
      (util/decode-route-value value-bytes))))

(defn list-listen-ports
  "List all configured listen ports."
  [listen-map]
  (->> (bpf/map-entries listen-map)
       (map (fn [[k v]]
              {:listen (util/decode-listen-key k)
               :target (util/decode-route-value v)}))))

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

(defn- encode-setting-value
  "Encode a 64-bit setting value."
  [value]
  (let [buf (java.nio.ByteBuffer/allocate 8)]
    (.order buf java.nio.ByteOrder/LITTLE_ENDIAN)  ; Array maps typically use native byte order
    (.putLong buf value)
    (.array buf)))

(defn- decode-setting-value
  "Decode a 64-bit setting value."
  [^bytes b]
  (let [buf (java.nio.ByteBuffer/wrap b)]
    (.order buf java.nio.ByteOrder/LITTLE_ENDIAN)
    (.getLong buf)))

(defn set-setting
  "Set a global setting by index."
  [settings-map index value]
  (let [key-bytes (let [buf (java.nio.ByteBuffer/allocate 4)]
                    (.order buf java.nio.ByteOrder/LITTLE_ENDIAN)
                    (.putInt buf index)
                    (.array buf))
        value-bytes (encode-setting-value value)]
    (bpf/map-update settings-map key-bytes value-bytes)))

(defn get-setting
  "Get a global setting by index."
  [settings-map index]
  (let [key-bytes (let [buf (java.nio.ByteBuffer/allocate 4)]
                    (.order buf java.nio.ByteOrder/LITTLE_ENDIAN)
                    (.putInt buf index)
                    (.array buf))]
    (when-let [value-bytes (bpf/map-lookup settings-map key-bytes)]
      (decode-setting-value value-bytes))))

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
  ;; This may need to access internal state or use a specific API
  (if (satisfies? bpf/IMapFD m)
    (bpf/get-fd m)
    ;; Fallback: assume the map object has an :fd key or is the fd itself
    (cond
      (map? m) (:fd m)
      (number? m) m
      :else (throw (ex-info "Cannot get file descriptor from map" {:map m})))))

;; Define protocol for map FD access if not in clj-ebpf
(defprotocol IMapFD
  (get-fd [m] "Get the file descriptor for this map"))
