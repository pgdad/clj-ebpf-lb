# eBPF Reverse Proxy Implementation Plan

## Overview

This document outlines the implementation of a high-performance reverse proxy using eBPF (via clj-ebpf 0.2.2) for kernel-space packet processing with a Clojure user-space control plane.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Space (Clojure)                     │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ Config API  │  │  Stats      │  │   CLI/REPL Interface    │  │
│  │ (CRUD ops)  │  │  Consumer   │  │   (nrepl + commands)    │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘  │
│         │                │                     │                │
│         ▼                ▼                     ▼                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              clj-ebpf Core API (0.2.2)                   │   │
│  │  - Map operations (hash, LPM trie, per-CPU)              │   │
│  │  - Ring buffer consumer                                   │   │
│  │  - XDP/TC program management                              │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ══════════╧══════════ (syscall boundary)
                              │
┌─────────────────────────────────────────────────────────────────┐
│                     Kernel Space (eBPF)                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   XDP Program                             │   │
│  │  - Packet inspection (IP/TCP/UDP headers)                 │   │
│  │  - Source IP lookup in routing map                        │   │
│  │  - NAT rewriting (dest IP/port)                          │   │
│  │  - Connection tracking update                             │   │
│  │  - Stats emission (if enabled)                            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌────────────────┬─────────┴──────┬───────────────────────┐   │
│  │                │                │                        │   │
│  ▼                ▼                ▼                        ▼   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐     │
│  │ Config   │  │ Conntrack│  │ Stats    │  │  Settings   │     │
│  │ Map      │  │ Map      │  │ Ring Buf │  │  Map        │     │
│  │ (LPM)    │  │ (Hash)   │  │          │  │  (Array)    │     │
│  └──────────┘  └──────────┘  └──────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

## eBPF Maps Structure

### 1. Configuration Map (LPM Trie)
Longest-prefix-match for source IP routing decisions.

```clojure
;; Key structure (for LPM trie)
{:prefix-len   32           ;; u32 - CIDR prefix length (0-32 for IPv4)
 :src-ip       0xC0A80001}  ;; u32 - Source IP in network byte order

;; Value structure
{:target-ip    0xC0A80101   ;; u32 - Target backend IP
 :target-port  8080         ;; u16 - Target backend port
 :flags        0x01}        ;; u8  - Flags (enabled, NAT mode, etc.)
```

### 2. Listen Port Map (Hash Map)
Maps listen interfaces/ports to their default targets.

```clojure
;; Key structure
{:ifindex      2            ;; u32 - Network interface index
 :port         80}          ;; u16 - Listen port (network byte order)

;; Value structure
{:default-target-ip    0x0A000001  ;; u32 - Default target IP
 :default-target-port  8080        ;; u16 - Default target port
 :stats-enabled        1}          ;; u8  - Whether to emit stats
```

### 3. Connection Tracking Map (Hash Map, Per-CPU for performance)
Tracks active connections for NAT reply path.

```clojure
;; Key structure (5-tuple)
{:src-ip       0xC0A80001   ;; u32
 :dst-ip       0xC0A80002   ;; u32
 :src-port     12345        ;; u16
 :dst-port     80           ;; u16
 :protocol     6}           ;; u8 (TCP=6, UDP=17)

;; Value structure
{:orig-dst-ip     0xC0A80002   ;; u32 - Original destination (for reply)
 :orig-dst-port   80           ;; u16
 :nat-dst-ip      0x0A000001   ;; u32 - NAT'd destination
 :nat-dst-port    8080         ;; u16
 :last-seen       1234567890   ;; u64 - Timestamp (ktime_ns)
 :packets-fwd     100          ;; u64 - Forward packet count
 :bytes-fwd       50000        ;; u64 - Forward byte count
 :packets-rev     95           ;; u64 - Reverse packet count
 :bytes-rev       48000}       ;; u64 - Reverse byte count
```

### 4. Settings Map (Array)
Global settings array.

```clojure
;; Index 0: Global stats enabled flag
;; Index 1: Connection timeout (seconds)
;; Index 2: Max connections
```

### 5. Stats Ring Buffer
For streaming connection events to user space.

```clojure
;; Event structure
{:event-type    :new-conn | :conn-closed | :periodic-stats
 :timestamp     u64
 :src-ip        u32
 :dst-ip        u32
 :src-port      u16
 :dst-port      u16
 :target-ip     u32
 :target-port   u16
 :packets-fwd   u64
 :bytes-fwd     u64
 :packets-rev   u64
 :bytes-rev     u64}
```

## eBPF Program Design

### XDP Program Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Packet Arrives                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Parse Ethernet Header                                     │
│    - Validate ethertype (IPv4: 0x0800)                      │
│    - Non-IPv4 → XDP_PASS                                    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Parse IP Header                                           │
│    - Validate header length                                  │
│    - Check protocol (TCP/UDP)                               │
│    - Non-TCP/UDP → XDP_PASS                                 │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Parse TCP/UDP Header                                      │
│    - Extract src/dst ports                                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Check Listen Port Map                                     │
│    - Key: {ifindex, dst_port}                               │
│    - Not found → XDP_PASS (not our traffic)                 │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Lookup Source IP in Config Map (LPM)                     │
│    - Key: {prefix_len=32, src_ip}                           │
│    - Found → Use specific target                            │
│    - Not found → Use default target from listen port map    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Check/Create Connection Tracking Entry                    │
│    - Lookup existing connection                              │
│    - If new: create entry, emit event (if stats enabled)    │
│    - Update last-seen timestamp                              │
│    - Increment packet/byte counters                          │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. Perform NAT                                               │
│    - Rewrite destination IP to target IP                     │
│    - Rewrite destination port to target port                 │
│    - Recalculate IP checksum (incremental)                  │
│    - Recalculate TCP/UDP checksum (incremental)             │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. Return XDP_TX or XDP_REDIRECT                            │
│    - TX: Send modified packet back out same interface       │
│    - REDIRECT: Forward to different interface               │
└─────────────────────────────────────────────────────────────┘
```

### Reply Path (TC Egress or Second XDP)

For full NAT functionality, we need to handle reply packets:

```
┌─────────────────────────────────────────────────────────────┐
│ Reply Packet Processing (TC egress or XDP on backend iface) │
├─────────────────────────────────────────────────────────────┤
│ 1. Parse packet headers                                      │
│ 2. Lookup reverse 5-tuple in conntrack map                  │
│ 3. If found: rewrite source IP/port to original values      │
│ 4. Recalculate checksums                                     │
│ 5. Forward packet                                            │
└─────────────────────────────────────────────────────────────┘
```

## User Space Program Design

### Project Structure

```
clj-ebpf-reverse-proxy/
├── deps.edn
├── src/
│   └── reverse_proxy/
│       ├── core.clj           ;; Main entry point
│       ├── config.clj         ;; Configuration management
│       ├── maps.clj           ;; eBPF map operations
│       ├── programs/
│       │   ├── xdp_ingress.clj   ;; XDP ingress program (DSL)
│       │   ├── tc_egress.clj     ;; TC egress program (DSL)
│       │   └── common.clj        ;; Shared program fragments
│       ├── stats.clj          ;; Statistics streaming
│       ├── conntrack.clj      ;; Connection tracking utilities
│       └── util.clj           ;; IP/port conversion utilities
└── test/
    └── reverse_proxy/
        ├── config_test.clj
        ├── maps_test.clj
        ├── programs_test.clj
        └── integration_test.clj
```

### Configuration Data Model

```clojure
;; Simple configuration
{:listen-interfaces ["eth0" "eth1"]
 :listen-port 80
 :default-target {:ip "10.0.0.1" :port 8080}}

;; Advanced configuration with source-based routing
{:listen-interfaces ["eth0"]
 :listen-port 443
 :default-target {:ip "10.0.0.1" :port 8443}
 :source-routes
 [{:source "192.168.1.0/24"    ;; CIDR notation
   :target {:ip "10.0.0.2" :port 8443}}
  {:source "192.168.2.100"     ;; Single IP (implies /32)
   :target {:ip "10.0.0.3" :port 9443}}
  {:source "customer-a.example.com"  ;; Hostname (resolved at config time)
   :target {:ip "10.0.0.4" :port 8443}}]}

;; Full configuration with multiple listen ports
{:proxies
 [{:name "web-proxy"
   :listen {:interfaces ["eth0"] :port 80}
   :default-target {:ip "10.0.0.1" :port 8080}
   :source-routes [...]}
  {:name "api-proxy"
   :listen {:interfaces ["eth0" "eth1"] :port 8080}
   :default-target {:ip "10.0.1.1" :port 3000}
   :source-routes [...]}]
 :settings
 {:stats-enabled true
  :connection-timeout-sec 300
  :max-connections 100000}}
```

### Core API Functions

```clojure
(ns reverse-proxy.core
  (:require [clj-ebpf.core :as bpf]
            [reverse-proxy.config :as config]
            [reverse-proxy.maps :as maps]
            [reverse-proxy.programs :as programs]
            [reverse-proxy.stats :as stats]))

;; Initialization
(defn init!
  "Initialize the eBPF subsystem and load programs"
  [config]
  ...)

(defn shutdown!
  "Clean shutdown - detach programs, close maps"
  []
  ...)

;; Configuration Management
(defn add-proxy!
  "Add a new proxy configuration"
  [proxy-config]
  ...)

(defn update-proxy!
  "Update an existing proxy configuration"
  [proxy-name updates]
  ...)

(defn remove-proxy!
  "Remove a proxy configuration"
  [proxy-name]
  ...)

(defn add-source-route!
  "Add a source-based route to an existing proxy"
  [proxy-name source-cidr target]
  ...)

(defn remove-source-route!
  "Remove a source-based route"
  [proxy-name source-cidr]
  ...)

;; Statistics Streaming
(defn start-stats-stream!
  "Start streaming connection statistics"
  [callback-fn]
  ...)

(defn stop-stats-stream!
  "Stop statistics streaming"
  []
  ...)

(defn get-active-connections
  "Get snapshot of active connections"
  []
  ...)

(defn get-connection-stats
  "Get statistics for a specific connection"
  [conn-key]
  ...)

;; Settings
(defn enable-stats!
  "Enable statistics collection in eBPF program"
  []
  ...)

(defn disable-stats!
  "Disable statistics collection"
  []
  ...)
```

### Maps Module

```clojure
(ns reverse-proxy.maps
  (:require [clj-ebpf.core :as bpf]))

;; Map creation
(defn create-maps!
  "Create all required eBPF maps"
  [{:keys [max-routes max-connections ringbuf-size]}]
  (let [config-map (bpf/create-lpm-trie-map
                     {:key-size 8      ;; prefix-len (4) + ip (4)
                      :value-size 8    ;; target-ip (4) + port (2) + flags (2)
                      :max-entries max-routes
                      :map-name "config_map"})

        listen-map (bpf/create-hash-map
                     {:key-size 6      ;; ifindex (4) + port (2)
                      :value-size 8    ;; target-ip (4) + port (2) + flags (2)
                      :max-entries 256
                      :map-name "listen_map"})

        conntrack-map (bpf/create-percpu-hash-map
                        {:key-size 13    ;; 5-tuple
                         :value-size 48  ;; tracking data
                         :max-entries max-connections
                         :map-name "conntrack_map"})

        settings-map (bpf/create-array-map
                       {:value-size 8
                        :max-entries 16
                        :map-name "settings_map"})

        stats-ringbuf (bpf/create-ringbuf-map
                        {:size ringbuf-size
                         :map-name "stats_ringbuf"})]

    {:config-map config-map
     :listen-map listen-map
     :conntrack-map conntrack-map
     :settings-map settings-map
     :stats-ringbuf stats-ringbuf}))

;; Configuration map operations
(defn add-source-route
  "Add a source IP route to config map"
  [config-map {:keys [src-ip prefix-len target-ip target-port]}]
  (let [key (encode-lpm-key prefix-len src-ip)
        value (encode-route-value target-ip target-port)]
    (bpf/map-update config-map key value)))

(defn remove-source-route
  "Remove a source IP route"
  [config-map src-ip prefix-len]
  (let [key (encode-lpm-key prefix-len src-ip)]
    (bpf/map-delete config-map key)))

;; Listen map operations
(defn add-listen-port
  "Configure a listen port with default target"
  [listen-map {:keys [ifindex port default-target stats-enabled]}]
  ...)

;; Conntrack operations
(defn get-all-connections
  "Retrieve all active connections"
  [conntrack-map]
  (->> (bpf/map-entries conntrack-map)
       (map decode-conntrack-entry)))

(defn clear-stale-connections!
  "Remove connections older than timeout"
  [conntrack-map timeout-ns]
  ...)
```

### Statistics Module

```clojure
(ns reverse-proxy.stats
  (:require [clj-ebpf.core :as bpf]
            [clojure.core.async :as async]))

(defn start-stats-consumer
  "Start consuming stats from ring buffer"
  [stats-ringbuf callback-fn]
  (let [running (atom true)
        consumer-thread
        (Thread.
          #(bpf/with-ringbuf-consumer [consumer stats-ringbuf]
             (while @running
               (bpf/process-events consumer
                 (fn [event-data]
                   (let [event (decode-stats-event event-data)]
                     (callback-fn event)))))))]
    (.start consumer-thread)
    {:thread consumer-thread
     :running running}))

(defn stop-stats-consumer
  [{:keys [running thread]}]
  (reset! running false)
  (.interrupt thread)
  (.join thread 1000))

;; Core.async channel-based streaming
(defn stats-channel
  "Returns a channel that receives stats events"
  [stats-ringbuf]
  (let [ch (async/chan 1000)]
    {:channel ch
     :consumer (start-stats-consumer
                 stats-ringbuf
                 #(async/>!! ch %))}))

;; Aggregation utilities
(defn aggregate-by-source
  "Aggregate stats by source IP"
  [events]
  (->> events
       (group-by :src-ip)
       (map-vals #(reduce merge-stats %))))

(defn aggregate-by-target
  "Aggregate stats by target"
  [events]
  ...)
```

### Program Module

```clojure
(ns reverse-proxy.programs.xdp-ingress
  "XDP ingress program for reverse proxy - built entirely with clj-ebpf DSL"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.dsl :as dsl]
            [reverse-proxy.programs.common :as common]))

;; Register allocation convention:
;; r1 = xdp_md context (preserved)
;; r6 = packet data start pointer
;; r7 = packet data end pointer
;; r8 = current parse position / scratch
;; r9 = scratch register
;; r10 = frame pointer (stack base)

;; XDP return codes
(def XDP_ABORTED 0)
(def XDP_DROP    1)
(def XDP_PASS    2)
(def XDP_TX      3)
(def XDP_REDIRECT 4)

;; Protocol numbers
(def ETH_P_IP    0x0800)
(def IPPROTO_TCP 6)
(def IPPROTO_UDP 17)

;; Header sizes
(def ETH_HLEN    14)
(def IP_HLEN_MIN 20)
(def TCP_HLEN_MIN 20)
(def UDP_HLEN    8)

(defn build-packet-bounds-check
  "Generate instructions to check packet bounds.
   Returns instructions that jump to :pass-label if bounds exceeded."
  [offset size pass-label]
  [(dsl/mov :r8 :r6)                    ;; r8 = data start
   (dsl/add :r8 (+ offset size))        ;; r8 = data + offset + size
   (dsl/jmp-reg :jgt :r8 :r7 pass-label)]) ;; if r8 > data_end, jump to pass

(defn build-parse-ethernet
  "Parse Ethernet header, extract ethertype.
   Stores ethertype in r8. Jumps to :pass if not IPv4."
  []
  (concat
    (build-packet-bounds-check 0 ETH_HLEN :pass)
    ;; Load ethertype from ethernet header (offset 12, 2 bytes)
    [(dsl/ldx :h :r8 :r6 12)            ;; r8 = ethertype (host byte order after load)
     (dsl/jmp-imm :jne :r8 ETH_P_IP :pass)])) ;; if not IPv4, pass

(defn build-parse-ip
  "Parse IP header, extract protocol, src/dst IPs.
   Stores: protocol on stack[-4], src_ip stack[-8], dst_ip stack[-12]"
  []
  (concat
    (build-packet-bounds-check ETH_HLEN IP_HLEN_MIN :pass)
    ;; Load IP header fields
    [(dsl/ldx :b :r8 :r6 (+ ETH_HLEN 9))   ;; r8 = protocol (offset 9 in IP header)
     (dsl/stx :w :r10 -4 :r8)               ;; stack[-4] = protocol

     (dsl/ldx :w :r8 :r6 (+ ETH_HLEN 12))   ;; r8 = src IP
     (dsl/stx :w :r10 -8 :r8)               ;; stack[-8] = src_ip

     (dsl/ldx :w :r8 :r6 (+ ETH_HLEN 16))   ;; r8 = dst IP
     (dsl/stx :w :r10 -12 :r8)              ;; stack[-12] = dst_ip

     ;; Check protocol is TCP or UDP
     (dsl/ldx :w :r8 :r10 -4)               ;; reload protocol
     (dsl/jmp-imm :jeq :r8 IPPROTO_TCP :parse-l4)
     (dsl/jmp-imm :jeq :r8 IPPROTO_UDP :parse-l4)
     (dsl/jmp-imm :ja 0 :pass)]))           ;; else pass

(defn build-parse-l4
  "Parse TCP/UDP header, extract src/dst ports.
   Assumes IP header is 20 bytes (no options - simplified).
   Stores: src_port stack[-14], dst_port stack[-16]"
  []
  (let [l4-offset (+ ETH_HLEN IP_HLEN_MIN)]
    [[:label :parse-l4]
     ;; Bounds check for L4 header (at least 4 bytes for ports)
     (dsl/mov :r8 :r6)
     (dsl/add :r8 (+ l4-offset 4))
     (dsl/jmp-reg :jgt :r8 :r7 :pass)

     ;; Load ports
     (dsl/ldx :h :r8 :r6 l4-offset)         ;; src port
     (dsl/stx :h :r10 -14 :r8)
     (dsl/ldx :h :r8 :r6 (+ l4-offset 2))   ;; dst port
     (dsl/stx :h :r10 -16 :r8)]))

(defn build-listen-map-lookup
  "Look up destination port in listen map.
   Key: {ifindex (4 bytes), port (2 bytes)}
   Result pointer in r0, jump to :pass if not found."
  [listen-map-fd]
  [;; Build key on stack: stack[-24..-18] = {ifindex, port}
   ;; Load ifindex from xdp_md->ingress_ifindex (offset 12)
   (dsl/ldx :w :r8 :r1 12)                  ;; r8 = ifindex
   (dsl/stx :w :r10 -24 :r8)                ;; stack[-24] = ifindex
   (dsl/ldx :h :r8 :r10 -16)                ;; r8 = dst_port
   (dsl/stx :h :r10 -20 :r8)                ;; stack[-20] = port

   ;; Call bpf_map_lookup_elem(listen_map, &key)
   (dsl/mov :r8 :r10)
   (dsl/add :r8 -24)                        ;; r8 = &key
   (dsl/lddw :r1 listen-map-fd)             ;; r1 = map fd
   (dsl/mov :r2 :r8)                        ;; r2 = &key
   (dsl/call :map-lookup-elem)

   ;; r0 = value ptr or NULL
   (dsl/jmp-imm :jeq :r0 0 :pass)])         ;; if NULL, pass

(defn build-lpm-lookup
  "Look up source IP in LPM trie config map.
   Key: {prefix_len (4 bytes), ip (4 bytes)}
   If found, use specific target. If not, use default from listen map."
  [config-map-fd]
  [;; Build LPM key: stack[-32..-24] = {prefix_len=32, src_ip}
   (dsl/mov :r8 32)
   (dsl/stx :w :r10 -32 :r8)                ;; prefix_len = 32
   (dsl/ldx :w :r8 :r10 -8)                 ;; src_ip from earlier parse
   (dsl/stx :w :r10 -28 :r8)                ;; stack[-28] = src_ip

   ;; Save listen map result pointer
   (dsl/mov :r9 :r0)                        ;; r9 = listen map value ptr

   ;; Call bpf_map_lookup_elem(config_map, &lpm_key)
   (dsl/mov :r8 :r10)
   (dsl/add :r8 -32)
   (dsl/lddw :r1 config-map-fd)
   (dsl/mov :r2 :r8)
   (dsl/call :map-lookup-elem)

   ;; If found, use config map result; else use listen map default
   (dsl/jmp-imm :jne :r0 0 :use-config-target)
   (dsl/mov :r0 :r9)                        ;; restore listen map ptr as target
   [:label :use-config-target]])

(defn build-nat-rewrite
  "Rewrite destination IP and port, update checksums.
   r0 = pointer to target value {target_ip, target_port, flags}"
  []
  [;; Load target values
   (dsl/ldx :w :r8 :r0 0)                   ;; r8 = target_ip
   (dsl/ldx :h :r9 :r0 4)                   ;; r9 = target_port

   ;; Store new dst IP in packet (ETH_HLEN + 16)
   (dsl/stx :w :r6 (+ ETH_HLEN 16) :r8)

   ;; Store new dst port (ETH_HLEN + IP_HLEN_MIN + 2)
   (dsl/stx :h :r6 (+ ETH_HLEN IP_HLEN_MIN 2) :r9)

   ;; Update checksums using helpers (see clj-ebpf feature requirements)
   ;; Call bpf_l3_csum_replace for IP checksum
   ;; Call bpf_l4_csum_replace for TCP/UDP checksum
   (dsl/call :csum-diff)   ;; placeholder - requires clj-ebpf support
   ])

(defn build-xdp-program
  "Build complete XDP ingress program using clj-ebpf DSL"
  [{:keys [listen-map-fd config-map-fd conntrack-map-fd settings-map-fd ringbuf-fd]}]
  (dsl/program
    ;; Prologue: load packet pointers
    (dsl/ldx :dw :r6 :r1 0)                 ;; r6 = xdp_md->data
    (dsl/ldx :dw :r7 :r1 4)                 ;; r7 = xdp_md->data_end

    ;; Parse headers
    (build-parse-ethernet)
    (build-parse-ip)
    (build-parse-l4)

    ;; Lookup in maps
    (build-listen-map-lookup listen-map-fd)
    (build-lpm-lookup config-map-fd)

    ;; Perform NAT rewrite
    (build-nat-rewrite)

    ;; TODO: conntrack update, stats emission

    ;; Return XDP_TX to send packet
    (dsl/mov :r0 XDP_TX)
    (dsl/exit-insn)

    ;; Pass label - return XDP_PASS
    [:label :pass]
    (dsl/mov :r0 XDP_PASS)
    (dsl/exit-insn)))

(defn load-and-attach-xdp!
  "Load XDP program and attach to interfaces"
  [program interfaces]
  (let [prog-fd (bpf/load-xdp-program program)]
    (doseq [iface interfaces]
      (let [ifindex (bpf/interface-name->index iface)]
        (bpf/attach-xdp prog-fd ifindex {:mode :skb})))
    prog-fd))

(defn detach-all!
  "Detach from all interfaces"
  [interfaces]
  (doseq [iface interfaces]
    (let [ifindex (bpf/interface-name->index iface)]
      (bpf/detach-xdp ifindex))))
```

### Utility Functions

```clojure
(ns reverse-proxy.util
  (:require [clojure.string :as str]))

;; IP address conversion
(defn ip-string->u32
  "Convert IP string to network byte order u32"
  [ip-str]
  (let [octets (str/split ip-str #"\.")
        bytes (mapv #(Integer/parseInt %) octets)]
    (bit-or (bit-shift-left (nth bytes 0) 24)
            (bit-shift-left (nth bytes 1) 16)
            (bit-shift-left (nth bytes 2) 8)
            (nth bytes 3))))

(defn u32->ip-string
  "Convert network byte order u32 to IP string"
  [n]
  (format "%d.%d.%d.%d"
          (bit-and (bit-shift-right n 24) 0xFF)
          (bit-and (bit-shift-right n 16) 0xFF)
          (bit-and (bit-shift-right n 8) 0xFF)
          (bit-and n 0xFF)))

;; CIDR parsing
(defn parse-cidr
  "Parse CIDR notation to {:ip :prefix-len}"
  [cidr-str]
  (if (str/includes? cidr-str "/")
    (let [[ip prefix] (str/split cidr-str #"/")]
      {:ip (ip-string->u32 ip)
       :prefix-len (Integer/parseInt prefix)})
    {:ip (ip-string->u32 cidr-str)
     :prefix-len 32}))

;; Hostname resolution
(defn resolve-hostname
  "Resolve hostname to IP address"
  [hostname]
  (-> (java.net.InetAddress/getByName hostname)
      (.getHostAddress)
      (ip-string->u32)))

;; Binary encoding for maps
(defn encode-lpm-key
  "Encode LPM trie key"
  [prefix-len ip]
  (let [buf (java.nio.ByteBuffer/allocate 8)]
    (.order buf java.nio.ByteOrder/BIG_ENDIAN)
    (.putInt buf prefix-len)
    (.putInt buf ip)
    (.array buf)))

(defn encode-route-value
  "Encode route value"
  [target-ip target-port flags]
  (let [buf (java.nio.ByteBuffer/allocate 8)]
    (.order buf java.nio.ByteOrder/BIG_ENDIAN)
    (.putInt buf target-ip)
    (.putShort buf (short target-port))
    (.putShort buf (short flags))
    (.array buf)))
```

## Implementation Phases

### Phase 1: Foundation (Core Infrastructure)
1. Set up project with deps.edn and clj-ebpf dependency
2. Implement utility functions (IP conversion, CIDR parsing, binary encoding)
3. Create map management module with all map types
4. Basic configuration data structures and validation
5. **Verify clj-ebpf DSL capabilities** - test label support, helper availability

### Phase 2: eBPF Program Development (Pure Clojure DSL)
1. Implement reusable DSL fragments for packet parsing
   - Ethernet header parsing
   - IPv4 header parsing
   - TCP/UDP header parsing
2. Implement listen port map lookup fragment
3. Implement LPM trie lookup for source-based routing
4. Implement NAT destination rewrite using DSL
5. Implement checksum updates using BPF helpers via DSL
6. Compose fragments into complete XDP program
7. **If DSL gaps found**: Document required clj-ebpf enhancements

### Phase 3: Connection Tracking
1. Design conntrack 5-tuple key encoding
2. Implement conntrack map operations in user space
3. Add connection creation/lookup in XDP program (DSL)
4. Implement TC egress program for reply path NAT (DSL)
5. Add connection timeout/cleanup in user space (periodic sweep)

### Phase 4: Statistics and Monitoring
1. Implement conditional stats check in eBPF (settings map lookup)
2. Implement ring buffer event emission in eBPF program (DSL)
3. Create stats consumer thread in user space
4. Add core.async channel-based streaming API
5. Implement aggregation utilities (by source, by target)

### Phase 5: Configuration API
1. Complete CRUD operations for proxy configurations
2. Add source route management (add/remove CIDR routes)
3. Configuration persistence (EDN file)
4. Hot reload support (update maps without program restart)
5. Configuration validation and error handling

### Phase 6: CLI and Integration
1. Command-line interface using tools.cli
2. nREPL integration for live REPL-driven management
3. Unit tests for utilities and encoding
4. Integration tests with network namespaces
5. Documentation and usage examples

## clj-ebpf Feature Requirements

This section identifies features that clj-ebpf 0.2.2 must support for a pure-Clojure implementation. If any features are missing, they should be added to the library.

### Required DSL Features

#### 1. Label and Jump Support
**Status**: Likely needs enhancement
**Requirement**: Support for named labels and jump-to-label instructions

```clojure
;; Required DSL syntax
[:label :my-label]                    ;; Define a named label
(dsl/jmp-imm :jeq :r0 0 :my-label)   ;; Jump to label if condition met
(dsl/ja :my-label)                    ;; Unconditional jump to label

;; The DSL must resolve labels to relative offsets during bytecode generation
```

**Suggested clj-ebpf enhancement**: Add a label resolution pass that converts symbolic labels to instruction offsets before final bytecode emission.

#### 2. BPF Helper Function Support
**Status**: Partially available (40+ helpers mentioned)
**Required helpers for this project**:

| Helper ID | Name | Purpose |
|-----------|------|---------|
| 1 | `bpf_map_lookup_elem` | Map lookups |
| 2 | `bpf_map_update_elem` | Map updates |
| 3 | `bpf_map_delete_elem` | Map deletions |
| 5 | `bpf_ktime_get_ns` | Timestamps for conntrack |
| 28 | `bpf_csum_diff` | Checksum difference calculation |
| 55 | `bpf_l3_csum_replace` | IP header checksum update |
| 56 | `bpf_l4_csum_replace` | TCP/UDP checksum update |
| 23 | `bpf_redirect` | Packet redirection |
| 51 | `bpf_redirect_map` | Redirect via devmap |
| 131 | `bpf_ringbuf_reserve` | Reserve ring buffer space |
| 132 | `bpf_ringbuf_submit` | Submit to ring buffer |
| 133 | `bpf_ringbuf_discard` | Discard ring buffer reservation |

**Suggested clj-ebpf enhancement**: Ensure all XDP/TC-relevant helpers are exposed via the DSL with proper argument conventions.

#### 3. Checksum Helper DSL Functions
**Status**: Needs verification/addition
**Requirement**: High-level DSL functions for checksum operations

```clojure
;; Required API
(dsl/l3-csum-replace skb-reg offset old-val new-val flags)
;; Generates: setup args in r1-r5, call helper 55

(dsl/l4-csum-replace skb-reg offset old-val new-val flags)
;; Generates: setup args in r1-r5, call helper 56

(dsl/csum-diff old-ptr old-size new-ptr new-size seed)
;; Generates: setup args, call helper 28
```

**Suggested clj-ebpf enhancement**: Add convenience functions in DSL namespace that generate the correct argument setup and helper calls for checksum operations.

#### 4. Ring Buffer Output from eBPF
**Status**: Needs verification
**Requirement**: DSL support for ring buffer operations within eBPF programs

```clojure
;; Required: reserve, write, submit pattern
(dsl/ringbuf-reserve ringbuf-fd size flags)  ;; Returns ptr in r0
(dsl/ringbuf-submit ptr flags)
(dsl/ringbuf-discard ptr flags)
```

**Suggested clj-ebpf enhancement**: Add ring buffer helper wrappers that handle the reserve-write-submit pattern.

#### 5. Wide Immediate Loads (lddw)
**Status**: Likely available
**Requirement**: Load 64-bit immediate values (for map FDs, large constants)

```clojure
(dsl/lddw :r1 map-fd)  ;; Load map FD into register
```

#### 6. Program Composition
**Status**: Needs enhancement
**Requirement**: Ability to compose program fragments and concatenate instruction sequences

```clojure
;; Required: flatten nested instruction vectors
(dsl/program
  (parse-ethernet-fragment)   ;; Returns vector of instructions
  (parse-ip-fragment)         ;; Returns vector of instructions
  (lookup-and-nat-fragment)   ;; Returns vector of instructions
  (dsl/exit-insn))

;; The program macro should flatten all nested vectors
```

**Suggested clj-ebpf enhancement**: Ensure the `program` macro properly flattens nested instruction vectors and handles label resolution across fragments.

### Required Map Features

#### 1. LPM Trie Map Support
**Status**: Documented as available
**Requirement**: Create and operate on LPM trie maps

```clojure
(bpf/create-lpm-trie-map {:key-size 8 :value-size 8 :max-entries 1000})
```

**Verification needed**: Confirm LPM trie operations work correctly with the expected key format (prefix_len + data).

#### 2. Per-CPU Hash Map
**Status**: Documented as available
**Requirement**: Per-CPU hash maps for lock-free conntrack

```clojure
(bpf/create-percpu-hash-map {:key-size 13 :value-size 48 :max-entries 100000})
(bpf/percpu-sum values)  ;; Aggregate across CPUs
```

#### 3. Ring Buffer Map
**Status**: Documented as available
**Requirement**: Ring buffer for stats streaming

```clojure
(bpf/create-ringbuf-map {:size (* 256 1024) :map-name "stats"})
(bpf/with-ringbuf-consumer [consumer ringbuf]
  (bpf/process-events consumer handler-fn))
```

#### 4. Map FD Passing to Programs
**Status**: Needs verification
**Requirement**: Ability to pass map file descriptors to eBPF programs for use in lddw instructions

```clojure
;; When building program, need map FDs
(build-xdp-program {:listen-map-fd (bpf/map-fd listen-map)
                    :config-map-fd (bpf/map-fd config-map)})
```

**Suggested clj-ebpf enhancement**: Add `(bpf/map-fd map)` function if not present.

### Required Attachment Features

#### 1. XDP Attachment with Mode Selection
**Status**: Documented as available
**Requirement**: Attach XDP programs with mode selection

```clojure
(bpf/attach-xdp prog-fd ifindex {:mode :skb})    ;; Generic/SKB mode
(bpf/attach-xdp prog-fd ifindex {:mode :drv})    ;; Driver/native mode
(bpf/attach-xdp prog-fd ifindex {:mode :hw})     ;; Hardware offload
```

#### 2. TC (Traffic Control) Attachment
**Status**: Documented as available
**Requirement**: Attach TC programs for egress path

```clojure
(bpf/attach-tc-filter prog-fd iface :egress {:priority 1})
```

#### 3. Interface Index Resolution
**Status**: Documented as available
**Requirement**: Convert interface names to indices

```clojure
(bpf/interface-name->index "eth0")  ;; => 2
(bpf/interface-index->name 2)        ;; => "eth0"
```

### Summary of Potential clj-ebpf Enhancements

| Feature | Priority | Description |
|---------|----------|-------------|
| Label resolution | **Critical** | Symbolic labels with automatic offset calculation |
| Checksum helpers | **Critical** | DSL wrappers for l3/l4 checksum updates |
| Ring buffer helpers | **High** | DSL wrappers for ringbuf_reserve/submit/discard |
| Program composition | **High** | Flatten nested instruction vectors in program macro |
| Map FD accessor | **Medium** | Function to get raw FD from map object |
| Instruction validation | **Medium** | Validate register usage and instruction sequences |
| Debug output | **Low** | Print generated bytecode for debugging |

### Workarounds if Features Are Missing

If certain DSL features are not available, these workarounds can be used:

1. **Labels**: Manually calculate instruction offsets (error-prone but functional)
2. **Checksum helpers**: Implement checksum calculation manually in BPF bytecode (complex but possible)
3. **Ring buffer**: Use perf_event_output as alternative (slightly less efficient)
4. **Program composition**: Manually flatten vectors before passing to program macro

## Technical Design Notes

### Bidirectional NAT Architecture
Full proxy requires handling both directions:
- **Ingress (XDP)**: client → proxy → backend (rewrite destination)
- **Egress (TC)**: backend → proxy → client (rewrite source)

Implementation approach:
- XDP program on ingress interfaces for incoming traffic
- TC egress program for reply path NAT
- Shared conntrack map between both programs

### Performance Considerations
- Per-CPU maps for conntrack to avoid lock contention
- LPM trie for efficient O(log n) CIDR matching
- Batch operations for bulk config updates
- Ring buffer sized as power of 2 (e.g., 256KB)
- Stats emission conditional on settings map flag

### IPv6 Support (Future Enhancement)
Current design focuses on IPv4. IPv6 would require:
- Larger key sizes in maps (128-bit addresses)
- IPv6 header parsing in XDP
- ICMPv6 handling
- Separate LPM trie for IPv6 routes

## Dependencies

```clojure
;; deps.edn
{:deps
 {org.clojure/clojure {:mvn/version "1.12.0"}
  org.clojars.pgdad/clj-ebpf {:mvn/version "0.2.2"}
  org.clojure/core.async {:mvn/version "1.6.681"}
  org.clojure/tools.cli {:mvn/version "1.1.230"}
  org.clojure/tools.logging {:mvn/version "1.3.0"}
  ch.qos.logback/logback-classic {:mvn/version "1.5.6"}}}
```

## System Requirements

- Linux kernel 5.8+ (recommended for full feature support)
- Java 21+ (Panama FFI requirement)
- Root or CAP_BPF + CAP_NET_ADMIN capabilities
- BPF filesystem mounted at /sys/fs/bpf

## Testing Strategy

1. **Unit Tests**: IP conversion, CIDR parsing, encoding functions
2. **Map Tests**: Create, update, lookup, delete operations
3. **Integration Tests**: Full proxy flow with network namespaces
4. **Performance Tests**: Throughput and latency benchmarks
5. **Stress Tests**: Connection limits, config changes under load

## References

- [clj-ebpf on Clojars](https://clojars.org/org.clojars.pgdad/clj-ebpf)
- [clj-ebpf Documentation](https://cljdoc.org/d/org.clojars.pgdad/clj-ebpf/0.2.2)
- [XDP Documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_firewalls_and_packet_filters/getting-started-with-xdp-and-ebpf)
- [eBPF Redirects](http://arthurchiao.art/blog/differentiate-bpf-redirects/)
- [Fast Packet Processing with eBPF](https://homepages.dcc.ufmg.br/~mmvieira/so/papers/Fast_Packet_Processing_with_eBPF_and_XDP.pdf)
