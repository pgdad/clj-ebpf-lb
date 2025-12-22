(ns lb.programs.tc-egress
  "TC egress program for the load balancer.
   Handles reply packets from backends: performs SNAT to restore original destination."
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.asm :as asm]
            [clj-ebpf.net :as net]
            [clj-ebpf.net.ethernet :as eth]
            [clj-ebpf.net.ipv4 :as ipv4]
            [clj-ebpf.net.tcp :as tcp]
            [clj-ebpf.net.udp :as udp]
            [clj-ebpf.net.checksum :as csum]
            [clj-ebpf.net.nat :as nat]
            [lb.programs.common :as common]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; TC Program Structure
;;; =============================================================================

;; The TC egress program handles the reply path:
;; 1. Parse packet headers (Ethernet, IPv4, TCP/UDP)
;; 2. Build reverse 5-tuple key from reply packet
;; 3. Look up connection in conntrack map
;; 4. If found, perform SNAT (rewrite source IP/port to original destination)
;; 5. Update checksums using kernel helpers (bpf_l3_csum_replace, bpf_l4_csum_replace)
;; 6. Return TC_ACT_OK to continue processing

;; Register allocation:
;; r1 = SKB context (input, clobbered by helpers)
;; r6 = saved SKB context (callee-saved)
;; r7 = data pointer (callee-saved)
;; r8 = data_end pointer (callee-saved)
;; r9 = IP header pointer / map value ptr (callee-saved)
;; r0-r5 = scratch, clobbered by helper calls

;; Stack layout for IPv4 (negative offsets from r10):
;; -16  : Conntrack key (16 bytes): {src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) + proto(1) + pad(3)}
;; -20  : old_src_ip (4 bytes) - source IP before SNAT
;; -24  : old_src_port (2 bytes) + padding (2 bytes)
;; -28  : protocol (1 byte) + padding (3 bytes)
;; -32  : L4 header offset from data (4 bytes)
;; -40  : scratch space (8 bytes)
;; -48  : packet length (8 bytes) - saved for stats update
;;
;; ============================================================================
;; Unified stack layout for IPv4/IPv6 dual-stack (used by build-tc-snat-program-unified):
;; ============================================================================
;; -40  : Conntrack key (40 bytes): {src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2) + proto(1) + pad(3)}
;; -56  : old_src_ip (16 bytes) - source IP before SNAT
;; -60  : old_src_port (2 bytes) + padding (2 bytes)
;; -61  : protocol (1 byte)
;; -62  : af (1 byte) - 4 = IPv4, 6 = IPv6
;; -64  : padding (2 bytes)
;; -68  : L4 header offset from data (4 bytes)
;; -84  : new_src_ip (16 bytes) - from conntrack value
;; -88  : new_src_port (2 bytes) + padding (2 bytes)
;; -96  : scratch space (8 bytes)
;;
;; Conntrack value structure (64 bytes, from XDP):
;;   offset 0:  orig_dst_ip (4) - for SNAT to restore as source
;;   offset 4:  orig_dst_port (2)
;;   offset 6:  pad (2)
;;   offset 8:  nat_dst_ip (4)
;;   offset 12: nat_dst_port (2)
;;   offset 14: pad (2)
;;   offset 16: created_ns (8)
;;   offset 24: last_seen_ns (8) - updated by TC
;;   offset 32: packets_fwd (8)
;;   offset 40: packets_rev (8) - incremented by TC
;;   offset 48: bytes_fwd (8)
;;   offset 56: bytes_rev (8) - updated by TC

;;; =============================================================================
;;; Simple Pass-Through TC Program
;;; =============================================================================

(defn build-tc-pass-program
  "Build a simple TC program that passes all packets.
   This is useful for initial testing of program loading/attachment."
  []
  (bpf/assemble
    [(dsl/mov :r0 net/TC-ACT-OK)
     (dsl/exit-insn)]))

;;; =============================================================================
;;; IPv4 Filter TC Program (using clj-ebpf.net)
;;; =============================================================================

(defn build-tc-ipv4-filter-program
  "Build TC program that passes IPv4 packets and drops others.
   Uses clj-ebpf.net primitives for packet parsing."
  []
  (bpf/assemble
    (concat
      ;; Save SKB and load data pointers
      [(dsl/mov-reg :r6 :r1)]
      (net/tc-load-data-ptrs :r7 :r8 :r1)

      ;; Check Ethernet header bounds
      (net/check-bounds :r7 :r8 net/ETH-HLEN 5 :r9)

      ;; Load and check ethertype
      (eth/load-ethertype :r9 :r7)
      (eth/is-ipv4 :r9 1)

      ;; Not IPv4 - pass through (let other protocols flow)
      [(dsl/mov :r0 net/TC-ACT-OK)
       (dsl/exit-insn)]

      ;; IPv4 - pass
      [(dsl/mov :r0 net/TC-ACT-OK)
       (dsl/exit-insn)])))

;;; =============================================================================
;;; TC Context Access Helpers
;;; =============================================================================

;; The __sk_buff struct fields are accessed as 32-bit values.
;; For TC programs, data and data_end are at different offsets than XDP.
;;
;; struct __sk_buff (relevant fields):
;;     ...
;;     __u32 data;         // offset 76
;;     __u32 data_end;     // offset 80
;;     ...

(defn tc-load-data-ptrs-32
  "Load data and data_end pointers from SKB context using 32-bit loads.

   data-reg: Register to store data pointer
   data-end-reg: Register to store data_end pointer
   ctx-reg: SKB context register (typically :r1)"
  [data-reg data-end-reg ctx-reg]
  [(dsl/ldx :w data-reg ctx-reg 76)     ; data at offset 76
   (dsl/ldx :w data-end-reg ctx-reg 80)]) ; data_end at offset 80

;;; =============================================================================
;;; BPF Helper Constants for TC
;;; =============================================================================

;; BPF helper function IDs
(def ^:const BPF-FUNC-ktime-get-ns 5)
;; TC programs can use these checksum helpers (unlike XDP)
(def ^:const BPF-FUNC-l3-csum-replace 10)
(def ^:const BPF-FUNC-l4-csum-replace 11)

;; Flags for l4_csum_replace
(def ^:const BPF-F-PSEUDO-HDR 0x10)
(def ^:const BPF-F-HDR-FIELD-MASK 0xF)

;;; =============================================================================
;;; Full TC Egress Program with SNAT
;;; =============================================================================

(defn build-tc-snat-program
  "Build TC egress program that performs SNAT on reply packets.

   This program:
   1. Parses IPv4/TCP or IPv4/UDP packets
   2. Builds reverse 5-tuple key from reply packet
   3. Looks up conntrack map to find original destination
   4. If found, performs SNAT (rewrites src IP and port to original dest)
   5. Updates IP and L4 checksums using kernel helpers
   6. Returns TC_ACT_OK to continue processing

   For a reply packet from backend to client:
   - Reply: src=backend_ip:backend_port, dst=client_ip:client_port
   - Reverse key: {client_ip, backend_ip, client_port, backend_port, proto}
   - This matches the conntrack entry created by XDP DNAT
   - SNAT rewrites: src=backend -> src=orig_dst (the proxy address)

   Register allocation:
   r6 = saved SKB context (callee-saved)
   r7 = data pointer (callee-saved)
   r8 = data_end pointer (callee-saved)
   r9 = IP header pointer / map value ptr (callee-saved)
   r0-r5 = scratch, clobbered by helpers

   Uses clj-ebpf.asm label-based assembly for automatic jump offset resolution."
  [conntrack-map-fd]
  (asm/assemble-with-labels
    (concat
      ;; =====================================================================
      ;; PHASE 1: Context Setup and Ethernet Parsing
      ;; =====================================================================

      ;; Save SKB context to callee-saved register
      [(dsl/mov-reg :r6 :r1)]

      ;; Load data and data_end pointers from SKB context
      (tc-load-data-ptrs-32 :r7 :r8 :r1)

      ;; Check Ethernet header bounds
      (asm/check-bounds :r7 :r8 net/ETH-HLEN :pass :r9)

      ;; Load and check ethertype for IPv4
      (eth/load-ethertype :r9 :r7)
      [(asm/jmp-imm :jne :r9 eth/ETH-P-IP-BE :pass)]

      ;; =====================================================================
      ;; PHASE 2: IPv4 Header Parsing
      ;; =====================================================================

      ;; Calculate IP header pointer: data + ETH_HLEN
      (eth/get-ip-header-ptr :r9 :r7)

      ;; Check IP header bounds (minimum 20 bytes)
      (asm/check-bounds :r9 :r8 net/IPV4-MIN-HLEN :pass :r0)

      ;; Load and store protocol
      [(dsl/ldx :b :r0 :r9 9)           ; protocol at offset 9
       (dsl/stx :b :r10 :r0 -28)]       ; store at stack[-28]

      ;; Load source IP (backend) and destination IP (client)
      ;; For conntrack key, we need to REVERSE: key.src = client, key.dst = backend
      [(dsl/ldx :w :r0 :r9 12)          ; src_ip (backend) at offset 12
       (dsl/stx :w :r10 :r0 -20)        ; store as old_src_ip at stack[-20]
       (dsl/stx :w :r10 :r0 -12)]       ; store as key.dst_ip at stack[-12]

      [(dsl/ldx :w :r0 :r9 16)          ; dst_ip (client) at offset 16
       (dsl/stx :w :r10 :r0 -16)]       ; store as key.src_ip at stack[-16]

      ;; =====================================================================
      ;; PHASE 3: Protocol Branching
      ;; =====================================================================

      ;; Check protocol and branch
      [(dsl/ldx :b :r0 :r10 -28)        ; load protocol
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_path)
       (asm/jmp-imm :jeq :r0 net/IPPROTO-UDP :udp_path)
       (asm/jmp :pass)]                  ; not TCP or UDP, pass through

      ;; =====================================================================
      ;; TCP Path: Parse TCP header and extract ports
      ;; =====================================================================
      [(asm/label :tcp_path)]

      ;; Calculate L4 header offset and store
      [(dsl/mov :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :w :r10 :r0 -32)]       ; L4 offset at stack[-32]

      ;; Calculate L4 header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))]

      ;; Check TCP header bounds (need at least 4 bytes for ports)
      [(dsl/mov-reg :r1 :r0)
       (dsl/add :r1 4)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Load TCP ports and build reverse key
      ;; Reply has: src=backend_port, dst=client_port
      ;; Key needs: src_port=client_port, dst_port=backend_port
      [(dsl/ldx :h :r1 :r0 0)           ; src_port (backend)
       (dsl/stx :h :r10 :r1 -24)        ; store as old_src_port at stack[-24]
       (dsl/stx :h :r10 :r1 -6)]        ; store as key.dst_port at stack[-6]

      [(dsl/ldx :h :r1 :r0 2)           ; dst_port (client)
       (dsl/stx :h :r10 :r1 -8)]        ; store as key.src_port at stack[-8]

      ;; Store protocol in key and padding
      [(dsl/ldx :b :r0 :r10 -28)        ; load protocol
       (dsl/stx :b :r10 :r0 -4)         ; key.protocol at stack[-4]
       (dsl/mov :r0 0)
       (dsl/stx :b :r10 :r0 -3)         ; padding
       (dsl/stx :h :r10 :r0 -2)]        ; padding (2 bytes)

      [(asm/jmp :lookup_conntrack)]

      ;; =====================================================================
      ;; UDP Path: Parse UDP header and extract ports
      ;; =====================================================================
      [(asm/label :udp_path)]

      ;; Calculate L4 header offset
      [(dsl/mov :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :w :r10 :r0 -32)]

      ;; Calculate L4 header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))]

      ;; Check UDP header bounds
      [(dsl/mov-reg :r1 :r0)
       (dsl/add :r1 4)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Load UDP ports and build reverse key
      [(dsl/ldx :h :r1 :r0 0)           ; src_port (backend)
       (dsl/stx :h :r10 :r1 -24)        ; old_src_port
       (dsl/stx :h :r10 :r1 -6)]        ; key.dst_port

      [(dsl/ldx :h :r1 :r0 2)           ; dst_port (client)
       (dsl/stx :h :r10 :r1 -8)]        ; key.src_port

      ;; Store protocol and padding
      [(dsl/ldx :b :r0 :r10 -28)
       (dsl/stx :b :r10 :r0 -4)
       (dsl/mov :r0 0)
       (dsl/stx :b :r10 :r0 -3)
       (dsl/stx :h :r10 :r0 -2)]

      ;; Fall through to lookup_conntrack

      ;; =====================================================================
      ;; PHASE 4: Conntrack Lookup
      ;; =====================================================================
      [(asm/label :lookup_conntrack)]

      ;; Call bpf_map_lookup_elem(conntrack_map, &key)
      (if conntrack-map-fd
        (concat
          [(dsl/ld-map-fd :r1 conntrack-map-fd)
           (dsl/mov-reg :r2 :r10)
           (dsl/add :r2 -16)              ; r2 = &key (stack[-16])
           (dsl/call 1)]                   ; bpf_map_lookup_elem
          ;; r0 = value ptr or NULL
          [(asm/jmp-imm :jeq :r0 0 :pass) ; no entry = not tracked, pass through
           ;; Save map value pointer in r9
           (dsl/mov-reg :r9 :r0)
           (asm/jmp :do_snat)])
        ;; No conntrack map - pass all traffic
        [(asm/jmp :pass)])

      ;; =====================================================================
      ;; PHASE 5: Update Conntrack Stats and Perform SNAT
      ;; =====================================================================
      [(asm/label :do_snat)]

      ;; r9 = pointer to conntrack value (64 bytes, see layout in header)
      ;; We want to:
      ;; 1. Update timestamps and stats
      ;; 2. Rewrite: src_ip -> orig_dst_ip, src_port -> orig_dst_port

      ;; --- Update last_seen_ns timestamp ---
      [(dsl/call BPF-FUNC-ktime-get-ns)   ; r0 = current time in ns
       (dsl/stx :dw :r9 :r0 24)]          ; value->last_seen_ns (offset 24)

      ;; --- Increment packets_rev counter ---
      [(dsl/ldx :dw :r0 :r9 40)           ; r0 = value->packets_rev
       (dsl/add :r0 1)                    ; r0++
       (dsl/stx :dw :r9 :r0 40)]          ; value->packets_rev = r0

      ;; --- Add packet length to bytes_rev ---
      ;; Get packet length from SKB->len (offset 0 in __sk_buff)
      [(dsl/ldx :w :r1 :r6 0)             ; r1 = skb->len
       (dsl/ldx :dw :r0 :r9 56)           ; r0 = value->bytes_rev
       (dsl/add-reg :r0 :r1)              ; r0 += packet_len
       (dsl/stx :dw :r9 :r0 56)]          ; value->bytes_rev = r0

      ;; --- Load the new source values from conntrack ---
      ;; new_src_ip = orig_dst_ip (offset 0)
      ;; new_src_port = orig_dst_port (offset 4)
      ;; Stack layout: -40 to -37 = new_src_ip (4 bytes), -36 to -35 = new_src_port (2 bytes)
      [(dsl/ldx :w :r1 :r9 0)           ; r1 = new_src_ip (orig_dst_ip)
       (dsl/stx :w :r10 :r1 -40)]       ; save at stack[-40] (bytes -40 to -37)

      [(dsl/ldx :h :r2 :r9 4)           ; r2 = new_src_port (orig_dst_port)
       (dsl/stx :h :r10 :r2 -36)]       ; save at stack[-36] (bytes -36 to -35, no overlap)

      ;; Branch by protocol for checksum calculation
      [(dsl/ldx :b :r0 :r10 -28)        ; load protocol
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_snat)
       (asm/jmp :udp_snat)]

      ;; =====================================================================
      ;; TCP SNAT: Update checksums and write new values
      ;; =====================================================================
      [(asm/label :tcp_snat)]

      ;; --- Update IP Checksum for src_ip change ---
      ;; bpf_l3_csum_replace(skb, csum_offset, old_val, new_val, flags)
      ;; IP checksum is at ETH_HLEN + 10 = 24
      [(dsl/mov-reg :r1 :r6)            ; r1 = skb
       (dsl/mov :r2 (+ net/ETH-HLEN 10)) ; r2 = IP checksum offset (14 + 10 = 24)
       (dsl/ldx :w :r3 :r10 -20)        ; r3 = old_src_ip
       (dsl/ldx :w :r4 :r10 -40)        ; r4 = new_src_ip
       (dsl/mov :r5 4)                  ; r5 = sizeof(u32)
       (dsl/call BPF-FUNC-l3-csum-replace)]

      ;; --- Update TCP Checksum for src_ip change (pseudo-header) ---
      ;; TCP checksum is at ETH_HLEN + IPV4_MIN_HLEN + 16 = 50
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 16)) ; TCP checksum offset = 50
       (dsl/ldx :w :r3 :r10 -20)        ; old_src_ip
       (dsl/ldx :w :r4 :r10 -40)        ; new_src_ip
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4)) ; flags: pseudo-header + sizeof
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; --- Update TCP Checksum for src_port change ---
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 16)) ; TCP checksum offset
       (dsl/ldx :h :r3 :r10 -24)        ; old_src_port
       (dsl/ldx :h :r4 :r10 -36)        ; new_src_port
       (dsl/mov :r5 2)                  ; sizeof(u16), no pseudo-header for port
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; --- Write new src_ip to IP header ---
      ;; Need to reload data pointer and re-check bounds
      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 54)                 ; 14 + 20 + 20 = 54 for TCP header access
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Get IP header pointer
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)       ; r9 = IP header
       (dsl/ldx :w :r1 :r10 -40)        ; r1 = new_src_ip
       (dsl/stx :w :r9 :r1 12)]         ; ip->saddr = new_src_ip

      ;; --- Write new src_port to TCP header ---
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r10 -36)        ; r1 = new_src_port
       (dsl/stx :h :r0 :r1 0)]          ; tcp->sport = new_src_port

      [(asm/jmp :done)]

      ;; =====================================================================
      ;; UDP SNAT: Update checksums and write new values
      ;; =====================================================================
      [(asm/label :udp_snat)]

      ;; --- Update IP Checksum for src_ip change ---
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN 10))
       (dsl/ldx :w :r3 :r10 -20)
       (dsl/ldx :w :r4 :r10 -40)
       (dsl/mov :r5 4)
       (dsl/call BPF-FUNC-l3-csum-replace)]

      ;; --- Check if UDP checksum is enabled (non-zero) ---
      ;; Reload data pointer and re-check bounds
      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 42)                 ; 14 + 20 + 8 = 42 for UDP header access
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r0 6)]          ; UDP checksum at offset 6
      [(asm/jmp-imm :jeq :r1 0 :udp_write_values)] ; skip L4 csum if disabled

      ;; --- Update UDP Checksum for src_ip change (pseudo-header) ---
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 6)) ; UDP checksum offset = 40
       (dsl/ldx :w :r3 :r10 -20)
       (dsl/ldx :w :r4 :r10 -40)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; --- Update UDP Checksum for src_port change ---
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 6))
       (dsl/ldx :h :r3 :r10 -24)
       (dsl/ldx :h :r4 :r10 -36)        ; new_src_port at -36
       (dsl/mov :r5 2)
       (dsl/call BPF-FUNC-l4-csum-replace)]

      [(asm/label :udp_write_values)]

      ;; --- Write new values ---
      ;; Reload data pointer and re-check bounds
      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 42)                 ; 14 + 20 + 8 = 42 for UDP write access
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Write new src_ip to IP header
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -40)
       (dsl/stx :w :r9 :r1 12)]

      ;; Write new src_port to UDP header
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r10 -36)        ; new_src_port at -36
       (dsl/stx :h :r0 :r1 0)]

      ;; Fall through to done

      ;; =====================================================================
      ;; Return TC_ACT_OK
      ;; =====================================================================
      [(asm/label :done)]
      (net/return-action net/TC-ACT-OK)

      [(asm/label :pass)]
      (net/return-action net/TC-ACT-OK))))

;;; =============================================================================
;;; Unified TC Egress Program with IPv4/IPv6 Dual-Stack Support
;;; =============================================================================

(defn build-tc-snat-program-unified
  "Build unified TC egress program that performs SNAT on both IPv4 and IPv6 reply packets.

   This program supports dual-stack operation:
   1. Parses EtherType and branches for IPv4 or IPv6
   2. Builds reverse 5-tuple key using unified 16-byte addresses
   3. Looks up conntrack map with 40-byte key
   4. If found, performs SNAT (rewrites src IP and port)
   5. Updates checksums (IP header for IPv4 only, L4 for both)
   6. Returns TC_ACT_OK

   Uses unified conntrack key format:
   - 40 bytes: src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2) + proto(1) + pad(3)

   Register allocation:
   r6 = saved SKB context (callee-saved)
   r7 = data pointer (callee-saved)
   r8 = data_end pointer (callee-saved)
   r9 = IP header pointer / map value ptr (callee-saved)
   r0-r5 = scratch, clobbered by helpers"
  [conntrack-map-fd]
  (asm/assemble-with-labels
    (concat
      ;; =====================================================================
      ;; PHASE 1: Context Setup and Ethernet Parsing
      ;; =====================================================================

      ;; Save SKB context to callee-saved register
      [(dsl/mov-reg :r6 :r1)]

      ;; Load data and data_end pointers from SKB context
      (tc-load-data-ptrs-32 :r7 :r8 :r1)

      ;; Check Ethernet header bounds
      (asm/check-bounds :r7 :r8 net/ETH-HLEN :pass_unified :r9)

      ;; Load ethertype
      (eth/load-ethertype :r9 :r7)

      ;; Branch on EtherType: IPv4 or IPv6
      [(asm/jmp-imm :jeq :r9 common/ETH-P-IP-BE :ipv4_tc_path)
       (asm/jmp-imm :jeq :r9 common/ETH-P-IPV6-BE :ipv6_tc_path)
       (asm/jmp :pass_unified)]

      ;; =====================================================================
      ;; IPv4 Path: Parse IPv4 header and build unified conntrack key
      ;; =====================================================================
      [(asm/label :ipv4_tc_path)]

      ;; Store address family (4 = IPv4)
      [(dsl/mov :r0 4)
       (dsl/stx :b :r10 :r0 -62)]

      ;; Calculate IP header pointer: data + ETH_HLEN
      (eth/get-ip-header-ptr :r9 :r7)

      ;; Check IP header bounds (minimum 20 bytes)
      (asm/check-bounds :r9 :r8 net/IPV4-MIN-HLEN :pass_unified :r0)

      ;; Load and store protocol
      [(dsl/ldx :b :r0 :r9 9)
       (dsl/stx :b :r10 :r0 -61)]

      ;; For reply packet from backend to client:
      ;; - src_ip = backend, dst_ip = client
      ;; - For conntrack lookup, we need REVERSE key: key.src = client, key.dst = backend

      ;; Load source IP (backend) - store as old_src_ip (unified 16-byte) and key.dst_ip
      ;; Zero-pad for unified format
      [(dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -56)        ; zero bytes 0-7 of old_src_ip
       (dsl/stx :w :r10 :r0 -48)         ; zero bytes 8-11 of old_src_ip
       (dsl/ldx :w :r0 :r9 12)           ; load src_ip (4 bytes)
       (dsl/stx :w :r10 :r0 -44)]        ; store at bytes 12-15 of old_src_ip

      ;; key.dst_ip = backend (16 bytes, zero-padded)
      [(dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -24)        ; zero bytes 0-7 of key.dst_ip at -40+16=-24
       (dsl/stx :w :r10 :r0 -16)         ; zero bytes 8-11
       (dsl/ldx :w :r0 :r9 12)           ; src_ip (backend)
       (dsl/stx :w :r10 :r0 -12)]        ; store at bytes 12-15 of key.dst_ip

      ;; Load destination IP (client) - store as key.src_ip
      [(dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -40)        ; zero bytes 0-7 of key.src_ip
       (dsl/stx :w :r10 :r0 -32)         ; zero bytes 8-11
       (dsl/ldx :w :r0 :r9 16)           ; dst_ip (client)
       (dsl/stx :w :r10 :r0 -28)]        ; store at bytes 12-15 of key.src_ip

      ;; Store L4 header offset
      [(dsl/mov :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :w :r10 :r0 -68)]

      [(asm/jmp :protocol_tc_dispatch)]

      ;; =====================================================================
      ;; IPv6 Path: Parse IPv6 header and build unified conntrack key
      ;; =====================================================================
      [(asm/label :ipv6_tc_path)]

      ;; Store address family (6 = IPv6)
      [(dsl/mov :r0 6)
       (dsl/stx :b :r10 :r0 -62)]

      ;; Check IPv6 header bounds (fixed 40 bytes)
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (asm/jmp-reg :jgt :r0 :r8 :pass_unified)]

      ;; Get IPv6 header pointer
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)]

      ;; Load and store Next Header (protocol)
      [(dsl/ldx :b :r0 :r9 common/IPV6-OFF-NEXT-HEADER)
       (dsl/stx :b :r10 :r0 -61)]

      ;; Load source IP (backend, 16 bytes) - store as old_src_ip
      [(dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 0))
       (dsl/stx :w :r10 :r0 -56)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 4))
       (dsl/stx :w :r10 :r0 -52)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 8))
       (dsl/stx :w :r10 :r0 -48)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 12))
       (dsl/stx :w :r10 :r0 -44)]

      ;; key.dst_ip = backend (16 bytes)
      [(dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 0))
       (dsl/stx :w :r10 :r0 -24)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 4))
       (dsl/stx :w :r10 :r0 -20)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 8))
       (dsl/stx :w :r10 :r0 -16)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 12))
       (dsl/stx :w :r10 :r0 -12)]

      ;; Load destination IP (client, 16 bytes) - store as key.src_ip
      [(dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 0))
       (dsl/stx :w :r10 :r0 -40)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 4))
       (dsl/stx :w :r10 :r0 -36)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 8))
       (dsl/stx :w :r10 :r0 -32)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 12))
       (dsl/stx :w :r10 :r0 -28)]

      ;; Store L4 header offset
      [(dsl/mov :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (dsl/stx :w :r10 :r0 -68)]

      ;; Fall through to protocol dispatch

      ;; =====================================================================
      ;; PHASE 2: Protocol Dispatch
      ;; =====================================================================
      [(asm/label :protocol_tc_dispatch)]

      [(dsl/ldx :b :r0 :r10 -61)         ; load protocol
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_tc_path_unified)
       (asm/jmp-imm :jeq :r0 net/IPPROTO-UDP :udp_tc_path_unified)
       (asm/jmp :pass_unified)]

      ;; =====================================================================
      ;; TCP Path: Extract ports and complete conntrack key
      ;; =====================================================================
      [(asm/label :tcp_tc_path_unified)]

      ;; Get L4 header offset
      [(dsl/ldx :w :r1 :r10 -68)]

      ;; Calculate L4 header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add-reg :r0 :r1)]

      ;; Check TCP header bounds
      [(dsl/mov-reg :r1 :r0)
       (dsl/add :r1 4)
       (asm/jmp-reg :jgt :r1 :r8 :pass_unified)]

      ;; Load ports and build reverse key
      ;; Reply has: src=backend_port, dst=client_port
      ;; Key needs: src_port=client_port, dst_port=backend_port
      [(dsl/ldx :h :r1 :r0 0)            ; src_port (backend)
       (dsl/stx :h :r10 :r1 -60)         ; old_src_port
       (dsl/stx :h :r10 :r1 -6)]         ; key.dst_port at -40+32+2=-6

      [(dsl/ldx :h :r1 :r0 2)            ; dst_port (client)
       (dsl/stx :h :r10 :r1 -8)]         ; key.src_port at -40+32=-8

      ;; Store protocol and padding
      [(dsl/ldx :b :r0 :r10 -61)
       (dsl/stx :b :r10 :r0 -4)          ; key.protocol
       (dsl/mov :r0 0)
       (dsl/stx :b :r10 :r0 -3)          ; pad[0]
       (dsl/stx :h :r10 :r0 -2)]         ; pad[1-2]

      [(asm/jmp :lookup_conntrack_unified)]

      ;; =====================================================================
      ;; UDP Path: Extract ports and complete conntrack key
      ;; =====================================================================
      [(asm/label :udp_tc_path_unified)]

      [(dsl/ldx :w :r1 :r10 -68)]

      [(dsl/mov-reg :r0 :r7)
       (dsl/add-reg :r0 :r1)]

      [(dsl/mov-reg :r1 :r0)
       (dsl/add :r1 4)
       (asm/jmp-reg :jgt :r1 :r8 :pass_unified)]

      [(dsl/ldx :h :r1 :r0 0)
       (dsl/stx :h :r10 :r1 -60)
       (dsl/stx :h :r10 :r1 -6)]

      [(dsl/ldx :h :r1 :r0 2)
       (dsl/stx :h :r10 :r1 -8)]

      [(dsl/ldx :b :r0 :r10 -61)
       (dsl/stx :b :r10 :r0 -4)
       (dsl/mov :r0 0)
       (dsl/stx :b :r10 :r0 -3)
       (dsl/stx :h :r10 :r0 -2)]

      ;; Fall through to lookup_conntrack_unified

      ;; =====================================================================
      ;; PHASE 3: Conntrack Lookup (40-byte key)
      ;; =====================================================================
      [(asm/label :lookup_conntrack_unified)]

      (if conntrack-map-fd
        (concat
          [(dsl/ld-map-fd :r1 conntrack-map-fd)
           (dsl/mov-reg :r2 :r10)
           (dsl/add :r2 -40)              ; r2 = &key (40 bytes)
           (dsl/call 1)]
          [(asm/jmp-imm :jeq :r0 0 :pass_unified)
           (dsl/mov-reg :r9 :r0)
           (asm/jmp :do_snat_unified)])
        [(asm/jmp :pass_unified)])

      ;; =====================================================================
      ;; PHASE 4: Update Stats and Load New Source Values
      ;; =====================================================================
      [(asm/label :do_snat_unified)]

      ;; r9 = pointer to unified conntrack value (128 bytes)
      ;; Layout: orig_dst_ip(16) + orig_dst_port(2) + pad(2) +
      ;;         nat_dst_ip(16) + nat_dst_port(2) + pad(2) +
      ;;         timestamps and counters ...
      ;;         PROXY protocol fields at offset 96:
      ;;           conn_state(1) + proxy_flags(1) + pad(2) +
      ;;           seq_offset(4) + orig_client_ip(16) + orig_client_port(2) + pad(6)

      ;; Update last_seen_ns (at offset 40 in unified format)
      [(dsl/call BPF-FUNC-ktime-get-ns)
       (dsl/stx :dw :r9 :r0 40)]

      ;; Increment packets_rev (at offset 56)
      [(dsl/ldx :dw :r0 :r9 56)
       (dsl/add :r0 1)
       (dsl/stx :dw :r9 :r0 56)]

      ;; Update bytes_rev (at offset 72)
      [(dsl/ldx :w :r1 :r6 0)            ; skb->len
       (dsl/ldx :dw :r0 :r9 72)
       (dsl/add-reg :r0 :r1)
       (dsl/stx :dw :r9 :r0 72)]

      ;; Load new_src_ip (orig_dst_ip, 16 bytes at offset 0)
      [(dsl/ldx :w :r0 :r9 0)
       (dsl/stx :w :r10 :r0 -84)
       (dsl/ldx :w :r0 :r9 4)
       (dsl/stx :w :r10 :r0 -80)
       (dsl/ldx :w :r0 :r9 8)
       (dsl/stx :w :r10 :r0 -76)
       (dsl/ldx :w :r0 :r9 12)
       (dsl/stx :w :r10 :r0 -72)]

      ;; Load new_src_port (at offset 16)
      [(dsl/ldx :h :r0 :r9 16)
       (dsl/stx :h :r10 :r0 -88)]

      ;; Load seq_offset from conntrack (offset 100) for PROXY protocol ACK adjustment
      ;; If PROXY header was injected, seq_offset will be non-zero (28 for IPv4, 52 for IPv6)
      ;; We need to subtract this from the ACK number in reply packets
      [(dsl/ldx :w :r0 :r9 100)          ; seq_offset at conntrack offset 100
       (dsl/stx :w :r10 :r0 -92)]        ; Save to stack[-92]

      ;; Branch by address family for SNAT
      [(dsl/ldx :b :r0 :r10 -62)
       (asm/jmp-imm :jeq :r0 4 :ipv4_snat_unified)
       (asm/jmp :ipv6_snat_unified)]

      ;; =====================================================================
      ;; IPv4 SNAT: Update IP checksum, L4 checksum, write values
      ;; =====================================================================
      [(asm/label :ipv4_snat_unified)]

      ;; Branch by protocol
      [(dsl/ldx :b :r0 :r10 -61)
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_snat_v4_unified)
       (asm/jmp :udp_snat_v4_unified)]

      ;; =====================================================================
      ;; IPv4 TCP SNAT
      ;; =====================================================================
      [(asm/label :tcp_snat_v4_unified)]

      ;; For IPv4, the actual IP is at bytes 12-15 of the 16-byte field
      ;; old_src_ip at [-44], new_src_ip at [-72]

      ;; Update IP checksum for src_ip change
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN 10))
       (dsl/ldx :w :r3 :r10 -44)         ; old_src_ip (4 bytes from unified)
       (dsl/ldx :w :r4 :r10 -72)         ; new_src_ip (4 bytes from unified)
       (dsl/mov :r5 4)
       (dsl/call BPF-FUNC-l3-csum-replace)]

      ;; Update TCP checksum for src_ip (pseudo-header)
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 16))
       (dsl/ldx :w :r3 :r10 -44)
       (dsl/ldx :w :r4 :r10 -72)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; Update TCP checksum for src_port
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 16))
       (dsl/ldx :h :r3 :r10 -60)
       (dsl/ldx :h :r4 :r10 -88)
       (dsl/mov :r5 2)
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; Write new values
      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 54)
       (asm/jmp-reg :jgt :r1 :r8 :pass_unified)]

      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -72)
       (dsl/stx :w :r9 :r1 12)]          ; ip->saddr

      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r10 -88)
       (dsl/stx :h :r0 :r1 0)]           ; tcp->sport

      ;; Check if PROXY header was injected (seq_offset != 0)
      ;; If so, adjust ACK number: tcp->ack_seq -= seq_offset
      [(dsl/ldx :w :r1 :r10 -92)         ; Load seq_offset from stack
       (asm/jmp-imm :jeq :r1 0 :done_unified)] ; Skip if zero

      ;; ACK adjustment for PROXY protocol (IPv4)
      ;; Need to reload data pointer and check bounds
      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 12)) ; Need access to ack_seq
       (asm/jmp-reg :jgt :r0 :r8 :done_unified)]

      ;; Get TCP header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))]

      ;; Load current ACK, subtract seq_offset, store back
      [(dsl/ldx :w :r2 :r0 8)            ; r2 = old ack_seq (at TCP offset 8)
       (dsl/mov-reg :r3 :r2)             ; Save old for checksum
       (dsl/end-to-be :r2 32)            ; Network to host byte order
       (dsl/ldx :w :r1 :r10 -92)         ; Reload seq_offset
       (dsl/sub-reg :r2 :r1)             ; Subtract seq_offset
       (dsl/end-to-be :r2 32)            ; Host to network byte order
       (dsl/stx :w :r0 :r2 8)]           ; Store new ack_seq

      ;; Update TCP checksum for ACK change
      [(dsl/mov-reg :r1 :r6)             ; r1 = skb
       (dsl/mov :r2 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 16)) ; TCP checksum offset
                                          ; r3 = old ack (already set above)
       (dsl/ldx :w :r4 :r0 8)            ; r4 = new ack
       (dsl/mov :r5 4)                   ; sizeof(u32)
       (dsl/call BPF-FUNC-l4-csum-replace)]

      [(asm/jmp :done_unified)]

      ;; =====================================================================
      ;; IPv4 UDP SNAT
      ;; =====================================================================
      [(asm/label :udp_snat_v4_unified)]

      ;; Update IP checksum
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN 10))
       (dsl/ldx :w :r3 :r10 -44)
       (dsl/ldx :w :r4 :r10 -72)
       (dsl/mov :r5 4)
       (dsl/call BPF-FUNC-l3-csum-replace)]

      ;; Check if UDP checksum is enabled
      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 42)
       (asm/jmp-reg :jgt :r1 :r8 :pass_unified)]

      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r0 6)]
      [(asm/jmp-imm :jeq :r1 0 :udp_write_v4_unified)]

      ;; Update UDP checksum
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 6))
       (dsl/ldx :w :r3 :r10 -44)
       (dsl/ldx :w :r4 :r10 -72)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 6))
       (dsl/ldx :h :r3 :r10 -60)
       (dsl/ldx :h :r4 :r10 -88)
       (dsl/mov :r5 2)
       (dsl/call BPF-FUNC-l4-csum-replace)]

      [(asm/label :udp_write_v4_unified)]

      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 42)
       (asm/jmp-reg :jgt :r1 :r8 :pass_unified)]

      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -72)
       (dsl/stx :w :r9 :r1 12)]

      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r10 -88)
       (dsl/stx :h :r0 :r1 0)]

      [(asm/jmp :done_unified)]

      ;; =====================================================================
      ;; IPv6 SNAT: No IP checksum, only L4 checksum
      ;; =====================================================================
      [(asm/label :ipv6_snat_unified)]

      [(dsl/ldx :b :r0 :r10 -61)
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_snat_v6_unified)
       (asm/jmp :udp_snat_v6_unified)]

      ;; =====================================================================
      ;; IPv6 TCP SNAT
      ;; =====================================================================
      [(asm/label :tcp_snat_v6_unified)]

      ;; For IPv6, we need to update TCP checksum for 16-byte address change
      ;; TC program can use l4_csum_replace, but we need multiple calls for 16-byte data
      ;; old_src_ip at [-56..-41], new_src_ip at [-84..-69]

      ;; Update TCP checksum for each 4-byte word of the 16-byte address
      ;; Word 0
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 16))
       (dsl/ldx :w :r3 :r10 -56)
       (dsl/ldx :w :r4 :r10 -84)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; Word 1
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 16))
       (dsl/ldx :w :r3 :r10 -52)
       (dsl/ldx :w :r4 :r10 -80)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; Word 2
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 16))
       (dsl/ldx :w :r3 :r10 -48)
       (dsl/ldx :w :r4 :r10 -76)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; Word 3
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 16))
       (dsl/ldx :w :r3 :r10 -44)
       (dsl/ldx :w :r4 :r10 -72)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; Update TCP checksum for port change
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 16))
       (dsl/ldx :h :r3 :r10 -60)
       (dsl/ldx :h :r4 :r10 -88)
       (dsl/mov :r5 2)
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; Write new values
      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 (+ net/ETH-HLEN common/IPV6-HLEN 20))
       (asm/jmp-reg :jgt :r1 :r8 :pass_unified)]

      ;; Write new src_ip to IPv6 header
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -84)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-SRC 0))
       (dsl/ldx :w :r1 :r10 -80)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-SRC 4))
       (dsl/ldx :w :r1 :r10 -76)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-SRC 8))
       (dsl/ldx :w :r1 :r10 -72)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-SRC 12))]

      ;; Write new src_port to TCP header
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (dsl/ldx :h :r1 :r10 -88)
       (dsl/stx :h :r0 :r1 0)]

      ;; Check if PROXY header was injected (seq_offset != 0)
      ;; If so, adjust ACK number: tcp->ack_seq -= seq_offset
      [(dsl/ldx :w :r1 :r10 -92)         ; Load seq_offset from stack
       (asm/jmp-imm :jeq :r1 0 :done_unified)] ; Skip if zero

      ;; ACK adjustment for PROXY protocol (IPv6)
      ;; Need to reload data pointer and check bounds
      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN 12)) ; Need access to ack_seq
       (asm/jmp-reg :jgt :r0 :r8 :done_unified)]

      ;; Get TCP header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))]

      ;; Load current ACK, subtract seq_offset, store back
      [(dsl/ldx :w :r2 :r0 8)            ; r2 = old ack_seq (at TCP offset 8)
       (dsl/mov-reg :r3 :r2)             ; Save old for checksum
       (dsl/end-to-be :r2 32)            ; Network to host byte order
       (dsl/ldx :w :r1 :r10 -92)         ; Reload seq_offset
       (dsl/sub-reg :r2 :r1)             ; Subtract seq_offset
       (dsl/end-to-be :r2 32)            ; Host to network byte order
       (dsl/stx :w :r0 :r2 8)]           ; Store new ack_seq

      ;; Update TCP checksum for ACK change
      [(dsl/mov-reg :r1 :r6)             ; r1 = skb
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 16)) ; TCP checksum offset
                                          ; r3 = old ack (already set above)
       (dsl/ldx :w :r4 :r0 8)            ; r4 = new ack
       (dsl/mov :r5 4)                   ; sizeof(u32)
       (dsl/call BPF-FUNC-l4-csum-replace)]

      [(asm/jmp :done_unified)]

      ;; =====================================================================
      ;; IPv6 UDP SNAT
      ;; =====================================================================
      [(asm/label :udp_snat_v6_unified)]

      ;; Check UDP checksum (mandatory for IPv6, but check anyway)
      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 (+ net/ETH-HLEN common/IPV6-HLEN 8))
       (asm/jmp-reg :jgt :r1 :r8 :pass_unified)]

      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (dsl/ldx :h :r1 :r0 6)]
      [(asm/jmp-imm :jeq :r1 0 :udp_write_v6_unified)]

      ;; Update UDP checksum for 16-byte address (4 words)
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 6))
       (dsl/ldx :w :r3 :r10 -56)
       (dsl/ldx :w :r4 :r10 -84)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 6))
       (dsl/ldx :w :r3 :r10 -52)
       (dsl/ldx :w :r4 :r10 -80)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 6))
       (dsl/ldx :w :r3 :r10 -48)
       (dsl/ldx :w :r4 :r10 -76)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 6))
       (dsl/ldx :w :r3 :r10 -44)
       (dsl/ldx :w :r4 :r10 -72)
       (dsl/mov :r5 (bit-or BPF-F-PSEUDO-HDR 4))
       (dsl/call BPF-FUNC-l4-csum-replace)]

      ;; Update UDP checksum for port change
      [(dsl/mov-reg :r1 :r6)
       (dsl/mov :r2 (+ net/ETH-HLEN common/IPV6-HLEN 6))
       (dsl/ldx :h :r3 :r10 -60)
       (dsl/ldx :h :r4 :r10 -88)
       (dsl/mov :r5 2)
       (dsl/call BPF-FUNC-l4-csum-replace)]

      [(asm/label :udp_write_v6_unified)]

      (tc-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 (+ net/ETH-HLEN common/IPV6-HLEN 8))
       (asm/jmp-reg :jgt :r1 :r8 :pass_unified)]

      ;; Write new src_ip
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -84)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-SRC 0))
       (dsl/ldx :w :r1 :r10 -80)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-SRC 4))
       (dsl/ldx :w :r1 :r10 -76)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-SRC 8))
       (dsl/ldx :w :r1 :r10 -72)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-SRC 12))]

      ;; Write new src_port
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (dsl/ldx :h :r1 :r10 -88)
       (dsl/stx :h :r0 :r1 0)]

      ;; Fall through to done_unified

      ;; =====================================================================
      ;; Return TC_ACT_OK
      ;; =====================================================================
      [(asm/label :done_unified)]
      (net/return-action net/TC-ACT-OK)

      [(asm/label :pass_unified)]
      (net/return-action net/TC-ACT-OK))))

(defn build-tc-egress-program-unified
  "Build the unified TC egress program for IPv4/IPv6 dual-stack.

   Performs SNAT on reply packets from backends:
   1. Branches on EtherType (IPv4 or IPv6)
   2. Builds reverse 5-tuple key with unified format
   3. Looks up unified conntrack map
   4. If found, rewrites source IP/port
   5. Updates checksums
   6. Returns TC_ACT_OK

   map-fds: Map containing unified :conntrack-map"
  [map-fds]
  (let [conntrack-map-fd (when (and (map? map-fds) (:conntrack-map map-fds))
                           (common/map-fd (:conntrack-map map-fds)))]
    (build-tc-snat-program-unified conntrack-map-fd)))

(defn load-program-unified
  "Load the unified TC egress program for IPv4/IPv6 dual-stack.
   Returns a BpfProgram record."
  [maps]
  (log/info "Loading unified TC egress program (IPv4/IPv6)")
  (let [bytecode (build-tc-egress-program-unified maps)]
    (require '[clj-ebpf.programs :as programs])
    ((resolve 'clj-ebpf.programs/load-program)
      {:insns bytecode
       :prog-type :sched-cls
       :prog-name "tc_egress_v6"
       :license "GPL"
       :log-level 1})))

(defn build-tc-egress-program
  "Build the TC egress program.

   Performs SNAT on reply packets from backends:
   1. Parses IPv4/TCP/UDP headers
   2. Builds reverse 5-tuple key from reply packet
   3. Looks up conntrack map to find original destination
   4. If found, rewrites source IP/port to original destination
   5. Updates checksums using kernel helpers
   6. Returns TC_ACT_OK

   map-fds: Map containing :conntrack-map"
  [map-fds]
  (let [conntrack-map-fd (when (and (map? map-fds) (:conntrack-map map-fds))
                           (common/map-fd (:conntrack-map map-fds)))]
    (build-tc-snat-program conntrack-map-fd)))

;;; =============================================================================
;;; Program Loading and Attachment
;;; =============================================================================

(defn load-program
  "Load the TC egress program.
   Returns a BpfProgram record."
  [maps]
  (log/info "Loading TC egress program")
  (let [bytecode (build-tc-egress-program maps)]
    (require '[clj-ebpf.programs :as programs])
    ((resolve 'clj-ebpf.programs/load-program)
      {:insns bytecode
       :prog-type :sched-cls
       :prog-name "tc_egress"
       :license "GPL"
       :log-level 1})))

(defn attach-to-interface
  "Attach TC egress program to a network interface.

   prog: BpfProgram record or program FD
   iface: Interface name (e.g., \"eth0\")
   priority: Filter priority (lower = higher priority)"
  [prog iface & {:keys [priority] :or {priority 1}}]
  (log/info "Attaching TC egress program to" iface "with priority" priority)
  (let [prog-fd (if (number? prog) prog (:fd prog))]
    (bpf/attach-tc-filter iface prog-fd :egress
                          :priority priority
                          :prog-name "tc_egress")))

(defn attach-to-interfaces
  "Attach TC egress program to multiple interfaces."
  [prog interfaces & opts]
  (doseq [iface interfaces]
    (apply attach-to-interface prog iface opts)))

(defn detach-from-interface
  "Detach TC egress program from an interface."
  [iface & {:keys [priority] :or {priority 1}}]
  (log/info "Detaching TC egress program from" iface)
  (try
    (bpf/detach-tc-filter iface :egress priority)
    (catch Exception e
      (log/warn "Failed to detach TC from" iface ":" (.getMessage e)))))

(defn detach-from-interfaces
  "Detach TC egress program from multiple interfaces."
  [interfaces & opts]
  (doseq [iface interfaces]
    (apply detach-from-interface iface opts)))

;;; =============================================================================
;;; TC Setup Utilities
;;; =============================================================================

(defn setup-tc-qdisc
  "Set up clsact qdisc on an interface (required for TC attachment)."
  [iface]
  (log/info "Setting up clsact qdisc on" iface)
  (try
    (bpf/add-clsact-qdisc iface)
    (catch Exception e
      ;; Ignore errors if qdisc already exists
      (when-not (re-find #"File exists|Exclusivity flag|already exists" (str e))
        (log/warn "Failed to add clsact qdisc:" (.getMessage e))))))

(defn teardown-tc-qdisc
  "Remove clsact qdisc from an interface."
  [iface]
  (log/info "Tearing down clsact qdisc on" iface)
  (try
    (bpf/remove-clsact-qdisc iface)
    (catch Exception e
      (log/warn "Failed to remove qdisc from" iface ":" (.getMessage e)))))

;;; =============================================================================
;;; Program Verification
;;; =============================================================================

(defn verify-program
  "Verify the TC program can be loaded (dry run).
   Returns {:valid true} or {:valid false :error <message>}"
  [maps]
  (try
    (let [prog (load-program maps)]
      (bpf/close-program prog)
      {:valid true})
    (catch Exception e
      {:valid false
       :error (.getMessage e)})))

;;; =============================================================================
;;; Debug Utilities
;;; =============================================================================

(defn dump-program-bytecode
  "Dump program bytecode for debugging."
  [maps]
  (let [bytecode (build-tc-egress-program maps)]
    (println "TC Egress Program Bytecode:")
    (println "===========================")
    (println "Length:" (count bytecode) "bytes")
    (println "Instructions:" (/ (count bytecode) 8))
    (doseq [[idx b] (map-indexed vector bytecode)]
      (print (format "%02x " b))
      (when (= 7 (mod idx 8))
        (println)))))
