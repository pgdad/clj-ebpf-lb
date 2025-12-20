(ns reverse-proxy.programs.xdp-ingress
  "XDP ingress program for the reverse proxy.
   Handles incoming packets: parses headers, looks up routing, performs DNAT."
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
            [reverse-proxy.programs.common :as common]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; XDP Program Structure
;;; =============================================================================

;; Register allocation:
;; r1 = XDP context (input, clobbered by helpers)
;; r6 = saved XDP context (callee-saved)
;; r7 = data pointer (callee-saved)
;; r8 = data_end pointer (callee-saved)
;; r9 = IP header pointer / map value ptr (callee-saved)
;; r0-r5 = scratch, clobbered by helper calls

;; Stack layout (negative offsets from r10):
;; -8   : Listen map key (8 bytes: ifindex(4) + port(2) + pad(2))
;; -16  : LPM key (8 bytes: prefix_len(4) + ip(4))
;; -24  : old_dst_ip (4 bytes)
;; -28  : old_dst_port (2 bytes) + pad (2 bytes)
;; -32  : nat_dst_ip (4 bytes)
;; -36  : nat_dst_port (2 bytes) + pad (2 bytes)
;; -40  : src_ip (4 bytes)
;; -44  : dst_ip original (4 bytes)
;; -48  : src_port (2 bytes)
;; -50  : dst_port original (2 bytes)
;; -52  : protocol (1 byte) + pad (3 bytes)
;; -56  : L4 header offset from data (4 bytes)
;; -64  : checksum scratch (8 bytes)
;; -72  : additional scratch (8 bytes)
;; -88  : Conntrack key (16 bytes: src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) + proto(1) + pad(3))
;; -152 : Conntrack value (64 bytes):
;;        offset 0:  orig_dst_ip (4) - proxy's IP for SNAT to restore
;;        offset 4:  orig_dst_port (2) - proxy's port
;;        offset 6:  pad (2)
;;        offset 8:  nat_dst_ip (4) - backend's IP
;;        offset 12: nat_dst_port (2) - backend's port
;;        offset 14: pad (2)
;;        offset 16: created_ns (8) - entry creation timestamp
;;        offset 24: last_seen_ns (8) - last packet timestamp
;;        offset 32: packets_fwd (8) - forward direction packet count
;;        offset 40: packets_rev (8) - reverse direction packet count
;;        offset 48: bytes_fwd (8) - forward direction byte count
;;        offset 56: bytes_rev (8) - reverse direction byte count

;;; =============================================================================
;;; Simple Pass-Through XDP Program
;;; =============================================================================

(defn build-xdp-pass-program
  "Build a simple XDP program that passes all packets.
   This is useful for initial testing of program loading/attachment."
  []
  (bpf/assemble
    [(dsl/mov :r0 net/XDP-PASS)
     (dsl/exit-insn)]))

;;; =============================================================================
;;; IPv4 Filter Program (using clj-ebpf.net)
;;; =============================================================================

(defn build-ipv4-filter-program
  "Build XDP program that passes IPv4 packets and drops others.
   Uses clj-ebpf.net primitives for packet parsing."
  []
  (asm/assemble-with-labels
    (concat
      ;; Save context and load data pointers using 32-bit loads
      [(dsl/mov-reg :r6 :r1)
       (dsl/ldx :w :r7 :r1 0)     ; data
       (dsl/ldx :w :r8 :r1 4)]    ; data_end

      ;; Check Ethernet header bounds
      (asm/check-bounds :r7 :r8 net/ETH-HLEN :pass :r9)

      ;; Load and check ethertype for IPv4
      (eth/load-ethertype :r9 :r7)
      [(asm/jmp-imm :jne :r9 eth/ETH-P-IP-BE :pass)]

      ;; IPv4 - pass
      [(dsl/mov :r0 net/XDP-PASS)
       (dsl/exit-insn)]

      ;; Not IPv4 or bounds check failed - pass
      [(asm/label :pass)]
      [(dsl/mov :r0 net/XDP-PASS)
       (dsl/exit-insn)])))

;;; =============================================================================
;;; XDP Context Access Helpers
;;; =============================================================================

;; The xdp_md struct fields must be accessed as 32-bit values.
;; The kernel converts them to actual pointers internally.
;;
;; struct xdp_md {
;;     __u32 data;         // offset 0
;;     __u32 data_end;     // offset 4
;;     __u32 data_meta;    // offset 8
;;     __u32 ingress_ifindex;  // offset 12
;;     __u32 rx_queue_index;   // offset 16
;;     __u32 egress_ifindex;   // offset 20
;; };

(defn xdp-load-data-ptrs-32
  "Load data and data_end pointers from XDP context using 32-bit loads.
   The kernel requires 32-bit access to xdp_md fields.

   data-reg: Register to store data pointer
   data-end-reg: Register to store data_end pointer
   ctx-reg: XDP context register (typically :r1)"
  [data-reg data-end-reg ctx-reg]
  [(dsl/ldx :w data-reg ctx-reg 0)     ; data at offset 0
   (dsl/ldx :w data-end-reg ctx-reg 4)]) ; data_end at offset 4

;;; =============================================================================
;;; XDP Checksum Helpers
;;; =============================================================================

;; BPF helper function IDs
(def ^:const BPF-FUNC-ktime-get-ns 5)
(def ^:const BPF-FUNC-csum-diff 28)

(defn xdp-fold-csum
  "Fold a 32-bit checksum to 16 bits in XDP.
   csum-reg will contain the folded result.
   scratch-reg is clobbered."
  [csum-reg scratch-reg]
  [;; First fold: csum = (csum & 0xffff) + (csum >> 16)
   (dsl/mov-reg scratch-reg csum-reg)
   (dsl/rsh scratch-reg 16)
   (dsl/and csum-reg 0xFFFF)
   (dsl/add-reg csum-reg scratch-reg)
   ;; Second fold (handles carry from first fold)
   (dsl/mov-reg scratch-reg csum-reg)
   (dsl/rsh scratch-reg 16)
   (dsl/and csum-reg 0xFFFF)
   (dsl/add-reg csum-reg scratch-reg)])

(defn xdp-apply-csum-diff
  "Apply a checksum difference to an existing checksum.
   old-csum-reg: Register containing old checksum (16-bit, will be modified)
   diff-reg: Register containing the difference from csum_diff
   scratch-reg: Scratch register

   Result: old-csum-reg contains new 16-bit checksum"
  [old-csum-reg diff-reg scratch-reg]
  (concat
    ;; Negate old checksum: ~old_csum
    [(dsl/xor-op old-csum-reg 0xFFFF)]
    ;; Add difference: ~old_csum + diff
    [(dsl/add-reg old-csum-reg diff-reg)]
    ;; Fold to 16 bits
    (xdp-fold-csum old-csum-reg scratch-reg)
    ;; Negate result: ~(~old_csum + diff)
    [(dsl/xor-op old-csum-reg 0xFFFF)]))

(defn xdp-update-csum-for-port-change
  "Update checksum for a 2-byte port change.
   csum-reg: Register containing current checksum (will be modified)
   old-port-reg: Register containing old port value
   new-port-reg: Register containing new port value
   scratch-reg: Scratch register

   Uses incremental checksum: new_csum = ~(~old_csum + ~old_val + new_val)"
  [csum-reg old-port-reg new-port-reg scratch-reg]
  [;; Negate old checksum
   (dsl/xor-op csum-reg 0xFFFF)
   ;; Add ~old_port (ones complement negation)
   (dsl/mov-reg scratch-reg old-port-reg)
   (dsl/xor-op scratch-reg 0xFFFF)
   (dsl/add-reg csum-reg scratch-reg)
   ;; Add new_port
   (dsl/add-reg csum-reg new-port-reg)
   ;; Fold to 16 bits (first pass)
   (dsl/mov-reg scratch-reg csum-reg)
   (dsl/rsh scratch-reg 16)
   (dsl/and csum-reg 0xFFFF)
   (dsl/add-reg csum-reg scratch-reg)
   ;; Second fold
   (dsl/mov-reg scratch-reg csum-reg)
   (dsl/rsh scratch-reg 16)
   (dsl/and csum-reg 0xFFFF)
   (dsl/add-reg csum-reg scratch-reg)
   ;; Negate result
   (dsl/xor-op csum-reg 0xFFFF)])

;;; =============================================================================
;;; Full XDP Ingress Program with DNAT
;;; =============================================================================

(defn build-xdp-dnat-program
  "Build XDP ingress program that performs DNAT on incoming packets.

   This program:
   1. Parses IPv4/TCP or IPv4/UDP packets
   2. Looks up listen map by (ifindex, dst_port)
   3. Falls back to config map LPM lookup by source IP
   4. If match found, performs DNAT (rewrites dst IP and port)
   5. Updates IP and L4 checksums
   6. Creates conntrack entry for TC SNAT to use on reply path
   7. Returns XDP_PASS to let kernel routing deliver packet

   Register allocation:
   r6 = saved XDP context (callee-saved)
   r7 = data pointer (callee-saved)
   r8 = data_end pointer (callee-saved)
   r9 = IP header pointer / map value ptr (callee-saved)
   r0-r5 = scratch, clobbered by helpers

   Uses clj-ebpf.asm label-based assembly for automatic jump offset resolution."
  [listen-map-fd config-map-fd conntrack-map-fd]
  (asm/assemble-with-labels
    (concat
      ;; =====================================================================
      ;; PHASE 1: Context Setup and Ethernet Parsing
      ;; =====================================================================

      ;; Save XDP context to callee-saved register
      [(dsl/mov-reg :r6 :r1)]

      ;; Load data and data_end pointers from XDP context
      (xdp-load-data-ptrs-32 :r7 :r8 :r1)

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
       (dsl/stx :b :r10 :r0 -52)]       ; store at stack[-52]

      ;; Load and store source IP
      [(dsl/ldx :w :r0 :r9 12)          ; src_ip at offset 12
       (dsl/stx :w :r10 :r0 -40)]       ; store at stack[-40]

      ;; Load and store destination IP (original)
      [(dsl/ldx :w :r0 :r9 16)          ; dst_ip at offset 16
       (dsl/stx :w :r10 :r0 -24)        ; store at stack[-24] (old_dst_ip)
       (dsl/stx :w :r10 :r0 -44)]       ; store at stack[-44] (for conntrack)

      ;; =====================================================================
      ;; PHASE 3: Protocol Branching
      ;; =====================================================================

      ;; Check protocol and branch
      [(dsl/ldx :b :r0 :r10 -52)        ; load protocol
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_path)
       (asm/jmp-imm :jeq :r0 net/IPPROTO-UDP :udp_path)
       (asm/jmp :pass)]                  ; not TCP or UDP, pass through

      ;; =====================================================================
      ;; TCP Path: Parse TCP header and extract ports
      ;; =====================================================================
      [(asm/label :tcp_path)]

      ;; Calculate L4 header offset: ETH_HLEN + IPV4_MIN_HLEN = 34
      ;; Note: For simplicity, we assume no IP options (20-byte IP header)
      [(dsl/mov :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :w :r10 :r0 -56)]       ; store L4 offset at stack[-56]

      ;; Calculate L4 header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))]

      ;; Check TCP header bounds (need at least 20 bytes for checksum access at offset 16)
      [(dsl/mov-reg :r1 :r0)
       (dsl/add :r1 20)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Load TCP ports
      [(dsl/ldx :h :r1 :r0 0)           ; src_port at offset 0
       (dsl/stx :h :r10 :r1 -48)        ; store at stack[-48]
       (dsl/ldx :h :r1 :r0 2)           ; dst_port at offset 2
       (dsl/stx :h :r10 :r1 -28)        ; store at stack[-28] (old_dst_port)
       (dsl/stx :h :r10 :r1 -50)]       ; store at stack[-50] (for conntrack)

      [(asm/jmp :lookup_listen)]

      ;; =====================================================================
      ;; UDP Path: Parse UDP header and extract ports
      ;; =====================================================================
      [(asm/label :udp_path)]

      ;; Calculate L4 header offset
      [(dsl/mov :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :w :r10 :r0 -56)]

      ;; Calculate L4 header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))]

      ;; Check UDP header bounds (need at least 8 bytes for checksum access at offset 6)
      [(dsl/mov-reg :r1 :r0)
       (dsl/add :r1 8)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Load UDP ports
      [(dsl/ldx :h :r1 :r0 0)           ; src_port
       (dsl/stx :h :r10 :r1 -48)
       (dsl/ldx :h :r1 :r0 2)           ; dst_port
       (dsl/stx :h :r10 :r1 -28)        ; old_dst_port
       (dsl/stx :h :r10 :r1 -50)]

      ;; Fall through to lookup_listen

      ;; =====================================================================
      ;; PHASE 4: Listen Map Lookup
      ;; =====================================================================
      [(asm/label :lookup_listen)]

      ;; Build listen map key at stack[-8]: {ifindex(4) + port(2) + pad(2)}
      ;; Load ifindex from xdp_md->ingress_ifindex (offset 12)
      [(dsl/ldx :w :r0 :r6 12)          ; r0 = ifindex
       (dsl/stx :w :r10 :r0 -8)         ; key.ifindex = ifindex
       (dsl/ldx :h :r0 :r10 -28)        ; r0 = dst_port (old)
       (dsl/stx :h :r10 :r0 -4)         ; key.port = dst_port
       (dsl/mov :r0 0)
       (dsl/stx :h :r10 :r0 -2)]        ; key.pad = 0

      ;; Call bpf_map_lookup_elem(listen_map, &key)
      ;; Only do lookup if we have a valid map FD
      (if listen-map-fd
        (concat
          [(dsl/ld-map-fd :r1 listen-map-fd)
           (dsl/mov-reg :r2 :r10)
           (dsl/add :r2 -8)               ; r2 = &key
           (dsl/call 1)]                   ; bpf_map_lookup_elem
          ;; r0 = value ptr or NULL
          ;; If NULL, this port isn't being proxied - pass through
          [(asm/jmp-imm :jeq :r0 0 :pass)
           ;; Save map value pointer in r9
           (dsl/mov-reg :r9 :r0)
           (asm/jmp :do_nat)])
        ;; No listen map - pass all traffic
        [(asm/jmp :pass)])

      ;; =====================================================================
      ;; PHASE 5: Perform DNAT
      ;; =====================================================================
      [(asm/label :do_nat)]

      ;; r9 = pointer to map value: {target_ip(4) + target_port(2) + flags(2)}
      ;; Load NAT target values
      [(dsl/ldx :w :r1 :r9 0)           ; r1 = new_dst_ip
       (dsl/stx :w :r10 :r1 -32)        ; store at stack[-32]
       (dsl/ldx :h :r2 :r9 4)           ; r2 = new_dst_port
       (dsl/stx :h :r10 :r2 -36)]       ; store at stack[-36]

      ;; Branch by protocol for checksum calculation
      [(dsl/ldx :b :r0 :r10 -52)        ; load protocol
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_nat)
       (asm/jmp :udp_nat)]

      ;; =====================================================================
      ;; TCP NAT: Update IP checksum, TCP checksum, write new values
      ;; =====================================================================
      [(asm/label :tcp_nat)]

      ;; Re-validate packet bounds after map lookups (verifier loses tracking)
      ;; Reload data/data_end from xdp context
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)

      ;; Re-check bounds for IP + TCP header access (14 + 20 + 20 = 54 bytes)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 54)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Get IP header pointer back
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)]       ; r9 = IP header

      ;; --- Update IP Checksum using bpf_csum_diff ---
      ;; csum_diff(&old_dst_ip, 4, &new_dst_ip, 4, 0)
      [(dsl/mov-reg :r1 :r10)
       (dsl/add :r1 -24)                 ; r1 = &old_dst_ip
       (dsl/mov :r2 4)                   ; r2 = 4 bytes
       (dsl/mov-reg :r3 :r10)
       (dsl/add :r3 -32)                 ; r3 = &new_dst_ip
       (dsl/mov :r4 4)                   ; r4 = 4 bytes
       (dsl/mov :r5 0)                   ; r5 = seed
       (dsl/call BPF-FUNC-csum-diff)]    ; r0 = diff

      ;; Save diff for L4 checksum
      [(dsl/stx :w :r10 :r0 -64)]        ; stack[-64] = ip_diff

      ;; Re-validate bounds after csum_diff call
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 54)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Load old IP checksum and apply diff
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)        ; r9 = IP header
       (dsl/ldx :h :r1 :r9 10)           ; r1 = old IP checksum (offset 10)
       (dsl/ldx :w :r2 :r10 -64)]        ; r2 = diff

      ;; Apply: new_csum = ~(~old_csum + diff)
      (xdp-apply-csum-diff :r1 :r2 :r3)

      ;; Store new IP checksum
      [(dsl/stx :h :r9 :r1 10)]          ; ip->check = new_csum

      ;; --- Update TCP Checksum ---
      ;; TCP pseudo-header includes dst_ip, so we apply the same IP diff
      ;; Plus we need to account for dst_port change

      ;; Get L4 header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))] ; r0 = TCP header

      ;; Load old TCP checksum (offset 16)
      [(dsl/ldx :h :r1 :r0 16)]          ; r1 = old TCP checksum

      ;; Apply IP diff first (for pseudo-header)
      [(dsl/ldx :w :r2 :r10 -64)]        ; r2 = ip_diff
      (xdp-apply-csum-diff :r1 :r2 :r3)

      ;; Now apply port diff
      [(dsl/ldx :h :r2 :r10 -28)         ; r2 = old_dst_port
       (dsl/ldx :h :r3 :r10 -36)]        ; r3 = new_dst_port
      (xdp-update-csum-for-port-change :r1 :r2 :r3 :r4)

      ;; Get TCP header pointer again and store new checksum
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :h :r0 :r1 16)]          ; tcp->check = new_csum

      ;; --- Write New Values ---
      ;; Write new dst_ip to IP header
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)        ; r9 = IP header
       (dsl/ldx :w :r1 :r10 -32)         ; r1 = new_dst_ip
       (dsl/stx :w :r9 :r1 16)]          ; ip->daddr = new_dst_ip

      ;; Write new dst_port to TCP header
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r10 -36)         ; r1 = new_dst_port
       (dsl/stx :h :r0 :r1 2)]           ; tcp->dport = new_dst_port

      [(asm/jmp :create_conntrack)]

      ;; =====================================================================
      ;; UDP NAT: Update IP checksum, UDP checksum (if non-zero), write values
      ;; =====================================================================
      [(asm/label :udp_nat)]

      ;; Re-validate packet bounds after map lookups (verifier loses tracking)
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)

      ;; Re-check bounds for IP + UDP header (14 + 20 + 8 = 42 bytes)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 42)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Get IP header pointer
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)]

      ;; --- Update IP Checksum using bpf_csum_diff ---
      [(dsl/mov-reg :r1 :r10)
       (dsl/add :r1 -24)
       (dsl/mov :r2 4)
       (dsl/mov-reg :r3 :r10)
       (dsl/add :r3 -32)
       (dsl/mov :r4 4)
       (dsl/mov :r5 0)
       (dsl/call BPF-FUNC-csum-diff)]

      ;; Save diff for L4 checksum
      [(dsl/stx :w :r10 :r0 -64)]

      ;; Re-validate bounds after csum_diff call
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 42)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Apply diff to IP checksum
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :h :r1 :r9 10)           ; old IP checksum
       (dsl/ldx :w :r2 :r10 -64)]        ; diff
      (xdp-apply-csum-diff :r1 :r2 :r3)
      [(dsl/stx :h :r9 :r1 10)]          ; store new IP checksum

      ;; --- Update UDP Checksum (if non-zero) ---
      ;; UDP checksum of 0 means disabled
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r0 6)]           ; UDP checksum at offset 6
      [(asm/jmp-imm :jeq :r1 0 :udp_write_values)] ; skip if checksum disabled

      ;; Apply IP diff to UDP checksum
      [(dsl/ldx :w :r2 :r10 -64)]
      (xdp-apply-csum-diff :r1 :r2 :r3)

      ;; Apply port diff
      [(dsl/ldx :h :r2 :r10 -28)         ; old_dst_port
       (dsl/ldx :h :r3 :r10 -36)]        ; new_dst_port
      (xdp-update-csum-for-port-change :r1 :r2 :r3 :r4)

      ;; Store new UDP checksum
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :h :r0 :r1 6)]

      [(asm/label :udp_write_values)]

      ;; --- Write New Values ---
      ;; Write new dst_ip to IP header
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -32)
       (dsl/stx :w :r9 :r1 16)]

      ;; Write new dst_port to UDP header
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r10 -36)
       (dsl/stx :h :r0 :r1 2)]

      ;; Fall through to create_conntrack

      ;; =====================================================================
      ;; PHASE 6: Create Conntrack Entry
      ;; =====================================================================
      ;; Create a conntrack entry so TC SNAT can find the mapping for reply packets.
      ;; Key uses POST-NAT 5-tuple so TC can look up by reversing reply packet:
      ;; Key: {src_ip, nat_dst_ip, src_port, nat_dst_port, protocol}
      ;; Value: {orig_dst_ip, orig_dst_port, nat_dst_ip, nat_dst_port}
      [(asm/label :create_conntrack)]

      ;; Build conntrack key at stack[-88] (16 bytes)
      ;; Key layout: src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) + proto(1) + pad(3)
      ;; Use NAT'd destination (backend) so TC can find entry from reply packet
      [(dsl/ldx :w :r0 :r10 -40)          ; r0 = src_ip (client)
       (dsl/stx :w :r10 :r0 -88)          ; key.src_ip
       (dsl/ldx :w :r0 :r10 -32)          ; r0 = nat_dst_ip (backend IP after NAT)
       (dsl/stx :w :r10 :r0 -84)          ; key.dst_ip
       (dsl/ldx :h :r0 :r10 -48)          ; r0 = src_port (client)
       (dsl/stx :h :r10 :r0 -80)          ; key.src_port
       (dsl/ldx :h :r0 :r10 -36)          ; r0 = nat_dst_port (backend port after NAT)
       (dsl/stx :h :r10 :r0 -78)          ; key.dst_port
       (dsl/ldx :b :r0 :r10 -52)          ; r0 = protocol
       (dsl/stx :b :r10 :r0 -76)          ; key.protocol
       (dsl/mov :r0 0)
       (dsl/stx :b :r10 :r0 -75)          ; key.pad[0]
       (dsl/stx :h :r10 :r0 -74)]         ; key.pad[1-2]

      ;; Build conntrack value at stack[-152] (64 bytes)
      ;; Value layout: see stack layout comment at top of file

      ;; NAT mapping info (offsets 0-15)
      [(dsl/ldx :w :r0 :r10 -24)          ; r0 = old_dst_ip (for SNAT to restore)
       (dsl/stx :w :r10 :r0 -152)         ; value.orig_dst_ip (offset 0)
       (dsl/ldx :h :r0 :r10 -28)          ; r0 = old_dst_port
       (dsl/stx :h :r10 :r0 -148)         ; value.orig_dst_port (offset 4)
       (dsl/mov :r0 0)
       (dsl/stx :h :r10 :r0 -146)         ; value.pad (offset 6)
       (dsl/ldx :w :r0 :r10 -32)          ; r0 = nat_dst_ip (backend IP)
       (dsl/stx :w :r10 :r0 -144)         ; value.nat_dst_ip (offset 8)
       (dsl/ldx :h :r0 :r10 -36)          ; r0 = nat_dst_port
       (dsl/stx :h :r10 :r0 -140)         ; value.nat_dst_port (offset 12)
       (dsl/mov :r0 0)
       (dsl/stx :h :r10 :r0 -138)]        ; value.pad (offset 14)

      ;; Get current timestamp for created_ns and last_seen_ns
      [(dsl/call BPF-FUNC-ktime-get-ns)   ; r0 = current time in ns
       (dsl/stx :dw :r10 :r0 -136)        ; value.created_ns (offset 16)
       (dsl/stx :dw :r10 :r0 -128)]       ; value.last_seen_ns (offset 24)

      ;; Initialize packet counters: packets_fwd = 1, packets_rev = 0
      [(dsl/mov :r0 1)
       (dsl/stx :dw :r10 :r0 -120)        ; value.packets_fwd = 1 (offset 32)
       (dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -112)]       ; value.packets_rev = 0 (offset 40)

      ;; Calculate packet length: bytes_fwd = data_end - data
      [(dsl/mov-reg :r0 :r8)              ; r0 = data_end
       (dsl/sub-reg :r0 :r7)              ; r0 = data_end - data = packet length
       (dsl/stx :dw :r10 :r0 -104)        ; value.bytes_fwd (offset 48)
       (dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -96)]        ; value.bytes_rev = 0 (offset 56)

      ;; Call bpf_map_update_elem(conntrack_map, &key, &value, BPF_ANY)
      (if conntrack-map-fd
        [(dsl/ld-map-fd :r1 conntrack-map-fd)
         (dsl/mov-reg :r2 :r10)
         (dsl/add :r2 -88)                 ; r2 = &key
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 -152)                ; r3 = &value
         (dsl/mov :r4 0)                   ; r4 = BPF_ANY (0)
         (dsl/call 2)]                     ; bpf_map_update_elem
        ;; No conntrack map - skip update
        [])

      ;; Fall through to done

      ;; =====================================================================
      ;; Return XDP_PASS
      ;; =====================================================================
      [(asm/label :done)]
      (net/return-action net/XDP-PASS)

      [(asm/label :pass)]
      (net/return-action net/XDP-PASS))))

(defn build-xdp-ingress-program
  "Build the XDP ingress program.

   Performs DNAT on incoming packets:
   1. Looks up listen map by (ifindex, dst_port)
   2. Falls back to config map LPM lookup by source IP
   3. If match found, rewrites destination IP/port
   4. Updates IP and L4 checksums
   5. Creates conntrack entry for TC SNAT
   6. Returns XDP_PASS to let kernel routing deliver packet

   map-fds: Map containing :listen-map, optionally :config-map and :conntrack-map"
  [map-fds]
  (let [listen-map-fd (when (and (map? map-fds) (:listen-map map-fds))
                        (common/map-fd (:listen-map map-fds)))
        config-map-fd (when (and (map? map-fds) (:config-map map-fds))
                        (common/map-fd (:config-map map-fds)))
        conntrack-map-fd (when (and (map? map-fds) (:conntrack-map map-fds))
                           (common/map-fd (:conntrack-map map-fds)))]
    (build-xdp-dnat-program listen-map-fd config-map-fd conntrack-map-fd)))

;;; =============================================================================
;;; Program Loading and Attachment
;;; =============================================================================

(defn load-program
  "Load the XDP ingress program.
   Returns a BpfProgram record."
  [maps]
  (log/info "Loading XDP ingress program")
  (let [bytecode (build-xdp-ingress-program maps)]
    (require '[clj-ebpf.programs :as programs])
    ((resolve 'clj-ebpf.programs/load-program)
      {:insns bytecode
       :prog-type :xdp
       :prog-name "xdp_ingress"
       :license "GPL"
       :log-level 1})))

(defn attach-to-interface
  "Attach XDP program to a network interface.

   prog: BpfProgram record or program FD
   iface: Interface name (e.g., \"eth0\")
   mode: :skb (generic), :drv (native), or :hw (hardware)"
  [prog iface & {:keys [mode] :or {mode :skb}}]
  (log/info "Attaching XDP program to" iface "in" mode "mode")
  (let [prog-fd (if (number? prog) prog (:fd prog))
        mode-flag (case mode
                    :skb :skb-mode
                    :drv :drv-mode
                    :hw :hw-mode
                    :skb-mode)]
    (bpf/attach-xdp iface prog-fd mode-flag)))

(defn attach-to-interfaces
  "Attach XDP program to multiple interfaces."
  [prog interfaces & opts]
  (doseq [iface interfaces]
    (apply attach-to-interface prog iface opts)))

(defn detach-from-interface
  "Detach XDP program from an interface."
  [iface & {:keys [mode] :or {mode :skb}}]
  (log/info "Detaching XDP program from" iface)
  (let [flags (case mode
                :skb [:skb-mode]
                :drv [:drv-mode]
                :hw [:hw-mode]
                [:skb-mode])]
    (try
      (apply bpf/detach-xdp iface flags)
      (catch Exception e
        (log/warn "Failed to detach XDP from" iface ":" (.getMessage e))))))

(defn detach-from-interfaces
  "Detach XDP program from multiple interfaces."
  [interfaces & opts]
  (doseq [iface interfaces]
    (apply detach-from-interface iface opts)))

;;; =============================================================================
;;; Program Verification
;;; =============================================================================

(defn verify-program
  "Verify the XDP program can be loaded (dry run).
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
  (let [bytecode (build-xdp-ingress-program maps)]
    (println "XDP Ingress Program Bytecode:")
    (println "=============================")
    (println "Length:" (count bytecode) "bytes")
    (println "Instructions:" (/ (count bytecode) 8))
    (doseq [[idx b] (map-indexed vector bytecode)]
      (print (format "%02x " b))
      (when (= 7 (mod idx 8))
        (println)))))
