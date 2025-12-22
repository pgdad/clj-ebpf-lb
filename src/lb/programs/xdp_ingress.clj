(ns lb.programs.xdp-ingress
  "XDP ingress program for the load balancer.
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
            [lb.programs.common :as common]
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

;; Stack layout for IPv4 (negative offsets from r10):
;; -8   : Listen map key (8 bytes: ifindex(4) + port(2) + pad(2))
;; -16  : LPM key (8 bytes: prefix_len(4) + ip(4))
;; -24  : old_dst_ip (4 bytes)
;; -28  : old_dst_port (2 bytes) + pad (2 bytes)
;; -32  : nat_dst_ip (4 bytes) - SELECTED target IP
;; -36  : nat_dst_port (2 bytes) + pad (2 bytes) - SELECTED target port
;; -40  : src_ip (4 bytes)
;; -44  : dst_ip original (4 bytes)
;; -48  : src_port (2 bytes)
;; -50  : dst_port original (2 bytes)
;; -52  : protocol (1 byte) + pad (3 bytes)
;; -56  : L4 header offset from data (4 bytes)
;; -60  : target_count (4 bytes) - for weighted selection
;; -64  : random_value (4 bytes) - for weighted selection
;; -72  : checksum scratch (8 bytes)
;; -80  : additional scratch (8 bytes)
;; -88  : SNI key for map lookup (8 bytes: hostname_hash)
;; -96  : Conntrack key (16 bytes: src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) + proto(1) + pad(3))
;; -160 : Conntrack value (64 bytes):
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
;;
;; ============================================================================
;; Unified stack layout for IPv4/IPv6 dual-stack (used by build-xdp-dnat-program-unified):
;; ============================================================================
;; -8   : Listen map key (8 bytes: ifindex(4) + port(2) + af(1) + pad(1))
;; -28  : LPM key (20 bytes: prefix_len(4) + ip(16))
;; -44  : old_dst_ip (16 bytes)
;; -48  : old_dst_port (2 bytes) + pad (2 bytes)
;; -64  : nat_dst_ip (16 bytes) - SELECTED target IP
;; -68  : nat_dst_port (2 bytes) + pad (2 bytes)
;; -84  : src_ip (16 bytes)
;; -100 : dst_ip original (16 bytes)
;; -102 : src_port (2 bytes)
;; -104 : dst_port original (2 bytes)
;; -105 : protocol (1 byte)
;; -106 : af (1 byte) - 4 = IPv4, 6 = IPv6
;; -108 : pad (2 bytes)
;; -112 : L4 header offset from data (4 bytes)
;; -116 : target_count (4 bytes)
;; -120 : random_value (4 bytes)
;; -124 : route_flags (2 bytes) + pad (2 bytes) - includes PROXY protocol flag
;; -128 : checksum scratch (8 bytes)
;; -136 : additional scratch (8 bytes)
;; -144 : SNI key for map lookup (8 bytes: hostname_hash)
;; -184 : Conntrack key (40 bytes: src_ip(16) + dst_ip(16) + ports(4) + proto(1) + pad(3))
;; -312 : Conntrack value (128 bytes): see unified conntrack format in util.clj
;;        Includes PROXY protocol fields at offset 96

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
   2. Applies per-source rate limiting (if configured)
   3. For TCP port 443, attempts SNI-based routing (TLS ClientHello parsing)
   4. Falls back to listen map lookup by (ifindex, dst_port)
   5. Falls back to config map LPM lookup by source IP
   6. If match found, applies per-backend rate limiting (if configured)
   7. Performs DNAT (rewrites dst IP and port)
   8. Updates IP and L4 checksums
   9. Creates conntrack entry for TC SNAT to use on reply path
   10. Returns XDP_PASS to let kernel routing deliver packet

   Routing priority:
   1. Source IP exact/CIDR match (config map)
   2. SNI hostname match (sni map, for TLS traffic)
   3. Default target (listen map)

   Register allocation:
   r6 = saved XDP context (callee-saved)
   r7 = data pointer (callee-saved)
   r8 = data_end pointer (callee-saved)
   r9 = IP header pointer / map value ptr (callee-saved)
   r0-r5 = scratch, clobbered by helpers

   Uses clj-ebpf.asm label-based assembly for automatic jump offset resolution."
  [listen-map-fd config-map-fd sni-map-fd conntrack-map-fd
   rate-limit-config-fd rate-limit-src-fd rate-limit-backend-fd]
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

      ;; Check if this is HTTPS traffic (port 443) for SNI-based routing
      ;; Port 443 in network byte order = 0x01BB
      ;; Only generate SNI parsing code if SNI map is provided
      (if sni-map-fd
        [(dsl/ldx :h :r1 :r10 -28)        ; load dst_port
         (asm/jmp-imm :jeq :r1 common/HTTPS-PORT-BE :try_sni_lookup)
         (asm/jmp :lookup_listen)]
        [(asm/jmp :lookup_listen)])

      ;; =====================================================================
      ;; SNI-Based Routing for HTTPS (port 443)
      ;; =====================================================================
      ;; This section attempts to parse TLS ClientHello to extract SNI hostname.
      ;; If successful, looks up SNI map for hostname-based routing.
      ;; Falls back to listen map if:
      ;; - Not a TLS handshake
      ;; - Not a ClientHello
      ;; - SNI extension not found
      ;; - SNI not in map
      ;; Note: This entire section is only generated when sni-map-fd is provided
      (when sni-map-fd
        (concat
          [(asm/label :try_sni_lookup)]

          ;; r0 still points to TCP header from earlier
          ;; TCP payload starts after TCP header (min 20 bytes, could have options)
          ;; For simplicity, we use minimum TCP header size (no options)
          ;; TLS record header is first 5 bytes of payload

          ;; Calculate TLS record start: data + ETH_HLEN + IP_MIN_HLEN + TCP_MIN_HLEN
          ;; Using minimum TCP header size (20 bytes, no options) for TLS detection
          [(dsl/mov-reg :r1 :r7)
           (dsl/add :r1 (+ net/ETH-HLEN net/IPV4-MIN-HLEN 20))
           ;; Bounds check: need at least 5 bytes for TLS record header
           (dsl/mov-reg :r2 :r1)
           (dsl/add :r2 5)
           (asm/jmp-reg :jgt :r2 :r8 :lookup_listen)]  ; not enough data

          ;; r1 = TLS record start
          ;; Check content type at offset 0 - must be 0x16 (Handshake)
          [(dsl/ldx :b :r2 :r1 0)
           (asm/jmp-imm :jne :r2 common/TLS-CONTENT-TYPE-HANDSHAKE :lookup_listen)]

          ;; Load TLS record length (bytes 3-4, big-endian)
          [(dsl/ldx :h :r3 :r1 3)]            ; r3 = TLS record length

          ;; Bounds check: need TLS header (5) + handshake header (4) at minimum
          [(dsl/mov-reg :r2 :r1)
           (dsl/add :r2 9)                    ; 5 (TLS header) + 4 (handshake header)
           (asm/jmp-reg :jgt :r2 :r8 :lookup_listen)]

          ;; Check handshake type at offset 5 - must be 0x01 (ClientHello)
          [(dsl/ldx :b :r2 :r1 5)
           (asm/jmp-imm :jne :r2 common/TLS-HANDSHAKE-CLIENT-HELLO :lookup_listen)]

          ;; Now we have a TLS ClientHello. Parse to find SNI extension.
          ;; ClientHello structure after handshake header (offset 9):
          ;; - version: 2 bytes
          ;; - random: 32 bytes
          ;; - session_id_length: 1 byte
          ;; - session_id: variable
          ;; - cipher_suites_length: 2 bytes
          ;; - cipher_suites: variable
          ;; - compression_methods_length: 1 byte
          ;; - compression_methods: variable
          ;; - extensions_length: 2 bytes
          ;; - extensions: variable

          ;; r1 = TLS record start
          ;; ClientHello body starts at offset 9 (5 + 4)
          ;; First skip version (2) + random (32) = 34 bytes to session_id_length

          ;; Bounds check for fixed ClientHello fields (9 + 34 + 1 = 44)
          [(dsl/mov-reg :r2 :r1)
           (dsl/add :r2 44)
           (asm/jmp-reg :jgt :r2 :r8 :lookup_listen)]

          ;; Load session_id_length at offset 43 (9 + 34)
          [(dsl/ldx :b :r2 :r1 43)            ; r2 = session_id_length
           ;; Calculate offset after session_id: 44 + session_id_length
           (dsl/mov :r3 44)
           (dsl/add-reg :r3 :r2)]              ; r3 = offset to cipher_suites_length

          ;; Bounds check for cipher_suites_length (2 bytes)
          [(dsl/mov-reg :r2 :r1)
           (dsl/add-reg :r2 :r3)
           (dsl/add :r2 2)
           (asm/jmp-reg :jgt :r2 :r8 :lookup_listen)]

          ;; Load cipher_suites_length (2 bytes big-endian)
          [(dsl/mov-reg :r2 :r1)
           (dsl/add-reg :r2 :r3)               ; r2 = ptr to cipher_suites_length
           (dsl/ldx :h :r4 :r2 0)              ; r4 = cipher_suites_length
           ;; Calculate offset after cipher_suites
           (dsl/add-reg :r3 :r4)
           (dsl/add :r3 2)]                    ; r3 = offset to compression_methods_length

          ;; Limit offset to prevent too deep parsing (security)
          [(asm/jmp-imm :jgt :r3 300 :lookup_listen)]

          ;; Bounds check for compression_methods_length (1 byte)
          [(dsl/mov-reg :r2 :r1)
           (dsl/add-reg :r2 :r3)
           (dsl/add :r2 1)
           (asm/jmp-reg :jgt :r2 :r8 :lookup_listen)]

          ;; Load compression_methods_length
          [(dsl/mov-reg :r2 :r1)
           (dsl/add-reg :r2 :r3)
           (dsl/ldx :b :r4 :r2 0)              ; r4 = compression_methods_length
           ;; Calculate offset to extensions_length
           (dsl/add-reg :r3 :r4)
           (dsl/add :r3 1)]                    ; r3 = offset to extensions_length

          ;; Limit offset
          [(asm/jmp-imm :jgt :r3 400 :lookup_listen)]

          ;; Bounds check for extensions_length (2 bytes)
          [(dsl/mov-reg :r2 :r1)
           (dsl/add-reg :r2 :r3)
           (dsl/add :r2 2)
           (asm/jmp-reg :jgt :r2 :r8 :lookup_listen)]

          ;; Load extensions_length
          [(dsl/mov-reg :r2 :r1)
           (dsl/add-reg :r2 :r3)
           (dsl/ldx :h :r4 :r2 0)              ; r4 = extensions_length
           ;; r3 + 2 = offset to first extension
           (dsl/add :r3 2)]

          ;; Store extensions end offset: r3 + extensions_length
          [(dsl/mov-reg :r5 :r3)
           (dsl/add-reg :r5 :r4)]              ; r5 = extensions_end_offset

          ;; Limit to avoid excessive parsing
          [(asm/jmp-imm :jgt :r5 600 :lookup_listen)]

          ;; Now iterate through extensions looking for SNI (type 0x0000)
          ;; Each extension: type(2) + length(2) + data(length)
          ;; r3 = current extension offset
          ;; r5 = extensions end offset
          ;; Use bounded loop (max 32 iterations)

          ;; Store loop variables on stack
          ;; stack[-72] = current extension offset
          ;; stack[-76] = extensions end offset
          [(dsl/stx :w :r10 :r3 -72)
           (dsl/stx :w :r10 :r5 -76)
           (dsl/mov :r0 0)]                    ; r0 = loop counter

          [(asm/label :ext_loop)]

          ;; Check loop bound (max 32 iterations for verifier)
          [(asm/jmp-imm :jge :r0 common/MAX-TLS-EXTENSIONS :lookup_listen)]

          ;; Load current offset and check against end
          [(dsl/ldx :w :r3 :r10 -72)           ; r3 = current offset
           (dsl/ldx :w :r5 :r10 -76)           ; r5 = end offset
           (asm/jmp-reg :jge :r3 :r5 :lookup_listen)] ; no more extensions

          ;; Bounds check for extension header (4 bytes: type + length)
          [(dsl/mov-reg :r2 :r1)
           (dsl/add-reg :r2 :r3)
           (dsl/add :r2 4)
           (asm/jmp-reg :jgt :r2 :r8 :lookup_listen)]

          ;; Load extension type (2 bytes)
          [(dsl/mov-reg :r2 :r1)
           (dsl/add-reg :r2 :r3)
           (dsl/ldx :h :r4 :r2 0)]             ; r4 = extension type

          ;; Check if SNI extension (type 0x0000)
          [(asm/jmp-imm :jeq :r4 common/TLS-EXT-SNI :found_sni)]

          ;; Not SNI, skip to next extension
          ;; Load extension length and advance offset
          [(dsl/ldx :h :r4 :r2 2)              ; r4 = extension length
           (dsl/add :r3 4)                     ; skip type + length fields
           (dsl/add-reg :r3 :r4)               ; skip extension data
           (dsl/stx :w :r10 :r3 -72)           ; update current offset
           (dsl/add :r0 1)                     ; increment loop counter
           (asm/jmp :ext_loop)]

          ;; =====================================================================
          ;; Found SNI Extension - Parse and Hash Hostname
          ;; =====================================================================
          [(asm/label :found_sni)]

          ;; r2 = pointer to SNI extension header
          ;; SNI extension data format:
          ;; - list_length: 2 bytes
          ;; - For each entry:
          ;;   - name_type: 1 byte (0 = hostname)
          ;;   - name_length: 2 bytes
          ;;   - name: variable

          ;; Load extension length
          [(dsl/ldx :h :r4 :r2 2)              ; r4 = extension length
           ;; Bounds check for SNI list header (4 + 2 + 1 + 2 = 9 bytes min)
           (dsl/mov-reg :r3 :r2)
           (dsl/add :r3 9)
           (asm/jmp-reg :jgt :r3 :r8 :lookup_listen)]

          ;; Check name_type at offset 6 (after ext header + list_length)
          [(dsl/ldx :b :r3 :r2 6)
           (asm/jmp-imm :jne :r3 common/TLS-SNI-NAME-TYPE-HOSTNAME :lookup_listen)]

          ;; Load hostname length at offset 7
          [(dsl/ldx :h :r4 :r2 7)              ; r4 = hostname length
           ;; Limit hostname length for hashing
           (asm/jmp-imm :jgt :r4 common/MAX-SNI-LENGTH :lookup_listen)]

          ;; Bounds check for hostname
          [(dsl/mov-reg :r3 :r2)
           (dsl/add :r3 9)                     ; offset to hostname
           (dsl/add-reg :r3 :r4)               ; add hostname length
           (asm/jmp-reg :jgt :r3 :r8 :lookup_listen)]

          ;; Now compute FNV-1a hash of hostname
          ;; r2 = extension header ptr
          ;; r4 = hostname length
          ;; hostname starts at r2 + 9
          ;; We need to compute hash byte by byte with lowercase conversion

          ;; Initialize FNV-1a hash (64-bit) using two 32-bit registers simulation
          ;; Actually, BPF registers are 64-bit, so we can use single register
          ;; FNV-1a offset basis: 0xcbf29ce484222325 (as signed long: -3750763034362895579)
          [(dsl/lddw :r3 -3750763034362895579)] ; r3 = hash (FNV-1a offset basis)

          ;; Store hostname ptr and length
          [(dsl/mov-reg :r5 :r2)
           (dsl/add :r5 9)                     ; r5 = hostname start
           (dsl/stx :w :r10 :r4 -72)           ; store length
           (dsl/stx :dw :r10 :r5 -80)]         ; store hostname ptr

          ;; r0 = loop counter, r4 = length limit
          [(dsl/mov :r0 0)]

          [(asm/label :hash_loop)]

          ;; Check loop bound
          [(asm/jmp-imm :jge :r0 common/MAX-SNI-LENGTH :hash_done)]
          [(dsl/ldx :w :r4 :r10 -72)           ; load length
           (asm/jmp-reg :jge :r0 :r4 :hash_done)]

          ;; Reload hostname ptr
          [(dsl/ldx :dw :r5 :r10 -80)]

          ;; Bounds check for this byte
          [(dsl/mov-reg :r2 :r5)
           (dsl/add-reg :r2 :r0)
           (dsl/add :r2 1)
           (asm/jmp-reg :jgt :r2 :r8 :hash_done)]

          ;; Load byte and convert to lowercase
          [(dsl/mov-reg :r2 :r5)
           (dsl/add-reg :r2 :r0)
           (dsl/ldx :b :r1 :r2 0)              ; r1 = byte

           ;; Lowercase: if 'A' <= byte <= 'Z', add 32
           ;; ASCII: A=65, Z=90, a=97
           (dsl/mov-reg :r2 :r1)
           (dsl/sub :r2 65)                    ; r2 = byte - 'A'
           (asm/jmp-imm :jgt :r2 25 :no_lowercase)  ; if > 25, not uppercase
           (dsl/add :r1 32)]                   ; convert to lowercase

          [(asm/label :no_lowercase)]

          ;; FNV-1a: hash = (hash XOR byte) * prime
          [(dsl/xor-reg :r3 :r1)
           ;; Multiply by FNV-1a prime 0x00000100000001B3 = 1099511628211
           ;; This is a 64-bit multiply which BPF supports
           (dsl/lddw :r2 1099511628211)
           (dsl/mul-reg :r3 :r2)]

          ;; Next byte
          [(dsl/add :r0 1)
           (asm/jmp :hash_loop)]

          [(asm/label :hash_done)]

          ;; r3 = computed FNV-1a hash of hostname
          ;; Store as SNI key at stack[-88] (8 bytes)
          [(dsl/stx :dw :r10 :r3 -88)]

          ;; Look up SNI map
          [(dsl/ld-map-fd :r1 sni-map-fd)
           (dsl/mov-reg :r2 :r10)
           (dsl/add :r2 -88)                   ; r2 = &sni_key
           (dsl/call 1)]                       ; bpf_map_lookup_elem

          ;; If found, use SNI route; otherwise fall through to listen map
          [(asm/jmp-imm :jeq :r0 0 :lookup_listen)
           (dsl/mov-reg :r9 :r0)               ; r9 = SNI route value ptr
           (asm/jmp :do_nat)]))

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
      ;; PHASE 5: Weighted Target Selection and DNAT
      ;; =====================================================================
      [(asm/label :do_nat)]

      ;; r9 = pointer to map value (weighted route format, 72 bytes):
      ;; Header (8 bytes): target_count(1) + reserved(3) + flags(2) + reserved(2)
      ;; Per target (8 bytes each): ip(4) + port(2) + cumulative_weight(2)

      ;; Load target_count from header byte 0
      [(dsl/ldx :b :r0 :r9 0)           ; r0 = target_count (1-8)
       (dsl/stx :w :r10 :r0 -60)]       ; store at stack[-60]

      ;; If target_count == 1, skip weighted selection (use first target directly)
      [(asm/jmp-imm :jeq :r0 1 :single_target)]

      ;; Multiple targets: weighted selection based on flags
      ;; Check flags for session persistence (offset 4 in header, 2 bytes native order)
      ;; r9 = map value pointer
      [(dsl/ldx :h :r6 :r9 4)           ; r6 = flags
       (dsl/stx :h :r10 :r6 -124)]      ; Store flags at stack[-124] for PROXY protocol

      ;; If session-persistence flag (bit 0) set, use source IP hash; else use random
      [(asm/jmp-imm :jset :r6 1 :use_ip_hash)]  ; if flags & 0x01 goto use_ip_hash

      ;; Default: use random selection
      [(dsl/call common/BPF-FUNC-get-prandom-u32)]
      [(asm/jmp :have_selection_value)]

      ;; Session persistence: hash source IP for deterministic selection
      [(asm/label :use_ip_hash)]
      [(dsl/ldx :w :r0 :r10 -40)]       ; r0 = source_ip (at stack[-40])
      ;; FNV-like hash: multiply by prime for distribution
      ;; Using 2654435761 (0x9E3779B1) - golden ratio prime
      [(dsl/lddw :r1 2654435761)]       ; r1 = FNV prime
      [(dsl/mul-reg :r0 :r1)]           ; r0 = ip * prime

      [(asm/label :have_selection_value)]
      ;; r0 = r0 % 100 (value 0-99)
      [(dsl/mod :r0 100)
       (dsl/stx :w :r10 :r0 -64)]       ; store selection value at stack[-64]

      ;; Loop through targets comparing random with cumulative weights
      ;; Target entries start at offset 8 in the map value
      ;; Each target is 8 bytes: ip(4) + port(2) + cumulative_weight(2)

      ;; r0 = loop counter (0-7)
      ;; r1 = current target offset
      ;; r2 = random value
      ;; r3 = cumulative weight

      [(dsl/mov :r0 0)                  ; loop counter
       (dsl/mov :r1 8)]                 ; first target at offset 8

      [(asm/label :weight_loop)]

      ;; Check loop bound with CONSTANT to satisfy verifier
      ;; This ensures the verifier knows counter < 8, so max offset is 70 < 72
      [(asm/jmp-imm :jge :r0 8 :single_target)] ; if counter >= 8, use first (safety)

      ;; Also check against actual target_count
      [(dsl/ldx :w :r3 :r10 -60)        ; r3 = target_count
       (asm/jmp-reg :jge :r0 :r3 :single_target)] ; if counter >= count, use first

      ;; Calculate target offset: 8 + (counter * 8)
      [(dsl/mov-reg :r1 :r0)
       (dsl/lsh :r1 3)                  ; r1 = counter * 8
       (dsl/add :r1 8)]                 ; r1 = 8 + counter * 8

      ;; Load cumulative_weight for this target (at offset 6 within target entry)
      [(dsl/mov-reg :r2 :r9)            ; r2 = map value base
       (dsl/add-reg :r2 :r1)            ; r2 = &target[i]
       (dsl/ldx :h :r3 :r2 6)           ; r3 = cumulative_weight (at offset 6)
       (dsl/ldx :w :r4 :r10 -64)]       ; r4 = random value

      ;; If random < cumulative_weight, select this target
      [(asm/jmp-reg :jlt :r4 :r3 :select_target)]

      ;; Otherwise, continue loop
      [(dsl/add :r0 1)                  ; counter++
       (asm/jmp :weight_loop)]

      ;; =====================================================================
      ;; Select current target (r1 = offset within map value)
      ;; =====================================================================
      [(asm/label :select_target)]

      ;; Load selected target IP (at offset r1+0 from map value)
      [(dsl/mov-reg :r2 :r9)
       (dsl/add-reg :r2 :r1)            ; r2 = &target[selected]
       (dsl/ldx :w :r3 :r2 0)           ; r3 = target_ip
       (dsl/stx :w :r10 :r3 -32)        ; store at stack[-32]
       (dsl/ldx :h :r3 :r2 4)           ; r3 = target_port
       (dsl/stx :h :r10 :r3 -36)]       ; store at stack[-36]
      [(asm/jmp :do_checksum)]

      ;; =====================================================================
      ;; Single target: use first target at offset 8
      ;; =====================================================================
      [(asm/label :single_target)]

      ;; Store flags for PROXY protocol (even for single target)
      [(dsl/ldx :h :r0 :r9 4)           ; r0 = flags
       (dsl/stx :h :r10 :r0 -124)]      ; Store flags at stack[-124]

      ;; Load first target (at offset 8): ip(4) + port(2) + cumulative(2)
      [(dsl/ldx :w :r1 :r9 8)           ; r1 = new_dst_ip
       (dsl/stx :w :r10 :r1 -32)        ; store at stack[-32]
       (dsl/ldx :h :r2 :r9 12)          ; r2 = new_dst_port
       (dsl/stx :h :r10 :r2 -36)]       ; store at stack[-36]

      ;; Fall through to do_checksum
      [(asm/label :do_checksum)]

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
      [(dsl/stx :w :r10 :r0 -72)]        ; stack[-72] = ip_diff

      ;; Re-validate bounds after csum_diff call
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 54)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Load old IP checksum and apply diff
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)        ; r9 = IP header
       (dsl/ldx :h :r1 :r9 10)           ; r1 = old IP checksum (offset 10)
       (dsl/ldx :w :r2 :r10 -72)]        ; r2 = diff

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
      [(dsl/ldx :w :r2 :r10 -72)]        ; r2 = ip_diff
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
      [(dsl/stx :w :r10 :r0 -72)]

      ;; Re-validate bounds after csum_diff call
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 42)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Apply diff to IP checksum
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :h :r1 :r9 10)           ; old IP checksum
       (dsl/ldx :w :r2 :r10 -72)]        ; diff
      (xdp-apply-csum-diff :r1 :r2 :r3)
      [(dsl/stx :h :r9 :r1 10)]          ; store new IP checksum

      ;; --- Update UDP Checksum (if non-zero) ---
      ;; UDP checksum of 0 means disabled
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r0 6)]           ; UDP checksum at offset 6
      [(asm/jmp-imm :jeq :r1 0 :udp_write_values)] ; skip if checksum disabled

      ;; Apply IP diff to UDP checksum
      [(dsl/ldx :w :r2 :r10 -72)]
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

      ;; Build conntrack key at stack[-96] (16 bytes)
      ;; Key layout: src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) + proto(1) + pad(3)
      ;; Use NAT'd destination (backend) so TC can find entry from reply packet
      [(dsl/ldx :w :r0 :r10 -40)          ; r0 = src_ip (client)
       (dsl/stx :w :r10 :r0 -96)          ; key.src_ip
       (dsl/ldx :w :r0 :r10 -32)          ; r0 = nat_dst_ip (backend IP after NAT)
       (dsl/stx :w :r10 :r0 -92)          ; key.dst_ip
       (dsl/ldx :h :r0 :r10 -48)          ; r0 = src_port (client)
       (dsl/stx :h :r10 :r0 -88)          ; key.src_port
       (dsl/ldx :h :r0 :r10 -36)          ; r0 = nat_dst_port (backend port after NAT)
       (dsl/stx :h :r10 :r0 -86)          ; key.dst_port
       (dsl/ldx :b :r0 :r10 -52)          ; r0 = protocol
       (dsl/stx :b :r10 :r0 -84)          ; key.protocol
       (dsl/mov :r0 0)
       (dsl/stx :b :r10 :r0 -83)          ; key.pad[0]
       (dsl/stx :h :r10 :r0 -82)]         ; key.pad[1-2]

      ;; Build conntrack value at stack[-160] (64 bytes)
      ;; Value layout: see stack layout comment at top of file

      ;; NAT mapping info (offsets 0-15)
      [(dsl/ldx :w :r0 :r10 -24)          ; r0 = old_dst_ip (for SNAT to restore)
       (dsl/stx :w :r10 :r0 -160)         ; value.orig_dst_ip (offset 0)
       (dsl/ldx :h :r0 :r10 -28)          ; r0 = old_dst_port
       (dsl/stx :h :r10 :r0 -156)         ; value.orig_dst_port (offset 4)
       (dsl/mov :r0 0)
       (dsl/stx :h :r10 :r0 -154)         ; value.pad (offset 6)
       (dsl/ldx :w :r0 :r10 -32)          ; r0 = nat_dst_ip (backend IP)
       (dsl/stx :w :r10 :r0 -152)         ; value.nat_dst_ip (offset 8)
       (dsl/ldx :h :r0 :r10 -36)          ; r0 = nat_dst_port
       (dsl/stx :h :r10 :r0 -148)         ; value.nat_dst_port (offset 12)
       (dsl/mov :r0 0)
       (dsl/stx :h :r10 :r0 -146)]        ; value.pad (offset 14)

      ;; Get current timestamp for created_ns and last_seen_ns
      [(dsl/call BPF-FUNC-ktime-get-ns)   ; r0 = current time in ns
       (dsl/stx :dw :r10 :r0 -144)        ; value.created_ns (offset 16)
       (dsl/stx :dw :r10 :r0 -136)]       ; value.last_seen_ns (offset 24)

      ;; Initialize packet counters: packets_fwd = 1, packets_rev = 0
      [(dsl/mov :r0 1)
       (dsl/stx :dw :r10 :r0 -128)        ; value.packets_fwd = 1 (offset 32)
       (dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -120)]       ; value.packets_rev = 0 (offset 40)

      ;; Calculate packet length: bytes_fwd = data_end - data
      [(dsl/mov-reg :r0 :r8)              ; r0 = data_end
       (dsl/sub-reg :r0 :r7)              ; r0 = data_end - data = packet length
       (dsl/stx :dw :r10 :r0 -112)        ; value.bytes_fwd (offset 48)
       (dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -104)]       ; value.bytes_rev = 0 (offset 56)

      ;; Call bpf_map_update_elem(conntrack_map, &key, &value, BPF_ANY)
      (if conntrack-map-fd
        [(dsl/ld-map-fd :r1 conntrack-map-fd)
         (dsl/mov-reg :r2 :r10)
         (dsl/add :r2 -96)                 ; r2 = &key
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 -160)                ; r3 = &value
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

;;; =============================================================================
;;; Unified XDP Ingress Program with IPv4/IPv6 Dual-Stack Support
;;; =============================================================================

(defn build-xdp-dnat-program-unified
  "Build unified XDP ingress program that performs DNAT on both IPv4 and IPv6 packets.

   This program supports dual-stack operation:
   1. Parses EtherType and branches for IPv4 or IPv6
   2. For IPv4: Parses 20-byte min header, stores addresses in 16-byte unified format
   3. For IPv6: Parses fixed 40-byte header
   4. Applies NAT using unified maps
   5. Updates checksums (IP header checksum for IPv4 only)
   6. Creates unified conntrack entries

   Uses unified map formats:
   - Listen map key: 8 bytes (ifindex(4) + port(2) + af(1) + pad(1))
   - LPM key: 20 bytes (prefix_len(4) + ip(16))
   - Route value: 168 bytes (header(8) + 8 targets × 20 bytes each)
   - Conntrack key: 40 bytes
   - Conntrack value: 96 bytes

   Register allocation:
   r6 = saved XDP context (callee-saved)
   r7 = data pointer (callee-saved)
   r8 = data_end pointer (callee-saved)
   r9 = IP header pointer / map value ptr (callee-saved)
   r0-r5 = scratch, clobbered by helpers"
  [listen-map-fd config-map-fd sni-map-fd conntrack-map-fd
   rate-limit-config-fd rate-limit-src-fd rate-limit-backend-fd]
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

      ;; Load ethertype
      (eth/load-ethertype :r9 :r7)

      ;; Branch on EtherType: IPv4 or IPv6
      [(asm/jmp-imm :jeq :r9 common/ETH-P-IP-BE :ipv4_path)
       (asm/jmp-imm :jeq :r9 common/ETH-P-IPV6-BE :ipv6_path)
       (asm/jmp :pass)]

      ;; =====================================================================
      ;; IPv4 Path: Parse IPv4 header and store in unified format
      ;; =====================================================================
      [(asm/label :ipv4_path)]

      ;; Store address family (4 = IPv4)
      [(dsl/mov :r0 4)
       (dsl/stx :b :r10 :r0 -106)]

      ;; Calculate IP header pointer: data + ETH_HLEN
      (eth/get-ip-header-ptr :r9 :r7)

      ;; Check IP header bounds (minimum 20 bytes)
      (asm/check-bounds :r9 :r8 net/IPV4-MIN-HLEN :pass :r0)

      ;; Load and store protocol
      [(dsl/ldx :b :r0 :r9 9)           ; protocol at offset 9
       (dsl/stx :b :r10 :r0 -105)]      ; store at stack[-105]

      ;; Load source IP (4 bytes) and store in unified format (16 bytes)
      ;; Zero first 12 bytes, then store 4-byte IP
      [(dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -84)       ; zero bytes 0-7 of src_ip
       (dsl/stx :w :r10 :r0 -76)        ; zero bytes 8-11 of src_ip
       (dsl/ldx :w :r0 :r9 12)          ; load src_ip (4 bytes)
       (dsl/stx :w :r10 :r0 -72)]       ; store at bytes 12-15 (offset -84+12 = -72)

      ;; Load destination IP and store in unified format
      [(dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -44)       ; zero bytes 0-7 of old_dst_ip
       (dsl/stx :w :r10 :r0 -36)        ; zero bytes 8-11 of old_dst_ip
       (dsl/ldx :w :r0 :r9 16)          ; load dst_ip (4 bytes)
       (dsl/stx :w :r10 :r0 -32)]       ; store at bytes 12-15 of old_dst_ip

      ;; Also store original dst_ip for conntrack
      [(dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -100)      ; zero bytes 0-7 of dst_ip_orig
       (dsl/stx :w :r10 :r0 -92)        ; zero bytes 8-11 of dst_ip_orig
       (dsl/ldx :w :r0 :r9 16)          ; load dst_ip again
       (dsl/stx :w :r10 :r0 -88)]       ; store at bytes 12-15 of dst_ip_orig

      ;; Calculate L4 header offset (ETH_HLEN + 20 for min IP header)
      [(dsl/mov :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :w :r10 :r0 -112)]

      [(asm/jmp :protocol_dispatch)]

      ;; =====================================================================
      ;; IPv6 Path: Parse IPv6 header (fixed 40 bytes)
      ;; =====================================================================
      [(asm/label :ipv6_path)]

      ;; Store address family (6 = IPv6)
      [(dsl/mov :r0 6)
       (dsl/stx :b :r10 :r0 -106)]

      ;; Check IPv6 header bounds (fixed 40 bytes)
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (asm/jmp-reg :jgt :r0 :r8 :pass)]

      ;; Get IPv6 header pointer
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)]

      ;; Load and store Next Header (protocol) at offset 6
      [(dsl/ldx :b :r0 :r9 common/IPV6-OFF-NEXT-HEADER)
       (dsl/stx :b :r10 :r0 -105)]

      ;; Load source IP (16 bytes) at offset 8
      [(dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 0))
       (dsl/stx :w :r10 :r0 -84)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 4))
       (dsl/stx :w :r10 :r0 -80)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 8))
       (dsl/stx :w :r10 :r0 -76)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-SRC 12))
       (dsl/stx :w :r10 :r0 -72)]

      ;; Load destination IP (16 bytes) at offset 24 - store as old_dst_ip
      [(dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 0))
       (dsl/stx :w :r10 :r0 -44)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 4))
       (dsl/stx :w :r10 :r0 -40)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 8))
       (dsl/stx :w :r10 :r0 -36)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 12))
       (dsl/stx :w :r10 :r0 -32)]

      ;; Also store as dst_ip_orig for conntrack
      [(dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 0))
       (dsl/stx :w :r10 :r0 -100)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 4))
       (dsl/stx :w :r10 :r0 -96)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 8))
       (dsl/stx :w :r10 :r0 -92)
       (dsl/ldx :w :r0 :r9 (+ common/IPV6-OFF-DST 12))
       (dsl/stx :w :r10 :r0 -88)]

      ;; Calculate L4 header offset (ETH_HLEN + 40 for IPv6 header)
      [(dsl/mov :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (dsl/stx :w :r10 :r0 -112)]

      ;; Fall through to protocol dispatch

      ;; =====================================================================
      ;; PHASE 2: Protocol Dispatch (TCP/UDP)
      ;; =====================================================================
      [(asm/label :protocol_dispatch)]

      [(dsl/ldx :b :r0 :r10 -105)       ; load protocol
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_path_unified)
       (asm/jmp-imm :jeq :r0 net/IPPROTO-UDP :udp_path_unified)
       (asm/jmp :pass)]

      ;; =====================================================================
      ;; TCP Path: Parse TCP header and extract ports
      ;; =====================================================================
      [(asm/label :tcp_path_unified)]

      ;; Get L4 header offset from stack
      [(dsl/ldx :w :r1 :r10 -112)]      ; r1 = L4 offset

      ;; Calculate L4 header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add-reg :r0 :r1)]           ; r0 = data + L4 offset

      ;; Check TCP header bounds (need at least 20 bytes)
      [(dsl/mov-reg :r1 :r0)
       (dsl/add :r1 20)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Load TCP ports
      [(dsl/ldx :h :r1 :r0 0)           ; src_port at offset 0
       (dsl/stx :h :r10 :r1 -102)       ; store at stack[-102]
       (dsl/ldx :h :r1 :r0 2)           ; dst_port at offset 2
       (dsl/stx :h :r10 :r1 -48)        ; store at stack[-48] (old_dst_port)
       (dsl/stx :h :r10 :r1 -104)]      ; store at stack[-104] (for conntrack)

      [(asm/jmp :lookup_listen_unified)]

      ;; =====================================================================
      ;; UDP Path: Parse UDP header and extract ports
      ;; =====================================================================
      [(asm/label :udp_path_unified)]

      ;; Get L4 header offset from stack
      [(dsl/ldx :w :r1 :r10 -112)]

      ;; Calculate L4 header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add-reg :r0 :r1)]

      ;; Check UDP header bounds (need at least 8 bytes)
      [(dsl/mov-reg :r1 :r0)
       (dsl/add :r1 8)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Load UDP ports
      [(dsl/ldx :h :r1 :r0 0)           ; src_port
       (dsl/stx :h :r10 :r1 -102)
       (dsl/ldx :h :r1 :r0 2)           ; dst_port
       (dsl/stx :h :r10 :r1 -48)        ; old_dst_port
       (dsl/stx :h :r10 :r1 -104)]

      ;; Fall through to lookup_listen_unified

      ;; =====================================================================
      ;; PHASE 3: Listen Map Lookup (Unified)
      ;; =====================================================================
      [(asm/label :lookup_listen_unified)]

      ;; Build listen map key at stack[-8]: {ifindex(4) + port(2) + af(1) + pad(1)}
      [(dsl/ldx :w :r0 :r6 12)          ; r0 = ifindex from xdp_md
       (dsl/stx :w :r10 :r0 -8)         ; key.ifindex
       (dsl/ldx :h :r0 :r10 -48)        ; r0 = dst_port (old)
       (dsl/stx :h :r10 :r0 -4)         ; key.port
       (dsl/ldx :b :r0 :r10 -106)       ; r0 = af
       (dsl/stx :b :r10 :r0 -2)         ; key.af
       (dsl/mov :r0 0)
       (dsl/stx :b :r10 :r0 -1)]        ; key.pad

      ;; Call bpf_map_lookup_elem(listen_map, &key)
      (if listen-map-fd
        (concat
          [(dsl/ld-map-fd :r1 listen-map-fd)
           (dsl/mov-reg :r2 :r10)
           (dsl/add :r2 -8)
           (dsl/call 1)]                 ; bpf_map_lookup_elem
          [(asm/jmp-imm :jeq :r0 0 :pass)
           (dsl/mov-reg :r9 :r0)         ; r9 = map value ptr
           (asm/jmp :do_nat_unified)])
        [(asm/jmp :pass)])

      ;; =====================================================================
      ;; PHASE 4: Weighted Target Selection (Unified - 20-byte targets)
      ;; =====================================================================
      [(asm/label :do_nat_unified)]

      ;; r9 = pointer to map value (unified weighted route format, 168 bytes):
      ;; Header (8 bytes): target_count(1) + reserved(3) + flags(2) + reserved(2)
      ;; Per target (20 bytes each): ip(16) + port(2) + cumulative_weight(2)

      ;; Load target_count from header byte 0
      [(dsl/ldx :b :r0 :r9 0)           ; r0 = target_count (1-8)
       (dsl/stx :w :r10 :r0 -116)]      ; store at stack[-116]

      ;; If target_count == 1, skip weighted selection
      [(asm/jmp-imm :jeq :r0 1 :single_target_unified)]

      ;; Store flags for PROXY protocol (at offset 4, 2 bytes)
      [(dsl/ldx :h :r6 :r9 4)           ; r6 = flags
       (dsl/stx :h :r10 :r6 -124)]      ; Store flags at stack[-124]

      ;; Multiple targets: use random selection (simplified for now)
      [(dsl/call common/BPF-FUNC-get-prandom-u32)]
      [(dsl/mod :r0 100)
       (dsl/stx :w :r10 :r0 -120)]      ; store random value

      ;; Loop through targets comparing with cumulative weights
      ;; Target entries start at offset 8, each is 20 bytes
      [(dsl/mov :r0 0)                  ; loop counter
       (dsl/mov :r1 8)]                 ; first target at offset 8

      [(asm/label :weight_loop_unified)]

      ;; Check loop bound
      [(asm/jmp-imm :jge :r0 8 :single_target_unified)]

      ;; Check against actual target_count
      [(dsl/ldx :w :r3 :r10 -116)
       (asm/jmp-reg :jge :r0 :r3 :single_target_unified)]

      ;; Calculate target offset: 8 + (counter * 20)
      ;; Using multiply: counter * 20 = counter * 4 * 5 = (counter << 2) * 5
      ;; Or simpler: counter * 16 + counter * 4 = counter * 20
      [(dsl/mov-reg :r1 :r0)
       (dsl/lsh :r1 4)                  ; r1 = counter * 16
       (dsl/mov-reg :r2 :r0)
       (dsl/lsh :r2 2)                  ; r2 = counter * 4
       (dsl/add-reg :r1 :r2)            ; r1 = counter * 20
       (dsl/add :r1 8)]                 ; r1 = 8 + counter * 20

      ;; Load cumulative_weight for this target (at offset 18 within target entry)
      [(dsl/mov-reg :r2 :r9)
       (dsl/add-reg :r2 :r1)            ; r2 = &target[i]
       (dsl/ldx :h :r3 :r2 18)          ; r3 = cumulative_weight (at offset 18)
       (dsl/ldx :w :r4 :r10 -120)]      ; r4 = random value

      ;; If random < cumulative_weight, select this target
      [(asm/jmp-reg :jlt :r4 :r3 :select_target_unified)]

      ;; Otherwise, continue loop
      [(dsl/add :r0 1)
       (asm/jmp :weight_loop_unified)]

      ;; =====================================================================
      ;; Select current target (r1 = offset within map value)
      ;; =====================================================================
      [(asm/label :select_target_unified)]

      ;; Load selected target IP (16 bytes at offset r1+0)
      [(dsl/mov-reg :r2 :r9)
       (dsl/add-reg :r2 :r1)]           ; r2 = &target[selected]

      ;; Copy 16-byte IP to nat_dst_ip at stack[-64]
      [(dsl/ldx :w :r3 :r2 0)
       (dsl/stx :w :r10 :r3 -64)
       (dsl/ldx :w :r3 :r2 4)
       (dsl/stx :w :r10 :r3 -60)
       (dsl/ldx :w :r3 :r2 8)
       (dsl/stx :w :r10 :r3 -56)
       (dsl/ldx :w :r3 :r2 12)
       (dsl/stx :w :r10 :r3 -52)]

      ;; Load port at offset 16
      [(dsl/ldx :h :r3 :r2 16)
       (dsl/stx :h :r10 :r3 -68)]       ; nat_dst_port

      [(asm/jmp :do_checksum_unified)]

      ;; =====================================================================
      ;; Single target: use first target at offset 8
      ;; =====================================================================
      [(asm/label :single_target_unified)]

      ;; Store flags for PROXY protocol (even for single target)
      [(dsl/ldx :h :r0 :r9 4)           ; r0 = flags
       (dsl/stx :h :r10 :r0 -124)]      ; Store flags at stack[-124]

      ;; Load first target IP (16 bytes)
      [(dsl/ldx :w :r1 :r9 8)
       (dsl/stx :w :r10 :r1 -64)
       (dsl/ldx :w :r1 :r9 12)
       (dsl/stx :w :r10 :r1 -60)
       (dsl/ldx :w :r1 :r9 16)
       (dsl/stx :w :r10 :r1 -56)
       (dsl/ldx :w :r1 :r9 20)
       (dsl/stx :w :r10 :r1 -52)]

      ;; Load port at offset 24 (8 + 16)
      [(dsl/ldx :h :r2 :r9 24)
       (dsl/stx :h :r10 :r2 -68)]

      ;; Fall through to do_checksum_unified

      ;; =====================================================================
      ;; PHASE 5: Checksum Update and NAT
      ;; =====================================================================
      [(asm/label :do_checksum_unified)]

      ;; Branch by address family for checksum
      [(dsl/ldx :b :r0 :r10 -106)       ; load af
       (asm/jmp-imm :jeq :r0 4 :ipv4_nat_unified)
       (asm/jmp :ipv6_nat_unified)]

      ;; =====================================================================
      ;; IPv4 NAT: Update IP checksum, L4 checksum, write values
      ;; =====================================================================
      [(asm/label :ipv4_nat_unified)]

      ;; Branch by protocol
      [(dsl/ldx :b :r0 :r10 -105)
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_nat_unified)
       (asm/jmp :udp_nat_unified)]

      ;; =====================================================================
      ;; IPv4 TCP NAT
      ;; =====================================================================
      [(asm/label :tcp_nat_unified)]

      ;; Re-validate packet bounds
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 54)                 ; ETH(14) + IP(20) + TCP(20)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Get IP header pointer
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)]

      ;; For IPv4, we store the 4-byte IP at offset 12 in the 16-byte field
      ;; old_dst_ip at stack[-44..-29]: actual IP at [-32] (offset 12)
      ;; nat_dst_ip at stack[-64..-49]: actual IP at [-52] (offset 12)

      ;; Update IP checksum using bpf_csum_diff
      ;; old value at stack[-32] (4 bytes), new value at stack[-52] (4 bytes)
      [(dsl/mov-reg :r1 :r10)
       (dsl/add :r1 -32)                ; r1 = &old_dst_ip (4 bytes)
       (dsl/mov :r2 4)
       (dsl/mov-reg :r3 :r10)
       (dsl/add :r3 -52)                ; r3 = &new_dst_ip (4 bytes)
       (dsl/mov :r4 4)
       (dsl/mov :r5 0)
       (dsl/call BPF-FUNC-csum-diff)]

      ;; Save diff for L4 checksum
      [(dsl/stx :w :r10 :r0 -128)]

      ;; Re-validate bounds
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 54)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Apply diff to IP checksum
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :h :r1 :r9 10)          ; old IP checksum
       (dsl/ldx :w :r2 :r10 -128)]      ; diff
      (xdp-apply-csum-diff :r1 :r2 :r3)
      [(dsl/stx :h :r9 :r1 10)]         ; store new IP checksum

      ;; Update TCP checksum
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r0 16)]         ; old TCP checksum

      ;; Apply IP diff
      [(dsl/ldx :w :r2 :r10 -128)]
      (xdp-apply-csum-diff :r1 :r2 :r3)

      ;; Apply port diff
      [(dsl/ldx :h :r2 :r10 -48)        ; old_dst_port
       (dsl/ldx :h :r3 :r10 -68)]       ; new_dst_port
      (xdp-update-csum-for-port-change :r1 :r2 :r3 :r4)

      ;; Store new TCP checksum
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :h :r0 :r1 16)]

      ;; Write new dst_ip to IP header (4 bytes from stack[-52])
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -52)        ; new_dst_ip (4 bytes)
       (dsl/stx :w :r9 :r1 16)]         ; ip->daddr

      ;; Write new dst_port to TCP header
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r10 -68)
       (dsl/stx :h :r0 :r1 2)]

      [(asm/jmp :create_conntrack_unified)]

      ;; =====================================================================
      ;; IPv4 UDP NAT
      ;; =====================================================================
      [(asm/label :udp_nat_unified)]

      ;; Re-validate packet bounds
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 42)                 ; ETH(14) + IP(20) + UDP(8)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Get IP header pointer
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)]

      ;; Update IP checksum
      [(dsl/mov-reg :r1 :r10)
       (dsl/add :r1 -32)
       (dsl/mov :r2 4)
       (dsl/mov-reg :r3 :r10)
       (dsl/add :r3 -52)
       (dsl/mov :r4 4)
       (dsl/mov :r5 0)
       (dsl/call BPF-FUNC-csum-diff)]
      [(dsl/stx :w :r10 :r0 -128)]

      ;; Re-validate and apply
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 42)
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :h :r1 :r9 10)
       (dsl/ldx :w :r2 :r10 -128)]
      (xdp-apply-csum-diff :r1 :r2 :r3)
      [(dsl/stx :h :r9 :r1 10)]

      ;; Update UDP checksum if non-zero
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r0 6)]
      [(asm/jmp-imm :jeq :r1 0 :udp_write_values_unified)]

      [(dsl/ldx :w :r2 :r10 -128)]
      (xdp-apply-csum-diff :r1 :r2 :r3)
      [(dsl/ldx :h :r2 :r10 -48)
       (dsl/ldx :h :r3 :r10 -68)]
      (xdp-update-csum-for-port-change :r1 :r2 :r3 :r4)
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/stx :h :r0 :r1 6)]

      [(asm/label :udp_write_values_unified)]

      ;; Write new dst_ip to IP header
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -52)
       (dsl/stx :w :r9 :r1 16)]

      ;; Write new dst_port to UDP header
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
       (dsl/ldx :h :r1 :r10 -68)
       (dsl/stx :h :r0 :r1 2)]

      [(asm/jmp :create_conntrack_unified)]

      ;; =====================================================================
      ;; IPv6 NAT: No IP checksum, only L4 checksum update
      ;; =====================================================================
      [(asm/label :ipv6_nat_unified)]

      ;; Branch by protocol
      [(dsl/ldx :b :r0 :r10 -105)
       (asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :tcp_nat_ipv6)
       (asm/jmp :udp_nat_ipv6)]

      ;; =====================================================================
      ;; IPv6 TCP NAT
      ;; =====================================================================
      [(asm/label :tcp_nat_ipv6)]

      ;; Re-validate packet bounds
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 (+ net/ETH-HLEN common/IPV6-HLEN 20)) ; ETH + IPv6 + TCP min
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; For IPv6, we need to update TCP checksum for:
      ;; 1. Destination address change (16 bytes)
      ;; 2. Destination port change (2 bytes)

      ;; Calculate checksum diff for 16-byte IP address
      ;; old_dst_ip at stack[-44..-29], new at stack[-64..-49]
      [(dsl/mov-reg :r1 :r10)
       (dsl/add :r1 -44)                ; old dst IP (16 bytes)
       (dsl/mov :r2 16)
       (dsl/mov-reg :r3 :r10)
       (dsl/add :r3 -64)                ; new dst IP (16 bytes)
       (dsl/mov :r4 16)
       (dsl/mov :r5 0)
       (dsl/call BPF-FUNC-csum-diff)]
      [(dsl/stx :w :r10 :r0 -128)]      ; save diff

      ;; Re-validate bounds
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 (+ net/ETH-HLEN common/IPV6-HLEN 20))
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Get TCP header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))]

      ;; Load old TCP checksum
      [(dsl/ldx :h :r1 :r0 16)]

      ;; Apply IP diff
      [(dsl/ldx :w :r2 :r10 -128)]
      (xdp-apply-csum-diff :r1 :r2 :r3)

      ;; Apply port diff
      [(dsl/ldx :h :r2 :r10 -48)        ; old_dst_port
       (dsl/ldx :h :r3 :r10 -68)]       ; new_dst_port
      (xdp-update-csum-for-port-change :r1 :r2 :r3 :r4)

      ;; Store new TCP checksum
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (dsl/stx :h :r0 :r1 16)]

      ;; Write new destination IP to IPv6 header (16 bytes at offset 24)
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -64)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-DST 0))
       (dsl/ldx :w :r1 :r10 -60)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-DST 4))
       (dsl/ldx :w :r1 :r10 -56)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-DST 8))
       (dsl/ldx :w :r1 :r10 -52)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-DST 12))]

      ;; Write new dst_port to TCP header
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (dsl/ldx :h :r1 :r10 -68)
       (dsl/stx :h :r0 :r1 2)]

      [(asm/jmp :create_conntrack_unified)]

      ;; =====================================================================
      ;; IPv6 UDP NAT
      ;; =====================================================================
      [(asm/label :udp_nat_ipv6)]

      ;; Re-validate packet bounds
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 (+ net/ETH-HLEN common/IPV6-HLEN 8)) ; ETH + IPv6 + UDP
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Calculate checksum diff for 16-byte IP
      [(dsl/mov-reg :r1 :r10)
       (dsl/add :r1 -44)
       (dsl/mov :r2 16)
       (dsl/mov-reg :r3 :r10)
       (dsl/add :r3 -64)
       (dsl/mov :r4 16)
       (dsl/mov :r5 0)
       (dsl/call BPF-FUNC-csum-diff)]
      [(dsl/stx :w :r10 :r0 -128)]

      ;; Re-validate
      (xdp-load-data-ptrs-32 :r7 :r8 :r6)
      [(dsl/mov-reg :r1 :r7)
       (dsl/add :r1 (+ net/ETH-HLEN common/IPV6-HLEN 8))
       (asm/jmp-reg :jgt :r1 :r8 :pass)]

      ;; Get UDP header pointer
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))]

      ;; Load UDP checksum - for IPv6 UDP checksum is mandatory (non-zero)
      [(dsl/ldx :h :r1 :r0 6)]
      [(asm/jmp-imm :jeq :r1 0 :udp_write_values_ipv6)]

      ;; Apply IP diff
      [(dsl/ldx :w :r2 :r10 -128)]
      (xdp-apply-csum-diff :r1 :r2 :r3)

      ;; Apply port diff
      [(dsl/ldx :h :r2 :r10 -48)
       (dsl/ldx :h :r3 :r10 -68)]
      (xdp-update-csum-for-port-change :r1 :r2 :r3 :r4)

      ;; Store new UDP checksum
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (dsl/stx :h :r0 :r1 6)]

      [(asm/label :udp_write_values_ipv6)]

      ;; Write new destination IP to IPv6 header
      [(dsl/mov-reg :r9 :r7)
       (dsl/add :r9 net/ETH-HLEN)
       (dsl/ldx :w :r1 :r10 -64)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-DST 0))
       (dsl/ldx :w :r1 :r10 -60)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-DST 4))
       (dsl/ldx :w :r1 :r10 -56)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-DST 8))
       (dsl/ldx :w :r1 :r10 -52)
       (dsl/stx :w :r9 :r1 (+ common/IPV6-OFF-DST 12))]

      ;; Write new dst_port to UDP header
      [(dsl/mov-reg :r0 :r7)
       (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
       (dsl/ldx :h :r1 :r10 -68)
       (dsl/stx :h :r0 :r1 2)]

      ;; Fall through to create_conntrack_unified

      ;; =====================================================================
      ;; PHASE 6: Create Unified Conntrack Entry (40-byte key, 96-byte value)
      ;; =====================================================================
      [(asm/label :create_conntrack_unified)]

      ;; Build conntrack key at stack[-184] (40 bytes)
      ;; Layout: src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2) + proto(1) + pad(3)

      ;; Copy src_ip (16 bytes) from stack[-84..-69]
      [(dsl/ldx :w :r0 :r10 -84)
       (dsl/stx :w :r10 :r0 -184)
       (dsl/ldx :w :r0 :r10 -80)
       (dsl/stx :w :r10 :r0 -180)
       (dsl/ldx :w :r0 :r10 -76)
       (dsl/stx :w :r10 :r0 -176)
       (dsl/ldx :w :r0 :r10 -72)
       (dsl/stx :w :r10 :r0 -172)]

      ;; Copy nat_dst_ip (16 bytes) from stack[-64..-49]
      [(dsl/ldx :w :r0 :r10 -64)
       (dsl/stx :w :r10 :r0 -168)
       (dsl/ldx :w :r0 :r10 -60)
       (dsl/stx :w :r10 :r0 -164)
       (dsl/ldx :w :r0 :r10 -56)
       (dsl/stx :w :r10 :r0 -160)
       (dsl/ldx :w :r0 :r10 -52)
       (dsl/stx :w :r10 :r0 -156)]

      ;; Copy ports and protocol
      [(dsl/ldx :h :r0 :r10 -102)       ; src_port
       (dsl/stx :h :r10 :r0 -152)
       (dsl/ldx :h :r0 :r10 -68)        ; nat_dst_port
       (dsl/stx :h :r10 :r0 -150)
       (dsl/ldx :b :r0 :r10 -105)       ; protocol
       (dsl/stx :b :r10 :r0 -148)
       (dsl/mov :r0 0)
       (dsl/stx :b :r10 :r0 -147)       ; pad[0]
       (dsl/stx :h :r10 :r0 -146)]      ; pad[1-2]

      ;; Build conntrack value at stack[-312] (128 bytes)
      ;; Layout: orig_dst_ip(16) + orig_dst_port(2) + pad(2) +
      ;;         nat_dst_ip(16) + nat_dst_port(2) + pad(2) +
      ;;         created_ns(8) + last_seen_ns(8) +
      ;;         packets_fwd(8) + packets_rev(8) + bytes_fwd(8) + bytes_rev(8) +
      ;;         conn_state(1) + proxy_flags(1) + pad(2) + seq_offset(4) +
      ;;         orig_client_ip(16) + orig_client_port(2) + pad(6)

      ;; Copy orig_dst_ip (old_dst_ip from stack[-44..-29])
      [(dsl/ldx :w :r0 :r10 -44)
       (dsl/stx :w :r10 :r0 -312)
       (dsl/ldx :w :r0 :r10 -40)
       (dsl/stx :w :r10 :r0 -308)
       (dsl/ldx :w :r0 :r10 -36)
       (dsl/stx :w :r10 :r0 -304)
       (dsl/ldx :w :r0 :r10 -32)
       (dsl/stx :w :r10 :r0 -300)]

      ;; orig_dst_port and pad
      [(dsl/ldx :h :r0 :r10 -48)        ; old_dst_port
       (dsl/stx :h :r10 :r0 -296)
       (dsl/mov :r0 0)
       (dsl/stx :h :r10 :r0 -294)]      ; pad

      ;; Copy nat_dst_ip
      [(dsl/ldx :w :r0 :r10 -64)
       (dsl/stx :w :r10 :r0 -292)
       (dsl/ldx :w :r0 :r10 -60)
       (dsl/stx :w :r10 :r0 -288)
       (dsl/ldx :w :r0 :r10 -56)
       (dsl/stx :w :r10 :r0 -284)
       (dsl/ldx :w :r0 :r10 -52)
       (dsl/stx :w :r10 :r0 -280)]

      ;; nat_dst_port and pad
      [(dsl/ldx :h :r0 :r10 -68)
       (dsl/stx :h :r10 :r0 -276)
       (dsl/mov :r0 0)
       (dsl/stx :h :r10 :r0 -274)]

      ;; Get timestamp
      [(dsl/call BPF-FUNC-ktime-get-ns)
       (dsl/stx :dw :r10 :r0 -272)      ; created_ns
       (dsl/stx :dw :r10 :r0 -264)]     ; last_seen_ns

      ;; Initialize counters
      [(dsl/mov :r0 1)
       (dsl/stx :dw :r10 :r0 -256)      ; packets_fwd = 1
       (dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -248)]     ; packets_rev = 0

      ;; Calculate packet length
      [(dsl/mov-reg :r0 :r8)
       (dsl/sub-reg :r0 :r7)
       (dsl/stx :dw :r10 :r0 -240)      ; bytes_fwd
       (dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -232)]     ; bytes_rev = 0

      ;; Initialize PROXY protocol fields at offset 96 from base (-312 + 96 = -216)
      ;; Check if PROXY protocol flag is set (bit 2 = 0x04 in route flags at stack[-124])
      [(dsl/ldx :h :r0 :r10 -124)       ; Load route flags
       (asm/jmp-imm :jset :r0 4 :set_proxy_fields)]  ; If FLAG-PROXY-PROTOCOL-V2 (0x04) set

      ;; PROXY disabled: zero all fields
      [(dsl/mov :r0 0)
       (dsl/stx :dw :r10 :r0 -216)      ; conn_state=0, proxy_flags=0, pad, seq_offset=0
       (dsl/stx :dw :r10 :r0 -208)      ; Zero orig_client_ip bytes 0-7
       (dsl/stx :dw :r10 :r0 -200)      ; Zero orig_client_ip bytes 8-15
       (dsl/stx :dw :r10 :r0 -192)]     ; Zero orig_client_port + pad
      [(asm/jmp :conntrack_map_update)]

      ;; PROXY enabled: set fields
      [(asm/label :set_proxy_fields)]
      ;; conn_state = 0 (NEW), proxy_flags = 0x01 (ENABLED), pad = 0, seq_offset = 0
      ;; Build 8-byte value: 0x01 at byte 1 (proxy_flags), rest zero
      [(dsl/mov :r0 0x0100)             ; Little-endian: 0x00, 0x01 (conn_state=0, proxy_flags=1)
       (dsl/stx :w :r10 :r0 -216)       ; Store conn_state + proxy_flags + pad
       (dsl/mov :r0 0)
       (dsl/stx :w :r10 :r0 -212)]      ; Store seq_offset = 0

      ;; Copy original client IP from stack[-84] to orig_client_ip at stack[-208]
      [(dsl/ldx :dw :r0 :r10 -84)
       (dsl/stx :dw :r10 :r0 -208)
       (dsl/ldx :dw :r0 :r10 -76)
       (dsl/stx :dw :r10 :r0 -200)]

      ;; Copy original client port from stack[-102] to orig_client_port at stack[-192]
      [(dsl/ldx :h :r0 :r10 -102)       ; Load src_port (2 bytes)
       (dsl/stx :h :r10 :r0 -192)       ; Store orig_client_port
       (dsl/mov :r0 0)
       (dsl/stx :h :r10 :r0 -190)       ; Zero pad (2 bytes)
       (dsl/stx :w :r10 :r0 -188)]      ; Zero remaining pad (4 bytes)

      [(asm/label :conntrack_map_update)]

      ;; Update conntrack map
      (if conntrack-map-fd
        [(dsl/ld-map-fd :r1 conntrack-map-fd)
         (dsl/mov-reg :r2 :r10)
         (dsl/add :r2 -184)             ; &key
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 -312)             ; &value
         (dsl/mov :r4 0)                ; BPF_ANY
         (dsl/call 2)]                  ; bpf_map_update_elem
        [])

      ;; Return XDP_PASS
      [(asm/label :done_unified)]
      (net/return-action net/XDP-PASS)

      [(asm/label :pass)]
      (net/return-action net/XDP-PASS))))

(defn build-xdp-ingress-program-unified
  "Build the unified XDP ingress program for IPv4/IPv6 dual-stack.

   Performs DNAT on incoming packets:
   1. Branches on EtherType (IPv4 or IPv6)
   2. Looks up listen map by (ifindex, dst_port, af)
   3. If match found, rewrites destination IP/port
   4. Updates checksums (IP header for IPv4 only, L4 for both)
   5. Creates unified conntrack entry
   6. Returns XDP_PASS

   map-fds: Map containing unified maps from create-all-maps-unified"
  [map-fds]
  (let [listen-map-fd (when (and (map? map-fds) (:listen-map map-fds))
                        (common/map-fd (:listen-map map-fds)))
        config-map-fd (when (and (map? map-fds) (:config-map map-fds))
                        (common/map-fd (:config-map map-fds)))
        sni-map-fd (when (and (map? map-fds) (:sni-map map-fds))
                     (common/map-fd (:sni-map map-fds)))
        conntrack-map-fd (when (and (map? map-fds) (:conntrack-map map-fds))
                           (common/map-fd (:conntrack-map map-fds)))
        rate-limit-config-fd (when (and (map? map-fds) (:rate-limit-config-map map-fds))
                               (common/map-fd (:rate-limit-config-map map-fds)))
        rate-limit-src-fd (when (and (map? map-fds) (:rate-limit-src-map map-fds))
                            (common/map-fd (:rate-limit-src-map map-fds)))
        rate-limit-backend-fd (when (and (map? map-fds) (:rate-limit-backend-map map-fds))
                                (common/map-fd (:rate-limit-backend-map map-fds)))]
    (build-xdp-dnat-program-unified listen-map-fd config-map-fd sni-map-fd conntrack-map-fd
                                     rate-limit-config-fd rate-limit-src-fd rate-limit-backend-fd)))

(defn load-program-unified
  "Load the unified XDP ingress program for IPv4/IPv6 dual-stack.
   Returns a BpfProgram record."
  [maps]
  (log/info "Loading unified XDP ingress program (IPv4/IPv6)")
  (let [bytecode (build-xdp-ingress-program-unified maps)]
    (require '[clj-ebpf.programs :as programs])
    ((resolve 'clj-ebpf.programs/load-program)
      {:insns bytecode
       :prog-type :xdp
       :prog-name "xdp_ingress_v6"
       :license "GPL"
       :log-level 1})))

(defn build-xdp-ingress-program
  "Build the XDP ingress program.

   Performs DNAT on incoming packets:
   1. For TCP port 443, attempts SNI-based routing (TLS ClientHello parsing)
   2. Falls back to listen map lookup by (ifindex, dst_port)
   3. Falls back to config map LPM lookup by source IP
   4. If match found, rewrites destination IP/port
   5. Updates IP and L4 checksums
   6. Creates conntrack entry for TC SNAT
   7. Returns XDP_PASS to let kernel routing deliver packet

   Rate limiting (if configured):
   - Per-source: Applied after parsing source IP
   - Per-backend: Applied after target selection

   map-fds: Map containing :listen-map, optionally :config-map, :sni-map, :conntrack-map,
            and rate limit maps"
  [map-fds]
  (let [listen-map-fd (when (and (map? map-fds) (:listen-map map-fds))
                        (common/map-fd (:listen-map map-fds)))
        config-map-fd (when (and (map? map-fds) (:config-map map-fds))
                        (common/map-fd (:config-map map-fds)))
        sni-map-fd (when (and (map? map-fds) (:sni-map map-fds))
                     (common/map-fd (:sni-map map-fds)))
        conntrack-map-fd (when (and (map? map-fds) (:conntrack-map map-fds))
                           (common/map-fd (:conntrack-map map-fds)))
        rate-limit-config-fd (when (and (map? map-fds) (:rate-limit-config-map map-fds))
                               (common/map-fd (:rate-limit-config-map map-fds)))
        rate-limit-src-fd (when (and (map? map-fds) (:rate-limit-src-map map-fds))
                            (common/map-fd (:rate-limit-src-map map-fds)))
        rate-limit-backend-fd (when (and (map? map-fds) (:rate-limit-backend-map map-fds))
                                (common/map-fd (:rate-limit-backend-map map-fds)))]
    (build-xdp-dnat-program listen-map-fd config-map-fd sni-map-fd conntrack-map-fd
                            rate-limit-config-fd rate-limit-src-fd rate-limit-backend-fd)))

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
