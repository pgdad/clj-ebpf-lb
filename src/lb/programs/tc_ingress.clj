(ns lb.programs.tc-ingress
  "TC ingress program for PROXY protocol v2 header injection.

   This program runs on the TC ingress path (after XDP DNAT) and injects
   PROXY protocol v2 headers into the first data packet of each connection
   that has proxy-protocol enabled.

   Flow:
   1. Parse packet headers (Ethernet, IPv4/IPv6, TCP)
   2. Lookup conntrack entry by 5-tuple
   3. Check if proxy_enabled flag is set
   4. Track TCP state (NEW -> SYN_SENT -> SYN_RECV -> ESTABLISHED)
   5. On first DATA packet in ESTABLISHED: inject PROXY v2 header
   6. Set header_injected flag and seq_offset for subsequent packets"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.asm :as asm]
            [clj-ebpf.net :as net]
            [clj-ebpf.net.ethernet :as eth]
            [lb.programs.common :as common]
            [lb.util :as util]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; TC Ingress Program Structure
;;; =============================================================================

;; The TC ingress program handles PROXY protocol header injection:
;; 1. Parse packet headers (Ethernet, IP, TCP)
;; 2. Build 5-tuple key from packet
;; 3. Look up connection in conntrack map
;; 4. If proxy_enabled is NOT set, return TC_ACT_OK immediately
;; 5. Track TCP state transitions:
;;    - NEW + SYN flag -> SYN_SENT, update conntrack
;;    - SYN_SENT + SYN-ACK -> SYN_RECV, update conntrack
;;    - SYN_RECV + ACK (no SYN) -> ESTABLISHED, update conntrack
;;    - ESTABLISHED + !header_injected + data -> INJECT PROXY HEADER
;; 6. For packets after injection: adjust TCP seq numbers
;; 7. Return TC_ACT_OK

;; Register allocation:
;; r1 = SKB context (input, clobbered by helpers)
;; r6 = saved SKB context (callee-saved)
;; r7 = data pointer (callee-saved)
;; r8 = data_end pointer (callee-saved)
;; r9 = conntrack value ptr / scratch (callee-saved)
;; r0-r5 = scratch, clobbered by helper calls

;; Stack layout for unified IPv4/IPv6 (negative offsets from r10):
;; -40   : Conntrack key (40 bytes, uses -80 to -41)
;; -44   : tcp_flags (2 bytes) + tcp_hdr_len (2 bytes)
;; -48   : L4 header offset (4 bytes)
;; -52   : af (1 byte) + protocol (1 byte) + pad (2 bytes)
;; -56   : payload_offset (4 bytes) - offset where TCP payload starts
;; -60   : total_len (2 bytes) + pad (2 bytes) - IP total length
;; -64   : seq_num (4 bytes) - TCP sequence number
;; -68   : conn_state (1 byte) - saved from conntrack
;; -72   : header_size (4 bytes) - PROXY header size (28 or 52)
;; -76   : payload_len (4 bytes) - original TCP payload length
;; -80   : current_chunk (4 bytes) - current chunk index for shifting
;; -144  : PROXY v2 header buffer start (52 bytes for IPv6, 28 for IPv4)
;;         Layout: sig(12) + ver/cmd(1) + family(1) + len(2) + addresses
;;         IPv4 addresses: src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2)
;;         IPv6 addresses: src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2)
;; -208  : chunk_buffer (64 bytes) - temp buffer for payload shifting
;; -212  : temp_len (4 bytes) - saved length for bpf_skb_store_bytes
;; -216  : original_pkt_len (4 bytes) - skb->len before extending
;; -220  : seq_offset (4 bytes) - saved seq offset for adjust_seq
;; -228  : seq_value (4 bytes) - buffer for seq number load/store
;; -232  : old_seq (4 bytes) - old seq value for checksum update

;;; =============================================================================
;;; BPF Helper Function Numbers
;;; =============================================================================

(def ^:const BPF-FUNC-map-lookup-elem 1)
(def ^:const BPF-FUNC-map-update-elem 2)
(def ^:const BPF-FUNC-ktime-get-ns 5)
(def ^:const BPF-FUNC-skb-store-bytes 9)
(def ^:const BPF-FUNC-l3-csum-replace 10)
(def ^:const BPF-FUNC-l4-csum-replace 11)
(def ^:const BPF-FUNC-skb-load-bytes 26)
(def ^:const BPF-FUNC-skb-change-tail 38)

;; BPF_F flags
(def ^:const BPF-F-RECOMPUTE-CSUM 0x01)
(def ^:const BPF-F-INVALIDATE-HASH 0x02)
(def ^:const BPF-F-PSEUDO-HDR 0x10)

;;; =============================================================================
;;; TCP Flags and Connection States
;;; =============================================================================

(def ^:const TCP-FLAG-FIN 0x01)
(def ^:const TCP-FLAG-SYN 0x02)
(def ^:const TCP-FLAG-RST 0x04)
(def ^:const TCP-FLAG-PSH 0x08)
(def ^:const TCP-FLAG-ACK 0x10)

(def ^:const CONN-STATE-NEW 0)
(def ^:const CONN-STATE-SYN-SENT 1)
(def ^:const CONN-STATE-SYN-RECV 2)
(def ^:const CONN-STATE-ESTABLISHED 3)

;; PROXY protocol flags (in conntrack value at offset 97)
(def ^:const PROXY-FLAG-ENABLED 0x01)
(def ^:const PROXY-FLAG-HEADER-INJECTED 0x02)

;;; =============================================================================
;;; PROXY Protocol v2 Constants
;;; =============================================================================

(def ^:const PROXY-V2-HEADER-SIZE-IPV4 28)
(def ^:const PROXY-V2-HEADER-SIZE-IPV6 52)

;; Payload shifting constants
;; Chunk size for copying - must fit in stack buffer
(def ^:const SHIFT-CHUNK-SIZE 64)
;; Maximum number of chunks to shift (24 * 64 = 1536 bytes max payload)
;; This covers most practical TCP payloads on standard MTU
(def ^:const SHIFT-MAX-CHUNKS 24)

;; PROXY v2 signature (12 bytes): 0x0D 0x0A 0x0D 0x0A 0x00 0x0D 0x0A 0x51 0x55 0x49 0x54 0x0A
;; Split into 32-bit words for easier writing:
;; Word 0: 0x0D0A0D0A (little-endian: 0x0A0D0A0D)
;; Word 1: 0x000D0A51 (little-endian: 0x510A0D00)
;; Word 2: 0x5549540A (little-endian: 0x0A544955)
;; Actually, we need to write in network byte order (big-endian)
;; Signature bytes: 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A
;; As 32-bit BE words: 0x0D0A0D0A, 0x000D0A51, 0x5549540A
;; Version/Command (1 byte): 0x21
;; Family/Protocol (1 byte): 0x11 (IPv4/TCP) or 0x21 (IPv6/TCP)
;; Length (2 bytes BE): 12 (IPv4) or 36 (IPv6)

(def ^:const PROXY-V2-SIG-WORD0 0x0D0A0D0A)
(def ^:const PROXY-V2-SIG-WORD1 0x000D0A51)
(def ^:const PROXY-V2-SIG-WORD2 0x5549540A)
(def ^:const PROXY-V2-VERSION-CMD 0x21)
(def ^:const PROXY-V2-FAMILY-TCP-IPV4 0x11)
(def ^:const PROXY-V2-FAMILY-TCP-IPV6 0x21)
(def ^:const PROXY-V2-ADDR-LEN-IPV4 12)    ; 4+4+2+2 = 12
(def ^:const PROXY-V2-ADDR-LEN-IPV6 36)    ; 16+16+2+2 = 36

;;; =============================================================================
;;; Conntrack Value Field Offsets (128-byte unified format)
;;; =============================================================================

;; Offsets 0-95: Original conntrack fields
;; Offsets 96-127: PROXY protocol fields
(def ^:const CT-OFF-CONN-STATE 96)         ; TCP connection state (1 byte)
(def ^:const CT-OFF-PROXY-FLAGS 97)        ; PROXY flags (1 byte)
(def ^:const CT-OFF-PAD 98)                ; Padding (2 bytes)
(def ^:const CT-OFF-SEQ-OFFSET 100)        ; Sequence offset after injection (4 bytes)
(def ^:const CT-OFF-ORIG-CLIENT-IP 104)    ; Original client IP (16 bytes)
(def ^:const CT-OFF-ORIG-CLIENT-PORT 120)  ; Original client port (2 bytes)

;;; =============================================================================
;;; TC Data Access Helpers
;;; =============================================================================

(defn tc-load-skb-data
  "Load SKB data and data_end pointers.
   SKB structure: data at offset 76, data_end at offset 80
   Saves: SKB -> r6, data -> r7, data_end -> r8"
  []
  [(dsl/mov-reg :r6 :r1)                    ; Save SKB context
   (dsl/ldx :w :r7 :r1 common/SKB-OFF-DATA) ; data
   (dsl/ldx :w :r8 :r1 common/SKB-OFF-DATA-END)]) ; data_end

(defn tc-reload-data-ptrs
  "Reload data pointers from saved SKB context (r6).
   Required after helpers that may invalidate pointers."
  []
  [(dsl/ldx :w :r7 :r6 common/SKB-OFF-DATA)
   (dsl/ldx :w :r8 :r6 common/SKB-OFF-DATA-END)])

;;; =============================================================================
;;; Simple Pass-Through TC Program
;;; =============================================================================

(defn build-tc-pass-program
  "Build a simple TC program that passes all packets."
  []
  (asm/assemble-with-labels
    [(dsl/mov :r0 net/TC-ACT-OK)
     (dsl/exit-insn)]))

;;; =============================================================================
;;; TC Ingress PROXY Protocol State Tracking Program
;;; =============================================================================

(defn build-tc-ingress-proxy-program
  "Build the TC ingress program for PROXY protocol v2 header injection.

   This program:
   1. Parses Ethernet/IP/TCP headers
   2. Looks up conntrack entry by 5-tuple
   3. Checks proxy_enabled flag
   4. Tracks TCP state machine
   5. Injects PROXY v2 header on first data packet in ESTABLISHED state
   6. Adjusts sequence numbers for subsequent packets

   map-fds: Map containing :conntrack-map from unified maps

   Returns assembled TC program bytecode."
  [map-fds]
  (let [conntrack-map-fd (when (and (map? map-fds) (:conntrack-map map-fds))
                           (common/map-fd (:conntrack-map map-fds)))]
    (asm/assemble-with-labels
      (concat
        ;; =====================================================================
        ;; PHASE 1: Context Setup and Ethernet Parsing
        ;; =====================================================================

        ;; Save SKB context and load data pointers
        (tc-load-skb-data)

        ;; Check Ethernet header bounds
        (asm/check-bounds :r7 :r8 net/ETH-HLEN :pass :r0)

        ;; Load ethertype
        (eth/load-ethertype :r9 :r7)

        ;; Branch on EtherType: IPv4 or IPv6
        [(asm/jmp-imm :jeq :r9 common/ETH-P-IP-BE :ipv4_path)
         (asm/jmp-imm :jeq :r9 common/ETH-P-IPV6-BE :ipv6_path)
         (asm/jmp :pass)]

        ;; =====================================================================
        ;; IPv4 Path: Parse headers and build conntrack key
        ;; =====================================================================
        [(asm/label :ipv4_path)]

        ;; Store address family
        [(dsl/mov :r0 4)
         (dsl/stx :b :r10 :r0 -52)]

        ;; Check IP header bounds
        [(dsl/mov-reg :r0 :r7)
         (dsl/add :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
         (asm/jmp-reg :jgt :r0 :r8 :pass)]

        ;; Get IP header pointer
        [(dsl/mov-reg :r9 :r7)
         (dsl/add :r9 net/ETH-HLEN)]

        ;; Load protocol
        [(dsl/ldx :b :r0 :r9 9)
         (dsl/stx :b :r10 :r0 -51)]

        ;; Check for TCP only (PROXY protocol is TCP-only)
        ;; Use explicit jeq + jmp to avoid assembler issues with jne to far labels
        [(asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :ipv4_is_tcp)]
        [(asm/jmp :pass)]
        [(asm/label :ipv4_is_tcp)]

        ;; Build conntrack key: src_ip (16 bytes, zero-padded)
        [(dsl/mov :r0 0)
         (dsl/stx :dw :r10 :r0 -40)         ; Zero first 8 bytes
         (dsl/stx :w :r10 :r0 -32)          ; Zero bytes 8-11
         (dsl/ldx :w :r0 :r9 12)            ; Load src_ip
         (dsl/stx :w :r10 :r0 -28)]         ; Store at bytes 12-15

        ;; dst_ip (16 bytes, zero-padded)
        [(dsl/mov :r0 0)
         (dsl/stx :dw :r10 :r0 -24)
         (dsl/stx :w :r10 :r0 -16)
         (dsl/ldx :w :r0 :r9 16)
         (dsl/stx :w :r10 :r0 -12)]

        ;; Store L4 offset
        [(dsl/mov :r0 (+ net/ETH-HLEN net/IPV4-MIN-HLEN))
         (dsl/stx :w :r10 :r0 -48)]

        ;; Load and store IP total length for later
        [(dsl/ldx :h :r0 :r9 2)             ; IP total length (big-endian)
         (dsl/stx :h :r10 :r0 -60)]

        [(asm/jmp :parse_tcp)]

        ;; =====================================================================
        ;; IPv6 Path: Parse headers and build conntrack key
        ;; =====================================================================
        [(asm/label :ipv6_path)]

        ;; Store address family
        [(dsl/mov :r0 6)
         (dsl/stx :b :r10 :r0 -52)]

        ;; Check IPv6 header bounds
        [(dsl/mov-reg :r0 :r7)
         (dsl/add :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
         (asm/jmp-reg :jgt :r0 :r8 :pass)]

        ;; Get IPv6 header pointer
        [(dsl/mov-reg :r9 :r7)
         (dsl/add :r9 net/ETH-HLEN)]

        ;; Load next header (protocol)
        [(dsl/ldx :b :r0 :r9 common/IPV6-OFF-NEXT-HEADER)
         (dsl/stx :b :r10 :r0 -51)]

        ;; Check for TCP only
        ;; Use explicit jeq + jmp to avoid assembler issues with jne to far labels
        [(asm/jmp-imm :jeq :r0 net/IPPROTO-TCP :ipv6_is_tcp)]
        [(asm/jmp :pass)]
        [(asm/label :ipv6_is_tcp)]

        ;; Build conntrack key: src_ip (16 bytes)
        (common/build-load-ipv6-address :r9 common/IPV6-OFF-SRC -40)

        ;; dst_ip (16 bytes)
        (common/build-load-ipv6-address :r9 common/IPV6-OFF-DST -24)

        ;; Store L4 offset
        [(dsl/mov :r0 (+ net/ETH-HLEN common/IPV6-HLEN))
         (dsl/stx :w :r10 :r0 -48)]

        ;; Load and store IPv6 payload length
        [(dsl/ldx :h :r0 :r9 4)             ; Payload length (big-endian)
         (dsl/stx :h :r10 :r0 -60)]

        ;; Fall through to parse_tcp

        ;; =====================================================================
        ;; PHASE 2: Parse TCP Header
        ;; =====================================================================
        [(asm/label :parse_tcp)]

        ;; Get L4 offset
        [(dsl/ldx :w :r1 :r10 -48)]

        ;; Calculate TCP header pointer
        [(dsl/mov-reg :r0 :r7)
         (dsl/add-reg :r0 :r1)]

        ;; Check TCP header bounds (minimum 20 bytes)
        [(dsl/mov-reg :r1 :r0)
         (dsl/add :r1 20)
         (asm/jmp-reg :jgt :r1 :r8 :pass)]

        ;; Load TCP ports for conntrack key
        [(dsl/ldx :h :r1 :r0 0)             ; src_port
         (dsl/stx :h :r10 :r1 -8)           ; key.src_port at -40+32=-8
         (dsl/ldx :h :r1 :r0 2)             ; dst_port
         (dsl/stx :h :r10 :r1 -6)]          ; key.dst_port at -40+34=-6

        ;; Store protocol and padding in key
        [(dsl/ldx :b :r1 :r10 -51)
         (dsl/stx :b :r10 :r1 -4)           ; key.protocol
         (dsl/mov :r1 0)
         (dsl/stx :b :r10 :r1 -3)           ; padding
         (dsl/stx :h :r10 :r1 -2)]

        ;; Load TCP flags (at offset 13 in TCP header)
        [(dsl/ldx :b :r1 :r0 13)
         (dsl/stx :b :r10 :r1 -44)]         ; Store flags

        ;; Load data offset (upper 4 bits of byte 12) to get TCP header length
        [(dsl/ldx :b :r1 :r0 12)
         (dsl/rsh :r1 4)                    ; r1 = data offset in 32-bit words
         (dsl/lsh :r1 2)                    ; r1 = TCP header length in bytes
         (dsl/stx :b :r10 :r1 -43)]         ; Store TCP header length

        ;; Load sequence number
        [(dsl/ldx :w :r1 :r0 4)             ; seq at offset 4
         (dsl/stx :w :r10 :r1 -64)]

        ;; Calculate payload offset = L4_offset + tcp_hdr_len
        [(dsl/ldx :w :r2 :r10 -48)          ; L4 offset
         (dsl/ldx :b :r1 :r10 -43)          ; TCP header length
         (dsl/add-reg :r2 :r1)
         (dsl/stx :w :r10 :r2 -56)]         ; Store payload offset

        ;; =====================================================================
        ;; PHASE 3: Conntrack Lookup
        ;; =====================================================================

        (if conntrack-map-fd
          (concat
            [(dsl/ld-map-fd :r1 conntrack-map-fd)
             (dsl/mov-reg :r2 :r10)
             (dsl/add :r2 -40)              ; r2 = &key (40 bytes)
             (dsl/call BPF-FUNC-map-lookup-elem)]

            ;; If no conntrack entry, pass (this connection not tracked)
            [(asm/jmp-imm :jeq :r0 0 :pass)]

            ;; Save conntrack value pointer in r9
            [(dsl/mov-reg :r9 :r0)]

            ;; Check proxy_enabled flag (offset 97 in conntrack value)
            [(dsl/ldx :b :r0 :r9 CT-OFF-PROXY-FLAGS)
             (dsl/and :r0 PROXY-FLAG-ENABLED)
             (asm/jmp-imm :jeq :r0 0 :pass)] ; Not proxy-enabled, pass

            ;; Check if header already injected
            [(dsl/ldx :b :r0 :r9 CT-OFF-PROXY-FLAGS)
             (dsl/and :r0 PROXY-FLAG-HEADER-INJECTED)
             (asm/jmp-imm :jne :r0 0 :adjust_seq)] ; Already injected, adjust seq

            ;; Load current connection state
            [(dsl/ldx :b :r0 :r9 CT-OFF-CONN-STATE)
             (dsl/stx :b :r10 :r0 -68)]     ; Save state to stack

            [(asm/jmp :state_machine)])

          ;; No conntrack map - pass all
          [(asm/jmp :pass)])

        ;; =====================================================================
        ;; PHASE 4: TCP State Machine
        ;; =====================================================================
        [(asm/label :state_machine)]

        ;; Load saved state and flags
        [(dsl/ldx :b :r0 :r10 -68)          ; conn_state
         (dsl/ldx :b :r1 :r10 -44)]         ; tcp_flags

        ;; STATE: NEW (0)
        ;; If SYN flag set (no ACK), transition to SYN_SENT
        [(asm/jmp-imm :jne :r0 CONN-STATE-NEW :check_syn_sent)]
        [(dsl/mov-reg :r2 :r1)
         (dsl/and :r2 (bit-or TCP-FLAG-SYN TCP-FLAG-ACK))
         (asm/jmp-imm :jne :r2 TCP-FLAG-SYN :pass)] ; Must be SYN only
        [(dsl/mov :r0 CONN-STATE-SYN-SENT)
         (dsl/stx :b :r9 :r0 CT-OFF-CONN-STATE)]
        [(asm/jmp :update_conntrack)]

        ;; STATE: SYN_SENT (1) - waiting for SYN-ACK (but this is ingress, so we see SYN)
        ;; Actually for ingress (client->backend), we don't see SYN-ACK here
        ;; The SYN-ACK comes from backend on egress path
        ;; Skip to ESTABLISHED check for ingress
        [(asm/label :check_syn_sent)]
        [(asm/jmp-imm :jne :r0 CONN-STATE-SYN-SENT :check_syn_recv)]
        ;; In SYN_SENT, if we see another packet with ACK, it's likely retransmit or data
        ;; For now, pass through
        [(asm/jmp :pass)]

        ;; STATE: SYN_RECV (2) - waiting for final ACK
        ;; If ACK (no SYN), transition to ESTABLISHED
        [(asm/label :check_syn_recv)]
        [(asm/jmp-imm :jne :r0 CONN-STATE-SYN-RECV :check_established)]
        [(dsl/mov-reg :r2 :r1)
         (dsl/and :r2 (bit-or TCP-FLAG-SYN TCP-FLAG-ACK))
         (asm/jmp-imm :jne :r2 TCP-FLAG-ACK :pass)] ; Must be ACK only
        [(dsl/mov :r0 CONN-STATE-ESTABLISHED)
         (dsl/stx :b :r9 :r0 CT-OFF-CONN-STATE)]
        [(asm/jmp :update_conntrack)]

        ;; STATE: ESTABLISHED (3)
        ;; Check if this packet has payload (first data packet)
        [(asm/label :check_established)]
        [(asm/jmp-imm :jne :r0 CONN-STATE-ESTABLISHED :pass)]

        ;; Check if there's payload in this packet
        ;; Payload exists if: data_end > payload_offset
        ;; Reload data pointers (may have been invalidated)
        (tc-reload-data-ptrs)

        [(dsl/ldx :w :r1 :r10 -56)          ; payload_offset
         (dsl/mov-reg :r0 :r7)
         (dsl/add-reg :r0 :r1)              ; r0 = data + payload_offset
         (asm/jmp-reg :jge :r0 :r8 :pass)]  ; No payload, pass

        ;; This is the first data packet! Time to inject PROXY header
        [(asm/jmp :inject_proxy_header)]

        ;; =====================================================================
        ;; PHASE 5: Update Conntrack and Return
        ;; =====================================================================
        [(asm/label :update_conntrack)]

        ;; Update last_seen_ns timestamp (at offset 40 in unified format)
        [(dsl/call BPF-FUNC-ktime-get-ns)
         (dsl/stx :dw :r9 :r0 40)]

        ;; Map update not needed - we modified in place
        [(asm/jmp :pass)]

        ;; =====================================================================
        ;; PHASE 6: Sequence Number Adjustment (for packets after injection)
        ;; =====================================================================
        [(asm/label :adjust_seq)]

        ;; Load seq_offset from conntrack
        [(dsl/ldx :w :r1 :r9 CT-OFF-SEQ-OFFSET)
         (asm/jmp-imm :jeq :r1 0 :pass)]    ; No adjustment needed

        ;; Use bpf_skb_load_bytes/store_bytes to avoid direct packet access issues
        ;; r1 holds seq_offset from conntrack

        ;; Save seq_offset to stack (r1 will be clobbered by helper)
        [(dsl/stx :w :r10 :r1 -220)]        ; Save seq_offset

        ;; Calculate seq field offset in packet: L4_offset + 4
        [(dsl/ldx :w :r2 :r10 -48)          ; L4 offset
         (dsl/add :r2 4)]                   ; seq field at TCP header + 4

        ;; Load seq number using bpf_skb_load_bytes(skb, offset, to, len)
        [(dsl/mov-reg :r1 :r6)              ; r1 = skb
                                            ; r2 = offset (L4 + 4)
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 -228)                 ; r3 = &stack_buf for seq (4 bytes)
         (dsl/mov :r4 4)                    ; r4 = len
         (dsl/call BPF-FUNC-skb-load-bytes)]

        ;; Check if load succeeded
        [(asm/jmp-imm :jne :r0 0 :pass)]

        ;; Load old seq from stack, save for checksum
        [(dsl/ldx :w :r2 :r10 -228)         ; r2 = old seq (network order)
         (dsl/stx :w :r10 :r2 -232)]        ; Save old seq to stack for later checksum use

        ;; Add seq_offset: convert to host, add, convert back
        [(dsl/ldx :w :r1 :r10 -220)         ; r1 = seq_offset
         (dsl/end-to-be :r2 32)             ; Network to host
         (dsl/add-reg :r2 :r1)              ; r2 = old_seq + seq_offset
         (dsl/end-to-be :r2 32)]            ; Host to network

        ;; Store new seq to stack
        [(dsl/stx :w :r10 :r2 -228)]

        ;; Write new seq using bpf_skb_store_bytes
        [(dsl/ldx :w :r2 :r10 -48)          ; L4 offset
         (dsl/add :r2 4)                    ; seq field offset
         (dsl/mov-reg :r1 :r6)              ; r1 = skb
                                            ; r2 = offset
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 -228)                 ; r3 = &new_seq on stack
         (dsl/mov :r4 4)                    ; r4 = len
         (dsl/mov :r5 0)                    ; flags = 0
         (dsl/call BPF-FUNC-skb-store-bytes)]

        ;; Update TCP checksum using l4_csum_replace
        ;; bpf_l4_csum_replace(skb, csum_offset, old, new, flags)
        [(dsl/ldx :w :r2 :r10 -48)          ; L4 offset
         (dsl/add :r2 16)                   ; TCP checksum at offset 16
         (dsl/mov-reg :r1 :r6)              ; r1 = skb
                                            ; r2 = csum offset (already set)
         (dsl/ldx :w :r3 :r10 -232)         ; r3 = old seq (saved earlier)
         (dsl/ldx :w :r4 :r10 -228)         ; r4 = new seq from stack
         (dsl/mov :r5 4)                    ; sizeof(u32)
         (dsl/call BPF-FUNC-l4-csum-replace)]

        [(asm/jmp :pass)]

        ;; =====================================================================
        ;; PHASE 7: PROXY Protocol Header Injection
        ;; =====================================================================
        [(asm/label :inject_proxy_header)]

        ;; This is the complex part: inject PROXY v2 header into the packet
        ;; Steps:
        ;; 1. Determine header size based on address family
        ;; 2. Extend packet using bpf_skb_change_tail
        ;; 3. Move TCP payload down to make room
        ;; 4. Write PROXY v2 header at original payload position
        ;; 5. Update IP total length
        ;; 6. Update checksums
        ;; 7. Set header_injected flag and seq_offset

        ;; Load address family to determine header size
        [(dsl/ldx :b :r1 :r10 -52)]         ; af: 4 or 6
        [(asm/jmp-imm :jeq :r1 6 :ipv6_header_size)]

        ;; IPv4: header size = 28
        [(dsl/mov :r1 PROXY-V2-HEADER-SIZE-IPV4)
         (dsl/stx :w :r10 :r1 -72)]         ; Save header size
        [(asm/jmp :extend_packet)]

        [(asm/label :ipv6_header_size)]
        [(dsl/mov :r1 PROXY-V2-HEADER-SIZE-IPV6)
         (dsl/stx :w :r10 :r1 -72)]

        ;; Extend packet using bpf_skb_change_tail
        ;; int bpf_skb_change_tail(skb, new_len, flags)
        [(asm/label :extend_packet)]

        ;; Save current packet length BEFORE extending (for payload_len calculation)
        [(dsl/ldx :w :r2 :r6 common/SKB-OFF-LEN) ; Current length
         (dsl/stx :w :r10 :r2 -216)]        ; Save original_pkt_len

        ;; Calculate new length and call bpf_skb_change_tail
        [(dsl/ldx :w :r1 :r10 -72)          ; Header size to add
         (dsl/add-reg :r2 :r1)              ; New length = old + header_size
         (dsl/mov-reg :r1 :r6)              ; r1 = skb
                                            ; r2 = new_len (already set)
         (dsl/mov :r3 0)                    ; flags = 0
         (dsl/call BPF-FUNC-skb-change-tail)]

        ;; Check if extension succeeded
        [(asm/jmp-imm :jne :r0 0 :pass)]    ; Failed, pass without modification

        ;; Reload data pointers after skb_change_tail
        (tc-reload-data-ptrs)

        ;; =====================================================================
        ;; PHASE 7a: Shift TCP Payload Down to Make Room for PROXY Header
        ;; =====================================================================
        ;;
        ;; After bpf_skb_change_tail, the packet is extended at the END.
        ;; The existing TCP payload is still at its original position.
        ;; We need to move it down (to higher offsets) by header_size bytes.
        ;;
        ;; Algorithm:
        ;; 1. Calculate original payload length
        ;; 2. Copy chunks from END to START (backwards) to avoid overwriting
        ;; 3. Use bounded iterations for BPF verifier
        ;;
        ;; payload_len = original_pkt_len - payload_offset
        ;; (We saved original_pkt_len at -216 before extending)

        ;; Calculate payload length using saved original packet length
        ;; This avoids doing arithmetic on pkt_end pointer which is prohibited
        [(dsl/ldx :w :r2 :r10 -216)         ; r2 = original_pkt_len (saved before extend)
         (dsl/ldx :w :r3 :r10 -56)          ; r3 = payload_offset
         (dsl/sub-reg :r2 :r3)              ; r2 = payload_len = original_len - payload_offset
         (dsl/stx :w :r10 :r2 -76)]         ; Save payload_len

        ;; If payload is zero or negative, skip shifting
        [(asm/jmp-imm :jle :r2 0 :build_proxy_header)]

        ;; Initialize chunk counter - we iterate from last chunk backwards
        ;; num_chunks = (payload_len + CHUNK_SIZE - 1) / CHUNK_SIZE
        ;; Start from chunk (num_chunks - 1) and go down to 0
        [(dsl/mov-reg :r0 :r2)              ; r0 = payload_len
         (dsl/add :r0 (dec SHIFT-CHUNK-SIZE)) ; r0 = payload_len + 63
         (dsl/rsh :r0 6)                    ; r0 = num_chunks (divide by 64)
         (dsl/sub :r0 1)]                   ; r0 = last chunk index

        ;; Clamp the initial chunk index to ensure verifier knows the bound
        ;; If r0 >= SHIFT_MAX_CHUNKS, skip shifting (payload too large)
        [(asm/jmp-imm :jslt :r0 0 :build_proxy_header)]  ; Skip if negative
        [(asm/jmp-imm :jge :r0 SHIFT-MAX-CHUNKS :build_proxy_header)]  ; Skip if too many chunks

        ;; Now r0 is bounded [0, SHIFT_MAX_CHUNKS-1]
        [(dsl/stx :w :r10 :r0 -80)]         ; Save current_chunk

        ;; Bounded loop for shifting - unroll for BPF verifier
        ;; Each iteration: copy one 64-byte chunk from (payload_offset + chunk*64)
        ;; to (payload_offset + header_size + chunk*64)
        ;;
        ;; The verifier knows current_chunk is in [0, SHIFT_MAX_CHUNKS-1] at entry

        [(asm/jmp :shift_loop_body)]

        [(asm/label :shift_chunk)]
        ;; r1 = current_chunk (already loaded and bounds-checked in shift_loop_body)
        ;; r1 is guaranteed to be in [0, SHIFT_MAX_CHUNKS-1]

        ;; Calculate source offset: payload_offset + (chunk_index * 64)
        [(dsl/ldx :w :r2 :r10 -56)          ; payload_offset
         (dsl/mov-reg :r3 :r1)
         (dsl/lsh :r3 6)                    ; chunk_index * 64
         (dsl/add-reg :r2 :r3)]             ; r2 = src_offset

        ;; Calculate bytes to copy for this chunk
        ;; For last chunk (highest offset), may be partial
        ;; bytes_to_copy = min(64, payload_len - chunk_index * 64)
        [(dsl/ldx :w :r4 :r10 -76)          ; payload_len
         (dsl/sub-reg :r4 :r3)              ; r4 = payload_len - (chunk_index * 64)
         (asm/jmp-imm :jge :r4 SHIFT-CHUNK-SIZE :full_chunk)]
        ;; Partial chunk - use r4 as length
        [(asm/jmp :do_shift)]

        [(asm/label :full_chunk)]
        [(dsl/mov :r4 SHIFT-CHUNK-SIZE)]

        [(asm/label :do_shift)]
        ;; r2 = src_offset, r4 = len
        ;; Skip if length <= 0
        [(asm/jmp-imm :jle :r4 0 :shift_next)]

        ;; Bounds check length (max 64)
        [(asm/jmp-imm :jgt :r4 SHIFT-CHUNK-SIZE :shift_next)]

        ;; Load bytes from source using bpf_skb_load_bytes
        ;; int bpf_skb_load_bytes(skb, offset, to, len)
        [(dsl/mov-reg :r1 :r6)              ; r1 = skb
                                             ; r2 = offset (already set)
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 -208)                 ; r3 = &chunk_buffer
         (dsl/stx :w :r10 :r4 -212)]        ; Save len to temp location
        ;; r4 is already len
        [(dsl/call BPF-FUNC-skb-load-bytes)]

        ;; Check if load succeeded
        [(asm/jmp-imm :jne :r0 0 :shift_next)]

        ;; Calculate destination offset: src_offset + header_size
        [(dsl/ldx :w :r1 :r10 -80)          ; current_chunk
         (dsl/ldx :w :r2 :r10 -56)          ; payload_offset
         (dsl/mov-reg :r3 :r1)
         (dsl/lsh :r3 6)                    ; chunk_index * 64
         (dsl/add-reg :r2 :r3)              ; r2 = src_offset
         (dsl/ldx :w :r3 :r10 -72)          ; header_size
         (dsl/add-reg :r2 :r3)]             ; r2 = dst_offset = src_offset + header_size

        ;; Store bytes to destination using bpf_skb_store_bytes
        ;; int bpf_skb_store_bytes(skb, offset, from, len, flags)
        ;; Reload len from stack and re-check bounds (verifier loses track after helper)
        [(dsl/ldx :w :r4 :r10 -212)         ; r4 = len (saved earlier)
         (asm/jmp-imm :jle :r4 0 :shift_next) ; Skip if len <= 0
         (asm/jmp-imm :jgt :r4 SHIFT-CHUNK-SIZE :shift_next)] ; Skip if len > 64

        [(dsl/mov-reg :r1 :r6)              ; r1 = skb
                                             ; r2 = dst_offset (already set)
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 -208)                 ; r3 = &chunk_buffer
                                             ; r4 = len (already loaded and checked)
         (dsl/mov :r5 0)                    ; flags = 0 (no recompute csum for data)
         (dsl/call BPF-FUNC-skb-store-bytes)]

        [(asm/label :shift_next)]
        ;; Decrement chunk counter in-place and check before storing
        [(dsl/ldx :w :r0 :r10 -80)          ; Load current_chunk
         (dsl/sub :r0 1)]                   ; Decrement
        ;; If r0 < 0 (signed), we're done
        [(asm/jmp-imm :jslt :r0 0 :build_proxy_header)]
        ;; Store and continue
        [(dsl/stx :w :r10 :r0 -80)]
        ;; Fall through to shift_loop_body

        [(asm/label :shift_loop_body)]
        ;; Re-validate bounds after loading from stack (verifier requirement)
        [(dsl/ldx :w :r1 :r10 -80)          ; Load current_chunk into r1
         (asm/jmp-imm :jslt :r1 0 :build_proxy_header)          ; Exit if < 0
         (asm/jmp-imm :jge :r1 SHIFT-MAX-CHUNKS :build_proxy_header)]  ; Exit if >= MAX
        ;; r1 is now bounded [0, SHIFT_MAX_CHUNKS-1], continue to shift_chunk
        [(asm/jmp :shift_chunk)]

        ;; =====================================================================
        ;; PHASE 7b: Build PROXY v2 Header on Stack
        ;; =====================================================================
        [(asm/label :build_proxy_header)]

        ;; Reload data pointers (may have been invalidated by helper calls)
        (tc-reload-data-ptrs)

        ;; Build PROXY v2 header on stack and write it
        ;; Write signature (12 bytes) + version/cmd (1) + family (1) + len (2) + addresses
        ;;
        ;; PROXY header buffer layout on stack (starting at -144, going up):
        ;; -144: signature word 0 (4 bytes)
        ;; -140: signature word 1 (4 bytes)
        ;; -136: signature word 2 (4 bytes)
        ;; -132: version/cmd (1) + family (1) = 2 bytes as halfword
        ;; -130: address length (2 bytes, big-endian)
        ;; -128: addresses start
        ;;   IPv4: src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) = 12 bytes
        ;;   IPv6: src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2) = 36 bytes

        ;; First, build the header on stack starting at -144
        ;; Signature word 0 (big-endian)
        [(dsl/mov :r0 PROXY-V2-SIG-WORD0)
         (dsl/end-to-be :r0 32)
         (dsl/stx :w :r10 :r0 -144)]
        ;; Signature word 1
        [(dsl/mov :r0 PROXY-V2-SIG-WORD1)
         (dsl/end-to-be :r0 32)
         (dsl/stx :w :r10 :r0 -140)]
        ;; Signature word 2
        [(dsl/mov :r0 PROXY-V2-SIG-WORD2)
         (dsl/end-to-be :r0 32)
         (dsl/stx :w :r10 :r0 -136)]

        ;; Version/Command (1 byte) + Family (1 byte)
        [(dsl/ldx :b :r0 :r10 -52)          ; Load af
         (asm/jmp-imm :jeq :r0 6 :ipv6_family)]
        ;; IPv4
        [(dsl/mov :r0 (bit-or (bit-shift-left PROXY-V2-VERSION-CMD 8)
                              PROXY-V2-FAMILY-TCP-IPV4))
         (dsl/stx :h :r10 :r0 -132)]
        ;; Address length (big-endian)
        [(dsl/mov :r0 PROXY-V2-ADDR-LEN-IPV4)
         (dsl/end-to-be :r0 16)
         (dsl/stx :h :r10 :r0 -130)]
        [(asm/jmp :write_addresses)]

        [(asm/label :ipv6_family)]
        [(dsl/mov :r0 (bit-or (bit-shift-left PROXY-V2-VERSION-CMD 8)
                              PROXY-V2-FAMILY-TCP-IPV6))
         (dsl/stx :h :r10 :r0 -132)]
        [(dsl/mov :r0 PROXY-V2-ADDR-LEN-IPV6)
         (dsl/end-to-be :r0 16)
         (dsl/stx :h :r10 :r0 -130)]

        ;; Write addresses from conntrack orig_client_ip/port
        [(asm/label :write_addresses)]

        ;; Load original client IP from conntrack (at offset 104, 16 bytes)
        ;; For IPv4, only last 4 bytes are used
        [(dsl/ldx :b :r0 :r10 -52)          ; af
         (asm/jmp-imm :jeq :r0 6 :write_ipv6_addr)]

        ;; IPv4: write 4-byte src IP, 4-byte dst IP, 2-byte src port, 2-byte dst port
        ;; Addresses start at -128
        ;; src IP = orig_client_ip (last 4 bytes of 16-byte field)
        [(dsl/ldx :w :r0 :r9 (+ CT-OFF-ORIG-CLIENT-IP 12))
         (dsl/stx :w :r10 :r0 -128)]
        ;; dst IP = PROXY/VIP address = orig_dst in conntrack (last 4 bytes)
        [(dsl/ldx :w :r0 :r9 12)            ; orig_dst_ip bytes 12-15
         (dsl/stx :w :r10 :r0 -124)]
        ;; src port = orig_client_port
        [(dsl/ldx :h :r0 :r9 CT-OFF-ORIG-CLIENT-PORT)
         (dsl/stx :h :r10 :r0 -120)]
        ;; dst port = orig_dst_port (at offset 16)
        [(dsl/ldx :h :r0 :r9 16)
         (dsl/stx :h :r10 :r0 -118)]

        [(asm/jmp :store_proxy_header)]

        ;; IPv6: write 16-byte addresses
        ;; Addresses start at -128
        [(asm/label :write_ipv6_addr)]
        ;; src IP (16 bytes)
        [(dsl/ldx :w :r0 :r9 (+ CT-OFF-ORIG-CLIENT-IP 0))
         (dsl/stx :w :r10 :r0 -128)
         (dsl/ldx :w :r0 :r9 (+ CT-OFF-ORIG-CLIENT-IP 4))
         (dsl/stx :w :r10 :r0 -124)
         (dsl/ldx :w :r0 :r9 (+ CT-OFF-ORIG-CLIENT-IP 8))
         (dsl/stx :w :r10 :r0 -120)
         (dsl/ldx :w :r0 :r9 (+ CT-OFF-ORIG-CLIENT-IP 12))
         (dsl/stx :w :r10 :r0 -116)]
        ;; dst IP (16 bytes from conntrack offset 0)
        [(dsl/ldx :w :r0 :r9 0)
         (dsl/stx :w :r10 :r0 -112)
         (dsl/ldx :w :r0 :r9 4)
         (dsl/stx :w :r10 :r0 -108)
         (dsl/ldx :w :r0 :r9 8)
         (dsl/stx :w :r10 :r0 -104)
         (dsl/ldx :w :r0 :r9 12)
         (dsl/stx :w :r10 :r0 -100)]
        ;; src port
        [(dsl/ldx :h :r0 :r9 CT-OFF-ORIG-CLIENT-PORT)
         (dsl/stx :h :r10 :r0 -96)]
        ;; dst port
        [(dsl/ldx :h :r0 :r9 16)
         (dsl/stx :h :r10 :r0 -94)]

        ;; Store PROXY header into packet using bpf_skb_store_bytes
        [(asm/label :store_proxy_header)]

        ;; bpf_skb_store_bytes(skb, offset, from, len, flags)
        ;; r1 = skb, r2 = offset (payload_offset), r3 = from (&header), r4 = len, r5 = flags
        [(dsl/mov-reg :r1 :r6)              ; r1 = skb
         (dsl/ldx :w :r2 :r10 -56)          ; r2 = payload_offset
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 -144)                 ; r3 = &header on stack (start at -144)
         (dsl/ldx :w :r4 :r10 -72)          ; r4 = header_size (len)
         (dsl/mov :r5 BPF-F-RECOMPUTE-CSUM) ; r5 = flags
         (dsl/call BPF-FUNC-skb-store-bytes)]

        ;; Update seq_offset in conntrack
        [(dsl/ldx :w :r0 :r10 -72)          ; header_size
         (dsl/stx :w :r9 :r0 CT-OFF-SEQ-OFFSET)]

        ;; Set header_injected flag
        ;; We know from earlier check that header_injected is NOT set (0),
        ;; so we can safely add the flag (equivalent to OR when bit is 0)
        [(dsl/ldx :b :r0 :r9 CT-OFF-PROXY-FLAGS)
         (dsl/add :r0 PROXY-FLAG-HEADER-INJECTED)
         (dsl/stx :b :r9 :r0 CT-OFF-PROXY-FLAGS)]

        ;; Update IP total length
        ;; For IPv4: need to update header checksum too
        [(dsl/ldx :b :r0 :r10 -52)          ; af
         (asm/jmp-imm :jeq :r0 6 :update_ipv6_len)]

        ;; IPv4: Update total length and header checksum
        (tc-reload-data-ptrs)
        [(dsl/mov-reg :r0 :r7)
         (dsl/add :r0 (+ net/ETH-HLEN 4))   ; Check access to IP total_length
         (asm/jmp-reg :jgt :r0 :r8 :pass)]

        [(dsl/mov-reg :r0 :r7)
         (dsl/add :r0 net/ETH-HLEN)         ; IP header
         (dsl/ldx :h :r1 :r0 2)             ; Old total length
         (dsl/ldx :w :r2 :r10 -72)          ; Header size added
         ;; Convert to host order, add, convert back
         (dsl/end-to-be :r1 16)
         (dsl/add-reg :r1 :r2)
         (dsl/end-to-be :r1 16)
         (dsl/stx :h :r0 :r1 2)]            ; Store new total length

        ;; Update IP checksum using l3_csum_replace
        [(dsl/mov-reg :r1 :r6)              ; skb
         (dsl/mov :r2 (+ net/ETH-HLEN 10))  ; IP checksum offset
         (dsl/ldx :h :r3 :r10 -60)          ; Old total length (saved earlier)
         (dsl/mov-reg :r4 :r0)              ; Actually need to recalc
         (dsl/ldx :h :r4 :r0 2)             ; New total length from packet
         (dsl/mov :r5 2)                    ; sizeof(u16)
         (dsl/call BPF-FUNC-l3-csum-replace)]

        [(asm/jmp :pass)]

        ;; IPv6: Update payload length (no header checksum)
        [(asm/label :update_ipv6_len)]
        (tc-reload-data-ptrs)
        [(dsl/mov-reg :r0 :r7)
         (dsl/add :r0 (+ net/ETH-HLEN 6))
         (asm/jmp-reg :jgt :r0 :r8 :pass)]

        [(dsl/mov-reg :r0 :r7)
         (dsl/add :r0 net/ETH-HLEN)
         (dsl/ldx :h :r1 :r0 4)             ; Old payload length
         (dsl/ldx :w :r2 :r10 -72)          ; Header size
         (dsl/end-to-be :r1 16)
         (dsl/add-reg :r1 :r2)
         (dsl/end-to-be :r1 16)
         (dsl/stx :h :r0 :r1 4)]

        ;; Fall through to pass

        ;; =====================================================================
        ;; Return TC_ACT_OK
        ;; =====================================================================
        [(asm/label :pass)]
        (net/return-action net/TC-ACT-OK)))))

;;; =============================================================================
;;; Program Loading and Attachment
;;; =============================================================================

(defn load-program
  "Load TC ingress program into kernel.
   Returns a BpfProgram record or throws on error."
  [maps]
  (log/info "Loading TC ingress PROXY protocol program")
  (let [bytecode (build-tc-ingress-proxy-program maps)]
    (require '[clj-ebpf.programs :as programs])
    ((resolve 'clj-ebpf.programs/load-program)
      {:insns bytecode
       :prog-type :sched-cls
       :prog-name "tc_ingress_proxy"
       :license "GPL"
       :log-level 1})))

(defn attach-to-interface
  "Attach TC program to interface ingress.
   Returns true on success."
  [prog iface & {:keys [priority] :or {priority 1}}]
  (log/info "Attaching TC ingress program to" iface "with priority" priority)
  (try
    (let [prog-fd (if (number? prog) prog (:fd prog))]
      (bpf/attach-tc-filter iface prog-fd :ingress
                            :priority priority
                            :prog-name "tc_ingress_proxy"))
    (catch Exception e
      (log/error e "Failed to attach TC ingress to" iface)
      (throw e))))

(defn attach-to-interfaces
  "Attach TC ingress program to multiple interfaces."
  [prog interfaces & opts]
  (doseq [iface interfaces]
    (apply attach-to-interface prog iface opts)))

(defn detach-from-interface
  "Detach TC ingress program from interface."
  [iface & {:keys [priority] :or {priority 1}}]
  (log/info "Detaching TC ingress program from" iface)
  (try
    (bpf/detach-tc-filter iface :ingress priority)
    (catch Exception e
      (log/warn "Failed to detach TC from" iface ":" (.getMessage e)))))

(defn detach-from-interfaces
  "Detach TC ingress program from multiple interfaces."
  [interfaces & opts]
  (doseq [iface interfaces]
    (apply detach-from-interface iface opts)))
