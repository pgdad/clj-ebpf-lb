(ns lb.programs.common
  "Common eBPF program fragments and DSL utilities shared between XDP and TC programs."
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.dsl :as dsl]
            [clj-ebpf.dsl.xdp :as dsl-xdp]
            [clj-ebpf.dsl.tc :as dsl-tc]
            [clj-ebpf.maps.helpers :as mh]
            [clj-ebpf.memory :as mem]
            [clj-ebpf.net :as net]
            [clj-ebpf.net.bounds :as bounds]
            [clj-ebpf.net.checksum :as csum]
            [clj-ebpf.net.ethernet :as eth]
            [clj-ebpf.net.ipv4 :as ipv4]
            [clj-ebpf.net.ipv6 :as ipv6]
            [clj-ebpf.net.tcp :as tcp]
            [clj-ebpf.net.udp :as udp]
            [clj-ebpf.rate-limit :as rl]
            [clj-ebpf.ringbuf :as rb]
            [clj-ebpf.time :as time]))

;;; =============================================================================
;;; BPF Constants (using clj-ebpf 0.7.8 DSL modules)
;;; =============================================================================

;; XDP return codes (from clj-ebpf.dsl.xdp)
(def XDP-ABORTED (dsl-xdp/xdp-action :aborted))
(def XDP-DROP (dsl-xdp/xdp-action :drop))
(def XDP-PASS (dsl-xdp/xdp-action :pass))
(def XDP-TX (dsl-xdp/xdp-action :tx))
(def XDP-REDIRECT (dsl-xdp/xdp-action :redirect))

;; TC return codes (from clj-ebpf.dsl.tc)
(def TC-ACT-OK (dsl-tc/tc-action :ok))
(def TC-ACT-SHOT (dsl-tc/tc-action :shot))
(def TC-ACT-REDIRECT (dsl-tc/tc-action :redirect))

;; Ethernet constants (from clj-ebpf.dsl.xdp)
(def ETH-P-IP (:ipv4 dsl-xdp/ethertypes))
(def ETH-P-IPV6 (:ipv6 dsl-xdp/ethertypes))
(def ETH-P-IP-BE 0x0008)            ; IPv4 in big-endian (network byte order)
(def ETH-P-IPV6-BE 0xDD86)          ; IPv6 in big-endian (network byte order)
(def ETH-HLEN dsl-xdp/ethernet-header-size)

;; IP protocol numbers
(def IPPROTO-ICMP 1)
(def IPPROTO-TCP 6)
(def IPPROTO-UDP 17)
(def IPPROTO-ICMPV6 58)             ; ICMPv6 protocol number

;; Header sizes - IPv4 (from clj-ebpf.dsl.xdp)
(def IP-HLEN-MIN dsl-xdp/ipv4-header-min-size)
(def TCP-HLEN-MIN dsl-xdp/tcp-header-min-size)
(def UDP-HLEN dsl-xdp/udp-header-size)

;; Header sizes - IPv6 (from clj-ebpf.dsl.xdp and clj-ebpf.net.ipv6)
(def IPV6-HLEN dsl-xdp/ipv6-header-size)  ; Fixed IPv6 header size (no options in base header)

;; IPv6 header field offsets (from clj-ebpf.net.ipv6)
(def IPV6-OFF-NEXT-HEADER ipv6/IPV6-OFF-NEXT-HEADER) ; Next Header (protocol) at offset 6
(def IPV6-OFF-HOP-LIMIT ipv6/IPV6-OFF-HOP-LIMIT)     ; Hop Limit at offset 7
(def IPV6-OFF-SRC ipv6/IPV6-OFF-SRC)                 ; Source address at offset 8 (16 bytes)
(def IPV6-OFF-DST ipv6/IPV6-OFF-DST)                 ; Destination address at offset 24 (16 bytes)

;; TLS constants for SNI parsing
(def TLS-CONTENT-TYPE-HANDSHAKE 0x16)
(def TLS-HANDSHAKE-CLIENT-HELLO 0x01)
(def TLS-EXT-SNI 0x0000)
(def TLS-SNI-NAME-TYPE-HOSTNAME 0x00)

;; TLS record header offsets
(def TLS-RECORD-CONTENT-TYPE-OFF 0)      ; 1 byte
(def TLS-RECORD-VERSION-OFF 1)            ; 2 bytes
(def TLS-RECORD-LENGTH-OFF 3)             ; 2 bytes
(def TLS-RECORD-HEADER-SIZE 5)

;; TLS handshake header offsets (from start of handshake)
(def TLS-HANDSHAKE-TYPE-OFF 0)            ; 1 byte
(def TLS-HANDSHAKE-LENGTH-OFF 1)          ; 3 bytes
(def TLS-HANDSHAKE-HEADER-SIZE 4)

;; SNI parsing limits
(def MAX-SNI-LENGTH 64)                   ; Max hostname length to hash
(def MAX-TLS-EXTENSIONS 32)               ; Bounded loop limit for extensions

;; HTTPS port (network byte order)
(def HTTPS-PORT-BE 0x01BB)                ; 443 in big-endian

;; FNV-1a 64-bit hash constants for SNI hashing
;; Must match lb.util/hostname->hash implementation
(def FNV1A-64-OFFSET-BASIS-LO 0x84222325) ; Lower 32 bits of 0xcbf29ce484222325
(def FNV1A-64-OFFSET-BASIS-HI 0xcbf29ce4) ; Upper 32 bits
(def FNV1A-64-PRIME-LO 0x000001B3)        ; Lower 32 bits of 0x00000100000001B3
(def FNV1A-64-PRIME-HI 0x00000100)        ; Upper 32 bits

;; SKB (sk_buff) structure offsets for TC programs (from clj-ebpf.dsl.tc)
(def SKB-OFF-LEN (dsl-tc/skb-offset :len))
(def SKB-OFF-DATA (dsl-tc/skb-offset :data))
(def SKB-OFF-DATA-END (dsl-tc/skb-offset :data-end))

;; BPF helper function IDs (map operations from clj-ebpf.maps.helpers)
(def BPF-FUNC-map-lookup-elem mh/BPF-FUNC-map-lookup-elem)
(def BPF-FUNC-map-update-elem mh/BPF-FUNC-map-update-elem)
(def BPF-FUNC-map-delete-elem mh/BPF-FUNC-map-delete-elem)

;; Time and random helper function IDs (from clj-ebpf.time)
(def BPF-FUNC-ktime-get-ns time/BPF-FUNC-ktime-get-ns)
(def BPF-FUNC-get-prandom-u32 time/BPF-FUNC-get-prandom-u32)  ;; For weighted load balancing
(def BPF-FUNC-redirect 23)
(def BPF-FUNC-csum-diff 28)
(def BPF-FUNC-l3-csum-replace 55)
(def BPF-FUNC-l4-csum-replace 56)
(def BPF-FUNC-redirect-map 51)
(def BPF-FUNC-xdp-adjust-head 44)
;; Ring buffer helper function IDs (from clj-ebpf.ringbuf)
(def BPF-FUNC-ringbuf-reserve rb/BPF-FUNC-ringbuf-reserve)
(def BPF-FUNC-ringbuf-submit rb/BPF-FUNC-ringbuf-submit)
(def BPF-FUNC-ringbuf-discard rb/BPF-FUNC-ringbuf-discard)

;; Map update flags (from clj-ebpf.maps.helpers)
(def BPF-ANY mh/BPF-ANY)
(def BPF-NOEXIST mh/BPF-NOEXIST)
(def BPF-EXIST mh/BPF-EXIST)

;; Rate limiting constants (from clj-ebpf.rate-limit)
(def TOKEN-SCALE rl/TOKEN-SCALE)     ; Token scaling factor
(def RATE-LIMIT-CONFIG-SRC 0)        ; Config map index for source rate limit
(def RATE-LIMIT-CONFIG-BACKEND 1)    ; Config map index for backend rate limit

;; BPF_F flags for checksum helpers (from clj-ebpf.net.checksum)
(def BPF-F-RECOMPUTE-CSUM csum/BPF-F-RECOMPUTE-CSUM)
(def BPF-F-PSEUDO-HDR csum/BPF-F-PSEUDO-HDR)

;;; =============================================================================
;;; Register Allocation Convention
;;; =============================================================================

;; r0  = return value / scratch
;; r1  = first arg / context pointer (preserved where needed)
;; r2  = second arg / scratch
;; r3  = third arg / scratch
;; r4  = fourth arg / scratch
;; r5  = fifth arg / scratch
;; r6  = packet data start (callee-saved)
;; r7  = packet data end (callee-saved)
;; r8  = scratch / current position (callee-saved)
;; r9  = scratch / saved value (callee-saved)
;; r10 = frame pointer (read-only)

;;; =============================================================================
;;; Instruction Building Helpers
;;; =============================================================================

(defn mov-imm
  "Move immediate value to register."
  [dst imm]
  (dsl/mov dst imm))

(defn mov-reg
  "Move register to register."
  [dst src]
  (dsl/mov-reg dst src))

(defn add-imm
  "Add immediate to register."
  [dst imm]
  (dsl/add dst imm))

(defn add-reg
  "Add register to register."
  [dst src]
  (dsl/add-reg dst src))

(defn sub-imm
  "Subtract immediate from register."
  [dst imm]
  (dsl/sub dst imm))

(defn sub-reg
  "Subtract register from register."
  [dst src]
  (dsl/sub-reg dst src))

(defn ldx-b
  "Load byte from memory."
  [dst src off]
  (dsl/ldx :b dst src off))

(defn ldx-h
  "Load half-word (2 bytes) from memory."
  [dst src off]
  (dsl/ldx :h dst src off))

(defn ldx-w
  "Load word (4 bytes) from memory."
  [dst src off]
  (dsl/ldx :w dst src off))

(defn ldx-dw
  "Load double-word (8 bytes) from memory."
  [dst src off]
  (dsl/ldx :dw dst src off))

(defn stx-b
  "Store byte to memory.
   Signature: *(dst + off) = src"
  [dst src off]
  (dsl/stx :b dst src off))

(defn stx-h
  "Store half-word to memory.
   Signature: *(dst + off) = src"
  [dst src off]
  (dsl/stx :h dst src off))

(defn stx-w
  "Store word to memory.
   Signature: *(dst + off) = src"
  [dst src off]
  (dsl/stx :w dst src off))

(defn stx-dw
  "Store double-word to memory.
   Signature: *(dst + off) = src"
  [dst src off]
  (dsl/stx :dw dst src off))

;;; =============================================================================
;;; Memory Operations (delegating to clj-ebpf.memory)
;;; =============================================================================

(def build-zero-bytes
  "Generate instructions to zero a contiguous range of bytes on the stack.
   Delegates to clj-ebpf.memory/build-zero-bytes."
  mem/build-zero-bytes)

;;; =============================================================================
;;; IPv6 Address Helpers (delegating to clj-ebpf.net.ipv6)
;;; =============================================================================

(def build-load-ipv6-address
  "Generate instructions to load a 16-byte IPv6 address from packet to stack.
   Delegates to clj-ebpf.net.ipv6/build-load-ipv6-address."
  ipv6/build-load-ipv6-address)

(def build-load-ipv4-unified
  "Generate instructions to load a 4-byte IPv4 address into unified 16-byte format.
   Delegates to clj-ebpf.net.ipv6/build-load-ipv4-unified."
  ipv6/build-load-ipv4-unified)

(def build-copy-ipv6-address
  "Generate instructions to copy a 16-byte IPv6 address from one stack location to another.
   Delegates to clj-ebpf.net.ipv6/build-copy-ipv6-address."
  ipv6/build-copy-ipv6-address)

(def build-load-ipv6-address-adjusted
  "Generate instructions to load a 16-byte IPv6 address with offset adjustment.
   Delegates to clj-ebpf.net.ipv6/build-load-ipv6-address-adjusted."
  ipv6/build-load-ipv6-address-adjusted)

(def build-load-ipv6-src
  "Generate instructions to load IPv6 source address from packet to stack.
   Delegates to clj-ebpf.net.ipv6/build-load-ipv6-src."
  ipv6/build-load-ipv6-src)

(def build-load-ipv6-dst
  "Generate instructions to load IPv6 destination address from packet to stack.
   Delegates to clj-ebpf.net.ipv6/build-load-ipv6-dst."
  ipv6/build-load-ipv6-dst)

(def build-store-ipv6-address
  "Generate instructions to store a 16-byte IPv6 address from stack to packet.
   Delegates to clj-ebpf.net.ipv6/build-store-ipv6-address."
  ipv6/build-store-ipv6-address)

;; IPv4 store helpers (new in 0.7.5)
(def ipv4-store-saddr
  "Store IPv4 source address from register to packet.
   Delegates to clj-ebpf.net.ipv4/store-saddr."
  ipv4/store-saddr)

(def ipv4-store-daddr
  "Store IPv4 destination address from register to packet.
   Delegates to clj-ebpf.net.ipv4/store-daddr."
  ipv4/store-daddr)

;; TCP store helpers (new in 0.7.5)
(def tcp-store-sport
  "Store TCP source port from register to packet (network byte order).
   Delegates to clj-ebpf.net.tcp/store-sport."
  tcp/store-sport)

(def tcp-store-dport
  "Store TCP destination port from register to packet (network byte order).
   Delegates to clj-ebpf.net.tcp/store-dport."
  tcp/store-dport)

;; UDP store helpers (new in 0.7.5)
(def udp-store-sport
  "Store UDP source port from register to packet (network byte order).
   Delegates to clj-ebpf.net.udp/store-sport."
  udp/store-sport)

(def udp-store-dport
  "Store UDP destination port from register to packet (network byte order).
   Delegates to clj-ebpf.net.udp/store-dport."
  udp/store-dport)

;;; =============================================================================
;;; Ethernet Helpers (new in 0.7.8, delegating to clj-ebpf.net.ethernet)
;;; =============================================================================

(def eth-is-ipv4
  "Check if packet is IPv4 and jump to label if true.
   Delegates to clj-ebpf.net.ethernet/is-ipv4."
  eth/is-ipv4)

(def eth-is-ipv6
  "Check if packet is IPv6 and jump to label if true.
   Delegates to clj-ebpf.net.ethernet/is-ipv6."
  eth/is-ipv6)

(def eth-is-not-ipv4
  "Check if packet is NOT IPv4 and jump to label if true.
   Delegates to clj-ebpf.net.ethernet/is-not-ipv4."
  eth/is-not-ipv4)

(def eth-load-ethertype
  "Load ethertype from Ethernet header (network byte order).
   Delegates to clj-ebpf.net.ethernet/load-ethertype."
  eth/load-ethertype)

(def eth-parse-ethernet
  "Parse Ethernet header with bounds check and load ethertype.
   Delegates to clj-ebpf.net.ethernet/parse-ethernet."
  eth/parse-ethernet)

(def eth-swap-macs
  "Swap source and destination MAC addresses.
   Delegates to clj-ebpf.net.ethernet/swap-macs."
  eth/swap-macs)


;;; =============================================================================
;;; Unified Stack Layout Constants
;;; =============================================================================
;;
;; These constants define a standard stack layout for packet parsing across
;; XDP and TC programs. Using consistent offsets simplifies code sharing.
;;
;; Standard layout (relative to frame pointer r10):
;;
;; Address parsing (unified IPv4/IPv6 format):
;;   -16 : src_ip (16 bytes, unified format)
;;   -32 : dst_ip (16 bytes, unified format)
;;   -48 : L4 header offset (4 bytes)
;;   -52 : protocol (1 byte stored as word)
;;   -53 : address family (1 byte: 4=IPv4, 6=IPv6)
;;
;; Port parsing:
;;   -56 : src_port (2 bytes, network order)
;;   -60 : dst_port (2 bytes, network order)
;;
;; Conntrack key (40 bytes for unified format):
;;   -64 to -103 : conntrack key

(def ^:const STACK-OFF-SRC-IP -16)
(def ^:const STACK-OFF-DST-IP -32)
(def ^:const STACK-OFF-L4-OFFSET -48)
(def ^:const STACK-OFF-PROTOCOL -52)
(def ^:const STACK-OFF-ADDR-FAMILY -53)
(def ^:const STACK-OFF-SRC-PORT -56)
(def ^:const STACK-OFF-DST-PORT -60)
(def ^:const STACK-OFF-CONNTRACK-KEY -64)

;; Address family constants
(def ^:const AF-INET 4)
(def ^:const AF-INET6 6)

;;; =============================================================================
;;; Packet Parsing Fragments
;;; =============================================================================

(defn build-bounds-check
  "Generate instructions to check if accessing [data + offset, data + offset + size)
   is within packet bounds. Jumps forward by fail-offset if out of bounds.

   Assumes: r6 = data start, r7 = data end
   Uses: r8 as scratch

   Delegates to clj-ebpf.net.bounds/build-bounds-check with r6/r7 convention."
  [offset size fail-offset]
  (bounds/build-bounds-check :r6 :r7 offset size fail-offset))

(defn build-parse-eth
  "Parse Ethernet header and check for IPv4.

   Assumes: r6 = data, r7 = data_end
   After: jumps forward by pass-offset if not IPv4
   Uses: r8 as scratch"
  [pass-offset]
  (concat
    ;; Bounds check for Ethernet header
    (build-bounds-check 0 ETH-HLEN pass-offset)
    ;; Load ethertype (offset 12 in eth header)
    [(ldx-h :r8 :r6 12)
     ;; Convert from network byte order (big-endian)
     (dsl/end-to-le :r8 16)
     ;; Check if IPv4 (0x0800)
     (dsl/jmp-imm :jne :r8 ETH-P-IP pass-offset)]))

(defn build-parse-ip
  "Parse IPv4 header, extract protocol and addresses.

   Assumes: r6 = data, r7 = data_end, Ethernet header already validated
   Stores on stack:
     stack[-4]  = protocol (1 byte as word)
     stack[-8]  = src IP
     stack[-12] = dst IP
     stack[-16] = IP header length (bytes)
   Uses: r8, r9 as scratch"
  [pass-offset]
  (let [ip-off ETH-HLEN]
    (concat
      ;; Bounds check for minimum IP header
      (build-bounds-check ip-off IP-HLEN-MIN pass-offset)
      ;; Load version/IHL byte to get header length
      [(ldx-b :r8 :r6 ip-off)
       ;; IHL is lower 4 bits, multiply by 4 for byte length
       (dsl/and :r8 0x0F)
       (dsl/lsh :r8 2)          ;; r8 = IP header length in bytes
       (stx-w :r10 :r8 -16)     ;; store IP header length

       ;; Verify IHL >= 20
       (dsl/jmp-imm :jlt :r8 IP-HLEN-MIN pass-offset)

       ;; Load protocol (offset 9 in IP header)
       (ldx-b :r8 :r6 (+ ip-off 9))
       (stx-w :r10 :r8 -4)

       ;; Load source IP (offset 12)
       (ldx-w :r8 :r6 (+ ip-off 12))
       (stx-w :r10 :r8 -8)

       ;; Load destination IP (offset 16)
       (ldx-w :r8 :r6 (+ ip-off 16))
       (stx-w :r10 :r8 -12)])))

(defn build-parse-l4
  "Parse TCP/UDP header to extract ports.

   Assumes: stack[-16] = IP header length, r6 = data, r7 = data_end
   Stores on stack:
     stack[-20] = src port
     stack[-24] = dst port
   Uses: r8, r9"
  [pass-offset]
  [(ldx-w :r8 :r10 -16)         ;; r8 = IP header length
   (add-imm :r8 ETH-HLEN)       ;; r8 = L4 offset
   (mov-reg :r9 :r8)            ;; save L4 offset in r9

   ;; Bounds check for L4 ports (need at least 4 bytes)
   (mov-reg :r8 :r6)
   (add-reg :r8 :r9)
   (add-imm :r8 4)
   (dsl/jmp-reg :jgt :r8 :r7 pass-offset)

   ;; Calculate L4 header address: data + L4_offset
   (mov-reg :r8 :r6)
   (add-reg :r8 :r9)

   ;; Load src port (offset 0) - network byte order
   (ldx-h :r9 :r8 0)
   (stx-h :r10 :r9 -20)

   ;; Load dst port (offset 2) - network byte order
   (ldx-h :r9 :r8 2)
   (stx-h :r10 :r9 -24)])

;;; =============================================================================
;;; IPv6 Packet Parsing Fragments
;;; =============================================================================

(defn build-parse-ipv6
  "Parse IPv6 header, extract next header (protocol) and addresses.

   IPv6 has a fixed 40-byte header (no options in base header).

   Assumes: r6 = data, r7 = data_end, Ethernet header already validated
   Stores on stack (unified format with 16-byte addresses):
     stack[-4]   = next header (protocol, 1 byte as word)
     stack[-20]  = src IP (16 bytes, at stack[-20..-5])
     stack[-36]  = dst IP (16 bytes, at stack[-36..-21])
     stack[-40]  = header length (always 40 for base IPv6)
   Uses: r8, r9 as scratch"
  [pass-offset]
  (let [ipv6-off ETH-HLEN]
    (concat
      ;; Bounds check for IPv6 header (fixed 40 bytes)
      (build-bounds-check ipv6-off IPV6-HLEN pass-offset)

      ;; Store IPv6 header length (always 40)
      [(mov-imm :r8 IPV6-HLEN)
       (stx-w :r10 :r8 -40)]

      ;; Load next header (protocol) at offset 6
      [(ldx-b :r8 :r6 (+ ipv6-off IPV6-OFF-NEXT-HEADER))
       (stx-w :r10 :r8 -4)]

      ;; Load source IP (16 bytes at offset 8)
      ;; We load 4 32-bit words
      [(ldx-w :r8 :r6 (+ ipv6-off IPV6-OFF-SRC))
       (stx-w :r10 :r8 -20)
       (ldx-w :r8 :r6 (+ ipv6-off IPV6-OFF-SRC 4))
       (stx-w :r10 :r8 -16)
       (ldx-w :r8 :r6 (+ ipv6-off IPV6-OFF-SRC 8))
       (stx-w :r10 :r8 -12)
       (ldx-w :r8 :r6 (+ ipv6-off IPV6-OFF-SRC 12))
       (stx-w :r10 :r8 -8)]

      ;; Load destination IP (16 bytes at offset 24)
      [(ldx-w :r8 :r6 (+ ipv6-off IPV6-OFF-DST))
       (stx-w :r10 :r8 -36)
       (ldx-w :r8 :r6 (+ ipv6-off IPV6-OFF-DST 4))
       (stx-w :r10 :r8 -32)
       (ldx-w :r8 :r6 (+ ipv6-off IPV6-OFF-DST 8))
       (stx-w :r10 :r8 -28)
       (ldx-w :r8 :r6 (+ ipv6-off IPV6-OFF-DST 12))
       (stx-w :r10 :r8 -24)])))

(defn build-parse-l4-ipv6
  "Parse TCP/UDP header to extract ports for IPv6.

   IPv6 has fixed 40-byte header, so L4 is always at ETH_HLEN + 40.

   Assumes: r6 = data, r7 = data_end, IPv6 header validated
   Stores on stack:
     stack[-44] = src port
     stack[-48] = dst port
   Uses: r8, r9"
  [pass-offset]
  (let [l4-off (+ ETH-HLEN IPV6-HLEN)]
    [(mov-imm :r8 l4-off)
     (mov-reg :r9 :r8)            ;; save L4 offset in r9

     ;; Bounds check for L4 ports (need at least 4 bytes)
     (mov-reg :r8 :r6)
     (add-imm :r8 (+ l4-off 4))
     (dsl/jmp-reg :jgt :r8 :r7 pass-offset)

     ;; Calculate L4 header address: data + L4_offset
     (mov-reg :r8 :r6)
     (add-reg :r8 :r9)

     ;; Load src port (offset 0) - network byte order
     (ldx-h :r9 :r8 0)
     (stx-h :r10 :r9 -44)

     ;; Load dst port (offset 2) - network byte order
     (ldx-h :r9 :r8 2)
     (stx-h :r10 :r9 -48)]))

;;; =============================================================================
;;; Map Lookup Helpers (delegating to clj-ebpf.maps.helpers)
;;; =============================================================================

(def build-map-lookup
  "Generate instructions for bpf_map_lookup_elem.
   Delegates to clj-ebpf.maps.helpers/build-map-lookup."
  mh/build-map-lookup)

(def build-map-update
  "Generate instructions for bpf_map_update_elem.
   Delegates to clj-ebpf.maps.helpers/build-map-update."
  mh/build-map-update)

(def build-map-delete
  "Generate instructions for bpf_map_delete_elem.
   Delegates to clj-ebpf.maps.helpers/build-map-delete."
  mh/build-map-delete)

(def build-map-lookup-or-init
  "Generate instructions for map lookup with initialization if not found.
   Delegates to clj-ebpf.maps.helpers/build-map-lookup-or-init."
  mh/build-map-lookup-or-init)

;;; =============================================================================
;;; Checksum Helpers (delegating to clj-ebpf.net.checksum)
;;; =============================================================================

(defn build-l3-csum-replace
  "Generate incremental IP checksum update.
   Delegates to clj-ebpf.net.checksum/l3-csum-replace-4.

   skb-reg: Register containing skb/xdp_md pointer
   csum-off: Offset of checksum field in packet
   old-reg: Old value (in register)
   new-reg: New value (in register)"
  [skb-reg csum-off old-reg new-reg]
  (csum/l3-csum-replace-4 skb-reg csum-off old-reg new-reg))

(defn build-l4-csum-replace
  "Generate incremental L4 (TCP/UDP) checksum update.
   Delegates to clj-ebpf.net.checksum/l4-csum-replace-4.

   skb-reg: Register containing skb/xdp_md pointer
   csum-off: Offset of checksum field in packet
   old-reg: Old value (in register)
   new-reg: New value (in register)
   flags: BPF_F flags (use BPF-F-PSEUDO-HDR for IP address changes)"
  [skb-reg csum-off old-reg new-reg flags]
  (csum/l4-csum-replace-4 skb-reg csum-off old-reg new-reg (not= 0 (bit-and flags BPF-F-PSEUDO-HDR))))

;;; =============================================================================
;;; Ring Buffer Helpers (delegating to clj-ebpf.ringbuf)
;;; =============================================================================

(def build-ringbuf-reserve
  "Reserve space in ring buffer.
   Delegates to clj-ebpf.ringbuf/build-ringbuf-reserve."
  rb/build-ringbuf-reserve)

(def build-ringbuf-submit
  "Submit ring buffer entry.
   Delegates to clj-ebpf.ringbuf/build-ringbuf-submit."
  rb/build-ringbuf-submit)

(def build-ringbuf-discard
  "Discard ring buffer reservation.
   Delegates to clj-ebpf.ringbuf/build-ringbuf-discard."
  rb/build-ringbuf-discard)

;;; =============================================================================
;;; Time Helpers (delegating to clj-ebpf.time)
;;; =============================================================================

(def build-ktime-get-ns
  "Get current time in nanoseconds.
   Delegates to clj-ebpf.time/build-ktime-get-ns."
  time/build-ktime-get-ns)

;;; =============================================================================
;;; Random Number Helpers (delegating to clj-ebpf.time)
;;; =============================================================================

(def build-get-prandom-u32
  "Get a pseudo-random 32-bit number.
   Delegates to clj-ebpf.time/build-get-prandom-u32."
  time/build-get-prandom-u32)

(defn build-random-mod-100
  "Generate random number in range [0, 99].
   Delegates to clj-ebpf.time/build-random-mod."
  []
  (time/build-random-mod 100))

;;; =============================================================================
;;; Map Utilities
;;; =============================================================================

(defn map-fd
  "Get the raw file descriptor for a map.
   This is needed when building eBPF programs that reference maps."
  [m]
  (cond
    ;; If it's a number, assume it's already an FD
    (number? m) m
    ;; If it's a map with an :fd key
    (and (map? m) (:fd m)) (:fd m)
    ;; If the map object has a method to get the fd
    (instance? clojure.lang.ILookup m) (or (:fd m) (:file-descriptor m) m)
    :else (throw (ex-info "Cannot get file descriptor from map" {:map m :type (type m)}))))

;;; =============================================================================
;;; Program Assembly
;;; =============================================================================

(defn flatten-instructions
  "Flatten nested instruction vectors.
   Returns a flat vector of instructions."
  [& instruction-groups]
  (vec (flatten (remove nil? instruction-groups))))

(defn assemble-program
  "Assemble a program from instruction fragments.
   Returns BPF bytecode ready for loading."
  [& fragments]
  (let [instructions (apply flatten-instructions fragments)]
    (bpf/assemble instructions)))

;;; =============================================================================
;;; Simple XDP Programs
;;; =============================================================================

(defn xdp-pass-all
  "Simple XDP program that passes all packets.
   Useful for testing XDP attachment."
  []
  (bpf/assemble
    [(dsl/mov :r0 XDP-PASS)
     (dsl/exit-insn)]))

(defn xdp-drop-all
  "Simple XDP program that drops all packets."
  []
  (bpf/assemble
    [(dsl/mov :r0 XDP-DROP)
     (dsl/exit-insn)]))

;;; =============================================================================
;;; Simple TC Programs
;;; =============================================================================

(defn tc-pass-all
  "Simple TC program that passes all packets."
  []
  (bpf/assemble
    [(dsl/mov :r0 TC-ACT-OK)
     (dsl/exit-insn)]))

(defn tc-drop-all
  "Simple TC program that drops all packets."
  []
  (bpf/assemble
    [(dsl/mov :r0 TC-ACT-SHOT)
     (dsl/exit-insn)]))

;;; =============================================================================
;;; Rate Limiting Helpers
;;; =============================================================================

;; Rate limit bucket structure (16 bytes):
;;   tokens (8 bytes) - current token count (scaled by 1000)
;;   last_update (8 bytes) - last update timestamp in nanoseconds

;; Rate limit config structure (16 bytes):
;;   rate (8 bytes) - tokens per second (scaled by 1000)
;;   burst (8 bytes) - max tokens (scaled by 1000)

(defn build-rate-limit-check
  "Generate BPF instructions for token bucket rate limit check.

   This implements a token bucket algorithm:
   1. Load config from config-map at config-index
   2. If rate == 0, skip (rate limiting disabled)
   3. Load/create bucket from bucket-map using key at key-stack-off
   4. Calculate elapsed time since last update
   5. Add tokens: new_tokens = old_tokens + elapsed_ns * rate / 1e9
   6. Cap at burst
   7. If tokens >= 1 (1000 scaled), consume and continue
   8. Else jump to drop-label

   Stack usage (relative to current-stack-off):
   offset 0-15: rate limit config (rate, burst)
   offset 16-31: bucket state (tokens, last_update)

   Parameters:
   config-map-fd: FD for rate_limit_config array map
   config-index: 0 for source, 1 for backend
   bucket-map-fd: FD for rate_limit_src or rate_limit_backend LRU map
   key-stack-off: Stack offset where lookup key is stored
   scratch-stack-off: Stack offset for scratch space (needs 32 bytes)
   skip-label: Label to jump to if rate limiting disabled/passed
   drop-label: Label to jump to if rate limited"
  [config-map-fd config-index bucket-map-fd key-stack-off scratch-stack-off skip-label drop-label]
  (when (and config-map-fd bucket-map-fd)
    (let [config-off scratch-stack-off        ; 16 bytes for config
          bucket-off (- scratch-stack-off 16) ; 16 bytes for bucket
          key-off (- scratch-stack-off 20)]   ; 4 bytes for config key
      (concat
        ;; Store config index as key
        [(dsl/mov :r0 config-index)
         (dsl/stx :w :r10 :r0 key-off)]

        ;; Look up rate limit config
        [(dsl/ld-map-fd :r1 config-map-fd)
         (dsl/mov-reg :r2 :r10)
         (dsl/add :r2 key-off)
         (dsl/call BPF-FUNC-map-lookup-elem)]

        ;; If no config, skip rate limiting
        [(clj-ebpf.asm/jmp-imm :jeq :r0 0 skip-label)]

        ;; Load rate (offset 0) - if 0, rate limiting disabled
        [(dsl/ldx :dw :r1 :r0 0)               ; r1 = rate (scaled)
         (clj-ebpf.asm/jmp-imm :jeq :r1 0 skip-label)]

        ;; Save config to stack
        [(dsl/ldx :dw :r2 :r0 8)               ; r2 = burst (scaled)
         (dsl/stx :dw :r10 :r1 config-off)     ; save rate
         (dsl/stx :dw :r10 :r2 (- config-off 8))] ; save burst

        ;; Look up bucket
        [(dsl/ld-map-fd :r1 bucket-map-fd)
         (dsl/mov-reg :r2 :r10)
         (dsl/add :r2 key-stack-off)
         (dsl/call BPF-FUNC-map-lookup-elem)]

        ;; Get current time
        [(dsl/call BPF-FUNC-ktime-get-ns)      ; r0 = now
         (dsl/stx :dw :r10 :r0 (- bucket-off 8))] ; save now as new last_update

        ;; Look up bucket again (r0 was clobbered by ktime)
        [(dsl/ld-map-fd :r1 bucket-map-fd)
         (dsl/mov-reg :r2 :r10)
         (dsl/add :r2 key-stack-off)
         (dsl/call BPF-FUNC-map-lookup-elem)]

        ;; If bucket doesn't exist, create new one with burst tokens
        [(clj-ebpf.asm/jmp-imm :jne :r0 0 :bucket_exists)]

        ;; New bucket: set tokens = burst, allow first packet
        [(dsl/ldx :dw :r1 :r10 (- config-off 8)) ; r1 = burst
         (dsl/sub :r1 TOKEN-SCALE)             ; consume 1 token for this packet
         (dsl/stx :dw :r10 :r1 bucket-off)     ; tokens
         (dsl/ldx :dw :r1 :r10 (- bucket-off 8)) ; r1 = now
         (dsl/stx :dw :r10 :r1 (- bucket-off 8))] ; last_update = now

        ;; Update bucket in map
        [(dsl/ld-map-fd :r1 bucket-map-fd)
         (dsl/mov-reg :r2 :r10)
         (dsl/add :r2 key-stack-off)
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 bucket-off)
         (dsl/mov :r4 0)                       ; BPF_ANY
         (dsl/call BPF-FUNC-map-update-elem)]

        ;; Skip to continue (new bucket, first packet allowed)
        [(clj-ebpf.asm/jmp skip-label)]

        ;; Existing bucket: check and update
        [(clj-ebpf.asm/label :bucket_exists)]

        ;; r0 = bucket pointer
        ;; Load current tokens and last_update
        [(dsl/ldx :dw :r1 :r0 0)               ; r1 = current tokens
         (dsl/ldx :dw :r2 :r0 8)               ; r2 = last_update
         (dsl/stx :dw :r10 :r1 bucket-off)     ; save tokens
         (dsl/ldx :dw :r3 :r10 (- bucket-off 8))] ; r3 = now

        ;; Calculate elapsed = now - last_update
        [(dsl/sub-reg :r3 :r2)                 ; r3 = elapsed_ns
         ;; Clamp elapsed to prevent overflow (max ~10 seconds worth)
         (dsl/mov :r4 10000000000)             ; 10 seconds in ns
         (clj-ebpf.asm/jmp-reg :jle :r3 :r4 :elapsed_ok)
         (dsl/mov-reg :r3 :r4)]                ; clamp to 10s

        [(clj-ebpf.asm/label :elapsed_ok)]

        ;; Calculate tokens to add: elapsed_ns * rate / 1e9
        ;; To avoid overflow, we do: (elapsed_ns / 1000) * rate / 1000000
        ;; This gives us tokens (still scaled by 1000)
        [(dsl/ldx :dw :r4 :r10 config-off)     ; r4 = rate (scaled)
         ;; elapsed_us = elapsed_ns / 1000
         (dsl/div :r3 1000)                    ; r3 = elapsed_us
         ;; tokens_to_add = elapsed_us * rate / 1000000
         (dsl/mul-reg :r3 :r4)                 ; r3 = elapsed_us * rate
         (dsl/div :r3 1000000)]                ; r3 = tokens to add (scaled)

        ;; Add tokens: new_tokens = old_tokens + tokens_to_add
        [(dsl/ldx :dw :r1 :r10 bucket-off)     ; r1 = old tokens
         (dsl/add-reg :r1 :r3)                 ; r1 = old + new tokens

         ;; Cap at burst
         (dsl/ldx :dw :r2 :r10 (- config-off 8)) ; r2 = burst
         (clj-ebpf.asm/jmp-reg :jle :r1 :r2 :tokens_capped)
         (dsl/mov-reg :r1 :r2)]                ; cap at burst

        [(clj-ebpf.asm/label :tokens_capped)]

        ;; Check if we have at least 1 token (1000 scaled)
        [(clj-ebpf.asm/jmp-imm :jlt :r1 TOKEN-SCALE drop-label)]

        ;; Consume 1 token
        [(dsl/sub :r1 TOKEN-SCALE)
         (dsl/stx :dw :r10 :r1 bucket-off)]    ; update tokens

        ;; Update last_update
        [(dsl/ldx :dw :r1 :r10 (- bucket-off 8))
         (dsl/stx :dw :r10 :r1 (- bucket-off 8))]

        ;; Write updated bucket to map
        [(dsl/ld-map-fd :r1 bucket-map-fd)
         (dsl/mov-reg :r2 :r10)
         (dsl/add :r2 key-stack-off)
         (dsl/mov-reg :r3 :r10)
         (dsl/add :r3 bucket-off)
         (dsl/mov :r4 0)                       ; BPF_ANY
         (dsl/call BPF-FUNC-map-update-elem)]

        ;; Rate limit check passed - continue
        ))))
