(ns reverse-proxy.programs.common
  "Common eBPF program fragments and DSL utilities shared between XDP and TC programs."
  (:require [clj-ebpf.core :as bpf]))

;;; =============================================================================
;;; BPF Constants
;;; =============================================================================

;; XDP return codes (from bpf/xdp-action)
(def XDP-ABORTED 0)
(def XDP-DROP 1)
(def XDP-PASS 2)
(def XDP-TX 3)
(def XDP-REDIRECT 4)

;; TC return codes
(def TC-ACT-OK 0)
(def TC-ACT-SHOT 2)
(def TC-ACT-REDIRECT 7)

;; Ethernet constants
(def ETH-P-IP 0x0800)
(def ETH-P-IPV6 0x86DD)
(def ETH-HLEN 14)

;; IP protocol numbers
(def IPPROTO-ICMP 1)
(def IPPROTO-TCP 6)
(def IPPROTO-UDP 17)

;; Header sizes
(def IP-HLEN-MIN 20)
(def TCP-HLEN-MIN 20)
(def UDP-HLEN 8)

;; BPF helper function IDs
(def BPF-FUNC-map-lookup-elem 1)
(def BPF-FUNC-map-update-elem 2)
(def BPF-FUNC-map-delete-elem 3)
(def BPF-FUNC-ktime-get-ns 5)
(def BPF-FUNC-redirect 23)
(def BPF-FUNC-csum-diff 28)
(def BPF-FUNC-l3-csum-replace 55)
(def BPF-FUNC-l4-csum-replace 56)
(def BPF-FUNC-redirect-map 51)
(def BPF-FUNC-xdp-adjust-head 44)
(def BPF-FUNC-ringbuf-reserve 131)
(def BPF-FUNC-ringbuf-submit 132)
(def BPF-FUNC-ringbuf-discard 133)

;; BPF_F flags for checksum helpers
(def BPF-F-RECOMPUTE-CSUM 0x01)
(def BPF-F-PSEUDO-HDR 0x10)

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
  (bpf/mov dst imm))

(defn mov-reg
  "Move register to register."
  [dst src]
  (bpf/mov-reg dst src))

(defn add-imm
  "Add immediate to register."
  [dst imm]
  (bpf/add dst imm))

(defn add-reg
  "Add register to register."
  [dst src]
  (bpf/add-reg dst src))

(defn sub-imm
  "Subtract immediate from register."
  [dst imm]
  (bpf/sub dst imm))

(defn sub-reg
  "Subtract register from register."
  [dst src]
  (bpf/sub-reg dst src))

(defn ldx-b
  "Load byte from memory."
  [dst src off]
  (bpf/ldx :b dst src off))

(defn ldx-h
  "Load half-word (2 bytes) from memory."
  [dst src off]
  (bpf/ldx :h dst src off))

(defn ldx-w
  "Load word (4 bytes) from memory."
  [dst src off]
  (bpf/ldx :w dst src off))

(defn ldx-dw
  "Load double-word (8 bytes) from memory."
  [dst src off]
  (bpf/ldx :dw dst src off))

(defn stx-b
  "Store byte to memory."
  [dst off src]
  (bpf/stx :b dst off src))

(defn stx-h
  "Store half-word to memory."
  [dst off src]
  (bpf/stx :h dst off src))

(defn stx-w
  "Store word to memory."
  [dst off src]
  (bpf/stx :w dst off src))

(defn stx-dw
  "Store double-word to memory."
  [dst off src]
  (bpf/stx :dw dst off src))

;;; =============================================================================
;;; Packet Parsing Fragments
;;; =============================================================================

(defn build-bounds-check
  "Generate instructions to check if accessing [data + offset, data + offset + size)
   is within packet bounds. Jumps forward by fail-offset if out of bounds.

   Assumes: r6 = data start, r7 = data end
   Uses: r8 as scratch"
  [offset size fail-offset]
  [(mov-reg :r8 :r6)                 ;; r8 = data start
   (add-imm :r8 (+ offset size))     ;; r8 = data + offset + size
   (bpf/jmp-reg :jgt :r8 :r7 fail-offset)]) ;; if r8 > data_end, jump forward

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
     (bpf/end-to-le :r8 16)
     ;; Check if IPv4 (0x0800)
     (bpf/jmp-imm :jne :r8 ETH-P-IP pass-offset)]))

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
       (bpf/and-op :r8 0x0F)
       (bpf/lsh :r8 2)          ;; r8 = IP header length in bytes
       (stx-w :r10 -16 :r8)     ;; store IP header length

       ;; Verify IHL >= 20
       (bpf/jmp-imm :jlt :r8 IP-HLEN-MIN pass-offset)

       ;; Load protocol (offset 9 in IP header)
       (ldx-b :r8 :r6 (+ ip-off 9))
       (stx-w :r10 -4 :r8)

       ;; Load source IP (offset 12)
       (ldx-w :r8 :r6 (+ ip-off 12))
       (stx-w :r10 -8 :r8)

       ;; Load destination IP (offset 16)
       (ldx-w :r8 :r6 (+ ip-off 16))
       (stx-w :r10 -12 :r8)])))

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
   (bpf/jmp-reg :jgt :r8 :r7 pass-offset)

   ;; Calculate L4 header address: data + L4_offset
   (mov-reg :r8 :r6)
   (add-reg :r8 :r9)

   ;; Load src port (offset 0) - network byte order
   (ldx-h :r9 :r8 0)
   (stx-h :r10 -20 :r9)

   ;; Load dst port (offset 2) - network byte order
   (ldx-h :r9 :r8 2)
   (stx-h :r10 -24 :r9)])

;;; =============================================================================
;;; Map Lookup Helpers
;;; =============================================================================

(defn build-map-lookup
  "Generate instructions for bpf_map_lookup_elem.

   Args:
     map-fd: The map file descriptor (will be loaded as 64-bit immediate)
     key-stack-off: Stack offset where key is stored (negative)

   Returns: instructions that leave result pointer in r0 (or NULL)"
  [map-fd key-stack-off]
  [(bpf/ld-map-fd :r1 map-fd)     ;; r1 = map fd
   (mov-reg :r2 :r10)             ;; r2 = frame pointer
   (add-imm :r2 key-stack-off)    ;; r2 = &key
   (bpf/call BPF-FUNC-map-lookup-elem)])

(defn build-map-update
  "Generate instructions for bpf_map_update_elem.

   Args:
     map-fd: The map file descriptor
     key-stack-off: Stack offset where key is stored
     value-stack-off: Stack offset where value is stored
     flags: Update flags (0 = any, 1 = noexist, 2 = exist)"
  [map-fd key-stack-off value-stack-off flags]
  [(bpf/ld-map-fd :r1 map-fd)
   (mov-reg :r2 :r10)
   (add-imm :r2 key-stack-off)
   (mov-reg :r3 :r10)
   (add-imm :r3 value-stack-off)
   (mov-imm :r4 flags)
   (bpf/call BPF-FUNC-map-update-elem)])

;;; =============================================================================
;;; Checksum Helpers
;;; =============================================================================

(defn build-l3-csum-replace
  "Generate incremental IP checksum update.

   skb-reg: Register containing skb/xdp_md pointer
   csum-off: Offset of checksum field in packet
   old-val: Old value (in register)
   new-val: New value (in register)"
  [skb-reg csum-off old-reg new-reg]
  ;; bpf_l3_csum_replace(skb, offset, from, to, flags)
  [(mov-reg :r1 skb-reg)
   (mov-imm :r2 csum-off)
   (mov-reg :r3 old-reg)
   (mov-reg :r4 new-reg)
   (mov-imm :r5 4)              ;; size = 4 bytes
   (bpf/call BPF-FUNC-l3-csum-replace)])

(defn build-l4-csum-replace
  "Generate incremental L4 (TCP/UDP) checksum update.

   skb-reg: Register containing skb/xdp_md pointer
   csum-off: Offset of checksum field in packet
   old-val: Old value (in register)
   new-val: New value (in register)
   flags: BPF_F flags (use BPF-F-PSEUDO-HDR for IP address changes)"
  [skb-reg csum-off old-reg new-reg flags]
  [(mov-reg :r1 skb-reg)
   (mov-imm :r2 csum-off)
   (mov-reg :r3 old-reg)
   (mov-reg :r4 new-reg)
   (mov-imm :r5 flags)
   (bpf/call BPF-FUNC-l4-csum-replace)])

;;; =============================================================================
;;; Ring Buffer Helpers
;;; =============================================================================

(defn build-ringbuf-reserve
  "Reserve space in ring buffer.

   ringbuf-fd: Ring buffer map FD
   size: Size to reserve

   Returns ptr in r0 (or NULL on failure)"
  [ringbuf-fd size]
  [(bpf/ld-map-fd :r1 ringbuf-fd)
   (mov-imm :r2 size)
   (mov-imm :r3 0)              ;; flags
   (bpf/call BPF-FUNC-ringbuf-reserve)])

(defn build-ringbuf-submit
  "Submit ring buffer entry.

   ptr-reg: Register containing pointer from reserve"
  [ptr-reg]
  [(mov-reg :r1 ptr-reg)
   (mov-imm :r2 0)              ;; flags
   (bpf/call BPF-FUNC-ringbuf-submit)])

(defn build-ringbuf-discard
  "Discard ring buffer reservation.

   ptr-reg: Register containing pointer from reserve"
  [ptr-reg]
  [(mov-reg :r1 ptr-reg)
   (mov-imm :r2 0)
   (bpf/call BPF-FUNC-ringbuf-discard)])

;;; =============================================================================
;;; Time Helper
;;; =============================================================================

(defn build-ktime-get-ns
  "Get current time in nanoseconds.
   Result in r0."
  []
  [(bpf/call BPF-FUNC-ktime-get-ns)])

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
    [(bpf/mov :r0 (:pass bpf/xdp-action))
     (bpf/exit-insn)]))

(defn xdp-drop-all
  "Simple XDP program that drops all packets."
  []
  (bpf/assemble
    [(bpf/mov :r0 (:drop bpf/xdp-action))
     (bpf/exit-insn)]))

;;; =============================================================================
;;; Simple TC Programs
;;; =============================================================================

(defn tc-pass-all
  "Simple TC program that passes all packets."
  []
  (bpf/assemble
    [(bpf/mov :r0 TC-ACT-OK)
     (bpf/exit-insn)]))

(defn tc-drop-all
  "Simple TC program that drops all packets."
  []
  (bpf/assemble
    [(bpf/mov :r0 TC-ACT-SHOT)
     (bpf/exit-insn)]))
