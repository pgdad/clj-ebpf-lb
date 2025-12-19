(ns reverse-proxy.programs.xdp-ingress
  "XDP ingress program for the reverse proxy.
   Handles incoming packets: parses headers, looks up routing, performs DNAT."
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.dsl :as dsl]
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
;; r1 = XDP context (preserved in r6 after save)
;; r6 = saved context / scratch
;; r7 = data pointer
;; r8 = data_end pointer
;; r9 = scratch / IP header pointer

;; Stack layout (negative offsets from r10):
;; -8   : Listen map key (8 bytes: ifindex + port + padding)
;; -16  : LPM key (8 bytes: prefix_len + ip)
;; -24  : Original dst IP (4 bytes) + Original dst port (4 bytes)
;; -32  : Conntrack key start (16 bytes)
;; -48  : Conntrack value (56 bytes)
;; -104 : Scratch space

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
  (bpf/assemble
    (concat
      ;; Save context and load data pointers
      [(dsl/mov-reg :r6 :r1)]
      (net/xdp-load-data-ptrs :r7 :r8 :r1)

      ;; Check Ethernet header bounds
      (net/check-bounds :r7 :r8 net/ETH-HLEN 5 :r9)

      ;; Load and check ethertype
      (eth/load-ethertype :r9 :r7)
      (eth/is-ipv4 :r9 1)

      ;; Not IPv4 - pass (let other protocols through)
      [(dsl/mov :r0 net/XDP-PASS)
       (dsl/exit-insn)]

      ;; IPv4 - pass
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
;;; Jump Offset Calculation Helpers
;;; =============================================================================

(defn count-instructions
  "Count the number of BPF instructions in a sequence.
   Each instruction is 8 bytes, but some helpers return vectors of instructions."
  [insn-seq]
  (if (sequential? insn-seq)
    (count insn-seq)
    1))

(defn calculate-jump-offset
  "Calculate BPF jump offset from source instruction to target instruction.
   BPF jump offsets are relative to the NEXT instruction after the jump.

   source-idx: Index of the jump instruction
   target-idx: Index of the target instruction

   Returns: Number of instructions to skip"
  [source-idx target-idx]
  (- target-idx source-idx 1))

;;; =============================================================================
;;; Full XDP Ingress Program with DNAT
;;; =============================================================================

(defn build-xdp-dnat-program
  "Build XDP ingress program that performs DNAT on incoming packets.

   This program:
   1. Parses IPv4/TCP or IPv4/UDP packets
   2. Validates packet structure
   3. Passes all valid packets (DNAT logic to be added)

   Register allocation:
   r6 = saved XDP context (callee-saved)
   r7 = data pointer (callee-saved)
   r8 = data_end pointer (callee-saved)
   r9 = IP header pointer / scratch (callee-saved)

   Jump offset calculation:
   We need to calculate the exact number of instructions between each
   conditional jump and the PASS label at the end."
  [_listen-map-fd _conntrack-map-fd]
  ;; Build instruction blocks and count them to calculate proper offsets
  ;;
  ;; Program structure:
  ;; Block 0: Save context (1 insn)
  ;; Block 1: Load data ptrs (2 insns)
  ;; Block 2: Check ETH bounds (3 insns, last is jump)
  ;; Block 3: Load ethertype (1 insn)
  ;; Block 4: Check IPv4 (1 insn, jump)
  ;; Block 5: Get IP header ptr (2 insns)
  ;; Block 6: Check IP bounds (3 insns, last is jump)
  ;; Block 7: PASS - return action (2 insns)

  (let [;; Count instructions in each block
        block-0-count 1   ; mov-reg :r6 :r1
        block-1-count 2   ; xdp-load-data-ptrs
        block-2-count 3   ; check-bounds (mov-reg, add, jmp-reg)
        block-3-count 1   ; load-ethertype
        block-4-count 1   ; is-not-ipv4 (jmp-imm)
        block-5-count 2   ; get-ip-header-ptr
        block-6-count 3   ; check-bounds (mov-reg, add, jmp-reg)
        block-7-count 2   ; return-action (mov, exit)

        ;; Calculate instruction indices (0-based)
        ;; Block 0 starts at index 0
        block-0-start 0
        block-1-start (+ block-0-start block-0-count)  ; 1
        block-2-start (+ block-1-start block-1-count)  ; 3
        block-3-start (+ block-2-start block-2-count)  ; 6
        block-4-start (+ block-3-start block-3-count)  ; 7
        block-5-start (+ block-4-start block-4-count)  ; 8
        block-6-start (+ block-5-start block-5-count)  ; 10
        block-7-start (+ block-6-start block-6-count)  ; 13 (PASS label)

        ;; Jump sources (index of the jump instruction)
        ;; Block 2 jump is at block-2-start + 2 = 5
        ;; Block 4 jump is at block-4-start = 7
        ;; Block 6 jump is at block-6-start + 2 = 12
        jump-2-idx (+ block-2-start 2)  ; 5
        jump-4-idx block-4-start        ; 7
        jump-6-idx (+ block-6-start 2)  ; 12

        ;; Calculate offsets to PASS label (block-7-start = 13)
        pass-label block-7-start
        offset-from-jump-2 (calculate-jump-offset jump-2-idx pass-label)  ; 13-5-1 = 7
        offset-from-jump-4 (calculate-jump-offset jump-4-idx pass-label)  ; 13-7-1 = 5
        offset-from-jump-6 (calculate-jump-offset jump-6-idx pass-label)] ; 13-12-1 = 0

    (bpf/assemble
      (concat
        ;; Block 0: Save XDP context to callee-saved register
        [(dsl/mov-reg :r6 :r1)]

        ;; Block 1: Load data and data_end pointers from XDP context
        ;; Using 32-bit loads as required by the kernel for xdp_md access
        (xdp-load-data-ptrs-32 :r7 :r8 :r1)

        ;; Block 2: Check Ethernet header bounds
        (net/check-bounds :r7 :r8 net/ETH-HLEN offset-from-jump-2 :r9)

        ;; Block 3: Load ethertype
        (eth/load-ethertype :r9 :r7)

        ;; Block 4: Check for IPv4
        (eth/is-not-ipv4 :r9 offset-from-jump-4)

        ;; Block 5: Calculate IP header pointer: data + ETH_HLEN
        (eth/get-ip-header-ptr :r9 :r7)

        ;; Block 6: Check IP header bounds
        (net/check-bounds :r9 :r8 net/IPV4-MIN-HLEN offset-from-jump-6 :r0)

        ;; Block 7: PASS - return XDP_PASS
        (net/return-action net/XDP-PASS)))))

(defn build-xdp-ingress-program
  "Build the XDP ingress program.

   Uses the DNAT program with proper jump offset calculation.
   The program parses Ethernet and IPv4 headers and validates bounds.

   Map FDs are accepted for future DNAT implementation but currently
   the program only does packet validation and passes all valid packets."
  [map-fds]
  (if (and (map? map-fds)
           (:listen-map map-fds)
           (:conntrack-map map-fds))
    (build-xdp-dnat-program
      (common/map-fd (:listen-map map-fds))
      (common/map-fd (:conntrack-map map-fds)))
    ;; Use DNAT program even without maps (it just passes packets)
    (build-xdp-dnat-program nil nil)))

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
