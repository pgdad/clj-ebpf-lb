(ns reverse-proxy.programs.tc-egress
  "TC egress program for the reverse proxy.
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
            [reverse-proxy.programs.common :as common]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; TC Program Structure
;;; =============================================================================

;; The TC egress program handles the reply path:
;; 1. Parse packet headers
;; 2. Look up reverse connection in conntrack map
;; 3. If found, rewrite source IP/port to original destination (SNAT)
;; 4. Update checksums using kernel helpers
;; 5. Return TC_ACT_OK to continue processing

;; Register allocation:
;; r1 = SKB context (preserved in r6 after save)
;; r6 = saved SKB context
;; r7 = data pointer
;; r8 = data_end pointer
;; r9 = scratch / IP header pointer

;; Stack layout for conntrack key (reverse 5-tuple):
;; -4   : protocol (4 bytes, padded)
;; -8   : src IP (from reply = dst of original)
;; -12  : dst IP (from reply = src of original)
;; -14  : src port (from reply)
;; -16  : dst port (from reply)
;; Total: 16 bytes aligned

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
;;; Full TC Egress Program with SNAT
;;; =============================================================================

(defn build-tc-snat-program
  "Build TC egress program that performs SNAT on reply packets.

   This program:
   1. Parses IPv4/TCP or IPv4/UDP packets
   2. Validates packet structure
   3. Passes all valid packets (SNAT logic to be added)

   Register allocation:
   r6 = saved SKB context (callee-saved)
   r7 = data pointer (callee-saved)
   r8 = data_end pointer (callee-saved)
   r9 = IP header pointer / scratch (callee-saved)

   Uses clj-ebpf.asm label-based assembly for automatic jump offset resolution."
  [_conntrack-map-fd]
  (asm/assemble-with-labels
    (concat
      ;; Save SKB context to callee-saved register
      [(dsl/mov-reg :r6 :r1)]

      ;; Load data and data_end pointers from SKB context
      ;; Using 32-bit loads as required by the kernel
      (tc-load-data-ptrs-32 :r7 :r8 :r1)

      ;; Check Ethernet header bounds - jump to :pass if out of bounds
      (asm/check-bounds :r7 :r8 net/ETH-HLEN :pass :r9)

      ;; Load ethertype
      (eth/load-ethertype :r9 :r7)

      ;; Check for IPv4 - jump to :pass if not IPv4
      [(asm/jmp-imm :jne :r9 eth/ETH-P-IP-BE :pass)]

      ;; Calculate IP header pointer: data + ETH_HLEN
      (eth/get-ip-header-ptr :r9 :r7)

      ;; Check IP header bounds - jump to :pass if out of bounds
      (asm/check-bounds :r9 :r8 net/IPV4-MIN-HLEN :pass :r0)

      ;; PASS label - return TC_ACT_OK
      [(asm/label :pass)]
      (net/return-action net/TC-ACT-OK))))

(defn build-tc-egress-program
  "Build the TC egress program.

   Uses the SNAT program with proper jump offset calculation.
   The program parses Ethernet and IPv4 headers and validates bounds.

   Map FDs are accepted for future SNAT implementation but currently
   the program only does packet validation and passes all valid packets."
  [map-fds]
  (if (and (map? map-fds)
           (:conntrack-map map-fds))
    (build-tc-snat-program
      (common/map-fd (:conntrack-map map-fds)))
    ;; Use SNAT program even without maps (it just passes packets)
    (build-tc-snat-program nil)))

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
