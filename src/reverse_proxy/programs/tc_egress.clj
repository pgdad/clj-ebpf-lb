(ns reverse-proxy.programs.tc-egress
  "TC egress program for the reverse proxy.
   Handles reply packets from backends: performs SNAT to restore original destination."
  (:require [clj-ebpf.core :as bpf]
            [reverse-proxy.programs.common :as common]
            [clojure.tools.logging :as log]
            [clojure.java.shell :as shell]))

;;; =============================================================================
;;; TC Program Structure
;;; =============================================================================

;; The TC egress program handles the reply path:
;; 1. Parse packet headers
;; 2. Look up reverse connection in conntrack map
;; 3. If found, rewrite source IP/port to original destination
;; 4. Return TC_ACT_OK to continue processing

;; Stack layout (negative offsets from r10):
;; -4   : IP protocol
;; -8   : Source IP (backend IP)
;; -12  : Destination IP (client IP)
;; -16  : IP header length
;; -20  : Source port (backend port)
;; -24  : Destination port (client port)
;; -40  : Conntrack lookup key (16 bytes)
;; -48  : Saved result pointer

;;; =============================================================================
;;; Simple Pass-Through TC Program
;;; =============================================================================

(defn build-tc-pass-program
  "Build a simple TC program that passes all packets.
   This is useful for initial testing of program loading/attachment."
  []
  (bpf/assemble
    [(bpf/mov :r0 common/TC-ACT-OK)
     (bpf/exit-insn)]))

;;; =============================================================================
;;; IPv4 Only TC Filter
;;; =============================================================================

(defn build-tc-ipv4-only-program
  "Build TC program that only passes IPv4 packets.
   Non-IPv4 packets are dropped."
  []
  (bpf/assemble
    [;; TC uses __sk_buff context
     ;; data is at offset 76, data_end at offset 80
     (bpf/ldx :w :r6 :r1 76)   ;; r6 = skb->data
     (bpf/ldx :w :r7 :r1 80)   ;; r7 = skb->data_end

     ;; Check if we have at least 14 bytes (Ethernet header)
     (bpf/mov-reg :r8 :r6)
     (bpf/add :r8 14)
     ;; if r8 > r7 goto +5 (ok, packet too short - pass)
     (bpf/jmp-reg :jgt :r8 :r7 5)

     ;; Load ethertype at offset 12
     (bpf/ldx :h :r8 :r6 12)
     ;; Convert to little endian for comparison
     (bpf/end-to-le :r8 16)
     ;; if ethertype == 0x0800 (IPv4), pass
     (bpf/jmp-imm :jeq :r8 0x0800 1)

     ;; Not IPv4 - drop
     (bpf/mov :r0 common/TC-ACT-SHOT)
     (bpf/exit-insn)

     ;; IPv4 or too short - pass
     (bpf/mov :r0 common/TC-ACT-OK)
     (bpf/exit-insn)]))

;;; =============================================================================
;;; Full TC Egress Program (Simplified)
;;; =============================================================================

;; Note: A full SNAT implementation requires:
;; 1. Reverse conntrack lookup
;; 2. Source IP/port rewriting
;; 3. Checksum recalculation
;;
;; Due to the complexity, we start with a simple pass-through.

(defn build-tc-egress-program
  "Build the TC egress program.

   For initial testing, this is a simple pass-through.
   The full SNAT implementation will be built incrementally."
  [_map-fds]
  ;; Start with simple pass-through for testing
  (build-tc-pass-program))

;;; =============================================================================
;;; Program Loading and Attachment
;;; =============================================================================

(defn load-program
  "Load the TC egress program.
   Returns a BpfProgram record."
  [maps]
  (log/info "Loading TC egress program")
  (let [bytecode (build-tc-egress-program maps)]
    ;; Note: We use clj-ebpf.programs/load-program directly because
    ;; clj-ebpf.tc/load-tc-program has a similar bug to load-xdp-program
    (require '[clj-ebpf.programs :as programs])
    ((resolve 'clj-ebpf.programs/load-program)
      {:insns bytecode
       :prog-type :sched-cls
       :prog-name "tc_egress"
       :license "GPL"
       :log-level 1})))

(defn attach-to-interface
  "Attach TC egress program to a network interface.
   Uses shell commands as workaround for clj-ebpf integer overflow bug.

   prog: BpfProgram record or program FD
   iface: Interface name (e.g., \"eth0\")
   priority: Filter priority (lower = higher priority)"
  [prog iface & {:keys [priority] :or {priority 1}}]
  (log/info "Attaching TC egress program to" iface "with priority" priority)
  (let [prog-fd (if (number? prog) prog (:fd prog))
        pin-path (str "/sys/fs/bpf/tc_egress_" iface)]
    ;; Pin the program to BPF filesystem
    (require '[clj-ebpf.programs :as programs])
    (try
      ((resolve 'clj-ebpf.programs/pin-program)
        {:fd prog-fd :name "tc_egress"} pin-path)
      (catch Exception e
        ;; Ignore if already pinned
        (when-not (re-find #"File exists|already exists" (str e))
          (throw e))))
    ;; Attach using tc filter add command with pinned object
    (let [result (shell/sh "tc" "filter" "add" "dev" iface
                           "egress" "prio" (str priority)
                           "bpf" "da" "pinned" pin-path)]
      (when (not= 0 (:exit result))
        (throw (ex-info "Failed to attach TC egress program"
                        {:interface iface :error (:err result)}))))))

(defn attach-to-interfaces
  "Attach TC egress program to multiple interfaces."
  [prog interfaces & opts]
  (doseq [iface interfaces]
    (apply attach-to-interface prog iface opts)))

(defn detach-from-interface
  "Detach TC egress program from an interface.
   Uses shell commands as workaround for clj-ebpf integer overflow bug."
  [iface & {:keys [priority] :or {priority 1}}]
  (log/info "Detaching TC egress program from" iface)
  (try
    ;; Remove TC filter
    (shell/sh "tc" "filter" "del" "dev" iface "egress" "prio" (str priority))
    ;; Remove pinned program
    (let [pin-path (str "/sys/fs/bpf/tc_egress_" iface)]
      (shell/sh "rm" "-f" pin-path))
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
  "Set up clsact qdisc on an interface (required for TC attachment).
   Uses shell command as workaround for clj-ebpf bug."
  [iface]
  (log/info "Setting up clsact qdisc on" iface)
  ;; Use tc command directly as workaround for clj-ebpf integer overflow bug
  (let [result (shell/sh "tc" "qdisc" "add" "dev" iface "clsact")]
    ;; Ignore errors if qdisc already exists
    (when (and (not= 0 (:exit result))
               (not (re-find #"File exists|Exclusivity flag|already exists" (:err result))))
      (log/warn "Failed to add clsact qdisc:" (:err result)))))

(defn teardown-tc-qdisc
  "Remove clsact qdisc from an interface.
   Uses shell command as workaround for clj-ebpf bug."
  [iface]
  (log/info "Tearing down clsact qdisc on" iface)
  (try
    (shell/sh "tc" "qdisc" "del" "dev" iface "clsact")
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
