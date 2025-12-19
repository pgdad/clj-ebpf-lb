(ns reverse-proxy.programs.xdp-ingress
  "XDP ingress program for the reverse proxy.
   Handles incoming packets: parses headers, looks up routing, performs DNAT."
  (:require [clj-ebpf.core :as bpf]
            [reverse-proxy.programs.common :as common]
            [clojure.tools.logging :as log]
            [clojure.java.shell :as shell]))

;;; =============================================================================
;;; XDP Program Structure
;;; =============================================================================

;; Stack layout (negative offsets from r10):
;; -4   : IP protocol (4 bytes, only lower byte used)
;; -8   : Source IP (4 bytes)
;; -12  : Destination IP (4 bytes)
;; -16  : IP header length (4 bytes)
;; -20  : Source port (2 bytes, stored as 4)
;; -24  : Destination port (2 bytes, stored as 4)
;; -32  : Listen map key (8 bytes)
;; -40  : LPM key (8 bytes)
;; -48  : Saved listen map value ptr (8 bytes)
;; -56  : ifindex (4 bytes)
;; -64  : Original dst IP for conntrack (4 bytes)
;; -72  : Original dst port (4 bytes)

;;; =============================================================================
;;; Simple Pass-Through XDP Program
;;; =============================================================================

(defn build-xdp-pass-program
  "Build a simple XDP program that passes all packets.
   This is useful for initial testing of program loading/attachment."
  []
  (bpf/assemble
    [(bpf/mov :r0 (:pass bpf/xdp-action))
     (bpf/exit-insn)]))

;;; =============================================================================
;;; IPv4 Only Filter Program
;;; =============================================================================

(defn build-ipv4-only-program
  "Build XDP program that only passes IPv4 packets.
   Non-IPv4 packets are dropped."
  []
  (bpf/assemble
    [;; r6 = ctx->data
     (bpf/ldx :w :r6 :r1 0)
     ;; r7 = ctx->data_end
     (bpf/ldx :w :r7 :r1 4)

     ;; Check if we have at least 14 bytes (Ethernet header)
     (bpf/mov-reg :r8 :r6)
     (bpf/add :r8 14)
     ;; if r8 > r7 goto +5 (pass, packet too short)
     (bpf/jmp-reg :jgt :r8 :r7 5)

     ;; Load ethertype at offset 12
     (bpf/ldx :h :r8 :r6 12)
     ;; Convert to little endian for comparison
     (bpf/end-to-le :r8 16)
     ;; if ethertype == 0x0800 (IPv4), pass
     (bpf/jmp-imm :jeq :r8 0x0800 1)

     ;; Not IPv4 - drop
     (bpf/mov :r0 (:drop bpf/xdp-action))
     (bpf/exit-insn)

     ;; IPv4 or too short - pass
     (bpf/mov :r0 (:pass bpf/xdp-action))
     (bpf/exit-insn)]))

;;; =============================================================================
;;; Port Filter Program
;;; =============================================================================

(defn build-port-filter-program
  "Build XDP program that passes packets on a specific port.
   Other TCP/UDP packets are passed through.
   This is a stepping stone toward the full proxy."
  [target-port]
  (bpf/assemble
    [;; r6 = ctx->data
     (bpf/ldx :w :r6 :r1 0)
     ;; r7 = ctx->data_end
     (bpf/ldx :w :r7 :r1 4)

     ;; Check Ethernet header bounds (14 bytes)
     (bpf/mov-reg :r8 :r6)
     (bpf/add :r8 14)
     (bpf/jmp-reg :jgt :r8 :r7 16) ;; jump to pass if too short

     ;; Load ethertype
     (bpf/ldx :h :r8 :r6 12)
     (bpf/end-to-le :r8 16)
     (bpf/jmp-imm :jne :r8 0x0800 13) ;; not IPv4, jump to pass

     ;; Check IP header bounds (14 + 20 = 34 bytes)
     (bpf/mov-reg :r8 :r6)
     (bpf/add :r8 34)
     (bpf/jmp-reg :jgt :r8 :r7 10) ;; jump to pass if too short

     ;; Load IP protocol at offset 14+9=23
     (bpf/ldx :b :r8 :r6 23)
     ;; Check if TCP (6) or UDP (17)
     (bpf/jmp-imm :jeq :r8 6 1)
     (bpf/jmp-imm :jne :r8 17 6) ;; not TCP or UDP, pass

     ;; Check L4 header bounds (need 4 more bytes for ports)
     (bpf/mov-reg :r8 :r6)
     (bpf/add :r8 38) ;; 14 + 20 + 4
     (bpf/jmp-reg :jgt :r8 :r7 3) ;; jump to pass if too short

     ;; Load destination port at offset 14+20+2=36 (2 bytes, big-endian)
     (bpf/ldx :h :r8 :r6 36)
     ;; Convert to little endian
     (bpf/end-to-le :r8 16)
     ;; Check if matches target port - if so, this is "our" traffic
     (bpf/jmp-imm :jne :r8 target-port 0) ;; match -> continue, else pass

     ;; Pass label
     (bpf/mov :r0 (:pass bpf/xdp-action))
     (bpf/exit-insn)]))

;;; =============================================================================
;;; Full XDP Ingress Program (Simplified)
;;; =============================================================================

;; Note: A full proxy implementation requires:
;; 1. Map lookups (listen ports, LPM routing table)
;; 2. Connection tracking updates
;; 3. DNAT (rewriting destination IP/port)
;; 4. Checksum recalculation
;;
;; Due to the complexity of implementing this in pure eBPF bytecode,
;; we'll start with a simple pass-through and iterate.

(defn build-xdp-ingress-program
  "Build the XDP ingress program.

   For initial testing, this is a simple pass-through.
   The full implementation will be built incrementally."
  [_map-fds]
  ;; Start with simple pass-through for testing
  (build-xdp-pass-program))

;;; =============================================================================
;;; Program Loading and Attachment
;;; =============================================================================

(defn load-program
  "Load the XDP ingress program.
   Returns a BpfProgram record."
  [maps]
  (log/info "Loading XDP ingress program")
  (let [bytecode (build-xdp-ingress-program maps)]
    ;; Note: We use clj-ebpf.programs/load-program directly because
    ;; clj-ebpf.xdp/load-xdp-program has a bug in its argument handling
    (require '[clj-ebpf.programs :as programs])
    ((resolve 'clj-ebpf.programs/load-program)
      {:insns bytecode
       :prog-type :xdp
       :prog-name "xdp_ingress"
       :license "GPL"
       :log-level 1})))

(defn attach-to-interface
  "Attach XDP program to a network interface.
   Uses ip command as workaround for clj-ebpf netlink bug.

   prog: BpfProgram record or program FD
   iface: Interface name (e.g., \"eth0\")
   mode: :skb (generic), :drv (native), or :hw (hardware)"
  [prog iface & {:keys [mode] :or {mode :skb}}]
  (log/info "Attaching XDP program to" iface "in" mode "mode")
  (let [prog-fd (if (number? prog) prog (:fd prog))
        pin-path (str "/sys/fs/bpf/xdp_" iface)
        mode-flag (case mode
                    :skb "xdpgeneric"
                    :drv "xdpdrv"
                    :hw "xdpoffload"
                    "xdpgeneric")]
    ;; Pin the program to BPF filesystem using clj-ebpf
    (require '[clj-ebpf.programs :as programs])
    (try
      ((resolve 'clj-ebpf.programs/pin-program)
        {:fd prog-fd :name "xdp_ingress"} pin-path)
      (catch Exception e
        ;; Ignore if already pinned
        (when-not (re-find #"File exists|already exists" (str e))
          (throw e))))
    ;; Attach using ip link
    (let [result (shell/sh "ip" "link" "set" "dev" iface mode-flag "pinned" pin-path)]
      (when (not= 0 (:exit result))
        (throw (ex-info "Failed to attach XDP program"
                        {:interface iface :error (:err result)}))))))

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
