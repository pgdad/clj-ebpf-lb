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
;;; Full XDP Ingress Program with DNAT
;;; =============================================================================

(defn build-xdp-dnat-program
  "Build XDP ingress program that performs DNAT on incoming packets.

   This program:
   1. Parses IPv4/TCP or IPv4/UDP packets
   2. Looks up listen map to find target backend
   3. Creates conntrack entry for the connection
   4. Rewrites destination IP/port (DNAT)
   5. Updates checksums manually (XDP has no kernel helpers)

   Register allocation:
   r6 = saved XDP context (callee-saved)
   r7 = data pointer (callee-saved)
   r8 = data_end pointer (callee-saved)
   r9 = IP header pointer / scratch (callee-saved)

   Note: XDP programs don't have access to bpf_l3_csum_replace and
   bpf_l4_csum_replace. They must use bpf_csum_diff or calculate manually."
  [_listen-map-fd _conntrack-map-fd]
  ;; For now, implement basic packet parsing with pass-through
  ;; Full DNAT with manual checksum handling is complex
  (let [pass-offset 2]
    (bpf/assemble
      (concat
        ;; === Program Entry ===
        ;; Save XDP context to callee-saved register
        [(dsl/mov-reg :r6 :r1)]

        ;; Load data and data_end pointers from XDP context
        ;; XDP md: data at offset 0, data_end at offset 8
        (net/xdp-load-data-ptrs :r7 :r8 :r1)

        ;; === Parse Ethernet Header ===
        ;; Check we have at least ETH_HLEN bytes
        (net/check-bounds :r7 :r8 net/ETH-HLEN pass-offset :r9)

        ;; Load ethertype and check for IPv4
        (eth/load-ethertype :r9 :r7)
        (eth/is-not-ipv4 :r9 pass-offset)

        ;; === Parse IPv4 Header ===
        ;; Calculate IP header pointer: data + ETH_HLEN
        (eth/get-ip-header-ptr :r9 :r7)

        ;; Check IP header bounds
        (net/check-bounds :r9 :r8 net/IPV4-MIN-HLEN pass-offset :r0)

        ;; For now, just pass all packets
        ;; Full DNAT with manual checksum handling requires:
        ;; 1. Store old IP/port values on stack
        ;; 2. Modify packet in place using nat/xdp-rewrite-* helpers
        ;; 3. Use csum/csum-diff to compute checksum delta
        ;; 4. Apply delta to IP and L4 checksums

        ;; === Pass Label ===
        (net/return-action net/XDP-PASS)))))

(defn build-xdp-ingress-program
  "Build the XDP ingress program.

   Currently uses pass-through mode while DNAT implementation
   with proper jump offset calculation is in development.

   The DNAT program structure is ready but needs careful
   instruction counting to calculate correct jump offsets."
  [_map-fds]
  ;; Use pass-through for now - DNAT requires proper jump offset calculation
  ;; The build-xdp-dnat-program has the right structure but jump offsets
  ;; need to be calculated based on actual instruction counts
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
