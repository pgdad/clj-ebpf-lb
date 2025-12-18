(ns reverse-proxy.programs.tc-egress
  "TC egress program for the reverse proxy.
   Handles reply packets from backends: performs SNAT to restore original destination."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.core :as bpf]
            [reverse-proxy.programs.common :as common]
            [clojure.tools.logging :as log]))

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
;;; Conntrack Reverse Lookup
;;; =============================================================================

(defn build-reverse-conntrack-key
  "Build reverse conntrack key for reply packet lookup.

   For a reply packet from backend to client:
   - src_ip = client IP (packet dst)
   - dst_ip = backend IP (packet src)
   - src_port = client port (packet dst port)
   - dst_port = backend port (packet src port)
   - protocol = same

   This matches the original forward connection."
  []
  [;; Reverse key: swap src/dst from packet
   ;; key.src_ip = packet.dst_ip (client)
   (common/ldx-w :r8 :r10 -12)
   (common/stx-w :r10 -40 :r8)

   ;; key.dst_ip = packet.src_ip (backend)
   (common/ldx-w :r8 :r10 -8)
   (common/stx-w :r10 -36 :r8)

   ;; key.src_port = packet.dst_port
   (common/ldx-h :r8 :r10 -24)
   (common/stx-h :r10 -32 :r8)

   ;; key.dst_port = packet.src_port
   (common/ldx-h :r8 :r10 -20)
   (common/stx-h :r10 -30 :r8)

   ;; key.protocol
   (common/ldx-w :r8 :r10 -4)
   (common/stx-b :r10 -28 :r8)

   ;; Padding
   (dsl/st :b :r10 -27 0)
   (dsl/st :h :r10 -26 0)])

(defn build-conntrack-lookup
  "Look up connection in conntrack map using reverse key.

   Returns pointer to conntrack entry in r0, or NULL."
  [conntrack-map-fd pass-label]
  (concat
    (build-reverse-conntrack-key)
    [;; Call map lookup
     (dsl/lddw :r1 conntrack-map-fd)
     (common/mov-reg :r2 :r10)
     (common/add-imm :r2 -40)
     (dsl/call common/BPF-FUNC-map-lookup-elem)

     ;; Check result
     (dsl/jmp-imm :jeq :r0 0 pass-label)

     ;; Save result pointer
     (common/stx-dw :r10 -48 :r0)]))

(defn build-snat-rewrite
  "Perform SNAT: rewrite source IP and port to original destination.

   r0 = pointer to conntrack value {orig_dst_ip, orig_dst_port, ...}
   r6 = packet data (skb->data for TC)

   The conntrack value contains the original destination that we need
   to restore as the source of the reply packet."
  []
  [;; r9 = conntrack value pointer
   (common/ldx-dw :r9 :r10 -48)

   ;; Load original destination IP (what client was trying to reach)
   (common/ldx-w :r8 :r9 0)       ;; r8 = orig_dst_ip

   ;; Store as new source IP in packet
   ;; Source IP offset = ETH_HLEN + 12
   (common/stx-w :r6 (+ common/ETH-HLEN 12) :r8)

   ;; Load original destination port
   ;; Note: conntrack value layout:
   ;; {orig_dst_ip (4), orig_dst_port (2), padding (2), nat_dst_ip (4), nat_dst_port (2), ...}
   (common/ldx-h :r8 :r9 4)       ;; r8 = orig_dst_port

   ;; Store as new source port in packet
   ;; Source port offset = ETH_HLEN + IP_HLEN_MIN + 0
   (common/stx-h :r6 (+ common/ETH-HLEN common/IP-HLEN-MIN 0) :r8)

   ;; TODO: Update checksums (same as DNAT but for source fields)
   ])

(defn build-tc-load-context
  "Load packet data pointers from __sk_buff context (TC).

   __sk_buff structure (relevant fields):
     u32 len;           // offset 0
     u32 pkt_type;      // offset 4
     u32 mark;          // offset 8
     u32 queue_mapping; // offset 12
     u32 protocol;      // offset 16
     ...
     u32 data;          // offset 76
     u32 data_end;      // offset 80

   Note: TC programs access data differently than XDP."
  []
  [(common/ldx-w :r6 :r1 76)     ;; r6 = skb->data
   (common/ldx-w :r7 :r1 80)])   ;; r7 = skb->data_end

(defn build-tc-return
  "Return TC action."
  [action]
  [(common/mov-imm :r0 action)
   (dsl/exit-insn)])

;;; =============================================================================
;;; Complete TC Egress Program
;;; =============================================================================

(defn build-tc-egress-program
  "Build the complete TC egress program.

   Parameters:
     conntrack-map-fd: FD of the connection tracking map
     settings-map-fd: FD of the settings array map
     stats-ringbuf-fd: FD of the stats ring buffer

   The program:
   1. Parses Ethernet/IP/TCP|UDP headers
   2. Builds reverse conntrack key
   3. Looks up connection in conntrack map
   4. If found, performs SNAT to restore original destination as source
   5. Returns TC_ACT_OK to continue normal processing"
  [{:keys [conntrack-map-fd settings-map-fd stats-ringbuf-fd]}]
  (common/flatten-instructions
    ;; Prologue: load context
    (build-tc-load-context)

    ;; Parse Ethernet header
    (common/build-parse-eth :pass)

    ;; Parse IP header
    (common/build-parse-ip :pass)

    ;; Parse L4 header
    (common/build-parse-l4 :pass)

    ;; Look up reverse connection
    (build-conntrack-lookup conntrack-map-fd :pass)

    ;; Perform SNAT
    (build-snat-rewrite)

    ;; TODO: Update stats if enabled

    ;; Return TC_ACT_OK
    (build-tc-return common/TC-ACT-OK)

    ;; Pass label: not our traffic, return OK
    [[:label :pass]]
    (build-tc-return common/TC-ACT-OK)))

;;; =============================================================================
;;; Program Loading and Attachment
;;; =============================================================================

(defn load-program
  "Load the TC egress program.

   Returns the program FD."
  [maps]
  (log/info "Loading TC egress program")
  (let [instructions (build-tc-egress-program
                       {:conntrack-map-fd (bpf/map-fd (:conntrack-map maps))
                        :settings-map-fd (bpf/map-fd (:settings-map maps))
                        :stats-ringbuf-fd (bpf/map-fd (:stats-ringbuf maps))})]
    (bpf/load-tc-program instructions)))

(defn attach-to-interface
  "Attach TC egress program to a network interface.

   prog-fd: Program file descriptor
   iface: Interface name (e.g., \"eth0\")
   priority: Filter priority (lower = higher priority)"
  [prog-fd iface & {:keys [priority] :or {priority 1}}]
  (log/info "Attaching TC egress program to" iface "with priority" priority)
  (bpf/attach-tc-filter prog-fd iface :egress {:priority priority}))

(defn attach-to-interfaces
  "Attach TC egress program to multiple interfaces."
  [prog-fd interfaces & opts]
  (doseq [iface interfaces]
    (apply attach-to-interface prog-fd iface opts)))

(defn detach-from-interface
  "Detach TC egress program from an interface."
  [iface & {:keys [priority] :or {priority 1}}]
  (log/info "Detaching TC egress program from" iface)
  (bpf/detach-tc-filter iface :egress {:priority priority}))

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
   Uses tc command via shell."
  [iface]
  (log/info "Setting up clsact qdisc on" iface)
  ;; This would normally use shell command:
  ;; tc qdisc add dev <iface> clsact
  ;; But we should use clj-ebpf's TC setup functions if available
  (bpf/setup-tc-qdisc iface))

(defn teardown-tc-qdisc
  "Remove clsact qdisc from an interface."
  [iface]
  (log/info "Tearing down clsact qdisc on" iface)
  (bpf/teardown-tc-qdisc iface))

;;; =============================================================================
;;; Debug Utilities
;;; =============================================================================

(defn dump-program-instructions
  "Dump program instructions for debugging."
  [maps]
  (let [instructions (build-tc-egress-program
                       {:conntrack-map-fd 0
                        :settings-map-fd 0
                        :stats-ringbuf-fd 0})]
    (println "TC Egress Program Instructions:")
    (println "================================")
    (doseq [[idx insn] (map-indexed vector instructions)]
      (println (format "%3d: %s" idx (pr-str insn))))))
