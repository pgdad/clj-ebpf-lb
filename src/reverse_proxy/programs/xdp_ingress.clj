(ns reverse-proxy.programs.xdp-ingress
  "XDP ingress program for the reverse proxy.
   Handles incoming packets: parses headers, looks up routing, performs DNAT."
  (:require [clj-ebpf.dsl :as dsl]
            [clj-ebpf.core :as bpf]
            [reverse-proxy.programs.common :as common]
            [clojure.tools.logging :as log]))

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
;;; Program Building Functions
;;; =============================================================================

(defn build-load-context
  "Load packet data pointers from xdp_md context.

   xdp_md structure:
     u32 data;       // offset 0
     u32 data_end;   // offset 4
     u32 data_meta;  // offset 8
     u32 ingress_ifindex; // offset 12
     u32 rx_queue_index;  // offset 16

   Sets: r6 = data, r7 = data_end, stores ifindex on stack"
  []
  [(common/ldx-w :r6 :r1 0)      ;; r6 = xdp_md->data
   (common/ldx-w :r7 :r1 4)      ;; r7 = xdp_md->data_end
   ;; Load and save ifindex
   (common/ldx-w :r8 :r1 12)     ;; r8 = xdp_md->ingress_ifindex
   (common/stx-w :r10 -56 :r8)]) ;; save ifindex on stack

(defn build-listen-map-lookup
  "Look up destination port in listen map.

   Key structure: {ifindex (4), port (2), padding (2)}
   Uses stack -32 to -24 for key

   Jumps to pass-label if not found.
   Saves result pointer in stack -48."
  [listen-map-fd pass-label]
  [;; Build key at stack -32
   ;; Load ifindex from stack -56
   (common/ldx-w :r8 :r10 -56)
   (common/stx-w :r10 -32 :r8)    ;; key.ifindex

   ;; Load dst port from stack -24
   (common/ldx-h :r8 :r10 -24)
   (common/stx-h :r10 -28 :r8)    ;; key.port
   (common/stx-h :r10 -26 :r8)    ;; padding (zero it)
   (dsl/st :h :r10 -26 0)         ;; zero padding

   ;; Call map lookup
   (dsl/lddw :r1 listen-map-fd)
   (common/mov-reg :r2 :r10)
   (common/add-imm :r2 -32)
   (dsl/call common/BPF-FUNC-map-lookup-elem)

   ;; Check result
   (dsl/jmp-imm :jeq :r0 0 pass-label)

   ;; Save result pointer
   (common/stx-dw :r10 -48 :r0)])

(defn build-lpm-lookup
  "Look up source IP in LPM trie config map.

   Key structure: {prefix_len (4), ip (4)}
   Uses stack -40 to -32 for key

   If found, r0 points to specific target.
   If not found, falls back to listen map default (from stack -48)."
  [config-map-fd]
  [;; Build LPM key at stack -40
   (dsl/st :w :r10 -40 32)        ;; prefix_len = 32 (exact match)
   (common/ldx-w :r8 :r10 -8)     ;; src IP from stack
   (common/stx-w :r10 -36 :r8)    ;; key.ip

   ;; Save listen map result in r9 (callee-saved)
   (common/ldx-dw :r9 :r10 -48)

   ;; Call LPM lookup
   (dsl/lddw :r1 config-map-fd)
   (common/mov-reg :r2 :r10)
   (common/add-imm :r2 -40)
   (dsl/call common/BPF-FUNC-map-lookup-elem)

   ;; If found (r0 != NULL), use it; else use listen map default
   (dsl/jmp-imm :jne :r0 0 :use-route-target)
   (common/mov-reg :r0 :r9)       ;; restore listen map ptr
   [:label :use-route-target]])

(defn build-save-original-dst
  "Save original destination IP and port before NAT.
   For use in connection tracking."
  []
  [(common/ldx-w :r8 :r10 -12)    ;; original dst IP
   (common/stx-w :r10 -64 :r8)
   (common/ldx-h :r8 :r10 -24)    ;; original dst port
   (common/stx-w :r10 -72 :r8)])

(defn build-dnat-rewrite
  "Perform DNAT: rewrite destination IP and port.

   r0 = pointer to route value {target_ip (4), target_port (2), flags (2)}
   r6 = packet data

   Also updates checksums."
  []
  [;; Save route pointer in r9
   (common/mov-reg :r9 :r0)

   ;; Load new destination IP
   (common/ldx-w :r8 :r9 0)       ;; r8 = target_ip

   ;; Calculate IP dest offset: ETH_HLEN + 16
   ;; Store new dst IP in packet
   (common/stx-w :r6 (+ common/ETH-HLEN 16) :r8)

   ;; Load new destination port
   (common/ldx-h :r8 :r9 4)       ;; r8 = target_port

   ;; Calculate L4 dest port offset
   ;; For simplicity, assume fixed IP header (20 bytes)
   ;; L4 offset = ETH_HLEN + IP_HLEN_MIN + 2 (dst port at offset 2)
   (common/stx-h :r6 (+ common/ETH-HLEN common/IP-HLEN-MIN 2) :r8)

   ;; TODO: Update checksums
   ;; This requires the checksum helper support in clj-ebpf
   ;; For now, we'll need to recalculate or use helpers if available

   ;; IP checksum update would be:
   ;; bpf_l3_csum_replace(xdp, csum_off, old_ip, new_ip, sizeof(u32))

   ;; L4 checksum update would be:
   ;; bpf_l4_csum_replace(xdp, l4_csum_off, old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(u32))
   ;; bpf_l4_csum_replace(xdp, l4_csum_off, old_port, new_port, sizeof(u16))
   ])

(defn build-return-action
  "Return XDP action."
  [action]
  [(common/mov-imm :r0 action)
   (dsl/exit-insn)])

(defn build-xdp-ingress-program
  "Build the complete XDP ingress program.

   Parameters:
     listen-map-fd: FD of the listen port map
     config-map-fd: FD of the LPM trie config map
     conntrack-map-fd: FD of the connection tracking map
     settings-map-fd: FD of the settings array map
     stats-ringbuf-fd: FD of the stats ring buffer

   The program:
   1. Parses Ethernet/IP/TCP|UDP headers
   2. Looks up destination port in listen map
   3. Looks up source IP in LPM trie for specific routing
   4. Falls back to default target if no specific route
   5. Performs DNAT (destination rewrite)
   6. Returns XDP_TX to transmit the modified packet"
  [{:keys [listen-map-fd config-map-fd conntrack-map-fd settings-map-fd stats-ringbuf-fd]}]
  (common/flatten-instructions
    ;; Prologue: load context
    (build-load-context)

    ;; Parse Ethernet header
    (common/build-parse-eth :pass)

    ;; Parse IP header
    (common/build-parse-ip :pass)

    ;; Parse L4 header (TCP/UDP ports)
    (common/build-parse-l4 :pass)

    ;; Look up in listen map
    (build-listen-map-lookup listen-map-fd :pass)

    ;; Save original destination for conntrack
    (build-save-original-dst)

    ;; Look up in LPM config map
    (build-lpm-lookup config-map-fd)

    ;; Perform DNAT
    (build-dnat-rewrite)

    ;; TODO: Add conntrack entry
    ;; TODO: Emit stats if enabled

    ;; Return XDP_TX
    (build-return-action common/XDP-TX)

    ;; Pass label: return XDP_PASS (not our traffic)
    [[:label :pass]]
    (build-return-action common/XDP-PASS)))

;;; =============================================================================
;;; Program Loading and Attachment
;;; =============================================================================

(defn load-program
  "Load the XDP ingress program.

   Returns the program FD."
  [maps]
  (log/info "Loading XDP ingress program")
  (let [instructions (build-xdp-ingress-program
                       {:listen-map-fd (bpf/map-fd (:listen-map maps))
                        :config-map-fd (bpf/map-fd (:config-map maps))
                        :conntrack-map-fd (bpf/map-fd (:conntrack-map maps))
                        :settings-map-fd (bpf/map-fd (:settings-map maps))
                        :stats-ringbuf-fd (bpf/map-fd (:stats-ringbuf maps))})]
    (bpf/load-xdp-program instructions)))

(defn attach-to-interface
  "Attach XDP program to a network interface.

   prog-fd: Program file descriptor
   iface: Interface name (e.g., \"eth0\")
   mode: :skb (generic), :drv (native), or :hw (hardware)"
  [prog-fd iface & {:keys [mode] :or {mode :skb}}]
  (log/info "Attaching XDP program to" iface "in" mode "mode")
  (let [ifindex (bpf/interface-name->index iface)]
    (when (nil? ifindex)
      (throw (ex-info "Interface not found" {:interface iface})))
    (bpf/attach-xdp prog-fd ifindex {:mode mode})))

(defn attach-to-interfaces
  "Attach XDP program to multiple interfaces."
  [prog-fd interfaces & opts]
  (doseq [iface interfaces]
    (apply attach-to-interface prog-fd iface opts)))

(defn detach-from-interface
  "Detach XDP program from an interface."
  [iface]
  (log/info "Detaching XDP program from" iface)
  (let [ifindex (bpf/interface-name->index iface)]
    (when ifindex
      (bpf/detach-xdp ifindex))))

(defn detach-from-interfaces
  "Detach XDP program from multiple interfaces."
  [interfaces]
  (doseq [iface interfaces]
    (detach-from-interface iface)))

;;; =============================================================================
;;; Program Verification
;;; =============================================================================

(defn verify-program
  "Verify the XDP program can be loaded (dry run).
   Returns {:valid true} or {:valid false :error <message>}"
  [maps]
  (try
    (let [prog-fd (load-program maps)]
      (bpf/close-program prog-fd)
      {:valid true})
    (catch Exception e
      {:valid false
       :error (.getMessage e)})))

;;; =============================================================================
;;; Debug Utilities
;;; =============================================================================

(defn dump-program-instructions
  "Dump program instructions for debugging."
  [maps]
  (let [instructions (build-xdp-ingress-program
                       {:listen-map-fd 0
                        :config-map-fd 0
                        :conntrack-map-fd 0
                        :settings-map-fd 0
                        :stats-ringbuf-fd 0})]
    (println "XDP Ingress Program Instructions:")
    (println "=================================")
    (doseq [[idx insn] (map-indexed vector instructions)]
      (println (format "%3d: %s" idx (pr-str insn))))))
