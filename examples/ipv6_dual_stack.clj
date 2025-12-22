;; IPv6 Dual-Stack Examples
;;
;; Demonstrates IPv6 support for load balancing with full dual-stack
;; operation where the same proxy handles both IPv4 and IPv6 traffic.
;;
;; Usage:
;;   sudo clojure -M:dev
;;   (load-file "examples/ipv6_dual_stack.clj")
;;
;; IPv6 support enables routing traffic to IPv6 backends and accepting
;; connections from IPv6 clients alongside existing IPv4 infrastructure.

(ns ipv6-dual-stack
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.util :as util]
            [lb.maps :as maps]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Example Configurations
;;; =============================================================================

(def example-config-ipv6-only
  "Configuration with IPv6-only backends.
   Proxy listens on all interfaces and routes to IPv6 backends."
  {:proxies
   [{:name "ipv6-api"
     :listen {:interfaces ["lo"] :port 8080}
     :default-target
     [{:ip "::1" :port 9001 :weight 50}
      {:ip "::1" :port 9002 :weight 50}]
     :health-check
     {:type :tcp
      :interval-ms 5000
      :timeout-ms 2000}}]
   :settings
   {:stats-enabled true
    :health-check-enabled true}})

(def example-config-dual-stack
  "Configuration with both IPv4 and IPv6 backends.
   Traffic is distributed across both address families."
  {:proxies
   [{:name "dual-stack-api"
     :listen {:interfaces ["lo"] :port 8080}
     :default-target
     [;; IPv4 backends
      {:ip "127.0.0.1" :port 9001 :weight 25}
      {:ip "127.0.0.1" :port 9002 :weight 25}
      ;; IPv6 backends
      {:ip "::1" :port 9003 :weight 25}
      {:ip "::1" :port 9004 :weight 25}]
     :health-check
     {:type :tcp
      :interval-ms 5000}}]
   :settings
   {:stats-enabled true
    :health-check-enabled true}})

(def example-config-ipv6-source-routes
  "Configuration with IPv6 source-based routing.
   Route clients from different IPv6 networks to specific backends."
  {:proxies
   [{:name "ipv6-routed"
     :listen {:interfaces ["lo"] :port 8080}
     :default-target {:ip "::1" :port 9000}
     :source-routes
     [;; Documentation prefix routes to backend 1
      {:source "2001:db8::/32"
       :target {:ip "2001:db8::1" :port 9001}}
      ;; Private network routes to backend 2
      {:source "fd00::/8"
       :target {:ip "fd00::1" :port 9002}}
      ;; Link-local stays local
      {:source "fe80::/10"
       :target {:ip "::1" :port 9003}}]}]})

(def example-config-ipv6-sni
  "Configuration with IPv6 backends for TLS/SNI routing.
   Route HTTPS traffic based on hostname to IPv6 backends."
  {:proxies
   [{:name "ipv6-https"
     :listen {:interfaces ["lo"] :port 443}
     :default-target {:ip "::1" :port 8443}
     :sni-routes
     [{:sni-hostname "api.example.com"
       :target {:ip "2001:db8::10" :port 8443}}
      {:sni-hostname "www.example.com"
       :target [{:ip "2001:db8::20" :port 8443 :weight 50}
                {:ip "2001:db8::21" :port 8443 :weight 50}]}]}]})

(def example-config-ipv6-weighted
  "Configuration with weighted IPv6 backends.
   Demonstrates weighted load balancing with IPv6 addresses."
  {:proxies
   [{:name "weighted-ipv6"
     :listen {:interfaces ["lo"] :port 8080}
     :default-target
     [{:ip "2001:db8::1" :port 8080 :weight 60}   ; Primary (60%)
      {:ip "2001:db8::2" :port 8080 :weight 30}   ; Secondary (30%)
      {:ip "2001:db8::3" :port 8080 :weight 10}]  ; Tertiary (10%)
     :session-persistence true}]})

;;; =============================================================================
;;; IPv6 Address Format Explanation
;;; =============================================================================

(defn explain-ipv6-formats
  "Explain supported IPv6 address formats"
  []
  (println "
=== Supported IPv6 Address Formats ===

Full format (8 groups of 4 hex digits):
  2001:0db8:0000:0000:0000:0000:0000:0001

Compressed format (:: replaces consecutive zeros):
  2001:db8::1
  ::1                 (loopback)
  ::                  (all zeros)
  fe80::1             (link-local)

Mixed notation (NOT supported - use pure IPv6):
  ::ffff:192.168.1.1  (IPv4-mapped - not supported)

Common prefixes:
  ::1/128             Loopback
  fe80::/10           Link-local
  fc00::/7            Unique local (private)
  2000::/3            Global unicast
  ff00::/8            Multicast

Configuration examples:
  {:ip \"::1\" :port 8080}
  {:ip \"2001:db8::1\" :port 8080 :weight 50}
  {:source \"2001:db8::/32\" :target {:ip \"2001:db8::1\" :port 8080}}
"))

;;; =============================================================================
;;; Address Parsing Demos
;;; =============================================================================

(defn demo-address-parsing
  "Demonstrate IPv6 address parsing utilities"
  []
  (println "\n=== IPv6 Address Parsing Demo ===\n")

  (let [test-addresses ["::1"
                        "2001:db8::1"
                        "fe80::1"
                        "2001:db8:85a3::8a2e:370:7334"
                        "fd00:1234:5678:9abc:def0:1234:5678:9abc"]]
    (println "Parsing IPv6 addresses:\n")
    (doseq [addr test-addresses]
      (let [bytes (util/ipv6-string->bytes addr)
            back (util/bytes->ipv6-string bytes)]
        (println (format "  %-40s -> %s" addr back)))))

  (println "\n\nUnified format (16 bytes for both IPv4 and IPv6):\n")
  (let [test-mixed ["192.168.1.1" "::1" "10.0.0.1" "2001:db8::1"]]
    (doseq [addr test-mixed]
      (let [bytes16 (util/ip-string->bytes16 addr)
            back (util/bytes16->ip-string bytes16)
            af (util/address-family addr)]
        (println (format "  %-20s (%s) -> %s" addr (name af) back))))))

(defn demo-cidr-parsing
  "Demonstrate IPv6 CIDR parsing"
  []
  (println "\n=== IPv6 CIDR Parsing Demo ===\n")

  (let [test-cidrs ["2001:db8::/32"
                    "fe80::/10"
                    "fd00::/8"
                    "::1/128"
                    "192.168.1.0/24"
                    "10.0.0.0/8"]]
    (println "Parsing CIDR notation:\n")
    (doseq [cidr test-cidrs]
      (let [parsed (util/parse-cidr-unified cidr)]
        (println (format "  %-25s -> prefix-len: %d, af: %s"
                         cidr
                         (:prefix-len parsed)
                         (name (:af parsed))))))))

;;; =============================================================================
;;; Unified Map Format Explanation
;;; =============================================================================

(defn explain-unified-maps
  "Explain how unified maps work for dual-stack"
  []
  (println "
=== Unified Map Format for Dual-Stack ===

The load balancer uses unified maps that support both IPv4 and IPv6:

LPM Trie Key (20 bytes):
  - prefix_len: 4 bytes (0-128 for IPv6, 0-32 for IPv4)
  - ip: 16 bytes (IPv4 zero-padded to 16 bytes)

Listen Map Key (8 bytes):
  - ifindex: 4 bytes
  - port: 2 bytes
  - af: 1 byte (4=IPv4, 6=IPv6)
  - pad: 1 byte

Route Value (168 bytes):
  - header: 8 bytes (target_count, flags, etc.)
  - targets: 8 x 20 bytes each
    - ip: 16 bytes
    - port: 2 bytes
    - cumulative_weight: 2 bytes

Conntrack Key (40 bytes):
  - src_ip: 16 bytes
  - dst_ip: 16 bytes
  - src_port: 2 bytes
  - dst_port: 2 bytes
  - protocol: 1 byte
  - pad: 3 bytes

IPv4 Address Embedding:
  IPv4 addresses are stored in the last 4 bytes of the 16-byte field,
  with the first 12 bytes set to zero.

  Example: 192.168.1.1 becomes:
  00:00:00:00:00:00:00:00:00:00:00:00:c0:a8:01:01
"))

;;; =============================================================================
;;; Checksum Handling Explanation
;;; =============================================================================

(defn explain-checksum-handling
  "Explain IPv6 checksum differences"
  []
  (println "
=== IPv6 Checksum Handling ===

Key differences from IPv4:

1. No IP Header Checksum
   IPv6 does not have an IP header checksum.
   Only TCP/UDP checksums need updating during NAT.

2. Larger Pseudo-Header
   IPv6 TCP/UDP pseudo-header is 40 bytes:
   - Source address: 16 bytes
   - Destination address: 16 bytes
   - Upper layer length: 4 bytes
   - Zero padding: 3 bytes
   - Next header: 1 byte

3. UDP Checksum Mandatory
   Unlike IPv4 where UDP checksum can be 0,
   IPv6 requires UDP checksum to be calculated.

4. Incremental Update
   When changing destination IP during DNAT:
   - IPv4: Update both IP checksum and L4 checksum
   - IPv6: Only update L4 checksum (16 bytes instead of 4)

XDP Implementation:
  - Uses bpf_csum_diff for 16-byte address changes
  - Four 4-byte word updates for each address change
  - No bpf_l3_csum_replace needed for IPv6
"))

;;; =============================================================================
;;; Runtime API Examples
;;; =============================================================================

(defn show-runtime-api
  "Show IPv6-related runtime API usage"
  []
  (println "
=== IPv6 Runtime API Examples ===

Address detection:
  (util/ipv6? \"2001:db8::1\")        ; => true
  (util/ipv4? \"192.168.1.1\")        ; => true
  (util/address-family \"::1\")       ; => :ipv6

Address conversion:
  (util/ipv6-string->bytes \"::1\")
  (util/bytes->ipv6-string bytes)
  (util/ip-string->bytes16 \"192.168.1.1\")  ; 16-byte unified
  (util/bytes16->ip-string bytes16)

CIDR parsing:
  (util/parse-cidr-unified \"2001:db8::/32\")
  ; => {:ip <16-byte-array> :prefix-len 32 :af :ipv6}

Creating unified maps:
  (maps/create-all-maps-unified)
  ; Returns maps with larger key/value sizes for IPv6

Adding IPv6 routes:
  (lb/add-source-route! proxy-name
    {:source \"2001:db8::/32\"
     :target {:ip \"2001:db8::1\" :port 8080}})

Adding IPv6 targets:
  (lb/add-weighted-target! proxy-name
    {:ip \"2001:db8::1\" :port 8080 :weight 50})
"))

;;; =============================================================================
;;; Best Practices
;;; =============================================================================

(defn show-best-practices
  "Show IPv6 deployment best practices"
  []
  (println "
=== IPv6 Deployment Best Practices ===

1. Use Unified Programs for Dual-Stack
   The unified XDP/TC programs handle both address families.
   Use build-xdp-ingress-program-unified and
   build-tc-egress-program-unified for dual-stack.

2. Keep IPv4 and IPv6 Backends Separate
   This implementation does not use IPv4-mapped IPv6 addresses.
   IPv6 targets should have native IPv6 backends.

3. Configure Health Checks for Both
   Health checks work with both IPv4 and IPv6 addresses.
   Ensure backends are reachable over the configured address family.

4. Consider Source Routing
   Use source-routes to direct IPv6 clients to IPv6 backends
   and IPv4 clients to IPv4 backends if needed.

5. Monitor Both Address Families
   Prometheus metrics include address family labels.
   Set up alerts for both IPv4 and IPv6 backend health.

6. Test Checksum Handling
   IPv6 checksums are critical (no fallback to IP checksum).
   Verify TCP/UDP connectivity after NAT.

7. Plan Address Allocation
   Use consistent IPv6 prefix allocation for source routing.
   Document your IPv6 address plan.
"))

;;; =============================================================================
;;; Main Demo
;;; =============================================================================

(defn -main
  "Run IPv6 dual-stack demos"
  []
  (println "\n=== IPv6 Dual-Stack Examples Loaded ===")
  (explain-ipv6-formats)
  (demo-address-parsing)
  (println "\nTo start load balancer with IPv6:")
  (println "  (def cfg (config/parse-config ipv6-dual-stack/example-config-ipv6-only))")
  (println "  (lb/init! cfg)")
  (println "\nTo start with dual-stack:")
  (println "  (def cfg (config/parse-config ipv6-dual-stack/example-config-dual-stack))")
  (println "  (lb/init! cfg)")
  (println "\nOther demos:")
  (println "  (demo-cidr-parsing)")
  (println "  (explain-unified-maps)")
  (println "  (explain-checksum-handling)")
  (println "  (show-runtime-api)")
  (println "  (show-best-practices)"))

;; Show usage on load
(println "
=== IPv6 Dual-Stack Examples Loaded ===

Quick start:
  ;; Initialize with IPv6 backends
  (def cfg (config/parse-config ipv6-dual-stack/example-config-ipv6-only))
  (lb/init! cfg)

  ;; Or with dual-stack (IPv4 + IPv6)
  (def cfg (config/parse-config ipv6-dual-stack/example-config-dual-stack))
  (lb/init! cfg)

  (lb/shutdown!)

Demos:
  (ipv6-dual-stack/-main)
  (explain-ipv6-formats)
  (demo-address-parsing)
  (demo-cidr-parsing)
  (explain-unified-maps)
  (explain-checksum-handling)
  (show-runtime-api)
  (show-best-practices)

Example configurations:
  example-config-ipv6-only       ; IPv6 backends only
  example-config-dual-stack      ; Mixed IPv4 and IPv6
  example-config-ipv6-source-routes  ; IPv6 source routing
  example-config-ipv6-sni        ; IPv6 with SNI routing
  example-config-ipv6-weighted   ; Weighted IPv6 backends
")
