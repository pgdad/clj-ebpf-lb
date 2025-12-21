;; DNS-Based Backend Resolution Examples
;;
;; Demonstrates using DNS hostnames for dynamic backend discovery,
;; useful for Kubernetes, cloud environments, and services with changing IPs.
;;
;; Usage:
;;   sudo clojure -M:dev
;;   (load-file "examples/dns-resolution.clj")
;;
;; DNS resolution:
;;   1. Use :host instead of :ip for DNS-backed targets
;;   2. Periodic re-resolution with configurable intervals
;;   3. Multiple A records expand to weighted targets automatically
;;   4. Graceful failure with last-known-good IP fallback

(ns dns-resolution
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.dns :as dns]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Example Configurations
;;; =============================================================================

(def basic-dns-config
  "Simple DNS-based backend configuration"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target
     {:host "localhost"        ; DNS hostname instead of IP
      :port 9000}}]})

(def dns-with-refresh-config
  "DNS with custom refresh interval (useful for dynamic environments)"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target
     {:host "localhost"
      :port 9000
      :dns-refresh-seconds 10}}]})  ; Re-resolve every 10 seconds

(def weighted-dns-config
  "DNS target with weight (for mixed static/DNS setups)"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target
     {:host "localhost"
      :port 9000
      :weight 100
      :dns-refresh-seconds 30}}]})

(def mixed-targets-config
  "Mix of static IPs and DNS hostnames"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target
     [{:ip "127.0.0.1" :port 9001 :weight 50}        ; Static IP
      {:host "localhost" :port 9002 :weight 50}]}]}) ; DNS hostname

(def dns-with-health-check-config
  "DNS target with health checking"
  {:proxies
   [{:name "api"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target
     {:host "localhost"
      :port 9000
      :dns-refresh-seconds 30
      :health-check {:type :http
                     :path "/health"
                     :interval-ms 5000
                     :timeout-ms 2000}}}]
   :settings
   {:health-check-enabled true}})

(def kubernetes-style-config
  "Configuration mimicking Kubernetes headless service discovery

   In Kubernetes, a headless service (clusterIP: None) returns all pod IPs
   as A records. This config demonstrates that pattern."
  {:proxies
   [{:name "backend-service"
     :listen {:interfaces ["eth0"] :port 80}
     :default-target
     {:host "backend.default.svc.cluster.local"  ; K8s DNS name
      :port 8080
      :dns-refresh-seconds 5                      ; Quick updates for pod changes
      :health-check {:type :http
                     :path "/healthz"
                     :interval-ms 3000}}}]
   :settings
   {:health-check-enabled true}})

(def multi-service-config
  "Multiple proxies with different DNS backends"
  {:proxies
   [{:name "frontend"
     :listen {:interfaces ["lo"] :port 8080}
     :default-target
     {:host "localhost"
      :port 3000
      :dns-refresh-seconds 60}}

    {:name "backend-api"
     :listen {:interfaces ["lo"] :port 8081}
     :default-target
     {:host "localhost"
      :port 4000
      :dns-refresh-seconds 30}}

    {:name "database-proxy"
     :listen {:interfaces ["lo"] :port 5432}
     :default-target
     {:host "localhost"
      :port 15432
      :dns-refresh-seconds 120}}]})  ; Databases change less often

;;; =============================================================================
;;; DNS Status Monitoring
;;; =============================================================================

(defn show-dns-status
  "Display DNS resolution status for all proxies"
  []
  (println "\n=== DNS Resolution Status ===\n")
  (let [all-status (lb/get-all-dns-status)]
    (if (empty? all-status)
      (println "No DNS targets registered.")
      (doseq [[proxy-name status] all-status]
        (println (str "Proxy: " proxy-name))
        (doseq [[hostname target] (:targets status)]
          (println (str "  " hostname ":"))
          (println (str "    Port: " (:port target)))
          (println (str "    Weight: " (:weight target)))
          (println (str "    Refresh: " (/ (:refresh-ms target) 1000) "s"))
          (println (str "    Last IPs: " (pr-str (:last-ips target))))
          (println (str "    Last resolved: " (java.util.Date. (:last-resolved-at target))))
          (println (str "    Failures: " (:consecutive-failures target))))
        (println)))))

(defn monitor-dns
  "Continuously monitor DNS resolution status.
   Press Ctrl+C to stop."
  []
  (println "\n=== Monitoring DNS Resolution ===")
  (println "Press Ctrl+C to stop.\n")
  (loop []
    (show-dns-status)
    (println "---")
    (Thread/sleep 5000)
    (recur)))

;;; =============================================================================
;;; Force DNS Resolution
;;; =============================================================================

(defn force-refresh
  "Force immediate DNS re-resolution for a hostname"
  [proxy-name hostname]
  (println (str "\nForcing DNS refresh for " hostname " in " proxy-name "..."))
  (if (lb/force-dns-resolve! proxy-name hostname)
    (do
      (println "Refresh triggered successfully.")
      (Thread/sleep 100)  ; Give time for resolution
      (when-let [status (lb/get-dns-status proxy-name)]
        (let [target (get-in status [:targets hostname])]
          (println (str "Current IPs: " (pr-str (:last-ips target)))))))
    (println "Failed to trigger refresh. Check proxy/hostname.")))

;;; =============================================================================
;;; DNS Event Subscription
;;; =============================================================================

(defn subscribe-to-dns-events
  "Subscribe to DNS resolution events and print them.
   Returns an unsubscribe function."
  []
  (println "\n=== Subscribing to DNS Events ===")
  (let [unsubscribe
        (dns/subscribe!
          (fn [event]
            (case (:type event)
              :dns-resolved
              (println (format "[DNS] %s/%s resolved: %s -> %s"
                               (:proxy-name event)
                               (:hostname event)
                               (pr-str (get-in event [:data :old-ips]))
                               (pr-str (get-in event [:data :new-ips]))))

              :dns-failed
              (println (format "[DNS] %s/%s FAILED: %s (%s) - failures: %d"
                               (:proxy-name event)
                               (:hostname event)
                               (get-in event [:data :error-type])
                               (get-in event [:data :message])
                               (get-in event [:data :consecutive-failures]))))))]
    (println "Subscribed. Call the returned function to unsubscribe.")
    unsubscribe))

;;; =============================================================================
;;; Multiple A Record Demo
;;; =============================================================================

(defn demo-multi-a-record
  "Demonstrate how multiple A records are handled.

   When a hostname resolves to multiple IPs, the weight is distributed
   equally among all resolved IPs."
  []
  (println "
=== Multiple A Record Handling ===

When a hostname resolves to multiple A records (IPs), clj-ebpf-lb
automatically distributes the configured weight equally among all IPs.

Example:
  Config: {:host \"backend.local\" :port 8080 :weight 60}

  If backend.local resolves to 3 IPs:
    10.0.0.1:8080 -> weight 20
    10.0.0.2:8080 -> weight 20
    10.0.0.3:8080 -> weight 20

This is ideal for:
  - Kubernetes headless services (pods have individual IPs)
  - Round-robin DNS configurations
  - Cloud provider load balancer backends
"))

;;; =============================================================================
;;; Kubernetes Use Case
;;; =============================================================================

(defn demo-kubernetes-pattern
  "Demonstrate Kubernetes-style service discovery pattern"
  []
  (println "
=== Kubernetes Service Discovery Pattern ===

In Kubernetes, you can use clj-ebpf-lb with headless services:

1. Create a headless service (clusterIP: None):

   apiVersion: v1
   kind: Service
   metadata:
     name: backend
   spec:
     clusterIP: None
     selector:
       app: backend
     ports:
       - port: 8080

2. Configure clj-ebpf-lb to use the service DNS:

   {:host \"backend.default.svc.cluster.local\"
    :port 8080
    :dns-refresh-seconds 5}

3. As pods scale up/down, DNS returns different A records,
   and clj-ebpf-lb automatically updates the target list.

Benefits:
  - No sidecar required
  - Sub-millisecond load balancing
  - Automatic failover when pods terminate
  - Works with any Kubernetes CNI
"))

;;; =============================================================================
;;; Failure Handling Demo
;;; =============================================================================

(defn demo-failure-handling
  "Demonstrate DNS failure handling"
  []
  (println "
=== DNS Failure Handling ===

clj-ebpf-lb handles DNS failures gracefully:

Startup Behavior:
  - Initial DNS resolution MUST succeed
  - If hostname can't be resolved, proxy creation fails
  - This prevents misconfiguration from going unnoticed

Runtime Behavior:
  - Failed resolutions are logged with warning level
  - Last-known-good IPs continue to be used
  - Consecutive failure count is tracked
  - Events are emitted for monitoring

Check failure status:
  (lb/get-dns-status \"proxy-name\")
  ;; Look for :consecutive-failures > 0

Subscribe to failure events:
  (dns/subscribe! (fn [event]
    (when (= :dns-failed (:type event))
      (alert! event))))
"))

;;; =============================================================================
;;; Direct DNS Resolution
;;; =============================================================================

(defn resolve-hostname
  "Directly resolve a hostname (for testing/debugging)"
  [hostname]
  (println (str "\nResolving " hostname "..."))
  (let [result (dns/resolve-hostname hostname)]
    (if (:success? result)
      (do
        (println "Success!")
        (println "IPs:" (pr-str (dns/resolve-all-ips hostname))))
      (do
        (println "Failed!")
        (println "Error:" (:error-type result))
        (println "Message:" (:message result))))))

;;; =============================================================================
;;; API Reference
;;; =============================================================================

(defn show-dns-api
  "Print available DNS API functions"
  []
  (println "
=== DNS Resolution API ===

Configuration (in :default-target):
  {:host \"hostname\"              ; Use DNS instead of :ip
   :port 8080                      ; Required
   :weight 100                     ; Optional, default 100
   :dns-refresh-seconds 30         ; Optional, default 30
   :health-check {...}}            ; Optional, applied to resolved IPs

Status functions:
  (lb/get-dns-status \"proxy-name\")     ; Status for one proxy
  (lb/get-all-dns-status)                ; Status for all proxies
  (lb/force-dns-resolve! \"proxy\" \"host\") ; Force refresh

Direct resolution (for testing):
  (dns/resolve-hostname \"hostname\")    ; Returns {:success? true :ips [...]}
  (dns/resolve-all-ips \"hostname\")     ; Returns [\"1.2.3.4\" \"5.6.7.8\"]

Event subscription:
  (dns/subscribe! callback-fn)           ; Returns unsubscribe function

  Events have:
    :type       - :dns-resolved or :dns-failed
    :proxy-name - Proxy name
    :hostname   - Hostname that was resolved
    :timestamp  - Event timestamp
    :data       - Event-specific data

Lifecycle (called automatically by lb/init! and lb/shutdown!):
  (dns/start!)
  (dns/stop!)
  (dns/running?)
"))

;;; =============================================================================
;;; Main Demo
;;; =============================================================================

(defn -main
  "Run demos. Note: Most demos work without root/BPF if just exploring DNS."
  []
  (println "\n=== DNS Resolution Examples ===\n")

  ;; These work without the load balancer running
  (println "Testing direct DNS resolution:")
  (resolve-hostname "localhost")
  (resolve-hostname "invalid.hostname.that.does.not.exist")

  (println "\n")
  (demo-multi-a-record)
  (demo-failure-handling)
  (show-dns-api)

  (println "
To run with the load balancer:

  ;; Initialize with DNS config
  (def cfg (config/parse-config examples.dns-resolution/basic-dns-config))
  (lb/init! cfg)

  ;; Monitor DNS status
  (show-dns-status)
  (force-refresh \"api\" \"localhost\")

  ;; Subscribe to events
  (def unsub (subscribe-to-dns-events))
  ;; ... later ...
  (unsub)

  ;; Shutdown
  (lb/shutdown!)
"))

;;; =============================================================================
;;; Quick Start on Load
;;; =============================================================================

(println "
=== DNS Resolution Examples Loaded ===

Quick test (no root required):
  (resolve-hostname \"localhost\")
  (resolve-hostname \"google.com\")

Full demo with load balancer (requires root):
  (def cfg (config/parse-config examples.dns-resolution/basic-dns-config))
  (lb/init! cfg)
  (show-dns-status)
  (lb/shutdown!)

Available configurations:
  basic-dns-config           - Simple DNS backend
  dns-with-refresh-config    - Custom refresh interval
  weighted-dns-config        - DNS with weight
  mixed-targets-config       - Static IP + DNS mixed
  dns-with-health-check-config - DNS with health checks
  kubernetes-style-config    - K8s headless service pattern
  multi-service-config       - Multiple proxies with DNS

Functions:
  (show-dns-status)          - Display current DNS status
  (monitor-dns)              - Continuous monitoring
  (force-refresh p h)        - Force DNS refresh
  (subscribe-to-dns-events)  - Subscribe to DNS events
  (resolve-hostname h)       - Direct hostname resolution
  (show-dns-api)             - Print API reference
  (-main)                    - Run all demos
")
