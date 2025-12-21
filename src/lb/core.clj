(ns lb.core
  "Core API for the eBPF load balancer.
   Provides high-level functions for initialization, configuration, and management."
  (:require [clj-ebpf.core :as bpf]
            [lb.config :as config]
            [lb.maps :as maps]
            [lb.programs.xdp-ingress :as xdp]
            [lb.programs.tc-egress :as tc]
            [lb.conntrack :as conntrack]
            [lb.stats :as stats]
            [lb.health :as health]
            [lb.drain :as drain]
            [lb.rate-limit :as rate-limit]
            [lb.reload :as reload]
            [lb.dns :as dns]
            [lb.util :as util]
            [clojure.tools.logging :as log]
            [clojure.tools.cli :refer [parse-opts]])
  (:import [lb.config TargetGroup DNSTargetGroup])
  (:gen-class))

;;; =============================================================================
;;; Forward Declarations
;;; =============================================================================

(declare apply-config! attach-interfaces! detach-interfaces!
         register-health-checks! unregister-health-checks!
         register-dns-targets! unregister-dns-targets!)

;;; =============================================================================
;;; Proxy State
;;; =============================================================================

(defonce ^:private proxy-state
  ;; Global proxy state atom.
  (atom nil))

(defn get-state
  "Get the current proxy state."
  []
  @proxy-state)

(defn- set-state!
  "Set the proxy state."
  [state]
  (reset! proxy-state state))

(defn running?
  "Check if the proxy is currently running."
  []
  (some? @proxy-state))

(defmacro with-lb-state
  "Execute body with load balancer state bound to the specified binding.
   Returns nil if the load balancer is not running.

   Example:
     (with-lb-state [state]
       (let [{:keys [maps config]} state]
         ;; work with state
         ))"
  [[binding] & body]
  `(when-let [~binding @proxy-state]
     ~@body))

;;; =============================================================================
;;; Initialization
;;; =============================================================================

(defn init!
  "Initialize the eBPF reverse proxy.

   Parameters:
     config - Configuration object (from config/parse-config or config/load-config-file)

   Options:
     :max-routes - Maximum number of source routes
     :max-connections - Maximum concurrent connections
     :ringbuf-size - Ring buffer size for stats

   Returns the proxy state map."
  [config & {:keys [max-routes max-connections ringbuf-size]
             :or {max-routes 10000
                  max-connections 100000
                  ringbuf-size (* 256 1024)}}]
  (when (running?)
    (throw (ex-info "Proxy is already running" {})))

  (log/info "Initializing eBPF load balancer")

  ;; Verify BPF availability
  (bpf/init!)

  ;; Create all maps
  (log/info "Creating eBPF maps")
  (let [maps-config {:max-routes max-routes
                     :max-connections max-connections
                     :ringbuf-size ringbuf-size}
        ebpf-maps (maps/create-all-maps maps-config)]

    (try
      ;; Load XDP program
      (log/info "Loading XDP ingress program")
      (let [xdp-prog-fd (xdp/load-program ebpf-maps)]

        ;; Load TC program
        (log/info "Loading TC egress program")
        (let [tc-prog-fd (tc/load-program ebpf-maps)]

          ;; Apply initial configuration
          (log/info "Applying configuration")
          (apply-config! ebpf-maps config)

          ;; Set up cleanup daemon
          (log/info "Starting cleanup daemon")
          (let [cleanup-daemon (conntrack/start-cleanup-daemon
                                 (:conntrack-map ebpf-maps)
                                 (:settings-map ebpf-maps))]

            ;; Store state
            (let [state {:config config
                         :maps ebpf-maps
                         :xdp-prog-fd xdp-prog-fd
                         :tc-prog-fd tc-prog-fd
                         :cleanup-daemon cleanup-daemon
                         :attached-interfaces (atom #{})
                         :stats-stream (atom nil)}]
              (set-state! state)

              ;; Attach to interfaces
              (doseq [proxy-cfg (:proxies config)]
                (let [interfaces (get-in proxy-cfg [:listen :interfaces])]
                  (attach-interfaces! interfaces)))

              ;; Register health checks if enabled
              (register-health-checks! ebpf-maps config)

              ;; Initialize drain module
              (let [drain-settings (:settings config)
                    drain-update-fn (create-drain-update-fn ebpf-maps)]
                (drain/init! (:conntrack-map ebpf-maps) drain-update-fn
                             :check-interval-ms (or (:drain-check-interval-ms drain-settings) 1000)))

              ;; Initialize rate limiting
              (rate-limit/init! (:rate-limit-config-map ebpf-maps)
                                (:rate-limit-src-map ebpf-maps)
                                (:rate-limit-backend-map ebpf-maps))

              ;; Apply rate limit settings from config if present
              (when-let [settings (:settings config)]
                (rate-limit/configure-from-settings! settings))

              ;; Start DNS resolution daemon and register DNS-backed targets
              (dns/start!)
              (register-dns-targets! ebpf-maps config)

              ;; Register reload functions for hot reload support
              (register-reload-functions!)

              (log/info "Load balancer initialized successfully")
              state))))

      (catch Exception e
        ;; Clean up on error
        (maps/close-all-maps ebpf-maps)
        (throw e)))))

(defn shutdown!
  "Shutdown the reverse proxy and release all resources."
  []
  (with-lb-state [state]
    (log/info "Shutting down load balancer")

    ;; Disable hot reload first
    (reload/disable-hot-reload!)

    ;; Stop DNS resolution daemon
    (unregister-dns-targets! (:config state))
    (dns/stop!)

    ;; Shutdown rate limiting
    (rate-limit/shutdown!)

    ;; Shutdown drain module
    (drain/shutdown!)

    ;; Stop health checking
    (unregister-health-checks! (:config state))

    ;; Stop stats stream if running
    (when-let [stream @(:stats-stream state)]
      (stats/stop-event-stream stream))

    ;; Stop cleanup daemon
    (when-let [daemon (:cleanup-daemon state)]
      (conntrack/stop-cleanup-daemon daemon))

    ;; Detach from all interfaces
    (let [interfaces @(:attached-interfaces state)]
      (detach-interfaces! (vec interfaces)))

    ;; Close programs
    (when-let [xdp-fd (:xdp-prog-fd state)]
      (bpf/close-program xdp-fd))
    (when-let [tc-fd (:tc-prog-fd state)]
      (bpf/close-program tc-fd))

    ;; Close maps
    (maps/close-all-maps (:maps state))

    ;; Clear state
    (set-state! nil)

    (log/info "Load balancer shutdown complete")))

;;; =============================================================================
;;; Configuration Application
;;; =============================================================================

(defn- apply-config!
  "Apply configuration to eBPF maps.
   Now supports weighted load balancing with TargetGroup records and SNI routing."
  [ebpf-maps config]
  (let [{:keys [listen-map config-map sni-map settings-map]} ebpf-maps]

    ;; Apply settings
    (let [settings (:settings config)]
      (if (:stats-enabled settings)
        (maps/enable-stats settings-map)
        (maps/disable-stats settings-map))
      (maps/set-connection-timeout settings-map
        (or (:connection-timeout-sec settings) 300)))

    ;; Apply proxy configurations
    (doseq [proxy-cfg (:proxies config)]
      (let [{:keys [listen default-target source-routes sni-routes]} proxy-cfg
            {:keys [interfaces port]} listen]

        ;; Add listen port for each interface
        ;; default-target is now a TargetGroup with :targets and :cumulative-weights
        (doseq [iface interfaces]
          (when-let [ifindex (util/get-interface-index iface)]
            (maps/add-listen-port-weighted listen-map ifindex port
              default-target
              :flags (if (:stats-enabled (:settings config)) 1 0))))

        ;; Add source routes
        ;; Each route now has :target-group instead of :target
        (doseq [route source-routes]
          (maps/add-source-route-weighted config-map
            {:ip (:source route)
             :prefix-len (:prefix-len route)}
            (:target-group route)))

        ;; Add SNI routes for TLS hostname-based routing
        (doseq [sni-route sni-routes]
          (maps/add-sni-route sni-map
            (:hostname sni-route)
            (:target-group sni-route)))))))

;;; =============================================================================
;;; Interface Attachment
;;; =============================================================================

(defn attach-interfaces!
  "Attach proxy programs to network interfaces."
  [interfaces]
  (with-lb-state [state]
    (let [{:keys [xdp-prog-fd tc-prog-fd attached-interfaces]} state]
      (doseq [iface interfaces]
        (when-not (contains? @attached-interfaces iface)
          (log/info "Attaching to interface:" iface)

          ;; Set up TC qdisc
          (tc/setup-tc-qdisc iface)

          ;; Attach XDP program
          (xdp/attach-to-interface xdp-prog-fd iface :mode :skb)

          ;; Attach TC egress program
          (tc/attach-to-interface tc-prog-fd iface)

          ;; Track attachment
          (swap! attached-interfaces conj iface))))))

(defn detach-interfaces!
  "Detach proxy programs from network interfaces."
  [interfaces]
  (with-lb-state [state]
    (let [{:keys [attached-interfaces]} state]
      (doseq [iface interfaces]
        (when (contains? @attached-interfaces iface)
          (log/info "Detaching from interface:" iface)

          ;; Detach XDP
          (xdp/detach-from-interface iface)

          ;; Detach TC
          (tc/detach-from-interface iface)

          ;; Tear down TC qdisc
          (tc/teardown-tc-qdisc iface)

          ;; Track detachment
          (swap! attached-interfaces disj iface))))))

(defn list-attached-interfaces
  "List currently attached interfaces."
  []
  (with-lb-state [state]
    (vec @(:attached-interfaces state))))

;;; =============================================================================
;;; Configuration Management
;;; =============================================================================

(defn add-proxy!
  "Add a new proxy configuration at runtime.
   Now supports weighted load balancing with TargetGroup records."
  [proxy-config]
  (with-lb-state [state]
    (let [parsed (config/parse-proxy-config proxy-config)
          new-config (config/add-proxy (:config state) parsed)]

      ;; Update maps
      (let [{:keys [listen-map config-map]} (:maps state)
            {:keys [listen default-target source-routes]} parsed
            {:keys [interfaces port]} listen]

        ;; Add listen port entries with weighted targets
        (doseq [iface interfaces]
          (when-let [ifindex (util/get-interface-index iface)]
            (maps/add-listen-port-weighted listen-map ifindex port
              default-target)))

        ;; Add source routes with weighted targets
        (doseq [route source-routes]
          (maps/add-source-route-weighted config-map
            {:ip (:source route)
             :prefix-len (:prefix-len route)}
            (:target-group route)))

        ;; Attach to new interfaces
        (attach-interfaces! interfaces))

      ;; Update state
      (swap! proxy-state assoc :config new-config)
      (log/info "Added proxy:" (:name parsed)))))

(defn remove-proxy!
  "Remove a proxy configuration at runtime."
  [proxy-name]
  (with-lb-state [state]
    (when-let [proxy-cfg (config/get-proxy (:config state) proxy-name)]
      (let [{:keys [listen-map config-map]} (:maps state)
            {:keys [listen source-routes]} proxy-cfg
            {:keys [interfaces port]} listen]

        ;; Remove listen port entries
        (doseq [iface interfaces]
          (when-let [ifindex (util/get-interface-index iface)]
            (maps/remove-listen-port listen-map ifindex port)))

        ;; Remove source routes
        (doseq [route source-routes]
          (maps/remove-source-route config-map
            {:ip (:source route)
             :prefix-len (:prefix-len route)}))

        ;; Update state
        (swap! proxy-state update :config config/remove-proxy proxy-name)
        (log/info "Removed proxy:" proxy-name)))))

(defn add-source-route!
  "Add a source route to a proxy.
   target can be:
   - Single target: {:ip \"10.0.0.1\" :port 8080}
   - Weighted targets: [{:ip \"10.0.0.1\" :port 8080 :weight 50}
                        {:ip \"10.0.0.2\" :port 8080 :weight 50}]"
  [proxy-name source target]
  (with-lb-state [state]
    (let [{:keys [config-map]} (:maps state)
          {:keys [ip prefix-len]} (util/resolve-to-ip source)
          ;; Normalize target to TargetGroup
          target-group (cond
                         ;; Already a TargetGroup record
                         (instance? TargetGroup target)
                         target

                         ;; Vector of targets - create weighted target group
                         (vector? target)
                         (config/make-weighted-target-group target)

                         ;; Single target map - create single target group
                         :else
                         (config/make-single-target-group
                           (if (string? (:ip target))
                             (util/ip-string->u32 (:ip target))
                             (:ip target))
                           (:port target)))
          ;; For config update, convert back to map format
          target-spec (if (vector? target) target {:ip (:ip target) :port (:port target)})]

      (maps/add-source-route-weighted config-map
        {:ip ip :prefix-len prefix-len}
        target-group)

      (swap! proxy-state update :config
             config/add-source-route-to-proxy proxy-name
             (if (vector? target)
               {:source source :targets target}
               {:source source :target target}))

      (log/info "Added source route:" source "->" target))))

(defn remove-source-route!
  "Remove a source route from a proxy."
  [proxy-name source]
  (with-lb-state [state]
    (let [{:keys [config-map]} (:maps state)
          {:keys [ip prefix-len]} (util/resolve-to-ip source)]

      (maps/remove-source-route config-map {:ip ip :prefix-len prefix-len})

      (swap! proxy-state update :config
             config/remove-source-route-from-proxy proxy-name ip prefix-len)

      (log/info "Removed source route:" source))))

;;; =============================================================================
;;; SNI Route Management (TLS/HTTPS hostname-based routing)
;;; =============================================================================

(defn add-sni-route!
  "Add an SNI route to a proxy for TLS hostname-based routing.
   hostname: TLS SNI hostname to match (e.g., \"api.example.com\")
   target can be:
   - Single target: {:ip \"10.0.0.1\" :port 8443}
   - Weighted targets: [{:ip \"10.0.0.1\" :port 8443 :weight 50}
                        {:ip \"10.0.0.2\" :port 8443 :weight 50}]"
  [proxy-name hostname target]
  (with-lb-state [state]
    (let [{:keys [sni-map]} (:maps state)
          ;; Normalize target to TargetGroup
          target-group (cond
                         ;; Already a TargetGroup record
                         (instance? TargetGroup target)
                         target

                         ;; Vector of targets - create weighted target group
                         (vector? target)
                         (config/make-weighted-target-group target)

                         ;; Single target map - create single target group
                         :else
                         (config/make-single-target-group
                           (if (string? (:ip target))
                             (util/ip-string->u32 (:ip target))
                             (:ip target))
                           (:port target)))
          ;; For config update, prepare the route map
          sni-route-map (if (vector? target)
                          {:sni-hostname hostname :targets target}
                          {:sni-hostname hostname :target target})]

      ;; Update BPF map
      (maps/add-sni-route sni-map hostname target-group)

      ;; Update config state
      (swap! proxy-state update :config
             config/add-sni-route-to-proxy proxy-name sni-route-map)

      (log/info "Added SNI route:" hostname "->" target))))

(defn remove-sni-route!
  "Remove an SNI route from a proxy."
  [proxy-name hostname]
  (with-lb-state [state]
    (let [{:keys [sni-map]} (:maps state)]

      ;; Remove from BPF map
      (maps/remove-sni-route sni-map hostname)

      ;; Update config state
      (swap! proxy-state update :config
             config/remove-sni-route-from-proxy proxy-name hostname)

      (log/info "Removed SNI route:" hostname))))

(defn list-sni-routes
  "List all SNI routes for a proxy.
   Returns a sequence of {:hostname :target-group} maps."
  [proxy-name]
  (with-lb-state [state]
    (when-let [proxy-cfg (config/get-proxy (:config state) proxy-name)]
      (:sni-routes proxy-cfg))))

(defn list-all-sni-routes
  "List all SNI routes from BPF map.
   Note: Returns hostname hashes since original hostnames aren't stored in BPF."
  []
  (with-lb-state [state]
    (let [{:keys [sni-map]} (:maps state)]
      (maps/list-sni-routes sni-map))))

;;; =============================================================================
;;; Statistics Control
;;; =============================================================================

(defn enable-stats!
  "Enable statistics collection."
  []
  (with-lb-state [state]
    (maps/enable-stats (get-in state [:maps :settings-map]))
    (log/info "Statistics collection enabled")))

(defn disable-stats!
  "Disable statistics collection."
  []
  (with-lb-state [state]
    (maps/disable-stats (get-in state [:maps :settings-map]))
    (log/info "Statistics collection disabled")))

(defn stats-enabled?
  "Check if statistics collection is enabled."
  []
  (with-lb-state [state]
    (maps/stats-enabled? (get-in state [:maps :settings-map]))))

(defn start-stats-stream!
  "Start streaming statistics events."
  []
  (with-lb-state [state]
    (when-not @(:stats-stream state)
      (let [stream (stats/create-event-stream
                     (get-in state [:maps :stats-ringbuf]))]
        (reset! (:stats-stream state) stream)
        (log/info "Stats stream started")
        stream))))

(defn stop-stats-stream!
  "Stop streaming statistics events."
  []
  (with-lb-state [state]
    (when-let [stream @(:stats-stream state)]
      (stats/stop-event-stream stream)
      (reset! (:stats-stream state) nil)
      (log/info "Stats stream stopped"))))

(defn subscribe-to-stats
  "Subscribe to the stats stream. Returns a channel."
  []
  (with-lb-state [state]
    (when-let [stream @(:stats-stream state)]
      (stats/subscribe-to-stream stream))))

;;; =============================================================================
;;; Connection Management
;;; =============================================================================

(defn get-connections
  "Get all active connections."
  []
  (with-lb-state [state]
    (conntrack/get-all-connections (get-in state [:maps :conntrack-map]))))

(defn get-connection-count
  "Get the number of active connections."
  []
  (with-lb-state [state]
    (conntrack/count-connections (get-in state [:maps :conntrack-map]))))

(defn clear-connections!
  "Clear all tracked connections."
  []
  (with-lb-state [state]
    (conntrack/clear-all-connections! (get-in state [:maps :conntrack-map]))))

(defn get-connection-stats
  "Get aggregated connection statistics."
  []
  (with-lb-state [state]
    (conntrack/aggregate-stats (get-in state [:maps :conntrack-map]))))

;;; =============================================================================
;;; Status and Information
;;; =============================================================================

(defn get-status
  "Get current proxy status."
  []
  (if-let [state @proxy-state]
    {:running true
     :attached-interfaces (vec @(:attached-interfaces state))
     :stats-enabled (stats-enabled?)
     :stats-streaming (some? @(:stats-stream state))
     :health-check-enabled (get-in state [:config :settings :health-check-enabled])
     :health-checking (health/running?)
     :connection-count (get-connection-count)
     :proxies (count (get-in state [:config :proxies]))}
    {:running false}))

(defn print-status
  "Print current load balancer status."
  []
  (let [status (get-status)]
    (println "=== Load Balancer Status ===")
    (println (format "Running:             %s" (:running status)))
    (when (:running status)
      (println (format "Attached interfaces: %s" (clojure.string/join ", " (:attached-interfaces status))))
      (println (format "Stats enabled:       %s" (:stats-enabled status)))
      (println (format "Stats streaming:     %s" (:stats-streaming status)))
      (println (format "Health check enabled:%s" (:health-check-enabled status)))
      (println (format "Health checking:     %s" (:health-checking status)))
      (println (format "Active connections:  %d" (:connection-count status)))
      (println (format "Configured proxies:  %d" (:proxies status))))))

(defn print-config
  "Print current configuration."
  []
  (with-lb-state [state]
    (println (config/format-config (:config state)))))

(defn print-connections
  "Print active connections."
  []
  (with-lb-state [state]
    (conntrack/print-connections (get-in state [:maps :conntrack-map]))))

;;; =============================================================================
;;; Health Checking Integration
;;; =============================================================================

(defn- create-weight-update-fn
  "Create a callback function for weight updates.
   Updates BPF maps when target weights change due to health status."
  [listen-map proxy-cfg]
  (let [{:keys [listen]} proxy-cfg
        {:keys [interfaces port]} listen]
    (fn [new-target-group]
      (log/info "Updating weights for proxy" (:name proxy-cfg)
                "new cumulative weights:" (:cumulative-weights new-target-group))
      ;; Update listen map entries for all interfaces
      (doseq [iface interfaces]
        (when-let [ifindex (util/get-interface-index iface)]
          (maps/add-listen-port-weighted listen-map ifindex port
            new-target-group
            :flags 0))))))

(defn- create-drain-update-fn
  "Create a callback function for drain weight updates.
   Updates BPF maps when target weights change due to drain status."
  [ebpf-maps]
  (let [{:keys [listen-map]} ebpf-maps]
    (fn [proxy-name new-target-group]
      (with-lb-state [state]
        (when-let [proxy-cfg (config/get-proxy (:config state) proxy-name)]
          (let [{:keys [listen]} proxy-cfg
                {:keys [interfaces port]} listen]
            (log/info "Updating drain weights for proxy" proxy-name
                      "new cumulative weights:" (:cumulative-weights new-target-group))
            ;; Update listen map entries for all interfaces
            (doseq [iface interfaces]
              (when-let [ifindex (util/get-interface-index iface)]
                (maps/add-listen-port-weighted listen-map ifindex port
                  new-target-group
                  :flags 0)))))))))

(defn- register-health-checks!
  "Register all proxies for health checking."
  [ebpf-maps config]
  (when (get-in config [:settings :health-check-enabled])
    (log/info "Starting health checking system")
    (health/start!)
    (let [listen-map (:listen-map ebpf-maps)
          settings (:settings config)]
      (doseq [proxy-cfg (:proxies config)]
        (let [target-group (:default-target proxy-cfg)
              targets (:targets target-group)
              ;; Only register if at least one target has health check config
              has-health-checks? (some :health-check targets)]
          (when has-health-checks?
            (let [update-fn (create-weight-update-fn listen-map proxy-cfg)]
              (health/register-proxy! (:name proxy-cfg) target-group settings update-fn)
              (log/info "Registered proxy" (:name proxy-cfg) "for health checking"))))))))

(defn- unregister-health-checks!
  "Unregister all proxies from health checking and stop the system."
  [config]
  (when (get-in config [:settings :health-check-enabled])
    (doseq [proxy-cfg (:proxies config)]
      (health/unregister-proxy! (:name proxy-cfg)))
    (health/stop!)
    (log/info "Health checking system stopped")))

(defn get-health-status
  "Get health status for a specific proxy."
  [proxy-name]
  (health/get-status proxy-name))

(defn get-all-health-status
  "Get health status for all proxies."
  []
  (health/get-all-status))

(defn print-health-status
  "Print health status for all proxies."
  []
  (health/print-all-status))

(defn health-check-enabled?
  "Check if health checking is enabled."
  []
  (with-lb-state [state]
    (get-in state [:config :settings :health-check-enabled])))

;;; =============================================================================
;;; DNS Resolution
;;; =============================================================================

(defn- create-dns-update-fn
  "Create a callback function for DNS resolution updates.
   Updates BPF maps when resolved IPs change."
  [listen-map proxy-cfg]
  (let [{:keys [listen]} proxy-cfg
        {:keys [interfaces port]} listen]
    (fn [hostname new-target-group]
      (log/info "DNS resolution changed for proxy" (:name proxy-cfg)
                "hostname:" hostname
                "new targets:" (count (:targets new-target-group)))
      ;; Update listen map entries for all interfaces
      (doseq [iface interfaces]
        (when-let [ifindex (util/get-interface-index iface)]
          (maps/add-listen-port-weighted listen-map ifindex port
            new-target-group
            :flags 0))))))

(defn- register-dns-targets!
  "Register all DNS-backed targets for periodic resolution."
  [ebpf-maps config]
  (let [listen-map (:listen-map ebpf-maps)]
    (doseq [proxy-cfg (:proxies config)]
      (let [default-target (:default-target proxy-cfg)]
        ;; Check if default-target uses DNS
        (when (config/dns-target-group? default-target)
          (log/info "Registering DNS targets for proxy" (:name proxy-cfg))
          (let [dns-targets (:dns-targets default-target)
                update-fn (create-dns-update-fn listen-map proxy-cfg)]
            (doseq [dns-target dns-targets]
              (dns/register-target!
                (:name proxy-cfg)
                (:host dns-target)
                {:port (:port dns-target)
                 :weight (:weight dns-target)
                 :dns-refresh-seconds (:dns-refresh-seconds dns-target)
                 :health-check (:health-check dns-target)}
                update-fn))))))))

(defn- unregister-dns-targets!
  "Unregister all DNS targets and stop resolution."
  [config]
  (doseq [proxy-cfg (:proxies config)]
    (dns/unregister-proxy! (:name proxy-cfg))))

(defn get-dns-status
  "Get DNS resolution status for a specific proxy."
  [proxy-name]
  (dns/get-status proxy-name))

(defn get-all-dns-status
  "Get DNS resolution status for all proxies."
  []
  (dns/get-all-status))

(defn force-dns-resolve!
  "Force immediate DNS re-resolution for a hostname."
  [proxy-name hostname]
  (dns/force-resolve! proxy-name hostname))

;;; =============================================================================
;;; Connection Draining
;;; =============================================================================

(defn drain-backend!
  "Start draining a backend. Stops new connections while existing ones complete.

   proxy-name: Name of the proxy (e.g., \"web\")
   target: Target specification - \"ip:port\" string or {:ip :port} map

   Options:
     :timeout-ms - Drain timeout in ms (default from config or 30000)
     :on-complete - Callback fn called with status (:completed, :timeout, :cancelled)

   Returns DrainState or throws if target not found/already draining."
  [proxy-name target & {:keys [timeout-ms on-complete]}]
  (with-lb-state [state]
    (when-let [proxy-cfg (config/get-proxy (:config state) proxy-name)]
      (let [target-group (:default-target proxy-cfg)
            default-timeout (get-in state [:config :settings :default-drain-timeout-ms] 30000)
            actual-timeout (or timeout-ms default-timeout)]
        (drain/drain-backend! proxy-name target-group target
                              :timeout-ms actual-timeout
                              :on-complete on-complete)))))

(defn undrain-backend!
  "Cancel draining and restore traffic to a backend.

   proxy-name: Name of the proxy
   target: Target specification - \"ip:port\" string or {:ip :port} map

   Returns true if undrain succeeded, false if target wasn't draining."
  [proxy-name target]
  (with-lb-state [state]
    (when-let [proxy-cfg (config/get-proxy (:config state) proxy-name)]
      (let [target-group (:default-target proxy-cfg)]
        (drain/undrain-backend! proxy-name target-group target)))))

(defn get-drain-status
  "Get drain status for a backend.

   target: Target specification - \"ip:port\" string or {:ip :port} map

   Returns map with :target-id :status :elapsed-ms :current-connections
   or nil if not draining."
  [target]
  (drain/get-drain-status target))

(defn get-all-draining
  "Get all currently draining backends.

   Returns seq of drain status maps."
  []
  (drain/get-all-draining))

(defn wait-for-drain!
  "Block until drain completes or times out.

   target: Target specification - \"ip:port\" string or {:ip :port} map

   Returns :completed, :timeout, or :cancelled."
  [target]
  (drain/wait-for-drain! target))

(defn draining?
  "Check if a target is currently draining."
  [target]
  (drain/draining? target))

(defn print-drain-status
  "Print all draining backends."
  []
  (drain/print-drain-status))

;;; =============================================================================
;;; Rate Limiting
;;; =============================================================================

(defn set-source-rate-limit!
  "Set per-source IP rate limit.

   rate: requests per second allowed from each source IP
   burst: maximum burst size (defaults to 2x rate)

   Returns true if successful."
  [rate & {:keys [burst]}]
  (if burst
    (rate-limit/set-source-rate-limit! rate :burst burst)
    (rate-limit/set-source-rate-limit! rate)))

(defn set-backend-rate-limit!
  "Set per-backend rate limit.

   rate: requests per second allowed to each backend
   burst: maximum burst size (defaults to 2x rate)

   Returns true if successful."
  [rate & {:keys [burst]}]
  (if burst
    (rate-limit/set-backend-rate-limit! rate :burst burst)
    (rate-limit/set-backend-rate-limit! rate)))

(defn disable-source-rate-limit!
  "Disable per-source rate limiting."
  []
  (rate-limit/disable-source-rate-limit!))

(defn disable-backend-rate-limit!
  "Disable per-backend rate limiting."
  []
  (rate-limit/disable-backend-rate-limit!))

(defn clear-rate-limits!
  "Disable all rate limiting."
  []
  (rate-limit/clear-rate-limits!))

(defn get-rate-limit-config
  "Get all rate limit configuration.
   Returns {:per-source {...} :per-backend {...}} or nils for disabled limits."
  []
  (rate-limit/get-rate-limit-config))

(defn rate-limiting-enabled?
  "Check if any rate limiting is enabled."
  []
  (rate-limit/rate-limiting-enabled?))

(defn print-rate-limit-status
  "Print current rate limit status."
  []
  (rate-limit/print-rate-limit-status))

;;; =============================================================================
;;; Hot Reload
;;; =============================================================================

(defn- register-reload-functions!
  "Register functions with the reload module for applying config changes.
   Called during initialization."
  []
  (reload/register-apply-fns!
    {:get-state get-state
     :add-proxy! add-proxy!
     :remove-proxy! remove-proxy!
     :add-source-route! (fn [proxy-name source prefix-len target-group]
                          ;; Adapter for add-source-route! that takes pre-parsed args
                          (let [source-str (util/cidr->string {:ip source :prefix-len prefix-len})]
                            (add-source-route! proxy-name {:source source-str
                                                           :target (config/target-group->map target-group)})))
     :remove-source-route! (fn [proxy-name source prefix-len]
                             (remove-source-route! proxy-name source prefix-len))
     :add-sni-route! (fn [proxy-name route]
                       (add-sni-route! proxy-name (config/sni-route->map route)))
     :remove-sni-route! remove-sni-route!
     :enable-stats! enable-stats!
     :disable-stats! disable-stats!
     :update-proxy-state! (fn [f & args]
                            (apply swap! proxy-state f args))}))

(defn reload-config!
  "Reload configuration from file or provided source.

   Without arguments, reloads from the last known config path (if hot reload is enabled).
   With a path argument, loads and applies that configuration file.

   Returns {:success? bool :changes {...} :error ...}"
  ([] (reload/reload-config!))
  ([config-path] (reload/reload-config! config-path)))

(defn reload-config-from-map!
  "Reload configuration from an in-memory config map.
   Useful for programmatic config changes.

   Returns {:success? bool :changes {...} :error ...}"
  [config-map]
  (reload/reload-config-from-map! config-map))

(defn enable-hot-reload!
  "Enable hot configuration reload for the specified config file.

   Options:
     :watch-file? - Enable file watching (default true)
     :sighup? - Enable SIGHUP handling (default true)
     :debounce-ms - File change debounce period (default 500ms)

   Returns true if enabled successfully."
  [config-path & opts]
  (apply reload/enable-hot-reload! config-path opts))

(defn disable-hot-reload!
  "Disable hot configuration reload."
  []
  (reload/disable-hot-reload!))

(defn hot-reload-enabled?
  "Check if hot reload is currently enabled."
  []
  (reload/hot-reload-enabled?))

(defn get-reload-state
  "Get current reload state for debugging."
  []
  (reload/get-reload-state))

;;; =============================================================================
;;; CLI
;;; =============================================================================

(def cli-options
  [["-c" "--config FILE" "Configuration file path"
    :default "config.edn"]
   ["-i" "--interface IFACE" "Network interface to attach to"
    :multi true
    :default []
    :update-fn conj]
   ["-p" "--port PORT" "Listen port"
    :parse-fn #(Integer/parseInt %)
    :default 80]
   ["-t" "--target TARGET" "Default target (ip:port)"
    :default "127.0.0.1:8080"]
   ["-s" "--stats" "Enable statistics collection"]
   ["-v" "--verbose" "Verbose output"]
   ["-h" "--help" "Show help"]])

(defn usage [options-summary]
  (->> ["eBPF Load Balancer"
        ""
        "Usage: clj-ebpf-lb [options]"
        ""
        "Options:"
        options-summary
        ""
        "Examples:"
        "  clj-ebpf-lb -c lb.edn"
        "  clj-ebpf-lb -i eth0 -p 80 -t 10.0.0.1:8080"
        ""]
       (clojure.string/join \newline)))

(defn error-msg [errors]
  (str "The following errors occurred:\n\n"
       (clojure.string/join \newline errors)))

(defn validate-args [args]
  (let [{:keys [options arguments errors summary]} (parse-opts args cli-options)]
    (cond
      (:help options)
      {:exit-message (usage summary) :ok? true}

      errors
      {:exit-message (error-msg errors)}

      :else
      {:options options})))

(defn -main
  "Main entry point."
  [& args]
  (let [{:keys [options exit-message ok?]} (validate-args args)]
    (if exit-message
      (do
        (println exit-message)
        (System/exit (if ok? 0 1)))

      (try
        ;; Load or create configuration
        (let [config (if (.exists (java.io.File. (:config options)))
                       (config/load-config-file (:config options))
                       (let [[target-ip target-port] (clojure.string/split (:target options) #":")
                             interfaces (if (seq (:interface options))
                                          (:interface options)
                                          ["eth0"])]
                         (config/make-simple-config
                           {:interface (first interfaces)
                            :port (:port options)
                            :target-ip target-ip
                            :target-port (Integer/parseInt target-port)
                            :stats-enabled (:stats options)})))]

          ;; Initialize proxy
          (init! config)

          ;; Wait for shutdown signal
          (println "Load balancer running. Press Ctrl+C to stop.")
          (.addShutdownHook (Runtime/getRuntime)
            (Thread. #(do
                        (println "\nShutting down...")
                        (shutdown!))))

          ;; Block forever
          @(promise))

        (catch Exception e
          (log/error e "Failed to start load balancer")
          (println "Error:" (.getMessage e))
          (System/exit 1))))))
