(ns lb.dns.manager
  "Background daemon for periodic DNS re-resolution.

   Follows the same pattern as lb.health.manager:
   - ScheduledExecutorService for periodic tasks
   - Jitter to avoid thundering herd
   - Callbacks to update BPF maps on IP changes
   - Last-known-good fallback on failures"
  (:require [lb.dns.resolver :as resolver]
            [lb.util :as util]
            [lb.config :as config]
            [clojure.tools.logging :as log])
  (:import [java.util.concurrent Executors ScheduledExecutorService ScheduledFuture TimeUnit]
           [java.util.concurrent.locks ReentrantLock]))

;;; =============================================================================
;;; State Management
;;; =============================================================================

(defonce ^:private manager-state
  (atom {:running? false
         :executor nil              ; ScheduledExecutorService
         :proxies {}                ; Map proxy-name -> ProxyDNSState
         :subscribers []}))         ; Event subscribers

(defonce ^:private state-lock (ReentrantLock.))

(defmacro ^:private with-lock
  "Execute body while holding the state lock."
  [& body]
  `(let [lock# state-lock]
     (.lock lock#)
     (try
       ~@body
       (finally
         (.unlock lock#)))))

;;; =============================================================================
;;; DNS Target State
;;; =============================================================================

(defrecord DNSTargetState
  [hostname              ; Original hostname
   port                  ; Target port
   weight                ; Original weight (before distribution)
   dns-refresh-ms        ; Refresh interval in milliseconds
   health-check          ; Health check config (or nil)
   last-resolved-ips     ; Vector of u32 IPs from last successful resolution
   last-resolved-at      ; Timestamp of last successful resolution
   consecutive-failures  ; Count of consecutive failures
   scheduled-task])      ; ScheduledFuture for periodic refresh

(defrecord ProxyDNSState
  [proxy-name
   dns-targets           ; Map hostname -> DNSTargetState
   update-callback])     ; Function to call when IPs change

;;; =============================================================================
;;; Event System
;;; =============================================================================

(defn- emit-event!
  "Emit an event to all subscribers."
  [event-type proxy-name hostname data]
  (let [event {:type event-type
               :proxy-name proxy-name
               :hostname hostname
               :timestamp (System/currentTimeMillis)
               :data data}]
    (doseq [subscriber (:subscribers @manager-state)]
      (try
        (subscriber event)
        (catch Exception e
          (log/warn e "Error in DNS event subscriber"))))))

;;; =============================================================================
;;; Resolution Logic
;;; =============================================================================

(defn- build-target-group
  "Build a TargetGroup from resolved IPs."
  [dns-target resolved-ips]
  (let [{:keys [port weight health-check proxy-protocol]} dns-target
        target-maps (resolver/expand-to-weighted-targets
                      resolved-ips port weight health-check)
        ;; Convert to WeightedTarget records
        targets (mapv (fn [{:keys [ip port weight health-check]}]
                        (config/->WeightedTarget ip port weight
                          (when health-check
                            (config/parse-health-check-config health-check nil))
                          proxy-protocol))
                      target-maps)
        cumulative (config/compute-cumulative-weights targets)]
    (config/->TargetGroup targets cumulative)))

(defn- run-dns-resolution!
  "Run DNS resolution for a single hostname and update state if IPs changed."
  [proxy-name hostname]
  (when (:running? @manager-state)
    (let [proxy-state (get-in @manager-state [:proxies proxy-name])
          dns-target (get-in proxy-state [:dns-targets hostname])]
      (when dns-target
        (let [result (resolver/resolve-hostname-all hostname 5000)]
          (if (:success? result)
            ;; Successful resolution
            (let [new-ips (:ips result)
                  old-ips (:last-resolved-ips dns-target)
                  ips-changed? (resolver/ips-changed? old-ips new-ips)]
              ;; Update state
              (with-lock
                (swap! manager-state update-in [:proxies proxy-name :dns-targets hostname]
                       assoc
                       :last-resolved-ips new-ips
                       :last-resolved-at (System/currentTimeMillis)
                       :consecutive-failures 0))
              ;; Notify if IPs changed
              (when ips-changed?
                (log/info "DNS resolution changed for" hostname
                          "in proxy" proxy-name ":"
                          (resolver/format-ips old-ips) "->"
                          (resolver/format-ips new-ips))
                (emit-event! :dns-resolved proxy-name hostname
                             {:old-ips old-ips :new-ips new-ips})
                ;; Call update callback with new TargetGroup
                (when-let [callback (:update-callback proxy-state)]
                  (try
                    (let [target-group (build-target-group dns-target new-ips)]
                      (callback hostname target-group))
                    (catch Exception e
                      (log/error e "Error in DNS update callback for"
                                 hostname "in proxy" proxy-name))))))
            ;; Failed resolution
            (let [failures (inc (:consecutive-failures dns-target))]
              (log/warn "DNS resolution failed for" hostname
                        "(" (:error-type result) "):"
                        (:message result)
                        "- consecutive failures:" failures)
              (with-lock
                (swap! manager-state update-in [:proxies proxy-name :dns-targets hostname]
                       assoc :consecutive-failures failures))
              (emit-event! :dns-failed proxy-name hostname
                           {:error-type (:error-type result)
                            :message (:message result)
                            :consecutive-failures failures
                            :using-cached (some? (:last-resolved-ips dns-target))}))))))))

;;; =============================================================================
;;; Scheduler Management
;;; =============================================================================

(defn- schedule-dns-refresh!
  "Schedule periodic DNS refresh for a hostname."
  [^ScheduledExecutorService executor proxy-name hostname interval-ms initial-delay-ms]
  (when (and executor (not (.isShutdown executor)))
    (.scheduleAtFixedRate
      executor
      (fn []
        (try
          (run-dns-resolution! proxy-name hostname)
          (catch Exception e
            (log/error e "Error running DNS resolution for" hostname))))
      initial-delay-ms
      interval-ms
      TimeUnit/MILLISECONDS)))

(defn- compute-jittered-delay
  "Compute initial delay with jitter to avoid thundering herd."
  [index total interval-ms]
  (let [base-delay (/ (* index interval-ms) total)
        jitter (* interval-ms 0.1 (- (rand) 0.5))]
    (long (max 0 (+ base-delay jitter)))))

;;; =============================================================================
;;; Public API - Lifecycle
;;; =============================================================================

(defn start!
  "Start the DNS resolution manager."
  []
  (with-lock
    (when-not (:running? @manager-state)
      (log/info "Starting DNS resolution manager")
      (let [executor (Executors/newSingleThreadScheduledExecutor)]
        (swap! manager-state assoc
               :running? true
               :executor executor))
      (log/info "DNS resolution manager started"))))

(defn stop!
  "Stop the DNS resolution manager."
  []
  (with-lock
    (when (:running? @manager-state)
      (log/info "Stopping DNS resolution manager")
      (when-let [^ScheduledExecutorService executor (:executor @manager-state)]
        (.shutdownNow executor)
        (try
          (.awaitTermination executor 2 TimeUnit/SECONDS)
          (catch InterruptedException _)))
      (swap! manager-state assoc
             :running? false
             :executor nil
             :proxies {})
      (log/info "DNS resolution manager stopped"))))

(defn running?
  "Check if the DNS manager is running."
  []
  (:running? @manager-state))

;;; =============================================================================
;;; Public API - Registration
;;; =============================================================================

(defn register-dns-target!
  "Register a DNS-backed target for periodic resolution.

   Parameters:
     proxy-name - Name of the proxy this target belongs to
     hostname - DNS hostname to resolve
     config - Map with:
       :port - Target port
       :weight - Weight for this target (1-100)
       :dns-refresh-seconds - Refresh interval (default 30)
       :health-check - Optional health check config
     update-callback - Function called with (hostname target-group) when IPs change

   Returns true if registered successfully.

   Note: Performs initial resolution synchronously. If initial resolution fails,
   throws an exception (startup failure)."
  [proxy-name hostname config update-callback]
  (with-lock
    (when-not (:running? @manager-state)
      (throw (ex-info "DNS manager not running" {})))

    (log/info "Registering DNS target" hostname "for proxy" proxy-name)

    ;; Perform initial resolution (must succeed at startup)
    (let [result (resolver/resolve-hostname-all hostname 5000)]
      (when-not (:success? result)
        (throw (ex-info (str "Failed to resolve DNS target at startup: " hostname)
                        {:hostname hostname
                         :error-type (:error-type result)
                         :message (:message result)})))

      (let [resolved-ips (:ips result)
            dns-refresh-ms (* 1000 (or (:dns-refresh-seconds config) 30))
            dns-target (->DNSTargetState
                         hostname
                         (:port config)
                         (or (:weight config) 100)
                         dns-refresh-ms
                         (:health-check config)
                         resolved-ips
                         (System/currentTimeMillis)
                         0    ; consecutive-failures
                         nil) ; scheduled-task (set below)
            executor (:executor @manager-state)]

        ;; Ensure proxy state exists
        (when-not (get-in @manager-state [:proxies proxy-name])
          (swap! manager-state assoc-in [:proxies proxy-name]
                 (->ProxyDNSState proxy-name {} update-callback)))

        ;; Add DNS target
        (swap! manager-state assoc-in [:proxies proxy-name :dns-targets hostname]
               dns-target)

        ;; Schedule periodic refresh with jitter
        (let [all-targets (get-in @manager-state [:proxies proxy-name :dns-targets])
              index (count all-targets)
              total (inc index)
              initial-delay (compute-jittered-delay index total dns-refresh-ms)
              task (schedule-dns-refresh! executor proxy-name hostname
                                          dns-refresh-ms initial-delay)]
          (swap! manager-state assoc-in [:proxies proxy-name :dns-targets hostname :scheduled-task]
                 task))

        (log/info "Registered DNS target" hostname "with" (count resolved-ips) "IPs:"
                  (resolver/format-ips resolved-ips))

        ;; Call initial callback with resolved target group
        (when update-callback
          (try
            (let [target-group (build-target-group dns-target resolved-ips)]
              (update-callback hostname target-group))
            (catch Exception e
              (log/error e "Error in initial DNS callback for" hostname))))

        true))))

(defn unregister-dns-target!
  "Unregister a DNS target and stop its refresh task."
  [proxy-name hostname]
  (with-lock
    (when-let [dns-target (get-in @manager-state [:proxies proxy-name :dns-targets hostname])]
      (log/info "Unregistering DNS target" hostname "from proxy" proxy-name)
      ;; Cancel scheduled task
      (when-let [^ScheduledFuture task (:scheduled-task dns-target)]
        (.cancel task false))
      ;; Remove from state
      (swap! manager-state update-in [:proxies proxy-name :dns-targets]
             dissoc hostname)
      ;; Clean up empty proxy
      (when (empty? (get-in @manager-state [:proxies proxy-name :dns-targets]))
        (swap! manager-state update :proxies dissoc proxy-name))
      true)))

(defn unregister-proxy!
  "Unregister all DNS targets for a proxy."
  [proxy-name]
  (with-lock
    (when-let [proxy-state (get-in @manager-state [:proxies proxy-name])]
      (log/info "Unregistering all DNS targets for proxy" proxy-name)
      ;; Cancel all scheduled tasks
      (doseq [[_ dns-target] (:dns-targets proxy-state)]
        (when-let [^ScheduledFuture task (:scheduled-task dns-target)]
          (.cancel task false)))
      ;; Remove proxy
      (swap! manager-state update :proxies dissoc proxy-name)
      true)))

;;; =============================================================================
;;; Public API - Status
;;; =============================================================================

(defn get-dns-status
  "Get DNS resolution status for a proxy."
  [proxy-name]
  (when-let [proxy-state (get-in @manager-state [:proxies proxy-name])]
    {:proxy-name proxy-name
     :targets (into {}
                    (map (fn [[hostname state]]
                           [hostname {:hostname hostname
                                      :port (:port state)
                                      :weight (:weight state)
                                      :refresh-ms (:dns-refresh-ms state)
                                      :last-ips (mapv util/u32->ip-string
                                                      (:last-resolved-ips state))
                                      :last-resolved-at (:last-resolved-at state)
                                      :consecutive-failures (:consecutive-failures state)}])
                         (:dns-targets proxy-state)))}))

(defn get-all-dns-status
  "Get DNS resolution status for all proxies."
  []
  (into {}
        (map (fn [[proxy-name _]]
               [proxy-name (get-dns-status proxy-name)])
             (:proxies @manager-state))))

(defn force-resolve!
  "Force immediate DNS re-resolution for a hostname."
  [proxy-name hostname]
  (when (get-in @manager-state [:proxies proxy-name :dns-targets hostname])
    (log/info "Forcing DNS resolution for" hostname "in proxy" proxy-name)
    (run-dns-resolution! proxy-name hostname)
    true))

;;; =============================================================================
;;; Public API - Subscriptions
;;; =============================================================================

(defn subscribe!
  "Subscribe to DNS events.

   Callback receives events with keys:
     :type - :dns-resolved or :dns-failed
     :proxy-name - Proxy name
     :hostname - Hostname that was resolved
     :timestamp - Event timestamp
     :data - Event-specific data

   Returns unsubscribe function."
  [callback]
  (swap! manager-state update :subscribers conj callback)
  (fn []
    (swap! manager-state update :subscribers
           (fn [subs] (vec (remove #(= % callback) subs))))))
