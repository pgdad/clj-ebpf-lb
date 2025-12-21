(ns lb.lb-manager
  "Background manager for least-connections load balancing.
   Periodically scans connection tracking to compute and update weights
   based on the current connection distribution across backends."
  (:require [clojure.tools.logging :as log]
            [lb.lb-algorithm :as algo]
            [lb.conntrack :as conntrack]
            [lb.config :as config]
            [lb.health.weights :as weights]
            [lb.util :as util])
  (:import [java.util.concurrent Executors ScheduledExecutorService TimeUnit]))

;;; =============================================================================
;;; State
;;; =============================================================================

(defonce manager-state
  (atom {:running? false
         :executor nil
         :config nil           ; LoadBalancingConfig record
         :conntrack-map nil    ; BPF conntrack map reference
         :proxies {}           ; proxy-name -> ProxyState map
         :last-update nil}))   ; Timestamp of last update cycle

;; ProxyState structure:
;; {:proxy-name "name"
;;  :target-group TargetGroup
;;  :interfaces ["eth0"]
;;  :port 8080
;;  :listen-map <bpf-map>
;;  :get-health-fn (fn [] [true true ...])
;;  :get-drain-fn (fn [] [false false ...])
;;  :get-cb-fn (fn [] [:closed :closed ...])}

;;; =============================================================================
;;; Weight Update Logic
;;; =============================================================================

(defn- get-target-ips
  "Extract IP strings from a target group."
  [target-group]
  (mapv #(util/u32->ip-string (:ip %)) (:targets target-group)))

(defn- get-connection-counts
  "Get connection counts for each target in a target group.
   Returns vector of counts in same order as targets."
  [conn-counts-map target-group]
  (let [target-ips (get-target-ips target-group)]
    (mapv #(get conn-counts-map % 0) target-ips)))

(defn- compute-new-weights
  "Compute new weights for a proxy based on connection counts and other states."
  [{:keys [target-group get-health-fn get-drain-fn get-cb-fn]} conn-counts-map lb-config]
  (let [targets (:targets target-group)
        original-weights (mapv :weight targets)
        target-conn-counts (get-connection-counts conn-counts-map target-group)
        ;; Get current health/drain/cb states from callbacks
        health-statuses (if get-health-fn
                          (get-health-fn)
                          (vec (repeat (count targets) true)))
        drain-statuses (if get-drain-fn
                         (get-drain-fn)
                         (vec (repeat (count targets) false)))
        cb-states (if get-cb-fn
                    (get-cb-fn)
                    (vec (repeat (count targets) :closed)))]
    ;; Compute effective weights using the algorithm
    (algo/compute-effective-weights
      (:algorithm lb-config)
      original-weights
      target-conn-counts
      health-statuses
      drain-statuses
      cb-states
      (:weighted lb-config))))

(defn- update-proxy-weights!
  "Update BPF map weights for a single proxy."
  [{:keys [proxy-name target-group interfaces port listen-map] :as proxy-state}
   conn-counts-map lb-config]
  (try
    (let [new-effective-weights (compute-new-weights proxy-state conn-counts-map lb-config)
          current-cumulative (:cumulative-weights target-group)
          new-cumulative (weights/weights->cumulative new-effective-weights)]
      ;; Only update if weights have changed
      (when (algo/weights-differ? current-cumulative new-cumulative)
        (log/debug "LB Manager updating weights for proxy" proxy-name
                   ":" (algo/format-weight-change
                         (get-target-ips target-group)
                         (weights/weights->cumulative (mapv :weight (:targets target-group)))
                         new-cumulative))
        ;; Create new target group with updated weights
        (let [new-target-group (-> target-group
                                   (assoc :cumulative-weights new-cumulative)
                                   (assoc :effective-weights new-effective-weights))]
          ;; Update BPF map for all interfaces
          (doseq [iface interfaces]
            (when-let [ifindex (util/get-interface-index iface)]
              ;; Import maps namespace dynamically to avoid circular deps
              (require '[lb.maps :as maps])
              ((resolve 'lb.maps/add-listen-port-weighted)
               listen-map ifindex port new-target-group :flags 0)))
          ;; Update stored target group state
          (swap! manager-state update-in [:proxies proxy-name]
                 assoc :target-group new-target-group)
          true)))
    (catch Exception e
      (log/error e "Failed to update weights for proxy" proxy-name)
      false)))

;;; =============================================================================
;;; Background Update Cycle
;;; =============================================================================

(defn- run-update-cycle!
  "Run a single update cycle for all registered proxies."
  []
  (try
    (let [{:keys [conntrack-map config proxies]} @manager-state]
      (when (and conntrack-map (seq proxies))
        ;; Get current connection counts from conntrack
        (let [conntrack-stats (conntrack/stats-by-target conntrack-map)
              conn-counts-map (algo/count-connections-by-backend conntrack-stats)]
          ;; Update each proxy
          (doseq [[_ proxy-state] proxies]
            (update-proxy-weights! proxy-state conn-counts-map config)))
        ;; Record update time
        (swap! manager-state assoc :last-update (System/currentTimeMillis))))
    (catch Exception e
      (log/error e "Error in LB manager update cycle"))))

;;; =============================================================================
;;; Proxy Registration
;;; =============================================================================

(defn register-proxy!
  "Register a proxy for least-connections weight management.

   proxy-name: Unique identifier for the proxy
   target-group: TargetGroup record
   interfaces: Vector of interface names to update
   port: Listen port
   listen-map: BPF listen map reference
   opts: Optional callbacks for integration:
         :get-health-fn - Returns vector of health booleans
         :get-drain-fn - Returns vector of drain booleans
         :get-cb-fn - Returns vector of circuit breaker states"
  [proxy-name target-group interfaces port listen-map & {:keys [get-health-fn get-drain-fn get-cb-fn]}]
  (log/info "LB Manager registering proxy" proxy-name
            "with" (count (:targets target-group)) "targets")
  (swap! manager-state assoc-in [:proxies proxy-name]
         {:proxy-name proxy-name
          :target-group target-group
          :interfaces interfaces
          :port port
          :listen-map listen-map
          :get-health-fn get-health-fn
          :get-drain-fn get-drain-fn
          :get-cb-fn get-cb-fn}))

(defn unregister-proxy!
  "Unregister a proxy from least-connections weight management."
  [proxy-name]
  (log/info "LB Manager unregistering proxy" proxy-name)
  (swap! manager-state update :proxies dissoc proxy-name))

(defn update-proxy-target-group!
  "Update the target group for a registered proxy.
   Used when targets change due to DNS resolution etc."
  [proxy-name new-target-group]
  (when (get-in @manager-state [:proxies proxy-name])
    (swap! manager-state assoc-in [:proxies proxy-name :target-group] new-target-group)))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start the LB manager background daemon.

   conntrack-map: BPF conntrack map for connection counting
   lb-config: LoadBalancingConfig record with algorithm settings"
  [conntrack-map lb-config]
  (when (= :least-connections (:algorithm lb-config))
    (log/info "Starting LB manager with least-connections algorithm"
              "update-interval:" (:update-interval-ms lb-config) "ms"
              "weighted:" (:weighted lb-config))
    (let [executor (Executors/newSingleThreadScheduledExecutor
                     (reify java.util.concurrent.ThreadFactory
                       (newThread [_ r]
                         (doto (Thread. r "lb-manager")
                           (.setDaemon true)))))]
      (swap! manager-state assoc
             :running? true
             :executor executor
             :config lb-config
             :conntrack-map conntrack-map)
      ;; Schedule periodic updates
      (.scheduleAtFixedRate executor
                            #(run-update-cycle!)
                            (:update-interval-ms lb-config)
                            (:update-interval-ms lb-config)
                            TimeUnit/MILLISECONDS)
      true)))

(defn stop!
  "Stop the LB manager background daemon."
  []
  (when-let [^ScheduledExecutorService executor (:executor @manager-state)]
    (log/info "Stopping LB manager")
    (.shutdown executor)
    (try
      (.awaitTermination executor 5 TimeUnit/SECONDS)
      (catch InterruptedException _
        (.shutdownNow executor))))
  (swap! manager-state assoc
         :running? false
         :executor nil
         :conntrack-map nil
         :proxies {}
         :last-update nil))

(defn running?
  "Check if the LB manager is running."
  []
  (:running? @manager-state))

;;; =============================================================================
;;; Status & Info
;;; =============================================================================

(defn get-algorithm
  "Get the current load balancing algorithm."
  []
  (if (:running? @manager-state)
    (get-in @manager-state [:config :algorithm] :weighted-random)
    :weighted-random))

(defn get-status
  "Get current LB manager status."
  []
  (let [{:keys [running? config proxies last-update]} @manager-state]
    {:running? running?
     :algorithm (if running?
                  (or (:algorithm config) :weighted-random)
                  :weighted-random)
     :weighted (get config :weighted true)
     :update-interval-ms (get config :update-interval-ms 1000)
     :registered-proxies (count proxies)
     :proxy-names (keys proxies)
     :last-update last-update}))

(defn get-proxy-info
  "Get current info for a specific proxy."
  [proxy-name]
  (when-let [proxy-state (get-in @manager-state [:proxies proxy-name])]
    (let [{:keys [target-group]} proxy-state]
      {:proxy-name proxy-name
       :targets (mapv (fn [t]
                        {:ip (util/u32->ip-string (:ip t))
                         :port (:port t)
                         :configured-weight (:weight t)
                         :effective-weight (:effective-weight t)})
                      (:targets target-group))
       :cumulative-weights (:cumulative-weights target-group)
       :effective-weights (:effective-weights target-group)})))

(defn force-update!
  "Force an immediate weight update cycle."
  []
  (when (:running? @manager-state)
    (run-update-cycle!)
    true))

;;; =============================================================================
;;; Connection Stats (for Prometheus metrics)
;;; =============================================================================

(defn get-connection-counts
  "Get current connection counts per backend for metrics.
   Returns map of {proxy-name {ip-port connection-count}}."
  []
  (let [{:keys [conntrack-map proxies]} @manager-state]
    (when conntrack-map
      (let [conntrack-stats (conntrack/stats-by-target conntrack-map)
            conn-counts-map (algo/count-connections-by-backend conntrack-stats)]
        (into {}
              (map (fn [[proxy-name {:keys [target-group]}]]
                     [proxy-name
                      (into {}
                            (map (fn [target]
                                   (let [ip (util/u32->ip-string (:ip target))
                                         port (:port target)]
                                     [(str ip ":" port) (get conn-counts-map ip 0)]))
                                 (:targets target-group)))])
                   proxies))))))
