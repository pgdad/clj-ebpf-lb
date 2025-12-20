(ns reverse-proxy.health
  "Public API for health checking system.
   Provides a simple interface for managing health-aware load balancing."
  (:require [reverse-proxy.health.manager :as manager]
            [reverse-proxy.health.checker :as checker]
            [reverse-proxy.health.weights :as weights]
            [reverse-proxy.config :as config]
            [reverse-proxy.util :as util]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Lifecycle Management
;;; =============================================================================

(defn start!
  "Start the health checking system.
   Must be called before registering proxies for health monitoring."
  []
  (manager/start!))

(defn stop!
  "Stop the health checking system.
   Stops all health checks and clears registered proxies."
  []
  (manager/stop!))

(defn running?
  "Check if the health checking system is running."
  []
  (manager/running?))

;;; =============================================================================
;;; Proxy Registration
;;; =============================================================================

(defn register-proxy!
  "Register a proxy for health checking.

   Arguments:
     proxy-name: Unique name for the proxy
     target-group: TargetGroup containing targets to monitor
     settings: Settings record with health-check-defaults
     update-fn: Function called when weights change (receives new TargetGroup)

   The update-fn is called with a new TargetGroup that has updated
   cumulative-weights based on target health. Use this to update BPF maps."
  [proxy-name target-group settings update-fn]
  (let [default-config (or (:health-check-defaults settings)
                           config/default-health-check-config)
        ;; Wrap the update-fn to create TargetGroup with new weights
        callback (fn [new-weights]
                   (let [targets (:targets target-group)
                         updated-targets (mapv (fn [t w]
                                                 (assoc t :effective-weight w))
                                               targets new-weights)
                         cumulative (weights/weights->cumulative new-weights)
                         new-group (assoc target-group
                                          :targets updated-targets
                                          :cumulative-weights cumulative
                                          :effective-weights new-weights)]
                     (update-fn new-group)))]
    (manager/register-proxy! proxy-name target-group default-config callback)))

(defn unregister-proxy!
  "Unregister a proxy from health checking."
  [proxy-name]
  (manager/unregister-proxy! proxy-name))

;;; =============================================================================
;;; Health Status Queries
;;; =============================================================================

(defn get-status
  "Get health status for a specific proxy.

   Returns:
     {:proxy-name \"name\"
      :targets [{:target-id \"ip:port\"
                 :ip \"10.0.0.1\"
                 :port 8080
                 :status :healthy/:unhealthy/:unknown
                 :consecutive-successes 3
                 :consecutive-failures 0
                 :last-check-time 1234567890
                 :last-latency-ms 5.2
                 :last-error nil}]
      :original-weights [50 30 20]
      :effective-weights [71 0 29]
      :last-update-time 1234567890}"
  [proxy-name]
  (manager/get-proxy-health proxy-name))

(defn get-all-status
  "Get health status for all registered proxies."
  []
  (manager/get-all-health))

(defn healthy?
  "Check if a specific target is healthy."
  [proxy-name target-id]
  (when-let [status (get-status proxy-name)]
    (some #(and (= (:target-id %) target-id)
                (= :healthy (:status %)))
          (:targets status))))

(defn all-healthy?
  "Check if all targets for a proxy are healthy."
  [proxy-name]
  (when-let [status (get-status proxy-name)]
    (every? #(= :healthy (:status %)) (:targets status))))

(defn unhealthy-targets
  "Get list of unhealthy targets for a proxy."
  [proxy-name]
  (when-let [status (get-status proxy-name)]
    (filter #(= :unhealthy (:status %)) (:targets status))))

;;; =============================================================================
;;; Event Subscription
;;; =============================================================================

(defn subscribe!
  "Subscribe to health events.

   Callback receives HealthEvent maps:
     {:type :target-healthy/:target-unhealthy/:weights-updated
      :proxy-name \"name\"
      :target-id \"ip:port\" (nil for :weights-updated)
      :timestamp epoch-ms
      :details {...}}

   Returns an unsubscribe function."
  [callback]
  (manager/subscribe! callback))

;;; =============================================================================
;;; Manual Control
;;; =============================================================================

(defn set-target-status!
  "Manually set a target's health status.
   Useful for maintenance windows or testing.

   status should be :healthy, :unhealthy, or :unknown"
  [proxy-name target-id status]
  (manager/set-target-status! proxy-name target-id status))

(defn force-check!
  "Force an immediate health check for a target.
   The check runs asynchronously."
  [proxy-name target-id]
  (manager/force-check! proxy-name target-id))

;;; =============================================================================
;;; Direct Health Checks (for testing/debugging)
;;; =============================================================================

(defn check-tcp
  "Perform a one-off TCP health check.
   Returns CheckResult with :success?, :latency-ms, :error, :message."
  [ip port timeout-ms]
  (checker/check-tcp ip port timeout-ms))

(defn check-http
  "Perform a one-off HTTP health check.
   Returns CheckResult with :success?, :latency-ms, :error, :message."
  ([ip port path] (check-http ip port path 3000 [200 201 202 204]))
  ([ip port path timeout-ms] (check-http ip port path timeout-ms [200 201 202 204]))
  ([ip port path timeout-ms expected-codes]
   (checker/check-http ip port path timeout-ms expected-codes)))

(defn check-https
  "Perform a one-off HTTPS health check.
   Returns CheckResult with :success?, :latency-ms, :error, :message."
  ([ip port path] (check-https ip port path 3000 [200 201 202 204]))
  ([ip port path timeout-ms] (check-https ip port path timeout-ms [200 201 202 204]))
  ([ip port path timeout-ms expected-codes]
   (checker/check-https ip port path timeout-ms expected-codes)))

;;; =============================================================================
;;; Utility Functions
;;; =============================================================================

(defn target-id
  "Create a target ID string from IP and port."
  [ip port]
  (checker/target-id ip port))

(defn format-status
  "Format health status for display."
  [proxy-name]
  (when-let [status (get-status proxy-name)]
    (str "Proxy: " (:proxy-name status) "\n"
         "Original weights: " (:original-weights status) "\n"
         "Effective weights: " (:effective-weights status) "\n"
         "Last update: " (when (:last-update-time status)
                           (java.util.Date. (:last-update-time status))) "\n"
         "Targets:\n"
         (clojure.string/join "\n"
           (map (fn [t]
                  (str "  " (:target-id t)
                       " [" (name (:status t)) "]"
                       (when (:last-latency-ms t)
                         (str " " (format "%.1fms" (:last-latency-ms t))))
                       (when (:last-error t)
                         (str " (" (name (:last-error t)) ")"))))
                (:targets status))))))

(defn print-status
  "Print health status for a proxy."
  [proxy-name]
  (println (format-status proxy-name)))

(defn print-all-status
  "Print health status for all proxies."
  []
  (doseq [status (get-all-status)]
    (println (format-status (:proxy-name status)))
    (println)))
