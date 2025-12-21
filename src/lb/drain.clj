(ns lb.drain
  "Connection draining for graceful backend removal.
   Allows backends to be drained by stopping new connections while
   allowing existing connections to complete."
  (:require [lb.conntrack :as conntrack]
            [lb.health.weights :as weights]
            [lb.util :as util]
            [lb.maps :as maps]
            [lb.config :as config]
            [clojure.tools.logging :as log]
            [clojure.core.async :as async :refer [go-loop <! >! chan timeout close!]])
  (:import [lb.config TargetGroup WeightedTarget]))

;;; =============================================================================
;;; Data Types
;;; =============================================================================

(defrecord DrainState
  [target-id           ; "ip:port" string
   proxy-name          ; Which proxy this target belongs to
   started-at          ; Epoch ms when drain started
   timeout-ms          ; Drain timeout in milliseconds
   original-weight     ; Original weight before draining
   initial-conn-count  ; Connection count at drain start
   status])            ; :draining, :completed, :cancelled, :timeout

;;; =============================================================================
;;; Global Drain State
;;; =============================================================================

;; Global drain state atom.
;; {:draining {}       ; Map of target-id -> DrainState
;;  :watcher nil       ; Watcher control map {:thread :running :stop-fn}
;;  :callbacks {}      ; Map of target-id -> completion callback fn
;;  :conntrack-map nil ; Reference to conntrack map for connection counting
;;  :update-weights-fn nil ; Function to update BPF map weights
;; }
(defonce drain-state
  (atom {:draining {}
         :watcher nil
         :callbacks {}
         :conntrack-map nil
         :update-weights-fn nil}))

;;; =============================================================================
;;; Target ID Helpers
;;; =============================================================================

(defn target-id
  "Create a target ID string from IP and port.
   IP can be a string or u32 value."
  [ip port]
  (let [ip-str (if (string? ip) ip (util/u32->ip-string ip))]
    (str ip-str ":" port)))

(defn parse-target-id
  "Parse a target ID string into {:ip :port}.
   Returns IP as u32 and port as int."
  [id]
  (let [[ip-str port-str] (clojure.string/split id #":")]
    {:ip (util/ip-string->u32 ip-str)
     :port (Integer/parseInt port-str)}))

(defn normalize-target
  "Normalize target to target-id string.
   Accepts: \"ip:port\" string, {:ip :port} map, or WeightedTarget record."
  [target]
  (cond
    (string? target) target
    (instance? WeightedTarget target) (target-id (:ip target) (:port target))
    (map? target) (target-id (:ip target) (:port target))
    :else (throw (ex-info "Invalid target format" {:target target}))))

;;; =============================================================================
;;; Connection Counting
;;; =============================================================================

(defn get-connections-for-target
  "Get the number of active connections to a specific target.
   Uses conntrack/stats-by-target to count connections."
  [conntrack-map target-id]
  (let [{:keys [ip]} (parse-target-id target-id)
        ip-str (util/u32->ip-string ip)
        by-target (conntrack/stats-by-target conntrack-map)
        target-stats (first (filter #(= (:target-ip %) ip-str) by-target))]
    (or (:connection-count target-stats) 0)))

;;; =============================================================================
;;; Weight Updates
;;; =============================================================================

(defn- get-drain-statuses
  "Get drain status for each target in a target group.
   Returns vector of booleans (true = draining)."
  [target-group]
  (let [draining (:draining @drain-state)]
    (mapv (fn [target]
            (let [tid (target-id (:ip target) (:port target))]
              (boolean (get draining tid))))
          (:targets target-group))))

(defn- compute-weights-with-drain
  "Compute effective weights considering both health and drain status.
   Draining targets get weight 0."
  [target-group health-statuses drain-statuses]
  (let [original-weights (mapv :weight (:targets target-group))]
    (weights/compute-drain-weights original-weights health-statuses drain-statuses)))

;;; =============================================================================
;;; Drain Watcher
;;; =============================================================================

(defn- complete-drain!
  "Mark a drain as complete and invoke callback."
  [target-id final-status]
  (log/info "Drain completed for" target-id "with status:" final-status)
  (let [{:keys [callbacks]} @drain-state
        callback (get callbacks target-id)
        drain-info (get-in @drain-state [:draining target-id])]
    ;; Update status
    (swap! drain-state update :draining dissoc target-id)
    (swap! drain-state update :callbacks dissoc target-id)
    ;; Invoke callback
    (when callback
      (try
        (callback final-status)
        (catch Exception e
          (log/error e "Error in drain callback for" target-id))))))

(defn- check-drain-completion
  "Check if a draining backend should be marked complete."
  [conntrack-map target-id drain-info]
  (let [conn-count (get-connections-for-target conntrack-map target-id)
        elapsed (- (System/currentTimeMillis) (:started-at drain-info))
        timeout-ms (:timeout-ms drain-info)]
    (cond
      ;; No more connections - drain complete
      (zero? conn-count)
      :completed

      ;; Timeout expired
      (>= elapsed timeout-ms)
      :timeout

      ;; Still draining
      :else nil)))

(defn- start-drain-watcher!
  "Start a background thread that monitors draining backends.
   Returns control map with :stop-fn."
  [conntrack-map check-interval-ms]
  (let [running (atom true)
        thread (Thread.
                 (fn []
                   (log/info "Drain watcher started, checking every" check-interval-ms "ms")
                   (while @running
                     (try
                       (let [draining (:draining @drain-state)]
                         (doseq [[target-id drain-info] draining]
                           (when-let [final-status (check-drain-completion
                                                     conntrack-map target-id drain-info)]
                             (complete-drain! target-id final-status))))
                       (Thread/sleep check-interval-ms)
                       (catch InterruptedException _
                         (reset! running false))
                       (catch Exception e
                         (log/error e "Error in drain watcher"))))
                   (log/info "Drain watcher stopped")))]
    (.setDaemon thread true)
    (.setName thread "drain-watcher")
    (.start thread)
    {:thread thread
     :running running
     :stop-fn #(do (reset! running false)
                   (.interrupt thread)
                   (.join thread 2000))}))

(defn- ensure-watcher-running!
  "Ensure the drain watcher is running."
  [conntrack-map check-interval-ms]
  (when (and (nil? (:watcher @drain-state))
             conntrack-map)
    (let [watcher (start-drain-watcher! conntrack-map check-interval-ms)]
      (swap! drain-state assoc :watcher watcher))))

(defn stop-drain-watcher!
  "Stop the drain watcher."
  []
  (when-let [watcher (:watcher @drain-state)]
    ((:stop-fn watcher))
    (swap! drain-state assoc :watcher nil)))

;;; =============================================================================
;;; Public API
;;; =============================================================================

(defn init!
  "Initialize the drain module with required resources.
   conntrack-map: BPF conntrack map for connection counting
   update-weights-fn: Function (fn [proxy-name new-target-group]) to update BPF maps
   opts:
     :check-interval-ms - How often to check drain status (default 1000ms)"
  [conntrack-map update-weights-fn & {:keys [check-interval-ms]
                                       :or {check-interval-ms 1000}}]
  (swap! drain-state assoc
         :conntrack-map conntrack-map
         :update-weights-fn update-weights-fn)
  (ensure-watcher-running! conntrack-map check-interval-ms)
  (log/info "Drain module initialized"))

(defn shutdown!
  "Shutdown the drain module."
  []
  (stop-drain-watcher!)
  ;; Complete any in-progress drains as cancelled
  (doseq [[target-id _] (:draining @drain-state)]
    (complete-drain! target-id :cancelled))
  (reset! drain-state {:draining {}
                       :watcher nil
                       :callbacks {}
                       :conntrack-map nil
                       :update-weights-fn nil})
  (log/info "Drain module shutdown"))

(defn draining?
  "Check if a target is currently draining."
  [target]
  (let [tid (normalize-target target)]
    (boolean (get-in @drain-state [:draining tid]))))

(defn drain-backend!
  "Start draining a backend target.

   proxy-name: Name of the proxy containing the target
   target-group: TargetGroup record containing the target
   target: Target to drain - \"ip:port\" string, {:ip :port} map, or WeightedTarget
   opts:
     :timeout-ms - Drain timeout (default 30000ms)
     :on-complete - Callback fn called with status when drain completes

   Returns DrainState or throws if target not found/already draining."
  [proxy-name target-group target & {:keys [timeout-ms on-complete]
                                      :or {timeout-ms 30000}}]
  (let [tid (normalize-target target)
        {:keys [ip port]} (parse-target-id tid)
        {:keys [conntrack-map update-weights-fn]} @drain-state]

    ;; Validate
    (when-not conntrack-map
      (throw (ex-info "Drain module not initialized" {})))

    (when (draining? tid)
      (throw (ex-info "Target is already draining" {:target tid})))

    ;; Find target in target group
    (let [target-in-group (first (filter #(and (= (:ip %) ip)
                                               (= (:port %) port))
                                         (:targets target-group)))]
      (when-not target-in-group
        (throw (ex-info "Target not found in target group"
                        {:target tid :proxy proxy-name})))

      ;; Get initial connection count
      (let [initial-conns (get-connections-for-target conntrack-map tid)
            drain-info (->DrainState
                         tid
                         proxy-name
                         (System/currentTimeMillis)
                         timeout-ms
                         (:weight target-in-group)
                         initial-conns
                         :draining)]

        (log/info "Starting drain for" tid
                  "- initial connections:" initial-conns
                  "- timeout:" timeout-ms "ms")

        ;; Store drain state
        (swap! drain-state assoc-in [:draining tid] drain-info)
        (when on-complete
          (swap! drain-state assoc-in [:callbacks tid] on-complete))

        ;; Update weights - draining targets get weight 0
        (when update-weights-fn
          (let [health-statuses (vec (repeat (count (:targets target-group)) true))
                drain-statuses (get-drain-statuses target-group)
                new-weights (compute-weights-with-drain target-group health-statuses drain-statuses)
                new-cumulative (weights/weights->cumulative new-weights)
                ;; Create updated target group
                updated-targets (mapv (fn [t w]
                                        (assoc t :effective-weight w))
                                      (:targets target-group) new-weights)
                new-target-group (-> target-group
                                     (assoc :targets updated-targets)
                                     (assoc :cumulative-weights new-cumulative)
                                     (assoc :effective-weights new-weights))]
            (update-weights-fn proxy-name new-target-group)))

        drain-info))))

(defn undrain-backend!
  "Cancel draining and restore traffic to a backend.

   proxy-name: Name of the proxy
   target-group: TargetGroup record containing the target
   target: Target to undrain

   Returns true if undrain succeeded, false if target wasn't draining."
  [proxy-name target-group target]
  (let [tid (normalize-target target)
        {:keys [update-weights-fn]} @drain-state]

    (if-not (draining? tid)
      (do
        (log/warn "Target" tid "is not draining")
        false)

      (do
        (log/info "Undraining" tid)

        ;; Remove from draining state
        (swap! drain-state update :draining dissoc tid)
        (swap! drain-state update :callbacks dissoc tid)

        ;; Restore weights
        (when update-weights-fn
          (let [health-statuses (vec (repeat (count (:targets target-group)) true))
                drain-statuses (get-drain-statuses target-group)
                new-weights (compute-weights-with-drain target-group health-statuses drain-statuses)
                new-cumulative (weights/weights->cumulative new-weights)
                updated-targets (mapv (fn [t w]
                                        (assoc t :effective-weight w))
                                      (:targets target-group) new-weights)
                new-target-group (-> target-group
                                     (assoc :targets updated-targets)
                                     (assoc :cumulative-weights new-cumulative)
                                     (assoc :effective-weights new-weights))]
            (update-weights-fn proxy-name new-target-group)))

        true))))

(defn get-drain-status
  "Get current drain status for a backend.

   Returns map with :target-id :status :elapsed-ms :current-connections
   or nil if not draining."
  [target]
  (let [tid (normalize-target target)
        {:keys [draining conntrack-map]} @drain-state
        drain-info (get draining tid)]
    (when drain-info
      (let [current-conns (if conntrack-map
                            (get-connections-for-target conntrack-map tid)
                            0)
            elapsed (- (System/currentTimeMillis) (:started-at drain-info))]
        {:target-id tid
         :proxy-name (:proxy-name drain-info)
         :status (:status drain-info)
         :started-at (:started-at drain-info)
         :elapsed-ms elapsed
         :timeout-ms (:timeout-ms drain-info)
         :original-weight (:original-weight drain-info)
         :initial-connections (:initial-conn-count drain-info)
         :current-connections current-conns}))))

(defn get-all-draining
  "Get all currently draining backends.

   Returns seq of drain status maps."
  []
  (let [{:keys [draining conntrack-map]} @drain-state]
    (map (fn [[tid drain-info]]
           (let [current-conns (if conntrack-map
                                 (get-connections-for-target conntrack-map tid)
                                 0)
                 elapsed (- (System/currentTimeMillis) (:started-at drain-info))]
             {:target-id tid
              :proxy-name (:proxy-name drain-info)
              :status (:status drain-info)
              :elapsed-ms elapsed
              :timeout-ms (:timeout-ms drain-info)
              :current-connections current-conns
              :initial-connections (:initial-conn-count drain-info)}))
         draining)))

(defn wait-for-drain!
  "Block until drain completes or times out.

   Returns :completed, :timeout, or :cancelled."
  [target]
  (let [tid (normalize-target target)]
    (if-not (draining? tid)
      (do
        (log/warn "Target" tid "is not draining")
        nil)

      (let [result-promise (promise)]
        ;; Register temporary callback
        (swap! drain-state update-in [:callbacks tid]
               (fn [existing-cb]
                 (fn [status]
                   (deliver result-promise status)
                   (when existing-cb
                     (existing-cb status)))))
        ;; Wait for result
        @result-promise))))

;;; =============================================================================
;;; Display
;;; =============================================================================

(defn format-drain-status
  "Format drain status for display."
  [status]
  (format "%s (%s): %d/%d connections, elapsed %dms/%dms"
          (:target-id status)
          (name (:status status))
          (:current-connections status)
          (:initial-connections status)
          (:elapsed-ms status)
          (:timeout-ms status)))

(defn print-drain-status
  "Print all draining backends."
  []
  (let [draining (get-all-draining)]
    (if (empty? draining)
      (println "No backends currently draining")
      (do
        (println (format "Draining backends: %d" (count draining)))
        (println "---")
        (doseq [status draining]
          (println (format-drain-status status)))))))
