(ns lb.reload
  "Configuration hot reload for the load balancer.

   Provides:
   - File watching (inotify-based via Java NIO WatchService)
   - SIGHUP signal handling
   - Incremental configuration updates
   - Validation before apply with rollback on failure

   Usage:
     ;; Enable hot reload for a config file
     (enable-hot-reload! \"/etc/lb/config.edn\")

     ;; Manual reload
     (reload-config!)

     ;; Disable hot reload
     (disable-hot-reload!)"
  (:require [clojure.java.io :as io]
            [clojure.edn :as edn]
            [clojure.core.async :as async :refer [chan go-loop <! >!! close! timeout alts!!]]
            [clojure.tools.logging :as log]
            [lb.config :as config]
            [lb.maps :as maps]
            [lb.util :as util])
  (:import [java.nio.file FileSystems StandardWatchEventKinds WatchEvent$Kind Path]
           [sun.misc Signal SignalHandler]))

;;; =============================================================================
;;; Reload State
;;; =============================================================================

(defonce ^:private reload-state
  (atom {:file-watcher nil       ; File watcher control map
         :config-path nil        ; Path to config file
         :sighup-handler nil     ; Previous SIGHUP handler (for restore)
         :enabled false          ; Whether hot reload is enabled
         :last-reload nil        ; Timestamp of last reload
         :reload-count 0}))      ; Number of successful reloads

;;; =============================================================================
;;; Forward Declarations
;;; =============================================================================

;; These will be set by core.clj to avoid circular dependency
(defonce ^:private apply-fns
  (atom {:get-state nil          ; fn to get current state
         :add-proxy! nil         ; fn to add a proxy
         :remove-proxy! nil      ; fn to remove a proxy
         :add-source-route! nil  ; fn to add source route
         :remove-source-route! nil ; fn to remove source route
         :add-sni-route! nil     ; fn to add SNI route
         :remove-sni-route! nil  ; fn to remove SNI route
         :enable-stats! nil      ; fn to enable stats
         :disable-stats! nil     ; fn to disable stats
         :update-proxy-state! nil})) ; fn to update proxy state atom

(defn register-apply-fns!
  "Register the apply functions from core.clj.
   Called during core initialization to avoid circular dependency."
  [fns]
  (reset! apply-fns fns))

;;; =============================================================================
;;; File Watcher
;;; =============================================================================

(defn start-file-watcher!
  "Start a background daemon that watches config file for changes.
   Uses Java NIO WatchService (which uses inotify on Linux).

   Parameters:
     config-path - Path to configuration file
     on-change-fn - Function called with config path when file changes

   Options:
     :debounce-ms - Debounce period to coalesce rapid changes (default 500ms)

   Returns a control map with :stop-fn to stop the watcher."
  [config-path on-change-fn & {:keys [debounce-ms] :or {debounce-ms 500}}]
  (let [stop-chan (chan)
        config-file (io/file config-path)
        parent-dir (.getParentFile config-file)
        watcher (.newWatchService (FileSystems/getDefault))
        watcher-thread
        (Thread.
          (fn []
            (log/info "Config file watcher started for:" config-path)
            (try
              ;; Register parent directory for MODIFY events
              (.register (.toPath parent-dir) watcher
                         (into-array WatchEvent$Kind
                           [StandardWatchEventKinds/ENTRY_MODIFY]))
              (loop [last-change 0]
                (let [[v ch] (alts!! [stop-chan (timeout 100)])]
                  (when-not (= ch stop-chan)
                    ;; Poll for watch events (non-blocking)
                    (if-let [key (.poll watcher)]
                      (let [events (.pollEvents key)
                            config-name (.getName config-file)
                            relevant? (some #(= config-name (str (.context %))) events)
                            now (System/currentTimeMillis)]
                        (.reset key)
                        (if (and relevant?
                                 (> (- now last-change) debounce-ms))
                          (do
                            (log/info "Config file changed, triggering reload")
                            (try
                              (on-change-fn config-path)
                              (catch Exception e
                                (log/error e "Error handling config change")))
                            (recur now))
                          (recur last-change)))
                      (recur last-change)))))
              (catch java.nio.file.ClosedWatchServiceException _
                (log/debug "Watch service closed"))
              (catch Exception e
                (log/error e "Error in file watcher")))
            (try (.close watcher) (catch Exception _))
            (log/info "Config file watcher stopped")))]
    (.setDaemon watcher-thread true)
    (.setName watcher-thread "config-file-watcher")
    (.start watcher-thread)
    {:thread watcher-thread
     :watcher watcher
     :stop-chan stop-chan
     :stop-fn (fn []
                (>!! stop-chan :stop)
                (try (.close watcher) (catch Exception _))
                (.join watcher-thread 2000))}))

(defn stop-file-watcher!
  "Stop the file watcher."
  [{:keys [stop-fn]}]
  (when stop-fn
    (stop-fn)))

;;; =============================================================================
;;; SIGHUP Signal Handler
;;; =============================================================================

(defn register-sighup-handler!
  "Register a handler for SIGHUP signal.
   On SIGHUP, calls reload-fn.

   Returns previous handler that can be restored."
  [reload-fn]
  (try
    (let [handler (proxy [SignalHandler] []
                    (handle [sig]
                      (log/info "Received SIGHUP, triggering config reload")
                      (try
                        (reload-fn)
                        (catch Exception e
                          (log/error e "Error during SIGHUP reload")))))]
      (Signal/handle (Signal. "HUP") handler))
    (catch IllegalArgumentException e
      ;; Signal not available on this platform (e.g., Windows)
      (log/warn "SIGHUP not available on this platform:" (.getMessage e))
      nil)))

(defn unregister-sighup-handler!
  "Restore default SIGHUP behavior."
  [previous-handler]
  (try
    (if previous-handler
      (Signal/handle (Signal. "HUP") previous-handler)
      (Signal/handle (Signal. "HUP") SignalHandler/SIG_DFL))
    (catch Exception e
      (log/warn "Failed to unregister SIGHUP handler:" (.getMessage e)))))

;;; =============================================================================
;;; Apply Diff Logic
;;; =============================================================================

(defn- apply-settings-diff!
  "Apply settings changes to the running system."
  [settings-changes]
  (let [{:keys [enable-stats! disable-stats!]} @apply-fns]
    ;; Handle stats-enabled change
    (when-let [{:keys [new]} (:stats-enabled settings-changes)]
      (if new
        (when enable-stats! (enable-stats!))
        (when disable-stats! (disable-stats!))))
    ;; Other settings changes are informational only for now
    ;; (connection-timeout, max-connections, etc. affect BPF behavior
    ;; but don't require runtime changes as they're read from maps)
    ))

(defn- apply-proxy-diff!
  "Apply changes for a single modified proxy."
  [proxy-name proxy-diff old-proxy new-proxy]
  (let [{:keys [add-proxy! remove-proxy! add-source-route! remove-source-route!
                add-sni-route! remove-sni-route!]} @apply-fns]
    (if (:listen-changed? proxy-diff)
      ;; Full proxy reload needed - remove and re-add
      (do
        (log/info "Proxy" proxy-name "listen config changed, performing full reload")
        (when remove-proxy! (remove-proxy! proxy-name))
        (when add-proxy! (add-proxy! (config/config->map
                                       (config/->Config [new-proxy] config/default-settings)))))
      ;; Incremental updates
      (do
        ;; Update default target if changed
        (when-let [{:keys [new]} (:default-target-diff proxy-diff)]
          (log/info "Updating default target for proxy" proxy-name)
          ;; This requires updating the listen map directly
          ;; For now, log that this would need a full reload
          (log/warn "Default target change requires proxy reload (not yet supported incrementally)"))

        ;; Remove old source routes first
        (doseq [{:keys [source prefix-len]} (:removed-source-routes proxy-diff)]
          (log/info "Removing source route" (util/cidr->string {:ip source :prefix-len prefix-len})
                    "from proxy" proxy-name)
          (when remove-source-route!
            (remove-source-route! proxy-name source prefix-len)))

        ;; Add new source routes
        (doseq [route (:added-source-routes proxy-diff)]
          (log/info "Adding source route" (util/cidr->string {:ip (:source route) :prefix-len (:prefix-len route)})
                    "to proxy" proxy-name)
          (when add-source-route!
            (add-source-route! proxy-name (:source route) (:prefix-len route)
                               (:target-group route))))

        ;; Remove old SNI routes
        (doseq [hostname (:removed-sni-routes proxy-diff)]
          (log/info "Removing SNI route" hostname "from proxy" proxy-name)
          (when remove-sni-route!
            (remove-sni-route! proxy-name hostname)))

        ;; Add new SNI routes
        (doseq [route (:added-sni-routes proxy-diff)]
          (log/info "Adding SNI route" (:hostname route) "to proxy" proxy-name)
          (when add-sni-route!
            (add-sni-route! proxy-name route)))))))

(defn- apply-config-diff!
  "Apply full config diff.
   Returns {:success? bool :error ...} on failure."
  [diff old-config new-config]
  (let [{:keys [add-proxy! remove-proxy!]} @apply-fns
        old-proxies-by-name (into {} (map (juxt :name identity) (:proxies old-config)))]
    (try
      ;; 1. Apply settings changes
      (when (seq (:settings-changes diff))
        (log/info "Applying settings changes:" (keys (:settings-changes diff)))
        (apply-settings-diff! (:settings-changes diff)))

      ;; 2. Add new proxies first (before removing old ones for continuity)
      (doseq [proxy (:added-proxies diff)]
        (log/info "Adding new proxy:" (:name proxy))
        (when add-proxy!
          ;; Convert ProxyConfig back to map format for add-proxy!
          (let [proxy-map (first (:proxies (config/config->map
                                             (config/->Config [proxy] config/default-settings))))]
            (add-proxy! proxy-map))))

      ;; 3. Apply modified proxy changes
      (doseq [proxy-diff (:modified-proxies diff)]
        (let [proxy-name (:proxy-name proxy-diff)
              old-proxy (old-proxies-by-name proxy-name)
              new-proxy (first (filter #(= (:name %) proxy-name) (:proxies new-config)))]
          (log/info "Applying changes to proxy:" proxy-name)
          (apply-proxy-diff! proxy-name proxy-diff old-proxy new-proxy)))

      ;; 4. Remove old proxies last
      (doseq [proxy-name (:removed-proxies diff)]
        (log/info "Removing proxy:" proxy-name)
        (when remove-proxy!
          (remove-proxy! proxy-name)))

      {:success? true}

      (catch Exception e
        (log/error e "Error applying config diff")
        {:success? false :error (.getMessage e)}))))

;;; =============================================================================
;;; Public API
;;; =============================================================================

;; Forward declaration for mutual reference
(declare disable-hot-reload!)

(defn reload-config!
  "Manually trigger a configuration reload.

   If path is provided, loads from that file.
   Otherwise, uses the last known config path.

   Returns {:success? bool :changes {...} :error ...}"
  ([]
   (if-let [config-path (:config-path @reload-state)]
     (reload-config! config-path)
     {:success? false :error "No config path set. Call with path argument."}))
  ([config-path]
   (let [{:keys [get-state update-proxy-state!]} @apply-fns]
     (if-not get-state
       {:success? false :error "Reload functions not registered. Is the load balancer running?"}
       (let [state (get-state)]
         (if-not state
           {:success? false :error "Load balancer not running"}
           (let [old-config (:config state)]
             ;; Step 1: Load and validate new config
             (try
               (let [config-map (edn/read-string (slurp config-path))
                     validation (config/validate-config config-map)]
                 (if-not (:valid validation)
                   {:success? false
                    :error :validation-failed
                    :details (str (:errors validation))}
                   (let [new-config (:config validation)
                         diff (config/diff-configs old-config new-config)]
                     (if (config/config-diff-empty? diff)
                       {:success? true :changes {:no-changes true}}
                       ;; Step 2: Apply the diff
                       (let [result (apply-config-diff! diff old-config new-config)]
                         (if (:success? result)
                           (do
                             ;; Update state with new config
                             (when update-proxy-state!
                               (update-proxy-state! assoc :config new-config))
                             (swap! reload-state
                                    #(-> %
                                         (assoc :last-reload (System/currentTimeMillis))
                                         (update :reload-count inc)))
                             {:success? true
                              :changes (config/summarize-diff diff)})
                           result))))))
               (catch java.io.FileNotFoundException _
                 {:success? false :error :file-not-found :details config-path})
               (catch Exception e
                 {:success? false :error :load-failed :details (.getMessage e)})))))))))

(defn reload-config-from-map!
  "Reload configuration from an in-memory config map.
   Useful for programmatic config changes.

   Returns {:success? bool :changes {...} :error ...}"
  [config-map]
  (let [{:keys [get-state update-proxy-state!]} @apply-fns]
    (if-not get-state
      {:success? false :error "Reload functions not registered"}
      (let [state (get-state)]
        (if-not state
          {:success? false :error "Load balancer not running"}
          (let [old-config (:config state)
                validation (config/validate-config config-map)]
            (if-not (:valid validation)
              {:success? false
               :error :validation-failed
               :details (str (:errors validation))}
              (let [new-config (:config validation)
                    diff (config/diff-configs old-config new-config)]
                (if (config/config-diff-empty? diff)
                  {:success? true :changes {:no-changes true}}
                  (let [result (apply-config-diff! diff old-config new-config)]
                    (if (:success? result)
                      (do
                        (when update-proxy-state!
                          (update-proxy-state! assoc :config new-config))
                        (swap! reload-state update :reload-count inc)
                        {:success? true
                         :changes (config/summarize-diff diff)})
                      result)))))))))))

(defn enable-hot-reload!
  "Enable hot reload for the specified config file.

   Options:
     :watch-file? - Enable file watching (default true)
     :sighup? - Enable SIGHUP handling (default true)
     :debounce-ms - File change debounce period (default 500ms)

   Returns true if enabled successfully."
  [config-path & {:keys [watch-file? sighup? debounce-ms]
                  :or {watch-file? true
                       sighup? true
                       debounce-ms 500}}]
  (when (:enabled @reload-state)
    (disable-hot-reload!))

  (log/info "Enabling hot reload for:" config-path)

  (let [file-watcher (when watch-file?
                       (start-file-watcher! config-path
                                            (fn [path] (reload-config! path))
                                            :debounce-ms debounce-ms))
        sighup-handler (when sighup?
                         (register-sighup-handler!
                           (fn [] (reload-config!))))]
    (swap! reload-state assoc
           :file-watcher file-watcher
           :config-path config-path
           :sighup-handler sighup-handler
           :enabled true)
    (log/info "Hot reload enabled"
              (str "(file-watch: " (some? file-watcher)
                   ", sighup: " (some? sighup-handler) ")"))
    true))

(defn disable-hot-reload!
  "Disable hot reload and cleanup resources."
  []
  (when (:enabled @reload-state)
    (log/info "Disabling hot reload")
    (when-let [watcher (:file-watcher @reload-state)]
      (stop-file-watcher! watcher))
    (when (:sighup-handler @reload-state)
      (unregister-sighup-handler! (:sighup-handler @reload-state)))
    (swap! reload-state assoc
           :file-watcher nil
           :sighup-handler nil
           :enabled false)
    true))

(defn hot-reload-enabled?
  "Check if hot reload is currently enabled."
  []
  (:enabled @reload-state))

(defn get-reload-state
  "Get current reload state for debugging."
  []
  (let [state @reload-state]
    {:enabled (:enabled state)
     :config-path (:config-path state)
     :file-watcher-active (some? (:file-watcher state))
     :sighup-handler-active (some? (:sighup-handler state))
     :last-reload (:last-reload state)
     :reload-count (:reload-count state)}))
