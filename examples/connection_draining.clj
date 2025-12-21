;; Connection Draining Examples
;;
;; Demonstrates graceful backend removal for zero-downtime deployments,
;; maintenance windows, and rolling updates.
;;
;; Usage:
;;   sudo clojure -M:dev
;;   (load-file "examples/connection-draining.clj")
;;
;; Connection draining:
;;   1. Stops new connections to the draining backend (weight set to 0)
;;   2. Allows existing connections to complete naturally
;;   3. Background watcher monitors connection counts
;;   4. Drain completes when connections reach 0 or timeout expires

(ns connection-draining
  (:require [lb.core :as lb]
            [lb.config :as config]
            [lb.drain :as drain]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Example Configuration
;;; =============================================================================

(def example-config
  "Configuration with weighted backends for draining demos"
  {:proxies
   [{:name "web"
     :listen {:interfaces ["lo"] :port 8000}
     :default-target
     [{:ip "127.0.0.1" :port 9001 :weight 50}
      {:ip "127.0.0.1" :port 9002 :weight 50}]}]
   :settings
   {:stats-enabled true
    :connection-timeout-sec 300
    :default-drain-timeout-ms 30000      ; 30 second drain timeout
    :drain-check-interval-ms 1000}})     ; Check every second

;;; =============================================================================
;;; Basic Draining
;;; =============================================================================

(defn demo-basic-drain
  "Demonstrate basic connection draining"
  []
  (println "\n=== Basic Drain Demo ===")

  ;; Start draining a backend
  (println "Starting drain for 127.0.0.1:9001...")
  (lb/drain-backend! "web" "127.0.0.1:9001")

  ;; Check status
  (println "\nDrain status:")
  (let [status (lb/get-drain-status "127.0.0.1:9001")]
    (println "  Target:" (:target-id status))
    (println "  Status:" (:status status))
    (println "  Elapsed:" (:elapsed-ms status) "ms")
    (println "  Connections:" (:current-connections status)))

  ;; Cancel the drain
  (println "\nCancelling drain...")
  (lb/undrain-backend! "web" "127.0.0.1:9001")
  (println "Drain cancelled."))

;;; =============================================================================
;;; Drain with Callback
;;; =============================================================================

(defn demo-drain-with-callback
  "Demonstrate draining with completion callback"
  []
  (println "\n=== Drain with Callback Demo ===")

  (lb/drain-backend! "web" "127.0.0.1:9001"
    :timeout-ms 10000  ; 10 second timeout for demo
    :on-complete
    (fn [status]
      (case status
        :completed (println "[Callback] Drain completed successfully!")
        :timeout   (println "[Callback] Drain timed out, forcing removal")
        :cancelled (println "[Callback] Drain was cancelled"))))

  (println "Drain started with callback.")
  (println "The callback will fire when drain completes or times out.")
  (println "Run (lb/undrain-backend! \"web\" \"127.0.0.1:9001\") to cancel."))

;;; =============================================================================
;;; Synchronous Drain
;;; =============================================================================

(defn demo-sync-drain
  "Demonstrate synchronous (blocking) drain"
  []
  (println "\n=== Synchronous Drain Demo ===")
  (println "This will block until the drain completes or times out...")

  ;; Start drain with short timeout
  (lb/drain-backend! "web" "127.0.0.1:9001"
    :timeout-ms 5000)  ; 5 second timeout

  ;; Block until complete
  (let [status (lb/wait-for-drain! "127.0.0.1:9001")]
    (println "Drain finished with status:" status)))

;;; =============================================================================
;;; Rolling Update Pattern
;;; =============================================================================

(defn rolling-update
  "Perform a rolling update of backends.

   For each backend:
   1. Drain the old instance (stop new connections)
   2. Wait for drain to complete
   3. Deploy new version
   4. Restore traffic

   Usage: (rolling-update \"web\" [\"127.0.0.1:9001\" \"127.0.0.1:9002\"])"
  [proxy-name targets]
  (println "\n=== Rolling Update ===")
  (doseq [target targets]
    (println "\n--- Updating" target "---")

    ;; Step 1: Start draining
    (println "1. Starting drain...")
    (lb/drain-backend! proxy-name target
      :timeout-ms 30000)

    ;; Step 2: Wait for drain (with progress)
    (println "2. Waiting for drain to complete...")
    (loop []
      (let [status (lb/get-drain-status target)]
        (when (and status (= :draining (:status status)))
          (println "   Connections remaining:" (:current-connections status))
          (Thread/sleep 1000)
          (recur))))

    (let [final-status (lb/wait-for-drain! target)]
      (println "   Drain completed with status:" final-status))

    ;; Step 3: Deploy new version (simulated)
    (println "3. Deploying new version... (simulated)")
    (Thread/sleep 1000)

    ;; Step 4: Restore traffic
    (println "4. Restoring traffic...")
    (lb/undrain-backend! proxy-name target)
    (println "   Traffic restored."))

  (println "\n=== Rolling Update Complete ==="))

;;; =============================================================================
;;; Monitor All Draining Backends
;;; =============================================================================

(defn monitor-drains
  "Continuously monitor all draining backends.
   Press Ctrl+C to stop."
  []
  (println "\n=== Monitoring Draining Backends ===")
  (println "Press Ctrl+C to stop.\n")
  (loop []
    (let [draining (lb/get-all-draining)]
      (if (empty? draining)
        (println "No backends currently draining.")
        (doseq [status draining]
          (println (format "%s: %s - %d connections, %dms elapsed"
                           (:target-id status)
                           (name (:status status))
                           (:current-connections status)
                           (:elapsed-ms status)))))
      (println "---")
      (Thread/sleep 2000)
      (recur))))

;;; =============================================================================
;;; Maintenance Window Pattern
;;; =============================================================================

(defn maintenance-window
  "Put a backend into maintenance mode.

   1. Drain the backend
   2. Wait for drain to complete
   3. Return a function to restore traffic

   Usage:
     (def restore (maintenance-window \"web\" \"127.0.0.1:9001\"))
     ;; ... perform maintenance ...
     (restore)"
  [proxy-name target]
  (println "Entering maintenance mode for" target)

  ;; Start drain
  (lb/drain-backend! proxy-name target
    :timeout-ms 60000)

  ;; Wait for completion
  (let [status (lb/wait-for-drain! target)]
    (println "Drain completed:" status))

  ;; Return restore function
  (fn []
    (println "Restoring traffic to" target)
    (lb/undrain-backend! proxy-name target)
    (println "Maintenance complete.")))

;;; =============================================================================
;;; Graceful Shutdown Pattern
;;; =============================================================================

(defn graceful-shutdown
  "Gracefully drain all backends before shutdown.

   Usage: (graceful-shutdown \"web\" 60000)"
  [proxy-name timeout-ms]
  (println "\n=== Graceful Shutdown ===")

  ;; Get all targets (would need proxy config in real scenario)
  (let [targets ["127.0.0.1:9001" "127.0.0.1:9002"]]

    ;; Start draining all backends in parallel
    (println "Starting drain for all backends...")
    (doseq [target targets]
      (try
        (lb/drain-backend! proxy-name target
          :timeout-ms timeout-ms)
        (println "  Started drain for" target)
        (catch Exception e
          (println "  Skipping" target ":" (.getMessage e)))))

    ;; Wait for all to complete
    (println "\nWaiting for all drains to complete...")
    (doseq [target targets]
      (when (lb/draining? target)
        (let [status (lb/wait-for-drain! target)]
          (println "  " target ":" status))))

    (println "\n=== All backends drained ===")
    (println "Safe to shutdown now.")))

;;; =============================================================================
;;; Helper to Show Drain API
;;; =============================================================================

(defn show-drain-api
  "Print available drain API functions"
  []
  (println "
=== Connection Draining API ===

Start draining:
  (lb/drain-backend! \"proxy-name\" \"ip:port\")
  (lb/drain-backend! \"proxy-name\" \"ip:port\"
    :timeout-ms 60000
    :on-complete (fn [status] ...))

Cancel drain:
  (lb/undrain-backend! \"proxy-name\" \"ip:port\")

Check status:
  (lb/draining? \"ip:port\")           ; => true/false
  (lb/get-drain-status \"ip:port\")    ; => {:status :draining ...}
  (lb/get-all-draining)                ; => [{:target-id ...} ...]

Wait for completion:
  (lb/wait-for-drain! \"ip:port\")     ; => :completed, :timeout, or :cancelled

Print status:
  (lb/print-drain-status)

Drain status values:
  :draining   - Drain in progress
  :completed  - All connections closed
  :timeout    - Timeout expired
  :cancelled  - Drain was cancelled
"))

;;; =============================================================================
;;; Main Demo
;;; =============================================================================

(defn -main
  "Run all demos. Requires load balancer to be initialized first."
  []
  (if (lb/running?)
    (do
      (show-drain-api)
      (demo-basic-drain)
      (Thread/sleep 1000)
      (println "\n\nTo run other demos:")
      (println "  (demo-drain-with-callback)")
      (println "  (demo-sync-drain)")
      (println "  (rolling-update \"web\" [\"127.0.0.1:9001\"])")
      (println "  (maintenance-window \"web\" \"127.0.0.1:9001\")"))
    (println "
Load balancer not running. Initialize first:

  (def cfg (lb.config/parse-config examples.connection-draining/example-config))
  (lb/init! cfg)

Then run demos:
  (examples.connection-draining/-main)

When done:
  (lb/shutdown!)
")))

;; Show usage on load
(println "
=== Connection Draining Examples Loaded ===

Quick start:
  (def cfg (lb.config/parse-config examples.connection-draining/example-config))
  (lb/init! cfg)
  (examples.connection-draining/-main)

Individual demos:
  (demo-basic-drain)
  (demo-drain-with-callback)
  (demo-sync-drain)
  (rolling-update \"web\" [\"127.0.0.1:9001\"])
  (maintenance-window \"web\" \"127.0.0.1:9001\")
  (graceful-shutdown \"web\" 30000)
  (monitor-drains)

API reference:
  (show-drain-api)
")
