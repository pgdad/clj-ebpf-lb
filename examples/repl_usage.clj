;; REPL Usage Example
;;
;; This file demonstrates interactive usage of the reverse proxy from the REPL.
;; Run with:
;;   sudo clojure -M:dev
;;   (load-file "examples/repl_usage.clj")
;;
;; Or evaluate each section interactively.

(ns examples.repl-usage
  (:require [reverse-proxy.core :as proxy]
            [reverse-proxy.config :as config]
            [reverse-proxy.conntrack :as conntrack]
            [clojure.pprint :refer [pprint]]))

;; =============================================================================
;; 1. Basic Initialization
;; =============================================================================

(comment
  ;; Create a simple configuration programmatically
  (def my-config
    (config/make-simple-config
      {:name "demo"
       :interface "eth0"    ; Change to your interface
       :port 80
       :target-ip "127.0.0.1"
       :target-port 8080
       :stats-enabled true}))

  ;; Initialize the proxy
  (proxy/init! my-config)

  ;; Check status
  (proxy/print-status)
  ;; => === Reverse Proxy Status ===
  ;;    Running:             true
  ;;    Attached interfaces: eth0
  ;;    Stats enabled:       true
  ;;    Active connections:  0
  ;;    Configured proxies:  1

  ;; Print the configuration
  (proxy/print-config))

;; =============================================================================
;; 2. Runtime Configuration
;; =============================================================================

(comment
  ;; Add a new proxy at runtime
  (proxy/add-proxy!
    {:name "api"
     :listen {:interfaces ["eth0"] :port 8080}
     :default-target {:ip "10.0.0.1" :port 3000}})

  ;; Add source routes to existing proxy
  (proxy/add-source-route! "demo" "192.168.1.0/24"
                           {:ip "10.0.0.2" :port 8080})

  (proxy/add-source-route! "demo" "10.10.0.0/16"
                           {:ip "10.0.0.3" :port 8080})

  ;; View updated configuration
  (proxy/print-config)

  ;; Remove a source route
  (proxy/remove-source-route! "demo" "10.10.0.0/16")

  ;; Remove a proxy
  (proxy/remove-proxy! "api"))

;; =============================================================================
;; 3. Connection Monitoring
;; =============================================================================

(comment
  ;; Get all active connections
  (def conns (proxy/get-connections))
  (pprint (map conntrack/connection->map conns))

  ;; Get connection count
  (proxy/get-connection-count)

  ;; Print connections in a formatted table
  (proxy/print-connections)

  ;; Get aggregate statistics
  (pprint (proxy/get-connection-stats))
  ;; => {:total-connections 42
  ;;     :total-packets-forward 12345
  ;;     :total-bytes-forward 987654
  ;;     :total-packets-reverse 11234
  ;;     :total-bytes-reverse 876543}

  ;; Clear all connections (useful for testing)
  (proxy/clear-connections!))

;; =============================================================================
;; 4. Interface Management
;; =============================================================================

(comment
  ;; List currently attached interfaces
  (proxy/list-attached-interfaces)
  ;; => ["eth0"]

  ;; Attach to additional interfaces
  (proxy/attach-interfaces! ["eth1" "eth2"])

  ;; Detach from an interface
  (proxy/detach-interfaces! ["eth2"])

  ;; Verify attachment
  (proxy/list-attached-interfaces)
  ;; => ["eth0" "eth1"]
  )

;; =============================================================================
;; 5. Statistics Control
;; =============================================================================

(comment
  ;; Check if stats are enabled
  (proxy/stats-enabled?)

  ;; Enable/disable stats
  (proxy/enable-stats!)
  (proxy/disable-stats!)

  ;; Start streaming stats (requires stats enabled)
  (proxy/start-stats-stream!)

  ;; Subscribe to the stats channel
  (require '[clojure.core.async :as async])
  (let [ch (proxy/subscribe-to-stats)]
    ;; Read a few events
    (dotimes [_ 5]
      (when-let [event (async/<!! ch)]
        (println "Event:" event))))

  ;; Stop streaming
  (proxy/stop-stats-stream!))

;; =============================================================================
;; 6. Loading Configuration from File
;; =============================================================================

(comment
  ;; Load configuration from EDN file
  (def file-config
    (config/load-config-file "examples/multi-backend.edn"))

  ;; Validate a configuration before using it
  (def validation
    (config/validate-config
      {:proxies [{:name "test"
                  :listen {:interfaces ["eth0"] :port 80}
                  :default-target {:ip "10.0.0.1" :port 8080}}]}))

  (if (:valid validation)
    (println "Configuration is valid")
    (pprint (:errors validation)))

  ;; Save current configuration to file
  (when-let [state (proxy/get-state)]
    (config/save-config-file (:config state) "my-config.edn")))

;; =============================================================================
;; 7. Shutdown
;; =============================================================================

(comment
  ;; Gracefully shutdown the proxy
  ;; This will:
  ;; - Stop stats streaming
  ;; - Stop cleanup daemon
  ;; - Detach from all interfaces
  ;; - Close all BPF programs and maps
  (proxy/shutdown!)

  ;; Verify shutdown
  (proxy/running?)
  ;; => false
  )

;; =============================================================================
;; 8. Complete Example Session
;; =============================================================================

(defn demo-session
  "Run a complete demo session. Requires a backend server running on port 8080."
  [interface]
  (println "Starting demo session on interface:" interface)

  ;; Initialize
  (let [cfg (config/make-simple-config
              {:interface interface
               :port 8888
               :target-ip "127.0.0.1"
               :target-port 8080
               :stats-enabled true})]
    (proxy/init! cfg))

  (println "\nProxy initialized. Status:")
  (proxy/print-status)

  (println "\nAdd a source route for 192.168.0.0/16...")
  (proxy/add-source-route! "default" "192.168.0.0/16"
                           {:ip "127.0.0.1" :port 8081})

  (println "\nCurrent configuration:")
  (proxy/print-config)

  (println "\nProxy is running on port 8888")
  (println "Test with: curl http://localhost:8888")
  (println "Press Enter to shutdown...")
  (read-line)

  (println "\nShutting down...")
  (proxy/shutdown!)
  (println "Done."))

;; Uncomment to run the demo:
;; (demo-session "eth0")

(println "REPL usage example loaded. See comments for usage patterns.")
