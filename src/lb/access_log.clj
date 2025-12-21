(ns lb.access-log
  "Access logging for the load balancer.
   Logs connection events to stdout and rotating file.
   Supports JSON and CLF (Common Log Format) output."
  (:require [clojure.core.async :as async :refer [go-loop <! chan sliding-buffer close!]]
            [clojure.tools.logging :as log]
            [lb.access-log.file-writer :as file-writer]
            [lb.access-log.logger :as logger]
            [lb.stats :as stats]
            [lb.util :as util]))

;;; =============================================================================
;;; State
;;; =============================================================================

(defonce ^:private access-log-state
  (atom {:running? false
         :logger nil
         :file-writer nil
         :event-chan nil
         :stats-stream nil}))

;;; =============================================================================
;;; Output Functions
;;; =============================================================================

(defn- make-stdout-output-fn
  "Create an output function that prints to stdout."
  []
  (fn [line]
    (println line)))

(defn- make-file-output-fn
  "Create an output function that writes to the rotating file writer.
   Returns a function that updates the file-writer atom."
  [file-writer-atom]
  (fn [line]
    (swap! file-writer-atom
           (fn [writer]
             (if writer
               (file-writer/write-line! writer line)
               writer)))))

;;; =============================================================================
;;; Event Processing
;;; =============================================================================

(defn- process-events!
  "Start processing stats events and converting to access log entries."
  [event-chan conntrack-map async-logger]
  (go-loop []
    (when-let [event (<! event-chan)]
      (when (#{1 2} (:event-type event))  ; new-conn or conn-closed
        (try
          (let [entry (logger/stats-event->log-entry event conntrack-map)]
            (logger/log-entry! async-logger entry))
          (catch Exception e
            (log/debug e "Error processing access log event"))))
      (recur))))

;;; =============================================================================
;;; Public API
;;; =============================================================================

(defn start!
  "Start access logging.

   Parameters:
     config - AccessLogConfig with :enabled :format :path :max-file-size-mb :max-files :buffer-size
     stats-stream - Stats event stream from lb.stats/create-event-stream
     conntrack-map - Connection tracking BPF map

   Returns true if started successfully."
  [config stats-stream conntrack-map]
  (when-not (:running? @access-log-state)
    (when (:enabled config)
      (log/info "Starting access logging"
                (format "(format=%s, path=%s, max-size=%dMB, max-files=%d)"
                        (name (:format config))
                        (:path config)
                        (:max-file-size-mb config)
                        (:max-files config)))

      (let [;; Create file writer atom for thread-safe updates
            file-writer-atom (atom (file-writer/create-writer
                                     :path (:path config)
                                     :max-size-mb (:max-file-size-mb config)
                                     :max-files (:max-files config)))

            ;; Create output functions for both stdout and file
            output-fns [(make-stdout-output-fn)
                        (make-file-output-fn file-writer-atom)]

            ;; Create async logger
            async-logger (logger/create-async-logger
                           (:format config)
                           output-fns
                           :buffer-size (:buffer-size config))

            ;; Subscribe to stats stream
            event-chan (stats/subscribe-to-stream stats-stream :buffer-size (:buffer-size config))]

        ;; Store state
        (swap! access-log-state assoc
               :running? true
               :logger async-logger
               :file-writer file-writer-atom
               :event-chan event-chan
               :stats-stream stats-stream)

        ;; Start event processing
        (process-events! event-chan conntrack-map async-logger)

        (log/info "Access logging started")
        true))))

(defn stop!
  "Stop access logging."
  []
  (when (:running? @access-log-state)
    (log/info "Stopping access logging")

    ;; Unsubscribe from stats stream
    (when-let [event-chan (:event-chan @access-log-state)]
      (when-let [stream (:stats-stream @access-log-state)]
        (stats/unsubscribe-from-stream stream event-chan)))

    ;; Stop the async logger
    (when-let [logger (:logger @access-log-state)]
      (logger/stop-logger! logger))

    ;; Close file writer
    (when-let [file-writer-atom (:file-writer @access-log-state)]
      (when-let [writer @file-writer-atom]
        (file-writer/close! writer)))

    ;; Clear state
    (swap! access-log-state assoc
           :running? false
           :logger nil
           :file-writer nil
           :event-chan nil
           :stats-stream nil)

    (log/info "Access logging stopped")))

(defn running?
  "Check if access logging is running."
  []
  (:running? @access-log-state))

(defn get-status
  "Get access logging status."
  []
  (if (:running? @access-log-state)
    (let [file-writer-atom (:file-writer @access-log-state)]
      {:running? true
       :file-writer (when file-writer-atom
                      (when-let [writer @file-writer-atom]
                        (file-writer/get-status writer)))})
    {:running? false}))

(defn flush!
  "Flush access log buffers."
  []
  (when-let [file-writer-atom (:file-writer @access-log-state)]
    (when-let [writer @file-writer-atom]
      (file-writer/flush! writer))))
