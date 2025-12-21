(ns lb.access-log.logger
  "Access log formatters and async processing.
   Supports JSON and CLF (Common Log Format) output."
  (:require [clojure.core.async :as async :refer [go-loop <! chan sliding-buffer close!]]
            [clojure.data.json :as json]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [lb.util :as util]
            [lb.conntrack :as conntrack])
  (:import [java.time Instant ZoneOffset]
           [java.time.format DateTimeFormatter]))

;;; =============================================================================
;;; Log Entry Record
;;; =============================================================================

(defrecord AccessLogEntry
  [timestamp           ; ISO-8601 timestamp
   event-type          ; :new-conn or :conn-closed
   src-ip              ; Source IP string
   src-port            ; Source port
   dst-ip              ; Destination IP (VIP) string
   dst-port            ; Destination port
   backend-ip          ; Backend IP string
   backend-port        ; Backend port
   duration-ms         ; Connection duration in ms (nil for :new-conn)
   bytes-fwd           ; Bytes forwarded to backend
   bytes-rev           ; Bytes returned from backend
   protocol])          ; "tcp" or "udp"

;;; =============================================================================
;;; Formatters
;;; =============================================================================

(def ^:private clf-date-formatter
  (DateTimeFormatter/ofPattern "dd/MMM/yyyy:HH:mm:ss Z"))

(defn- format-clf-timestamp
  "Format timestamp in CLF format: 10/Oct/2000:13:55:36 -0700"
  [^String iso-timestamp]
  (try
    (let [instant (Instant/parse iso-timestamp)]
      (.format clf-date-formatter (.atOffset instant ZoneOffset/UTC)))
    (catch Exception _
      iso-timestamp)))

(defn format-json
  "Format an AccessLogEntry as JSON."
  [^AccessLogEntry entry]
  (json/write-str
    {:timestamp (:timestamp entry)
     :event (name (:event-type entry))
     :src {:ip (:src-ip entry) :port (:src-port entry)}
     :dst {:ip (:dst-ip entry) :port (:dst-port entry)}
     :backend {:ip (:backend-ip entry) :port (:backend-port entry)}
     :duration_ms (:duration-ms entry)
     :bytes_fwd (:bytes-fwd entry)
     :bytes_rev (:bytes-rev entry)
     :protocol (:protocol entry)}))

(defn format-clf
  "Format an AccessLogEntry in Common Log Format style.
   Format: src_ip - - [timestamp] \"event dst_ip:dst_port -> backend_ip:backend_port\" bytes_fwd/bytes_rev duration_ms"
  [^AccessLogEntry entry]
  (format "%s - - [%s] \"%s %s:%d -> %s:%d\" %d/%d %s"
          (:src-ip entry)
          (format-clf-timestamp (:timestamp entry))
          (str/upper-case (name (:event-type entry)))
          (:dst-ip entry)
          (:dst-port entry)
          (:backend-ip entry)
          (:backend-port entry)
          (or (:bytes-fwd entry) 0)
          (or (:bytes-rev entry) 0)
          (if (:duration-ms entry)
            (format "%dms" (:duration-ms entry))
            "-")))

(defn format-entry
  "Format an AccessLogEntry using the specified format."
  [format-type ^AccessLogEntry entry]
  (case format-type
    :json (format-json entry)
    :clf (format-clf entry)
    (format-json entry)))

;;; =============================================================================
;;; Event to Entry Conversion
;;; =============================================================================

(defn- get-connection-duration
  "Get connection duration in milliseconds from conntrack.
   Returns nil if not found."
  [conntrack-map event]
  (when conntrack-map
    (try
      (let [conn-key {:src-ip (:src-ip event)
                      :dst-ip (:dst-ip event)
                      :src-port (:src-port event)
                      :dst-port (:dst-port event)
                      :protocol 6}
            conn (conntrack/get-connection conntrack-map conn-key)]
        (when conn
          (long (* 1000 (conntrack/connection-age-seconds conn)))))
      (catch Exception _
        nil))))

(defn stats-event->log-entry
  "Convert a StatsEvent to an AccessLogEntry."
  [event conntrack-map]
  (let [event-type (case (:event-type event)
                     1 :new-conn
                     2 :conn-closed
                     :unknown)
        duration-ms (when (= event-type :conn-closed)
                      (get-connection-duration conntrack-map event))]
    (->AccessLogEntry
      (.toString (Instant/now))
      event-type
      (util/u32->ip-string (:src-ip event))
      (:src-port event)
      (util/u32->ip-string (:dst-ip event))
      (:dst-port event)
      (util/u32->ip-string (:target-ip event))
      (:target-port event)
      duration-ms
      (:bytes-fwd event)
      (:bytes-rev event)
      "tcp")))

;;; =============================================================================
;;; Async Logger
;;; =============================================================================

(defrecord AsyncLogger
  [input-chan           ; Channel for receiving entries
   format-type          ; :json or :clf
   output-fns           ; Vector of output functions: [(fn [line] ...)]
   running?])           ; Atom

(defn create-async-logger
  "Create an async logger that formats and writes log entries.

   output-fns: Vector of functions that accept a formatted log line string.
               Each function is called for every log entry.

   Returns an AsyncLogger record."
  [format-type output-fns & {:keys [buffer-size]
                              :or {buffer-size 10000}}]
  (let [input-chan (chan (sliding-buffer buffer-size))
        running? (atom true)
        logger (->AsyncLogger input-chan format-type output-fns running?)]

    ;; Start processing loop
    (go-loop []
      (when @running?
        (when-let [entry (<! input-chan)]
          (try
            (let [line (format-entry format-type entry)]
              (doseq [output-fn output-fns]
                (try
                  (output-fn line)
                  (catch Exception e
                    (log/debug e "Error in access log output function")))))
            (catch Exception e
              (log/debug e "Error formatting access log entry")))
          (recur))))

    logger))

(defn log-entry!
  "Submit an entry to the async logger for processing.
   Non-blocking, returns immediately."
  [^AsyncLogger logger ^AccessLogEntry entry]
  (when @(:running? logger)
    (async/put! (:input-chan logger) entry)))

(defn stop-logger!
  "Stop the async logger and close its channel."
  [^AsyncLogger logger]
  (reset! (:running? logger) false)
  (close! (:input-chan logger)))

(defn logger-running?
  "Check if the logger is running."
  [^AsyncLogger logger]
  @(:running? logger))
