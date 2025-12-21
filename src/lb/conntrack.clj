(ns lb.conntrack
  "Connection tracking management for the load balancer.
   Provides utilities for monitoring, cleaning, and querying connection state."
  (:require [lb.maps :as maps]
            [lb.util :as util]
            [clojure.tools.logging :as log]
            [clojure.core.async :as async :refer [go-loop <! >! chan timeout close!]]))

;;; =============================================================================
;;; Connection Representation
;;; =============================================================================

(defrecord Connection
  [src-ip dst-ip src-port dst-port protocol
   orig-dst-ip orig-dst-port nat-dst-ip nat-dst-port
   created-ns last-seen packets-fwd packets-rev bytes-fwd bytes-rev])

(defn connection->map
  "Convert a Connection to a human-readable map."
  [^Connection conn]
  {:source {:ip (util/u32->ip-string (:src-ip conn))
            :port (:src-port conn)}
   :destination {:ip (util/u32->ip-string (:dst-ip conn))
                 :port (:dst-port conn)}
   :protocol (case (:protocol conn)
               6 :tcp
               17 :udp
               (:protocol conn))
   :nat {:original-dst {:ip (util/u32->ip-string (:orig-dst-ip conn))
                        :port (:orig-dst-port conn)}
         :nat-dst {:ip (util/u32->ip-string (:nat-dst-ip conn))
                   :port (:nat-dst-port conn)}}
   :stats {:packets-forward (:packets-fwd conn)
           :packets-reverse (:packets-rev conn)
           :bytes-forward (:bytes-fwd conn)
           :bytes-reverse (:bytes-rev conn)}
   :created-ns (:created-ns conn)
   :last-seen-ns (:last-seen conn)})

(defn raw-entry->connection
  "Convert raw map entry to Connection record."
  [{:keys [key value]}]
  (map->Connection
    (merge key value)))

;;; =============================================================================
;;; Connection Age and Time Helpers
;;; =============================================================================

(defn connection-age-ns
  "Get the age of a connection in nanoseconds.
   Returns nil if created-ns is 0 (not set)."
  [^Connection conn current-time-ns]
  (let [created (:created-ns conn)]
    (when (and created (pos? created))
      (- current-time-ns created))))

(defn connection-age-seconds
  "Get the age of a connection in seconds."
  [^Connection conn current-time-ns]
  (when-let [age-ns (connection-age-ns conn current-time-ns)]
    (/ age-ns 1000000000.0)))

(defn connection-idle-ns
  "Get the idle time of a connection in nanoseconds (time since last packet)."
  [^Connection conn current-time-ns]
  (let [last-seen (:last-seen conn)]
    (when (and last-seen (pos? last-seen))
      (- current-time-ns last-seen))))

(defn connection-idle-seconds
  "Get the idle time of a connection in seconds."
  [^Connection conn current-time-ns]
  (when-let [idle-ns (connection-idle-ns conn current-time-ns)]
    (/ idle-ns 1000000000.0)))

(defn connection-expired?
  "Check if a connection has expired based on idle timeout."
  [^Connection conn current-time-ns timeout-ns]
  (let [idle (connection-idle-ns conn current-time-ns)]
    (and idle (> idle timeout-ns))))

;;; =============================================================================
;;; Connection Queries
;;; =============================================================================

(defn get-all-connections
  "Get all active connections as Connection records."
  [conntrack-map]
  (->> (maps/list-connections conntrack-map)
       (map raw-entry->connection)))

(defn get-connection
  "Get a specific connection by 5-tuple."
  [conntrack-map {:keys [src-ip dst-ip src-port dst-port protocol]}]
  (when-let [value (maps/lookup-connection conntrack-map
                     {:src-ip src-ip
                      :dst-ip dst-ip
                      :src-port src-port
                      :dst-port dst-port
                      :protocol protocol})]
    (map->Connection
      (merge {:src-ip src-ip :dst-ip dst-ip
              :src-port src-port :dst-port dst-port
              :protocol protocol}
             value))))

(defn count-connections
  "Get the number of active connections."
  [conntrack-map]
  (count (maps/list-connections conntrack-map)))

(defn get-connections-by-source
  "Get all connections from a specific source IP."
  [conntrack-map src-ip]
  (let [src-ip-u32 (if (string? src-ip)
                     (util/ip-string->u32 src-ip)
                     src-ip)]
    (->> (get-all-connections conntrack-map)
         (filter #(= (:src-ip %) src-ip-u32)))))

(defn get-connections-by-target
  "Get all connections to a specific NAT target."
  [conntrack-map target-ip]
  (let [target-ip-u32 (if (string? target-ip)
                        (util/ip-string->u32 target-ip)
                        target-ip)]
    (->> (get-all-connections conntrack-map)
         (filter #(= (:nat-dst-ip %) target-ip-u32)))))

;;; =============================================================================
;;; Connection Cleanup
;;; =============================================================================

(defn get-stale-connections
  "Get connections that haven't been seen within the timeout period."
  [conntrack-map current-time-ns timeout-ns]
  (->> (get-all-connections conntrack-map)
       (filter #(connection-expired? % current-time-ns timeout-ns))))

(defn cleanup-stale-connections!
  "Remove connections older than the timeout.

   Returns the number of connections removed."
  [conntrack-map timeout-seconds]
  (let [current-ns (System/nanoTime)
        timeout-ns (* timeout-seconds 1000000000)
        stale (get-stale-connections conntrack-map current-ns timeout-ns)]
    (doseq [conn stale]
      (maps/delete-connection conntrack-map
        {:src-ip (:src-ip conn)
         :dst-ip (:dst-ip conn)
         :src-port (:src-port conn)
         :dst-port (:dst-port conn)
         :protocol (:protocol conn)}))
    (let [count (count stale)]
      (when (pos? count)
        (log/info "Cleaned up" count "stale connections"))
      count)))

(defn clear-all-connections!
  "Remove all connections from the tracking map.

   Returns the number of connections removed."
  [conntrack-map]
  (let [connections (get-all-connections conntrack-map)
        count (count connections)]
    (doseq [conn connections]
      (maps/delete-connection conntrack-map
        {:src-ip (:src-ip conn)
         :dst-ip (:dst-ip conn)
         :src-port (:src-port conn)
         :dst-port (:dst-port conn)
         :protocol (:protocol conn)}))
    (log/info "Cleared" count "connections")
    count))

;;; =============================================================================
;;; Connection Cleanup Daemon
;;; =============================================================================

(defn start-cleanup-daemon
  "Start a background daemon that periodically cleans up stale connections.

   Returns a control map with :stop-fn to stop the daemon."
  [conntrack-map settings-map & {:keys [interval-seconds]
                                  :or {interval-seconds 60}}]
  (let [stop-chan (chan)
        daemon-thread
        (Thread.
          (fn []
            (log/info "Connection cleanup daemon started")
            (loop []
              (let [[_ ch] (async/alts!! [stop-chan (timeout (* interval-seconds 1000))])]
                (when-not (= ch stop-chan)
                  (try
                    (let [timeout-sec (or (maps/get-connection-timeout settings-map) 300)]
                      (cleanup-stale-connections! conntrack-map timeout-sec))
                    (catch Exception e
                      (log/error e "Error during connection cleanup")))
                  (recur))))
            (log/info "Connection cleanup daemon stopped")))]
    (.start daemon-thread)
    {:thread daemon-thread
     :stop-chan stop-chan
     :stop-fn (fn []
                (async/>!! stop-chan :stop)
                (.join daemon-thread 5000))}))

(defn stop-cleanup-daemon
  "Stop the cleanup daemon."
  [{:keys [stop-fn]}]
  (when stop-fn
    (stop-fn)))

;;; =============================================================================
;;; Connection Statistics
;;; =============================================================================

(defn aggregate-stats
  "Aggregate statistics across all connections."
  [conntrack-map]
  (let [connections (get-all-connections conntrack-map)]
    {:total-connections (count connections)
     :total-packets-forward (reduce + 0 (map :packets-fwd connections))
     :total-bytes-forward (reduce + 0 (map :bytes-fwd connections))
     :total-packets-reverse (reduce + 0 (map :packets-rev connections))
     :total-bytes-reverse (reduce + 0 (map :bytes-rev connections))}))

(defn stats-by-source
  "Aggregate statistics grouped by source IP."
  [conntrack-map]
  (->> (get-all-connections conntrack-map)
       (group-by :src-ip)
       (map (fn [[ip conns]]
              {:source-ip (util/u32->ip-string ip)
               :connection-count (count conns)
               :packets-forward (reduce + 0 (map :packets-fwd conns))
               :bytes-forward (reduce + 0 (map :bytes-fwd conns))
               :packets-reverse (reduce + 0 (map :packets-rev conns))
               :bytes-reverse (reduce + 0 (map :bytes-rev conns))}))
       (sort-by :connection-count >)))

(defn stats-by-target
  "Aggregate statistics grouped by NAT target."
  [conntrack-map]
  (->> (get-all-connections conntrack-map)
       (group-by :nat-dst-ip)
       (map (fn [[ip conns]]
              {:target-ip (util/u32->ip-string ip)
               :connection-count (count conns)
               :packets-forward (reduce + 0 (map :packets-fwd conns))
               :bytes-forward (reduce + 0 (map :bytes-fwd conns))
               :packets-reverse (reduce + 0 (map :packets-rev conns))
               :bytes-reverse (reduce + 0 (map :bytes-rev conns))}))
       (sort-by :connection-count >)))

(defn stats-by-protocol
  "Aggregate statistics grouped by protocol."
  [conntrack-map]
  (->> (get-all-connections conntrack-map)
       (group-by :protocol)
       (map (fn [[proto conns]]
              {:protocol (case proto 6 :tcp 17 :udp proto)
               :connection-count (count conns)
               :packets-forward (reduce + 0 (map :packets-fwd conns))
               :bytes-forward (reduce + 0 (map :bytes-fwd conns))
               :packets-reverse (reduce + 0 (map :packets-rev conns))
               :bytes-reverse (reduce + 0 (map :bytes-rev conns))}))))

;;; =============================================================================
;;; Connection Display
;;; =============================================================================

(defn format-duration
  "Format a duration in seconds to a human-readable string."
  [seconds]
  (cond
    (nil? seconds) "N/A"
    (< seconds 60) (format "%.1fs" (double seconds))
    (< seconds 3600) (format "%.1fm" (/ seconds 60.0))
    :else (format "%.1fh" (/ seconds 3600.0))))

(defn format-connection
  "Format a connection for display."
  ([^Connection conn]
   (format-connection conn (System/nanoTime)))
  ([^Connection conn current-time-ns]
   (let [proto (case (:protocol conn) 6 "TCP" 17 "UDP" (str (:protocol conn)))
         age-sec (connection-age-seconds conn current-time-ns)
         idle-sec (connection-idle-seconds conn current-time-ns)]
     (format "%s %s:%d -> %s:%d (NAT: %s:%d) [%d/%d pkts, %d/%d bytes] age=%s idle=%s"
             proto
             (util/u32->ip-string (:src-ip conn))
             (:src-port conn)
             (util/u32->ip-string (:orig-dst-ip conn))
             (:orig-dst-port conn)
             (util/u32->ip-string (:nat-dst-ip conn))
             (:nat-dst-port conn)
             (:packets-fwd conn)
             (:packets-rev conn)
             (:bytes-fwd conn)
             (:bytes-rev conn)
             (format-duration age-sec)
             (format-duration idle-sec)))))

(defn print-connections
  "Print all connections to stdout."
  [conntrack-map]
  (let [connections (get-all-connections conntrack-map)
        current-ns (System/nanoTime)]
    (println (format "Active connections: %d" (count connections)))
    (println "---")
    (doseq [conn (sort-by :last-seen > connections)]
      (println (format-connection conn current-ns)))))

(defn print-connection-stats
  "Print aggregated connection statistics."
  [conntrack-map]
  (let [stats (aggregate-stats conntrack-map)]
    (println "Connection Statistics")
    (println "=====================")
    (println (format "Total connections:    %d" (:total-connections stats)))
    (println (format "Packets (fwd/rev):    %d / %d"
                     (:total-packets-forward stats)
                     (:total-packets-reverse stats)))
    (println (format "Bytes (fwd/rev):      %d / %d"
                     (:total-bytes-forward stats)
                     (:total-bytes-reverse stats)))))
