(ns reverse-proxy.conntrack
  "Connection tracking management for the reverse proxy.
   Provides utilities for monitoring, cleaning, and querying connection state."
  (:require [reverse-proxy.maps :as maps]
            [reverse-proxy.util :as util]
            [clojure.tools.logging :as log]
            [clojure.core.async :as async :refer [go-loop <! >! chan timeout close!]]))

;;; =============================================================================
;;; Connection Representation
;;; =============================================================================

(defrecord Connection
  [src-ip dst-ip src-port dst-port protocol
   orig-dst-ip orig-dst-port nat-dst-ip nat-dst-port
   last-seen packets-fwd bytes-fwd packets-rev bytes-rev])

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
           :bytes-forward (:bytes-fwd conn)
           :packets-reverse (:packets-rev conn)
           :bytes-reverse (:bytes-rev conn)}
   :last-seen-ns (:last-seen conn)})

(defn raw-entry->connection
  "Convert raw map entry to Connection record."
  [{:keys [key value]}]
  (map->Connection
    (merge key value)))

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
  (let [cutoff (- current-time-ns timeout-ns)]
    (->> (get-all-connections conntrack-map)
         (filter #(< (:last-seen %) cutoff)))))

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

(defn format-connection
  "Format a connection for display."
  [^Connection conn]
  (let [proto (case (:protocol conn) 6 "TCP" 17 "UDP" (str (:protocol conn)))]
    (format "%s %s:%d -> %s:%d (NAT: %s:%d) [%d/%d pkts, %d/%d bytes]"
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
            (:bytes-rev conn))))

(defn print-connections
  "Print all connections to stdout."
  [conntrack-map]
  (let [connections (get-all-connections conntrack-map)]
    (println (format "Active connections: %d" (count connections)))
    (println "---")
    (doseq [conn (sort-by :last-seen > connections)]
      (println (format-connection conn)))))

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
