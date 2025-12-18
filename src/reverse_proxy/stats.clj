(ns reverse-proxy.stats
  "Statistics streaming and aggregation for the reverse proxy.
   Consumes events from the eBPF ring buffer and provides real-time stats."
  (:require [clj-ebpf.core :as bpf]
            [reverse-proxy.util :as util]
            [reverse-proxy.maps :as maps]
            [clojure.tools.logging :as log]
            [clojure.core.async :as async :refer [go go-loop <! >! >!! <!! chan
                                                  sliding-buffer close! timeout
                                                  mult tap untap]]))

;;; =============================================================================
;;; Event Types
;;; =============================================================================

(def event-types
  "Event type codes."
  {:new-conn 1
   :conn-closed 2
   :periodic-stats 3})

(def event-type-names
  "Reverse mapping of event types."
  {1 :new-conn
   2 :conn-closed
   3 :periodic-stats})

;;; =============================================================================
;;; Event Record
;;; =============================================================================

(defrecord StatsEvent
  [event-type timestamp
   src-ip dst-ip src-port dst-port
   target-ip target-port
   packets-fwd bytes-fwd packets-rev bytes-rev])

(defn event->map
  "Convert a StatsEvent to a human-readable map."
  [^StatsEvent event]
  {:event-type (:event-type event)
   :timestamp (:timestamp event)
   :source {:ip (util/u32->ip-string (:src-ip event))
            :port (:src-port event)}
   :destination {:ip (util/u32->ip-string (:dst-ip event))
                 :port (:dst-port event)}
   :target {:ip (util/u32->ip-string (:target-ip event))
            :port (:target-port event)}
   :stats {:packets-forward (:packets-fwd event)
           :bytes-forward (:bytes-fwd event)
           :packets-reverse (:packets-rev event)
           :bytes-reverse (:bytes-rev event)}})

(defn parse-event
  "Parse raw event bytes into a StatsEvent record."
  [^bytes event-bytes]
  (let [parsed (util/decode-stats-event event-bytes)]
    (map->StatsEvent parsed)))

;;; =============================================================================
;;; Ring Buffer Consumer
;;; =============================================================================

(defn start-ringbuf-consumer
  "Start consuming events from the stats ring buffer.

   Returns a map with:
     :channel - core.async channel that receives parsed events
     :stop-fn - function to stop the consumer

   Options:
     :buffer-size - channel buffer size (default 1000)
     :filter-fn - optional function to filter events"
  [stats-ringbuf & {:keys [buffer-size filter-fn]
                    :or {buffer-size 1000}}]
  (log/info "Starting ring buffer consumer")
  (let [event-chan (chan (sliding-buffer buffer-size))
        running (atom true)
        consumer-thread
        (Thread.
          (fn []
            (try
              (bpf/with-ringbuf-consumer [consumer stats-ringbuf]
                (while @running
                  (bpf/process-events consumer
                    (fn [event-data]
                      (try
                        (let [event (parse-event event-data)]
                          (when (or (nil? filter-fn)
                                    (filter-fn event))
                            (>!! event-chan event)))
                        (catch Exception e
                          (log/warn e "Error parsing ring buffer event")))))))
              (catch Exception e
                (log/error e "Ring buffer consumer error"))
              (finally
                (close! event-chan)
                (log/info "Ring buffer consumer stopped")))))]
    (.start consumer-thread)
    {:channel event-chan
     :thread consumer-thread
     :running running
     :stop-fn (fn []
                (reset! running false)
                (.interrupt consumer-thread)
                (.join consumer-thread 2000))}))

(defn stop-ringbuf-consumer
  "Stop the ring buffer consumer."
  [{:keys [stop-fn]}]
  (when stop-fn
    (stop-fn)))

;;; =============================================================================
;;; Event Streaming
;;; =============================================================================

(defn create-event-stream
  "Create a multiplexed event stream from the ring buffer.

   Returns a map with:
     :mult - core.async mult for subscribing
     :stop-fn - function to stop streaming"
  [stats-ringbuf & opts]
  (let [consumer (apply start-ringbuf-consumer stats-ringbuf opts)
        m (mult (:channel consumer))]
    {:mult m
     :consumer consumer
     :stop-fn (:stop-fn consumer)}))

(defn subscribe-to-stream
  "Subscribe to an event stream.

   Returns a channel that receives events."
  [{:keys [mult]} & {:keys [buffer-size] :or {buffer-size 100}}]
  (let [ch (chan (sliding-buffer buffer-size))]
    (tap mult ch)
    ch))

(defn unsubscribe-from-stream
  "Unsubscribe from an event stream."
  [{:keys [mult]} ch]
  (untap mult ch)
  (close! ch))

(defn stop-event-stream
  "Stop the event stream."
  [{:keys [stop-fn]}]
  (when stop-fn
    (stop-fn)))

;;; =============================================================================
;;; Event Handlers
;;; =============================================================================

(defn on-new-connection
  "Handle new connection event."
  [event callback]
  (when (= (:event-type event) :new-conn)
    (callback event)))

(defn on-connection-closed
  "Handle connection closed event."
  [event callback]
  (when (= (:event-type event) :conn-closed)
    (callback event)))

(defn on-periodic-stats
  "Handle periodic stats event."
  [event callback]
  (when (= (:event-type event) :periodic-stats)
    (callback event)))

(defn process-events-with-handlers
  "Process events from a channel with handler functions.

   handlers is a map of:
     :on-new-conn - function called for new connection events
     :on-closed - function called for connection closed events
     :on-stats - function called for periodic stats events
     :on-any - function called for all events"
  [event-chan {:keys [on-new-conn on-closed on-stats on-any]}]
  (go-loop []
    (when-let [event (<! event-chan)]
      (try
        (when on-any (on-any event))
        (case (:event-type event)
          :new-conn (when on-new-conn (on-new-conn event))
          :conn-closed (when on-closed (on-closed event))
          :periodic-stats (when on-stats (on-stats event))
          nil)
        (catch Exception e
          (log/warn e "Error in event handler")))
      (recur))))

;;; =============================================================================
;;; Statistics Aggregation
;;; =============================================================================

(defn create-stats-aggregator
  "Create a statistics aggregator that tracks metrics over time.

   Returns a map with:
     :stats - atom containing current aggregated stats
     :channel - channel to send events to
     :stop-fn - function to stop the aggregator"
  []
  (let [stats (atom {:total-events 0
                     :new-connections 0
                     :closed-connections 0
                     :total-packets-fwd 0
                     :total-bytes-fwd 0
                     :total-packets-rev 0
                     :total-bytes-rev 0
                     :by-source {}
                     :by-target {}
                     :start-time (System/currentTimeMillis)})
        event-chan (chan 1000)
        running (atom true)]

    ;; Aggregation loop
    (go-loop []
      (when @running
        (when-let [event (<! event-chan)]
          (swap! stats
            (fn [s]
              (let [src-key (str (util/u32->ip-string (:src-ip event)))
                    tgt-key (str (util/u32->ip-string (:target-ip event)))]
                (-> s
                    (update :total-events inc)
                    (update (case (:event-type event)
                              :new-conn :new-connections
                              :conn-closed :closed-connections
                              :total-events) inc)
                    (update :total-packets-fwd + (or (:packets-fwd event) 0))
                    (update :total-bytes-fwd + (or (:bytes-fwd event) 0))
                    (update :total-packets-rev + (or (:packets-rev event) 0))
                    (update :total-bytes-rev + (or (:bytes-rev event) 0))
                    (update-in [:by-source src-key :events] (fnil inc 0))
                    (update-in [:by-source src-key :bytes]
                               (fnil + 0) (+ (or (:bytes-fwd event) 0)
                                             (or (:bytes-rev event) 0)))
                    (update-in [:by-target tgt-key :events] (fnil inc 0))
                    (update-in [:by-target tgt-key :bytes]
                               (fnil + 0) (+ (or (:bytes-fwd event) 0)
                                             (or (:bytes-rev event) 0)))))))
          (recur))))

    {:stats stats
     :channel event-chan
     :stop-fn (fn []
                (reset! running false)
                (close! event-chan))}))

(defn get-aggregated-stats
  "Get current aggregated statistics."
  [{:keys [stats]}]
  @stats)

(defn reset-aggregated-stats
  "Reset aggregated statistics."
  [{:keys [stats]}]
  (reset! stats {:total-events 0
                 :new-connections 0
                 :closed-connections 0
                 :total-packets-fwd 0
                 :total-bytes-fwd 0
                 :total-packets-rev 0
                 :total-bytes-rev 0
                 :by-source {}
                 :by-target {}
                 :start-time (System/currentTimeMillis)}))

(defn stop-stats-aggregator
  "Stop the statistics aggregator."
  [{:keys [stop-fn]}]
  (when stop-fn
    (stop-fn)))

;;; =============================================================================
;;; Rate Calculation
;;; =============================================================================

(defn create-rate-calculator
  "Create a rate calculator that computes events/packets/bytes per second.

   Returns a map with:
     :rates - atom containing current rates
     :channel - channel to send events to
     :stop-fn - function to stop the calculator

   Options:
     :window-ms - time window for rate calculation (default 1000ms)"
  [& {:keys [window-ms] :or {window-ms 1000}}]
  (let [rates (atom {:events-per-sec 0
                     :packets-per-sec 0
                     :bytes-per-sec 0
                     :last-update (System/currentTimeMillis)})
        window-events (atom [])
        event-chan (chan 10000)
        running (atom true)]

    ;; Rate calculation loop
    (go-loop []
      (when @running
        (<! (timeout (/ window-ms 10)))  ; Update 10x per window
        (let [now (System/currentTimeMillis)
              cutoff (- now window-ms)
              current-events @window-events
              recent (filter #(> (:time %) cutoff) current-events)]

          ;; Update window
          (reset! window-events (vec recent))

          ;; Calculate rates
          (let [event-count (count recent)
                packet-count (reduce + 0 (map #(+ (or (:packets-fwd %) 0)
                                                   (or (:packets-rev %) 0))
                                              recent))
                byte-count (reduce + 0 (map #(+ (or (:bytes-fwd %) 0)
                                                 (or (:bytes-rev %) 0))
                                            recent))
                seconds (/ window-ms 1000.0)]
            (reset! rates {:events-per-sec (/ event-count seconds)
                           :packets-per-sec (/ packet-count seconds)
                           :bytes-per-sec (/ byte-count seconds)
                           :last-update now})))
        (recur)))

    ;; Event ingestion loop
    (go-loop []
      (when @running
        (when-let [event (<! event-chan)]
          (swap! window-events conj
                 (assoc event :time (System/currentTimeMillis)))
          (recur))))

    {:rates rates
     :channel event-chan
     :stop-fn (fn []
                (reset! running false)
                (close! event-chan))}))

(defn get-current-rates
  "Get current rate calculations."
  [{:keys [rates]}]
  @rates)

(defn stop-rate-calculator
  "Stop the rate calculator."
  [{:keys [stop-fn]}]
  (when stop-fn
    (stop-fn)))

;;; =============================================================================
;;; Convenience Functions
;;; =============================================================================

(defn enable-stats-collection
  "Enable statistics collection in the eBPF program."
  [settings-map]
  (maps/enable-stats settings-map))

(defn disable-stats-collection
  "Disable statistics collection in the eBPF program."
  [settings-map]
  (maps/disable-stats settings-map))

(defn stats-collection-enabled?
  "Check if statistics collection is enabled."
  [settings-map]
  (maps/stats-enabled? settings-map))

;;; =============================================================================
;;; Display Functions
;;; =============================================================================

(defn format-event
  "Format an event for display."
  [event]
  (format "[%s] %s:%d -> %s:%d (target: %s:%d) [%d/%d pkts, %d/%d bytes]"
          (name (:event-type event))
          (util/u32->ip-string (:src-ip event))
          (:src-port event)
          (util/u32->ip-string (:dst-ip event))
          (:dst-port event)
          (util/u32->ip-string (:target-ip event))
          (:target-port event)
          (:packets-fwd event)
          (:packets-rev event)
          (:bytes-fwd event)
          (:bytes-rev event)))

(defn print-event
  "Print an event to stdout."
  [event]
  (println (format-event event)))

(defn print-rates
  "Print current rates."
  [rate-calc]
  (let [{:keys [events-per-sec packets-per-sec bytes-per-sec]} (get-current-rates rate-calc)]
    (println (format "Rates: %.1f events/s, %.1f packets/s, %.1f bytes/s"
                     (double events-per-sec)
                     (double packets-per-sec)
                     (double bytes-per-sec)))))

(defn print-aggregated-stats
  "Print aggregated statistics."
  [aggregator]
  (let [stats (get-aggregated-stats aggregator)
        runtime-sec (/ (- (System/currentTimeMillis) (:start-time stats)) 1000.0)]
    (println "Aggregated Statistics")
    (println "=====================")
    (println (format "Runtime:              %.1f seconds" runtime-sec))
    (println (format "Total events:         %d" (:total-events stats)))
    (println (format "New connections:      %d" (:new-connections stats)))
    (println (format "Closed connections:   %d" (:closed-connections stats)))
    (println (format "Packets (fwd/rev):    %d / %d"
                     (:total-packets-fwd stats)
                     (:total-packets-rev stats)))
    (println (format "Bytes (fwd/rev):      %d / %d"
                     (:total-bytes-fwd stats)
                     (:total-bytes-rev stats)))
    (println)
    (println "Top sources:")
    (doseq [[src data] (take 5 (sort-by (comp - :events second) (:by-source stats)))]
      (println (format "  %s: %d events, %d bytes" src (:events data) (:bytes data))))
    (println)
    (println "Top targets:")
    (doseq [[tgt data] (take 5 (sort-by (comp - :events second) (:by-target stats)))]
      (println (format "  %s: %d events, %d bytes" tgt (:events data) (:bytes data))))))
