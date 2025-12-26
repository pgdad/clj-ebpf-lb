(ns lb.cluster.gossip
  "Gossip protocol implementation for state synchronization.

   Uses UDP for small messages (<1KB) and TCP for larger payloads.
   Implements push-pull anti-entropy for eventual consistency."
  (:require [lb.cluster.protocol :as proto]
            [lb.cluster.membership :as membership]
            [clojure.edn :as edn]
            [clojure.tools.logging :as log])
  (:import [java.net DatagramSocket DatagramPacket InetSocketAddress
            ServerSocket Socket SocketTimeoutException]
           [java.io BufferedReader BufferedWriter InputStreamReader OutputStreamWriter
            ByteArrayInputStream ByteArrayOutputStream]
           [java.nio.charset StandardCharsets]
           [java.util.concurrent Executors ScheduledExecutorService TimeUnit
            ExecutorService LinkedBlockingQueue]))

;;; =============================================================================
;;; Configuration
;;; =============================================================================

(def default-config
  "Default gossip configuration."
  {:bind-address "0.0.0.0"
   :bind-port 7946
   :udp-buffer-size 65535          ; Max UDP payload
   :tcp-timeout-ms 5000            ; TCP connection/read timeout
   :max-udp-message-size 1024      ; Messages larger than this use TCP
   :gossip-interval-ms 200         ; How often to gossip
   :gossip-fanout 2                ; Peers to gossip to each round
   :push-pull-interval-ms 10000    ; Full state sync interval
   :max-batch-size 100})           ; Max states per message

(defonce ^:private config (atom default-config))

(defn configure!
  "Update gossip configuration."
  [new-config]
  (swap! config merge new-config))

;;; =============================================================================
;;; State
;;; =============================================================================

;; Gossip transport state
(defonce ^:private gossip-state
  (atom {:running? false
         :udp-socket nil
         :tcp-server nil
         :executor nil
         :receiver-thread nil
         :message-queue nil
         :state-providers (atom {})}))

;;; =============================================================================
;;; Serialization
;;; =============================================================================

(defn- serialize-message
  "Serialize a gossip message to bytes."
  [msg]
  (let [m (proto/gossip-message->map msg)
        s (pr-str m)]
    (.getBytes s StandardCharsets/UTF_8)))

(defn- deserialize-message
  "Deserialize bytes to a gossip message."
  [^bytes data]
  (try
    (let [s (String. data StandardCharsets/UTF_8)
          m (edn/read-string s)]
      (proto/map->gossip-message m))
    (catch Exception e
      (log/warn "Failed to deserialize message:" (.getMessage e))
      nil)))

(defn- deserialize-message-str
  "Deserialize string to a gossip message."
  [^String s]
  (try
    (let [m (edn/read-string s)]
      (proto/map->gossip-message m))
    (catch Exception e
      (log/warn "Failed to deserialize message:" (.getMessage e))
      nil)))

;;; =============================================================================
;;; UDP Transport
;;; =============================================================================

(defn- parse-address
  "Parse 'ip:port' string to [ip port]."
  [address]
  (let [[ip port-str] (clojure.string/split address #":")]
    [ip (Integer/parseInt port-str)]))

(defn- send-udp!
  "Send a message via UDP."
  [^DatagramSocket socket address msg]
  (try
    (let [data (serialize-message msg)
          [ip port] (parse-address address)
          packet (DatagramPacket. data (count data) (InetSocketAddress. ip port))]
      (when (> (count data) (:max-udp-message-size @config))
        (log/debug "Message too large for UDP, should use TCP:" (count data) "bytes"))
      (.send socket packet)
      true)
    (catch Exception e
      (log/debug "UDP send failed to" address ":" (.getMessage e))
      false)))

(defn- receive-udp!
  "Receive a message via UDP (blocking)."
  [^DatagramSocket socket]
  (let [buffer (byte-array (:udp-buffer-size @config))
        packet (DatagramPacket. buffer (count buffer))]
    (.receive socket packet)
    (let [data (byte-array (.getLength packet))
          _ (System/arraycopy (.getData packet) 0 data 0 (.getLength packet))
          sender-addr (str (.getHostAddress (.getAddress packet)) ":" (.getPort packet))]
      {:data data :sender-addr sender-addr})))

;;; =============================================================================
;;; TCP Transport (for large messages)
;;; =============================================================================

(defn- send-tcp!
  "Send a message via TCP."
  [address msg]
  (try
    (let [[ip port] (parse-address address)
          socket (Socket.)]
      (.connect socket (InetSocketAddress. ip port) (:tcp-timeout-ms @config))
      (.setSoTimeout socket (:tcp-timeout-ms @config))
      (try
        (let [out (BufferedWriter. (OutputStreamWriter. (.getOutputStream socket) StandardCharsets/UTF_8))
              data (pr-str (proto/gossip-message->map msg))]
          (.write out data)
          (.write out "\n")
          (.flush out)
          true)
        (finally
          (.close socket))))
    (catch Exception e
      (log/debug "TCP send failed to" address ":" (.getMessage e))
      false)))

(defn- handle-tcp-connection!
  "Handle an incoming TCP connection."
  [^Socket client-socket message-handler]
  (try
    (.setSoTimeout client-socket (:tcp-timeout-ms @config))
    (let [in (BufferedReader. (InputStreamReader. (.getInputStream client-socket) StandardCharsets/UTF_8))
          line (.readLine in)]
      (when line
        (when-let [msg (deserialize-message-str line)]
          (message-handler msg))))
    (catch SocketTimeoutException e
      (log/debug "TCP read timeout"))
    (catch Exception e
      (log/debug "Error handling TCP connection:" (.getMessage e)))
    (finally
      (try (.close client-socket) (catch Exception _)))))

(defn- tcp-accept-loop!
  "Accept incoming TCP connections."
  [^ServerSocket server message-handler]
  (while (and (:running? @gossip-state) (not (.isClosed server)))
    (try
      (let [client (.accept server)]
        ;; Handle in a virtual thread for non-blocking
        (Thread/startVirtualThread #(handle-tcp-connection! client message-handler)))
      (catch SocketTimeoutException e
        ;; Expected, allows checking running? flag
        )
      (catch Exception e
        (when (:running? @gossip-state)
          (log/error e "Error accepting TCP connection"))))))

;;; =============================================================================
;;; Message Sending
;;; =============================================================================

(defn send-message!
  "Send a gossip message to a peer. Uses UDP for small messages, TCP for large."
  [address msg]
  (let [data (serialize-message msg)
        size (count data)]
    (if (<= size (:max-udp-message-size @config))
      (when-let [socket (:udp-socket @gossip-state)]
        (send-udp! socket address msg))
      (send-tcp! address msg))))

(defn broadcast-message!
  "Broadcast a message to all alive peers."
  [msg]
  (let [node-id (membership/get-node-id)
        alive (membership/get-alive-nodes)]
    (doseq [peer-id (disj alive node-id)]
      (when-let [peer-info (membership/get-node-info peer-id)]
        (send-message! (:address peer-info) msg)))))

(defn gossip-to-random!
  "Gossip a message to random subset of peers."
  [msg]
  (let [node-id (membership/get-node-id)
        alive (membership/get-alive-nodes)
        peers (disj alive node-id)
        fanout (:gossip-fanout @config)
        selected (take fanout (shuffle (vec peers)))]
    (doseq [peer-id selected]
      (when-let [peer-info (membership/get-node-info peer-id)]
        (send-message! (:address peer-info) msg)))))

;;; =============================================================================
;;; State Providers
;;; =============================================================================

(defn register-state-provider!
  "Register a state provider for synchronization."
  [provider]
  (let [type (proto/provider-type provider)]
    (swap! (:state-providers @gossip-state) assoc type provider)
    (log/info "Registered state provider:" type)))

(defn unregister-state-provider!
  "Unregister a state provider."
  [type]
  (swap! (:state-providers @gossip-state) dissoc type))

(defn get-state-providers
  "Get all registered state providers."
  []
  @(:state-providers @gossip-state))

(defn get-all-sync-states
  "Get all syncable states from all providers."
  []
  (reduce
    (fn [states [_ provider]]
      (into states (proto/get-sync-state provider)))
    []
    @(:state-providers @gossip-state)))

(defn get-state-digest
  "Get combined state digest from all providers."
  []
  (reduce
    (fn [digest [_ provider]]
      (merge digest (proto/get-state-digest provider)))
    {}
    @(:state-providers @gossip-state)))

(defn apply-remote-states!
  "Apply received remote states to appropriate providers."
  [states]
  (let [by-type (group-by :state-type states)
        providers @(:state-providers @gossip-state)]
    (doseq [[type type-states] by-type]
      (when-let [provider (get providers type)]
        (try
          (proto/apply-remote-state provider type-states)
          (catch Exception e
            (log/error e "Error applying remote state for" type)))))))

;;; =============================================================================
;;; Anti-Entropy (Push-Pull Sync)
;;; =============================================================================

(defn- do-push-pull!
  "Perform push-pull sync with a random peer."
  []
  (when (:running? @gossip-state)
    (let [node-id (membership/get-node-id)
          alive (membership/get-alive-nodes)
          peers (disj alive node-id)]
      (when (seq peers)
        (let [peer-id (rand-nth (vec peers))]
          (when-let [peer-info (membership/get-node-info peer-id)]
            (let [states (get-all-sync-states)
                  digest (get-state-digest)
                  msg (proto/push-pull-message node-id states digest)]
              (log/debug "Push-pull sync with" peer-id "states:" (count states))
              (send-message! (:address peer-info) msg))))))))

;;; =============================================================================
;;; Rumor Mongering (Immediate Propagation)
;;; =============================================================================

(defn broadcast-state-change!
  "Immediately broadcast a state change to peers."
  [state]
  (let [msg (proto/push-message (membership/get-node-id) [state])]
    (gossip-to-random! msg)))

(defn broadcast-states!
  "Broadcast multiple state changes to peers."
  [states]
  (when (seq states)
    (let [msg (proto/push-message (membership/get-node-id) states)]
      (gossip-to-random! msg))))

;;; =============================================================================
;;; Message Handling
;;; =============================================================================

(defn- handle-push!
  "Handle push message with state updates."
  [{:keys [states]}]
  (when (seq states)
    (log/debug "Received push with" (count states) "states")
    (doseq [state states]
      (proto/update-clock! (:version state)))
    (apply-remote-states! states)))

(defn- handle-pull!
  "Handle pull message, respond with requested states."
  [{:keys [sender digest]} sender-addr]
  (let [our-states (get-all-sync-states)
        ;; Filter to states newer than what peer has
        newer-states (filter
                       (fn [state]
                         (let [key (proto/state-key state)
                               peer-version (get digest key 0)]
                           (> (:version state) peer-version)))
                       our-states)]
    (when (seq newer-states)
      (let [msg (proto/push-message (membership/get-node-id) newer-states)]
        (send-message! sender-addr msg)))))

(defn- handle-push-pull!
  "Handle push-pull message for bidirectional sync."
  [{:keys [sender states digest]} sender-addr]
  ;; Apply incoming states
  (handle-push! {:states states})
  ;; Respond with our states that are newer
  (handle-pull! {:sender sender :digest digest} sender-addr))

(defn- handle-gossip-message!
  "Handle an incoming gossip message."
  [msg sender-addr]
  (let [send-fn (fn [addr m] (send-message! addr m))]
    (case (:msg-type msg)
      ;; State sync messages
      :push (handle-push! msg)
      :pull (handle-pull! msg sender-addr)
      :push-pull (handle-push-pull! msg sender-addr)

      ;; Membership messages - delegate to membership module
      (:ping :ping-ack :ping-req :join :leave :suspect :alive)
      (when-let [response (membership/handle-message! msg send-fn)]
        (send-message! sender-addr response))

      ;; Unknown message type
      (log/warn "Unknown message type:" (:msg-type msg)))))

;;; =============================================================================
;;; Message Receiver
;;; =============================================================================

(defn- udp-receive-loop!
  "Receive and process UDP messages."
  [^DatagramSocket socket]
  (while (and (:running? @gossip-state) (not (.isClosed socket)))
    (try
      (let [{:keys [data sender-addr]} (receive-udp! socket)]
        (when-let [msg (deserialize-message data)]
          ;; Process in virtual thread to not block receiver
          (Thread/startVirtualThread #(handle-gossip-message! msg sender-addr))))
      (catch SocketTimeoutException e
        ;; Expected, allows checking running? flag
        )
      (catch Exception e
        (when (:running? @gossip-state)
          (log/error e "Error receiving UDP message"))))))

;;; =============================================================================
;;; Periodic Tasks
;;; =============================================================================

(defn- gossip-tick!
  "One tick of the gossip loop - push states to random peers."
  []
  (try
    (when (:running? @gossip-state)
      (let [states (get-all-sync-states)]
        (when (seq states)
          ;; Batch states for efficiency
          (let [batches (partition-all (:max-batch-size @config) states)]
            (doseq [batch batches]
              (broadcast-states! batch))))))
    (catch Exception e
      (log/error e "Error in gossip tick"))))

;;; =============================================================================
;;; Lifecycle
;;; =============================================================================

(defn start!
  "Start the gossip transport."
  []
  (when-not (:running? @gossip-state)
    (let [cfg @config
          bind-addr (:bind-address cfg)
          bind-port (:bind-port cfg)
          inet-addr (java.net.InetAddress/getByName bind-addr)
          ;; Create UDP socket
          udp-socket (DatagramSocket. bind-port inet-addr)
          _ (.setSoTimeout udp-socket 1000)  ; 1s timeout for clean shutdown
          ;; Create TCP server
          tcp-server (ServerSocket.)
          _ (.setReuseAddress tcp-server true)
          _ (.bind tcp-server (InetSocketAddress. inet-addr bind-port))
          _ (.setSoTimeout tcp-server 1000)
          ;; Create executor for periodic tasks
          executor (Executors/newScheduledThreadPool 2)]

      (swap! gossip-state assoc
             :running? true
             :udp-socket udp-socket
             :tcp-server tcp-server
             :executor executor
             :state-providers (atom {}))

      ;; Start UDP receiver thread
      (let [receiver-thread (Thread. #(udp-receive-loop! udp-socket))]
        (.setDaemon receiver-thread true)
        (.setName receiver-thread "gossip-udp-receiver")
        (.start receiver-thread)
        (swap! gossip-state assoc :receiver-thread receiver-thread))

      ;; Start TCP accept thread
      (let [tcp-thread (Thread. #(tcp-accept-loop! tcp-server handle-gossip-message!))]
        (.setDaemon tcp-thread true)
        (.setName tcp-thread "gossip-tcp-acceptor")
        (.start tcp-thread))

      ;; Schedule periodic gossip
      (.scheduleAtFixedRate executor
                            #(gossip-tick!)
                            (:gossip-interval-ms cfg)
                            (:gossip-interval-ms cfg)
                            TimeUnit/MILLISECONDS)

      ;; Schedule periodic push-pull sync
      (.scheduleAtFixedRate executor
                            #(do-push-pull!)
                            (:push-pull-interval-ms cfg)
                            (:push-pull-interval-ms cfg)
                            TimeUnit/MILLISECONDS)

      (log/info "Gossip transport started on" (str bind-addr ":" bind-port)))
    true))

(defn stop!
  "Stop the gossip transport."
  []
  (when (:running? @gossip-state)
    (swap! gossip-state assoc :running? false)

    ;; Shutdown executor
    (when-let [executor (:executor @gossip-state)]
      (.shutdown executor)
      (try
        (.awaitTermination executor 5 TimeUnit/SECONDS)
        (catch InterruptedException _)))

    ;; Close sockets
    (when-let [udp (:udp-socket @gossip-state)]
      (try (.close udp) (catch Exception _)))
    (when-let [tcp (:tcp-server @gossip-state)]
      (try (.close tcp) (catch Exception _)))

    (swap! gossip-state assoc
           :udp-socket nil
           :tcp-server nil
           :executor nil)

    (log/info "Gossip transport stopped")))

(defn running?
  "Check if gossip transport is running."
  []
  (:running? @gossip-state))

(defn gossip-stats
  "Get gossip statistics."
  []
  {:running? (:running? @gossip-state)
   :provider-count (count @(:state-providers @gossip-state))
   :config @config})
