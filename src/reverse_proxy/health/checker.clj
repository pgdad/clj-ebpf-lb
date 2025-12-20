(ns reverse-proxy.health.checker
  "Health check implementations for TCP and HTTP protocols.
   Uses virtual threads for efficient concurrent checking."
  (:require [clojure.tools.logging :as log]
            [reverse-proxy.util :as util])
  (:import [java.net Socket InetSocketAddress]
           [java.net.http HttpClient HttpClient$Redirect HttpRequest HttpResponse$BodyHandlers]
           [java.time Duration]
           [java.util.concurrent Executors]))

;;; =============================================================================
;;; Health Check Result
;;; =============================================================================

(defrecord CheckResult [success? latency-ms error message])

(defn success-result
  "Create a successful check result."
  [latency-ms]
  (->CheckResult true latency-ms nil nil))

(defn failure-result
  "Create a failed check result."
  ([error] (failure-result error nil))
  ([error message]
   (->CheckResult false nil error message)))

;;; =============================================================================
;;; TCP Health Check
;;; =============================================================================

(defn check-tcp
  "Perform a TCP connection health check.
   Returns CheckResult with success/failure and latency."
  [ip port timeout-ms]
  (let [start (System/nanoTime)
        ip-str (if (string? ip) ip (util/u32->ip-string ip))]
    (try
      (let [socket (Socket.)]
        (try
          (.connect socket (InetSocketAddress. ^String ip-str ^int port) ^int timeout-ms)
          (let [latency (/ (- (System/nanoTime) start) 1000000.0)]
            (success-result latency))
          (finally
            (when-not (.isClosed socket)
              (.close socket)))))
      (catch java.net.SocketTimeoutException _
        (failure-result :timeout "Connection timed out"))
      (catch java.net.ConnectException e
        (failure-result :connection-refused (.getMessage e)))
      (catch java.net.NoRouteToHostException _
        (failure-result :no-route "No route to host"))
      (catch java.io.IOException e
        (failure-result :io-error (.getMessage e)))
      (catch Exception e
        (failure-result :unknown (.getMessage e))))))

;;; =============================================================================
;;; HTTP Health Check
;;; =============================================================================

(def ^:private http-client-executor
  "Virtual thread executor for HTTP clients."
  (delay (Executors/newVirtualThreadPerTaskExecutor)))

(defn- create-http-client
  "Create an HTTP client with the specified timeout."
  [timeout-ms]
  (-> (HttpClient/newBuilder)
      (.executor @http-client-executor)
      (.connectTimeout (Duration/ofMillis timeout-ms))
      (.followRedirects HttpClient$Redirect/NORMAL)
      (.build)))

(defn check-http
  "Perform an HTTP health check.
   Returns CheckResult with success/failure and latency."
  [ip port path timeout-ms expected-codes]
  (let [start (System/nanoTime)
        ip-str (if (string? ip) ip (util/u32->ip-string ip))
        url (str "http://" ip-str ":" port path)
        expected-set (set expected-codes)]
    (try
      (let [client (create-http-client timeout-ms)
            request (-> (HttpRequest/newBuilder)
                        (.uri (java.net.URI/create url))
                        (.timeout (Duration/ofMillis timeout-ms))
                        (.GET)
                        (.build))
            response (.send client request (HttpResponse$BodyHandlers/discarding))
            status (.statusCode response)
            latency (/ (- (System/nanoTime) start) 1000000.0)]
        (if (contains? expected-set status)
          (success-result latency)
          (failure-result :unexpected-status
                          (str "HTTP " status " not in expected codes " expected-codes))))
      (catch java.net.http.HttpTimeoutException _
        (failure-result :timeout "HTTP request timed out"))
      (catch java.net.ConnectException e
        (failure-result :connection-refused (.getMessage e)))
      (catch java.io.IOException e
        (failure-result :io-error (.getMessage e)))
      (catch Exception e
        (failure-result :unknown (.getMessage e))))))

;;; =============================================================================
;;; HTTPS Health Check
;;; =============================================================================

(defn check-https
  "Perform an HTTPS health check.
   Returns CheckResult with success/failure and latency."
  [ip port path timeout-ms expected-codes]
  (let [start (System/nanoTime)
        ip-str (if (string? ip) ip (util/u32->ip-string ip))
        url (str "https://" ip-str ":" port path)
        expected-set (set expected-codes)]
    (try
      (let [client (create-http-client timeout-ms)
            request (-> (HttpRequest/newBuilder)
                        (.uri (java.net.URI/create url))
                        (.timeout (Duration/ofMillis timeout-ms))
                        (.GET)
                        (.build))
            response (.send client request (HttpResponse$BodyHandlers/discarding))
            status (.statusCode response)
            latency (/ (- (System/nanoTime) start) 1000000.0)]
        (if (contains? expected-set status)
          (success-result latency)
          (failure-result :unexpected-status
                          (str "HTTPS " status " not in expected codes " expected-codes))))
      (catch java.net.http.HttpTimeoutException _
        (failure-result :timeout "HTTPS request timed out"))
      (catch javax.net.ssl.SSLException e
        (failure-result :ssl-error (.getMessage e)))
      (catch java.net.ConnectException e
        (failure-result :connection-refused (.getMessage e)))
      (catch java.io.IOException e
        (failure-result :io-error (.getMessage e)))
      (catch Exception e
        (failure-result :unknown (.getMessage e))))))

;;; =============================================================================
;;; Unified Check Interface
;;; =============================================================================

(defn perform-check
  "Perform a health check based on the configuration.
   Returns CheckResult."
  [health-check-config ip port]
  (let [{:keys [type path timeout-ms expected-codes]} health-check-config]
    (case type
      :tcp (check-tcp ip port timeout-ms)
      :http (check-http ip port path timeout-ms expected-codes)
      :https (check-https ip port path timeout-ms expected-codes)
      :none (success-result 0)
      (failure-result :invalid-type (str "Unknown health check type: " type)))))

;;; =============================================================================
;;; Target Identification
;;; =============================================================================

(defn target-id
  "Create a unique identifier for a target."
  [ip port]
  (let [ip-str (if (string? ip) ip (util/u32->ip-string ip))]
    (str ip-str ":" port)))

(defn parse-target-id
  "Parse a target ID back to IP and port."
  [id]
  (let [[ip port] (clojure.string/split id #":")]
    {:ip ip :port (Integer/parseInt port)}))
