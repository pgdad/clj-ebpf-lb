(ns reverse-proxy.health-test
  "Comprehensive tests for the health checking system."
  (:require [clojure.test :refer [deftest testing is are use-fixtures]]
            [reverse-proxy.health :as health]
            [reverse-proxy.health.checker :as checker]
            [reverse-proxy.health.weights :as weights]
            [reverse-proxy.health.manager :as manager]
            [reverse-proxy.config :as config]
            [reverse-proxy.util :as util])
  (:import [java.net ServerSocket InetSocketAddress]
           [java.io File FileInputStream]
           [java.security KeyStore]
           [javax.net.ssl SSLContext KeyManagerFactory]
           [com.sun.net.httpserver HttpServer HttpsServer HttpHandler HttpExchange HttpsConfigurator]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn health-manager-fixture
  "Start and stop the health manager around tests."
  [f]
  ;; Ensure clean state before test
  (when (manager/running?)
    (manager/stop!)
    (Thread/sleep 100))
  (try
    (f)
    (finally
      (when (manager/running?)
        (manager/stop!)
        (Thread/sleep 100)))))

(use-fixtures :each health-manager-fixture)

;;; =============================================================================
;;; Checker Tests
;;; =============================================================================

(deftest check-tcp-success-test
  (testing "TCP check succeeds when port is open"
    ;; Start a temporary server
    (let [server (ServerSocket. 0)  ; Bind to random available port
          port (.getLocalPort server)]
      (try
        (let [result (checker/check-tcp "127.0.0.1" port 1000)]
          (is (:success? result))
          (is (number? (:latency-ms result)))
          (is (nil? (:error result))))
        (finally
          (.close server))))))

(deftest check-tcp-connection-refused-test
  (testing "TCP check fails with connection refused on closed port"
    ;; Use a port that's very likely to be closed
    (let [result (checker/check-tcp "127.0.0.1" 59999 1000)]
      (is (not (:success? result)))
      (is (= :connection-refused (:error result))))))

(deftest check-tcp-timeout-test
  (testing "TCP check fails with timeout on non-routable address"
    ;; Use a non-routable IP that will timeout
    (let [result (checker/check-tcp "10.255.255.1" 80 100)]
      (is (not (:success? result)))
      ;; Could be timeout or no-route depending on network
      (is (contains? #{:timeout :no-route :connection-refused} (:error result))))))

(deftest target-id-test
  (testing "Target ID generation"
    (is (= "10.0.0.1:8080" (checker/target-id "10.0.0.1" 8080)))
    (is (= "192.168.1.1:80" (checker/target-id 0xC0A80101 80)))))

(deftest parse-target-id-test
  (testing "Target ID parsing"
    (is (= {:ip "10.0.0.1" :port 8080} (checker/parse-target-id "10.0.0.1:8080")))
    (is (= {:ip "192.168.1.100" :port 443} (checker/parse-target-id "192.168.1.100:443")))))

;;; =============================================================================
;;; HTTP Health Check Integration Tests
;;; =============================================================================

(defn- create-http-handler
  "Create an HTTP handler that responds with the given status code and body."
  [status-code body]
  (reify HttpHandler
    (handle [_ exchange]
      (let [response-bytes (.getBytes ^String body "UTF-8")]
        (.sendResponseHeaders ^HttpExchange exchange status-code (count response-bytes))
        (with-open [os (.getResponseBody ^HttpExchange exchange)]
          (.write os response-bytes))))))

(defn- start-test-http-server
  "Start a test HTTP server on a random port with the given handlers.
   handlers is a map of path -> [status-code body]
   Returns [server port]."
  [handlers]
  (let [server (HttpServer/create (InetSocketAddress. 0) 0)
        port (.getPort (.getAddress server))]
    (doseq [[path [status body]] handlers]
      (.createContext server path (create-http-handler status body)))
    (.setExecutor server nil)
    (.start server)
    [server port]))

(defn- stop-test-http-server
  "Stop the test HTTP server."
  [^HttpServer server]
  (.stop server 0))

(deftest check-http-success-test
  (testing "HTTP check succeeds with 200 OK"
    (let [[server port] (start-test-http-server {"/health" [200 "OK"]})]
      (try
        (let [result (checker/check-http "127.0.0.1" port "/health" 2000 [200])]
          (is (:success? result))
          (is (number? (:latency-ms result)))
          (is (nil? (:error result))))
        (finally
          (stop-test-http-server server))))))

(deftest check-http-custom-path-test
  (testing "HTTP check works with custom health check path"
    (let [[server port] (start-test-http-server {"/api/v1/healthz" [200 "{\"status\":\"healthy\"}"]})]
      (try
        (let [result (checker/check-http "127.0.0.1" port "/api/v1/healthz" 2000 [200])]
          (is (:success? result)))
        (finally
          (stop-test-http-server server))))))

(deftest check-http-multiple-expected-codes-test
  (testing "HTTP check accepts multiple expected status codes"
    (let [[server port] (start-test-http-server {"/health" [204 ""]})]
      (try
        ;; 204 No Content should be accepted when in expected codes
        (let [result (checker/check-http "127.0.0.1" port "/health" 2000 [200 204])]
          (is (:success? result)))
        (finally
          (stop-test-http-server server))))))

(deftest check-http-unexpected-status-test
  (testing "HTTP check fails with unexpected status code"
    (let [[server port] (start-test-http-server {"/health" [503 "Service Unavailable"]})]
      (try
        (let [result (checker/check-http "127.0.0.1" port "/health" 2000 [200])]
          (is (not (:success? result)))
          (is (= :unexpected-status (:error result)))
          (is (clojure.string/includes? (:message result) "503")))
        (finally
          (stop-test-http-server server))))))

(deftest check-http-404-test
  (testing "HTTP check fails when endpoint returns 404"
    (let [[server port] (start-test-http-server {"/other" [200 "OK"]})]
      (try
        ;; Request /health but server only has /other
        (let [result (checker/check-http "127.0.0.1" port "/health" 2000 [200])]
          (is (not (:success? result)))
          (is (= :unexpected-status (:error result))))
        (finally
          (stop-test-http-server server))))))

(deftest check-http-connection-refused-test
  (testing "HTTP check fails with connection refused on closed port"
    (let [result (checker/check-http "127.0.0.1" 59998 "/health" 1000 [200])]
      (is (not (:success? result)))
      (is (= :connection-refused (:error result))))))

(deftest check-http-various-status-codes-test
  (testing "HTTP check handles various status codes correctly"
    (let [[server port] (start-test-http-server {"/ok" [200 "OK"]
                                                  "/created" [201 "Created"]
                                                  "/accepted" [202 "Accepted"]
                                                  "/bad-request" [400 "Bad Request"]
                                                  "/internal-error" [500 "Internal Server Error"]})]
      (try
        ;; 200 OK - success
        (is (:success? (checker/check-http "127.0.0.1" port "/ok" 2000 [200])))

        ;; 201 Created - success when expected
        (is (:success? (checker/check-http "127.0.0.1" port "/created" 2000 [200 201 202])))

        ;; 400 Bad Request - failure
        (let [result (checker/check-http "127.0.0.1" port "/bad-request" 2000 [200])]
          (is (not (:success? result)))
          (is (= :unexpected-status (:error result))))

        ;; 500 Internal Error - failure
        (let [result (checker/check-http "127.0.0.1" port "/internal-error" 2000 [200])]
          (is (not (:success? result)))
          (is (= :unexpected-status (:error result))))
        (finally
          (stop-test-http-server server))))))

(deftest check-http-via-public-api-test
  (testing "HTTP check via public health API"
    (let [[server port] (start-test-http-server {"/health" [200 "OK"]})]
      (try
        (let [result (health/check-http "127.0.0.1" port "/health" 2000 [200])]
          (is (:success? result)))
        (finally
          (stop-test-http-server server))))))

(deftest check-http-latency-measurement-test
  (testing "HTTP check measures latency correctly"
    (let [[server port] (start-test-http-server {"/health" [200 "OK"]})]
      (try
        (let [result (checker/check-http "127.0.0.1" port "/health" 2000 [200])]
          (is (:success? result))
          (is (number? (:latency-ms result)))
          (is (> (:latency-ms result) 0))
          (is (< (:latency-ms result) 2000)))  ; Should be much faster than timeout
        (finally
          (stop-test-http-server server))))))

;;; =============================================================================
;;; HTTPS Health Check Integration Tests
;;; =============================================================================

(defn- generate-test-keystore-file
  "Generate a temporary keystore file with a self-signed certificate using keytool.
   Returns the keystore file path and password."
  []
  (let [keystore-file (File/createTempFile "test-keystore" ".jks")
        keystore-path (.getAbsolutePath keystore-file)
        password "testpass123"]
    ;; Delete the file first since keytool won't overwrite
    (.delete keystore-file)
    ;; Generate keystore with self-signed cert using keytool
    (let [process (-> (ProcessBuilder.
                        ["keytool" "-genkeypair"
                         "-alias" "test"
                         "-keyalg" "RSA"
                         "-keysize" "2048"
                         "-validity" "1"
                         "-keystore" keystore-path
                         "-storepass" password
                         "-keypass" password
                         "-dname" "CN=localhost,O=Test,L=Test,ST=Test,C=US"
                         "-storetype" "JKS"])
                      (.redirectErrorStream true)
                      (.start))
          exit-code (.waitFor process)]
      (when (not= 0 exit-code)
        (throw (ex-info "Failed to generate test keystore"
                        {:exit-code exit-code
                         :output (slurp (.getInputStream process))}))))
    ;; Mark for deletion on JVM exit
    (.deleteOnExit keystore-file)
    {:path keystore-path
     :password password
     :file keystore-file}))

(defn- load-keystore
  "Load a KeyStore from a file."
  [{:keys [path password]}]
  (let [keystore (KeyStore/getInstance "JKS")]
    (with-open [fis (FileInputStream. path)]
      (.load keystore fis (.toCharArray password)))
    {:keystore keystore
     :password (.toCharArray password)}))

(defn- create-ssl-context-for-server
  "Create an SSLContext for the test HTTPS server."
  [{:keys [keystore password]}]
  (let [kmf (doto (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
              (.init keystore password))
        ssl-context (doto (SSLContext/getInstance "TLS")
                      (.init (.getKeyManagers kmf) nil nil))]
    ssl-context))

(defn- start-test-https-server
  "Start a test HTTPS server on a random port with the given handlers.
   handlers is a map of path -> [status-code body]
   Returns [server port keystore-info]."
  [handlers]
  (let [ks-file-info (generate-test-keystore-file)
        ks-info (load-keystore ks-file-info)
        ssl-context (create-ssl-context-for-server ks-info)
        server (HttpsServer/create (InetSocketAddress. 0) 0)
        port (.getPort (.getAddress server))]
    (.setHttpsConfigurator server (HttpsConfigurator. ssl-context))
    (doseq [[path [status body]] handlers]
      (.createContext server path (create-http-handler status body)))
    (.setExecutor server nil)
    (.start server)
    [server port (assoc ks-file-info :keystore (:keystore ks-info))]))

(defn- stop-test-https-server
  "Stop the test HTTPS server."
  [^HttpsServer server]
  (.stop server 0))

(deftest check-https-connection-refused-test
  (testing "HTTPS check fails with connection refused on closed port"
    (let [result (checker/check-https "127.0.0.1" 59997 "/health" 1000 [200])]
      (is (not (:success? result)))
      (is (= :connection-refused (:error result))))))

(deftest check-https-ssl-error-self-signed-test
  (testing "HTTPS check fails with SSL error for self-signed certificate"
    ;; Start HTTPS server with self-signed cert
    ;; Client should reject it because it's not in the trust store
    (let [[server port _] (start-test-https-server {"/health" [200 "OK"]})]
      (try
        (let [result (checker/check-https "127.0.0.1" port "/health" 2000 [200])]
          ;; Should fail with SSL error because self-signed cert is not trusted
          (is (not (:success? result)))
          (is (= :ssl-error (:error result)))
          (is (some? (:message result))))
        (finally
          (stop-test-https-server server))))))

(deftest check-https-ssl-error-message-content-test
  (testing "HTTPS SSL error message contains useful information"
    (let [[server port _] (start-test-https-server {"/health" [200 "OK"]})]
      (try
        (let [result (checker/check-https "127.0.0.1" port "/health" 2000 [200])]
          (is (not (:success? result)))
          (is (= :ssl-error (:error result)))
          ;; Message should mention certificate or SSL/TLS issue
          (is (or (clojure.string/includes? (str (:message result)) "certificate")
                  (clojure.string/includes? (str (:message result)) "PKIX")
                  (clojure.string/includes? (str (:message result)) "SSL")
                  (clojure.string/includes? (str (:message result)) "trust"))))
        (finally
          (stop-test-https-server server))))))

(deftest check-https-to-http-server-test
  (testing "HTTPS check to HTTP-only server fails gracefully"
    ;; Try HTTPS against a plain HTTP server
    (let [[server port] (start-test-http-server {"/health" [200 "OK"]})]
      (try
        (let [result (checker/check-https "127.0.0.1" port "/health" 2000 [200])]
          ;; Should fail - could be SSL error, IO error, or timeout
          ;; (HTTP server doesn't speak TLS, so SSL handshake fails or times out)
          (is (not (:success? result)))
          (is (contains? #{:ssl-error :io-error :timeout} (:error result))))
        (finally
          (stop-test-http-server server))))))

(deftest check-https-via-public-api-test
  (testing "HTTPS check via public health API"
    (let [[server port _] (start-test-https-server {"/health" [200 "OK"]})]
      (try
        (let [result (health/check-https "127.0.0.1" port "/health" 2000 [200])]
          ;; Should fail with SSL error (self-signed cert)
          (is (not (:success? result)))
          (is (= :ssl-error (:error result))))
        (finally
          (stop-test-https-server server))))))

(deftest check-https-different-paths-test
  (testing "HTTPS check handles different paths correctly"
    (let [[server port _] (start-test-https-server {"/health" [200 "OK"]
                                                     "/ready" [200 "Ready"]
                                                     "/live" [204 ""]})]
      (try
        ;; All paths should fail with SSL error (self-signed cert)
        ;; but the server is correctly configured for different paths
        ;; Note: On slower systems (ARM emulation), may timeout instead
        (doseq [path ["/health" "/ready" "/live"]]
          (let [result (checker/check-https "127.0.0.1" port path 2000 [200 204])]
            (is (not (:success? result)))
            (is (contains? #{:ssl-error :timeout} (:error result)))))
        (finally
          (stop-test-https-server server))))))

(deftest check-https-timeout-test
  (testing "HTTPS check fails with timeout on non-routable address"
    (let [result (checker/check-https "10.255.255.1" 443 "/health" 100 [200])]
      (is (not (:success? result)))
      ;; Could be timeout, no-route, or connection-refused depending on network
      (is (contains? #{:timeout :no-route :connection-refused :io-error} (:error result))))))

;;; =============================================================================
;;; Weights Tests
;;; =============================================================================

(deftest redistribute-weights-all-healthy-test
  (testing "All healthy targets keep original weights"
    (is (= [50 30 20] (weights/redistribute-weights [50 30 20] [true true true])))
    (is (= [100] (weights/redistribute-weights [100] [true])))
    (is (= [25 25 25 25] (weights/redistribute-weights [25 25 25 25] [true true true true])))))

(deftest redistribute-weights-one-unhealthy-test
  (testing "Weights redistribute when one target is unhealthy"
    ;; [50, 30, 20] with middle one down: 50+20=70, so 50/70*100=71, 20/70*100=29
    (let [result (weights/redistribute-weights [50 30 20] [true false true])]
      (is (= 0 (nth result 1)))
      (is (> (nth result 0) 50))
      (is (> (nth result 2) 20)))))

(deftest redistribute-weights-all-unhealthy-test
  (testing "All unhealthy keeps original weights (graceful degradation)"
    (is (= [50 30 20] (weights/redistribute-weights [50 30 20] [false false false])))))

(deftest fix-weight-rounding-test
  (testing "Weight rounding correction"
    (is (= 100 (reduce + (weights/fix-weight-rounding [33 33 33]))))
    (is (= 100 (reduce + (weights/fix-weight-rounding [25 25 25 24]))))
    (is (= [100] (weights/fix-weight-rounding [100])))))

(deftest compute-effective-weights-test
  (testing "Effective weight computation"
    (let [result (weights/compute-effective-weights [50 50] [true false])]
      (is (= 100 (reduce + result)))
      (is (= 0 (second result)))
      (is (= 100 (first result))))))

(deftest weights->cumulative-test
  (testing "Cumulative weight conversion"
    (is (= [50 80 100] (weights/weights->cumulative [50 30 20])))
    (is (= [100] (weights/weights->cumulative [100])))
    (is (= [25 50 75 100] (weights/weights->cumulative [25 25 25 25])))))

(deftest compute-recovery-weight-test
  (testing "Recovery weight computation"
    (is (= 25 (weights/compute-recovery-weight 100 0)))   ; 25%
    (is (= 50 (weights/compute-recovery-weight 100 1)))   ; 50%
    (is (= 75 (weights/compute-recovery-weight 100 2)))   ; 75%
    (is (= 100 (weights/compute-recovery-weight 100 3)))  ; 100%
    (is (= 100 (weights/compute-recovery-weight 100 4))))) ; Beyond steps

;;; =============================================================================
;;; Manager Tests
;;; =============================================================================

(deftest manager-lifecycle-test
  (testing "Manager start and stop"
    (is (not (manager/running?)))
    (manager/start!)
    (is (manager/running?))
    (manager/stop!)
    (is (not (manager/running?)))))

(deftest manager-proxy-registration-test
  (testing "Proxy registration and unregistration"
    (manager/start!)
    (let [target-group (config/make-weighted-target-group
                         [{:ip "10.0.0.1" :port 8080 :weight 50
                           :health-check {:type :tcp :interval-ms 60000 :timeout-ms 1000
                                          :healthy-threshold 2 :unhealthy-threshold 3}}
                          {:ip "10.0.0.2" :port 8080 :weight 50
                           :health-check {:type :tcp :interval-ms 60000 :timeout-ms 1000
                                          :healthy-threshold 2 :unhealthy-threshold 3}}])
          updates (atom [])
          callback (fn [new-weights] (swap! updates conj new-weights))]
      (manager/register-proxy! "test-proxy" target-group
                               config/default-health-check-config callback)
      ;; Verify registration
      (let [health (manager/get-proxy-health "test-proxy")]
        (is (some? health))
        (is (= "test-proxy" (:proxy-name health)))
        (is (= 2 (count (:targets health))))
        (is (= [50 50] (:original-weights health))))
      ;; Unregister
      (manager/unregister-proxy! "test-proxy")
      (is (nil? (manager/get-proxy-health "test-proxy"))))))

(deftest manager-manual-status-override-test
  (testing "Manual health status override"
    (manager/start!)
    (let [target-group (config/make-weighted-target-group
                         [{:ip "10.0.0.1" :port 8080 :weight 60
                           :health-check {:type :tcp :interval-ms 60000 :timeout-ms 1000
                                          :healthy-threshold 2 :unhealthy-threshold 3}}
                          {:ip "10.0.0.2" :port 8080 :weight 40
                           :health-check {:type :tcp :interval-ms 60000 :timeout-ms 1000
                                          :healthy-threshold 2 :unhealthy-threshold 3}}])
          weight-updates (atom [])
          callback (fn [new-weights] (swap! weight-updates conj new-weights))]
      (manager/register-proxy! "override-proxy" target-group
                               config/default-health-check-config callback)
      ;; Set one target as unhealthy
      (manager/set-target-status! "override-proxy" "10.0.0.1:8080" :unhealthy)
      ;; Weights should update
      (Thread/sleep 100) ; Give time for async update
      (let [health (manager/get-proxy-health "override-proxy")
            t1 (first (filter #(= "10.0.0.1:8080" (:target-id %)) (:targets health)))]
        (is (= :unhealthy (:status t1))))
      (manager/unregister-proxy! "override-proxy"))))

;;; =============================================================================
;;; Public API Tests
;;; =============================================================================

(deftest health-api-lifecycle-test
  (testing "Health API lifecycle"
    (is (not (health/running?)))
    (health/start!)
    (is (health/running?))
    (health/stop!)
    (is (not (health/running?)))))

(deftest health-direct-tcp-check-test
  (testing "Direct TCP health check via API"
    (let [server (ServerSocket. 0)
          port (.getLocalPort server)]
      (try
        (let [result (health/check-tcp "127.0.0.1" port 1000)]
          (is (:success? result)))
        (finally
          (.close server))))))

(deftest health-target-id-test
  (testing "Target ID generation via API"
    (is (= "10.0.0.1:8080" (health/target-id "10.0.0.1" 8080)))))

;;; =============================================================================
;;; Config Integration Tests
;;; =============================================================================

(deftest health-check-config-parsing-test
  (testing "Health check config parsing"
    (let [hc-config {:type :http
                     :path "/health"
                     :interval-ms 5000
                     :timeout-ms 2000}
          parsed (config/parse-health-check-config hc-config nil)]
      (is (= :http (:type parsed)))
      (is (= "/health" (:path parsed)))
      (is (= 5000 (:interval-ms parsed)))
      (is (= 2000 (:timeout-ms parsed))))))

(deftest health-check-config-defaults-test
  (testing "Health check config with defaults"
    (let [hc-config {:type :tcp}
          parsed (config/parse-health-check-config hc-config nil)]
      ;; Should use defaults for missing values
      (is (= :tcp (:type parsed)))
      (is (= 10000 (:interval-ms parsed)))  ; Default
      (is (= 3000 (:timeout-ms parsed)))    ; Default
      (is (= 2 (:healthy-threshold parsed))))))

(deftest health-check-none-type-test
  (testing "Health check type :none returns nil"
    (let [parsed (config/parse-health-check-config {:type :none} nil)]
      (is (nil? parsed)))))

(deftest weighted-target-with-health-check-test
  (testing "WeightedTarget with health check"
    (let [target-map {:ip "10.0.0.1"
                      :port 8080
                      :weight 50
                      :health-check {:type :tcp :interval-ms 5000}}
          parsed (config/parse-weighted-target target-map nil)]
      (is (= 0x0A000001 (:ip parsed)))
      (is (= 8080 (:port parsed)))
      (is (= 50 (:weight parsed)))
      (is (some? (:health-check parsed)))
      (is (= :tcp (get-in parsed [:health-check :type]))))))

(deftest make-weighted-target-group-with-health-test
  (testing "Create weighted target group with health checks"
    (let [tg (config/make-weighted-target-group
               [{:ip "10.0.0.1" :port 8080 :weight 50
                 :health-check {:type :tcp :interval-ms 5000}}
                {:ip "10.0.0.2" :port 8080 :weight 50
                 :health-check {:type :http :path "/health"}}])]
      (is (= 2 (count (:targets tg))))
      (is (= [50 100] (:cumulative-weights tg)))
      (is (= :tcp (get-in tg [:targets 0 :health-check :type])))
      (is (= :http (get-in tg [:targets 1 :health-check :type]))))))

;;; =============================================================================
;;; Weight Distribution Tests
;;; =============================================================================

(deftest weight-distribution-scenarios-test
  (testing "Various weight distribution scenarios"
    ;; Two targets, one down
    (let [result (weights/compute-effective-weights [50 50] [true false])]
      (is (= [100 0] result)))

    ;; Three targets, one down
    (let [result (weights/compute-effective-weights [40 30 30] [true true false])]
      (is (= 100 (reduce + result)))
      (is (= 0 (nth result 2)))
      (is (> (nth result 0) 40))
      (is (> (nth result 1) 30)))

    ;; Asymmetric weights
    (let [result (weights/compute-effective-weights [70 20 10] [true false true])]
      (is (= 100 (reduce + result)))
      (is (= 0 (second result)))
      ;; 70/(70+10)*100 = 87.5, 10/(70+10)*100 = 12.5
      (is (>= (first result) 87))
      (is (<= (nth result 2) 13)))))

(deftest update-target-group-weights-test
  (testing "Target group weight updates"
    (let [tg (config/make-weighted-target-group
               [{:ip "10.0.0.1" :port 8080 :weight 50}
                {:ip "10.0.0.2" :port 8080 :weight 50}])
          updated (weights/update-target-group-weights tg [true false])]
      (is (= [100 0] (:effective-weights updated)))
      (is (= [100 100] (:cumulative-weights updated))))))

;;; =============================================================================
;;; Event Subscription Tests
;;; =============================================================================

(deftest health-event-subscription-test
  (testing "Health event subscription and notification"
    (health/start!)
    (let [events (atom [])
          unsubscribe (health/subscribe! (fn [event] (swap! events conj event)))
          target-group (config/make-weighted-target-group
                         [{:ip "10.0.0.1" :port 8080 :weight 100
                           :health-check {:type :tcp :interval-ms 60000 :timeout-ms 1000
                                          :healthy-threshold 1 :unhealthy-threshold 1}}])]
      (health/register-proxy! "event-proxy" target-group
                              (config/parse-settings {:health-check-enabled true})
                              (fn [_]))
      ;; Force a status change
      (manager/set-target-status! "event-proxy" "10.0.0.1:8080" :healthy)
      (Thread/sleep 50)
      (manager/set-target-status! "event-proxy" "10.0.0.1:8080" :unhealthy)
      (Thread/sleep 50)
      ;; Check that we received events
      (is (seq @events))
      ;; Unsubscribe
      (unsubscribe)
      (health/unregister-proxy! "event-proxy")
      (health/stop!))))
