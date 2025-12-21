(ns lb.admin-test
  "Unit tests for admin API module."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [clojure.data.json :as json]
            [lb.admin.server :as server])
  (:import [java.net HttpURLConnection URL]))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn server-fixture [f]
  ;; Start server with minimal routes for testing
  (let [test-routes [{:method :get
                      :pattern "/api/v1/test"
                      :handler (fn [_] {:data {:message "OK"}})}
                     {:method :post
                      :pattern "/api/v1/echo"
                      :handler (fn [{:keys [body]}] {:data body})}
                     {:method :get
                      :pattern "/api/v1/items/:id"
                      :handler (fn [{:keys [params]}] {:data {:id (:id params)}})}
                     {:method :delete
                      :pattern "/api/v1/items/:id"
                      :handler (fn [{:keys [params]}] {:data {:deleted (:id params)}})}
                     {:method :get
                      :pattern "/api/v1/error"
                      :handler (fn [_] {:error "Test error" :code "TEST_ERROR" :status 400})}]]
    (server/start! {:port 18081 :routes test-routes})
    (try
      (Thread/sleep 100) ; Give server time to start
      (f)
      (finally
        (server/stop!)))))

(use-fixtures :each server-fixture)

;;; =============================================================================
;;; HTTP Client Helpers
;;; =============================================================================

(defn- http-get [path]
  (let [url (URL. (str "http://localhost:18081" path))
        conn ^HttpURLConnection (.openConnection url)]
    (.setRequestMethod conn "GET")
    (.setConnectTimeout conn 5000)
    (.setReadTimeout conn 5000)
    (try
      (let [status (.getResponseCode conn)
            body (slurp (if (>= status 400)
                          (.getErrorStream conn)
                          (.getInputStream conn)))]
        {:status status :body (json/read-str body :key-fn keyword)})
      (finally
        (.disconnect conn)))))

(defn- http-post [path body]
  (let [url (URL. (str "http://localhost:18081" path))
        conn ^HttpURLConnection (.openConnection url)]
    (.setRequestMethod conn "POST")
    (.setDoOutput conn true)
    (.setConnectTimeout conn 5000)
    (.setReadTimeout conn 5000)
    (.setRequestProperty conn "Content-Type" "application/json")
    (when body
      (with-open [os (.getOutputStream conn)]
        (.write os (.getBytes (json/write-str body) "UTF-8"))))
    (try
      (let [status (.getResponseCode conn)
            resp-body (slurp (if (>= status 400)
                               (.getErrorStream conn)
                               (.getInputStream conn)))]
        {:status status :body (json/read-str resp-body :key-fn keyword)})
      (finally
        (.disconnect conn)))))

(defn- http-delete [path]
  (let [url (URL. (str "http://localhost:18081" path))
        conn ^HttpURLConnection (.openConnection url)]
    (.setRequestMethod conn "DELETE")
    (.setConnectTimeout conn 5000)
    (.setReadTimeout conn 5000)
    (try
      (let [status (.getResponseCode conn)
            body (slurp (if (>= status 400)
                          (.getErrorStream conn)
                          (.getInputStream conn)))]
        {:status status :body (json/read-str body :key-fn keyword)})
      (finally
        (.disconnect conn)))))

;;; =============================================================================
;;; Server Lifecycle Tests
;;; =============================================================================

(deftest server-lifecycle-test
  (testing "Server is running"
    (is (server/running?)))

  (testing "Server status returns correct info"
    (let [status (server/get-status)]
      (is (some? status))
      (is (:running status))
      (is (= 18081 (:port status))))))

;;; =============================================================================
;;; GET Request Tests
;;; =============================================================================

(deftest get-request-test
  (testing "Simple GET returns success"
    (let [{:keys [status body]} (http-get "/api/v1/test")]
      (is (= 200 status))
      (is (:success body))
      (is (= "OK" (get-in body [:data :message])))))

  (testing "GET with path parameter"
    (let [{:keys [status body]} (http-get "/api/v1/items/123")]
      (is (= 200 status))
      (is (:success body))
      (is (= "123" (get-in body [:data :id]))))))

;;; =============================================================================
;;; POST Request Tests
;;; =============================================================================

(deftest post-request-test
  (testing "POST with body echoes data"
    (let [{:keys [status body]} (http-post "/api/v1/echo" {:name "test" :value 42})]
      (is (= 200 status))
      (is (:success body))
      (is (= "test" (get-in body [:data :name])))
      (is (= 42 (get-in body [:data :value]))))))

;;; =============================================================================
;;; DELETE Request Tests
;;; =============================================================================

(deftest delete-request-test
  (testing "DELETE with path parameter"
    (let [{:keys [status body]} (http-delete "/api/v1/items/456")]
      (is (= 200 status))
      (is (:success body))
      (is (= "456" (get-in body [:data :deleted]))))))

;;; =============================================================================
;;; Error Handling Tests
;;; =============================================================================

(deftest error-handling-test
  (testing "Handler error returns error response"
    (let [{:keys [status body]} (http-get "/api/v1/error")]
      (is (= 400 status))
      (is (not (:success body)))
      (is (= "TEST_ERROR" (get-in body [:error :code])))
      (is (= "Test error" (get-in body [:error :message])))))

  (testing "Not found returns 404"
    (let [{:keys [status body]} (http-get "/api/v1/nonexistent")]
      (is (= 404 status))
      (is (not (:success body)))
      (is (= "NOT_FOUND" (get-in body [:error :code]))))))

;;; =============================================================================
;;; Path Parameter Extraction Tests
;;; =============================================================================

(deftest path-param-extraction-test
  (testing "Extracts single parameter"
    (let [result (server/extract-path-params "/api/v1/proxies/web" "/api/v1/proxies/:name")]
      (is (= {:name "web"} result))))

  (testing "Extracts multiple parameters"
    (let [result (server/extract-path-params "/api/v1/proxies/web/routes/192.168.1.0"
                                              "/api/v1/proxies/:name/routes/:source")]
      (is (= {:name "web" :source "192.168.1.0"} result))))

  (testing "Returns nil for non-matching paths"
    (is (nil? (server/extract-path-params "/api/v1/proxies" "/api/v1/proxies/:name")))
    (is (nil? (server/extract-path-params "/api/v1/proxies/a/b" "/api/v1/proxies/:name")))))

;;; =============================================================================
;;; Router Tests
;;; =============================================================================

(deftest router-test
  (testing "Creates router that matches routes"
    (let [routes [{:method :get :pattern "/api/v1/test" :handler :handler1}
                  {:method :post :pattern "/api/v1/test" :handler :handler2}]
          router (server/create-router routes)]
      ;; Note: router needs an HttpExchange, these tests are unit tests for the functions
      (is (fn? router)))))

;;; =============================================================================
;;; Authentication Tests
;;; =============================================================================

(deftest auth-disabled-test
  ;; Current fixture doesn't use API key, so all requests should work
  (testing "Requests work without API key when not configured"
    (let [{:keys [status]} (http-get "/api/v1/test")]
      (is (= 200 status)))))

;;; =============================================================================
;;; Handler Helper Tests (skipped - private functions tested via integration)
;;; =============================================================================

;; Note: require-param and safe-call are private helper functions.
;; They are tested indirectly through the endpoint tests above.

;;; =============================================================================
;;; Routes Definition Test (loaded dynamically to avoid cyclic dependency)
;;; =============================================================================

(deftest routes-definition-test
  (require 'lb.admin.handlers)
  (let [routes @(resolve 'lb.admin.handlers/routes)]
    (testing "Routes are defined"
      (is (vector? routes))
      (is (pos? (count routes))))

    (testing "All routes have required keys"
      (doseq [route routes]
        (is (contains? route :method))
        (is (contains? route :pattern))
        (is (contains? route :handler))))

    (testing "Routes cover expected endpoints"
      (let [patterns (set (map :pattern routes))]
        (is (contains? patterns "/api/v1/status"))
        (is (contains? patterns "/api/v1/config"))
        (is (contains? patterns "/api/v1/proxies"))
        (is (contains? patterns "/api/v1/health"))
        (is (contains? patterns "/api/v1/connections"))))))
