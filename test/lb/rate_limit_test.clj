(ns lb.rate-limit-test
  "Tests for rate limiting module."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [lb.rate-limit :as rate-limit]
            [lb.maps :as maps]
            [lb.config :as config]))

;;; =============================================================================
;;; Mock Maps for Testing
;;; =============================================================================

(defn create-mock-config-map
  "Create a mock config map for testing."
  []
  (atom {}))

(defn create-mock-src-map
  "Create a mock source rate limit map for testing."
  []
  (atom {}))

(defn create-mock-backend-map
  "Create a mock backend rate limit map for testing."
  []
  (atom {}))

;;; =============================================================================
;;; Test Fixtures
;;; =============================================================================

(defn rate-limit-fixture
  "Ensure clean rate limit state around tests."
  [f]
  ;; Shutdown any existing state
  (rate-limit/shutdown!)
  (try
    (f)
    (finally
      (rate-limit/shutdown!))))

(use-fixtures :each rate-limit-fixture)

;;; =============================================================================
;;; Initialization Tests
;;; =============================================================================

(deftest initialized-test
  (testing "Rate limiting starts uninitialized"
    (is (not (rate-limit/initialized?)))))

(deftest init-test
  (testing "Rate limiting can be initialized with mock maps"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      ;; Mock the maps/set-rate-limit-config function
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)
        (is (rate-limit/initialized?))))))

(deftest shutdown-test
  (testing "Rate limiting can be shutdown"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)
        (is (rate-limit/initialized?))
        (rate-limit/shutdown!)
        (is (not (rate-limit/initialized?)))))))

;;; =============================================================================
;;; Configuration Tests
;;; =============================================================================

(deftest set-source-rate-limit-test
  (testing "Set source rate limit with default burst"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)
          set-calls (atom [])]
      (with-redefs [maps/set-rate-limit-config (fn [m type rate burst]
                                                  (swap! set-calls conj {:map m :type type :rate rate :burst burst})
                                                  nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)
        (is (rate-limit/set-source-rate-limit! 100))
        (is (= {:rate 100 :burst 200} (rate-limit/get-source-rate-limit)))
        ;; Verify the BPF map was updated
        (is (some #(and (= :source (:type %))
                        (= 100 (:rate %))
                        (= 200 (:burst %)))
                  @set-calls)))))

  (testing "Set source rate limit with custom burst"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)
        (is (rate-limit/set-source-rate-limit! 100 :burst 500))
        (is (= {:rate 100 :burst 500} (rate-limit/get-source-rate-limit)))))))

(deftest set-backend-rate-limit-test
  (testing "Set backend rate limit with default burst"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)
          set-calls (atom [])]
      (with-redefs [maps/set-rate-limit-config (fn [m type rate burst]
                                                  (swap! set-calls conj {:map m :type type :rate rate :burst burst})
                                                  nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)
        (is (rate-limit/set-backend-rate-limit! 10000))
        (is (= {:rate 10000 :burst 20000} (rate-limit/get-backend-rate-limit)))
        ;; Verify the BPF map was updated
        (is (some #(and (= :backend (:type %))
                        (= 10000 (:rate %))
                        (= 20000 (:burst %)))
                  @set-calls)))))

  (testing "Set backend rate limit with custom burst"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)
        (is (rate-limit/set-backend-rate-limit! 10000 :burst 15000))
        (is (= {:rate 10000 :burst 15000} (rate-limit/get-backend-rate-limit)))))))

(deftest invalid-rate-limit-test
  (testing "Negative rate throws exception"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)
        (is (thrown? clojure.lang.ExceptionInfo
                     (rate-limit/set-source-rate-limit! -100))))))

  (testing "Negative burst throws exception"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)
        (is (thrown? clojure.lang.ExceptionInfo
                     (rate-limit/set-source-rate-limit! 100 :burst -50)))))))

(deftest rate-limit-not-initialized-test
  (testing "Setting rate limit before init throws exception"
    (is (thrown? clojure.lang.ExceptionInfo
                 (rate-limit/set-source-rate-limit! 100)))))

;;; =============================================================================
;;; Disable Tests
;;; =============================================================================

(deftest disable-source-rate-limit-test
  (testing "Disable source rate limit"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)
          disable-calls (atom [])]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [m type]
                                               (swap! disable-calls conj {:map m :type type})
                                               nil)]
        (rate-limit/init! config-map src-map backend-map)
        (rate-limit/set-source-rate-limit! 100)
        (is (rate-limit/source-rate-limit-enabled?))
        (rate-limit/disable-source-rate-limit!)
        (is (not (rate-limit/source-rate-limit-enabled?)))
        (is (nil? (rate-limit/get-source-rate-limit)))
        ;; Verify BPF map was updated
        (is (some #(= :source (:type %)) @disable-calls))))))

(deftest disable-backend-rate-limit-test
  (testing "Disable backend rate limit"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)
          disable-calls (atom [])]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [m type]
                                               (swap! disable-calls conj {:map m :type type})
                                               nil)]
        (rate-limit/init! config-map src-map backend-map)
        (rate-limit/set-backend-rate-limit! 10000)
        (is (rate-limit/backend-rate-limit-enabled?))
        (rate-limit/disable-backend-rate-limit!)
        (is (not (rate-limit/backend-rate-limit-enabled?)))
        (is (nil? (rate-limit/get-backend-rate-limit)))
        ;; Verify BPF map was updated
        (is (some #(= :backend (:type %)) @disable-calls))))))

(deftest clear-rate-limits-test
  (testing "Clear all rate limits"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)
        (rate-limit/set-source-rate-limit! 100)
        (rate-limit/set-backend-rate-limit! 10000)
        (is (rate-limit/rate-limiting-enabled?))
        (rate-limit/clear-rate-limits!)
        (is (not (rate-limit/rate-limiting-enabled?)))
        (is (nil? (rate-limit/get-source-rate-limit)))
        (is (nil? (rate-limit/get-backend-rate-limit)))))))

;;; =============================================================================
;;; Status Tests
;;; =============================================================================

(deftest get-rate-limit-config-test
  (testing "Get all rate limit configuration"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)

        ;; No rate limits configured
        (let [config (rate-limit/get-rate-limit-config)]
          (is (nil? (:per-source config)))
          (is (nil? (:per-backend config))))

        ;; Configure source rate limit only
        (rate-limit/set-source-rate-limit! 100)
        (let [config (rate-limit/get-rate-limit-config)]
          (is (= {:rate 100 :burst 200} (:per-source config)))
          (is (nil? (:per-backend config))))

        ;; Configure backend rate limit too
        (rate-limit/set-backend-rate-limit! 10000 :burst 15000)
        (let [config (rate-limit/get-rate-limit-config)]
          (is (= {:rate 100 :burst 200} (:per-source config)))
          (is (= {:rate 10000 :burst 15000} (:per-backend config))))))))

(deftest rate-limiting-enabled-test
  (testing "Rate limiting enabled checks"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)

        ;; Nothing enabled
        (is (not (rate-limit/rate-limiting-enabled?)))
        (is (not (rate-limit/source-rate-limit-enabled?)))
        (is (not (rate-limit/backend-rate-limit-enabled?)))

        ;; Enable source only
        (rate-limit/set-source-rate-limit! 100)
        (is (rate-limit/rate-limiting-enabled?))
        (is (rate-limit/source-rate-limit-enabled?))
        (is (not (rate-limit/backend-rate-limit-enabled?)))

        ;; Enable backend too
        (rate-limit/set-backend-rate-limit! 10000)
        (is (rate-limit/rate-limiting-enabled?))
        (is (rate-limit/source-rate-limit-enabled?))
        (is (rate-limit/backend-rate-limit-enabled?))

        ;; Disable source
        (rate-limit/disable-source-rate-limit!)
        (is (rate-limit/rate-limiting-enabled?))
        (is (not (rate-limit/source-rate-limit-enabled?)))
        (is (rate-limit/backend-rate-limit-enabled?))))))

;;; =============================================================================
;;; Configure from Settings Tests
;;; =============================================================================

(deftest configure-from-settings-test
  (testing "Configure rate limits from settings map"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)

        (rate-limit/configure-from-settings!
          {:rate-limits
           {:per-source {:requests-per-sec 100 :burst 200}
            :per-backend {:requests-per-sec 10000 :burst 15000}}})

        (is (= {:rate 100 :burst 200} (rate-limit/get-source-rate-limit)))
        (is (= {:rate 10000 :burst 15000} (rate-limit/get-backend-rate-limit))))))

  (testing "Configure rate limits with only source"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)

        (rate-limit/configure-from-settings!
          {:rate-limits
           {:per-source {:requests-per-sec 50}}})

        (is (= {:rate 50 :burst 100} (rate-limit/get-source-rate-limit)))
        (is (nil? (rate-limit/get-backend-rate-limit))))))

  (testing "Configure rate limits with empty settings"
    (let [config-map (create-mock-config-map)
          src-map (create-mock-src-map)
          backend-map (create-mock-backend-map)]
      (with-redefs [maps/set-rate-limit-config (fn [_ _ _ _] nil)
                    maps/disable-rate-limit (fn [_ _] nil)]
        (rate-limit/init! config-map src-map backend-map)

        (rate-limit/configure-from-settings! {})

        (is (nil? (rate-limit/get-source-rate-limit)))
        (is (nil? (rate-limit/get-backend-rate-limit)))))))

;;; =============================================================================
;;; Config Spec Tests
;;; =============================================================================

(deftest rate-limit-config-spec-test
  (testing "Valid rate limit config"
    (let [result (config/validate-config
                   {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}}]
                    :settings
                    {:rate-limits
                     {:per-source {:requests-per-sec 100 :burst 200}
                      :per-backend {:requests-per-sec 10000 :burst 15000}}}})]
      (is (:valid result))))

  (testing "Valid rate limit config with only source"
    (let [result (config/validate-config
                   {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}}]
                    :settings
                    {:rate-limits
                     {:per-source {:requests-per-sec 100}}}})]
      (is (:valid result))))

  (testing "Valid rate limit config with only backend"
    (let [result (config/validate-config
                   {:proxies
                    [{:name "test"
                      :listen {:interfaces ["eth0"] :port 80}
                      :default-target {:ip "10.0.0.1" :port 8080}}]
                    :settings
                    {:rate-limits
                     {:per-backend {:requests-per-sec 10000}}}})]
      (is (:valid result)))))
