(ns lb.reload-test
  "Unit tests for configuration diffing and hot reload logic.
   These tests don't require BPF/root privileges."
  (:require [clojure.test :refer [deftest testing is are]]
            [lb.config :as config]
            [lb.reload :as reload]))

;;; =============================================================================
;;; Test Helpers
;;; =============================================================================

(defn- make-config
  "Create a config from a simple map specification."
  [config-map]
  (config/parse-config config-map))

(defn- simple-proxy
  "Create a simple proxy config map."
  [name port target-ip target-port]
  {:name name
   :listen {:interfaces ["eth0"] :port port}
   :default-target {:ip target-ip :port target-port}})

;;; =============================================================================
;;; Settings Diffing Tests
;;; =============================================================================

(deftest diff-settings-no-changes-test
  (testing "Identical settings produce empty diff"
    (let [settings (config/parse-settings {:stats-enabled true
                                            :connection-timeout-sec 300})
          diff (config/diff-settings settings settings)]
      (is (empty? diff)))))

(deftest diff-settings-with-changes-test
  (testing "Changed settings are detected"
    (let [old-settings (config/parse-settings {:stats-enabled false
                                                :connection-timeout-sec 300})
          new-settings (config/parse-settings {:stats-enabled true
                                                :connection-timeout-sec 600})
          diff (config/diff-settings old-settings new-settings)]
      (is (= 2 (count diff)))
      (is (= {:old false :new true} (:stats-enabled diff)))
      (is (= {:old 300 :new 600} (:connection-timeout-sec diff))))))

(deftest diff-settings-partial-changes-test
  (testing "Only changed fields are in diff"
    (let [old-settings (config/parse-settings {:stats-enabled false
                                                :connection-timeout-sec 300})
          new-settings (config/parse-settings {:stats-enabled true
                                                :connection-timeout-sec 300})
          diff (config/diff-settings old-settings new-settings)]
      (is (= 1 (count diff)))
      (is (contains? diff :stats-enabled))
      (is (not (contains? diff :connection-timeout-sec))))))

;;; =============================================================================
;;; Target Group Diffing Tests
;;; =============================================================================

(deftest diff-target-group-identical-test
  (testing "Identical target groups return nil"
    (let [tg (config/parse-target-group {:ip "10.0.0.1" :port 8080} "test")
          diff (config/diff-target-group tg tg)]
      (is (nil? diff)))))

(deftest diff-target-group-different-ip-test
  (testing "Different IPs are detected"
    (let [tg1 (config/parse-target-group {:ip "10.0.0.1" :port 8080} "test")
          tg2 (config/parse-target-group {:ip "10.0.0.2" :port 8080} "test")
          diff (config/diff-target-group tg1 tg2)]
      (is (some? diff))
      (is (= tg1 (:old diff)))
      (is (= tg2 (:new diff))))))

(deftest diff-target-group-different-port-test
  (testing "Different ports are detected"
    (let [tg1 (config/parse-target-group {:ip "10.0.0.1" :port 8080} "test")
          tg2 (config/parse-target-group {:ip "10.0.0.1" :port 9000} "test")
          diff (config/diff-target-group tg1 tg2)]
      (is (some? diff)))))

(deftest diff-target-group-different-weights-test
  (testing "Different weights are detected"
    (let [tg1 (config/parse-target-group
                [{:ip "10.0.0.1" :port 8080 :weight 50}
                 {:ip "10.0.0.2" :port 8080 :weight 50}] "test")
          tg2 (config/parse-target-group
                [{:ip "10.0.0.1" :port 8080 :weight 70}
                 {:ip "10.0.0.2" :port 8080 :weight 30}] "test")
          diff (config/diff-target-group tg1 tg2)]
      (is (some? diff)))))

(deftest diff-target-group-different-count-test
  (testing "Different target counts are detected"
    (let [tg1 (config/parse-target-group {:ip "10.0.0.1" :port 8080} "test")
          tg2 (config/parse-target-group
                [{:ip "10.0.0.1" :port 8080 :weight 50}
                 {:ip "10.0.0.2" :port 8080 :weight 50}] "test")
          diff (config/diff-target-group tg1 tg2)]
      (is (some? diff)))))

;;; =============================================================================
;;; Listen Diffing Tests
;;; =============================================================================

(deftest diff-listen-identical-test
  (testing "Identical listen configs return false (no change)"
    (let [listen (config/parse-listen {:interfaces ["eth0"] :port 80})
          diff (config/diff-listen listen listen)]
      (is (false? diff)))))

(deftest diff-listen-different-port-test
  (testing "Different ports are detected"
    (let [l1 (config/parse-listen {:interfaces ["eth0"] :port 80})
          l2 (config/parse-listen {:interfaces ["eth0"] :port 443})
          diff (config/diff-listen l1 l2)]
      (is (true? diff)))))

(deftest diff-listen-different-interfaces-test
  (testing "Different interfaces are detected"
    (let [l1 (config/parse-listen {:interfaces ["eth0"] :port 80})
          l2 (config/parse-listen {:interfaces ["eth1"] :port 80})
          diff (config/diff-listen l1 l2)]
      (is (true? diff)))))

(deftest diff-listen-interface-order-irrelevant-test
  (testing "Interface order doesn't matter"
    (let [l1 (config/parse-listen {:interfaces ["eth0" "eth1"] :port 80})
          l2 (config/parse-listen {:interfaces ["eth1" "eth0"] :port 80})
          diff (config/diff-listen l1 l2)]
      (is (false? diff)))))

;;; =============================================================================
;;; Source Route Diffing Tests
;;; =============================================================================

(deftest diff-source-routes-no-changes-test
  (testing "Identical routes produce empty diff"
    (let [config (make-config
                   {:proxies [(assoc (simple-proxy "test" 80 "10.0.0.1" 8080)
                                :source-routes
                                [{:source "192.168.1.0/24"
                                  :target {:ip "10.0.1.1" :port 8080}}])]})
          routes (get-in config [:proxies 0 :source-routes])
          diff (config/diff-source-routes routes routes)]
      (is (empty? (:added diff)))
      (is (empty? (:removed diff))))))

(deftest diff-source-routes-added-test
  (testing "Added routes are detected"
    (let [config1 (make-config
                    {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]})
          config2 (make-config
                    {:proxies [(assoc (simple-proxy "test" 80 "10.0.0.1" 8080)
                                 :source-routes
                                 [{:source "192.168.1.0/24"
                                   :target {:ip "10.0.1.1" :port 8080}}])]})
          old-routes (get-in config1 [:proxies 0 :source-routes])
          new-routes (get-in config2 [:proxies 0 :source-routes])
          diff (config/diff-source-routes old-routes new-routes)]
      (is (= 1 (count (:added diff))))
      (is (empty? (:removed diff))))))

(deftest diff-source-routes-removed-test
  (testing "Removed routes are detected"
    (let [config1 (make-config
                    {:proxies [(assoc (simple-proxy "test" 80 "10.0.0.1" 8080)
                                 :source-routes
                                 [{:source "192.168.1.0/24"
                                   :target {:ip "10.0.1.1" :port 8080}}])]})
          config2 (make-config
                    {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]})
          old-routes (get-in config1 [:proxies 0 :source-routes])
          new-routes (get-in config2 [:proxies 0 :source-routes])
          diff (config/diff-source-routes old-routes new-routes)]
      (is (empty? (:added diff)))
      (is (= 1 (count (:removed diff)))))))

(deftest diff-source-routes-modified-test
  (testing "Modified routes appear in both added and removed"
    (let [config1 (make-config
                    {:proxies [(assoc (simple-proxy "test" 80 "10.0.0.1" 8080)
                                 :source-routes
                                 [{:source "192.168.1.0/24"
                                   :target {:ip "10.0.1.1" :port 8080}}])]})
          config2 (make-config
                    {:proxies [(assoc (simple-proxy "test" 80 "10.0.0.1" 8080)
                                 :source-routes
                                 [{:source "192.168.1.0/24"
                                   :target {:ip "10.0.1.2" :port 9000}}])]}) ; Different target
          old-routes (get-in config1 [:proxies 0 :source-routes])
          new-routes (get-in config2 [:proxies 0 :source-routes])
          diff (config/diff-source-routes old-routes new-routes)]
      ;; Modified routes should be in both added (new version) and removed (old version)
      (is (= 1 (count (:added diff))))
      (is (= 1 (count (:removed diff)))))))

;;; =============================================================================
;;; SNI Route Diffing Tests
;;; =============================================================================

(deftest diff-sni-routes-no-changes-test
  (testing "Identical SNI routes produce empty diff"
    (let [config (make-config
                   {:proxies [(assoc (simple-proxy "test" 443 "10.0.0.1" 8443)
                                :sni-routes
                                [{:sni-hostname "api.example.com"
                                  :target {:ip "10.0.1.1" :port 8443}}])]})
          routes (get-in config [:proxies 0 :sni-routes])
          diff (config/diff-sni-routes routes routes)]
      (is (empty? (:added diff)))
      (is (empty? (:removed diff))))))

(deftest diff-sni-routes-added-test
  (testing "Added SNI routes are detected"
    (let [config1 (make-config
                    {:proxies [(simple-proxy "test" 443 "10.0.0.1" 8443)]})
          config2 (make-config
                    {:proxies [(assoc (simple-proxy "test" 443 "10.0.0.1" 8443)
                                 :sni-routes
                                 [{:sni-hostname "api.example.com"
                                   :target {:ip "10.0.1.1" :port 8443}}])]})
          old-routes (get-in config1 [:proxies 0 :sni-routes])
          new-routes (get-in config2 [:proxies 0 :sni-routes])
          diff (config/diff-sni-routes old-routes new-routes)]
      (is (= 1 (count (:added diff))))
      (is (= "api.example.com" (:hostname (first (:added diff)))))
      (is (empty? (:removed diff))))))

(deftest diff-sni-routes-removed-test
  (testing "Removed SNI routes are detected"
    (let [config1 (make-config
                    {:proxies [(assoc (simple-proxy "test" 443 "10.0.0.1" 8443)
                                 :sni-routes
                                 [{:sni-hostname "api.example.com"
                                   :target {:ip "10.0.1.1" :port 8443}}])]})
          config2 (make-config
                    {:proxies [(simple-proxy "test" 443 "10.0.0.1" 8443)]})
          old-routes (get-in config1 [:proxies 0 :sni-routes])
          new-routes (get-in config2 [:proxies 0 :sni-routes])
          diff (config/diff-sni-routes old-routes new-routes)]
      (is (empty? (:added diff)))
      (is (= 1 (count (:removed diff))))
      (is (= "api.example.com" (first (:removed diff)))))))

;;; =============================================================================
;;; Proxy Diffing Tests
;;; =============================================================================

(deftest diff-proxy-no-changes-test
  (testing "Identical proxies produce empty diff"
    (let [config (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]})
          proxy (first (:proxies config))
          diff (config/diff-proxy proxy proxy)]
      (is (config/proxy-diff-empty? diff)))))

(deftest diff-proxy-listen-changed-test
  (testing "Listen changes are detected"
    (let [config1 (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]})
          config2 (make-config {:proxies [(simple-proxy "test" 443 "10.0.0.1" 8080)]})
          diff (config/diff-proxy (first (:proxies config1))
                                   (first (:proxies config2)))]
      (is (:listen-changed? diff))
      (is (not (config/proxy-diff-empty? diff))))))

(deftest diff-proxy-default-target-changed-test
  (testing "Default target changes are detected"
    (let [config1 (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]})
          config2 (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.2" 9000)]})
          diff (config/diff-proxy (first (:proxies config1))
                                   (first (:proxies config2)))]
      (is (some? (:default-target-diff diff)))
      (is (not (config/proxy-diff-empty? diff))))))

(deftest diff-proxy-routes-changed-test
  (testing "Route changes are detected"
    (let [config1 (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]})
          config2 (make-config
                    {:proxies [(assoc (simple-proxy "test" 80 "10.0.0.1" 8080)
                                 :source-routes
                                 [{:source "192.168.1.0/24"
                                   :target {:ip "10.0.1.1" :port 8080}}])]})
          diff (config/diff-proxy (first (:proxies config1))
                                   (first (:proxies config2)))]
      (is (= 1 (count (:added-source-routes diff))))
      (is (not (config/proxy-diff-empty? diff))))))

;;; =============================================================================
;;; Full Config Diffing Tests
;;; =============================================================================

(deftest diff-configs-no-changes-test
  (testing "Identical configs produce empty diff"
    (let [config (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]})
          diff (config/diff-configs config config)]
      (is (config/config-diff-empty? diff)))))

(deftest diff-configs-added-proxy-test
  (testing "Added proxies are detected"
    (let [config1 (make-config {:proxies [(simple-proxy "proxy1" 80 "10.0.0.1" 8080)]})
          config2 (make-config {:proxies [(simple-proxy "proxy1" 80 "10.0.0.1" 8080)
                                          (simple-proxy "proxy2" 443 "10.0.0.2" 8443)]})
          diff (config/diff-configs config1 config2)]
      (is (= 1 (count (:added-proxies diff))))
      (is (= "proxy2" (:name (first (:added-proxies diff)))))
      (is (empty? (:removed-proxies diff)))
      (is (not (config/config-diff-empty? diff))))))

(deftest diff-configs-removed-proxy-test
  (testing "Removed proxies are detected"
    (let [config1 (make-config {:proxies [(simple-proxy "proxy1" 80 "10.0.0.1" 8080)
                                          (simple-proxy "proxy2" 443 "10.0.0.2" 8443)]})
          config2 (make-config {:proxies [(simple-proxy "proxy1" 80 "10.0.0.1" 8080)]})
          diff (config/diff-configs config1 config2)]
      (is (empty? (:added-proxies diff)))
      (is (= 1 (count (:removed-proxies diff))))
      (is (= "proxy2" (first (:removed-proxies diff))))
      (is (not (config/config-diff-empty? diff))))))

(deftest diff-configs-modified-proxy-test
  (testing "Modified proxies are detected"
    (let [config1 (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]})
          config2 (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.2" 9000)]})
          diff (config/diff-configs config1 config2)]
      (is (empty? (:added-proxies diff)))
      (is (empty? (:removed-proxies diff)))
      (is (= 1 (count (:modified-proxies diff))))
      (is (= "test" (:proxy-name (first (:modified-proxies diff)))))
      (is (not (config/config-diff-empty? diff))))))

(deftest diff-configs-settings-changed-test
  (testing "Settings changes are detected"
    (let [config1 (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]
                                :settings {:stats-enabled false}})
          config2 (make-config {:proxies [(simple-proxy "test" 80 "10.0.0.1" 8080)]
                                :settings {:stats-enabled true}})
          diff (config/diff-configs config1 config2)]
      (is (contains? (:settings-changes diff) :stats-enabled))
      (is (not (config/config-diff-empty? diff))))))

(deftest diff-configs-complex-test
  (testing "Complex changes are all detected"
    (let [config1 (make-config
                    {:proxies [(simple-proxy "keep" 80 "10.0.0.1" 8080)
                               (simple-proxy "remove" 8080 "10.0.0.2" 9000)
                               (simple-proxy "modify" 443 "10.0.0.3" 8443)]
                     :settings {:stats-enabled false}})
          config2 (make-config
                    {:proxies [(simple-proxy "keep" 80 "10.0.0.1" 8080)  ; unchanged
                               (simple-proxy "add" 9000 "10.0.0.4" 9001) ; added
                               (simple-proxy "modify" 443 "10.0.0.5" 9443)] ; modified
                     :settings {:stats-enabled true}})  ; changed
          diff (config/diff-configs config1 config2)]
      (is (= 1 (count (:added-proxies diff))))
      (is (= "add" (:name (first (:added-proxies diff)))))
      (is (= 1 (count (:removed-proxies diff))))
      (is (= "remove" (first (:removed-proxies diff))))
      (is (= 1 (count (:modified-proxies diff))))
      (is (= "modify" (:proxy-name (first (:modified-proxies diff)))))
      (is (contains? (:settings-changes diff) :stats-enabled)))))

;;; =============================================================================
;;; Summarize Diff Tests
;;; =============================================================================

(deftest summarize-diff-test
  (testing "Summarize diff produces correct counts"
    (let [config1 (make-config
                    {:proxies [(simple-proxy "keep" 80 "10.0.0.1" 8080)
                               (simple-proxy "remove" 8080 "10.0.0.2" 9000)]
                     :settings {:stats-enabled false}})
          config2 (make-config
                    {:proxies [(simple-proxy "keep" 80 "10.0.0.1" 8080)
                               (simple-proxy "add" 9000 "10.0.0.4" 9001)]
                     :settings {:stats-enabled true}})
          diff (config/diff-configs config1 config2)
          summary (config/summarize-diff diff)]
      (is (= 1 (:settings-changed summary)))
      (is (= 1 (:proxies-added summary)))
      (is (= 1 (:proxies-removed summary)))
      (is (= 0 (:proxies-modified summary))))))

;;; =============================================================================
;;; Reload State Tests
;;; =============================================================================

(deftest reload-state-initially-disabled-test
  (testing "Hot reload is initially disabled"
    (reload/disable-hot-reload!)  ; Ensure clean state
    (is (not (reload/hot-reload-enabled?)))))

(deftest reload-state-structure-test
  (testing "Reload state has expected structure"
    (reload/disable-hot-reload!)  ; Ensure clean state
    (let [state (reload/get-reload-state)]
      (is (contains? state :enabled))
      (is (contains? state :config-path))
      (is (contains? state :file-watcher-active))
      (is (contains? state :sighup-handler-active))
      (is (contains? state :reload-count)))))
