(ns lb.xdp-load-test
  "Test loading and running XDP program on a veth interface."
  (:require [clojure.test :refer [deftest testing is]]
            [clj-ebpf.core :as bpf]
            [lb.maps :as maps]
            [lb.programs.xdp-ingress :as xdp]
            [lb.util :as util]
            [clojure.tools.logging :as log]
            [clojure.java.shell :refer [sh]]))

;;; =============================================================================
;;; Veth Setup/Teardown Helpers
;;; =============================================================================

(defn exec
  "Execute shell command, return output or throw on error."
  [& args]
  (let [result (apply sh args)]
    (when (not= 0 (:exit result))
      (throw (ex-info (str "Command failed: " (pr-str args))
                      {:exit (:exit result)
                       :out (:out result)
                       :err (:err result)})))
    (:out result)))

(defn setup-veth-pair
  "Create a veth pair for testing.
   Returns {:veth0 name :veth1 name :ns namespace-name}

   veth0 is in the default namespace (where XDP attaches)
   veth1 is in a test namespace (traffic source/sink)"
  [test-name]
  (let [veth0 (str "xdp-" test-name "0")
        veth1 (str "xdp-" test-name "1")
        ns-name (str "xdp-test-" test-name)]
    (log/info "Creating veth pair" veth0 "<->" veth1 "in namespace" ns-name)
    ;; Create namespace
    (exec "ip" "netns" "add" ns-name)
    ;; Create veth pair
    (exec "ip" "link" "add" veth0 "type" "veth" "peer" "name" veth1)
    ;; Move veth1 to namespace
    (exec "ip" "link" "set" veth1 "netns" ns-name)
    ;; Configure veth0 (XDP side)
    (exec "ip" "addr" "add" "10.200.1.1/24" "dev" veth0)
    (exec "ip" "link" "set" veth0 "up")
    ;; Configure veth1 (in namespace)
    (exec "ip" "netns" "exec" ns-name "ip" "addr" "add" "10.200.1.2/24" "dev" veth1)
    (exec "ip" "netns" "exec" ns-name "ip" "link" "set" veth1 "up")
    (exec "ip" "netns" "exec" ns-name "ip" "link" "set" "lo" "up")
    {:veth0 veth0
     :veth1 veth1
     :ns ns-name}))

(defn teardown-veth-pair
  "Remove veth pair and namespace."
  [{:keys [veth0 ns]}]
  (log/info "Cleaning up veth pair and namespace")
  (try
    ;; Detach XDP first (if attached)
    (try (xdp/detach-from-interface veth0) (catch Exception _))
    ;; Delete veth (automatically removes peer)
    (try (exec "ip" "link" "del" veth0) (catch Exception _))
    ;; Delete namespace
    (try (exec "ip" "netns" "del" ns) (catch Exception _))
    (catch Exception e
      (log/warn "Error during cleanup:" (.getMessage e)))))

(defmacro with-veth-pair
  "Execute body with a veth pair, cleaning up afterwards."
  [binding test-name & body]
  `(let [~binding (setup-veth-pair ~test-name)]
     (try
       ~@body
       (finally
         (teardown-veth-pair ~binding)))))

;;; =============================================================================
;;; Resource Management Macros
;;; =============================================================================

(defmacro with-xdp-attached
  "Attach XDP program to interface and ensure detachment after use.

   Example:
     (with-xdp-attached [_ prog veth0 :mode :skb]
       ;; XDP program is attached
       (do-tests))"
  [[binding prog iface & {:keys [mode] :or {mode :skb}}] & body]
  `(do
     (xdp/attach-to-interface ~prog ~iface :mode ~mode)
     (try
       (let [~binding ~iface]
         ~@body)
       (finally
         (xdp/detach-from-interface ~iface :mode ~mode)))))

(defmacro with-bpf-maps
  "Create multiple BPF maps and ensure they are closed after use.

   Example:
     (with-bpf-maps [listen-map (maps/create-listen-map {:max-listen-ports 10})
                     conntrack-map (maps/create-conntrack-map {:max-connections 100})]
       ;; Use maps
       (do-tests))"
  [bindings & body]
  (if (empty? bindings)
    `(do ~@body)
    (let [[binding expr & rest-bindings] bindings]
      `(let [~binding ~expr]
         (try
           (with-bpf-maps [~@rest-bindings]
             ~@body)
           (finally
             (bpf/close-map ~binding)))))))

;;; =============================================================================
;;; Connectivity Test Helpers
;;; =============================================================================

(defn ping-from-ns
  "Ping from the test namespace to the veth0 side.
   Returns true if ping succeeds."
  [ns-name target-ip & {:keys [count timeout] :or {count 3 timeout 2}}]
  (let [result (sh "ip" "netns" "exec" ns-name
                   "ping" "-c" (str count) "-W" (str timeout) target-ip)]
    (= 0 (:exit result))))

;;; =============================================================================
;;; XDP Load Tests
;;; =============================================================================

(deftest ^:integration test-xdp-pass-program
  ;; Test the simplest XDP program that just passes all packets
  (when (= 0 (-> (Runtime/getRuntime)
                 (.exec "id -u")
                 (.getInputStream)
                 (slurp)
                 (clojure.string/trim)
                 (Integer/parseInt)))
    (testing "Simple XDP pass program loads and allows traffic"
      (with-veth-pair veth "pass"
        (let [{:keys [veth0 ns]} veth]
          ;; Verify connectivity before XDP
          (is (ping-from-ns ns "10.200.1.1" :count 1)
              "Baseline connectivity should work")

          ;; Load and attach simple pass program using with-program
          (let [bytecode (xdp/build-xdp-pass-program)]
            (bpf/with-program [prog {:insns bytecode
                                     :prog-type :xdp
                                     :prog-name "xdp_pass"
                                     :license "GPL"
                                     :log-level 1}]
              (is prog "Program should load successfully")
              (is (:fd prog) "Program should have FD")

              ;; Attach to interface using with-xdp-attached
              (with-xdp-attached [_ prog veth0 :mode :skb]
                ;; Verify XDP is attached
                (let [link-info (exec "ip" "link" "show" veth0)]
                  (is (re-find #"xdp" link-info) "XDP should be attached"))

                ;; Traffic should still work
                (is (ping-from-ns ns "10.200.1.1" :count 3)
                    "Traffic should pass with XDP attached")))))))))

(deftest ^:integration test-xdp-ipv4-filter
  ;; Test IPv4 filter program
  (when (= 0 (-> (Runtime/getRuntime)
                 (.exec "id -u")
                 (.getInputStream)
                 (slurp)
                 (clojure.string/trim)
                 (Integer/parseInt)))
    (testing "IPv4 filter program loads and passes IPv4 traffic"
      (with-veth-pair veth "ipv4"
        (let [{:keys [veth0 ns]} veth]
          ;; Build and load IPv4 filter using with-program
          (let [bytecode (xdp/build-ipv4-filter-program)]
            (bpf/with-program [prog {:insns bytecode
                                     :prog-type :xdp
                                     :prog-name "xdp_ipv4"
                                     :license "GPL"
                                     :log-level 1}]
              (is prog "Program should load")

              (with-xdp-attached [_ prog veth0 :mode :skb]
                ;; IPv4 traffic should work
                (is (ping-from-ns ns "10.200.1.1" :count 3)
                    "IPv4 traffic should pass")))))))))

(deftest ^:integration test-xdp-dnat-program
  ;; Test the full DNAT program with maps
  (when (= 0 (-> (Runtime/getRuntime)
                 (.exec "id -u")
                 (.getInputStream)
                 (slurp)
                 (clojure.string/trim)
                 (Integer/parseInt)))
    (testing "XDP DNAT program loads with maps"
      (with-veth-pair veth "dnat"
        (let [{:keys [veth0 ns]} veth
              ifindex (util/get-interface-index veth0)]
          ;; Create maps using with-bpf-maps
          (with-bpf-maps [listen-map (maps/create-listen-map {:max-listen-ports 10})
                          conntrack-map (maps/create-conntrack-map {:max-connections 100})]
            ;; Add a listen port entry for our interface
            (maps/add-listen-port listen-map ifindex 80
              {:ip (util/ip-string->u32 "10.200.1.100")
               :port 8080})

            ;; Build and load DNAT program using with-program
            (let [bytecode (xdp/build-xdp-ingress-program
                            {:listen-map listen-map
                             :conntrack-map conntrack-map})]
              (log/info "XDP DNAT bytecode size:" (count bytecode) "bytes"
                        "(" (/ (count bytecode) 8) "instructions)")
              (bpf/with-program [prog {:insns bytecode
                                       :prog-type :xdp
                                       :prog-name "xdp_dnat"
                                       :license "GPL"
                                       :log-level 4}]
                (is prog "DNAT program should load")
                (is (:fd prog) "Program should have FD")
                (log/info "XDP DNAT program loaded successfully, fd:" (:fd prog))

                ;; Attach to interface using with-xdp-attached
                (with-xdp-attached [_ prog veth0 :mode :skb]
                  (log/info "XDP DNAT program attached to" veth0)

                  ;; Verify XDP is attached
                  (let [link-info (exec "ip" "link" "show" veth0)]
                    (is (re-find #"xdp" link-info) "XDP should be attached"))

                  ;; Non-TCP/UDP traffic (ICMP ping) should pass through
                  (is (ping-from-ns ns "10.200.1.1" :count 2)
                      "ICMP traffic should pass (not TCP/UDP)")

                  (log/info "XDP DNAT test completed successfully"))))))))))

;;; =============================================================================
;;; Manual Testing Entry Point
;;; =============================================================================

(defn run-xdp-load-tests
  "Run all XDP load tests."
  []
  (clojure.test/run-tests 'lb.xdp-load-test))

(defn manual-test
  "Manual interactive test - keeps XDP attached for inspection.
   Call (cleanup) when done."
  []
  (println "Setting up veth pair...")
  (let [veth (setup-veth-pair "manual")
        {:keys [veth0 ns]} veth
        ifindex (util/get-interface-index veth0)
        listen-map (maps/create-listen-map {:max-listen-ports 10})
        conntrack-map (maps/create-conntrack-map {:max-connections 100})]

    (println "Created veth pair:" veth0 "ifindex:" ifindex)

    ;; Add listen port
    (maps/add-listen-port listen-map ifindex 80
      {:ip (util/ip-string->u32 "10.200.1.100")
       :port 8080})
    (println "Added listen port: ifindex" ifindex "port 80 -> 10.200.1.100:8080")

    ;; Build and load program
    (println "Building XDP DNAT program...")
    (let [bytecode (xdp/build-xdp-ingress-program
                    {:listen-map listen-map
                     :conntrack-map conntrack-map})
          _ (println "Bytecode size:" (count bytecode) "bytes")
          prog (bpf/load-program {:insns bytecode
                                  :prog-type :xdp
                                  :prog-name "xdp_dnat"
                                  :license "GPL"
                                  :log-level 4})]
      (println "Program loaded, FD:" (:fd prog))

      ;; Attach
      (xdp/attach-to-interface prog veth0 :mode :skb)
      (println "XDP attached to" veth0)
      (println)
      (println "Test commands:")
      (println "  ping from namespace: ip netns exec" ns "ping 10.200.1.1")
      (println "  check XDP stats: ip link show" veth0)
      (println "  tcpdump: tcpdump -i" veth0 "-n")
      (println)
      (println "Call (cleanup) to tear down")

      ;; Return state for cleanup
      {:veth veth
       :listen-map listen-map
       :conntrack-map conntrack-map
       :prog prog})))

(defn cleanup
  "Cleanup after manual-test."
  [{:keys [veth listen-map conntrack-map prog]}]
  (println "Cleaning up...")
  (when veth
    (try (xdp/detach-from-interface (:veth0 veth)) (catch Exception _))
    (teardown-veth-pair veth))
  (when prog (try (bpf/close-program prog) (catch Exception _)))
  (when listen-map (try (bpf/close-map listen-map) (catch Exception _)))
  (when conntrack-map (try (bpf/close-map conntrack-map) (catch Exception _)))
  (println "Done"))
