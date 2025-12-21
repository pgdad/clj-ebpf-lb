(ns lb.test-util
  "Shared test utilities and macros for clj-ebpf-lb tests."
  (:require [clj-ebpf.core :as bpf]))

;;; =============================================================================
;;; Root Privilege Checking
;;; =============================================================================

(defn root?
  "Returns true if the current process is running as root (uid 0).
   Used to conditionally run integration tests that require BPF privileges."
  []
  (try
    (= 0 (-> (Runtime/getRuntime)
             (.exec "id -u")
             (.getInputStream)
             (slurp)
             (clojure.string/trim)
             (Integer/parseInt)))
    (catch Exception _
      false)))

(defmacro when-root
  "Execute body only if running as root (uid 0).
   Returns nil if not running as root.

   Example:
     (deftest ^:integration my-test
       (when-root
         (testing \"requires root\"
           ;; test code
           )))"
  [& body]
  `(when (root?)
     ~@body))

;;; =============================================================================
;;; BPF Resource Management Macros
;;; =============================================================================

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

(defmacro with-xdp-attached
  "Attach XDP program to interface and ensure detachment after use.

   Example:
     (with-xdp-attached [_ prog veth0 :mode :skb]
       ;; XDP program is attached
       (do-tests))"
  [[binding prog iface & {:keys [mode] :or {mode :skb}}] detach-fn & body]
  `(do
     ;; Attach is done by caller before this macro
     (try
       (let [~binding ~iface]
         ~@body)
       (finally
         (~detach-fn ~iface :mode ~mode)))))
