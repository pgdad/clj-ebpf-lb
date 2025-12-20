(ns reverse-proxy.config
  "Configuration management for the reverse proxy.
   Handles configuration data structures, validation, and persistence."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [reverse-proxy.util :as util]
            [clojure.tools.logging :as log]))

;;; =============================================================================
;;; Specs for Configuration Validation
;;; =============================================================================

;; IP address as string
(s/def ::ip-string (s/and string? #(re-matches #"\d+\.\d+\.\d+\.\d+" %)))

;; CIDR notation
(s/def ::cidr-string (s/and string? #(re-matches #"\d+\.\d+\.\d+\.\d+(/\d+)?" %)))

;; Hostname
(s/def ::hostname (s/and string? #(re-matches #"[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*" %)))

;; Source specification (IP, CIDR, or hostname)
(s/def ::source (s/or :cidr ::cidr-string :hostname ::hostname))

;; Port number
(s/def ::port (s/and int? #(>= % 1) #(<= % 65535)))

;; Weight for load balancing (1-100, represents percentage)
(s/def ::weight (s/and int? #(>= % 1) #(<= % 100)))

;; Target specification (single target, with optional weight)
(s/def ::ip ::ip-string)
(s/def ::target (s/keys :req-un [::ip ::port] :opt-un [::weight]))

;; Weighted targets array (for load balancing across multiple backends)
(s/def ::targets (s/coll-of ::target :min-count 1 :max-count 8))

;; Interface name
(s/def ::interface (s/and string? #(re-matches #"[a-zA-Z0-9\-_]+" %)))
(s/def ::interfaces (s/coll-of ::interface :min-count 1))

;; Listen specification
(s/def ::listen (s/keys :req-un [::interfaces ::port]))

;; Source route - supports either :target (single) or :targets (weighted array)
(s/def ::source-route
  (s/and (s/keys :req-un [::source]
                 :opt-un [::target ::targets])
         ;; Must have exactly one of :target or :targets
         #(or (and (contains? % :target) (not (contains? % :targets)))
              (and (contains? % :targets) (not (contains? % :target))))))
(s/def ::source-routes (s/coll-of ::source-route))

;; Proxy configuration
(s/def ::name (s/and string? #(> (count %) 0)))
;; Default target can be single target map or array of weighted targets
(s/def ::default-target (s/or :single ::target :weighted ::targets))
(s/def ::proxy-config
  (s/keys :req-un [::name ::listen ::default-target]
          :opt-un [::source-routes]))

;; Global settings
(s/def ::stats-enabled boolean?)
(s/def ::connection-timeout-sec (s/and int? pos?))
(s/def ::max-connections (s/and int? pos?))
(s/def ::settings
  (s/keys :opt-un [::stats-enabled ::connection-timeout-sec ::max-connections]))

;; Full configuration
(s/def ::proxies (s/coll-of ::proxy-config :min-count 1))
(s/def ::config (s/keys :req-un [::proxies] :opt-un [::settings]))

;;; =============================================================================
;;; Configuration Data Types
;;; =============================================================================

;; Single target (ip and port as u32 values)
(defrecord Target [ip port])

;; Weighted target extends Target with weight (1-100 percentage)
(defrecord WeightedTarget [ip port weight])

;; Group of weighted targets with cumulative weights for fast selection
;; targets: vector of WeightedTarget
;; cumulative-weights: vector of cumulative percentages, e.g., [50 80 100] for weights [50 30 20]
(defrecord TargetGroup [targets cumulative-weights])

;; Source route now holds a TargetGroup instead of single Target
(defrecord SourceRoute [source prefix-len target-group])

(defrecord Listen [interfaces port])

;; ProxyConfig now holds TargetGroup for default-target
(defrecord ProxyConfig [name listen default-target source-routes])

(defrecord Settings [stats-enabled connection-timeout-sec max-connections])
(defrecord Config [proxies settings])

;;; =============================================================================
;;; Weight Validation
;;; =============================================================================

(defn validate-weights
  "Validate weights for a group of targets.
   Returns nil if valid, error message string if invalid.

   Rules:
   - Single target: weight is optional and ignored
   - Multiple targets: all must have explicit weights that sum to 100"
  [targets]
  (if (= 1 (count targets))
    nil  ; Single target always valid
    (let [weights (map #(:weight %) targets)
          has-missing (some nil? weights)
          total (reduce + 0 (remove nil? weights))]
      (cond
        has-missing "All targets must have explicit weights when multiple targets are specified"
        (not= 100 total) (format "Weights must sum to 100, got %d" total)
        :else nil))))

(defn validate-target-weights!
  "Validate weights for targets, throwing on error.
   context-msg should describe where the targets are (e.g., 'proxy web default-target')"
  [targets context-msg]
  (when-let [error (validate-weights targets)]
    (throw (ex-info (str "Weight validation failed for " context-msg ": " error)
                    {:context context-msg
                     :targets targets
                     :error error}))))

;;; =============================================================================
;;; Configuration Parsing
;;; =============================================================================

(defn parse-weighted-target
  "Parse a target map to WeightedTarget record with resolved IP.
   If weight is not specified, defaults to 100 (for single target scenarios)."
  [{:keys [ip port weight]}]
  (->WeightedTarget (util/ip-string->u32 ip) port (or weight 100)))

(defn compute-cumulative-weights
  "Compute cumulative weights from a sequence of WeightedTarget records.
   Example: targets with weights [50, 30, 20] -> cumulative [50, 80, 100]"
  [targets]
  (reduce (fn [acc target]
            (conj acc (+ (or (peek acc) 0) (:weight target))))
          []
          targets))

(defn parse-target-group
  "Parse a target specification into a TargetGroup.
   Accepts either a single target map or a vector of targets.
   Validates weights for multi-target groups."
  [target-spec context-msg]
  (let [targets (if (vector? target-spec) target-spec [target-spec])]
    ;; Validate weights before parsing
    (validate-target-weights! targets context-msg)
    (let [parsed (mapv parse-weighted-target targets)
          cumulative (compute-cumulative-weights parsed)]
      (->TargetGroup parsed cumulative))))

(defn parse-target
  "Parse a single target map to Target record with resolved IP.
   Kept for backward compatibility."
  [{:keys [ip port]}]
  (->Target (util/ip-string->u32 ip) port))

(defn parse-source-route
  "Parse a source route, resolving hostname if necessary.
   Supports both :target (single) and :targets (weighted array) formats."
  [{:keys [source target targets]} proxy-name]
  (let [{:keys [ip prefix-len]} (util/resolve-to-ip source)]
    (when (nil? ip)
      (throw (ex-info "Failed to resolve source" {:source source})))
    (let [target-spec (or targets target)
          context (format "proxy '%s' source-route %s" proxy-name source)]
      (->SourceRoute ip prefix-len (parse-target-group target-spec context)))))

(defn parse-listen
  "Parse listen configuration."
  [{:keys [interfaces port]}]
  (->Listen (vec interfaces) port))

(defn parse-proxy-config
  "Parse a single proxy configuration."
  [{:keys [name listen default-target source-routes]}]
  (let [default-context (format "proxy '%s' default-target" name)]
    (->ProxyConfig
      name
      (parse-listen listen)
      (parse-target-group default-target default-context)
      (mapv #(parse-source-route % name) (or source-routes [])))))

(defn parse-settings
  "Parse settings with defaults."
  [settings]
  (->Settings
    (get settings :stats-enabled false)
    (get settings :connection-timeout-sec 300)
    (get settings :max-connections 100000)))

(defn parse-config
  "Parse full configuration from EDN map."
  [{:keys [proxies settings]}]
  (->Config
    (mapv parse-proxy-config proxies)
    (parse-settings (or settings {}))))

;;; =============================================================================
;;; Configuration Validation
;;; =============================================================================

(defn validate-config
  "Validate configuration map against spec.
   Returns {:valid true :config <parsed>} or {:valid false :errors <explain-data>}"
  [config-map]
  (if (s/valid? ::config config-map)
    {:valid true
     :config (parse-config config-map)}
    {:valid false
     :errors (s/explain-data ::config config-map)}))

(defn validate-proxy-config
  "Validate a single proxy configuration."
  [proxy-map]
  (if (s/valid? ::proxy-config proxy-map)
    {:valid true
     :config (parse-proxy-config proxy-map)}
    {:valid false
     :errors (s/explain-data ::proxy-config proxy-map)}))

;;; =============================================================================
;;; Configuration Persistence
;;; =============================================================================

(defn load-config-file
  "Load configuration from an EDN file."
  [path]
  (log/info "Loading configuration from:" path)
  (try
    (let [config-map (edn/read-string (slurp path))
          validation (validate-config config-map)]
      (if (:valid validation)
        (:config validation)
        (throw (ex-info "Invalid configuration" {:errors (:errors validation)}))))
    (catch java.io.FileNotFoundException _
      (throw (ex-info "Configuration file not found" {:path path})))))

(defn target-group->map
  "Convert a TargetGroup back to EDN format.
   Returns a single target map if only one target, otherwise a vector."
  [^TargetGroup tg]
  (let [targets (:targets tg)]
    (if (= 1 (count targets))
      ;; Single target - return simple map without weight
      (let [t (first targets)]
        {:ip (util/u32->ip-string (:ip t))
         :port (:port t)})
      ;; Multiple targets - return array with weights
      (mapv (fn [t]
              {:ip (util/u32->ip-string (:ip t))
               :port (:port t)
               :weight (:weight t)})
            targets))))

(defn config->map
  "Convert parsed Config back to plain EDN map."
  [^Config config]
  {:proxies
   (mapv (fn [^ProxyConfig p]
           (let [base {:name (:name p)
                       :listen {:interfaces (vec (get-in p [:listen :interfaces]))
                                :port (get-in p [:listen :port])}
                       :default-target (target-group->map (:default-target p))}]
             (if (seq (:source-routes p))
               (assoc base :source-routes
                      (mapv (fn [^SourceRoute sr]
                              (let [source-str (util/cidr->string {:ip (:source sr) :prefix-len (:prefix-len sr)})
                                    target-map (target-group->map (:target-group sr))
                                    base-route {:source source-str}]
                                ;; Use :targets if multiple, :target if single
                                (if (vector? target-map)
                                  (assoc base-route :targets target-map)
                                  (assoc base-route :target target-map))))
                            (:source-routes p)))
               base)))
         (:proxies config))
   :settings
   {:stats-enabled (get-in config [:settings :stats-enabled])
    :connection-timeout-sec (get-in config [:settings :connection-timeout-sec])
    :max-connections (get-in config [:settings :max-connections])}})

(defn save-config-file
  "Save configuration to an EDN file."
  [config path]
  (log/info "Saving configuration to:" path)
  (let [config-map (config->map config)]
    (spit path (pr-str config-map))))

;;; =============================================================================
;;; Default Configuration
;;; =============================================================================

(def default-settings
  "Default settings values."
  (->Settings false 300 100000))

(defn make-single-target-group
  "Create a TargetGroup with a single target.
   Convenience function for simple configurations."
  [ip port]
  (let [ip-u32 (if (string? ip) (util/ip-string->u32 ip) ip)]
    (->TargetGroup
      [(->WeightedTarget ip-u32 port 100)]
      [100])))

(defn make-weighted-target-group
  "Create a TargetGroup with multiple weighted targets.
   targets should be a sequence of {:ip :port :weight} maps.
   Validates that weights sum to 100."
  [targets]
  (validate-target-weights! targets "make-weighted-target-group")
  (let [parsed (mapv (fn [{:keys [ip port weight]}]
                       (->WeightedTarget (util/ip-string->u32 ip) port weight))
                     targets)
        cumulative (compute-cumulative-weights parsed)]
    (->TargetGroup parsed cumulative)))

(defn make-simple-config
  "Create a simple single-proxy configuration.
   Useful for quick testing or simple deployments."
  [{:keys [name interface port target-ip target-port stats-enabled]
    :or {name "default"
         interface "eth0"
         port 80
         target-ip "127.0.0.1"
         target-port 8080
         stats-enabled false}}]
  (->Config
    [(->ProxyConfig
       name
       (->Listen [interface] port)
       (make-single-target-group target-ip target-port)
       [])]
    (->Settings stats-enabled 300 100000)))

;;; =============================================================================
;;; Configuration Modification
;;; =============================================================================

(defn add-proxy
  "Add a new proxy configuration."
  [^Config config proxy-config]
  (let [parsed (if (instance? ProxyConfig proxy-config)
                 proxy-config
                 (parse-proxy-config proxy-config))]
    (when (some #(= (:name %) (:name parsed)) (:proxies config))
      (throw (ex-info "Proxy with this name already exists" {:name (:name parsed)})))
    (update config :proxies conj parsed)))

(defn remove-proxy
  "Remove a proxy configuration by name."
  [^Config config proxy-name]
  (update config :proxies (fn [proxies]
                            (vec (remove #(= (:name %) proxy-name) proxies)))))

(defn update-proxy
  "Update a proxy configuration by name."
  [^Config config proxy-name update-fn]
  (update config :proxies
          (fn [proxies]
            (mapv (fn [p]
                    (if (= (:name p) proxy-name)
                      (update-fn p)
                      p))
                  proxies))))

(defn get-proxy
  "Get a proxy configuration by name."
  [^Config config proxy-name]
  (first (filter #(= (:name %) proxy-name) (:proxies config))))

(defn add-source-route-to-proxy
  "Add a source route to a proxy.
   source-route can be a SourceRoute record or a map with :source and :target/:targets."
  [^Config config proxy-name source-route]
  (let [route (if (instance? SourceRoute source-route)
                source-route
                (parse-source-route source-route proxy-name))]
    (update-proxy config proxy-name
                  #(update % :source-routes conj route))))

(defn remove-source-route-from-proxy
  "Remove a source route from a proxy by source IP/prefix."
  [^Config config proxy-name source-ip prefix-len]
  (update-proxy config proxy-name
                #(update % :source-routes
                         (fn [routes]
                           (vec (remove (fn [r]
                                          (and (= (:source r) source-ip)
                                               (= (:prefix-len r) prefix-len)))
                                        routes))))))

(defn update-settings
  "Update global settings."
  [^Config config new-settings]
  (assoc config :settings
         (merge (:settings config)
                (if (instance? Settings new-settings)
                  new-settings
                  (parse-settings new-settings)))))

;;; =============================================================================
;;; Configuration Display
;;; =============================================================================

(defn format-target-group
  "Format a TargetGroup for display."
  [^TargetGroup tg]
  (let [targets (:targets tg)]
    (if (= 1 (count targets))
      (let [t (first targets)]
        (str (util/u32->ip-string (:ip t)) ":" (:port t)))
      (clojure.string/join ", "
        (map (fn [t]
               (str (util/u32->ip-string (:ip t)) ":" (:port t)
                    " (" (:weight t) "%)"))
             targets)))))

(defn format-proxy
  "Format a proxy configuration for display."
  [^ProxyConfig proxy]
  (let [listen (:listen proxy)
        default (:default-target proxy)]
    (str "Proxy: " (:name proxy) "\n"
         "  Listen: " (clojure.string/join ", " (:interfaces listen))
         " port " (:port listen) "\n"
         "  Default target: " (format-target-group default) "\n"
         (when (seq (:source-routes proxy))
           (str "  Source routes:\n"
                (clojure.string/join "\n"
                  (map (fn [^SourceRoute r]
                         (str "    " (util/cidr->string {:ip (:source r) :prefix-len (:prefix-len r)})
                              " -> " (format-target-group (:target-group r))))
                       (:source-routes proxy))))))))

(defn format-config
  "Format full configuration for display."
  [^Config config]
  (str "=== Reverse Proxy Configuration ===\n\n"
       (clojure.string/join "\n\n" (map format-proxy (:proxies config)))
       "\n\n=== Settings ===\n"
       "  Stats enabled: " (get-in config [:settings :stats-enabled]) "\n"
       "  Connection timeout: " (get-in config [:settings :connection-timeout-sec]) " sec\n"
       "  Max connections: " (get-in config [:settings :max-connections])))
