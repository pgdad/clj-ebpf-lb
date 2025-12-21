(ns lb.config
  "Configuration management for the load balancer.
   Handles configuration data structures, validation, and persistence."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [lb.util :as util]
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

;;; Health Check Specs
(s/def ::health-check-type #{:tcp :http :https :none})
(s/def ::path (s/and string? #(clojure.string/starts-with? % "/")))
(s/def ::interval-ms (s/and int? #(>= % 1000) #(<= % 300000)))
(s/def ::timeout-ms (s/and int? #(>= % 100) #(<= % 60000)))
(s/def ::healthy-threshold (s/and int? #(>= % 1) #(<= % 10)))
(s/def ::unhealthy-threshold (s/and int? #(>= % 1) #(<= % 10)))
(s/def ::expected-codes (s/coll-of int? :min-count 1))

(s/def ::health-check
  (s/keys :opt-un [::health-check-type ::path ::interval-ms ::timeout-ms
                   ::healthy-threshold ::unhealthy-threshold ::expected-codes]))

;; Target specification (single target, with optional weight and health check)
(s/def ::ip ::ip-string)
(s/def ::target (s/keys :req-un [::ip ::port] :opt-un [::weight ::health-check]))

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

;; SNI route - routes based on TLS SNI hostname (exact match only)
(s/def ::sni-hostname (s/and string?
                             #(re-matches #"[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?" %)
                             #(<= (count %) 253)))  ; Max DNS name length
(s/def ::sni-route
  (s/and (s/keys :req-un [::sni-hostname]
                 :opt-un [::target ::targets])
         ;; Must have exactly one of :target or :targets
         #(or (and (contains? % :target) (not (contains? % :targets)))
              (and (contains? % :targets) (not (contains? % :target))))))
(s/def ::sni-routes (s/coll-of ::sni-route))

;; Proxy configuration
(s/def ::name (s/and string? #(> (count %) 0)))
;; Default target can be single target map or array of weighted targets
(s/def ::default-target (s/or :single ::target :weighted ::targets))
(s/def ::proxy-config
  (s/keys :req-un [::name ::listen ::default-target]
          :opt-un [::source-routes ::sni-routes]))

;; Global settings
(s/def ::stats-enabled boolean?)
(s/def ::connection-timeout-sec (s/and int? pos?))
(s/def ::max-connections (s/and int? pos?))
(s/def ::health-check-enabled boolean?)
(s/def ::health-check-defaults ::health-check)

;; Drain settings
(s/def ::default-drain-timeout-ms (s/and int? #(>= % 1000) #(<= % 3600000)))  ; 1s to 1h
(s/def ::drain-check-interval-ms (s/and int? #(>= % 100) #(<= % 60000)))       ; 100ms to 60s

(s/def ::settings
  (s/keys :opt-un [::stats-enabled ::connection-timeout-sec ::max-connections
                   ::health-check-enabled ::health-check-defaults
                   ::default-drain-timeout-ms ::drain-check-interval-ms]))

;; Full configuration
(s/def ::proxies (s/coll-of ::proxy-config :min-count 1))
(s/def ::config (s/keys :req-un [::proxies] :opt-un [::settings]))

;;; =============================================================================
;;; Configuration Data Types
;;; =============================================================================

;; Single target (ip and port as u32 values)
(defrecord Target [ip port])

;; Health check configuration for a target
;; type: :tcp, :http, :https, or :none
;; path: HTTP path to check (for :http/:https)
;; interval-ms: time between checks
;; timeout-ms: max time to wait for check
;; healthy-threshold: consecutive successes needed to mark healthy
;; unhealthy-threshold: consecutive failures needed to mark unhealthy
;; expected-codes: HTTP status codes considered healthy (default [200])
(defrecord HealthCheckConfig [type path interval-ms timeout-ms
                              healthy-threshold unhealthy-threshold
                              expected-codes])

;; Default health check configuration values
(def default-health-check-config
  {:type :tcp
   :path "/health"
   :interval-ms 10000
   :timeout-ms 3000
   :healthy-threshold 2
   :unhealthy-threshold 3
   :expected-codes [200 201 202 204]})

;; Weighted target extends Target with weight (1-100 percentage) and optional health check
(defrecord WeightedTarget [ip port weight health-check])

;; Group of weighted targets with cumulative weights for fast selection
;; targets: vector of WeightedTarget
;; cumulative-weights: vector of cumulative percentages, e.g., [50 80 100] for weights [50 30 20]
(defrecord TargetGroup [targets cumulative-weights])

;; Source route now holds a TargetGroup instead of single Target
(defrecord SourceRoute [source prefix-len target-group])

;; SNI route - routes TLS traffic based on SNI hostname
;; hostname: the TLS SNI hostname to match (exact match, lowercase)
;; hostname-hash: FNV-1a 64-bit hash of lowercase hostname for fast lookup
;; target-group: TargetGroup with weighted targets
(defrecord SNIRoute [hostname hostname-hash target-group])

(defrecord Listen [interfaces port])

;; ProxyConfig now holds TargetGroup for default-target
;; sni-routes: optional vector of SNIRoute for TLS SNI-based routing
(defrecord ProxyConfig [name listen default-target source-routes sni-routes])

(defrecord Settings [stats-enabled connection-timeout-sec max-connections
                     health-check-enabled health-check-defaults
                     default-drain-timeout-ms drain-check-interval-ms])
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

(defn parse-health-check-config
  "Parse health check configuration, merging with defaults."
  [health-check-map global-defaults]
  (when (and health-check-map (not= (:type health-check-map) :none))
    (let [defaults (merge default-health-check-config global-defaults)
          merged (merge defaults health-check-map)]
      (->HealthCheckConfig
        (:type merged)
        (:path merged)
        (:interval-ms merged)
        (:timeout-ms merged)
        (:healthy-threshold merged)
        (:unhealthy-threshold merged)
        (:expected-codes merged)))))

(defn parse-weighted-target
  "Parse a target map to WeightedTarget record with resolved IP.
   If weight is not specified, defaults to 100 (for single target scenarios).
   global-health-defaults: optional global health check defaults from settings."
  ([target-map] (parse-weighted-target target-map nil))
  ([{:keys [ip port weight health-check]} global-health-defaults]
   (->WeightedTarget
     (util/ip-string->u32 ip)
     port
     (or weight 100)
     (parse-health-check-config health-check global-health-defaults))))

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

(defn parse-sni-route
  "Parse an SNI route for TLS SNI-based routing.
   Supports both :target (single) and :targets (weighted array) formats."
  [{:keys [sni-hostname target targets]} proxy-name]
  (let [hostname (clojure.string/lower-case sni-hostname)
        hostname-hash (util/hostname->hash hostname)
        target-spec (or targets target)
        context (format "proxy '%s' sni-route %s" proxy-name sni-hostname)]
    (->SNIRoute hostname hostname-hash (parse-target-group target-spec context))))

(defn parse-listen
  "Parse listen configuration."
  [{:keys [interfaces port]}]
  (->Listen (vec interfaces) port))

(defn parse-proxy-config
  "Parse a single proxy configuration."
  [{:keys [name listen default-target source-routes sni-routes]}]
  (let [default-context (format "proxy '%s' default-target" name)]
    (->ProxyConfig
      name
      (parse-listen listen)
      (parse-target-group default-target default-context)
      (mapv #(parse-source-route % name) (or source-routes []))
      (mapv #(parse-sni-route % name) (or sni-routes [])))))

(defn parse-settings
  "Parse settings with defaults."
  [settings]
  (->Settings
    (get settings :stats-enabled false)
    (get settings :connection-timeout-sec 300)
    (get settings :max-connections 100000)
    (get settings :health-check-enabled false)
    (get settings :health-check-defaults default-health-check-config)
    (get settings :default-drain-timeout-ms 30000)       ; 30 seconds default
    (get settings :drain-check-interval-ms 1000)))

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

(defn health-check->map
  "Convert a HealthCheckConfig back to EDN format."
  [^HealthCheckConfig hc]
  (when hc
    {:type (:type hc)
     :path (:path hc)
     :interval-ms (:interval-ms hc)
     :timeout-ms (:timeout-ms hc)
     :healthy-threshold (:healthy-threshold hc)
     :unhealthy-threshold (:unhealthy-threshold hc)
     :expected-codes (:expected-codes hc)}))

(defn target-group->map
  "Convert a TargetGroup back to EDN format.
   Returns a single target map if only one target, otherwise a vector."
  [^TargetGroup tg]
  (let [targets (:targets tg)]
    (if (= 1 (count targets))
      ;; Single target - return simple map without weight
      (let [t (first targets)
            base {:ip (util/u32->ip-string (:ip t))
                  :port (:port t)}]
        (if (:health-check t)
          (assoc base :health-check (health-check->map (:health-check t)))
          base))
      ;; Multiple targets - return array with weights
      (mapv (fn [t]
              (let [base {:ip (util/u32->ip-string (:ip t))
                          :port (:port t)
                          :weight (:weight t)}]
                (if (:health-check t)
                  (assoc base :health-check (health-check->map (:health-check t)))
                  base)))
            targets))))

(defn sni-route->map
  "Convert an SNIRoute back to EDN format."
  [^SNIRoute sr]
  (let [target-map (target-group->map (:target-group sr))
        base-route {:sni-hostname (:hostname sr)}]
    ;; Use :targets if multiple, :target if single
    (if (vector? target-map)
      (assoc base-route :targets target-map)
      (assoc base-route :target target-map))))

(defn config->map
  "Convert parsed Config back to plain EDN map."
  [^Config config]
  {:proxies
   (mapv (fn [^ProxyConfig p]
           (let [base {:name (:name p)
                       :listen {:interfaces (vec (get-in p [:listen :interfaces]))
                                :port (get-in p [:listen :port])}
                       :default-target (target-group->map (:default-target p))}
                 ;; Add source-routes if present
                 with-source (if (seq (:source-routes p))
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
                               base)]
             ;; Add sni-routes if present
             (if (seq (:sni-routes p))
               (assoc with-source :sni-routes (mapv sni-route->map (:sni-routes p)))
               with-source)))
         (:proxies config))
   :settings
   {:stats-enabled (get-in config [:settings :stats-enabled])
    :connection-timeout-sec (get-in config [:settings :connection-timeout-sec])
    :max-connections (get-in config [:settings :max-connections])
    :health-check-enabled (get-in config [:settings :health-check-enabled])
    :health-check-defaults (get-in config [:settings :health-check-defaults])
    :default-drain-timeout-ms (get-in config [:settings :default-drain-timeout-ms])
    :drain-check-interval-ms (get-in config [:settings :drain-check-interval-ms])}})

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
  (->Settings false 300 100000 false default-health-check-config 30000 1000))

(defn make-single-target-group
  "Create a TargetGroup with a single target.
   Convenience function for simple configurations."
  ([ip port] (make-single-target-group ip port nil))
  ([ip port health-check]
   (let [ip-u32 (if (string? ip) (util/ip-string->u32 ip) ip)]
     (->TargetGroup
       [(->WeightedTarget ip-u32 port 100 health-check)]
       [100]))))

(defn make-weighted-target-group
  "Create a TargetGroup with multiple weighted targets.
   targets should be a sequence of {:ip :port :weight :health-check} maps.
   Validates that weights sum to 100."
  [targets]
  (validate-target-weights! targets "make-weighted-target-group")
  (let [parsed (mapv (fn [{:keys [ip port weight health-check]}]
                       (->WeightedTarget (util/ip-string->u32 ip) port weight
                                         (when health-check
                                           (parse-health-check-config health-check nil))))
                     targets)
        cumulative (compute-cumulative-weights parsed)]
    (->TargetGroup parsed cumulative)))

(defn make-simple-config
  "Create a simple single-proxy configuration.
   Useful for quick testing or simple deployments."
  [{:keys [name interface port target-ip target-port stats-enabled health-check-enabled]
    :or {name "default"
         interface "eth0"
         port 80
         target-ip "127.0.0.1"
         target-port 8080
         stats-enabled false
         health-check-enabled false}}]
  (->Config
    [(->ProxyConfig
       name
       (->Listen [interface] port)
       (make-single-target-group target-ip target-port)
       []   ; source-routes
       [])] ; sni-routes
    (->Settings stats-enabled 300 100000 health-check-enabled default-health-check-config
                30000 1000)))

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

(defn add-sni-route-to-proxy
  "Add an SNI route to a proxy.
   sni-route can be an SNIRoute record or a map with :sni-hostname and :target/:targets."
  [^Config config proxy-name sni-route]
  (let [route (if (instance? SNIRoute sni-route)
                sni-route
                (parse-sni-route sni-route proxy-name))]
    ;; Check for duplicate hostname
    (let [proxy (get-proxy config proxy-name)]
      (when (some #(= (:hostname %) (:hostname route)) (:sni-routes proxy))
        (throw (ex-info "SNI route for this hostname already exists"
                        {:hostname (:hostname route) :proxy proxy-name}))))
    (update-proxy config proxy-name
                  #(update % :sni-routes conj route))))

(defn remove-sni-route-from-proxy
  "Remove an SNI route from a proxy by hostname."
  [^Config config proxy-name hostname]
  (let [normalized-hostname (clojure.string/lower-case hostname)]
    (update-proxy config proxy-name
                  #(update % :sni-routes
                           (fn [routes]
                             (vec (remove (fn [r]
                                            (= (:hostname r) normalized-hostname))
                                          routes)))))))

(defn update-sni-route-in-proxy
  "Update an existing SNI route in a proxy by hostname.
   new-sni-route should be a map with :sni-hostname and :target/:targets."
  [^Config config proxy-name hostname new-sni-route]
  (let [normalized-hostname (clojure.string/lower-case hostname)
        new-route (parse-sni-route new-sni-route proxy-name)]
    (update-proxy config proxy-name
                  #(update % :sni-routes
                           (fn [routes]
                             (mapv (fn [r]
                                     (if (= (:hostname r) normalized-hostname)
                                       new-route
                                       r))
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
                       (:source-routes proxy)))
                "\n"))
         (when (seq (:sni-routes proxy))
           (str "  SNI routes:\n"
                (clojure.string/join "\n"
                  (map (fn [^SNIRoute r]
                         (str "    " (:hostname r)
                              " -> " (format-target-group (:target-group r))))
                       (:sni-routes proxy))))))))

(defn format-config
  "Format full configuration for display."
  [^Config config]
  (str "=== Load Balancer Configuration ===\n\n"
       (clojure.string/join "\n\n" (map format-proxy (:proxies config)))
       "\n\n=== Settings ===\n"
       "  Stats enabled: " (get-in config [:settings :stats-enabled]) "\n"
       "  Connection timeout: " (get-in config [:settings :connection-timeout-sec]) " sec\n"
       "  Max connections: " (get-in config [:settings :max-connections])))
