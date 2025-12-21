(ns lb.config
  "Configuration management for the load balancer.
   Handles configuration data structures, validation, and persistence."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.set :as set]
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

;; DNS-backed target specification (uses hostname instead of IP)
(s/def ::host ::hostname)
(s/def ::dns-refresh-seconds (s/and int? #(>= % 1) #(<= % 3600)))
(s/def ::dns-target (s/keys :req-un [::host ::port]
                            :opt-un [::weight ::health-check ::dns-refresh-seconds]))

;; Weighted targets array (for load balancing across multiple backends)
;; Can contain either IP-based or DNS-based targets
(s/def ::targets (s/coll-of (s/or :ip-target ::target :dns-target ::dns-target)
                            :min-count 1 :max-count 8))

;; Interface name
(s/def ::interface (s/and string? #(re-matches #"[a-zA-Z0-9\-_]+" %)))
(s/def ::interfaces (s/coll-of ::interface :min-count 1))

;; Listen specification
(s/def ::listen (s/keys :req-un [::interfaces ::port]))

;; Session persistence (sticky sessions based on source IP hash)
(s/def ::session-persistence boolean?)

;; Source route - supports either :target (single) or :targets (weighted array)
(s/def ::source-route
  (s/and (s/keys :req-un [::source]
                 :opt-un [::target ::targets ::session-persistence])
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
                 :opt-un [::target ::targets ::session-persistence])
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
          :opt-un [::source-routes ::sni-routes ::session-persistence ::health-check]))

;; Global settings
(s/def ::stats-enabled boolean?)
(s/def ::connection-timeout-sec (s/and int? pos?))
(s/def ::max-connections (s/and int? pos?))
(s/def ::health-check-enabled boolean?)
(s/def ::health-check-defaults ::health-check)

;; Drain settings
(s/def ::default-drain-timeout-ms (s/and int? #(>= % 1000) #(<= % 3600000)))  ; 1s to 1h
(s/def ::drain-check-interval-ms (s/and int? #(>= % 100) #(<= % 60000)))       ; 100ms to 60s

;; Rate limit settings
(s/def ::requests-per-sec (s/and int? pos?))  ; Tokens per second
(s/def ::burst (s/and int? pos?))              ; Max burst size

(s/def ::per-source-rate-limit
  (s/keys :req-un [::requests-per-sec]
          :opt-un [::burst]))

(s/def ::per-backend-rate-limit
  (s/keys :req-un [::requests-per-sec]
          :opt-un [::burst]))

(s/def ::rate-limits
  (s/keys :opt-un [::per-source ::per-backend]))

;; Alias per-source and per-backend to rate limit specs
(s/def ::per-source ::per-source-rate-limit)
(s/def ::per-backend ::per-backend-rate-limit)

;; Metrics settings
(s/def ::metrics-enabled boolean?)
(s/def ::metrics-port (s/and int? #(>= % 1024) #(<= % 65535)))
(s/def ::metrics-path (s/and string? #(clojure.string/starts-with? % "/")))

(s/def ::metrics
  (s/keys :opt-un [::metrics-enabled ::metrics-port ::metrics-path]))

;; Alias for nested map keys
(s/def ::enabled boolean?)

;; Circuit breaker settings
(s/def ::error-threshold-pct (s/and int? #(>= % 1) #(<= % 100)))
(s/def ::cb-min-requests (s/and int? #(>= % 1) #(<= % 10000)))
(s/def ::open-duration-ms (s/and int? #(>= % 1000) #(<= % 600000)))
(s/def ::half-open-requests (s/and int? #(>= % 1) #(<= % 100)))
(s/def ::window-size-ms (s/and int? #(>= % 1000) #(<= % 300000)))

(s/def ::circuit-breaker
  (s/keys :opt-un [::enabled ::error-threshold-pct ::cb-min-requests
                   ::open-duration-ms ::half-open-requests ::window-size-ms]))

;; Load balancing settings
(s/def ::lb-algorithm #{:weighted-random :least-connections})
(s/def ::lb-weighted boolean?)
(s/def ::lb-update-interval-ms (s/and int? #(>= % 100) #(<= % 10000)))

(s/def ::load-balancing
  (s/keys :opt-un [::lb-algorithm ::lb-weighted ::lb-update-interval-ms]))

;; Access log settings
(s/def ::access-log-format #{:json :clf})
(s/def ::access-log-path (s/and string? #(not (clojure.string/blank? %))))
(s/def ::access-log-max-file-size-mb (s/and int? #(>= % 1) #(<= % 1024)))
(s/def ::access-log-max-files (s/and int? #(>= % 1) #(<= % 100)))
(s/def ::access-log-buffer-size (s/and int? #(>= % 100) #(<= % 100000)))

(s/def ::access-log
  (s/keys :opt-un [::enabled ::access-log-format ::access-log-path
                   ::access-log-max-file-size-mb ::access-log-max-files
                   ::access-log-buffer-size]))

(s/def ::settings
  (s/keys :opt-un [::stats-enabled ::connection-timeout-sec ::max-connections
                   ::health-check-enabled ::health-check-defaults
                   ::default-drain-timeout-ms ::drain-check-interval-ms
                   ::rate-limits ::metrics ::circuit-breaker ::load-balancing
                   ::access-log]))

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

;; DNS-backed weighted target - resolved to IPs at runtime
;; host: hostname to resolve
;; port: target port
;; weight: weight for this target (1-100)
;; dns-refresh-seconds: how often to re-resolve DNS
;; health-check: optional health check config
(defrecord DNSWeightedTarget [host port weight dns-refresh-seconds health-check])

;; Group of weighted targets with cumulative weights for fast selection
;; targets: vector of WeightedTarget
;; cumulative-weights: vector of cumulative percentages, e.g., [50 80 100] for weights [50 30 20]
(defrecord TargetGroup [targets cumulative-weights])

;; Target group that includes DNS-backed targets (before resolution)
;; Used during config parsing; resolved to TargetGroup at runtime
;; dns-targets: vector of DNSWeightedTarget
;; static-targets: vector of WeightedTarget (already resolved)
(defrecord DNSTargetGroup [dns-targets static-targets])

;; Circuit breaker configuration
;; enabled: whether circuit breaker is active
;; error-threshold-pct: error rate percentage to trigger open state (1-100)
;; min-requests: minimum requests in window before evaluating threshold
;; open-duration-ms: time to stay in open state before trying half-open
;; half-open-requests: successful requests needed in half-open to close
;; window-size-ms: sliding window size for error rate calculation
(defrecord CircuitBreakerConfig [enabled error-threshold-pct min-requests
                                  open-duration-ms half-open-requests window-size-ms])

;; Default circuit breaker configuration values
(def default-circuit-breaker-config
  {:enabled false
   :error-threshold-pct 50
   :min-requests 10
   :open-duration-ms 30000
   :half-open-requests 3
   :window-size-ms 60000})

;; Load balancing configuration
;; algorithm: :weighted-random (default) or :least-connections
;; weighted: whether to factor in original weights (default true)
;; update-interval-ms: how often to update weights for least-connections (default 1000)
(defrecord LoadBalancingConfig [algorithm weighted update-interval-ms])

;; Access log configuration
;; enabled: whether access logging is active
;; format: :json (default) or :clf (Common Log Format)
;; path: file path for log output (e.g., "logs/access.log")
;; max-file-size-mb: max size before rotation (default 100)
;; max-files: max number of rotated files to keep (default 10)
;; buffer-size: async channel buffer size (default 10000)
(defrecord AccessLogConfig [enabled format path max-file-size-mb max-files buffer-size])

;; Default load balancing configuration values
(def default-load-balancing-config
  {:algorithm :weighted-random
   :weighted true
   :update-interval-ms 1000})

;; Default access log configuration values
(def default-access-log-config
  {:enabled false
   :format :json
   :path "logs/access.log"
   :max-file-size-mb 100
   :max-files 10
   :buffer-size 10000})

;; Source route now holds a TargetGroup instead of single Target
;; session-persistence: optional boolean for sticky sessions
(defrecord SourceRoute [source prefix-len target-group session-persistence])

;; SNI route - routes TLS traffic based on SNI hostname
;; hostname: the TLS SNI hostname to match (exact match, lowercase)
;; hostname-hash: FNV-1a 64-bit hash of lowercase hostname for fast lookup
;; target-group: TargetGroup with weighted targets
;; session-persistence: optional boolean for sticky sessions
(defrecord SNIRoute [hostname hostname-hash target-group session-persistence])

(defrecord Listen [interfaces port])

;; ProxyConfig now holds TargetGroup for default-target
;; sni-routes: optional vector of SNIRoute for TLS SNI-based routing
;; session-persistence: optional boolean for sticky sessions on default-target
(defrecord ProxyConfig [name listen default-target source-routes sni-routes session-persistence])

(defrecord Settings [stats-enabled connection-timeout-sec max-connections
                     health-check-enabled health-check-defaults
                     default-drain-timeout-ms drain-check-interval-ms
                     load-balancing access-log])
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

(defn parse-circuit-breaker-config
  "Parse circuit breaker configuration, merging with defaults."
  [cb-config-map]
  (let [merged (merge default-circuit-breaker-config cb-config-map)]
    (->CircuitBreakerConfig
      (:enabled merged)
      (:error-threshold-pct merged)
      (:min-requests merged)
      (:open-duration-ms merged)
      (:half-open-requests merged)
      (:window-size-ms merged))))

(defn parse-load-balancing-config
  "Parse load balancing configuration, merging with defaults.
   Config keys use lb- prefix in specs but normal names in config maps."
  [lb-config-map]
  (let [;; Handle both prefixed spec keys and normal config keys
        normalized (cond-> (or lb-config-map {})
                     (contains? lb-config-map :lb-algorithm)
                     (assoc :algorithm (:lb-algorithm lb-config-map))
                     (contains? lb-config-map :lb-weighted)
                     (assoc :weighted (:lb-weighted lb-config-map))
                     (contains? lb-config-map :lb-update-interval-ms)
                     (assoc :update-interval-ms (:lb-update-interval-ms lb-config-map)))
        merged (merge default-load-balancing-config normalized)]
    (->LoadBalancingConfig
      (:algorithm merged)
      (:weighted merged)
      (:update-interval-ms merged))))

(defn parse-access-log-config
  "Parse access log configuration, merging with defaults."
  [access-log-map]
  (let [;; Normalize keys from spec format to config format
        normalized (cond-> (or access-log-map {})
                     (contains? access-log-map :access-log-format)
                     (assoc :format (:access-log-format access-log-map))
                     (contains? access-log-map :access-log-path)
                     (assoc :path (:access-log-path access-log-map))
                     (contains? access-log-map :access-log-max-file-size-mb)
                     (assoc :max-file-size-mb (:access-log-max-file-size-mb access-log-map))
                     (contains? access-log-map :access-log-max-files)
                     (assoc :max-files (:access-log-max-files access-log-map))
                     (contains? access-log-map :access-log-buffer-size)
                     (assoc :buffer-size (:access-log-buffer-size access-log-map)))
        merged (merge default-access-log-config normalized)]
    (->AccessLogConfig
      (:enabled merged)
      (:format merged)
      (:path merged)
      (:max-file-size-mb merged)
      (:max-files merged)
      (:buffer-size merged))))

(defn dns-target?
  "Check if a target specification uses DNS (has :host instead of :ip)."
  [target-spec]
  (and (map? target-spec) (contains? target-spec :host)))

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

(defn parse-dns-weighted-target
  "Parse a DNS-backed target map to DNSWeightedTarget record.
   The hostname will be resolved at runtime by the DNS manager.
   global-health-defaults: optional global health check defaults from settings."
  ([target-map] (parse-dns-weighted-target target-map nil))
  ([{:keys [host port weight dns-refresh-seconds health-check]} global-health-defaults]
   (->DNSWeightedTarget
     host
     port
     (or weight 100)
     (or dns-refresh-seconds 30)
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
  "Parse a target specification into a TargetGroup or DNSTargetGroup.
   Accepts either a single target map or a vector of targets.
   Validates weights for multi-target groups.

   Returns:
   - TargetGroup if all targets are IP-based
   - DNSTargetGroup if any targets use DNS hostnames"
  [target-spec context-msg]
  (let [targets (if (vector? target-spec) target-spec [target-spec])
        has-dns? (some dns-target? targets)]
    ;; Validate weights before parsing
    (validate-target-weights! targets context-msg)
    (if has-dns?
      ;; Has DNS targets - return DNSTargetGroup for runtime resolution
      (let [dns-targets (filterv dns-target? targets)
            static-targets (filterv #(not (dns-target? %)) targets)
            parsed-dns (mapv parse-dns-weighted-target dns-targets)
            parsed-static (mapv parse-weighted-target static-targets)]
        (->DNSTargetGroup parsed-dns parsed-static))
      ;; All static - return regular TargetGroup
      (let [parsed (mapv parse-weighted-target targets)
            cumulative (compute-cumulative-weights parsed)]
        (->TargetGroup parsed cumulative)))))

(defn dns-target-group?
  "Check if a parsed target group contains DNS targets.
   Returns true for DNSTargetGroup, false for TargetGroup."
  [target-group]
  (instance? DNSTargetGroup target-group))

(defn parse-target
  "Parse a single target map to Target record with resolved IP.
   Kept for backward compatibility."
  [{:keys [ip port]}]
  (->Target (util/ip-string->u32 ip) port))

(defn parse-source-route
  "Parse a source route, resolving hostname if necessary.
   Supports both :target (single) and :targets (weighted array) formats."
  [{:keys [source target targets session-persistence]} proxy-name]
  (let [{:keys [ip prefix-len]} (util/resolve-to-ip source)]
    (when (nil? ip)
      (throw (ex-info "Failed to resolve source" {:source source})))
    (let [target-spec (or targets target)
          context (format "proxy '%s' source-route %s" proxy-name source)]
      (->SourceRoute ip prefix-len (parse-target-group target-spec context) session-persistence))))

(defn parse-sni-route
  "Parse an SNI route for TLS SNI-based routing.
   Supports both :target (single) and :targets (weighted array) formats."
  [{:keys [sni-hostname target targets session-persistence]} proxy-name]
  (let [hostname (clojure.string/lower-case sni-hostname)
        hostname-hash (util/hostname->hash hostname)
        target-spec (or targets target)
        context (format "proxy '%s' sni-route %s" proxy-name sni-hostname)]
    (->SNIRoute hostname hostname-hash (parse-target-group target-spec context) session-persistence)))

(defn parse-listen
  "Parse listen configuration."
  [{:keys [interfaces port]}]
  (->Listen (vec interfaces) port))

(defn parse-proxy-config
  "Parse a single proxy configuration."
  [{:keys [name listen default-target source-routes sni-routes session-persistence]}]
  (let [default-context (format "proxy '%s' default-target" name)]
    (->ProxyConfig
      name
      (parse-listen listen)
      (parse-target-group default-target default-context)
      (mapv #(parse-source-route % name) (or source-routes []))
      (mapv #(parse-sni-route % name) (or sni-routes []))
      session-persistence)))

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
    (get settings :drain-check-interval-ms 1000)
    (parse-load-balancing-config (get settings :load-balancing))
    (parse-access-log-config (get settings :access-log))))

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
    :drain-check-interval-ms (get-in config [:settings :drain-check-interval-ms])
    :load-balancing (let [lb (get-in config [:settings :load-balancing])]
                      {:algorithm (:algorithm lb)
                       :weighted (:weighted lb)
                       :update-interval-ms (:update-interval-ms lb)})
    :access-log (let [al (get-in config [:settings :access-log])]
                  {:enabled (:enabled al)
                   :format (:format al)
                   :path (:path al)
                   :max-file-size-mb (:max-file-size-mb al)
                   :max-files (:max-files al)
                   :buffer-size (:buffer-size al)})}})

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
  (->Settings false 300 100000 false default-health-check-config 30000 1000
              (parse-load-balancing-config nil)
              (parse-access-log-config nil)))

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
       []     ; source-routes
       []     ; sni-routes
       false)] ; session-persistence
    (->Settings stats-enabled 300 100000 health-check-enabled default-health-check-config
                30000 1000 (parse-load-balancing-config nil)
                (parse-access-log-config nil))))

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

;;; =============================================================================
;;; Configuration Diffing for Hot Reload
;;; =============================================================================

;; Diff result for changes within a single proxy
(defrecord ProxyDiff
  [proxy-name           ; Name of the proxy
   listen-changed?      ; If true, full proxy reload needed (remove + add)
   default-target-diff  ; {:old TargetGroup :new TargetGroup} or nil
   added-source-routes  ; Vector of SourceRoute to add
   removed-source-routes ; Vector of {:source :prefix-len} to remove
   added-sni-routes     ; Vector of SNIRoute to add
   removed-sni-routes]) ; Vector of hostnames to remove

;; Full diff result between two Config records
(defrecord ConfigDiff
  [settings-changes     ; Map of {:field {:old v1 :new v2}}
   added-proxies        ; Vector of ProxyConfig to add
   removed-proxies      ; Vector of proxy names to remove
   modified-proxies])   ; Vector of ProxyDiff for changed proxies

(defn diff-settings
  "Compare two Settings records.
   Returns map of {:field {:old v1 :new v2}} for changed fields, or empty map if identical."
  [^Settings old-settings ^Settings new-settings]
  (let [fields [:stats-enabled :connection-timeout-sec :max-connections
                :health-check-enabled :health-check-defaults
                :default-drain-timeout-ms :drain-check-interval-ms]]
    (reduce (fn [acc field]
              (let [old-val (get old-settings field)
                    new-val (get new-settings field)]
                (if (= old-val new-val)
                  acc
                  (assoc acc field {:old old-val :new new-val}))))
            {}
            fields)))

(defn diff-target-group
  "Compare two TargetGroup records.
   Returns nil if identical, {:old :new} if different."
  [^TargetGroup old-tg ^TargetGroup new-tg]
  (let [old-targets (:targets old-tg)
        new-targets (:targets new-tg)]
    ;; Compare by IP, port, and weight of each target
    (when-not (and (= (count old-targets) (count new-targets))
                   (every? true?
                           (map (fn [old new]
                                  (and (= (:ip old) (:ip new))
                                       (= (:port old) (:port new))
                                       (= (:weight old) (:weight new))))
                                old-targets new-targets)))
      {:old old-tg :new new-tg})))

(defn diff-listen
  "Compare two Listen records.
   Returns true if different."
  [^Listen old-listen ^Listen new-listen]
  (or (not= (set (:interfaces old-listen)) (set (:interfaces new-listen)))
      (not= (:port old-listen) (:port new-listen))))

(defn- source-route-key
  "Create a key for comparing source routes (source IP + prefix length)."
  [^SourceRoute route]
  [(:source route) (:prefix-len route)])

(defn diff-source-routes
  "Compare source route vectors.
   Returns {:added [SourceRoute] :removed [{:source :prefix-len}]}."
  [old-routes new-routes]
  (let [old-keys (set (map source-route-key old-routes))
        new-keys (set (map source-route-key new-routes))
        old-by-key (into {} (map (juxt source-route-key identity) old-routes))
        new-by-key (into {} (map (juxt source-route-key identity) new-routes))
        added-keys (set/difference new-keys old-keys)
        removed-keys (set/difference old-keys new-keys)
        ;; Also check for modified routes (same key, different target)
        common-keys (set/intersection old-keys new-keys)
        modified-keys (filter (fn [k]
                                (some? (diff-target-group
                                         (:target-group (old-by-key k))
                                         (:target-group (new-by-key k)))))
                              common-keys)]
    {:added (vec (concat
                   (map new-by-key added-keys)
                   (map new-by-key modified-keys)))
     :removed (vec (concat
                     (map (fn [[src plen]] {:source src :prefix-len plen}) removed-keys)
                     (map (fn [[src plen]] {:source src :prefix-len plen}) modified-keys)))}))

(defn diff-sni-routes
  "Compare SNI route vectors.
   Returns {:added [SNIRoute] :removed [hostname]}."
  [old-routes new-routes]
  (let [old-hostnames (set (map :hostname old-routes))
        new-hostnames (set (map :hostname new-routes))
        old-by-hostname (into {} (map (juxt :hostname identity) old-routes))
        new-by-hostname (into {} (map (juxt :hostname identity) new-routes))
        added-hostnames (set/difference new-hostnames old-hostnames)
        removed-hostnames (set/difference old-hostnames new-hostnames)
        ;; Also check for modified routes (same hostname, different target)
        common-hostnames (set/intersection old-hostnames new-hostnames)
        modified-hostnames (filter (fn [h]
                                     (some? (diff-target-group
                                              (:target-group (old-by-hostname h))
                                              (:target-group (new-by-hostname h)))))
                                   common-hostnames)]
    {:added (vec (concat
                   (map new-by-hostname added-hostnames)
                   (map new-by-hostname modified-hostnames)))
     :removed (vec (concat removed-hostnames modified-hostnames))}))

(defn diff-proxy
  "Compare two ProxyConfig records with the same name.
   Returns ProxyDiff record describing changes."
  [^ProxyConfig old-proxy ^ProxyConfig new-proxy]
  (let [listen-changed? (diff-listen (:listen old-proxy) (:listen new-proxy))
        default-target-diff (diff-target-group (:default-target old-proxy)
                                                (:default-target new-proxy))
        source-route-diff (diff-source-routes (:source-routes old-proxy)
                                               (:source-routes new-proxy))
        sni-route-diff (diff-sni-routes (:sni-routes old-proxy)
                                         (:sni-routes new-proxy))]
    (->ProxyDiff
      (:name old-proxy)
      listen-changed?
      default-target-diff
      (:added source-route-diff)
      (:removed source-route-diff)
      (:added sni-route-diff)
      (:removed sni-route-diff))))

(defn proxy-diff-empty?
  "Check if a ProxyDiff represents no changes."
  [^ProxyDiff diff]
  (and (not (:listen-changed? diff))
       (nil? (:default-target-diff diff))
       (empty? (:added-source-routes diff))
       (empty? (:removed-source-routes diff))
       (empty? (:added-sni-routes diff))
       (empty? (:removed-sni-routes diff))))

(defn diff-configs
  "Compare two Config records.
   Returns ConfigDiff record describing all changes."
  [^Config old-config ^Config new-config]
  (let [settings-changes (diff-settings (:settings old-config) (:settings new-config))
        old-proxy-names (set (map :name (:proxies old-config)))
        new-proxy-names (set (map :name (:proxies new-config)))
        old-proxies-by-name (into {} (map (juxt :name identity) (:proxies old-config)))
        new-proxies-by-name (into {} (map (juxt :name identity) (:proxies new-config)))
        added-names (set/difference new-proxy-names old-proxy-names)
        removed-names (set/difference old-proxy-names new-proxy-names)
        common-names (set/intersection old-proxy-names new-proxy-names)
        ;; Check for modified proxies
        proxy-diffs (keep (fn [name]
                            (let [diff (diff-proxy (old-proxies-by-name name)
                                                   (new-proxies-by-name name))]
                              (when-not (proxy-diff-empty? diff)
                                diff)))
                          common-names)]
    (->ConfigDiff
      settings-changes
      (vec (map new-proxies-by-name added-names))
      (vec removed-names)
      (vec proxy-diffs))))

(defn config-diff-empty?
  "Check if a ConfigDiff represents no changes."
  [^ConfigDiff diff]
  (and (empty? (:settings-changes diff))
       (empty? (:added-proxies diff))
       (empty? (:removed-proxies diff))
       (empty? (:modified-proxies diff))))

(defn summarize-diff
  "Create a human-readable summary of a ConfigDiff."
  [^ConfigDiff diff]
  {:settings-changed (count (:settings-changes diff))
   :proxies-added (count (:added-proxies diff))
   :proxies-removed (count (:removed-proxies diff))
   :proxies-modified (count (:modified-proxies diff))})
