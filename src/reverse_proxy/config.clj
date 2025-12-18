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

;; Target specification
(s/def ::target (s/keys :req-un [::ip ::port]))
(s/def ::ip ::ip-string)

;; Interface name
(s/def ::interface (s/and string? #(re-matches #"[a-zA-Z0-9\-_]+" %)))
(s/def ::interfaces (s/coll-of ::interface :min-count 1))

;; Listen specification
(s/def ::listen (s/keys :req-un [::interfaces ::port]))

;; Source route
(s/def ::source-route (s/keys :req-un [::source ::target]))
(s/def ::source-routes (s/coll-of ::source-route))

;; Proxy configuration
(s/def ::name (s/and string? #(> (count %) 0)))
(s/def ::default-target ::target)
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

(defrecord Target [ip port])
(defrecord SourceRoute [source prefix-len target])
(defrecord Listen [interfaces port])
(defrecord ProxyConfig [name listen default-target source-routes])
(defrecord Settings [stats-enabled connection-timeout-sec max-connections])
(defrecord Config [proxies settings])

;;; =============================================================================
;;; Configuration Parsing
;;; =============================================================================

(defn parse-target
  "Parse a target map to Target record with resolved IP."
  [{:keys [ip port]}]
  (->Target (util/ip-string->u32 ip) port))

(defn parse-source-route
  "Parse a source route, resolving hostname if necessary."
  [{:keys [source target]}]
  (let [{:keys [ip prefix-len]} (util/resolve-to-ip source)]
    (when (nil? ip)
      (throw (ex-info "Failed to resolve source" {:source source})))
    (->SourceRoute ip prefix-len (parse-target target))))

(defn parse-listen
  "Parse listen configuration."
  [{:keys [interfaces port]}]
  (->Listen (vec interfaces) port))

(defn parse-proxy-config
  "Parse a single proxy configuration."
  [{:keys [name listen default-target source-routes]}]
  (->ProxyConfig
    name
    (parse-listen listen)
    (parse-target default-target)
    (mapv parse-source-route (or source-routes []))))

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

(defn save-config-file
  "Save configuration to an EDN file."
  [config path]
  (log/info "Saving configuration to:" path)
  (let [config-map (config->map config)]
    (spit path (pr-str config-map))))

(defn config->map
  "Convert parsed Config back to plain EDN map."
  [^Config config]
  {:proxies
   (mapv (fn [^ProxyConfig p]
           {:name (:name p)
            :listen {:interfaces (vec (get-in p [:listen :interfaces]))
                     :port (get-in p [:listen :port])}
            :default-target {:ip (util/u32->ip-string (get-in p [:default-target :ip]))
                             :port (get-in p [:default-target :port])}
            :source-routes
            (mapv (fn [^SourceRoute sr]
                    {:source (util/cidr->string {:ip (:source sr) :prefix-len (:prefix-len sr)})
                     :target {:ip (util/u32->ip-string (get-in sr [:target :ip]))
                              :port (get-in sr [:target :port])}})
                  (:source-routes p))})
         (:proxies config))
   :settings
   {:stats-enabled (get-in config [:settings :stats-enabled])
    :connection-timeout-sec (get-in config [:settings :connection-timeout-sec])
    :max-connections (get-in config [:settings :max-connections])}})

;;; =============================================================================
;;; Default Configuration
;;; =============================================================================

(def default-settings
  "Default settings values."
  (->Settings false 300 100000))

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
       (->Target (util/ip-string->u32 target-ip) target-port)
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
  "Add a source route to a proxy."
  [^Config config proxy-name source-route]
  (let [route (if (instance? SourceRoute source-route)
                source-route
                (parse-source-route source-route))]
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

(defn format-proxy
  "Format a proxy configuration for display."
  [^ProxyConfig proxy]
  (let [listen (:listen proxy)
        default (:default-target proxy)]
    (str "Proxy: " (:name proxy) "\n"
         "  Listen: " (clojure.string/join ", " (:interfaces listen))
         " port " (:port listen) "\n"
         "  Default target: " (util/u32->ip-string (:ip default))
         ":" (:port default) "\n"
         (when (seq (:source-routes proxy))
           (str "  Source routes:\n"
                (clojure.string/join "\n"
                  (map (fn [^SourceRoute r]
                         (str "    " (util/cidr->string {:ip (:source r) :prefix-len (:prefix-len r)})
                              " -> " (util/u32->ip-string (get-in r [:target :ip]))
                              ":" (get-in r [:target :port])))
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
