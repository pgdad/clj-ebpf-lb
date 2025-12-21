(ns lb.dns.resolver
  "DNS resolution logic with multiple A record support.

   Provides:
   - Resolution of hostnames to all A records
   - Conversion of resolved IPs to weighted targets
   - Result types for success/failure handling"
  (:require [lb.util :as util]
            [clojure.tools.logging :as log])
  (:import [java.net InetAddress UnknownHostException]))

;;; =============================================================================
;;; Result Types
;;; =============================================================================

(defrecord ResolveResult
  [success?    ; boolean - resolution succeeded
   ips         ; vector of u32 IPs (on success)
   ttl         ; TTL in seconds (if available, often nil)
   error-type  ; keyword (:unknown-host, :timeout, :error) on failure
   message])   ; error message on failure

(defn success-result
  "Create a successful resolution result."
  ([ips] (success-result ips nil))
  ([ips ttl]
   (->ResolveResult true ips ttl nil nil)))

(defn failure-result
  "Create a failed resolution result."
  [error-type message]
  (->ResolveResult false nil nil error-type message))

;;; =============================================================================
;;; DNS Resolution
;;; =============================================================================

(defn resolve-hostname-all
  "Resolve hostname to all A records.

   Parameters:
     hostname - DNS hostname to resolve
     timeout-ms - Resolution timeout in milliseconds (not directly supported
                  by Java InetAddress, but sets a reasonable expectation)

   Returns ResolveResult with either:
     - success? true, ips as vector of u32
     - success? false, error-type and message"
  [hostname timeout-ms]
  (try
    (let [addresses (InetAddress/getAllByName hostname)]
      (if (empty? addresses)
        (failure-result :empty-response (str "No A records for " hostname))
        (let [ips (mapv (fn [^InetAddress addr]
                          (util/bytes->ip (.getAddress addr)))
                        addresses)]
          (log/debug "Resolved" hostname "to" (count ips) "IPs:"
                     (mapv util/u32->ip-string ips))
          (success-result ips))))
    (catch UnknownHostException _
      (failure-result :unknown-host (str "Unknown host: " hostname)))
    (catch SecurityException e
      (failure-result :security-error (str "Security exception: " (.getMessage e))))
    (catch Exception e
      (failure-result :error (str "DNS error: " (.getMessage e))))))

(defn resolve-hostname-single
  "Resolve hostname to first A record only.
   Simpler wrapper when only one IP is needed.

   Returns ResolveResult."
  [hostname timeout-ms]
  (try
    (let [addr (InetAddress/getByName hostname)
          ip (util/bytes->ip (.getAddress addr))]
      (log/debug "Resolved" hostname "to" (util/u32->ip-string ip))
      (success-result [ip]))
    (catch UnknownHostException _
      (failure-result :unknown-host (str "Unknown host: " hostname)))
    (catch Exception e
      (failure-result :error (str "DNS error: " (.getMessage e))))))

;;; =============================================================================
;;; Target Expansion
;;; =============================================================================

(defn distribute-weight
  "Distribute a total weight among n targets.
   Returns a vector of weights that sum to the original weight.

   Uses floor division with remainder distributed to first targets.
   Example: (distribute-weight 100 3) => [34 33 33]"
  [total-weight n]
  (if (<= n 0)
    []
    (let [base (quot total-weight n)
          remainder (rem total-weight n)]
      (vec (concat
             (repeat remainder (inc base))
             (repeat (- n remainder) base))))))

(defn expand-to-weighted-targets
  "Expand resolved IPs to weighted targets with distributed weights.

   Parameters:
     resolved-ips - vector of u32 IPs from DNS resolution
     port - target port number
     total-weight - total weight to distribute (1-100)
     health-check - optional health check config

   Returns vector of maps suitable for creating WeightedTargets:
     [{:ip <u32> :port <int> :weight <int> :health-check <config>} ...]"
  [resolved-ips port total-weight health-check]
  (let [weights (distribute-weight total-weight (count resolved-ips))]
    (mapv (fn [ip weight]
            {:ip ip
             :port port
             :weight weight
             :health-check health-check})
          resolved-ips
          weights)))

;;; =============================================================================
;;; Utility Functions
;;; =============================================================================

(defn ips-changed?
  "Check if resolved IPs have changed.
   Order-independent comparison."
  [old-ips new-ips]
  (not= (set old-ips) (set new-ips)))

(defn format-ips
  "Format vector of u32 IPs as readable string."
  [ips]
  (str "[" (clojure.string/join ", " (map util/u32->ip-string ips)) "]"))
