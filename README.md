# clj-ebpf-lb

[![CI](https://github.com/pgdad/clj-ebpf-lb/actions/workflows/ci.yml/badge.svg)](https://github.com/pgdad/clj-ebpf-lb/actions/workflows/ci.yml)
[![Clojars Project](https://img.shields.io/clojars/v/org.clojars.pgdad/clj-ebpf-lb.svg)](https://clojars.org/org.clojars.pgdad/clj-ebpf-lb)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance eBPF-based Layer 4 load balancer written in Clojure. Uses XDP (eXpress Data Path) for ingress DNAT and TC (Traffic Control) for egress SNAT, providing kernel-level packet processing for efficient traffic distribution. Can also be used as a simple reverse proxy.

## Features

- **High Performance**: Packet processing happens in the Linux kernel using eBPF, bypassing the userspace networking stack
- **XDP Ingress DNAT**: Incoming packets are redirected to backend targets at the earliest point in the network stack
- **TC Egress SNAT**: Return traffic has its source address rewritten to appear as the proxy
- **Connection Tracking**: Full stateful NAT with per-CPU hash maps for scalability
- **Source-Based Routing**: Route traffic to different backends based on client IP/subnet
- **SNI-Based Routing**: Route TLS traffic based on hostname without terminating TLS (layer 4 passthrough)
- **Weighted Load Balancing**: Distribute traffic across multiple backends with configurable weights
- **Connection Draining**: Gracefully remove backends by stopping new connections while existing ones complete
- **DNS-Based Backends**: Use DNS hostnames for dynamic backend discovery with periodic re-resolution
- **Runtime Configuration**: Add/remove proxies and routes without restart
- **Statistics Collection**: Real-time connection and traffic statistics via ring buffer
- **Prometheus Metrics**: Built-in `/metrics` endpoint for Prometheus scraping
- **ARM64 Support**: Full cross-platform support with QEMU-based ARM64 testing

## Requirements

### System Requirements

- **Linux Kernel**: 6.8+ recommended (5.15+ minimum)
- **Architecture**: x86_64 or ARM64
- **Root Access**: Required for BPF system calls and network interface attachment

### Software Dependencies

- **Java**: OpenJDK 25+ (for Panama FFI)
- **Clojure CLI**: 1.12+
- **Linux Packages**:
  - `bpftool` (optional, for debugging)
  - `iproute2` (for TC qdisc management)

### Installation

1. **Install Java 25**:
   ```bash
   # Ubuntu 24.04+
   sudo apt-get install openjdk-25-jdk

   # Or download from https://jdk.java.net/25/
   ```

2. **Install Clojure CLI**:
   ```bash
   curl -L -O https://github.com/clojure/brew-install/releases/latest/download/linux-install.sh
   chmod +x linux-install.sh
   sudo ./linux-install.sh
   ```

3. **Clone the repository**:
   ```bash
   git clone https://github.com/pgdad/clj-ebpf-lb.git
   cd clj-ebpf-lb
   ```

## Quick Start

### Basic Usage

1. **Create a configuration file** (`proxy.edn`):
   ```clojure
   {:proxies
    [{:name "web"
      :listen {:interfaces ["eth0"] :port 80}
      :default-target {:ip "10.0.0.1" :port 8080}}]
    :settings
    {:stats-enabled false
     :connection-timeout-sec 300}}
   ```

2. **Run the load balancer**:
   ```bash
   sudo clojure -M:run -c lb.edn
   ```

### Command Line Options

```
Usage: clj-ebpf-lb [options]

Options:
  -c, --config FILE       Configuration file path (default: config.edn)
  -i, --interface IFACE   Network interface to attach to (can specify multiple)
  -p, --port PORT         Listen port (default: 80)
  -t, --target TARGET     Default target as ip:port (default: 127.0.0.1:8080)
  -s, --stats             Enable statistics collection
  -v, --verbose           Verbose output
  -h, --help              Show help

Examples:
  clj-ebpf-lb -c lb.edn
  clj-ebpf-lb -i eth0 -p 80 -t 10.0.0.1:8080
  clj-ebpf-lb -i eth0 -i eth1 -p 443 -t 10.0.0.2:8443 --stats
```

## Configuration

### Configuration File Format

The proxy is configured using an EDN (Extensible Data Notation) file:

```clojure
{:proxies
 [;; Each proxy configuration
  {:name "proxy-name"              ; Unique identifier
   :listen
   {:interfaces ["eth0" "eth1"]    ; Network interfaces to listen on
    :port 80}                      ; Port to listen on

   :default-target
   {:ip "10.0.0.1"                 ; Default backend IP
    :port 8080}                    ; Default backend port

   :source-routes                  ; Optional: source-based routing rules
   [{:source "192.168.1.0/24"      ; Source IP or CIDR
     :target {:ip "10.0.0.2" :port 8080}}
    {:source "10.10.0.0/16"
     :target {:ip "10.0.0.3" :port 8080}}]}]

 :settings
 {:stats-enabled false             ; Enable real-time statistics
  :connection-timeout-sec 300      ; Connection idle timeout
  :max-connections 100000}}        ; Maximum tracked connections
```

### Source-Based Routing

Route traffic to different backends based on the client's source IP:

```clojure
:source-routes
[;; Route internal network to internal backend
 {:source "192.168.0.0/16"
  :target {:ip "10.0.0.10" :port 8080}}

 ;; Route specific host to dedicated backend
 {:source "192.168.1.100"
  :target {:ip "10.0.0.20" :port 8080}}

 ;; Route cloud VPC to cloud backend
 {:source "10.0.0.0/8"
  :target {:ip "10.0.0.30" :port 8080}}]
```

The routing precedence is:
1. Most specific source route (longest prefix match)
2. SNI hostname match (for TLS traffic)
3. Default target (if no route matches)

### SNI-Based Routing

Route TLS traffic to different backends based on the Server Name Indication (SNI) hostname in the TLS ClientHello. This enables multi-tenant HTTPS load balancing without terminating TLS (layer 4 passthrough with layer 7 inspection).

```clojure
{:proxies
 [{:name "https-gateway"
   :listen {:interfaces ["eth0"] :port 443}
   :default-target {:ip "10.0.0.1" :port 8443}
   :sni-routes
   [{:sni-hostname "api.example.com"
     :target {:ip "10.0.1.1" :port 8443}}
    {:sni-hostname "web.example.com"
     :target {:ip "10.0.2.1" :port 8443}}
    {:sni-hostname "app.example.com"
     :targets [{:ip "10.0.3.1" :port 8443 :weight 70}
               {:ip "10.0.3.2" :port 8443 :weight 30}]}]}]}
```

**How it works:**
1. XDP program parses the TLS ClientHello to extract the SNI hostname
2. Hostname is hashed (FNV-1a 64-bit) for efficient BPF map lookup
3. If SNI route found, traffic is routed to the configured backend(s)
4. If no SNI match or non-TLS traffic, falls back to source routes or default target

**SNI Routing Features:**
- **Case-insensitive**: `API.Example.COM` matches `api.example.com`
- **Weighted targets**: Distribute traffic across multiple backends per hostname
- **Zero TLS overhead**: No decryption/encryption, packets are passed through
- **Kernel-level performance**: SNI parsing adds ~50-100ns per TLS connection

**Use Cases:**
- Multi-tenant SaaS with per-customer backends
- Microservices routing (api.*, web.*, admin.*)
- Blue/green deployments per service
- Geographic or capacity-based routing per hostname

**Limitations:**
- Exact hostname match only (no wildcards like `*.example.com`)
- Requires TLS 1.0+ with SNI extension (supported by all modern clients)
- Maximum 64-byte hostnames (longer hostnames are truncated)

### Weighted Load Balancing

Distribute traffic across multiple backend servers with configurable weights. This is useful for canary deployments, A/B testing, capacity-based distribution, and blue/green deployments.

```clojure
;; Weighted default target - distribute across 3 backends
:default-target
[{:ip "10.0.0.1" :port 8080 :weight 50}   ; 50% of traffic
 {:ip "10.0.0.2" :port 8080 :weight 30}   ; 30% of traffic
 {:ip "10.0.0.3" :port 8080 :weight 20}]  ; 20% of traffic

;; Weighted source routes
:source-routes
[{:source "192.168.0.0/16"
  :targets [{:ip "10.0.1.1" :port 8080 :weight 70}
            {:ip "10.0.1.2" :port 8080 :weight 30}]}]
```

**Weight Rules:**
- Weights are percentages and must sum to exactly 100
- For single targets, weight is optional (backward compatible)
- For multiple targets, all must have explicit weights
- Maximum 8 targets per group
- Selection is per new connection (established connections maintain affinity)

**Canary Deployment Example:**
```clojure
;; 95% stable, 5% canary
:default-target
[{:ip "10.0.0.1" :port 8080 :weight 95}   ; Stable version
 {:ip "10.0.0.2" :port 8080 :weight 5}]   ; Canary version
```

**Blue/Green Deployment Example:**
```clojure
;; Gradual traffic shift from blue to green
:default-target
[{:ip "10.0.0.1" :port 8080 :weight 20}   ; Blue (old)
 {:ip "10.0.0.2" :port 8080 :weight 80}]  ; Green (new)
```

### Health Checking

Automatically detect unhealthy backends and redistribute traffic to healthy ones. Health checking uses virtual threads for efficient concurrent monitoring.

**Enable health checking in settings:**
```clojure
:settings
{:health-check-enabled true
 :health-check-defaults
 {:type :tcp
  :interval-ms 10000          ; Check every 10 seconds
  :timeout-ms 3000            ; 3 second timeout
  :healthy-threshold 2        ; 2 successes = healthy
  :unhealthy-threshold 3}}    ; 3 failures = unhealthy
```

**Per-target health check configuration:**
```clojure
:default-target
[{:ip "10.0.0.1" :port 8080 :weight 50
  :health-check {:type :tcp
                 :interval-ms 5000
                 :timeout-ms 2000}}
 {:ip "10.0.0.2" :port 8080 :weight 50
  :health-check {:type :http
                 :path "/health"
                 :interval-ms 5000
                 :expected-codes [200 204]}}]
```

**Health Check Types:**

| Type | Description | Use Case |
|------|-------------|----------|
| `:tcp` | TCP connection test | Fast, low overhead |
| `:http` | HTTP GET with status validation | Application-level health |
| `:https` | HTTPS GET with status validation | Secure endpoints |
| `:none` | Skip health checking | Always considered healthy |

**Weight Redistribution:**

When a backend becomes unhealthy, its traffic is redistributed proportionally to remaining healthy backends:

```
Original weights: [50, 30, 20]
If middle server fails: [71, 0, 29]  (proportional redistribution)
If all servers fail: [50, 30, 20]    (graceful degradation - keep original)
```

**Gradual Recovery:**

When a backend recovers, traffic is gradually restored to prevent overwhelming it:
- Step 1: 25% of original weight
- Step 2: 50% of original weight
- Step 3: 75% of original weight
- Step 4: 100% of original weight

**Health Check Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `type` | `:tcp` | Check type (`:tcp`, `:http`, `:https`, `:none`) |
| `path` | `"/health"` | HTTP(S) endpoint path |
| `interval-ms` | `10000` | Time between checks (1000-300000) |
| `timeout-ms` | `3000` | Check timeout (100-60000) |
| `healthy-threshold` | `2` | Consecutive successes to mark healthy |
| `unhealthy-threshold` | `3` | Consecutive failures to mark unhealthy |
| `expected-codes` | `[200 201 202 204]` | Valid HTTP response codes |

### DNS-Based Backend Resolution

Use DNS hostnames instead of static IPs for backend targets. Ideal for dynamic environments like Kubernetes, cloud deployments, or services with frequently changing IPs.

**Basic DNS backend:**
```clojure
:default-target
{:host "backend.service.local"   ; DNS hostname instead of :ip
 :port 8080
 :dns-refresh-seconds 30}        ; Re-resolve every 30 seconds (default)
```

**DNS with health checking:**
```clojure
:default-target
{:host "api.backend.local"
 :port 8080
 :dns-refresh-seconds 15
 :health-check {:type :http
                :path "/health"
                :interval-ms 5000}}
```

**Mixed static and DNS targets:**
```clojure
:default-target
[{:ip "10.0.0.1" :port 8080 :weight 50}        ; Static IP
 {:host "dynamic.backend.local"                 ; DNS hostname
  :port 8080
  :weight 50
  :dns-refresh-seconds 10}]
```

**Kubernetes headless service pattern:**
```clojure
;; Headless services (clusterIP: None) return pod IPs as A records
:default-target
{:host "myapp.default.svc.cluster.local"
 :port 8080
 :dns-refresh-seconds 5}    ; Quick refresh for pod scaling
```

**Multiple A Record Handling:**

When a hostname resolves to multiple A records, the weight is distributed equally:
- Config: `{:host "backend.local" :port 8080 :weight 60}`
- Resolves to 3 IPs: Each gets weight 20 (60 ÷ 3)

**Failure Handling:**

| Scenario | Startup | Runtime |
|----------|---------|---------|
| DNS timeout | Fatal error | Use last-known-good IPs |
| Unknown host | Fatal error | Use last-known-good IPs |
| Empty A records | Fatal error | Use last-known-good IPs |

**DNS API:**
```clojure
;; Get DNS resolution status
(lb/get-dns-status "proxy-name")
;; => {:proxy-name "proxy-name"
;;     :targets {"backend.local"
;;               {:hostname "backend.local"
;;                :port 8080
;;                :last-ips ["10.0.0.1" "10.0.0.2"]
;;                :consecutive-failures 0}}}

(lb/get-all-dns-status)          ; All proxies
(lb/force-dns-resolve! "proxy" "hostname")  ; Force refresh

;; Subscribe to DNS events
(require '[lb.dns :as dns])
(dns/subscribe! (fn [event]
  (println (:type event) (:hostname event))))
;; Events: :dns-resolved, :dns-failed
```

### Connection Draining

Gracefully remove backends from the load balancer by stopping new connections while allowing existing ones to complete. This is essential for zero-downtime deployments, maintenance windows, and rolling updates.

**Basic draining:**
```clojure
;; Start draining - no new connections, existing ones continue
(lb/drain-backend! "web" "10.0.0.1:8080")

;; Check drain status
(lb/get-drain-status "10.0.0.1:8080")
;; => {:target-id "10.0.0.1:8080"
;;     :status :draining
;;     :elapsed-ms 5000
;;     :current-connections 3
;;     :initial-connections 10}

;; Cancel drain and restore traffic
(lb/undrain-backend! "web" "10.0.0.1:8080")
```

**Draining with timeout and callback:**
```clojure
;; Drain with 60 second timeout and completion callback
(lb/drain-backend! "web" "10.0.0.1:8080"
  :timeout-ms 60000
  :on-complete (fn [status]
                 (case status
                   :completed (println "Drain complete, safe to remove")
                   :timeout   (println "Drain timed out, forcing removal")
                   :cancelled (println "Drain was cancelled"))))
```

**Synchronous draining (blocks until complete):**
```clojure
;; Block until drain completes or times out
(let [status (lb/wait-for-drain! "10.0.0.1:8080")]
  (when (= status :completed)
    (lb/remove-backend! "web" "10.0.0.1:8080")))
```

**Rolling update example:**
```clojure
(defn rolling-update [proxy-name targets]
  (doseq [target targets]
    ;; Drain the old instance
    (lb/drain-backend! proxy-name target :timeout-ms 30000)
    (lb/wait-for-drain! target)
    ;; Deploy and add new instance
    (deploy-new-version! target)
    (lb/undrain-backend! proxy-name target)))
```

**Drain Status Values:**

| Status | Description |
|--------|-------------|
| `:draining` | Drain in progress, waiting for connections to close |
| `:completed` | All connections closed, drain finished successfully |
| `:timeout` | Timeout expired, some connections may still exist |
| `:cancelled` | Drain cancelled via `undrain-backend!` |

**Configuration:**
```clojure
:settings
{:default-drain-timeout-ms 30000    ; Default timeout (30 seconds)
 :drain-check-interval-ms 1000}     ; How often to check connection counts
```

**How it works:**
1. `drain-backend!` sets the target's weight to 0 in BPF maps
2. XDP program stops routing new connections to draining targets
3. Background watcher monitors connection counts via conntrack
4. Drain completes when connections reach 0 or timeout expires
5. Optional callback notifies completion status

### Prometheus Metrics

Export metrics in Prometheus format for monitoring and alerting. The metrics endpoint is compatible with Prometheus, Grafana, and other monitoring tools.

**Enable metrics in settings:**
```clojure
:settings
{:metrics {:enabled true
           :port 9090              ; Metrics server port (default 9090)
           :path "/metrics"}}      ; Endpoint path (default "/metrics")
```

**Available metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `lb_up` | gauge | - | Whether the load balancer is running (1=up) |
| `lb_info` | gauge | version | Load balancer version information |
| `lb_connections_active` | gauge | target_ip, target_port | Current active connections per backend |
| `lb_bytes_total` | counter | target_ip, target_port, direction | Bytes transferred (forward/reverse) |
| `lb_packets_total` | counter | target_ip, target_port, direction | Packets transferred (forward/reverse) |
| `lb_backend_health` | gauge | proxy_name, target_ip, target_port | Backend health status (1=healthy, 0=unhealthy) |
| `lb_health_check_latency_seconds` | histogram | proxy_name, target_id | Health check latency distribution |
| `lb_dns_resolution_status` | gauge | proxy_name, hostname | DNS resolution status (1=resolved, 0=failed) |

**Example Prometheus output:**
```
# HELP lb_up Whether the load balancer is running (1=up, 0=down)
# TYPE lb_up gauge
lb_up 1

# HELP lb_backend_health Backend health status (1=healthy, 0=unhealthy)
# TYPE lb_backend_health gauge
lb_backend_health{proxy_name="web",target_ip="10.0.0.1",target_port="8080"} 1
lb_backend_health{proxy_name="web",target_ip="10.0.0.2",target_port="8080"} 0

# HELP lb_health_check_latency_seconds Health check latency in seconds
# TYPE lb_health_check_latency_seconds histogram
lb_health_check_latency_seconds_bucket{proxy_name="web",target_id="10.0.0.1:8080",le="0.005"} 45
lb_health_check_latency_seconds_bucket{proxy_name="web",target_id="10.0.0.1:8080",le="0.01"} 120
lb_health_check_latency_seconds_bucket{proxy_name="web",target_id="10.0.0.1:8080",le="+Inf"} 200
lb_health_check_latency_seconds_sum{proxy_name="web",target_id="10.0.0.1:8080"} 1.234
lb_health_check_latency_seconds_count{proxy_name="web",target_id="10.0.0.1:8080"} 200
```

**Prometheus scrape configuration:**
```yaml
scrape_configs:
  - job_name: 'clj-ebpf-lb'
    static_configs:
      - targets: ['localhost:9090']
```

**Metrics API:**
```clojure
(require '[lb.metrics :as metrics])

;; Start/stop metrics server
(metrics/start! {:port 9090 :path "/metrics"})
(metrics/stop!)
(metrics/running?)  ; => true/false

;; Get server status
(metrics/get-status)
;; => {:running true :port 9090 :path "/metrics" :url "http://localhost:9090/metrics"}

;; Collect metrics programmatically (returns Prometheus text format)
(metrics/collect-metrics)
```

## Programmatic API

Use the load balancer as a library in your Clojure application:

```clojure
(require '[lb.core :as lb]
         '[lb.config :as config])

;; Create configuration
(def cfg (config/make-simple-config
           {:interface "eth0"
            :port 80
            :target-ip "10.0.0.1"
            :target-port 8080
            :stats-enabled true}))

;; Initialize the load balancer
(lb/init! cfg)

;; Check status
(lb/get-status)
;; => {:running true, :attached-interfaces ["eth0"], ...}

;; Add a source route at runtime (single target)
(lb/add-source-route! "web" "192.168.1.0/24"
                         {:ip "10.0.0.2" :port 8080})

;; Add a weighted source route at runtime
(lb/add-source-route! "web" "10.10.0.0/16"
                         [{:ip "10.0.0.3" :port 8080 :weight 70}
                          {:ip "10.0.0.4" :port 8080 :weight 30}])

;; Get active connections
(lb/get-connections)

;; Print connection statistics
(lb/print-connections)

;; Shutdown
(lb/shutdown!)
```

### Runtime Configuration

```clojure
;; Add a new proxy at runtime
(lb/add-proxy!
  {:name "api"
   :listen {:interfaces ["eth0"] :port 8080}
   :default-target {:ip "10.0.1.1" :port 3000}})

;; Remove a proxy
(lb/remove-proxy! "api")

;; Add/remove source routes
(lb/add-source-route! "web" "10.20.0.0/16" {:ip "10.0.0.5" :port 8080})
(lb/remove-source-route! "web" "10.20.0.0/16")

;; Add/remove SNI routes (for TLS traffic)
(lb/add-sni-route! "https-gateway" "api.example.com"
                   {:ip "10.0.1.1" :port 8443})

;; Add weighted SNI route
(lb/add-sni-route! "https-gateway" "web.example.com"
                   [{:ip "10.0.2.1" :port 8443 :weight 70}
                    {:ip "10.0.2.2" :port 8443 :weight 30}])

;; Remove SNI route (case-insensitive)
(lb/remove-sni-route! "https-gateway" "api.example.com")

;; List SNI routes
(lb/list-sni-routes "https-gateway")
;; => [{:hostname "web.example.com"
;;      :targets [{:ip "10.0.2.1" :port 8443 :weight 70}
;;                {:ip "10.0.2.2" :port 8443 :weight 30}]}]

;; List all SNI routes across all proxies
(lb/list-all-sni-routes)

;; Attach/detach interfaces
(lb/attach-interfaces! ["eth1" "eth2"])
(lb/detach-interfaces! ["eth2"])
```

### Statistics and Monitoring

```clojure
;; Enable/disable stats
(lb/enable-stats!)
(lb/disable-stats!)

;; Get connection statistics
(lb/get-connection-count)
(lb/get-connection-stats)
;; => {:total-connections 42
;;     :total-packets-forward 12345
;;     :total-bytes-forward 987654
;;     :total-packets-reverse 11234
;;     :total-bytes-reverse 876543}

;; Start streaming statistics
(lb/start-stats-stream!)
(let [ch (lb/subscribe-to-stats)]
  ;; Read events from channel
  (async/<! ch))
(lb/stop-stats-stream!)
```

### Health Checking API

```clojure
(require '[lb.health :as health])

;; Start/stop health checking system
(health/start!)
(health/stop!)
(health/running?)  ; => true/false

;; Get health status
(health/get-status "web")
;; => {:proxy-name "web"
;;     :targets [{:target-id "10.0.0.1:8080"
;;                :status :healthy
;;                :last-latency-ms 2.5
;;                :consecutive-successes 5}
;;               {:target-id "10.0.0.2:8080"
;;                :status :unhealthy
;;                :last-error :connection-refused}]
;;     :original-weights [50 50]
;;     :effective-weights [100 0]}

(health/get-all-status)       ; All proxies
(health/healthy? "web" "10.0.0.1:8080")
(health/all-healthy? "web")
(health/unhealthy-targets "web")

;; Subscribe to health events
(def unsubscribe
  (health/subscribe!
    (fn [event]
      (println "Health event:" (:type event) (:target-id event)))))
;; Events: :target-healthy, :target-unhealthy, :weights-updated

;; Unsubscribe
(unsubscribe)

;; Manual control (for maintenance)
(health/set-target-status! "web" "10.0.0.1:8080" :unhealthy)
(health/force-check! "web" "10.0.0.1:8080")

;; Direct health checks (for testing)
(health/check-tcp "10.0.0.1" 8080 2000)
;; => {:success? true :latency-ms 1.5}

(health/check-http "10.0.0.1" 8080 "/health" 3000 [200])
;; => {:success? true :latency-ms 15.2 :message "HTTP 200"}

;; Format status for display
(health/print-status "web")
(health/print-all-status)
```

### Connection Draining API

```clojure
;; Start draining a backend (stops new connections)
(lb/drain-backend! "web" "10.0.0.1:8080")
(lb/drain-backend! "web" "10.0.0.1:8080"
  :timeout-ms 60000
  :on-complete (fn [status] (println "Drain finished:" status)))

;; Cancel drain and restore traffic
(lb/undrain-backend! "web" "10.0.0.1:8080")

;; Check if target is draining
(lb/draining? "10.0.0.1:8080")  ; => true/false

;; Get drain status for a target
(lb/get-drain-status "10.0.0.1:8080")
;; => {:target-id "10.0.0.1:8080"
;;     :proxy-name "web"
;;     :status :draining
;;     :elapsed-ms 5000
;;     :timeout-ms 30000
;;     :current-connections 3
;;     :initial-connections 10}

;; Get all currently draining backends
(lb/get-all-draining)
;; => [{:target-id "10.0.0.1:8080" :status :draining ...}
;;     {:target-id "10.0.0.2:8080" :status :draining ...}]

;; Block until drain completes (returns :completed, :timeout, or :cancelled)
(lb/wait-for-drain! "10.0.0.1:8080")

;; Print drain status
(lb/print-drain-status)
```

## How It Works

### Architecture

```
                    +------------------+
                    |   User Space     |
                    |  (Clojure App)   |
                    +--------+---------+
                             |
          BPF Maps (shared)  |
    +------------------------+------------------------+
    |                        |                        |
    v                        v                        v
+--------+            +------------+           +----------+
| Listen |            | Conntrack  |           | Settings |
|  Map   |            |    Map     |           |   Map    |
+--------+            +------------+           +----------+
    |                        |                        |
    +------------------------+------------------------+
                             |
    +------------------------+------------------------+
    |                        |                        |
    v                        v                        v
+--------+            +------------+           +----------+
|  XDP   |  Ingress   |   Kernel   |  Egress   |    TC    |
| (DNAT) +----------->+   Stack    +---------->+  (SNAT)  |
+--------+            +------------+           +----------+
    ^                                               |
    |                                               v
+---+-----------------------------------------------+---+
|                   Network Interface                   |
+-------------------------------------------------------+
```

### XDP Ingress (DNAT)

1. Packet arrives at network interface
2. XDP program intercepts at the earliest point
3. Looks up destination port in listen map
4. Optionally checks source routes for custom backend
5. Rewrites destination IP and port
6. Creates conntrack entry for return traffic
7. Returns `XDP_PASS` to continue normal processing

### TC Egress (SNAT)

1. Response packet from backend reaches TC egress
2. TC program looks up connection in conntrack
3. Rewrites source IP and port to original destination
4. Updates packet checksums
5. Packet leaves with proxy's address as source

## Testing

### Run Tests Locally

```bash
# Run all tests (requires root)
sudo clojure -M:test
```

### ARM64 Testing

The project includes QEMU-based ARM64 testing infrastructure:

```bash
# One-time setup (downloads Ubuntu 24.04 ARM64 image)
./qemu-arm64/setup-vm.sh

# Start the ARM64 VM
./qemu-arm64/start-vm.sh --daemon

# Run tests in ARM VM
./qemu-arm64/run-tests-in-vm.sh --sync

# Stop the VM
./qemu-arm64/stop-vm.sh
```

See `qemu-arm64/README.md` for detailed ARM64 testing documentation.

## Building

### Create an Uberjar

```bash
clojure -X:uberjar

# Run the uberjar
sudo java -jar target/clj-ebpf-lb.jar -c lb.edn
```

## Troubleshooting

### Common Issues

**"Cannot attach XDP program"**
- Ensure you're running as root (`sudo`)
- Check that the interface exists: `ip link show`
- Verify kernel version supports XDP: `uname -r` (need 5.15+)

**"BPF program verification failed"**
- Check kernel logs: `dmesg | tail -50`
- Verify kernel has BPF support: `zgrep CONFIG_BPF /proc/config.gz`

**"Connection not being NAT'd"**
- Verify listen port is configured: check configuration file
- Ensure interface is attached: `(lb/list-attached-interfaces)`
- Check conntrack entries: `(lb/get-connections)`

### Debugging

```bash
# View attached XDP programs
sudo bpftool prog list

# View BPF maps
sudo bpftool map list

# Monitor traffic
sudo tcpdump -i eth0 -n port 80
```

## Performance Considerations

- **CPU Affinity**: XDP and TC programs run on the CPU receiving interrupts. Consider RSS (Receive Side Scaling) for multi-core distribution.
- **Map Sizes**: Adjust `max-connections` based on expected concurrent connections.
- **Connection Timeout**: Lower timeouts reduce memory usage but may break long-lived idle connections.

## License

MIT License. See [LICENSE](LICENSE) for details.

## See Also

- [clj-ebpf](https://github.com/pgdad/clj-ebpf) - The underlying eBPF library for Clojure
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) - Learn more about XDP programming
- [TC BPF](https://docs.cilium.io/en/stable/bpf/) - Traffic Control with BPF

---

**Note**: This project was previously named `clj-ebpf-reverse-proxy`. The core functionality remains the same, but the name was changed to better reflect the weighted load balancing capabilities.
