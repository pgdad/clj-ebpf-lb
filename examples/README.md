# Examples

This directory contains example configurations and usage patterns for clj-ebpf-lb.

## Quick Reference

| Example | Description | Complexity |
|---------|-------------|------------|
| [simple-proxy.edn](#simple-single-backend-proxy) | Basic single backend setup | Beginner |
| [multi-backend.edn](#multi-backend-with-source-routing) | Source-based routing to multiple backends | Intermediate |
| [sni-routing.edn](#sni-based-routing) | Route TLS traffic by hostname (SNI) | Intermediate |
| [multi-interface.edn](#multi-interface-proxy) | Proxy across multiple network interfaces | Intermediate |
| [kubernetes-ingress.edn](#kubernetes-ingress-style) | K8s-style ingress controller pattern | Advanced |
| [repl_usage.clj](#repl-usage) | Interactive REPL session | Intermediate |
| [monitoring.clj](#statistics-and-monitoring) | Real-time statistics monitoring | Advanced |
| [connection_draining.clj](#connection-draining) | Graceful backend removal patterns | Advanced |
| [dns_resolution.clj](#dns-resolution) | DNS-based backend discovery | Advanced |
| [rate_limiting.clj](#rate-limiting) | Token bucket rate limiting | Advanced |
| [prometheus_metrics.clj](#prometheus-metrics) | Prometheus metrics export | Intermediate |
| [circuit_breaker.clj](#circuit-breaker) | Automatic failure detection and recovery | Advanced |
| [least_connections.clj](#least-connections) | Dynamic weight adjustment based on connections | Intermediate |
| [session_persistence.clj](#session-persistence) | Sticky sessions based on source IP hash | Intermediate |
| [access_logging.clj](#access-logging) | Access logs and backend latency tracking | Intermediate |
| [admin_api.clj](#admin-http-api) | HTTP REST API for runtime management | Intermediate |

## Prerequisites

All examples require:
- Linux kernel 6.8+ (5.15+ minimum)
- OpenJDK 25+
- Clojure CLI 1.12+
- Root/sudo access

## Examples

### Simple Single-Backend Proxy

The simplest configuration: forward all traffic on port 80 to a single backend.

**File: `simple-proxy.edn`**

**Use Case**: Simple reverse proxy for a single application server.

**Setup**:
```bash
# Terminal 1: Start a test backend server
python3 -m http.server 8080

# Terminal 2: Run the load balancer
cd /path/to/clj-ebpf-lb
sudo clojure -M:run -c examples/simple-proxy.edn

# Terminal 3: Test the load balancer
curl http://localhost:80
```

---

### Multi-Backend with Source Routing

Route traffic to different backends based on the client's source IP address.

**File: `multi-backend.edn`**

**Use Case**:
- Route internal users to internal servers
- Route VPN users to dedicated backends
- Geographic or tenant-based routing

**Setup**:
```bash
# Start multiple backend servers
python3 -m http.server 8080 &  # Default backend
python3 -m http.server 8081 &  # Internal network backend
python3 -m http.server 8082 &  # VIP client backend

# Run the proxy
sudo clojure -M:run -c examples/multi-backend.edn

# Test from different source IPs
curl http://localhost:80  # Uses default backend (8080)
# Traffic from 192.168.x.x would go to 8081
# Traffic from 10.10.x.x would go to 8082
```

---

### SNI-Based Routing

Route TLS traffic to different backends based on the SNI hostname without terminating TLS.

**File: `sni-routing.edn`**

**Use Case**:
- Multi-tenant SaaS (customer-a.example.com, customer-b.example.com)
- Microservices routing (api.myapp.io, web.myapp.io, admin.myapp.io)
- Blue/green or canary deployments per service
- HTTPS load balancing without TLS termination

**Setup**:
```bash
# Start backend servers for different hostnames
# Each backend handles TLS termination
python3 -m http.server 8443 &  # Default backend
python3 -m http.server 8444 &  # api.example.com backend
python3 -m http.server 8445 &  # web.example.com backend

# Run the proxy
sudo clojure -M:run -c examples/sni-routing.edn

# Test with curl (specify SNI hostname)
curl -k --resolve api.example.com:443:127.0.0.1 https://api.example.com/
curl -k --resolve web.example.com:443:127.0.0.1 https://web.example.com/

# Or use openssl to verify SNI is being read
openssl s_client -connect localhost:443 -servername api.example.com
```

**Routing Priority**:
1. Source IP/CIDR routes (checked first)
2. SNI hostname routes (checked second)
3. Default target (fallback)

**Features**:
- Case-insensitive: `API.Example.COM` matches `api.example.com`
- Weighted targets per hostname for canary/blue-green deployments
- Zero TLS overhead (layer 4 passthrough)
- ~50-100ns added latency per new TLS connection

---

### Multi-Interface Proxy

Listen on multiple network interfaces, useful for servers with multiple NICs.

**File: `multi-interface.edn`**

**Use Case**:
- Public and private network interfaces
- Multiple VLANs
- Bonded network interfaces

**Setup**:
```bash
# List available interfaces
ip link show

# Update the configuration with your interface names
# Then run the proxy
sudo clojure -M:run -c examples/multi-interface.edn
```

---

### Kubernetes Ingress Style

Multiple proxies for different services, similar to a Kubernetes Ingress controller.

**File: `kubernetes-ingress.edn`**

**Use Case**:
- Microservices architecture
- Multi-tenant deployments
- API gateway patterns

**Setup**:
```bash
# Start service backends
# Web service on 8080
# API service on 3000
# Admin service on 9000

# Run the proxy
sudo clojure -M:run -c examples/kubernetes-ingress.edn

# Traffic flows:
# Port 80  -> Web backend (8080)
# Port 443 -> API backend (3000) - note: no TLS, layer 4 only
# Port 8443 -> Admin backend (9000)
```

---

### REPL Usage

Interactive usage from the Clojure REPL for development and debugging.

**File: `repl_usage.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'repl-usage)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'repl-usage)
```

The example demonstrates:
- Initializing the load balancer programmatically
- Adding/removing proxies at runtime
- Adding/removing source routes
- Querying connections and statistics
- Graceful shutdown

---

### Statistics and Monitoring

Real-time statistics collection and monitoring.

**File: `monitoring.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'monitoring)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'monitoring)
```

The example demonstrates:
- Enabling statistics collection
- Starting the stats event stream
- Subscribing to real-time events
- Aggregating statistics
- Calculating rates (events/packets/bytes per second)

---

### Connection Draining

Graceful backend removal patterns for zero-downtime deployments.

**File: `connection_draining.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'connection-draining)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'connection-draining)
```

The example demonstrates:
- Basic draining: Stop new connections while existing ones complete
- Drain with callback: Get notified when drain completes
- Synchronous draining: Block until drain finishes
- Rolling updates: Drain backends one at a time for zero-downtime deployments
- Maintenance windows: Safely take a backend offline for maintenance
- Graceful shutdown: Drain all backends before system shutdown
- Monitoring: Watch drain progress in real-time

**Key API Functions**:
```clojure
;; Start draining (stops new connections)
(lb/drain-backend! "proxy-name" "ip:port"
  :timeout-ms 30000
  :on-complete (fn [status] ...))

;; Cancel drain and restore traffic
(lb/undrain-backend! "proxy-name" "ip:port")

;; Check drain status
(lb/get-drain-status "ip:port")
(lb/get-all-draining)
(lb/draining? "ip:port")

;; Block until drain completes
(lb/wait-for-drain! "ip:port")  ; => :completed, :timeout, or :cancelled
```

---

### DNS Resolution

DNS-based backend discovery for dynamic environments like Kubernetes or cloud deployments.

**File: `dns_resolution.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'dns-resolution)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'dns-resolution)
```

The example demonstrates:
- Using DNS hostnames instead of static IPs
- Periodic re-resolution with configurable intervals
- Multiple A record expansion to weighted targets
- Graceful failure with last-known-good IP fallback
- Mixed static IP and DNS target configurations
- Kubernetes headless service patterns

---

### Rate Limiting

Token bucket rate limiting to protect backends and prevent client abuse.

**File: `rate_limiting.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'rate-limiting)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'rate-limiting)
```

The example demonstrates:
- Per-source IP rate limiting
- Per-backend rate limiting
- Token bucket algorithm configuration
- Burst handling for traffic spikes
- Runtime rate limit adjustment

---

### Prometheus Metrics

Export metrics in Prometheus format for monitoring and alerting.

**File: `prometheus_metrics.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'prometheus-metrics) (prometheus-metrics/run-demo)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'prometheus-metrics)
(prometheus-metrics/run-demo)
```

**Just start the metrics server**:
```clojure
(require '[lb.metrics :as metrics])
(metrics/start! {:port 9090})
;; Now visit http://localhost:9090/metrics
```

The example demonstrates:
- Starting a standalone metrics server
- Full integration with load balancer
- Available metrics (connections, bytes, health, latency histograms)
- Prometheus scrape configuration
- Grafana query examples
- Custom data source registration

---

### Circuit Breaker

Automatic failure detection and recovery using the circuit breaker pattern.

**File: `circuit_breaker.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'circuit-breaker) (circuit-breaker/-main)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'circuit-breaker)
(circuit-breaker/-main)
```

The example demonstrates:
- Circuit breaker state machine (CLOSED -> OPEN -> HALF-OPEN -> CLOSED)
- Configuring error thresholds and recovery timeouts
- Manual control: force-open, force-close, reset
- Event subscription for state change notifications
- Weight computation effects on traffic distribution
- Integration with health checks

**Key API Functions**:
```clojure
;; Check circuit state
(lb/circuit-open? "ip:port")           ; => true if blocking traffic
(lb/circuit-half-open? "ip:port")      ; => true if testing recovery
(lb/get-circuit-status)                ; => all circuits with details

;; Manual control
(lb/force-open-circuit! "ip:port")     ; Stop traffic immediately
(lb/force-close-circuit! "ip:port")    ; Resume traffic immediately
(lb/reset-circuit! "ip:port")          ; Reset counters

;; Event subscription
(require '[lb.circuit-breaker :as cb])
(cb/subscribe! (fn [event]
                 (println (:type event) (:target-id event))))
```

**State Machine**:
```
  CLOSED (normal)
     |
     | error rate >= 50%
     v
  OPEN (blocking)
     |
     | 30 seconds elapsed
     v
  HALF-OPEN (testing)
    /  \
   /    \
  v      v
CLOSED  OPEN
(success) (failure)
```

**Configuration**:
```clojure
{:settings
 {:circuit-breaker
  {:enabled true
   :error-threshold-pct 50      ; Trip when >50% requests fail
   :min-requests 10             ; Need 10 requests to evaluate
   :open-duration-ms 30000      ; Stay open for 30 seconds
   :half-open-requests 3        ; Need 3 successes to close
   :window-size-ms 60000}}}     ; 60 second sliding window
```

---

### Least Connections

Dynamic load balancing that routes new connections to backends with fewer active connections.

**File: `least_connections.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'least-connections) (least-connections/-main)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'least-connections)
(least-connections/-main)
```

The example demonstrates:
- Configuring least-connections vs weighted-random algorithms
- How weights are computed based on connection counts
- Weighted mode (respects backend capacity) vs pure mode
- Integration with health checks, drain, and circuit breaker
- Real-time connection distribution monitoring

**Key API Functions**:
```clojure
;; Query algorithm status
(lb/get-lb-algorithm)          ; => :weighted-random or :least-connections
(lb/get-lb-status)             ; => full status map
(lb/lb-least-connections?)     ; => true if least-connections enabled

;; Force immediate weight update
(lb/force-lb-update!)
```

**Weight Computation**:
```
Original weights: [50, 50]
Connection counts: [10, 50]

Backend A capacity: 50 / (1 + 10) = 4.55
Backend B capacity: 50 / (1 + 50) = 0.98
Total: 5.53

Effective weights: [82, 18]
(Backend A gets ~82% of new connections)
```

**Configuration**:
```clojure
{:settings
 {:load-balancing
  {:algorithm :least-connections  ; or :weighted-random (default)
   :weighted true                  ; Factor in original weights
   :update-interval-ms 1000}}}     ; Update frequency (100-10000ms)
```

**When to use least-connections**:
- Database connection pools
- WebSocket servers
- Long-polling endpoints
- Streaming media
- Mixed workloads with varying request durations

**When to use weighted-random** (default):
- Simple HTTP APIs with short requests
- Stateless microservices
- When you need explicit traffic ratios

---

### Session Persistence

Sticky sessions based on source IP hashing to route clients consistently to the same backend.

**File: `session_persistence.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'session-persistence) (session-persistence/-main)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'session-persistence)
(session-persistence/-main)
```

The example demonstrates:
- Enabling sticky sessions with `:session-persistence true`
- How source IP hashing ensures consistent backend selection
- Per-route session persistence configuration
- Use cases and best practices

**Configuration**:
```clojure
{:proxies
 [{:name "sticky-api"
   :listen {:interfaces ["eth0"] :port 8080}
   :session-persistence true  ; Enable sticky sessions
   :default-target
   [{:ip "10.0.0.1" :port 8080 :weight 50}
    {:ip "10.0.0.2" :port 8080 :weight 50}]}]}
```

**Per-route configuration**:
```clojure
{:source-routes
 [{:source "10.0.0.0/8"
   :target {:ip "10.0.0.1" :port 8080}
   :session-persistence true}]}
```

**Hash algorithm**:
```
selection_value = (source_ip * FNV_PRIME) % 100
```

Same source IP always produces the same hash, selecting the same backend (unless weights change or backend becomes unhealthy).

**When to use session persistence**:
- Shopping cart applications
- User login sessions
- WebSocket connections
- Gaming servers with player state
- File upload/download resumption

**When NOT to use**:
- Stateless microservices
- Short-lived requests
- When backends have unequal capacity
- During canary deployments

---

### Access Logging

Access logging and backend latency tracking for monitoring, debugging, and audit trails.

**File: `access_logging.clj`**

**Single-line execution**:
```bash
sudo clojure -M:dev -e "(require 'access-logging)"
```

**Interactive REPL**:
```bash
sudo clojure -M:dev
```
```clojure
(require 'access-logging)
```

The example demonstrates:
- Configuring access logging to stdout and rotating file
- JSON and CLF (Common Log Format) output formats
- Backend latency histogram tracking
- Prometheus metrics integration

**JSON Log Format**:
```json
{"timestamp":"2025-01-15T10:30:45.123Z","event":"conn-closed",
 "src":{"ip":"192.168.1.100","port":54321},
 "dst":{"ip":"10.0.0.1","port":80},
 "backend":{"ip":"10.0.0.5","port":8080},
 "duration_ms":1523,"bytes_fwd":1024,"bytes_rev":4096,"protocol":"tcp"}
```

**CLF Log Format**:
```
192.168.1.100 - - [15/Jan/2025:10:30:45 +0000] "CONN-CLOSED 10.0.0.1:80 -> 10.0.0.5:8080" 1024/4096 1523ms
```

**Configuration**:
```clojure
{:settings
 {:stats-enabled true               ; Required for access logging
  :metrics {:enabled true           ; Required for latency histograms
            :port 9090}
  :access-log {:enabled true
               :format :json         ; :json or :clf
               :path "logs/access.log"
               :max-file-size-mb 100  ; Rotate at 100MB
               :max-files 10          ; Keep 10 rotated files
               :buffer-size 10000}}}  ; Async buffer size
```

**Backend Latency Metrics** (available at `/metrics`):
```
# HELP lb_backend_latency_seconds Backend connection latency in seconds
# TYPE lb_backend_latency_seconds histogram
lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="0.01"} 15
lb_backend_latency_seconds_bucket{proxy_name="web",target_ip="10.0.0.1",target_port="8080",le="+Inf"} 100
lb_backend_latency_seconds_sum{proxy_name="web",target_ip="10.0.0.1",target_port="8080"} 45.678
lb_backend_latency_seconds_count{proxy_name="web",target_ip="10.0.0.1",target_port="8080"} 100
```

**Key API Functions**:
```clojure
;; Access logging
(require '[lb.access-log :as access-log])
(access-log/running?)               ; Check if logging is active
(access-log/get-status)             ; Get log file status
(access-log/flush!)                 ; Flush buffers before shutdown

;; Backend latency tracking
(require '[lb.latency :as latency])
(latency/running?)                  ; Check if tracking is active
(latency/get-percentiles "web" "10.0.0.1:8080")
;; => {:p50 0.023 :p95 0.15 :p99 0.45 :mean 0.056 :count 1523}
(latency/get-all-histograms)        ; All per-backend histograms
(latency/reset-histograms!)         ; Reset for testing
```

---

### Admin HTTP API

HTTP REST API for runtime management without REPL access.

**File: `admin_api.clj`**

**Use Case**:
- Automation and scripting of LB operations
- Integration with orchestration tools (Kubernetes, Ansible)
- Remote management via HTTP
- Monitoring and health checks

**Setup**:
```bash
# Start the load balancer with admin API enabled
sudo clojure -M:dev

# In REPL:
(require 'admin-api)
(lb/init! (config/parse-config admin-api/config-with-admin-api))

# In another terminal, test the API:
curl http://localhost:8081/api/v1/status
curl http://localhost:8081/api/v1/proxies
```

**Example curl commands**:
```bash
# Get status
curl http://localhost:8081/api/v1/status

# List all proxies
curl http://localhost:8081/api/v1/proxies

# Add a new proxy
curl -X POST http://localhost:8081/api/v1/proxies \
  -H "Content-Type: application/json" \
  -d '{"name":"web","listen":{"interfaces":["eth0"],"port":80},"default-target":{"ip":"10.0.0.1","port":8080}}'

# Add a source route
curl -X POST http://localhost:8081/api/v1/proxies/web/routes \
  -H "Content-Type: application/json" \
  -d '{"source":"192.168.1.0/24","target":{"ip":"10.0.0.5","port":8080}}'

# Drain a backend
curl -X POST http://localhost:8081/api/v1/drains \
  -H "Content-Type: application/json" \
  -d '{"proxy":"web","target":"10.0.0.1:8080","timeout_ms":30000}'

# Force circuit open
curl -X POST http://localhost:8081/api/v1/circuits/10.0.0.1%3A8080/open

# With API key authentication
curl -H "X-API-Key: my-secret-key" http://localhost:8081/api/v1/status
```

**Configuration**:
```clojure
{:settings
 {:admin-api {:enabled true
              :port 8081              ; HTTP port (default 8081)
              :api-key "secret-key"   ; Optional API key auth
              :allowed-origins nil}}} ; Optional CORS origins
```

**API Endpoints**:
- `GET /api/v1/status` - Overall status
- `GET /api/v1/config` - Current configuration
- `GET/POST/DELETE /api/v1/proxies` - Proxy management
- `GET/POST/DELETE /api/v1/proxies/:name/routes` - Source routes
- `GET/POST/DELETE /api/v1/proxies/:name/sni-routes` - SNI routes
- `GET/DELETE /api/v1/connections` - Connection management
- `GET /api/v1/health` - Health status
- `GET/POST/DELETE /api/v1/drains` - Connection draining
- `GET/POST /api/v1/circuits/:target/*` - Circuit breaker control
- `POST /api/v1/reload` - Config hot reload

**Response format**:
```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

---

## Testing Examples Locally

### Create a Test Environment with Network Namespaces

```bash
#!/bin/bash
# Create isolated network namespace for testing

# Create namespace
sudo ip netns add test-ns

# Create veth pair
sudo ip link add veth-host type veth peer name veth-ns

# Move one end to namespace
sudo ip link set veth-ns netns test-ns

# Configure host side
sudo ip addr add 10.99.1.1/24 dev veth-host
sudo ip link set veth-host up

# Configure namespace side
sudo ip netns exec test-ns ip addr add 10.99.1.2/24 dev veth-ns
sudo ip netns exec test-ns ip link set veth-ns up
sudo ip netns exec test-ns ip link set lo up

# Start backend in namespace
sudo ip netns exec test-ns python3 -m http.server 8080 &

# Now you can test with the proxy attached to veth-host
```

### Cleanup Test Environment

```bash
sudo ip link del veth-host
sudo ip netns del test-ns
```

## Configuration Tips

### Determining the Right Interface

```bash
# Find the interface receiving traffic
ip route get 8.8.8.8 | grep -oP 'dev \K\S+'

# List all interfaces with IPs
ip -br addr show

# Show interface details
ip link show eth0
```

### Estimating Connection Limits

```clojure
;; Each connection uses approximately:
;; - Conntrack entry: ~100 bytes
;; - Per-CPU overhead: ~50 bytes * num_cpus
;;
;; For 100,000 connections on 8 CPUs:
;; Memory = 100,000 * (100 + 50*8) = ~50 MB

{:settings {:max-connections 100000}}
```

### Timeout Tuning

```clojure
{:settings
 {:connection-timeout-sec 300    ; 5 minutes for web traffic
  ;; Or for long-lived connections:
  ;; :connection-timeout-sec 3600 ; 1 hour
  ;; Or for high-churn services:
  ;; :connection-timeout-sec 60   ; 1 minute
  }}
```

## Common Patterns

### Blue-Green Deployment

```clojure
;; Switch between backends by updating the default target
(lb/remove-proxy! "web")
(lb/add-proxy!
  {:name "web"
   :listen {:interfaces ["eth0"] :port 80}
   :default-target {:ip "10.0.0.2" :port 8080}})  ; Green backend
```

### Canary Releases

```clojure
;; Route specific IPs to canary backend
(lb/add-source-route! "web" "192.168.1.0/24"
                         {:ip "10.0.0.3" :port 8080})  ; Canary backend
```

### Maintenance Mode

```clojure
;; Option 1: Use connection draining (recommended)
;; Gracefully drain existing connections, then perform maintenance
(let [restore (do
                (lb/drain-backend! "web" "10.0.0.1:8080" :timeout-ms 60000)
                (lb/wait-for-drain! "10.0.0.1:8080")
                ;; Return a restore function
                #(lb/undrain-backend! "web" "10.0.0.1:8080"))]
  ;; Perform maintenance...
  (restore))

;; Option 2: Redirect all traffic to maintenance page server
(lb/remove-proxy! "web")
(lb/add-proxy!
  {:name "web"
   :listen {:interfaces ["eth0"] :port 80}
   :default-target {:ip "10.0.0.99" :port 8080}})  ; Maintenance server
```

### SNI-Based Multi-Tenant Routing

```clojure
;; Add SNI routes at runtime for new tenants
(lb/add-sni-route! "https-gateway" "new-customer.example.com"
                   {:ip "10.5.0.1" :port 8443})

;; Weighted SNI route for canary deployment
(lb/add-sni-route! "https-gateway" "api.example.com"
                   [{:ip "10.5.1.1" :port 8443 :weight 90}   ; Stable
                    {:ip "10.5.1.2" :port 8443 :weight 10}]) ; Canary

;; Remove a tenant's route
(lb/remove-sni-route! "https-gateway" "old-customer.example.com")

;; List all SNI routes
(lb/list-sni-routes "https-gateway")
```

### Per-Service Blue/Green with SNI

```clojure
;; Each service can have independent blue/green deployments
;; API: 100% green (migration complete)
(lb/add-sni-route! "gateway" "api.myapp.io"
                   {:ip "10.0.1.2" :port 8443})  ; Green only

;; Web: 50/50 split (mid-migration)
(lb/add-sni-route! "gateway" "web.myapp.io"
                   [{:ip "10.0.2.1" :port 8443 :weight 50}   ; Blue
                    {:ip "10.0.2.2" :port 8443 :weight 50}]) ; Green

;; Admin: 100% blue (not yet migrated)
(lb/add-sni-route! "gateway" "admin.myapp.io"
                   {:ip "10.0.3.1" :port 8443})  ; Blue only
```

### Graceful Rolling Updates

```clojure
;; Zero-downtime rolling update across all backends
(defn rolling-update [proxy-name targets deploy-fn]
  (doseq [target targets]
    ;; 1. Drain the backend (stop new connections)
    (lb/drain-backend! proxy-name target :timeout-ms 30000)

    ;; 2. Wait for existing connections to complete
    (lb/wait-for-drain! target)

    ;; 3. Deploy new version
    (deploy-fn target)

    ;; 4. Restore traffic
    (lb/undrain-backend! proxy-name target)))

;; Usage:
(rolling-update "web"
                ["10.0.0.1:8080" "10.0.0.2:8080"]
                (fn [target] (println "Deploying to" target)))
```

## Next Steps

- Read the main [README.md](../README.md) for complete documentation
- Explore the [source code](../src/lb/) for implementation details
- Check out [clj-ebpf](https://github.com/pgdad/clj-ebpf) for the underlying eBPF library
