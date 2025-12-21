# clj-ebpf-lb

A high-performance eBPF-based Layer 4 load balancer written in Clojure. Uses XDP (eXpress Data Path) for ingress DNAT and TC (Traffic Control) for egress SNAT, providing kernel-level packet processing for efficient traffic distribution. Can also be used as a simple reverse proxy.

## Features

- **High Performance**: Packet processing happens in the Linux kernel using eBPF, bypassing the userspace networking stack
- **XDP Ingress DNAT**: Incoming packets are redirected to backend targets at the earliest point in the network stack
- **TC Egress SNAT**: Return traffic has its source address rewritten to appear as the proxy
- **Connection Tracking**: Full stateful NAT with per-CPU hash maps for scalability
- **Source-Based Routing**: Route traffic to different backends based on client IP/subnet
- **Weighted Load Balancing**: Distribute traffic across multiple backends with configurable weights
- **Runtime Configuration**: Add/remove proxies and routes without restart
- **Statistics Collection**: Real-time connection and traffic statistics via ring buffer
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
2. Default target (if no route matches)

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

Copyright (c) 2025. All rights reserved.

## See Also

- [clj-ebpf](https://github.com/pgdad/clj-ebpf) - The underlying eBPF library for Clojure
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) - Learn more about XDP programming
- [TC BPF](https://docs.cilium.io/en/stable/bpf/) - Traffic Control with BPF

---

**Note**: This project was previously named `clj-ebpf-reverse-proxy`. The core functionality remains the same, but the name was changed to better reflect the weighted load balancing capabilities.
