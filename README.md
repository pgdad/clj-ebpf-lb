# clj-ebpf-reverse-proxy

A high-performance eBPF-based reverse proxy written in Clojure. Uses XDP (eXpress Data Path) for ingress DNAT and TC (Traffic Control) for egress SNAT, providing kernel-level packet processing for efficient Layer 4 load balancing.

## Features

- **High Performance**: Packet processing happens in the Linux kernel using eBPF, bypassing the userspace networking stack
- **XDP Ingress DNAT**: Incoming packets are redirected to backend targets at the earliest point in the network stack
- **TC Egress SNAT**: Return traffic has its source address rewritten to appear as the proxy
- **Connection Tracking**: Full stateful NAT with per-CPU hash maps for scalability
- **Source-Based Routing**: Route traffic to different backends based on client IP/subnet
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
   git clone https://github.com/your-org/clj-ebpf-reverse-proxy.git
   cd clj-ebpf-reverse-proxy
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

2. **Run the proxy**:
   ```bash
   sudo clojure -M:run -c proxy.edn
   ```

### Command Line Options

```
Usage: reverse-proxy [options]

Options:
  -c, --config FILE       Configuration file path (default: config.edn)
  -i, --interface IFACE   Network interface to attach to (can specify multiple)
  -p, --port PORT         Listen port (default: 80)
  -t, --target TARGET     Default target as ip:port (default: 127.0.0.1:8080)
  -s, --stats             Enable statistics collection
  -v, --verbose           Verbose output
  -h, --help              Show help

Examples:
  reverse-proxy -c proxy.edn
  reverse-proxy -i eth0 -p 80 -t 10.0.0.1:8080
  reverse-proxy -i eth0 -i eth1 -p 443 -t 10.0.0.2:8443 --stats
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

## Programmatic API

Use the proxy as a library in your Clojure application:

```clojure
(require '[reverse-proxy.core :as proxy]
         '[reverse-proxy.config :as config])

;; Create configuration
(def cfg (config/make-simple-config
           {:interface "eth0"
            :port 80
            :target-ip "10.0.0.1"
            :target-port 8080
            :stats-enabled true}))

;; Initialize the proxy
(proxy/init! cfg)

;; Check status
(proxy/get-status)
;; => {:running true, :attached-interfaces ["eth0"], ...}

;; Add a source route at runtime
(proxy/add-source-route! "web" "192.168.1.0/24"
                         {:ip "10.0.0.2" :port 8080})

;; Get active connections
(proxy/get-connections)

;; Print connection statistics
(proxy/print-connections)

;; Shutdown
(proxy/shutdown!)
```

### Runtime Configuration

```clojure
;; Add a new proxy at runtime
(proxy/add-proxy!
  {:name "api"
   :listen {:interfaces ["eth0"] :port 8080}
   :default-target {:ip "10.0.1.1" :port 3000}})

;; Remove a proxy
(proxy/remove-proxy! "api")

;; Add/remove source routes
(proxy/add-source-route! "web" "10.20.0.0/16" {:ip "10.0.0.5" :port 8080})
(proxy/remove-source-route! "web" "10.20.0.0/16")

;; Attach/detach interfaces
(proxy/attach-interfaces! ["eth1" "eth2"])
(proxy/detach-interfaces! ["eth2"])
```

### Statistics and Monitoring

```clojure
;; Enable/disable stats
(proxy/enable-stats!)
(proxy/disable-stats!)

;; Get connection statistics
(proxy/get-connection-count)
(proxy/get-connection-stats)
;; => {:total-connections 42
;;     :total-packets-forward 12345
;;     :total-bytes-forward 987654
;;     :total-packets-reverse 11234
;;     :total-bytes-reverse 876543}

;; Start streaming statistics
(proxy/start-stats-stream!)
(let [ch (proxy/subscribe-to-stats)]
  ;; Read events from channel
  (async/<! ch))
(proxy/stop-stats-stream!)
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
sudo java -jar target/reverse-proxy.jar -c proxy.edn
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
- Ensure interface is attached: `(proxy/list-attached-interfaces)`
- Check conntrack entries: `(proxy/get-connections)`

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
