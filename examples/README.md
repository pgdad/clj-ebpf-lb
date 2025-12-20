# Examples

This directory contains example configurations and usage patterns for the clj-ebpf-reverse-proxy.

## Quick Reference

| Example | Description | Complexity |
|---------|-------------|------------|
| [simple-proxy.edn](#simple-single-backend-proxy) | Basic single backend setup | Beginner |
| [multi-backend.edn](#multi-backend-with-source-routing) | Source-based routing to multiple backends | Intermediate |
| [multi-interface.edn](#multi-interface-proxy) | Proxy across multiple network interfaces | Intermediate |
| [kubernetes-ingress.edn](#kubernetes-ingress-style) | K8s-style ingress controller pattern | Advanced |
| [repl_usage.clj](#repl-usage) | Interactive REPL session | Intermediate |
| [monitoring.clj](#statistics-and-monitoring) | Real-time statistics monitoring | Advanced |

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

# Terminal 2: Run the proxy
cd /path/to/clj-ebpf-reverse-proxy
sudo clojure -M:run -c examples/simple-proxy.edn

# Terminal 3: Test the proxy
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

**Instructions**:
```bash
# Start a REPL with the dev alias
sudo clojure -M:dev

# Load and run the example
(load-file "examples/repl_usage.clj")
```

The example demonstrates:
- Initializing the proxy programmatically
- Adding/removing proxies at runtime
- Adding/removing source routes
- Querying connections and statistics
- Graceful shutdown

---

### Statistics and Monitoring

Real-time statistics collection and monitoring.

**File: `monitoring.clj`**

**Instructions**:
```bash
# Start a REPL
sudo clojure -M:dev

# Load and run the example
(load-file "examples/monitoring.clj")
```

The example demonstrates:
- Enabling statistics collection
- Starting the stats event stream
- Subscribing to real-time events
- Aggregating statistics
- Calculating rates (events/packets/bytes per second)

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
(proxy/remove-proxy! "web")
(proxy/add-proxy!
  {:name "web"
   :listen {:interfaces ["eth0"] :port 80}
   :default-target {:ip "10.0.0.2" :port 8080}})  ; Green backend
```

### Canary Releases

```clojure
;; Route specific IPs to canary backend
(proxy/add-source-route! "web" "192.168.1.0/24"
                         {:ip "10.0.0.3" :port 8080})  ; Canary backend
```

### Maintenance Mode

```clojure
;; Redirect all traffic to maintenance page server
(proxy/remove-proxy! "web")
(proxy/add-proxy!
  {:name "web"
   :listen {:interfaces ["eth0"] :port 80}
   :default-target {:ip "10.0.0.99" :port 8080}})  ; Maintenance server
```

## Next Steps

- Read the main [README.md](../README.md) for complete documentation
- Explore the [source code](../src/reverse_proxy/) for implementation details
- Check out [clj-ebpf](https://github.com/pgdad/clj-ebpf) for the underlying eBPF library
