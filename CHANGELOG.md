# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.2] - 2025-12-29

### Changed
- Updated clj-ebpf dependency from 0.7.4 to 0.7.5
- Added new namespace requires in common.clj:
  - `clj-ebpf.net.ipv4` - IPv4 packet helpers
  - `clj-ebpf.net.tcp` - TCP packet helpers
  - `clj-ebpf.net.udp` - UDP packet helpers
- Added new 0.7.5 store helper delegations in common.clj:
  - `ipv4-store-saddr` - Store IPv4 source address from register to packet
  - `ipv4-store-daddr` - Store IPv4 destination address from register to packet
  - `tcp-store-sport` - Store TCP source port from register to packet
  - `tcp-store-dport` - Store TCP destination port from register to packet
  - `udp-store-sport` - Store UDP source port from register to packet
  - `udp-store-dport` - Store UDP destination port from register to packet

## [0.10.1] - 2025-12-29

### Changed
- Updated clj-ebpf dependency from 0.7.0 to 0.7.4
  - 0.7.3: Minor bug fixes and performance improvements
  - 0.7.4: New IPv6 helpers (`build-load-ipv6-src`, `build-load-ipv6-dst`, `build-store-ipv6-address`)
- Refactored tc_egress.clj to use `build-store-ipv6-address` helper for IPv6 SNAT
  - Simplified manual word-by-word address stores to single helper calls
  - Reduced code by ~13 lines while maintaining identical functionality
- Added new helper delegations in common.clj:
  - `build-load-ipv6-src` - Load IPv6 source address from packet to stack
  - `build-load-ipv6-dst` - Load IPv6 destination address from packet to stack
  - `build-store-ipv6-address` - Store IPv6 address from stack to packet
- Updated all dependencies to latest versions:
  - org.clojure/clojure: 1.12.0 → 1.12.4
  - org.clojure/core.async: 1.6.681 → 1.8.741
  - org.clojure/tools.cli: 1.1.230 → 1.2.245
  - ch.qos.logback/logback-classic: 1.5.6 → 1.5.23
  - io.github.clojure/tools.build: 0.10.6 → 0.10.7

## [0.10.0] - 2025-12-22

### Added
- IPv6 dual-stack support for full IPv4/IPv6 operation
  - Same proxy handles both IPv4 and IPv6 traffic simultaneously
  - Unified 16-byte address format (IPv4 addresses zero-padded)
  - XDP ingress program with EtherType branching for IPv4/IPv6
  - TC egress program with IPv4/IPv6 SNAT handling
  - Unified BPF maps with larger key/value sizes:
    - LPM key: 20 bytes (prefix_len(4) + ip(16))
    - Route value: 168 bytes (header(8) + 8 targets × 20 bytes each)
    - Conntrack key: 40 bytes (src_ip(16) + dst_ip(16) + ports(4) + proto(1) + pad(3))
    - Conntrack value: 96 bytes
  - IPv6-specific checksum handling (no IP header checksum)
  - Full address parsing for IPv6 formats (full, compressed, zone IDs)
  - New utility functions: `ipv6-string->bytes`, `bytes->ipv6-string`
  - New unified functions: `ip-string->bytes16`, `bytes16->ip-string`
  - New unified CIDR parsing: `parse-cidr-unified`
  - New unified key encoding: `encode-lpm-key-unified`, `encode-conntrack-key-unified`
  - New unified map creation: `create-all-maps-unified`
  - New unified program builders: `build-xdp-ingress-program-unified`, `build-tc-egress-program-unified`
  - IPv6 addresses supported in targets: `{:ip "2001:db8::1" :port 8080}`
  - IPv6 source routes: `{:source "2001:db8:cafe::/48" :target ...}`
  - Comprehensive IPv6 test coverage
  - IPv6 constants: `ETH-P-IPV6-BE`, `IPV6-HLEN`, `IPV6-OFF-*`

### Changed
- Stack layout updated for unified 16-byte addresses
- Conntrack value format extended for 16-byte IP storage

## [0.9.0] - 2025-12-21

### Added
- Admin HTTP REST API for runtime management without REPL access
  - RESTful JSON API using Java's built-in HttpServer (zero dependencies)
  - Complete proxy management: list, add, remove proxies
  - Source route management: list, add, remove CIDR-based routes
  - SNI route management: list, add, remove hostname-based TLS routes
  - Connection management: list, count, stats, clear connections
  - Health status queries per proxy and aggregate
  - Connection draining control: start drain, cancel drain
  - Circuit breaker control: force open, close, reset circuits
  - DNS resolution status and forced re-resolution
  - Load balancing status and forced weight updates
  - Rate limit configuration: set source/backend limits, clear all
  - Configuration hot reload trigger
  - Optional API key authentication via X-API-Key header
  - Optional CORS support for web dashboard integration
  - Health endpoint at /health for Kubernetes probes
  - Configuration: `{:settings {:admin-api {:enabled true :port 8081 :api-key nil}}}`
  - Runtime API: `admin/start!`, `admin/stop!`, `admin/running?`, `admin/get-status`
  - New modules: `lb.admin`, `lb.admin.server`, `lb.admin.handlers`
  - Comprehensive examples with curl commands in `examples/admin_api.clj`

## [0.8.0] - 2025-12-21

### Added
- Access logging for connection events with audit trail and debugging support
  - Logs connection lifecycle events (new-conn, conn-closed) to stdout and file
  - JSON format with structured data (timestamps, IPs, ports, duration, bytes)
  - CLF (Common Log Format) style for familiar Apache/nginx-like output
  - Rotating file writer with configurable size and file count limits
  - Async non-blocking design with buffered channels
  - Configuration: `{:settings {:access-log {:enabled true :format :json :path "logs/access.log"}}}`
  - Runtime API: `access-log/running?`, `access-log/get-status`, `access-log/flush!`
  - New modules: `lb.access-log`, `lb.access-log.logger`, `lb.access-log.file-writer`
- Backend latency tracking for per-backend connection duration histograms
  - Tracks connection lifetime (creation to close) as latency metric
  - Prometheus histogram metrics: `lb_backend_latency_seconds` with buckets
  - Percentile queries: p50, p95, p99, mean, count per backend
  - Zero BPF changes required (uses existing stats event stream)
  - Automatic integration when metrics enabled
  - Runtime API: `latency/get-percentiles`, `latency/get-all-histograms`, `latency/get-status`
  - New module: `lb.latency`
  - Comprehensive examples in `examples/access_logging.clj`

### Changed
- Added `org.clojure/data.json` dependency for JSON formatting

## [0.7.0] - 2025-12-21

### Added
- Session persistence (sticky sessions) based on source IP hashing
  - Routes same client IP consistently to same backend server
  - Deterministic hash: `(source_ip * FNV_PRIME) % 100`
  - XDP-level implementation for zero-overhead persistence
  - Per-proxy configuration: `{:session-persistence true}`
  - Per-route configuration for source-routes and SNI routes
  - Respects weighted distribution across backends
  - Integrates with health checks (unhealthy backends excluded)
  - Flag-based activation using route value flags field
  - New constant: `util/FLAG-SESSION-PERSISTENCE` (0x0001)
  - Comprehensive examples in `examples/session_persistence.clj`

## [0.6.0] - 2025-12-21

### Added
- Least-connections load balancing algorithm for dynamic traffic distribution
  - Routes new connections to backends with fewer active connections
  - Userspace periodic weight updates leveraging existing conntrack data
  - Background daemon scans connection counts every update-interval-ms
  - Two modes: weighted (capacity-aware) and pure (ignores original weights)
  - Weight formula: `capacity = original_weight / (1 + connections)`
  - Integrates with health checks, drain, and circuit breaker systems
  - Zero BPF changes required (uses existing weight mechanism)
  - Configuration: `{:settings {:load-balancing {:algorithm :least-connections :weighted true :update-interval-ms 1000}}}`
  - Runtime API: `get-lb-algorithm`, `get-lb-status`, `lb-least-connections?`, `force-lb-update!`
  - Prometheus metrics: `lb_algorithm`, `lb_backend_connections`
  - New modules: `lb.lb-algorithm`, `lb.lb-manager`
  - Comprehensive examples in `examples/least_connections.clj`

## [0.5.0] - 2025-12-21

### Added
- Circuit breaker pattern for automatic failure detection and recovery
  - Prevents cascade failures by stopping traffic to failing backends
  - Three-state machine: CLOSED (normal), OPEN (blocking), HALF-OPEN (testing)
  - Configurable error threshold, minimum requests, and recovery timeout
  - Sliding window for error rate calculation
  - Automatic transition from OPEN to HALF-OPEN after timeout
  - Gradual traffic restoration with 10% test traffic in HALF-OPEN
  - Graceful degradation when all circuits open (traffic continues)
  - Integration with health check events for error tracking
  - Weight computation combines health, drain, and circuit breaker states
  - Prometheus metrics: `lb_circuit_breaker_state`, `lb_circuit_breaker_error_rate`
  - Runtime API: `circuit-open?`, `circuit-half-open?`, `force-open-circuit!`, `force-close-circuit!`, `reset-circuit!`
  - Event subscription for state change notifications
  - Configuration: `{:settings {:circuit-breaker {:enabled true :error-threshold-pct 50 :min-requests 10 :open-duration-ms 30000}}}`
  - New module: `lb.circuit-breaker`
  - Comprehensive examples in `examples/circuit_breaker.clj`

## [0.4.0] - 2025-12-21

### Added
- Prometheus metrics export for monitoring and observability
  - HTTP endpoint at `/metrics` with standard Prometheus text format
  - Metrics include: `lb_connections_active`, `lb_bytes_total`, `lb_packets_total`
  - Backend health status: `lb_backend_health` (1=healthy, 0=unhealthy)
  - Health check latency histogram: `lb_health_check_latency_seconds`
  - DNS resolution status: `lb_dns_resolution_status`
  - System info: `lb_up`, `lb_info`
  - Configurable port and path via settings
  - Automatic integration with health check system for latency recording
  - Configuration: `{:settings {:metrics {:enabled true :port 9090 :path "/metrics"}}}`
  - Runtime API: `metrics/start!`, `metrics/stop!`, `metrics/running?`, `metrics/get-status`
- DNS-based backend resolution for dynamic environments
  - Use `:host` instead of `:ip` for DNS-backed targets
  - Periodic re-resolution with configurable intervals (`:dns-refresh-seconds`)
  - Multiple A record expansion to weighted targets (weight distributed equally)
  - Graceful failure handling with last-known-good IP fallback
  - Background daemon with jitter to avoid thundering herd
  - Health check integration for resolved IPs
  - Event subscription system for DNS resolution changes
  - Mixed static IP and DNS target support in same target group
  - Runtime API: `get-dns-status`, `get-all-dns-status`, `force-dns-resolve!`
  - New modules: `lb.dns`, `lb.dns.resolver`, `lb.dns.manager`
  - Configuration examples:
    - Basic: `{:host "backend.local" :port 8080}`
    - With refresh: `{:host "backend.local" :port 8080 :dns-refresh-seconds 60}`
    - Mixed: `[{:ip "10.0.0.1" :port 8080 :weight 50} {:host "dynamic.svc" :port 8080 :weight 50}]`
- Hot reload configuration without restart
  - File watching with inotify-based detection (Java NIO WatchService)
  - SIGHUP signal handling for manual reload trigger
  - Configuration diffing with incremental apply
  - Validation before apply with rollback on failure
  - Runtime API: `reload-config!`, `reload-config-from-map!`
  - Enable/disable: `enable-hot-reload!`, `disable-hot-reload!`
  - Status: `hot-reload-enabled?`, `get-reload-state`
  - New config diffing functions in `lb.config`
- Rate limiting with token bucket algorithm
  - Per-source IP rate limiting to prevent client abuse
  - Per-backend rate limiting to protect backend capacity
  - BPF-based enforcement with sub-millisecond overhead
  - LRU hash maps for automatic bucket expiration
  - Token scaling (1000x) for precise sub-token accounting
  - Runtime API: `set-source-rate-limit!`, `set-backend-rate-limit!`
  - Disable functions: `disable-source-rate-limit!`, `disable-backend-rate-limit!`, `clear-rate-limits!`
  - Status functions: `get-rate-limit-config`, `rate-limiting-enabled?`
  - Configuration via settings: `{:rate-limits {:per-source {:requests-per-sec 100 :burst 200}}}`

## [0.3.0] - 2025-12-21

### Added
- Connection draining for graceful backend removal
  - Stop new connections while allowing existing ones to complete
  - Background watcher monitors connection counts via conntrack
  - Configurable drain timeout (default 30 seconds)
  - Callback support for drain completion notification
  - Runtime API: `drain-backend!`, `undrain-backend!`, `wait-for-drain!`
  - Status functions: `get-drain-status`, `get-all-draining`, `draining?`
  - Drain-aware weight computation integrates with health system
  - No BPF changes required (uses existing weight=0 handling)
  - Comprehensive examples in `examples/connection-draining.clj`

## [0.2.0] - 2025-12-21

### Added
- TLS/SNI-based routing for layer 4 passthrough with layer 7 inspection
  - Route TLS traffic based on hostname without terminating TLS
  - XDP-level TLS ClientHello parsing with SNI extraction
  - FNV-1a 64-bit hashing for efficient BPF map lookup
  - Case-insensitive hostname matching
  - Weighted load balancing support per SNI hostname
  - Runtime SNI route management (`add-sni-route!`, `remove-sni-route!`, `list-sni-routes`)
  - Graceful fallback to default target when SNI not found or parsing fails
- New macros for cleaner code patterns
  - `with-lb-state` macro in core API for cleaner state access (replaces 25 `when-let` patterns)
  - `when-root` and `root?` in test utilities for root privilege checking
  - `with-bpf-maps` macro for automatic BPF map cleanup in tests
  - `with-xdp-attached` macro for automatic XDP detachment in tests
- Shared test utilities namespace (`lb.test-util`) for common test patterns
- Integration with `bpf/with-program` macro from clj-ebpf library for program lifecycle

## [0.1.0] - 2025-12-21

### Added
- Initial release of clj-ebpf-lb
- XDP-based ingress DNAT for high-performance packet processing
- TC-based egress SNAT for return traffic handling
- Stateful connection tracking with per-CPU hash maps
- Source-based routing with LPM trie for CIDR matching
- Weighted load balancing across multiple backends (up to 8 targets per group)
- Health checking system with TCP, HTTP, and HTTPS checks
- Automatic weight redistribution when backends become unhealthy
- Gradual recovery for backends returning to healthy state
- Runtime configuration API for adding/removing proxies and routes
- Real-time statistics collection via ring buffer
- EDN-based configuration file format
- Command-line interface with multiple options
- ARM64 support with QEMU-based testing infrastructure
- GitHub Actions CI/CD pipeline
- Clojars publishing on version tags

[0.10.2]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pgdad/clj-ebpf-lb/releases/tag/v0.1.0
