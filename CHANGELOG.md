# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pgdad/clj-ebpf-lb/releases/tag/v0.1.0
