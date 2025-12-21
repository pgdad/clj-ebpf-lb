# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pgdad/clj-ebpf-lb/releases/tag/v0.1.0
