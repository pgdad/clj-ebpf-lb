# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- TLS/SNI-based routing for layer 4 passthrough with layer 7 inspection
  - Route TLS traffic based on hostname without terminating TLS
  - XDP-level TLS ClientHello parsing with SNI extraction
  - FNV-1a 64-bit hashing for efficient BPF map lookup
  - Case-insensitive hostname matching
  - Weighted load balancing support per SNI hostname
  - Runtime SNI route management (`add-sni-route!`, `remove-sni-route!`, `list-sni-routes`)
  - Graceful fallback to default target when SNI not found or parsing fails

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

[Unreleased]: https://github.com/pgdad/clj-ebpf-lb/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pgdad/clj-ebpf-lb/releases/tag/v0.1.0
