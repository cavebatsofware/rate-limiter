# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2025-11-29

### Fixed

- Updated `prometheus` dependency from 0.13 to 0.14 to resolve RUSTSEC-2024-0437 security advisory

## [0.2.1] - 2025-11-28

### Added

- Configurable IP extraction via `IpExtractionStrategy` enum:
  - `ForwardedHeader` (with configurable header name and extraction logic)
    - Convenience methods for common headers:
      - `x_forwarded_for()` (default) - expects exactly one IP from trusted proxy
      - `x_real_ip()` (nginx)
      - `cloudflare()` (uses `CF-Connecting-IP`)
      - `custom_header("X-Custom-IP")`
  - `SocketAddr` (direct connections)
- `SecurityContextConfig` for configuring the security context middleware
- `security_context_middleware_with_config` for custom IP extraction

## [0.2.0] - 2025-11-28

### Changed

- **BREAKING**: User agent patterns are now treated as full regex patterns (previously they were escaped as literal substrings). Existing configurations using literal strings like `"zgrab"` will continue to work, but patterns containing regex metacharacters will now be interpreted as regex.
- Switched from individual `Regex` objects to `RegexSet` for both path and user agent pattern matching. This provides significant performance improvements:
  - Single-pass matching against all patterns instead of iterating through each pattern
  - Eliminates per-request `String` allocation from `to_lowercase()` for user agent matching
  - Typical 3-10x performance improvement for pattern matching
