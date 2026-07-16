# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `docs/` with detailed guides: SETUP, CONFIG, ARCHITECTURE, CI, LEGITIMACY.

### Changed

- `AUTH.md` moved to `docs/LEGITIMACY.md`.
- All source comments unified to English with Doxygen-style doc-comments;
  user-facing CLI output translated to English.
- CI actions modernized to Node 24: `checkout@v5`, `upload-artifact@v7`,
  `setup-qemu-action@v4`, and `actions/cache` replaced with
  `Swatinem/rust-cache@v2` (Rust-aware caching). Clears all Node 20
  deprecation warnings.

## [0.1.0] - 2026-07-16

### Added

- Layer 1: passive reachability probe (DNS / HTTPS / TCP:443 / ICMP) and
  read-only security audit, run from the operator's own servers.
- Layer 2: optional corroboration against a public reference measurement API
  (read-only GET; endpoint and country code operator-configured via env).
- Orchestrator (`run-all`) over SSH to the operator's own servers.
- Aggregation with anomaly detection (HTTP≠200, TCP≠open, latency>2000ms).
- systemd **user** units (probe/audit timers) + linger-based persistence.
- Targets split into a separate private `targets.toml` (git-ignored); the code
  ships no hardcoded hosts.
- CI matrix (ubuntu + macos): fmt / clippy / test / build / native aarch64.
- GPL-3.0 license.

### Security

- Allowlist-only measurement; passive checks only; built-in rate-limit;
  minimal logs (no telemetry/credentials). Layer 3 (active probing) forbidden.
