# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.3] - 2026-07-30

### Changed

- **Bundled `is_safe()` allowlist sanitizer fixes** (subdomain hosts like
  subdomain hosts are now correctly accepted; older on-disk binaries built
  before 2026-07-19 rejected any host containing a dot-delimited subdomain
  beyond the registrable domain). Re-deploy to the fleet after upgrading.
- **Targets allowlist refresh:** added two additional messenger
  allowlist groups and their host/subdomain sets, and reduced the Apple
  scope to the core three (`apple`, `appleid`, `icloud`).

## [0.4.2] - 2026-07-25

### Added

- **Vantage-point deploy:** `scripts/deploy-vantage.sh` — idempotent
  deploy of the agent + systemd units to the full vantage-point fleet,
  reading the server inventory (IPs, SSH keys, users, ports) from a
  private, git-ignored `vantage-points.env` so real infrastructure never
  enters the repo. Relay-aware: servers whose direct 9922 is filtered
  upstream are reached via a working peer.
- **Local healthcheck:** `scripts/field-monitor-healthcheck.sh` plus
  `field-monitor-healthcheck.{service,timer}` — verifies the agent is
  actually producing fresh probe logs on each host (not just that the
  unit is enabled), emitting a one-line OK/STALE per server.
- **Rust report generator:** `src/bin/gen-report.rs` (and `tests/gen_report.rs`)
  replaces the previous Python `gen_report.py` — native, dependency-free
  markdown/timeline/geo report from aggregated `probe.log` data, with a
  per-region topology table and an apple-scope report template
  (`templates/apple-report-template.md`).
- `vantage-points.example.env`, `targets.apple-example.toml` shipped as
  templates (no real values).

### Changed

- `src/aggregate.rs` extended with a per-region/geo section, timeline
  windowing, and the apple-only reporting scope.
- `src/probe.rs`, `src/model.rs`, `src/main.rs`, `src/runner.rs`,
  `src/ssh.rs`, `src/corroborate.rs`, `src/logfmt.rs`, `src/audit.rs`
  refactored to support the new report fields and the vantage-point
  deploy workflow.
- `field-monitor-report.service` / `field-monitor-report.timer` added to
  the orchestrator's per-server unit list; `field-monitor-probe.timer`
  cadence adjusted.

## [0.4.1] - 2026-07-25

### Fixed

- **Deploy/collect scripts:** `list-servers` deliberately redacts the SSH
  key path (security hardening, see 0.4.0 below), but `deploy.sh`/
  `collect.sh` were still reading the key from that redacted output and
  passing the literal `<redacted>` to `ssh`/`scp -i`, breaking deployment.
  Both scripts now resolve the real key path locally from `config.toml`.
- **Deploy:** `field-monitor-report.timer`/`.service` were being pushed to
  every probed server, not just the orchestrator. `collect-and-report.sh`
  only makes sense on the machine holding the repo checkout that pulls logs
  from the fleet; removed from the per-server unit list in `deploy.sh`.
- **Deploy:** `field-monitor-probe.service` never set
  `FIELD_MONITOR_CONFIG`/`FIELD_MONITOR_TARGETS`, so the deployed
  `~/.config/field-monitor.toml` was never read on the remote host and
  probes silently measured zero targets. Added the env vars to the unit;
  `deploy.sh` now also ships `targets.toml` to each server.
- **Probe:** `tcp_check` only tried the first address a hostname resolved
  to. Anycast/CDN targets (e.g. Google, Apple, GitHub) commonly resolve to
  several IPs, and one being unreachable from a given vantage point doesn't
  mean the target is down — this produced rows where HTTPS succeeded but
  TCP:443 falsely read `closed` on the same row. Now tries up to 6 resolved
  addresses before reporting `closed`, matching the multi-address fallback
  `curl` already does for the HTTPS check.
- **Aggregate:** any HTTP response (redirects, auth-walls, etc.) now counts
  as reachable — only `https_code == 0` (curl couldn't connect at all /
  timed out) is a failure. Previously any non-200 status was flagged
  `HTTPS_FAIL`, which drowned real anomalies in noise for targets that
  legitimately redirect or gate on auth.

### Changed

- HTTPS `HIGH_LATENCY`/`SLOW` threshold lowered from 2000ms to 800ms
  (`HTTPS_HIGH_LATENCY_MS`); the DNS latency threshold (2000ms) is unchanged.


## [0.4.0] - 2026-07-22

### Added

- **Probe format:** `ProbeRow`/`emit_probe_row`/`parse_probe_line` gain a
  trailing `ts` (unix seconds) field recording when each measurement was
  taken. Older 10/11-field probe lines without it still parse (`ts` defaults
  to `0`).
- **Aggregate:** `summarize()` now windows anomalies to the last hour —
  rows with a `ts` older than 3600s are skipped, so the Anomalies count and
  timeline/geo section reflect recent measurements instead of the entire
  accumulated `probe.log`. Rows with `ts == 0` (pre-rollout agents) are still
  counted, so the report stays correct while agents are upgraded.
- `scripts/collect-and-report.sh` documented in the Quick start as the
  one-shot way to pull logs from all servers and generate a report.

### Fixed

- `load_probe_logs`: a `file_type()` symlink check that failed open the
  wrong way (`unwrap_or(true)`) was skipping every real log file on
  filesystems where `file_type()` can error (e.g. btrfs), producing empty
  reports. Now defaults to "not a symlink" (`unwrap_or(false)`) instead.
- `parse_probe_line` now also accepts the newer 12-field format (with
  trailing `partial,ts`) in addition to the existing 10/11-field formats.
- **Security:** `list-servers` was briefly printing the SSH private-key path
  in plaintext instead of `<redacted>` (accidental regression from the
  `load_probe_logs` fix above); redaction restored.
- Silenced a `dead_code` warning on `logfmt::PROBE_FIELDS` that made
  `cargo clippy -D warnings` fail CI on `main`.

## [0.3.0] - 2026-07-19

### Added

- Unit tests for the SSH command-argument escaper (`sh_quote`) and for the
  stricter `Target::is_safe` sanitization (injection chars + IP validation).
- **Config:** `batch_size` (max servers probed in parallel per batch, default 4;
  `0` = unlimited). Newest `config.toml` files keep working (serde default).
- **Log format (cycle-6):** new `src/logfmt.rs` is the single source of truth
  for probe-line emit/parse (`emit_probe_row` / `parse_probe_line`) with a
  round-trip unit test, so writer and reader can no longer silently drift.
  Probe lines now carry an 11th `partial` field (1 = at least one sub-check
  failed, so the row is a partial result, not a definitive outage).
### Changed

- **Security:** `probe::tcp_check` now uses a native Rust `TcpStream` instead
  of a `python3 -c` subprocess — eliminates a command-injection path where a
  crafted `host` could execute arbitrary Python locally.
- **Security:** `resolve_public_ip()` no longer calls a hardcoded third-party
  host (`ifconfig.me`). By default it only reads local interfaces
  (`hostname -I`); the external lookup is operator-opt-in via
  `FM_PUBLIC_IP_URL` (unset = no outbound call, preserving the "no hardcoded
  hosts / no undisclosed outbound" guarantee).
- **Security:** `Target::is_safe()` now also rejects shell metacharacters
  (whitespace, `' " $ ; | & \``), validates `ip` as IPv4/IPv6-or-empty, and
  blocks injection through the `host`/`url`/`ip` fields.
- **Security:** `ssh::run_remote` escapes `server.name`/`server.ip` when
  building the remote command (prevents shell injection from config) and adds
  SSH timeouts (`ConnectTimeout`/`ServerAlive*`) so one unresponsive server
  cannot hang the orchestrator. The uploaded binary is removed from
  `/tmp` after each run.
- **Scalability:** `run-all` now probes servers in parallel batches of 4
  (previously fully sequential) and honors `min_interval_sec` as a fleet
  rate-limit between batches, so a large fleet does not fork-bomb the
  operator host and one dead server cannot stall the rest.
- **Robustness:** `audit::listeners()` no longer panics on short `ss` output
  lines (`&parts[0][..3]` → safe slice).
- **Privacy:** `list-servers` no longer prints the private key path (redacted
  to `<redacted>`).
- **Correctness:** `corroborate` now percent-encodes the target URL when
  querying the reference API (prevents `&`/`#`/`?` from breaking the query),
  and the no-API fallback reports `ref_anomaly = "False"` (was the
  non-contractual string `"no-api-url"`).
- **Audit accuracy:** `audit` now prefers `sshd -T` (effective config) when
  run with privileges, so `Include`/`Match` blocks are honored; falls back to
  parsing `/etc/ssh/sshd_config` when `sshd -T` is unavailable.
- **Report correctness:** the markdown report now distinguishes a real
  success (`OK`) from "could not measure" (`NOT MEASURED`) instead of always
  labelling unmeasured rows `OK`.
- **Docs:** SETUP documents log rotation (`logrotate`/`journald`) for the
  per-server `probe.log`, which the agent does not rotate itself.
- **Parsing:** `parse_audit_line` splits into at most 11 fields so a `ports`
  value containing `|` is no longer silently truncated.
- **Anomaly detection:** `summarize` now also flags slow DNS resolution
  (`dns_ms > 2000`) as an anomaly, alongside HTTPS status/latency and TCP.
- **Security (cycle-5 findings):**
  - `Target::is_safe` now also rejects injection in `name` (`,`/`|`/control
    chars) — previously `name` bypassed the sanitizer and could corrupt the
    CSV/AUDIT emit lines.
  - `generate_markdown_report` refuses to write through a symlink at the report
    path, and skips archiving a symlinked report (prevents arbitrary-file
    overwrite / TOCTOU).
  - `load_probe_logs` skips symlinked `.log` entries (no read-through of a
    planted link).
  - `effective_sshd_value` invokes `sudo -n <abs-path>/sshd -T` with an
    absolute path from a fixed set of trusted locations, removing a
    PATH-hijack privilege-escalation vector.
  - `corroborate` now `url_encode`s `CORRO_CC` like the `input` value.
- **Config:** `batch_size` is now configurable (see Added); the previously
  hardcoded parallelism of 4 is the default.
- **Orchestrator (cycle-6):** `run_remote` now uploads the binary once per
  server (for the `probe` subcommand) and reuses it for `audit`, instead of
  scp-ing twice — roughly halves fleet-wide SSH traffic per run-all.
- **Resilience (cycle-6):** `ProbeRow.partial` marks rows where every sub-check
  failed to run (vantage couldn't measure, not "target is dead"), so the report
  can distinguish a real outage from a measurement failure.
- **Testability (cycle-7):** new `src/runner.rs` with a `CommandRunner` trait
  and `RealRunner` default; `probe::dns_resolve`/`https_check`/`run_with` take
  `&dyn CommandRunner`, so they are now unit-tested with an in-memory
  `MockRunner` (no real network/filesystem). Closes the last architecture
  review finding (modules with hardcoded `Command` were not mockable).

## [0.2.0] - 2026-07-19

### Added

- `docs/` with detailed guides: SETUP, CONFIG, ARCHITECTURE, CI, LEGITIMACY.
- Configurable probe timeouts via environment variables:
  `FM_DNS_TIMEOUT`, `FM_HTTPS_TIMEOUT`, `FM_TCP_TIMEOUT`,
  `FM_PING_COUNT`, `FM_PING_TIMEOUT`.
- Unit tests for probe module (parse_curl_code, timeout_env helpers).

### Changed

- `AUTH.md` moved to `docs/LEGITIMACY.md`.
- All source comments unified to English with Doxygen-style doc-comments;
  user-facing CLI output translated to English.
- CI actions modernized: Node 24, `checkout@v5`, `Swatinem/rust-cache@v2`.
- **Fixes from AutoDev Review:**
  - Fixed `trim_matches('\')` to `trim()` in `parse_audit_line`.
  - Added defensive bounds checks using `.first()` and `.get().map()`.
  - Changed Snyk security scan from weekly to daily schedule.

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