# field-monitor

[![CI](https://github.com/ni9aii/field-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/ni9aii/field-monitor/actions/workflows/ci.yml)

![field-monitor](https://raw.githubusercontent.com/ni9aii/field-monitor/main/logo.gif)

_Terminal demo of field-monitor measuring public endpoints from multiple vantage points_

**Passive reachability monitoring of operator-defined public endpoints from
your own servers, plus a read-only security audit. Written in Rust.**

`field-monitor` answers one question: *are the public services I depend on
reachable from my own infrastructure, and do my servers look healthy?* It
does this without touching third-party hosts and without running anyone
else's agents.

## Why this exists

Most uptime monitors are SaaS: you hand a vendor your endpoints and trust
their vantage points. `field-monitor` is the opposite — **self-hosted and
self-owned**. You run lightweight agents on servers you control; each agent
measures only the targets *you* allowlist and audits *its own* SSH/OS
hygiene. The result is a private, tamper-resistant view from your own
network vantage points.

## Legitimacy by design

- **Your infrastructure only** — agents run on servers you own (VPS, ARM64
  SBC, your workstation).
- **Allowlist-limited** — the agent refuses to measure anything outside the
  operator-defined target list (kept in a separate private file, never in
  this repo).
- **Passive only** — plain `curl` / `dig` / `ping` from the server's own IP.
  No spoofing, no proxies, no circumvention, no scanning of third parties.
- **Rate-limited** — one measurement per target per 5 minutes by default.
- **Minimal logs** — timestamps, status codes, latencies. No telemetry,
  no credentials.
- **Public methodology** — the approach is documented in `docs/LEGITIMACY.md`
  and `docs/`. Transparency over obscurity.

See [docs/LEGITIMACY.md](docs/LEGITIMACY.md) for the operator boundary and
why Layer 3 (active probing) is explicitly out of scope.

## Quick start

```bash
cargo build --release
# binary: target/release/field-monitor
```

```bash
# 1. Define YOUR servers (private, git-ignored)
cp config.example.toml config.toml
# 2. Define YOUR targets  (private, git-ignored)
cp targets.example.toml targets.toml
# 3. Measure from a server
FIELD_PROBE_IP=YOUR_SERVER_IP ./target/release/field-monitor probe
# 4. Read-only security audit of that server
FIELD_PROBE_IP=YOUR_SERVER_IP ./target/release/field-monitor audit
# 5. Optional: cross-check against a public reference API
./target/release/field-monitor corroborate
# 6. Generate markdown report (latest per target, anomalies only)
FIELD_MONITOR_MD=/path/to/report.md ./target/release/field-monitor aggregate
```

For production deployment (systemd user-units, multi-server orchestration,
aarch64 builds) see [docs/SETUP.md](docs/SETUP.md).
For the full configuration reference see [docs/CONFIG.md](docs/CONFIG.md).

## What it is not

`field-monitor` is **not** a scanner, a circumvention tool, or a way to
measure hosts you don't operate. It is a monitoring instrument for your own
vantage points.

## Status

Layer 1 (probe + audit) and Layer 2 (optional corroboration) are implemented
and covered by tests + CI. Cross-architecture builds (x86_64 / aarch64) are
verified in CI.

## License

GNU GPL v3.0 — see [LICENSE](LICENSE). Copyleft: derivatives must stay open.
