# Legitimacy & Operator Boundary

## Who operates it

`field-monitor` is run by the **owner of the infrastructure** on their own
servers (the list lives in `config.toml`). The servers belong to the operator;
access is via the operator's own SSH keys.

## What the project does NOT do (by design)

- **Does NOT** scan third-party hosts (only the operator's own servers from the allowlist).
- **Does NOT** intercept third-party traffic.
- **Does NOT** circumvent blocking in the agent (no spoofing, no Tor, no
  proxy chains to hide the source).
- **Does NOT** generate load (built-in rate-limit).

## What the project does

1. **Passive reachability** of public endpoints the operator is a user of,
   from the operator's own vantage points. Same class as any uptime monitor,
   but self-hosted and self-owned.
2. **Read-only security audit** of the operator's own servers (SSH hygiene, OS,
   auto-updates, listeners, fail2ban, docker) — without changing configuration.

The specific endpoints and the set of servers are **operator-defined** and
live only in the private `config.toml` (git-ignored). This repository
ships no list of what is measured or where.

## Hard guardrails in code

| Guard | Where | Meaning |
|-------|-------|---------|
| Target allowlist | `model.rs::Target::is_safe` | agent refuses to measure outside the list |
| Rate-limit | `Config::min_interval_sec` (default 300s) | at most 1 measurement / 5 min per target |
| Passivity | `probe.rs` | plain `curl`/`dig`/`ping` from the server's own IP; no spoofing/proxy |
| Minimal data | `model.rs` | logs only timestamps/codes/latencies, no telemetry/credentials |
| Public methodology | this file + README | transparency over obscurity |

## Architecture boundaries

This project is **not** a blocking-circumvention tool and does **not**
replicate active probing datasets.

- **Layer 1 — Passive Reachability** (implemented): passive reachability of
  public endpoints from the server's own IP. No spoofing/proxy/circumvention.
- **Layer 2 — Corroboration** (implemented): optionally cross-checking the
  operator's measurements with a **public reference measurement API** — read-only
  (GET), without running third-party agents on the operator's servers.
  The API endpoint and country code are operator-configured (env), not hardcoded.
- **Layer 3 — Active Probing is FORBIDDEN** in this project (legal risk):
  no DPI tests, SNI-spin, or generation of circumvention/provocative traffic.
  If ever needed — only a separate, explicitly-labeled repository, never mixed
  with Layer 1.

## Privacy

- The **code and methodology are public** (this file + README) to demonstrate
  legitimacy: only own infrastructure, passive checks, allowlist, rate-limit.
- Raw **results are not published**: no public dashboard, no upload to external
  datasets. They stay in local repos + local logs.
