# Architecture

`field-monitor` is built around a strict **legitimacy boundary**: the agent
only ever observes from vantage points the operator owns, only measures
targets the operator explicitly allowlisted, and never acts on third-party
hosts. The design enforces this in code, not just in docs.

## Overview

```
                         operator's laptop / controller
                                    │
                          config.toml  (servers, gitignored)
                          targets.toml (allowlist, gitignored)
                                    │
                            ┌───────┴────────┐
                            │   run-all       │  iterates servers, scp binary
                            │   (orchestrator)│  + ssh probe/audit
                            └───────┬────────┘
            ┌───────────────┬───────┴────────┬────────────────┐
            ▼               ▼                 ▼                ▼
      vantage point 1  vantage point 2   ...          vantage point N
      (your server)    (your server)                 (your server, aarch64)
            │               │                          │
     ┌──────┴──────┐  ┌──────┴──────┐           ┌──────┴──────┐
     │ probe       │  │ probe       │           │ probe       │  Layer 1a: DNS/HTTPS/TCP/ICMP
     │ audit (RO)  │  │ audit (RO)  │           │ audit (RO)  │  Layer 1b: sshd_config, units
     └──────┬──────┘  └──────┬──────┘           └──────┬──────┘
            │  ~/.local/share/field-monitor/*.log       │
            └───────────────┬───────────────────────────┘
                            ▼
                  collect.sh → controller
                            │
                   field-monitor aggregate  ──┐  anomaly: HTTP≠200 / TCP≠open /
                            │                  ├─ latency>2000ms, cross-checked
                            ▼                  │  with Layer 2
                   summary report              │
                                               ▼
                                  (optional) corroborate  Layer 2: read-only
                                  GET public reference API, compare notes
```

No broker, no shared infra: each vantage point is reached only over the
operator's own SSH keys. Layer 3 (active probing) is intentionally absent.

## Layered model

| Layer | Command | What it does | Status |
|-------|---------|--------------|--------|
| 1a | `probe` | Passive reachability from a server's own IP: DNS resolve, HTTPS status, TCP:443, ICMP. Plain `curl`/`dig`/`ping`. | implemented |
| 1b | `audit` | Read-only security audit of the **same** server (SSH hygiene, OS, open ports via `ss`/`systemctl`). No writes. | implemented |
| 2 | `corroborate` | Optional cross-check of allowlist targets against a **public reference measurement API** (read-only GET). Operator configures the endpoint via env. | implemented |
| 3 | — | Active probing / packet injection / circumvention | **forbidden** |

Layer 3 is explicitly out of scope (see ADR-001). The tool is a monitor, not
a probe attacker.

## Why targets live in a separate private file

`src/model.rs` ships **no** hardcoded hosts. The allowlist is loaded from
`targets.toml` (git-ignored). Two reasons:

1. **Privacy** — the set of measured endpoints is operator-specific and
   never published.
2. **Safety** — `Target::is_safe()` rejects injection-like and malformed
   input: no `host:port` / `host/path`, no shell metacharacters (`' " $ ; | &` \``
   or whitespace/control chars) in `host`/`url`, and `ip` must be a valid
   IPv4/IPv6 or empty. The allowlist itself is the hard boundary.
   `default_targets()` returns an empty list — the operator MUST define
   targets, the code provides none.

### Public IP discovery (no hardcoded outbound)

`resolve_public_ip()` no longer calls a fixed third-party host. By default it
only reads local interfaces (`hostname -I`). The external lookup is
operator-opt-in via `FM_PUBLIC_IP_URL` (unset = no outbound call, so no third
party learns the vantage point's IP). This keeps the "no hardcoded hosts / no
undisclosed outbound" guarantee.

### TCP:443 check is native Rust

`probe::tcp_check` opens a `std::net::TcpStream` directly — no `python3`
subprocess, so a crafted `host` value cannot inject into a `python3 -c`
string.

This means the repository is a generic monitoring framework; what it watches
is entirely your configuration.

## Module map

```
src/
  main.rs        # subcommands: probe | audit | corroborate | run-all | aggregate | list-servers
  model.rs       # types + allowlist + is_safe() sanitizer + bin_for_arch()
  probe.rs       # field_probe: DNS / HTTPS / TCP:443 / ICMP (wraps curl/dig/ping)
  audit.rs       # security_audit: read-only (sshd_config, systemctl status)
  corroborate.rs # Layer 2: optional cross-check with a public reference API (GET only)
  aggregate.rs   # summary + anomaly detection (HTTP≠200, TCP≠open, latency>2000ms)
  ssh.rs         # orchestrator: scp + ssh to the operator's own servers (run-all)
scripts/
  deploy.sh      # build + push binary + systemd user-units to all servers
  collect.sh     # pull logs from servers + aggregate
```

## Orchestration

`run-all` iterates servers from `config.toml`, `scp`s the matching binary
(`bin_for_arch` picks `aarch64-unknown-linux-gnu` for ARM hosts), runs
`probe` + `audit` over SSH, and writes logs to
`~/.local/share/field-monitor/*.log`. Everything is over the operator's own
SSH keys — no shared infra, no broker.

## Anomaly detection

`aggregate` flags a row when:

- HTTPS code ≠ 200, or
- TCP ≠ `open`, or
- DNS/HTTPS/TCP latency > 2000 ms (configurable threshold),

and cross-references Layer 2 (if enabled) to separate "my server is down"
from "the target is broadly unreachable".
