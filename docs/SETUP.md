# Setup & Deployment

This guide covers production deployment: building the agent, pushing it to
your servers, and running it as a systemd **user** service (no root needed).

> Operational notes, fleet topology, and sizing tips also live in the
> [Deployment notes](https://github.com/ni9aii/field-monitor/wiki/Deployment-notes)
> on the wiki. This file is the canonical, versioned reference; the wiki page
> is the living companion.

## Prerequisites (on every target host)

- A non-root user with SSH access (key-based).
- System tools the agent wraps: `curl`, `dig` (bind-tools / dnsutils),
  `ping` (iputils-ping). (TCP:443 checks use a native Rust socket — `python3`
  is no longer required.)
- For the read-only audit: the user must be able to read `/etc/ssh/sshd_config`
  and run `systemctl status` (no sudo required for the audit itself).
- `loginctl enable-linger <user>` so timers survive without an open session.

## 1. Build

```bash
cargo build --release
# binary: target/release/field-monitor
```

### Cross-architecture (aarch64 / ARM64 SBC)

The agent is built **natively** for aarch64 — no cross-linker hacks. CI does
this in an `arm64v8/rust:1-bookworm` container under QEMU. Locally, build on
the target itself, or in a matching container:

```bash
docker run --rm --platform linux/arm64 -v "$PWD":/src -w /src \
  arm64v8/rust:1-bookworm \
  bash -c "apt-get update && apt-get install -y libssl-dev && cargo build --release"
```

The static build flag (see `.cargo/config.toml`) links musl/glibc statically
so the binary runs on the SBC without a matching toolchain.

## 2. Configure

Create two private files (both git-ignored):

- `config.toml` — your servers + global rate-limit. Copy from
  `config.example.toml`.
- `targets.toml` — your allowlist of endpoints to measure. Copy from
  `targets.example.toml`.

See [CONFIG.md](CONFIG.md) for the full schema.

## 3. Deploy (push binary + units to all servers)

```bash
./scripts/deploy.sh
```

`deploy.sh` reads servers from `config.toml` (via `list-servers`) and, for
each host:

1. `scp`s the built binary to `~/.local/bin/field-monitor`.
2. Installs the systemd **user** units (`*.service` + `*.timer`).
3. Copies `config.toml` to `~/.config/field-monitor.toml`.
4. Reloads and enables the timers:
   - `field-monitor-probe.timer` — probe every 15 min
   - `field-monitor-audit.timer` — read-only audit every 6 h

No root on the servers — only your SSH user.

## 4. Collect & aggregate

```bash
./scripts/collect.sh          # pull *.log from all servers → results/
./target/release/field-monitor aggregate   # print summary
```

Logs live at `~/.local/share/field-monitor/*.log` on each server.

## 5. Enable linger

On each server (once):

```bash
sudo loginctl enable-linger "$USER"
```

This keeps the user manager alive after logout, so the timers keep firing.

## Local machine

Run the same probe timer locally as a user-systemd unit — identical to the
servers. The agent measures from your machine's own IP.

## Updating

Bump the binary with `deploy.sh` again; it overwrites `~/.local/bin/`
and restarts the probe service. Config/units only change when you edit them.
