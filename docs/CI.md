# CI / CD

## CI (GitHub Actions)

Workflow: `.github/workflows/ci.yml`. Runs on every push and PR.

### Jobs

| Job | OS | What it does |
|-----|----|--------------|
| `fmt` | ubuntu + macos | `cargo fmt --check` |
| `clippy` | ubuntu + macos | `cargo clippy -D warnings` |
| `test` | ubuntu + macos | `cargo test --release` |
| `build` | ubuntu + macos | `cargo build --release` |
| `native-aarch64` | ubuntu (QEMU) | native build in `arm64v8/rust:1-bookworm` |

### Why a native aarch64 container

Cross-compilation to aarch64 needs a matching linker/glibc; instead of
installing a cross-toolchain we run the build **natively** inside an
`arm64v8/rust:1-bookworm` image via `docker/setup-qemu-action`. The produced
binary links against the same glibc as Debian bookworm and runs on an ARM64
SBC out of the box. The artifact `field-monitor-aarch64` is uploaded.

### Privacy-friendly

CI has **no** access to `config.toml` / `targets.toml` / `.env` (all
git-ignored) and uses no secrets. Tests use placeholder targets
(`example.com`) and placeholder server IPs (`YOUR_SERVER_IP`) — no real
infrastructure is ever referenced.

### Covered by tests

- `model::is_safe` — allowlist rejects foreign hosts; IP-only target is
  legitimate when the operator allows it.
- `model::bin_for_arch` — x86_64 returns the current binary; aarch64 points
  to `target/aarch64-unknown-linux-gnu/release/field-monitor`.
- `aggregate::parse_audit_line` — correct parse and rejection of a short line.
- `aggregate::summarize` — anomaly detection (HTTP≠200, TCP≠open,
  latency > 2000ms).
- `aggregate::load_probe_logs` — parsing the `run-all` output format
  (`[N] IP -> target,...`).

## CD (operator-local)

Deployment is **not** automated in CI — it runs from the operator's machine
via `scripts/deploy.sh` (see [SETUP.md](SETUP.md)). This keeps server access
out of the public pipeline entirely.
