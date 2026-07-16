# Contributing

Thanks for your interest in `field-monitor`.

## Scope

This is a **legitimacy-first** tool: passive monitoring of operator-owned
infrastructure, allowlist-only targets, no circumvention, no active probing.
Contributions must stay within that boundary. PRs that add proxying, traffic
alteration, or measurement of hosts the operator did not explicitly list will
not be accepted.

## Development

```bash
cargo build --release
# copy the examples, fill YOUR_* placeholders with YOUR OWN infra
cp config.example.toml config.toml
cp targets.example.toml targets.toml
./target/release/field-monitor list-servers
```

## Before opening a PR

- `cargo fmt --check` is clean.
- `cargo clippy --release -- -D warnings` passes (CI treats warnings as errors).
- `cargo test --release` passes.
- The integration job (CLI smoke test on example configs) passes.

## Documentation

- Canonical, versioned docs live in `docs/`. Keep them in sync with code changes.
- The wiki is a living companion (FAQ / troubleshooting / deployment notes) —
  feel free to improve it.
- Keep all source comments and user-facing output in English.

## Privacy

Never commit real infrastructure data. `config.toml`, `targets.toml`, and `.env`
are git-ignored. Use `YOUR_*` placeholders in examples.
