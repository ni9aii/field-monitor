# Configuration Reference

`field-monitor` reads two private TOML files (both git-ignored). The code
ships **no** hardcoded hosts — see `src/model.rs`.

| File | Purpose | Tracked? |
|------|---------|----------|
| `config.toml` | Servers + global rate-limit | No (git-ignored) |
| `targets.toml` | Allowlist of endpoints to measure | No (git-ignored) |
| `.env` | Env overrides / secrets | No (git-ignored) |

Templates: `config.example.toml`, `targets.example.toml`, `.env.example`.

## config.toml

```toml
# Global rate-limit: at most 1 measurement per target per N seconds.
min_interval_sec = 300

# One [[servers]] block per host you operate.
[[servers]]
ip   = "YOUR_SERVER_IP"          # public IP of the host
name = "server-1"                # label used in logs
key  = "/home/YOUR_USER/.ssh/id_your_key"   # SSH private key (local path)
user = "YOUR_USER"               # SSH user on the host
port = 22                        # SSH port (default 22)

# ARM64 SBC example — set arch so the orchestrator picks the right binary.
[[servers]]
ip   = "YOUR_SERVER_IP_2"
name = "arm-node-1"
key  = "/home/YOUR_USER/.ssh/id_your_key"
user = "YOUR_USER"
port = 22
arch = "aarch64"                 # "x86_64" (default) or "aarch64"
```

### Server fields

| Field | Required | Default | Notes |
|-------|----------|---------|-------|
| `ip` | yes | — | Public IP of the host |
| `name` | yes | — | Label for logs |
| `key` | yes | — | Local path to SSH private key |
| `user` | yes | — | SSH user on the host |
| `port` | no | `22` | SSH port |
| `arch` | no | `"x86_64"` | `"x86_64"` or `"aarch64"` |

## targets.toml

```toml
# Each target: a name + either (host + url) for HTTPS/DNS, or ip for raw ICMP/TCP.
[[targets]]
name = "example"
host = "example.com"
url  = "https://example.com"
ip   = ""

[[targets]]
name = "example-api"
host = "api.example.com"
url  = "https://api.example.com"
ip   = ""
```

### Target fields

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | Label |
| `host` | one of host/url/ip | DNS name for resolve + HTTPS |
| `url`  | one of host/url/ip | HTTPS check URL |
| `ip`   | one of host/url/ip | Raw ICMP/TCP target (host/url empty) |

At least one of `host` / `url` / `ip` must be set. The agent refuses anything
outside this list (`Target::is_safe` sanitizes, but the allowlist itself is
the boundary).

## Environment variables

| Var | Purpose |
|-----|---------|
| `FIELD_MONITOR_CONFIG` | Override path to `config.toml` |
| `FIELD_MONITOR_TARGETS` | Override path to `targets.toml` |
| `FIELD_PROBE_IP` | The server's public IP (for local `probe` / `audit`) |
| `CORRO_API_URL` | Reference measurement API for Layer 2 (operator-configured) |
| `CORRO_CC` | Country code for cross-check (operator-configured) |
| `CORRO_API_TOKEN` | Only if the reference API requires auth |
| `SSH_KEY_PASSPHRASE` | Only if your SSH key is passphrase-protected |
| `FIELD_MONITOR_JSON` | If set, `corroborate` / `aggregate` emit JSON |

Secrets (API tokens, key passphrases) belong in `.env` — never in
`config.toml` or the repo.
