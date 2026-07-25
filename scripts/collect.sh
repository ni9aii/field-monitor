#!/usr/bin/env bash
# collect.sh — pull monitoring logs from the servers and aggregate locally.
set -euo pipefail
cd "$(dirname "$0")/.."
export RESULTS_DIR="${RESULTS_DIR:-$HOME/.local/share/field-monitor}"
mkdir -p "$RESULTS_DIR"

# Clean old per-server logs before collecting fresh ones. Excludes
# report.log: when this script runs under field-monitor-report.service,
# systemd redirects this very process's stdout/stderr there, so a bare
# *.log glob would unlink the file this process is actively writing to
# (the data survives until exit via the open fd, then vanishes with it —
# report.log never persists).
find "$RESULTS_DIR" -maxdepth 1 -name '*.log' ! -name 'report.log' -delete

BIN=target/release/field-monitor
echo "=== collect ($(date -u +%Y-%m-%dT%H:%M:%SZ)) ==="

CONFIG_PATH="${FIELD_MONITOR_CONFIG:-config.toml}"
key_for_ip() {
  python3 -c "
import sys, tomllib
with open('$CONFIG_PATH', 'rb') as f:
    cfg = tomllib.load(f)
for s in cfg.get('servers', []):
    if s.get('ip') == sys.argv[1]:
        print(s.get('key', ''))
        break
" "$1"
}

"$BIN" list-servers | while IFS='|' read -r ip name _key_redacted port user; do
  [ -z "$ip" ] && continue
  user="${user:-$USER}"
  key="$(key_for_ip "$ip")"
  [ -z "$key" ] && { echo "    (no key found for $ip, skipping)"; continue; }
  echo ">>> $name ($ip)"
  timeout 10 scp -i "$key" -P "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -q \
    "$user@$ip:~/.local/share/field-monitor/probe.log" "$RESULTS_DIR/$name.log" 2>/dev/null || \
    echo "    (no log / offline)"
done

echo "=== aggregate ==="
FIELD_MONITOR_MD="$RESULTS_DIR/report.md" "$BIN" aggregate