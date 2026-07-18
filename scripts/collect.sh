#!/usr/bin/env bash
# collect.sh — pull monitoring logs from the servers and aggregate locally.
# Complements deploy.sh: servers write to ~/.local/share/field-monitor/{probe.log,report.md},
# we pull them into RESULTS_DIR and build the summary.
set -euo pipefail
cd "$(dirname "$0")/.."
export RESULTS_DIR="${RESULTS_DIR:-$HOME/.local/share/field-monitor}"
mkdir -p "$RESULTS_DIR"
BIN=target/release/field-monitor
echo "=== collect ($(date -u +%Y-%m-%dT%H:%M:%SZ)) ==="

"$BIN" list-servers | while IFS='|' read -r ip name key port user; do
  [ -z "$ip" ] && continue
  user="${user:-$USER}"
  echo ">>> $name ($ip)"
  timeout 10 scp -i "$key" -P "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -q \
    "$user@$ip:~/.local/share/field-monitor/probe.log" "$RESULTS_DIR/$name.log" 2>/dev/null || \
    echo "    (no log / offline)"
done

echo "=== aggregate ==="
FIELD_MONITOR_MD="$RESULTS_DIR/report.md" "$BIN" aggregate