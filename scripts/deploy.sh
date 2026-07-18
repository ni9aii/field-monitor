#!/usr/bin/env bash
# deploy.sh — CI/CD: build + orchestrated deployment of field-monitor to all servers.
# The binary + systemd user-units + config are copied to each server, and the
# user systemd timer is activated (monitoring every 1 hour / audit every 6 h).
# Requires no root on the servers (user systemd + loginctl enable-linger).
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=target/release/field-monitor
[ -x "$BIN" ] || { echo "building release..."; cargo build --release; }
echo "=== deploy field-monitor ($(date -u +%Y-%m-%dT%H:%M:%SZ)) ==="

# Server list comes from the binary itself (it already parses config.toml).
# Format: ip|name|key|port|user
"$BIN" list-servers | while IFS='|' read -r ip name key port user; do
  [ -z "$ip" ] && continue
  user="${user:-$USER}"
  echo ">>> $name ($ip)"
  ssh -i "$key" -p "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
    "$user@$ip" "mkdir -p ~/.local/bin ~/.config/systemd/user ~/.local/share/field-monitor" </dev/null 2>&1 || true
  scp -i "$key" -P "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -q \
    "$BIN" "$user@$ip:~/.local/bin/field-monitor" </dev/null 2>&1 || true
  # Use local config if project config doesn't exist
  CONFIG_SRC="config.toml"
  [ ! -f "$CONFIG_SRC" ] && CONFIG_SRC="$HOME/.config/field-monitor.toml"
  scp -i "$key" -P "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -q \
    "$CONFIG_SRC" "$user@$ip:~/.config/field-monitor.toml" </dev/null 2>&1 || true
  for u in systemd/field-monitor-probe.service systemd/field-monitor-probe.timer \
           systemd/field-monitor-audit.service systemd/field-monitor-audit.timer \
           systemd/field-monitor-report.service systemd/field-monitor-report.timer; do
    scp -i "$key" -P "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -q \
      "$u" "$user@$ip:~/.config/systemd/user/" </dev/null 2>&1 || true
  done
  ssh -i "$key" -p "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
    "$user@$ip" "loginctl enable-linger \$USER && systemctl --user daemon-reload && systemctl --user enable --now field-monitor-probe.timer field-monitor-audit.timer field-monitor-report.timer && echo 'deployed'" </dev/null 2>&1 || true
done
echo "=== done ==="