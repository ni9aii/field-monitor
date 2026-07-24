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

# Server list: ip|name|port|user comes from the binary (list-servers redacts
# the key path by design — see CHANGELOG "restore SSH key path redaction").
# The real key path is looked up locally from config.toml by ip, since these
# scripts (unlike the binary's stdout) never get logged/shared.
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
  [ -z "$key" ] && { echo "!!! no key found for $ip in $CONFIG_PATH, skipping"; continue; }
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
  # Targets (allowlist) are a separate private file; deploy it alongside
  # config.toml so the remote probe.service (FIELD_MONITOR_TARGETS) finds it.
  TARGETS_SRC="targets.toml"
  if [ -f "$TARGETS_SRC" ]; then
    scp -i "$key" -P "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -q \
      "$TARGETS_SRC" "$user@$ip:~/.config/field-monitor-targets.toml" </dev/null 2>&1 || true
  fi
  # report.timer runs collect-and-report.sh, which needs the repo checked
  # out and pulls FROM the servers below — it belongs on the orchestrator
  # (this machine) only, never on a probed server.
  for u in systemd/field-monitor-probe.service systemd/field-monitor-probe.timer \
           systemd/field-monitor-audit.service systemd/field-monitor-audit.timer; do
    scp -i "$key" -P "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -q \
      "$u" "$user@$ip:~/.config/systemd/user/" </dev/null 2>&1 || true
  done
  ssh -i "$key" -p "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
    "$user@$ip" "loginctl enable-linger \$USER && systemctl --user daemon-reload && systemctl --user enable --now field-monitor-probe.timer field-monitor-audit.timer && echo 'deployed'" </dev/null 2>&1 || true
done
echo "=== done ==="