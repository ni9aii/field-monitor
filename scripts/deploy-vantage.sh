#!/usr/bin/env bash
#
# deploy.sh — build field-monitor and roll it out to all vantage points.
#
# What it does (idempotent, safe to re-run):
#   1. cargo build --release (x86_64) from the source tree
#   2. cargo build --release for aarch64 (cross, if needed) — linker
#      aarch64-linux-gnu-gcc, configured via .cargo/config.toml in the source tree
#   3. for each host: upload binary + targets.toml (cat-pipe over ssh, because
#      plain scp INSIDE a nested ssh over a relay does NOT reach the target),
#      rewrite the systemd unit with FIELD_PROBE_IP/NAME, daemon-reload,
#      and restart the timer (timers hang after daemon-reload — must restart).
#
# Prereqs:
#   - field-monitor source checked out (see $SRC below)
#   - SSH keys available: $KEY_DIRECT for direct+relay hops, $KEY_RELAY for
#     the ARM64 host (if any)
#   - local targets.toml (git-ignored) with the target allowlist; an example
#     is provided as targets.toml.example
#
# EDIT THE VARIABLES BELOW before running — they are placeholders, not real
# infrastructure. No real IPs, hostnames, or usernames are committed to the
# repo.
#
# Host map: "ip name key relay" — relay empty for direct hosts.
#
set -u

# ─── Fill these in for YOUR deployment (do NOT commit real values) ──────────
DEPLOY_USER="your-user"                 # SSH user on the vantage points
KEY_DIRECT="$HOME/.ssh/id_ed25519"      # key for direct + relay hops
KEY_RELAY="$HOME/.ssh/id_ed25519"        # key for the ARM64 host (if any)
SRC="$HOME/code/field-monitor"           # path to the source tree
TARGETS="${TARGETS_TOML:-$HOME/.config/field-monitor/targets.toml}"

# ip            name    key           relay(ip or empty)
HOSTS=(
  "$VP01_IP vp-01 $KEY_DIRECT ''"
  "$VP02_IP vp-02 $KEY_DIRECT $VP01_IP"
  "$VP03_IP vp-03 $KEY_DIRECT ''"
  "$VP04_IP vp-04 $KEY_DIRECT $VP03_IP"
  "$VP05_IP vp-05 $KEY_DIRECT ''"
  "$VP06_IP vp-06 $KEY_DIRECT $VP01_IP"
  "$VP07_IP vp-07 $KEY_DIRECT ''"
  "$VP08_IP vp-08 $KEY_DIRECT ''"
  "$VP09_IP vp-09 $KEY_DIRECT ''"
  "$VP10_IP vp-10 $KEY_DIRECT ''"
  "$VP11_IP vp-11 $KEY_DIRECT $VP01_IP"
  "$VP12_IP vp-12 $KEY_RELAY   ''"
)
# ─────────────────────────────────────────────────────────────────────────────

echo "==> building x86_64 release"
( cd "$SRC" && cargo build --release ) || { echo "x86_64 build failed"; exit 1; }
BIN_X86="$SRC/target/release/field-monitor"

# aarch64 only if an ARM64 host is in the map; build once
echo "==> building aarch64 release (cross)"
( cd "$SRC" && cargo build --release --target aarch64-unknown-linux-gnu ) || { echo "aarch64 build failed"; exit 1; }
BIN_ARM="$SRC/target/aarch64-unknown-linux-gnu/release/field-monitor"

[ -f "$TARGETS" ] || { echo "targets.toml not found at $TARGETS (see targets.toml.example)"; exit 1; }

ssh_base() {
  # $1=ip $2=key $3=relay
  if [ -n "$3" ]; then
    echo "ssh -F /dev/null -i $2 -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $DEPLOY_USER@$3 ssh -i $2 -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $DEPLOY_USER@$1"
  else
    echo "ssh -F /dev/null -i $2 -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 $DEPLOY_USER@$1"
  fi
}

for entry in "${HOSTS[@]}"; do
  read -r ip name key relay <<<"$entry"
  bin="$BIN_X86"; [ "$name" = "vp-12" ] && bin="$BIN_ARM"

  echo "==> $name ($ip)"

  # upload binary via cat-pipe (works through relays; plain scp inside nested ssh does not)
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$DEPLOY_USER@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $DEPLOY_USER@$ip 'cat > ~/.local/bin/field-monitor'" < "$bin" \
      && echo "    binary uploaded (relay)"
  else
    cat "$bin" | ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "$DEPLOY_USER@$ip" 'cat > ~/.local/bin/field-monitor' \
      && echo "    binary uploaded"
  fi

  # upload targets.toml
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$DEPLOY_USER@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $DEPLOY_USER@$ip 'cat > ~/targets.toml'" < "$TARGETS" \
      && echo "    targets.toml uploaded (relay)"
  else
    cat "$TARGETS" | ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "$DEPLOY_USER@$ip" 'cat > ~/targets.toml' \
      && echo "    targets.toml uploaded"
  fi

  # rewrite unit with FIELD_PROBE_IP/NAME, daemon-reload, restart timer
  unit="[Unit]
Description=field-monitor passive reachability probe (user)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=FIELD_PROBE_IP=$ip
Environment=FIELD_PROBE_NAME=$name
ExecStart=%h/.local/bin/field-monitor probe
StandardOutput=append:%h/.local/share/field-monitor/probe.log
StandardError=append:%h/.local/share/field-monitor/probe.log

[Install]
WantedBy=multi-user.target"

  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$DEPLOY_USER@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $DEPLOY_USER@$ip 'cat > ~/.config/systemd/user/field-monitor-probe.service'" <<<"$unit"
  else
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "$DEPLOY_USER@$ip" 'cat > ~/.config/systemd/user/field-monitor-probe.service' <<<"$unit"
  fi

  inner="systemctl --user daemon-reload && systemctl --user restart field-monitor-probe.timer"
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$DEPLOY_USER@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $DEPLOY_USER@$ip '$inner'" >/dev/null 2>&1
  else
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "$DEPLOY_USER@$ip" "$inner" >/dev/null 2>&1
  fi
  echo "    unit rewritten, daemon-reload + timer restart done"
done

echo "==> deploy complete"
