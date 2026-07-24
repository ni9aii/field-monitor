#!/usr/bin/env bash
#
# deploy.sh — build field-monitor v0.4.0 and roll it out to all 12 vantage points.
#
# What it does (idempotent, safe to re-run):
#   1. cargo build --release (x86_64) from ../field-monitor
#   2. cargo build --release for aarch64 (cross, if needed) — linker
#      aarch64-linux-gnu-gcc, configured via .cargo/config.toml in the source tree
#   3. for each host: upload binary + targets.toml (cat-pipe over ssh, because
#      plain scp INSIDE a nested ssh over a relay does NOT reach the target),
#      rewrite the systemd unit with FIELD_PROBE_IP/NAME, daemon-reload,
#      and restart the timer (timers hang after daemon-reload — must restart).
#
# Prereqs:
#   - ../field-monitor checked out at commit 1183b0b (v0.4.0)
#   - ssh keys available: KEY_A for direct+relay hops, KEY_B for vp-perm-home
#   - local targets.toml (git-ignored) with the 14-target allowlist; an example
#     is provided as targets.toml.example
#
# Host map: "ip name key relay" — relay empty for direct hosts.
#
set -u

KEY_A="$HOME/.ssh/id_ed25519_a"
KEY_B="$HOME/.ssh/id_ed25519_b"
SRC="$HOME/code/field-monitor"
TARGETS="${TARGETS_TOML:-$HOME/.config/field-monitor/targets.toml}"

# ip  name  key  relay(ip or empty)
HOSTS=(
  "VP01_IP vp-spb2          $KEY_A ''"
  "VP12_IP   SPB           $KEY_A VP01_IP"
  "VP02_IP  vp-spb-ruvds     $KEY_A ''"
  "VP11_IP EKB          $KEY_A VP03_IP"
  "VP03_IP vp-ekb-ruvds    $KEY_A ''"
  "VP04_IP vp-mow-vladimir  $KEY_A VP01_IP"
  "VP05_IP   OMSK          $KEY_A ''"
  "VP06_IP vp-kzn-ruvds     $KEY_A ''"
  "VP07_IP vp-nsk-ruvds    $KEY_A ''"
  "VP08_IP vp-vvo-ruvds   $KEY_A ''"
  "VP09_IP vp-mow-bm-server $KEY_A ''"
  "VP10_IP   vp-perm-home     $KEY_B ''"
)

echo "==> building x86_64 release"
( cd "$SRC" && cargo build --release ) || { echo "x86_64 build failed"; exit 1; }
BIN_X86="$SRC/target/release/field-monitor"

# aarch64 only if vp-perm-home is in the map (it is); build once
echo "==> building aarch64 release (cross)"
( cd "$SRC" && cargo build --release --target aarch64-unknown-linux-gnu ) || { echo "aarch64 build failed"; exit 1; }
BIN_ARM="$SRC/target/aarch64-unknown-linux-gnu/release/field-monitor"

[ -f "$TARGETS" ] || { echo "targets.toml not found at $TARGETS (see targets.toml.example)"; exit 1; }

ssh_base() {
  # $1=ip $2=key $3=relay
  if [ -n "$3" ]; then
    echo "ssh -F /dev/null -i $2 -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 DEPLOY_USER@$3 ssh -i $2 -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 DEPLOY_USER@$1"
  else
    echo "ssh -F /dev/null -i $2 -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 DEPLOY_USER@$1"
  fi
}

for entry in "${HOSTS[@]}"; do
  read -r ip name key relay <<<"$entry"
  bin="$BIN_X86"; [ "$name" = "vp-perm-home" ] && bin="$BIN_ARM"

  echo "==> $name ($ip)"

  # upload binary via cat-pipe (works through relays; plain scp inside nested ssh does not)
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "DEPLOY_USER@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 DEPLOY_USER@$ip 'cat > ~/.local/bin/field-monitor'" < "$bin" \
      && echo "    binary uploaded (relay)"
  else
    cat "$bin" | ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "DEPLOY_USER@$ip" 'cat > ~/.local/bin/field-monitor' \
      && echo "    binary uploaded"
  fi

  # upload targets.toml
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "DEPLOY_USER@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 DEPLOY_USER@$ip 'cat > ~/targets.toml'" < "$TARGETS" \
      && echo "    targets.toml uploaded (relay)"
  else
    cat "$TARGETS" | ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "DEPLOY_USER@$ip" 'cat > ~/targets.toml' \
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
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "DEPLOY_USER@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 DEPLOY_USER@$ip 'cat > ~/.config/systemd/user/field-monitor-probe.service'" <<<"$unit"
  else
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "DEPLOY_USER@$ip" 'cat > ~/.config/systemd/user/field-monitor-probe.service' <<<"$unit"
  fi

  inner="systemctl --user daemon-reload && systemctl --user restart field-monitor-probe.timer"
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "DEPLOY_USER@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 DEPLOY_USER@$ip '$inner'" >/dev/null 2>&1
  else
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "DEPLOY_USER@$ip" "$inner" >/dev/null 2>&1
  fi
  echo "    unit rewritten, daemon-reload + timer restart done"
done

echo "==> deploy complete"
