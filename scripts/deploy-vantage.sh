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
#   - ssh keys available: KEY_A for direct+relay hops, KEY_B for PERM-home
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
  "178.72.170.27 SPB2          $KEY_A ''"
  "2.59.41.170   SPB           $KEY_A 178.72.170.27"
  "194.87.210.7  SPB-ruvds     $KEY_A ''"
  "185.173.176.89 EKB          $KEY_A 85.208.208.113"
  "85.208.208.113 EKB-ruvds    $KEY_A ''"
  "45.143.138.48 MOW-vladimir  $KEY_A 178.72.170.27"
  "5.182.27.43   OMSK          $KEY_A ''"
  "46.17.248.172 KZN-ruvds     $KEY_A ''"
  "195.133.198.80 NSK-ruvds    $KEY_A ''"
  "193.238.134.134 VVO-ruvds   $KEY_A ''"
  "185.184.128.1 MOW-bm-server $KEY_A ''"
  "62.16.40.82   PERM-home     $KEY_B ''"
)

echo "==> building x86_64 release"
( cd "$SRC" && cargo build --release ) || { echo "x86_64 build failed"; exit 1; }
BIN_X86="$SRC/target/release/field-monitor"

# aarch64 only if PERM-home is in the map (it is); build once
echo "==> building aarch64 release (cross)"
( cd "$SRC" && cargo build --release --target aarch64-unknown-linux-gnu ) || { echo "aarch64 build failed"; exit 1; }
BIN_ARM="$SRC/target/aarch64-unknown-linux-gnu/release/field-monitor"

[ -f "$TARGETS" ] || { echo "targets.toml not found at $TARGETS (see targets.toml.example)"; exit 1; }

ssh_base() {
  # $1=ip $2=key $3=relay
  if [ -n "$3" ]; then
    echo "ssh -F /dev/null -i $2 -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ni9aii@$3 ssh -i $2 -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ni9aii@$1"
  else
    echo "ssh -F /dev/null -i $2 -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 ni9aii@$1"
  fi
}

for entry in "${HOSTS[@]}"; do
  read -r ip name key relay <<<"$entry"
  bin="$BIN_X86"; [ "$name" = "PERM-home" ] && bin="$BIN_ARM"

  echo "==> $name ($ip)"

  # upload binary via cat-pipe (works through relays; plain scp inside nested ssh does not)
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "ni9aii@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ni9aii@$ip 'cat > ~/.local/bin/field-monitor'" < "$bin" \
      && echo "    binary uploaded (relay)"
  else
    cat "$bin" | ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "ni9aii@$ip" 'cat > ~/.local/bin/field-monitor' \
      && echo "    binary uploaded"
  fi

  # upload targets.toml
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "ni9aii@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ni9aii@$ip 'cat > ~/targets.toml'" < "$TARGETS" \
      && echo "    targets.toml uploaded (relay)"
  else
    cat "$TARGETS" | ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "ni9aii@$ip" 'cat > ~/targets.toml' \
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
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "ni9aii@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ni9aii@$ip 'cat > ~/.config/systemd/user/field-monitor-probe.service'" <<<"$unit"
  else
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "ni9aii@$ip" 'cat > ~/.config/systemd/user/field-monitor-probe.service' <<<"$unit"
  fi

  inner="systemctl --user daemon-reload && systemctl --user restart field-monitor-probe.timer"
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "ni9aii@$relay" \
      "ssh -i $key -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ni9aii@$ip '$inner'" >/dev/null 2>&1
  else
    ssh -F /dev/null -i "$key" -p 9922 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "ni9aii@$ip" "$inner" >/dev/null 2>&1
  fi
  echo "    unit rewritten, daemon-reload + timer restart done"
done

echo "==> deploy complete"
