#!/usr/bin/env bash
#
# field-monitor-healthcheck.sh — verify all vantage points are still measuring
# the Apple service family (probe.log apple-family count is GROWING).
#
# Apple-family = the 10 Apple targets: apple, appleid, apps, music, mesu,
# support, developer, itunes, books, icloud.
#
# Read-only: ssh + grep -c, no writes to remote hosts. Emits a short report to
# stdout (captured by journald) and appends a timestamped line to a local log.
#
# Edit the variables below (placeholders, not real infrastructure) before use.
#
# Real vantage-point IPs are loaded from $HOME/.config/field-monitor/
# vantage-points.env (git-ignored, private) if present. Create that file with:
#   VP01_IP=1.2.3.4
#   VP02_IP=5.6.7.8
#   ... (one per host, matching the order in HOSTS below)
# If the file is missing, the script reports all hosts as unreachable (-1)
# instead of crashing.
#
set -o pipefail

DEPLOY_USER="your-user"            # SSH user on the vantage points (override in vantage-points.env)
KEY_A="$HOME/.ssh/id_ed25519"      # key for direct + relay hops (override in vantage-points.env)
KEY_B="$HOME/.ssh/id_ed25519"      # key for the ARM64 host (if any) (override in vantage-points.env)
SSH_PORT=9922

# Real vantage-point IPs + key overrides are loaded from
# $HOME/.config/field-monitor/vantage-points.env (git-ignored, private) if
# present. The file may redefine DEPLOY_USER / KEY_A / KEY_B / VP0N_IP.
# Create it with:
#   VP01_IP=1.2.3.4
#   VP02_IP=5.6.7.8
#   ... (one per host, matching the order in HOSTS below)
#   KEY_A=/home/you/.ssh/real_key_a
#   KEY_B=/home/you/.ssh/real_key_b
#   DEPLOY_USER=your-ssh-user
# If the file is missing, the script reports all hosts as unreachable (-1)
# instead of crashing.
CONFIG="${VANTAGE_POINTS_ENV:-$HOME/.config/field-monitor/vantage-points.env}"
if [ -f "$CONFIG" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG"
fi

RESULTS_DIR="${RESULTS_DIR:-$HOME/.local/share/field-monitor}"
LOG="$RESULTS_DIR/healthcheck.log"

# ip name key relay(ip or empty) — fill VP0N_IP with your real IPs (never commit)
HOSTS=(
  "$VP01_IP vp-01 $KEY_A ''"
  "$VP02_IP vp-02 $KEY_A $VP01_IP"
  "$VP03_IP vp-03 $KEY_A ''"
  "$VP04_IP vp-04 $KEY_A $VP03_IP"
  "$VP05_IP vp-05 $KEY_A ''"
  "$VP06_IP vp-06 $KEY_A $VP01_IP"
  "$VP07_IP vp-07 $KEY_A ''"
  "$VP08_IP vp-08 $KEY_A ''"
  "$VP09_IP vp-09 $KEY_A ''"
  "$VP10_IP vp-10 $KEY_A ''"
  "$VP11_IP vp-11 $KEY_A $VP01_IP"
  "$VP12_IP vp-12 $KEY_B   ''"
)

APPLE_NAMES="apple appleid apps music mesu support developer itunes books icloud"

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Run a command on a host (via relay if given).
run_remote() {
  local ip="$1" key="$2" inner="$3" relay="${4:-}"
  if [ -n "$relay" ]; then
    ssh -F /dev/null -i "$key" -p "$SSH_PORT" \
      -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=10 \
      "$DEPLOY_USER@$relay" \
      "ssh -i $key -p $SSH_PORT -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=10 $DEPLOY_USER@$ip '$inner'"
  else
    ssh -F /dev/null -i "$key" -p "$SSH_PORT" \
      -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=10 \
      "$DEPLOY_USER@$ip" "$inner"
  fi
}

# Count apple-family lines in probe.log on a host (single ssh, loop server-side).
apple_family_count() {
  local ip="$1" key="$2" relay="${3:-}"
  local names="$APPLE_NAMES"
  local cmd="c=0; for n in $names; do c=\$((c+\$(grep -c \"target,\$n,\" $RESULTS_DIR/probe.log))); done; echo \$c"
  local out
  out=$(run_remote "$ip" "$key" "$cmd" "$relay" 2>/dev/null)
  local last
  last=$(printf '%s\n' "$out" | tail -1)
  if [[ "$last" =~ ^[0-9]+$ ]]; then
    printf '%s' "$last"
  else
    printf '%s' "-1"
  fi
}

counts=()
problems=()

for entry in "${HOSTS[@]}"; do
  read -r ip name key relay <<<"$entry"
  if [ -z "$ip" ]; then
    c=-1
  else
    c=$(apple_family_count "$ip" "$key" "$relay")
  fi
  counts+=("$name=$c")
  if [ "$c" -le 0 ]; then
    problems+=("$name ($ip) apple_family_count=$c")
  fi
done

# Compare with previous run log.
declare -A prev
if [ -f "$LOG" ]; then
  while read -r _rest; do
    # format: <ts> name1=c1 name2=c2 ...
    set -- $_rest
    shift # drop timestamp
    for kv in "$@"; do
      local_n="${kv%%=*}"
      local_v="${kv##*=}"
      if [[ "$local_v" =~ ^[0-9]+$ ]]; then
        prev["$local_n"]="$local_v"
      fi
    done
  done < "$LOG"
fi

mkdir -p "$(dirname "$LOG")"
printf '%s %s\n' "$now" "${counts[*]}" >> "$LOG"

echo "field-monitor healthcheck @ $now"
echo "  vantage points checked: ${#HOSTS[@]}"
echo "  metric: apple-family (apple,appleid,apps,music,mesu,support,developer,itunes,books,icloud)"
ok=0
for kv in "${counts[@]}"; do
  n="${kv%%=*}"
  c="${kv##*=}"
  p="${prev[$n]:-}"
  if [ "$c" -gt 0 ] && { [ -z "$p" ] || [ "$c" -ge "$p" ]; }; then
    ok=$((ok+1))
    if [ -z "$p" ]; then trend="new"; else trend="+$((c-p))"; fi
  else
    trend="STALE/EMPTY"
    problems+=("$n apple_family=$c prev=$p")
  fi
  printf '  %-14s apple_family=%4d  %s\n' "$n" "$c" "$trend"
done
echo
echo "  healthy: $ok/${#HOSTS[@]}"
if [ ${#problems[@]} -gt 0 ]; then
  echo "  PROBLEMS:"
  for p in "${problems[@]}"; do
    echo "    - $p"
  done
else
  echo "  all vantage points measuring apple-family, counts non-decreasing. OK"
fi
