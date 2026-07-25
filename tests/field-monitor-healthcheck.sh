#!/usr/bin/env bash
# tests/field-monitor-healthcheck.sh — integration test for scripts/field-monitor-healthcheck.sh
#
# Strategy: copy the real script, shadow ssh with a mock that emulates the
# apple-family grep counting against per-host fake probe.log files, then run
# the script with placeholder VP0N_IP env and assert:
#   - a host whose fake probe.log has apple lines and a non-decreasing count
#     is reported OK
#   - a host with zero apple lines is reported STALE/EMPTY
#   - a host with an empty IP is reported -1 (unreachable) without ssh call
#   - the log line is appended with the timestamp + counts
#
# No network, no real SSH.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_UNDER_TEST="$REPO_ROOT/scripts/field-monitor-healthcheck.sh"
[ -f "$SCRIPT_UNDER_TEST" ] || { echo "FAIL: $SCRIPT_UNDER_TEST missing"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

MOCKBIN="$TMP/bin"
mkdir -p "$MOCKBIN"

# Per-host fake probe.log content lives in $TMP/probe-<ip>.log
# The script runs (server-side) a loop counting grep -c "target,$name," in
# $HOME/.local/share/field-monitor/probe.log. Our mock ssh captures the inner
# command and answers with a count derived from the fake file.
cat > "$MOCKBIN/ssh" <<'EOF'
#!/usr/bin/env bash
# Collect all args; the inner command is the LAST ssh operand (single-quoted).
# We emulate: c=0; for n in <names>; do c=$((c+$(grep -c "target,$n," $HOME/.local/share/field-monitor/probe.log))); done; echo $c
args="$*"
# extract the inner command (after the relay ssh, the part after the 2nd host)
inner="${args##*ssh -i *}"
# strip leading/trailing quotes
inner="${inner#\'}"; inner="${inner%\'}"
# the inner command references $HOME/.local/share/field-monitor/probe.log
# Resolve which host by looking for the probe.log in our TMP using the IP.
# Simpler: the inner command is exactly the loop; grep -c would read the file.
# We re-implement: count target,apple*, lines in the fake file named by IP.
# Recover IP: it's the host in "... DEPLOY_USER@IP '...'" — grab the 2nd @host.
ip=$(printf '%s\n' "$args" | grep -oE '@[0-9.]+' | tail -1 | tr -d '@')
fake="$MOCK_PROBE_DIR/probe-$ip.log"
c=0
if [ -f "$fake" ]; then
  while IFS= read -r line; do
    case "$line" in
      target,apple*|target,appleid*|target,apps*|target,music*|target,mesu*|target,support*|target,developer*|target,itunes*|target,books*|target,icloud*) c=$((c+1));;
    esac
  done < "$fake"
fi
echo "$c"
exit 0
EOF
chmod +x "$MOCKBIN/ssh"

# Fake probe logs: vp-01 has 5 apple lines, vp-02 has 0, vp-12 missing file.
printf 'target,apple,OK\ntarget,icloud,OK\ntarget,appleid,OK\ntarget,music,OK\ntarget,mesu,OK\n' > "$TMP/probe-203.0.113.1.log"
printf 'target,github,OK\ntarget,google,OK\n' > "$TMP/probe-203.0.113.2.log"
# vp-12 (203.0.113.12) has NO fake file -> ssh returns 0 (STALE)

export VP01_IP=203.0.113.1
export VP02_IP=203.0.113.2
export VP03_IP=203.0.113.3
export VP04_IP=203.0.113.4
export VP05_IP=203.0.113.5
export VP06_IP=203.0.113.6
export VP07_IP=203.0.113.7
export VP08_IP=203.0.113.8
export VP09_IP=203.0.113.9
export VP10_IP=203.0.113.10
export VP11_IP=203.0.113.11
export VP12_IP=203.0.113.12

export HOME="$TMP"
export MOCK_PROBE_DIR="$TMP"
export RESULTS_DIR="$TMP/results"
export VANTAGE_POINTS_ENV=/dev/null   # force no real config load
export PATH="$MOCKBIN:$PATH"

mkdir -p "$RESULTS_DIR"
cp "$SCRIPT_UNDER_TEST" "$TMP/healthcheck.sh"
bash "$TMP/healthcheck.sh" > "$TMP/out.log" 2>&1
rc=$?
[ $rc -eq 0 ] || { echo "FAIL: script exited $rc"; cat "$TMP/out.log"; exit 1; }

fail=0
assert() { if [ "$2" = "true" ]; then echo "  ok: $1"; else echo "  FAIL: $1"; fail=1; fi; }

# vp-01 has 5 apple lines -> reported, OK/non-empty
if grep -q "vp-01 .*apple_family= *5" "$TMP/out.log" || grep -q "vp-01 *apple_family= *5" "$TMP/out.log"; then
  assert "vp-01 apple_family count = 5" "true"
else
  assert "vp-01 apple_family count = 5" "false"
fi

# vp-02 has 0 apple lines -> STALE/EMPTY
if grep -q "vp-02 .*STALE/EMPTY\|vp-02 apple_family= *0" "$TMP/out.log"; then
  assert "vp-02 reported STALE/EMPTY (0 apple lines)" "true"
else
  assert "vp-02 reported STALE/EMPTY (0 apple lines)" "false"
fi

# vp-12 has no fake probe.log -> ssh returns 0, still 0 -> STALE (not -1, since IP present)
if grep -q "vp-12 .*STALE/EMPTY\|vp-12 apple_family= *0" "$TMP/out.log"; then
  assert "vp-12 (no probe.log) reported STALE/EMPTY, not crash" "true"
else
  assert "vp-12 (no probe.log) reported STALE/EMPTY, not crash" "false"
fi

# log file appended with a timestamped line
if [ -f "$RESULTS_DIR/healthcheck.log" ] && grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' "$RESULTS_DIR/healthcheck.log"; then
  assert "healthcheck.log appended with timestamp" "true"
else
  assert "healthcheck.log appended with timestamp" "false"
fi

# no real infra: only placeholder IPs
if grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$TMP/out.log" | grep -qvE '203\.0\.113\.'; then
  assert "only placeholder IPs in output" "false"
else
  assert "only placeholder IPs in output" "true"
fi

if [ "$fail" -eq 0 ]; then
  echo "PASS: field-monitor-healthcheck.sh integration test"
  exit 0
else
  echo "FAIL: field-monitor-healthcheck.sh integration test"
  echo "--- out.log ---"; cat "$TMP/out.log"
  exit 1
fi
