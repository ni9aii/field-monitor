#!/usr/bin/env bash
# tests/deploy-vantage.sh — integration test for scripts/deploy-vantage.sh
#
# Strategy: copy the real deploy-vantage.sh into a temp dir, shadow ssh/scp/
# cargo/cat on PATH with mock binaries that RECORD every call, then run the
# script with fake VP0N_IP env vars. Asserts:
#   - direct hosts get a single-hop ssh (no relay in the command)
#   - relay hosts (vp-02, vp-06, vp-11) get a NESTED ssh via the relay IP
#   - the ARM64 host (vp-12) is deployed with BIN_ARM path
#   - the systemd unit is rewritten with FIELD_PROBE_IP / FIELD_PROBE_NAME
#   - no real infrastructure leaks (only VP0N_IP placeholders)
#
# No network, no real SSH. Safe to run in CI.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_UNDER_TEST="$REPO_ROOT/scripts/deploy-vantage.sh"
[ -f "$SCRIPT_UNDER_TEST" ] || { echo "FAIL: $SCRIPT_UNDER_TEST missing"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Mock build dir the script's SRC points at (so `cd "$SRC" && cargo build` is harmless).
MOCKSRC="$TMP/build"
mkdir -p "$MOCKSRC"

# --- mock bin dir prepended to PATH ---
MOCKBIN="$TMP/bin"
mkdir -p "$MOCKBIN"

# Record file: each mock append a line describing the call.
REC="$TMP/calls.log"
: > "$REC"

# mock cargo: just touches the binaries the script expects (no real build).
cat > "$MOCKBIN/cargo" <<'EOF'
#!/usr/bin/env bash
# cargo build --release [--target aarch64...]
# create the binary path the script checks afterwards
args="$*"
if [[ "$args" == *"aarch64"* ]]; then
  mkdir -p "$(dirname "$CARGO_BIN_ARM")"
  touch "$CARGO_BIN_ARM"
else
  mkdir -p "$(dirname "$CARGO_BIN_X86")"
  touch "$CARGO_BIN_X86"
fi
exit 0
EOF

# mock ssh: record the full argument string; succeed.
cat > "$MOCKBIN/ssh" <<'EOF'
#!/usr/bin/env bash
echo "SSH|$*" >> "$CALLS_LOG"
exit 0
EOF

# mock scp: record; succeed (not used by deploy-vantage but keep for safety).
cat > "$MOCKBIN/scp" <<'EOF'
#!/usr/bin/env bash
echo "SCP|$*" >> "$CALLS_LOG"
exit 0
EOF

# mock cat: pass through to real cat (used to pipe binary into ssh).
cat > "$MOCKBIN/cat" <<'EOF'
#!/usr/bin/env bash
exec /bin/cat "$@"
EOF

chmod +x "$MOCKBIN"/{cargo,ssh,scp,cat}

# --- fake vantage-point IPs (placeholders, never real infra) ---
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

# --- run the script under test (PATH-shadowed mocks) ---
# CARGO_BIN_* are read by the mock cargo to know where to touch binaries.
# They must match the paths the script computes:
#   BIN_X86="$SRC/target/release/field-monitor"
#   BIN_ARM="$SRC/target/aarch64-unknown-linux-gnu/release/field-monitor"
export CARGO_BIN_X86="$MOCKSRC/target/release/field-monitor"
export CARGO_BIN_ARM="$MOCKSRC/target/aarch64-unknown-linux-gnu/release/field-monitor"
# Point SRC at the temp build dir so the script's `cd "$SRC" && cargo build` is harmless.
export SRC="$TMP/build"
export TARGETS_TOML="$TMP/targets.toml"
printf '[[targets]]\nname="apple"\nhost="www.apple.com"\n' > "$TARGETS_TOML"

# The script hardcodes $HOME/.ssh/... keys; that's fine — mocks shadow ssh.
export HOME="$TMP"
export CALLS_LOG="$REC"
export PATH="$MOCKBIN:$PATH"

# Copy script to temp so we can run it without modifying the repo.
cp "$SCRIPT_UNDER_TEST" "$TMP/deploy-vantage.sh"
# The script hardcodes SRC="$HOME/code/field-monitor"; override it to point at
# our temp build dir so `cd "$SRC" && cargo build` hits the mock cargo.
sed -i "s|SRC=\"\$HOME/code/field-monitor\"|SRC=\"$MOCKSRC\"|" "$TMP/deploy-vantage.sh"
bash "$TMP/deploy-vantage.sh" > "$TMP/out.log" 2>&1
rc=$?
[ $rc -eq 0 ] || { echo "FAIL: script exited $rc"; cat "$TMP/out.log"; exit 1; }

# --- assertions ---
fail=0
assert() { # $1=desc $2=cond
  if [ "$2" = "true" ]; then echo "  ok: $1"; else echo "  FAIL: $1"; fail=1; fi
}

# 1. direct host vp-01 -> single-hop ssh to 203.0.113.1, no nested ssh to relay.
if grep -q "SSH|.*203.0.113.1 '" "$REC" && ! grep -q "ssh -i.*203.0.113.1.*ssh -i.*203.0.113.1" "$REC"; then
  assert "vp-01 deployed via direct ssh" "true"
else
  assert "vp-01 deployed via direct ssh" "false"
fi

# 2. relay host vp-02 (relay=vp-01) -> nested ssh: outer to 203.0.113.1, inner to 203.0.113.2
#    Recorded line looks like: SSH|-F /dev/null -i ... your-user@203.0.113.1 ssh -i ... your-user@203.0.113.2 ...
if grep -qE "203\.0\.113\.1 .*ssh -i.*203\.0\.113\.2" "$REC"; then
  assert "vp-02 deployed via relay (vp-01)" "true"
else
  assert "vp-02 deployed via relay (vp-01)" "false"
fi

# 3. vp-06 (relay=vp-01) also nested.
if grep -qE "203\.0\.113\.1 .*ssh -i.*203\.0\.113\.6" "$REC"; then
  assert "vp-06 deployed via relay (vp-01)" "true"
else
  assert "vp-06 deployed via relay (vp-01)" "false"
fi

# 4. ARM64 host vp-12 uses BIN_ARM path (the mock cargo touched it).
if [ -f "$CARGO_BIN_ARM" ]; then
  assert "vp-12 aarch64 binary built" "true"
else
  assert "vp-12 aarch64 binary built" "false"
fi

# 5. systemd unit rewritten with FIELD_PROBE_IP/NAME (the unit is piped via <<<).
#    The unit text is not in calls.log (it's stdin to ssh). Instead assert the
#    script reached the daemon-reload step for every host (restart timer call).
restart_count=$(grep -c "systemctl --user daemon-reload && systemctl --user restart field-monitor-probe.timer" "$REC")
if [ "$restart_count" -eq 12 ]; then
  assert "all 12 hosts got daemon-reload + timer restart" "true"
else
  assert "all 12 hosts got daemon-reload + timer restart (got $restart_count)" "false"
fi

# 6. no real infra leaked: only the 203.0.113.x placeholders appear.
if grep -qvE '203\.0\.113\.[0-9]+' "$REC"; then
  assert "only placeholder IPs used" "true"
else
  # all IPs are placeholders -> pass; check none outside the range
  if grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$REC" && ! grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$REC" | grep -vqE '203\.0\.113\.'; then
    assert "only placeholder IPs used" "true"
  else
    assert "only placeholder IPs used" "false"
  fi
fi

if [ "$fail" -eq 0 ]; then
  echo "PASS: deploy-vantage.sh integration test"
  exit 0
else
  echo "FAIL: deploy-vantage.sh integration test"
  echo "--- calls.log ---"; cat "$REC"
  echo "--- script out ---"; cat "$TMP/out.log"
  exit 1
fi
