#!/usr/bin/env sh
# Runs the OBX conformance suite (obx-conformance from obx-go) against a
# fresh node-rs: setup with a known code, the MAISON NOOR fixtures, every
# profile. The report is written to conformance-report.json.
#
#   scripts/conformance.sh [profile]        profile: all (default), protocol, ingest, portal, security
#
# Needs: a built node-rs (NODE_RS, default target/debug/node-rs) and
# obx-conformance on PATH or CONFORMANCE_BIN (go install
# github.com/openbrandexchange/obx-go/cmd/obx-conformance@main).
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${1:-all}"
NODE_RS="${NODE_RS:-${CARGO_TARGET_DIR:-$HERE/target}/debug/node-rs}"
CONF="${CONFORMANCE_BIN:-obx-conformance}"
PORT="${CONFORMANCE_PORT:-18431}"
DATA="$(mktemp -d)"
REPORT="${REPORT:-$HERE/conformance-report.json}"
HOOK="$DATA/operator-hook.sh"
printf '#!/bin/sh\nexec env OBX_DATA_DIR="%s" OBX_PUBLIC_URL="http://127.0.0.1:%s" "%s" admin operator-hook "$1"\n' "$DATA" "$PORT" "$NODE_RS" > "$HOOK"
chmod +x "$HOOK"

OBX_DATA_DIR="$DATA" OBX_PUBLIC_URL="http://127.0.0.1:$PORT" PORT="$PORT" OBX_SETUP_CODE=CONF-TEST-CODE \
  OBX_LOG_LEVEL="${OBX_LOG_LEVEL:-warn}" "$NODE_RS" serve > "$DATA/node.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true; rm -rf "$DATA"' EXIT
i=0
until curl -fsS -m 2 "http://127.0.0.1:$PORT/healthz" > /dev/null 2>&1; do
  i=$((i + 1))
  if [ $i -gt 100 ]; then echo "node-rs did not start:"; cat "$DATA/node.log"; exit 1; fi
  sleep 0.1
done
set +e
"$CONF" "$PROFILE" --url "http://127.0.0.1:$PORT" --setup-code CONF-TEST-CODE --operator-hook "$HOOK" --json > "$REPORT"
CODE=$?
set -e
"$CONF" report "$REPORT" || true
if [ "$CODE" -ne 0 ]; then
  echo "--- node log (last 50 lines)"; tail -n 50 "$DATA/node.log"
fi
exit $CODE
