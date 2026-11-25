#!/usr/bin/env sh
# Builds node-rs, starts a fresh node on a temporary data directory and walks
# the brand admin + retailer portal in a headless browser.
#   e2e/run.sh            (needs Rust, Bun and zip; installs Playwright on first run)
#   NODE_RS=path/to/node-rs e2e/run.sh   uses an existing binary
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PORT="${PORT:-18080}"
TMP="$HERE/tmp"
rm -rf "$TMP" "$HERE/screenshots"
mkdir -p "$TMP/data" "$HERE/screenshots"
# zipdir OUT PATH...: zip, or Python's zipfile where zip is not installed (run inside the folder).
zipdir() {
  out="$1"; shift
  if command -v zip >/dev/null 2>&1; then zip -qr "$out" "$@"; else
    python3 -I -c 'import sys, os, zipfile
z = zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED)
for p in sys.argv[2:]:
    for root, _, files in (os.walk(p) if os.path.isdir(p) else [(os.path.dirname(p), [], [os.path.basename(p)])]):
        for f in sorted(files): z.write(os.path.join(root, f))
z.close()' "$out" "$@"
  fi
}
FIXTURES="$ROOT/crates/obx-conformance/fixtures/maison-noor"
NODE_RS="${NODE_RS:-}"
if [ -z "$NODE_RS" ]; then
  (cd "$ROOT" && cargo build --locked)
  NODE_RS="${CARGO_TARGET_DIR:-$ROOT/target}/debug/node-rs"
fi
NODE_RS="$(cd "$(dirname "$NODE_RS")" && pwd)/$(basename "$NODE_RS")"
(cd "$FIXTURES" && zipdir "$TMP/images.zip" images)
# A "nightly export" for the scheduled import: the same catalog with one renamed article.
mkdir -p "$TMP/export"
cp -R "$FIXTURES/." "$TMP/export/"
sed 's/Fine Merino Crew-Neck Sweater/Merino Crew Jumper/' "$FIXTURES/products.csv" >"$TMP/export/products.csv"
(cd "$TMP/export" && zipdir "$TMP/package.zip" products.csv assets.csv images)
[ -d "$HERE/node_modules" ] || (cd "$HERE" && bun install --frozen-lockfile && bunx playwright install chromium)

URL="http://localhost:$PORT"
OBX_DATA_DIR="$TMP/data" PORT="$PORT" OBX_PUBLIC_URL="$URL" \
  OBX_SETUP_CODE=SETUP-1234 OBX_ALLOW_PRIVATE_URLS=true OBX_MAIL_LOG_BODIES=true \
  "$NODE_RS" serve >"$TMP/node.log" 2>&1 &
NODE_PID=$!
trap 'kill "$NODE_PID" 2>/dev/null || true' EXIT INT TERM
i=0
until curl -sf "http://localhost:$PORT/healthz" >/dev/null; do
  i=$((i + 1)); [ "$i" -lt 30 ] || { cat "$TMP/node.log"; exit 1; }
  sleep 1
done
cd "$HERE"
OBX_E2E_URL="http://localhost:$PORT" OBX_E2E_FIXTURES="$FIXTURES" OBX_E2E_NODE_LOG="$TMP/node.log" OBX_E2E_IMAGES_ZIP="$TMP/images.zip" OBX_E2E_PACKAGE_ZIP="$TMP/package.zip" \
  bunx playwright test "$@"
