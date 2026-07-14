#!/usr/bin/env bash
# Smoke test: builds blobfind, assembles a synthetic dependency tree (npm
# native addon, prebuild tarball, pip extension module, vendored cargo
# crate with a precompiled object, wasm module, unattributed high-entropy
# blob), then asserts on every subcommand and every exit-code contract.
# Self-contained: temp dirs only, no network.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

echo "[smoke] building..."
cargo build --quiet
BIN=target/debug/blobfind

WORK=$(mktemp -d "${TMPDIR:-/tmp}/blobfind-smoke.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/app"

# --- 1. version/help sanity -------------------------------------------------
"$BIN" --version | grep -q '^blobfind 0\.1\.0$' || fail "--version mismatch"
"$BIN" --help | grep -q 'COMMANDS:' || fail "--help missing sections"

# --- 2. assemble the fixture tree -------------------------------------------
echo "[smoke] assembling fixture tree"

make_elf() { # $1=path $2=e_type (\003 shared object, \001 relocatable)
  mkdir -p "$(dirname "$1")"
  { printf '\177ELF\002\001\001'
    head -c 9 /dev/zero
    printf "$2"'\000\076\000'
    head -c 236 /dev/zero
  } > "$1"
}

mkdir -p "$TREE/node_modules/sharp"
printf '{"name": "sharp", "version": "0.33.4"}\n' > "$TREE/node_modules/sharp/package.json"
make_elf "$TREE/node_modules/sharp/build/Release/sharp.node" '\003'
printf 'module.exports = 1;\n' > "$TREE/node_modules/sharp/index.js"

mkdir -p "$TREE/node_modules/leveldown/prebuilds"
printf 'prebuilt payload' | gzip > "$TREE/node_modules/leveldown/prebuilds/linux-x64.tar.gz"

SITE="$TREE/venv/lib/python3.12/site-packages"
mkdir -p "$SITE/numpy-1.26.4.dist-info"
make_elf "$SITE/numpy/core/_multiarray_umath.cpython-312-x86_64-linux-gnu.so" '\003'

mkdir -p "$TREE/vendor/ring/pregenerated"
printf '[package]\nname = "ring"\nversion = "0.17.8"\n' > "$TREE/vendor/ring/Cargo.toml"
make_elf "$TREE/vendor/ring/pregenerated/aesni-x86_64-elf.o" '\001'

mkdir -p "$TREE/assets"
printf '\000asm\001\000\000\000' > "$TREE/assets/filters.wasm"
# Deterministic high-entropy blob (hash chain) so every run is identical.
seed=blobfind
for _ in $(seq 1 256); do
  seed=$(printf '%s' "$seed" | sha256sum | cut -c1-64)
  printf '%s' "$seed"
done | while IFS= read -r -n2 h; do printf "\\x$h"; done > "$TREE/assets/telemetry.bin"

# --- 3. scan: provenance, kinds, hints ---------------------------------------
echo "[smoke] blobfind scan"
"$BIN" scan "$TREE" > "$WORK/scan.out"
grep -q 'npm · sharp@0.33.4' "$WORK/scan.out"      || fail "scan missing npm provenance"
grep -q 'pip · numpy@1.26.4' "$WORK/scan.out"      || fail "scan missing pip dist-info version"
grep -q 'cargo · ring@0.17.8' "$WORK/scan.out"     || fail "scan missing vendored crate"
grep -q 'ELF shared object' "$WORK/scan.out"       || fail "scan missing ELF format"
grep -q 'ELF relocatable object' "$WORK/scan.out"  || fail "scan missing .o detection"
grep -q 'WebAssembly module' "$WORK/scan.out"      || fail "scan missing wasm"
grep -q 'gzip data' "$WORK/scan.out"               || fail "scan missing archive"
grep -q 'high-entropy data' "$WORK/scan.out"       || fail "scan missing opaque blob"
grep -q 'unattributed' "$WORK/scan.out"            || fail "scan missing unattributed group"
grep -q 'summary: 9 files scanned · 4 native · 1 archive · 1 opaque blob · 4 packages affected' \
  "$WORK/scan.out" || fail "scan summary wrong: $(tail -1 "$WORK/scan.out")"
echo "[smoke] scan: 4 ecosystems, all three kinds present"

# --- 4. JSON report -----------------------------------------------------------
"$BIN" scan "$TREE" --json > "$WORK/scan.json"
grep -q '"blobfind": "0.1.0"' "$WORK/scan.json"    || fail "json missing version"
grep -q '"summary": { "native": 4, "archive": 1, "opaque": 1 }' "$WORK/scan.json" \
  || fail "json summary wrong"
grep -q '"package": "sharp"' "$WORK/scan.json"     || fail "json missing package"
grep -q '"sha256": "' "$WORK/scan.json"            || fail "json missing hashes"
echo "[smoke] scan --json OK"

# --- 5. explain one file -------------------------------------------------------
"$BIN" explain "$TREE/node_modules/sharp/build/Release/sharp.node" --root "$TREE" \
  > "$WORK/explain.out"
grep -q 'kind:     native' "$WORK/explain.out"     || fail "explain missing kind"
grep -q 'arch:     x86-64 (64-bit)' "$WORK/explain.out" || fail "explain missing arch"
grep -q 'package:  npm · sharp@0.33.4' "$WORK/explain.out" || fail "explain missing package"
grep -q 'node-gyp build output' "$WORK/explain.out" || fail "explain missing hint"
echo "[smoke] explain OK"

# --- 6. snapshot + clean diff --------------------------------------------------
"$BIN" snapshot "$TREE" -o "$WORK/blobfind.lock" | grep -q 'wrote 6 blobs' \
  || fail "snapshot did not write 6 blobs"
grep -q '^# blobfind lock v1$' "$WORK/blobfind.lock" || fail "lock missing header"
"$BIN" diff "$TREE" --against "$WORK/blobfind.lock" > "$WORK/diff.out" \
  || fail "clean diff must exit 0"
grep -q 'baseline OK — 6 blobs, no drift' "$WORK/diff.out" || fail "clean diff wrong output"
echo "[smoke] snapshot + clean diff OK"

# --- 7. drift detection: a new binary appears, an existing one changes ---------
make_elf "$TREE/node_modules/sharp/vendored-helper.so" '\003'
printf 'tampered' >> "$TREE/assets/telemetry.bin"
if "$BIN" diff "$TREE" --against "$WORK/blobfind.lock" > "$WORK/drift.out"; then
  fail "drift must exit 1"
fi
grep -q '+ added    native  node_modules/sharp/vendored-helper.so' "$WORK/drift.out" \
  || fail "drift missing added binary"
grep -q '~ changed  opaque  assets/telemetry.bin' "$WORK/drift.out" \
  || fail "drift missing changed blob"
grep -q 'drift: 1 added · 0 removed · 1 changed' "$WORK/drift.out" || fail "drift totals wrong"
echo "[smoke] diff caught the planted drift"

# --- 8. exit-code contracts -----------------------------------------------------
if "$BIN" scan "$TREE" --strict > /dev/null; then fail "--strict must exit 1 on findings"; fi
mkdir -p "$WORK/clean" && printf 'console.log(1);\n' > "$WORK/clean/app.js"
"$BIN" scan "$WORK/clean" --strict > /dev/null || fail "clean tree under --strict must exit 0"
set +e
"$BIN" scan /nonexistent-blobfind-dir > /dev/null 2>&1; [ $? -eq 2 ] || fail "bad dir must exit 2"
"$BIN" frobnicate > /dev/null 2>&1;                  [ $? -eq 2 ] || fail "bad command must exit 2"
set -e
echo "[smoke] exit codes: 0 clean / 1 findings·drift / 2 usage"

echo "SMOKE OK"
