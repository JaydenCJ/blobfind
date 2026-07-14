#!/usr/bin/env bash
# Build a small synthetic dependency tree — an npm native addon, a prebuilt
# tarball, a pip extension module, a vendored Rust crate with a precompiled
# object file, a wasm module and one unattributed high-entropy blob — and
# run blobfind against it. Useful for trying every subcommand without
# scanning a real project.
#
#   bash examples/fixture.sh                 # scan the fixture
#   bash examples/fixture.sh scan --json     # any blobfind arguments work
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet
BIN=target/debug/blobfind

WORK=$(mktemp -d "${TMPDIR:-/tmp}/blobfind-example.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/app"

# Minimal but well-formed ELF headers (little-endian, 64-bit).
make_elf() { # $1=path $2=e_type (\003 shared object, \001 relocatable)
  mkdir -p "$(dirname "$1")"
  { printf '\177ELF\002\001\001'
    head -c 9 /dev/zero
    printf "$2"'\000\076\000'
    head -c 236 /dev/zero
  } > "$1"
}

# npm: a node-gyp addon compiled at install time.
mkdir -p "$TREE/node_modules/sharp"
cat > "$TREE/node_modules/sharp/package.json" <<'EOF'
{"name": "sharp", "version": "0.33.4"}
EOF
make_elf "$TREE/node_modules/sharp/build/Release/sharp.node" '\003'
printf 'module.exports = 1;\n' > "$TREE/node_modules/sharp/index.js"

# npm: a prebuild tarball nobody ever reads.
mkdir -p "$TREE/node_modules/leveldown/prebuilds"
printf 'prebuilt payload' | gzip > "$TREE/node_modules/leveldown/prebuilds/linux-x64.tar.gz"

# pip: a compiled extension module inside a venv.
SITE="$TREE/venv/lib/python3.12/site-packages"
mkdir -p "$SITE/numpy-1.26.4.dist-info"
make_elf "$SITE/numpy/core/_multiarray_umath.cpython-312-x86_64-linux-gnu.so" '\003'

# cargo: a vendored crate shipping a precompiled object file.
mkdir -p "$TREE/vendor/ring/pregenerated"
cat > "$TREE/vendor/ring/Cargo.toml" <<'EOF'
[package]
name = "ring"
version = "0.17.8"
EOF
make_elf "$TREE/vendor/ring/pregenerated/aesni-x86_64-elf.o" '\001'

# A wasm module and one blob no manifest claims. The blob is a deterministic
# hash chain (not /dev/urandom) so repeated runs print identical reports.
mkdir -p "$TREE/assets"
printf '\000asm\001\000\000\000' > "$TREE/assets/filters.wasm"
seed=blobfind
for _ in $(seq 1 256); do
  seed=$(printf '%s' "$seed" | sha256sum | cut -c1-64)
  printf '%s' "$seed"
done | while IFS= read -r -n2 h; do printf "\\x$h"; done > "$TREE/assets/telemetry.bin"

if [ "$#" -eq 0 ]; then
  "$BIN" scan "$TREE"
else
  CMD="$1"; shift
  "$BIN" "$CMD" "$TREE" "$@"
fi
