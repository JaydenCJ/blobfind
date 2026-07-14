# blobfind examples

## `fixture.sh` — a dependency tree with things hiding in it

Builds a disposable project tree in `mktemp -d` containing the payloads
that real dependency trees accumulate:

- `node_modules/sharp/build/Release/sharp.node`: an ELF shared object where
  node-gyp leaves its install-time build output,
- `node_modules/leveldown/prebuilds/linux-x64.tar.gz`: a prebuild tarball
  nobody ever unpacks by hand,
- `venv/.../site-packages/numpy/core/*.so`: a compiled Python extension with
  its version resolvable from the `numpy-1.26.4.dist-info` sibling,
- `vendor/ring/pregenerated/aesni-x86_64-elf.o`: a precompiled object file
  inside a vendored Rust crate,
- `assets/filters.wasm` and `assets/telemetry.bin`: a wasm module and one
  high-entropy blob that no package manifest claims.

Run the default scan:

```bash
bash examples/fixture.sh
```

Any blobfind arguments are forwarded, so every subcommand can be tried
against the same fixture:

```bash
bash examples/fixture.sh scan --json
bash examples/fixture.sh scan --strict        # exits 1: the fixture has findings
bash examples/fixture.sh scan --no-archives
bash examples/fixture.sh snapshot             # lock file on stdout
```

The fixture never touches your real projects, needs no network, and removes
itself on exit.
