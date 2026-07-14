# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Format sniffing from a 512-byte header: ELF (class, endianness, type, machine), Mach-O thin and universal (cpu, filetype, `0xCAFEBABE` disambiguation against Java class files), PE/COFF (machine, DLL vs EXE), WebAssembly, Java class files, `ar` static libraries, and the container formats that smuggle binaries (zip, gzip, xz, zstd, bzip2, tar).
- Three-way classification: `native` (executable machine/byte code), `archive` (containers that can hide binaries), `opaque` (unrecognized data at or above the entropy threshold, default 7.5 bits/byte, with a `--min-blob` size floor and a media/font extension exemption that magic bytes always override).
- Provenance resolution from on-disk package-manager state: `node_modules/<pkg>` incl. scopes and nested trees (package.json name/version), `site-packages`/`dist-packages` with `.dist-info` version lookup incl. top-level extension modules, vendored cargo crates via `Cargo.toml`, Go `vendor/modules.txt` longest-prefix matching, Bundler `gems/<name>-<ver>`, plus a nearest-manifest fallback (package.json, Cargo.toml, pyproject.toml/setup.py, go.mod, composer.json) scoped to the scan root.
- Provenance hints on every finding: `prebuilds/` payloads, node-gyp `build/Release` output, `.node` addons, compiled Python extensions, precompiled `.o` objects, jar/wheel/egg/apk containers, bundled tarballs, statistically-random data, and files with no owning manifest.
- Streaming SHA-256 (std-only, NIST-vector tested) and Shannon entropy computed in a single pass per finding.
- CLI: `blobfind scan` (grouped human report or `--json`, `--strict` exit 1 on any finding), `blobfind explain <file>` (full detail for one file), `blobfind snapshot` (deterministic, git-diffable lock file), `blobfind diff` (added/removed/changed blobs vs a baseline, exit 1 on drift).
- Deterministic, read-only traversal: sorted order, symlinks never followed, VCS directories skipped, unreadable paths reported as warnings instead of aborting the census.
- Exit-code contract: 0 clean, 1 `--strict` findings or baseline drift, 2 usage error.
- Test suite: 82 unit tests, 10 CLI integration tests against the compiled binary, and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/blobfind/releases/tag/v0.1.0
