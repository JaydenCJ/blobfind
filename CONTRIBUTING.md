# Contributing to blobfind

Thanks for your interest in improving blobfind. Issues, discussions and pull requests are all welcome.

## Getting started

Prerequisites: Rust 1.75 or newer (stable toolchain).

```bash
git clone https://github.com/JaydenCJ/blobfind.git
cd blobfind
cargo build
cargo test
bash scripts/smoke.sh
```

`scripts/smoke.sh` assembles a synthetic dependency tree (npm addon, pip extension, vendored crate, prebuild tarball, opaque blob) in a temp dir and asserts on every subcommand and exit code. It finishes in well under a minute and must print `SMOKE OK`.

## Before you open a pull request

1. `cargo fmt` — formatting is enforced.
2. `cargo clippy --all-targets -- -D warnings` — clippy must be clean.
3. `cargo test` — unit tests and the CLI integration tests must pass.
4. `bash scripts/smoke.sh` — the smoke test must print `SMOKE OK`.
5. Add tests for behavior changes. Detection, hashing, provenance and lock-file logic live in pure modules (`sniff`, `sha256`, `entropy`, `provenance`, `baseline`) that are easy to unit-test; please keep it that way.

## Ground rules

- Keep dependencies at zero. blobfind is std-only by design — a supply-chain census tool must not have a supply chain of its own. A new dependency needs an exceptional justification in the PR description.
- No network calls, ever, and no telemetry. blobfind only reads the tree it is pointed at and only writes the file passed to `-o`.
- Determinism first: identical trees must produce byte-identical reports and lock files. Sorted traversal, no wall-clock data in output.
- Honest classification over clever guessing: when a header cannot be parsed safely, report `unrecognized` / `opaque` rather than misattribute. New format detectors must be decidable from the 512-byte sniff window.
- Code comments and doc comments are written in English.

## Reporting bugs

Please include the `blobfind --version` output, the exact command line, the relevant `blobfind scan --json` records (or the lock file lines), and — for detection bugs — a hex dump of the first 64 bytes of the misclassified file (`xxd -l 64 <file>`). Detection and provenance bugs are much easier to fix with a concrete byte-level or path-layout repro.

## Security

If you find a security issue (e.g. a way to make a scan misreport or hide executable content), please do not open a public issue. Use GitHub's private vulnerability reporting on this repository instead.
