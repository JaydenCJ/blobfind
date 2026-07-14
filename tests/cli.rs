//! End-to-end tests against the compiled `blobfind` binary: scan report,
//! JSON output, explain, snapshot/diff round trip and every exit-code
//! contract. All fixtures are synthesized into temp dirs — no network, no
//! real package installs, fully deterministic.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_blobfind")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run blobfind binary")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("blobfind-cli-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A minimal ELF shared object header (x86-64, little-endian) padded so the
/// file is clearly a binary and not accidentally opaque-sized.
fn elf_so() -> Vec<u8> {
    let mut b = vec![0u8; 256];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; // 64-bit
    b[5] = 1; // little-endian
    b[0x10] = 3; // ET_DYN
    b[0x12] = 62; // EM_X86_64
    b
}

/// Deterministic pseudo-random bytes with ~8 bits/byte entropy.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e3779b97f4a7c15u64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// The canonical fixture: an npm addon, a pip extension, a stray opaque
/// blob and a bundled tarball.
fn fixture(tag: &str) -> PathBuf {
    let d = tempdir(tag);
    let sharp = d.join("node_modules/sharp");
    fs::create_dir_all(sharp.join("build/Release")).unwrap();
    fs::write(
        sharp.join("package.json"),
        r#"{"name": "sharp", "version": "0.33.4"}"#,
    )
    .unwrap();
    fs::write(sharp.join("build/Release/sharp.node"), elf_so()).unwrap();
    fs::write(sharp.join("index.js"), "module.exports = 1;\n").unwrap();

    let site = d.join("venv/lib/python3.12/site-packages");
    fs::create_dir_all(site.join("numpy/core")).unwrap();
    fs::create_dir_all(site.join("numpy-1.26.4.dist-info")).unwrap();
    fs::write(
        site.join("numpy/core/_multiarray_umath.cpython-312-x86_64-linux-gnu.so"),
        elf_so(),
    )
    .unwrap();

    fs::write(d.join("mystery.bin"), noise(8192)).unwrap();

    let mut gz = vec![0x1f, 0x8b, 0x08];
    gz.extend(noise(2048));
    fs::create_dir_all(d.join("node_modules/leveldown/prebuilds")).unwrap();
    fs::write(
        d.join("node_modules/leveldown/prebuilds/linux-x64.tar.gz"),
        &gz,
    )
    .unwrap();
    d
}

#[test]
fn help_and_version() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    let text = stdout(&help);
    for cmd in ["scan", "explain", "snapshot", "diff", "EXIT CODES"] {
        assert!(text.contains(cmd), "help must mention '{cmd}'");
    }

    let version = run(&["--version"]);
    assert!(version.status.success());
    assert_eq!(
        stdout(&version).trim(),
        format!("blobfind {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn scan_reports_all_kinds_with_provenance() {
    let d = fixture("scan");
    let out = run(&["scan", d.to_str().unwrap()]);
    assert!(out.status.success(), "scan must exit 0 without --strict");
    let text = stdout(&out);
    // Provenance labels for both ecosystems.
    assert!(text.contains("npm · sharp@0.33.4 — 1 finding\n"), "{text}");
    assert!(text.contains("pip · numpy@1.26.4 — 1 finding\n"), "{text}");
    // Formats and kinds.
    assert!(text.contains("ELF shared object"));
    assert!(text.contains("x86-64 (64-bit)"));
    assert!(text.contains("opaque"));
    assert!(text.contains("archive"));
    // Inner paths, not just root-relative ones.
    assert!(text.contains("build/Release/sharp.node"));
    // The stray blob is unattributed and grouped last.
    assert!(text.contains("unattributed"));
    assert!(text.find("sharp").unwrap() < text.find("unattributed").unwrap());
    assert!(text.contains(
        "summary: 6 files scanned · 2 native · 1 archive · 1 opaque blob · 3 packages affected"
    ));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn scan_json_is_machine_readable() {
    let d = fixture("json");
    let out = run(&["scan", d.to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains(&format!("\"blobfind\": \"{}\"", env!("CARGO_PKG_VERSION"))));
    assert!(text.contains("\"summary\": { \"native\": 2, \"archive\": 1, \"opaque\": 1 }"));
    assert!(text.contains("\"path\": \"node_modules/sharp/build/Release/sharp.node\""));
    assert!(text.contains("\"package\": \"numpy\""));
    assert!(text.contains("\"version\": \"1.26.4\""));
    assert!(text.contains("\"sha256\": \""));
    assert!(text.contains("\"kind\": \"opaque\""));
    // Balanced document.
    assert_eq!(text.matches('{').count(), text.matches('}').count());
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn strict_exit_code_depends_on_findings() {
    let clean = tempdir("strict-clean");
    fs::write(clean.join("app.js"), "console.log(1);\n").unwrap();
    let out = run(&["scan", clean.to_str().unwrap(), "--strict"]);
    assert!(
        out.status.success(),
        "clean tree under --strict must exit 0"
    );
    assert!(stdout(&out).contains("0 native"));
    let _ = fs::remove_dir_all(&clean);

    let dirty = fixture("strict-dirty");
    let out = run(&["scan", dirty.to_str().unwrap(), "--strict"]);
    assert_eq!(out.status.code(), Some(1), "findings under --strict exit 1");
    let _ = fs::remove_dir_all(&dirty);
}

#[test]
fn tuning_flags_change_what_counts() {
    let d = fixture("tuning");
    // Suppressing archives drops the tarball finding.
    let out = run(&["scan", d.to_str().unwrap(), "--no-archives"]);
    assert!(stdout(&out).contains("0 archives"));
    // Raising the min-blob floor above the blob size hides the opaque hit.
    let out = run(&["scan", d.to_str().unwrap(), "--min-blob", "16K"]);
    assert!(stdout(&out).contains("0 opaque blobs"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn explain_details_one_file() {
    let d = fixture("explain");
    let file = d.join("node_modules/sharp/build/Release/sharp.node");
    let out = run(&[
        "explain",
        file.to_str().unwrap(),
        "--root",
        d.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("kind:     native"));
    assert!(text.contains("format:   ELF shared object"));
    assert!(text.contains("arch:     x86-64 (64-bit)"));
    assert!(text.contains("sha256:   "));
    assert!(text.contains("package:  npm · sharp@0.33.4"));
    assert!(text.contains("node-gyp build output"));

    let json = run(&[
        "explain",
        file.to_str().unwrap(),
        "--root",
        d.to_str().unwrap(),
        "--json",
    ]);
    assert!(stdout(&json).contains("\"inner_path\": \"build/Release/sharp.node\""));

    // Regression: a *relative* FILE with the default root (the current
    // directory) must still walk the manifests between the file and the
    // root — it once skipped straight to the root manifest.
    let rel = Command::new(bin())
        .args(["explain", "node_modules/sharp/build/Release/sharp.node"])
        .current_dir(&d)
        .output()
        .expect("failed to run blobfind binary");
    assert!(rel.status.success());
    assert!(
        stdout(&rel).contains("package:  npm · sharp@0.33.4"),
        "relative explain must attribute the owning package: {}",
        stdout(&rel)
    );
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn snapshot_then_diff_round_trips_clean() {
    let d = fixture("roundtrip");
    let lock = d.join("blobfind.lock");
    let out = run(&[
        "snapshot",
        d.to_str().unwrap(),
        "-o",
        lock.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("wrote 4 blobs"));
    let text = fs::read_to_string(&lock).unwrap();
    assert!(text.starts_with("# blobfind lock v1\n"));
    assert_eq!(text.lines().count(), 5, "header + 4 entries: {text}");

    // The lock file itself is text and must not disturb the census.
    let out = run(&["diff", d.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "clean diff must exit 0: {}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("baseline OK — 4 blobs, no drift"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn diff_flags_added_changed_and_removed_blobs() {
    let d = fixture("drift");
    let lock = d.join("baseline.lock");
    run(&[
        "snapshot",
        d.to_str().unwrap(),
        "-o",
        lock.to_str().unwrap(),
    ]);

    // A new binary appears, an existing one changes, the blob disappears.
    fs::write(d.join("node_modules/sharp/vendored.so"), elf_so()).unwrap();
    let mut patched = elf_so();
    patched[0x12] = 183; // now AArch64
    fs::write(
        d.join("node_modules/sharp/build/Release/sharp.node"),
        patched,
    )
    .unwrap();
    fs::remove_file(d.join("mystery.bin")).unwrap();

    let out = run(&[
        "diff",
        d.to_str().unwrap(),
        "--against",
        lock.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1), "drift must exit 1");
    let text = stdout(&out);
    assert!(text.contains("+ added"));
    assert!(text.contains("vendored.so"));
    assert!(text.contains("~ changed"));
    assert!(text.contains("sharp.node"));
    assert!(text.contains("- removed"));
    assert!(text.contains("mystery.bin"));
    assert!(text.contains("drift: 1 added · 1 removed · 1 changed (baseline had 4 blobs)"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn diff_with_missing_or_corrupt_baseline_is_an_error() {
    let d = tempdir("badbase");
    let out = run(&["diff", d.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("cannot read baseline"));

    fs::write(
        d.join("blobfind.lock"),
        "# blobfind lock v1\ngarbage line\n",
    )
    .unwrap();
    let out = run(&["diff", d.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("line 2"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn usage_errors_exit_2_with_a_pointer_to_help() {
    let out = run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown command"));
    assert!(stderr(&out).contains("--help"));

    let out = run(&["scan", "--frob"]);
    assert_eq!(out.status.code(), Some(2));

    let out = run(&["scan", "/nonexistent/blobfind-no-such-dir"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("not a directory"));

    let out = run(&["explain", "/nonexistent/blobfind-no-such-file.so"]);
    assert_eq!(out.status.code(), Some(2));
}
