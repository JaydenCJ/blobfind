//! The census engine: walks a tree, sniffs every file, classifies findings
//! into `native` / `archive` / `opaque`, hashes them, and attaches
//! provenance and hints. Pure filesystem reads; the output is deterministic
//! for a given tree.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::entropy::Counter;
use crate::provenance::{self, Provenance};
use crate::sha256::Sha256;
use crate::sniff::{self, ElfType, Format, MachType};
use crate::util;
use crate::walk;

/// Scan configuration; see `blobfind scan --help` for the user-facing story.
pub struct Config {
    pub root: PathBuf,
    /// Bits/byte at or above which an unrecognized file counts as opaque.
    pub entropy_threshold: f64,
    /// Unrecognized files smaller than this are never opaque findings.
    pub min_blob: u64,
    /// Include media/font extensions in opaque classification (`--all`).
    pub include_media: bool,
    /// Drop archive findings entirely (`--no-archives`).
    pub skip_archives: bool,
}

/// Default bits/byte at or above which unrecognized data counts as opaque.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 7.5;

impl Config {
    pub fn new(root: PathBuf) -> Self {
        Config {
            root,
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            min_blob: 4096,
            include_media: false,
            skip_archives: false,
        }
    }
}

/// Coarse classification of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Executable machine or byte code: ELF, Mach-O, PE, Wasm, class, ar.
    Native,
    /// A container format that can smuggle binaries: zip, gzip, tar, …
    Archive,
    /// Unrecognized high-entropy data.
    Opaque,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Native => "native",
            Kind::Archive => "archive",
            Kind::Opaque => "opaque",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "native" => Some(Kind::Native),
            "archive" => Some(Kind::Archive),
            "opaque" => Some(Kind::Opaque),
            _ => None,
        }
    }
}

/// One inventoried blob.
pub struct Finding {
    pub rel: String,
    pub size: u64,
    pub kind: Kind,
    pub format: String,
    pub arch: Option<String>,
    pub entropy: f64,
    pub sha256: String,
    pub provenance: Provenance,
    /// Path inside the owning package, when one was identified.
    pub inner: Option<String>,
    pub hints: Vec<String>,
}

/// The result of a scan.
pub struct Census {
    pub root: PathBuf,
    pub files_scanned: u64,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

/// Extensions that are high-entropy by nature but not executable content:
/// images, fonts, audio/video, documents. Skipped for opaque classification
/// unless `--all` is given. Recognized container/binary magics always win
/// over the extension, so a "PNG" that is really an ELF is still reported.
const MEDIA_EXTS: [&str; 26] = [
    "png", "jpg", "jpeg", "gif", "webp", "avif", "ico", "icns", "bmp", "tif", "tiff", "heic",
    "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "m4a", "ogg", "wav", "webm", "flac", "mov",
    "pdf",
];

fn is_media_ext(path: &Path) -> bool {
    util::extension(path)
        .map(|e| MEDIA_EXTS.contains(&e.as_str()))
        .unwrap_or(false)
}

/// Hash + entropy in a single streaming pass over the file.
fn digest_file(path: &Path) -> std::io::Result<(String, f64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut counter = Counter::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        counter.update(&buf[..n]);
    }
    Ok((hasher.finish_hex(), counter.bits_per_byte()))
}

fn read_header(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; sniff::HEADER_LEN];
    let mut filled = 0;
    while filled < buf.len() {
        let n = file.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Provenance- and path-derived hints that tell the auditor *why* this blob
/// is probably here. Ordered from most to least specific.
pub fn hints_for(
    rel: &str,
    kind: Kind,
    format: Option<&Format>,
    prov: &Provenance,
    inner: Option<&str>,
    entropy: f64,
    entropy_threshold: f64,
) -> Vec<String> {
    let mut hints = Vec::new();
    let inner = inner.unwrap_or(rel);
    let ext = Path::new(rel)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    if inner.starts_with("prebuilds/") || inner.contains("/prebuilds/") {
        hints.push("prebuilt binary shipped inside the package (prebuilds/)".into());
    }
    if inner.contains("build/Release/") {
        hints.push(
            "node-gyp build output (build/Release/) — compiled on this machine at install time"
                .into(),
        );
    }
    if ext == "node" {
        hints.push("Node.js native addon — loaded straight into the node process".into());
    }
    if prov.ecosystem == Some("pip") {
        if let Some(Format::Elf {
            etype: ElfType::SharedObject,
            ..
        })
        | Some(Format::MachO {
            filetype: MachType::Dylib | MachType::Bundle,
            ..
        }) = format
        {
            hints.push("compiled Python extension module — imported like plain Python".into());
        }
    }
    if let Some(Format::Elf {
        etype: ElfType::Relocatable,
        ..
    }) = format
    {
        hints.push("precompiled object file — linked into builds without compilation".into());
    }
    if matches!(format, Some(Format::Zip)) {
        match ext.as_str() {
            "jar" | "war" => hints.push("Java archive — contains compiled bytecode".into()),
            "whl" => hints.push("Python wheel — may contain compiled extensions".into()),
            "egg" => hints.push("Python egg — may contain compiled extensions".into()),
            "apk" | "aar" => hints.push("Android archive — contains compiled code".into()),
            _ => {}
        }
    }
    if matches!(
        format,
        Some(Format::Gzip | Format::Xz | Format::Zstd | Format::Bzip2 | Format::Tar)
    ) && (inner.contains(".tar.")
        || inner.ends_with(".tgz")
        || matches!(format, Some(Format::Tar)))
    {
        hints.push("bundled tarball — may unpack binaries at install time".into());
    }
    if kind == Kind::Opaque {
        // `explain` reports any unrecognized file as opaque, including plain
        // low-entropy data; only claim "statistically random" when it is.
        if entropy >= entropy_threshold {
            hints.push(
                "no known format; content is statistically random (packed, encrypted or compressed)"
                    .into(),
            );
        } else {
            hints.push(
                "no known format, but entropy is low — a scan would not flag this file".into(),
            );
        }
    }
    if prov.package.is_none() {
        hints.push("no package manifest found above this file".into());
    }
    hints
}

fn classify(header: &[u8], size: u64, path: &Path, cfg: &Config) -> Option<(Kind, Option<Format>)> {
    if let Some(format) = sniff::detect(header, size) {
        let kind = if format.is_native() {
            Kind::Native
        } else {
            Kind::Archive
        };
        if kind == Kind::Archive && cfg.skip_archives {
            return None;
        }
        return Some((kind, Some(format)));
    }
    // Unknown format: only large, non-media files can qualify as opaque.
    if size < cfg.min_blob {
        return None;
    }
    if !cfg.include_media && is_media_ext(path) {
        return None;
    }
    Some((Kind::Opaque, None))
}

/// Run the census over `cfg.root`.
pub fn scan(cfg: &Config) -> Census {
    let mut findings = Vec::new();
    // Both the visit and warn closures report problems; share the sink.
    let warnings = std::cell::RefCell::new(Vec::new());
    let mut files_scanned = 0u64;

    walk::walk_files(
        &cfg.root,
        &mut |entry| {
            files_scanned += 1;
            if entry.size == 0 {
                return;
            }
            let header = match read_header(&entry.path) {
                Ok(h) => h,
                Err(err) => {
                    warnings
                        .borrow_mut()
                        .push(format!("cannot read {}: {err}", entry.path.display()));
                    return;
                }
            };
            let Some((kind, format)) = classify(&header, entry.size, &entry.path, cfg) else {
                return;
            };
            let (sha256, entropy) = match digest_file(&entry.path) {
                Ok(pair) => pair,
                Err(err) => {
                    warnings
                        .borrow_mut()
                        .push(format!("cannot read {}: {err}", entry.path.display()));
                    return;
                }
            };
            // Opaque status is decided by measured entropy over the whole file.
            if kind == Kind::Opaque && entropy < cfg.entropy_threshold {
                return;
            }
            let rel = util::rel_slash(&cfg.root, &entry.path);
            let provenance = provenance::resolve(&cfg.root, &entry.path);
            let inner = provenance.inner(&entry.path);
            let hints = hints_for(
                &rel,
                kind,
                format.as_ref(),
                &provenance,
                inner.as_deref(),
                entropy,
                cfg.entropy_threshold,
            );
            findings.push(Finding {
                rel,
                size: entry.size,
                kind,
                format: format
                    .as_ref()
                    .map(|f| f.describe())
                    .unwrap_or_else(|| "high-entropy data".into()),
                arch: format.as_ref().and_then(|f| f.arch()),
                entropy,
                sha256,
                provenance,
                inner,
                hints,
            });
        },
        &mut |w| warnings.borrow_mut().push(w),
    );

    findings.sort_by(|a, b| a.rel.cmp(&b.rel));
    Census {
        root: cfg.root.clone(),
        files_scanned,
        findings,
        warnings: warnings.into_inner(),
    }
}

/// Inspect a single file the way the scanner would, regardless of size or
/// entropy thresholds (used by `blobfind explain`).
pub fn inspect_file(root: &Path, path: &Path) -> std::io::Result<Finding> {
    let meta = std::fs::metadata(path)?;
    let header = read_header(path)?;
    let format = sniff::detect(&header, meta.len());
    let (sha256, entropy) = digest_file(path)?;
    let kind = match &format {
        Some(f) if f.is_native() => Kind::Native,
        Some(_) => Kind::Archive,
        None => Kind::Opaque,
    };
    let rel = util::rel_slash(root, path);
    let provenance = provenance::resolve(root, path);
    let inner = provenance.inner(path);
    let hints = hints_for(
        &rel,
        kind,
        format.as_ref(),
        &provenance,
        inner.as_deref(),
        entropy,
        DEFAULT_ENTROPY_THRESHOLD,
    );
    Ok(Finding {
        rel,
        size: meta.len(),
        kind,
        format: format
            .as_ref()
            .map(|f| f.describe())
            .unwrap_or_else(|| "unrecognized data".into()),
        arch: format.as_ref().and_then(|f| f.arch()),
        entropy,
        sha256,
        provenance,
        inner,
        hints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("blobfind-inv-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A minimal ELF shared object (x86-64, little-endian).
    fn elf_so() -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[0x10] = 3;
        b[0x12] = 62;
        b
    }

    /// Deterministic pseudo-random bytes that hit ~8 bits/byte of entropy.
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

    #[test]
    fn finds_an_elf_inside_node_modules_with_provenance() {
        let d = tempdir("elf");
        let pkg = d.join("node_modules/sharp");
        fs::create_dir_all(pkg.join("build/Release")).unwrap();
        fs::write(
            pkg.join("package.json"),
            r#"{"name":"sharp","version":"0.33.4"}"#,
        )
        .unwrap();
        fs::write(pkg.join("build/Release/sharp.node"), elf_so()).unwrap();
        fs::write(pkg.join("index.js"), "module.exports = 1;\n").unwrap();

        let census = scan(&Config::new(d.clone()));
        assert_eq!(census.findings.len(), 1);
        let f = &census.findings[0];
        assert_eq!(f.kind, Kind::Native);
        assert_eq!(f.format, "ELF shared object");
        assert_eq!(f.arch.as_deref(), Some("x86-64 (64-bit)"));
        assert_eq!(f.provenance.label(), "npm · sharp@0.33.4");
        assert!(f.hints.iter().any(|h| h.contains("node-gyp")));
        assert!(f.hints.iter().any(|h| h.contains("native addon")));
        assert_eq!(f.sha256.len(), 64);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn source_and_empty_files_produce_no_findings() {
        let d = tempdir("clean");
        fs::create_dir_all(d.join("src")).unwrap();
        fs::write(d.join("src/lib.js"), "export const x = 1;\n").unwrap();
        fs::write(d.join("README.md"), "# hello\n").unwrap();
        fs::write(d.join("empty.so"), b"").unwrap();
        let census = scan(&Config::new(d.clone()));
        assert_eq!(census.files_scanned, 3);
        assert!(census.findings.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn high_entropy_unknown_file_is_opaque() {
        let d = tempdir("opaque");
        fs::write(d.join("payload.bin"), noise(8192)).unwrap();
        let census = scan(&Config::new(d.clone()));
        assert_eq!(census.findings.len(), 1);
        let f = &census.findings[0];
        assert_eq!(f.kind, Kind::Opaque);
        assert!(f.entropy > 7.5, "noise entropy was {}", f.entropy);
        assert!(f.hints.iter().any(|h| h.contains("statistically random")));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unknown_files_below_either_threshold_are_skipped() {
        let d = tempdir("thresholds");
        // High entropy but under the min-blob floor: too small to matter.
        fs::write(d.join("tiny.bin"), noise(512)).unwrap();
        // Large but low entropy: not statistically opaque.
        fs::write(d.join("data.bin"), vec![7u8; 100_000]).unwrap();
        let census = scan(&Config::new(d.clone()));
        assert!(census.findings.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn media_extensions_are_exempt_unless_all() {
        let d = tempdir("media");
        fs::write(d.join("photo.jpg"), noise(8192)).unwrap();
        let mut cfg = Config::new(d.clone());
        assert!(scan(&cfg).findings.is_empty());
        cfg.include_media = true;
        assert_eq!(scan(&cfg).findings.len(), 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn media_extension_does_not_hide_a_real_elf() {
        // Extension exemption applies to *unrecognized* content only: an ELF
        // renamed to .png is exactly the smuggling trick a census must catch.
        let d = tempdir("disguise");
        fs::write(d.join("logo.png"), elf_so()).unwrap();
        let census = scan(&Config::new(d.clone()));
        assert_eq!(census.findings.len(), 1);
        assert_eq!(census.findings[0].kind, Kind::Native);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn archives_reported_by_default_suppressed_by_flag() {
        let d = tempdir("arch");
        let mut gz = vec![0x1f, 0x8b, 0x08];
        gz.extend(noise(4096));
        fs::write(d.join("prebuild.tar.gz"), &gz).unwrap();
        let mut cfg = Config::new(d.clone());
        let census = scan(&cfg);
        assert_eq!(census.findings.len(), 1);
        assert_eq!(census.findings[0].kind, Kind::Archive);
        assert!(census.findings[0]
            .hints
            .iter()
            .any(|h| h.contains("unpack binaries")));
        cfg.skip_archives = true;
        assert!(scan(&cfg).findings.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn entropy_threshold_is_configurable() {
        let d = tempdir("thresh");
        // ASCII base64-ish text: ~6 bits/byte, below 7.5 but above 5.0.
        let data: Vec<u8> = (0..8192u32)
            .map(|i| {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    [(i % 64) as usize]
            })
            .collect();
        fs::write(d.join("encoded.dat"), &data).unwrap();
        let mut cfg = Config::new(d.clone());
        assert!(scan(&cfg).findings.is_empty());
        cfg.entropy_threshold = 5.0;
        assert_eq!(scan(&cfg).findings.len(), 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn wasm_and_wheel_are_inventoried_in_path_order() {
        let d = tempdir("mix");
        fs::write(d.join("mod.wasm"), b"\0asm\x01\0\0\0more").unwrap();
        let mut whl = b"PK\x03\x04".to_vec();
        whl.extend(noise(1024));
        fs::write(d.join("vendored-1.0-py3-none-any.whl"), &whl).unwrap();
        let census = scan(&Config::new(d.clone()));
        let rels: Vec<&str> = census.findings.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, vec!["mod.wasm", "vendored-1.0-py3-none-any.whl"]);
        assert_eq!(census.findings[0].kind, Kind::Native);
        let whl = &census.findings[1];
        assert_eq!(whl.kind, Kind::Archive);
        assert!(whl.hints.iter().any(|h| h.contains("wheel")));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn inspect_file_reports_even_boring_files() {
        let d = tempdir("inspect");
        let file = d.join("notes.txt");
        fs::write(&file, "hello world\n").unwrap();
        let f = inspect_file(&d, &file).unwrap();
        assert_eq!(f.kind, Kind::Opaque);
        assert_eq!(f.format, "unrecognized data");
        assert_eq!(f.sha256, crate::sha256::hex_digest(b"hello world\n"));
        // Low-entropy plain text must not be described as statistically
        // random; the hint has to stay honest about what a scan would do.
        assert!(
            f.hints.iter().any(|h| h.contains("entropy is low")),
            "{:?}",
            f.hints
        );
        assert!(!f.hints.iter().any(|h| h.contains("statistically random")));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn prebuilds_hint_fires_on_inner_path() {
        let d = tempdir("prebuilds");
        let pkg = d.join("node_modules/classic-level/prebuilds/linux-x64");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(pkg.join("node.napi.node"), elf_so()).unwrap();
        let census = scan(&Config::new(d.clone()));
        assert_eq!(census.findings.len(), 1);
        assert!(census.findings[0]
            .hints
            .iter()
            .any(|h| h.contains("prebuilds/")));
        let _ = fs::remove_dir_all(&d);
    }
}
