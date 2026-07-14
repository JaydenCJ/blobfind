//! Provenance resolution: given a file deep inside a dependency tree, name
//! the package that shipped it. Layout conventions are used first
//! (`node_modules/<pkg>`, `site-packages/<pkg>`, `vendor/<crate>`,
//! Go `vendor/modules.txt`, Bundler `gems/<name>-<ver>`), then the nearest
//! manifest file as a fallback. Everything is read from disk state the
//! package managers already wrote — no network, no tool invocations.

use std::fs;
use std::path::{Path, PathBuf};

/// Which package shipped a file, as far as the tree layout can tell.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Provenance {
    pub ecosystem: Option<&'static str>,
    pub package: Option<String>,
    pub version: Option<String>,
    /// Root directory of the owning package, when one was identified.
    pub package_root: Option<PathBuf>,
}

impl Provenance {
    /// Grouping label, e.g. `npm · sharp@0.33.4` or `unattributed`.
    pub fn label(&self) -> String {
        match (&self.ecosystem, &self.package) {
            (Some(eco), Some(pkg)) => match &self.version {
                Some(v) => format!("{eco} · {pkg}@{v}"),
                None => format!("{eco} · {pkg}"),
            },
            _ => "unattributed".to_string(),
        }
    }

    /// Path of `file` inside the package root, `/`-separated.
    pub fn inner(&self, file: &Path) -> Option<String> {
        let root = self.package_root.as_ref()?;
        Some(crate::util::rel_slash(root, file))
    }
}

/// Extract the first top-ish-level string value for `key` from a JSON
/// document. Not a full parser — package.json `name`/`version` are reliably
/// simple strings, and a miss only degrades a label, never correctness.
pub fn json_str_field(src: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut search_from = 0;
    while let Some(pos) = src[search_from..].find(&needle) {
        let after = search_from + pos + needle.len();
        let rest = src[after..].trim_start();
        if let Some(rest) = rest.strip_prefix(':') {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('"') {
                let mut out = String::new();
                let mut chars = rest.chars();
                while let Some(c) = chars.next() {
                    match c {
                        '"' => return Some(out),
                        '\\' => {
                            if let Some(esc) = chars.next() {
                                out.push(match esc {
                                    'n' => '\n',
                                    't' => '\t',
                                    other => other,
                                });
                            }
                        }
                        other => out.push(other),
                    }
                }
                return None; // unterminated string
            }
        }
        search_from = after;
    }
    None
}

/// Extract `key = "value"` from the `[package]` section of a Cargo.toml.
pub fn toml_package_field(src: &str, key: &str) -> Option<String> {
    let mut in_package = false;
    for line in src.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                let rest = rest.strip_prefix('"')?;
                return rest.split('"').next().map(|s| s.to_string());
            }
        }
    }
    None
}

/// PEP 503-style normalization so `Pillow` matches `pillow-10.3.0.dist-info`.
fn pep503(name: &str) -> String {
    name.to_ascii_lowercase().replace(['-', '.'], "_")
}

fn dir_name(p: &Path) -> Option<String> {
    p.file_name().map(|n| n.to_string_lossy().into_owned())
}

fn npm_package(dir: &Path) -> Option<Provenance> {
    let parent = dir.parent()?;
    let name = dir_name(dir)?;
    // node_modules/<pkg> or node_modules/@scope/<pkg>.
    let full_name = if dir_name(parent).as_deref() == Some("node_modules") {
        if name.starts_with('@') {
            return None; // scope directory itself, not a package
        }
        name
    } else if dir_name(parent)
        .map(|n| n.starts_with('@'))
        .unwrap_or(false)
        && parent.parent().and_then(dir_name).as_deref() == Some("node_modules")
    {
        format!("{}/{}", dir_name(parent)?, name)
    } else {
        return None;
    };
    let manifest = fs::read_to_string(dir.join("package.json")).unwrap_or_default();
    let pkg = json_str_field(&manifest, "name").unwrap_or(full_name);
    Some(Provenance {
        ecosystem: Some("npm"),
        package: Some(pkg),
        version: json_str_field(&manifest, "version"),
        package_root: Some(dir.to_path_buf()),
    })
}

/// Version lookup via `<name>-<version>.dist-info` siblings in site-packages.
fn pip_dist_info_version(site: &Path, package: &str) -> Option<String> {
    let want = pep503(package);
    let entries = fs::read_dir(site).ok()?;
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok().and_then(|e| dir_name(&e.path())))
        .filter(|n| n.ends_with(".dist-info"))
        .collect();
    names.sort();
    for n in names {
        let stem = n.trim_end_matches(".dist-info");
        if let Some((dist_name, version)) = stem.rsplit_once('-') {
            if pep503(dist_name) == want {
                return Some(version.to_string());
            }
        }
    }
    None
}

fn is_site_packages(name: &str) -> bool {
    name == "site-packages" || name == "dist-packages"
}

fn pip_package(dir: &Path) -> Option<Provenance> {
    let parent = dir.parent()?;
    if !is_site_packages(&dir_name(parent)?) {
        return None;
    }
    let name = dir_name(dir)?;
    if name.ends_with(".dist-info") || name.ends_with(".data") || name == "__pycache__" {
        return None;
    }
    Some(Provenance {
        ecosystem: Some("pip"),
        package: Some(name.clone()),
        version: pip_dist_info_version(parent, &name),
        package_root: Some(dir.to_path_buf()),
    })
}

/// A `.so`/`.pyd` sitting directly in site-packages (single-file extension
/// modules like `_cffi_backend.cpython-312-x86_64-linux-gnu.so`).
fn pip_toplevel_module(file: &Path) -> Option<Provenance> {
    let site = file.parent()?;
    if !is_site_packages(&dir_name(site)?) {
        return None;
    }
    let stem = file.file_name()?.to_string_lossy().into_owned();
    let module = stem.split('.').next()?.to_string();
    let version = pip_dist_info_version(site, &module);
    Some(Provenance {
        ecosystem: Some("pip"),
        package: Some(module),
        version,
        package_root: Some(site.to_path_buf()),
    })
}

fn cargo_package(dir: &Path) -> Option<Provenance> {
    let manifest_path = dir.join("Cargo.toml");
    if !manifest_path.is_file() {
        return None;
    }
    let src = fs::read_to_string(&manifest_path).ok()?;
    let name = toml_package_field(&src, "name")?;
    Some(Provenance {
        ecosystem: Some("cargo"),
        package: Some(name),
        version: toml_package_field(&src, "version"),
        package_root: Some(dir.to_path_buf()),
    })
}

/// Bundler layout: `gems/<name>-<version>/…` where version starts the first
/// dash-separated component that begins with a digit.
fn gem_package(dir: &Path) -> Option<Provenance> {
    if dir_name(dir.parent()?)? != "gems" {
        return None;
    }
    let full = dir_name(dir)?;
    let mut split_at = None;
    for (idx, part) in full.match_indices('-') {
        if full[idx + 1..].starts_with(|c: char| c.is_ascii_digit()) {
            split_at = Some((idx, part));
            break;
        }
    }
    let (idx, _) = split_at?;
    Some(Provenance {
        ecosystem: Some("gem"),
        package: Some(full[..idx].to_string()),
        version: Some(full[idx + 1..].to_string()),
        package_root: Some(dir.to_path_buf()),
    })
}

/// Go vendored deps: `vendor/modules.txt` lists `# <module> <version>` lines;
/// the owning module is the longest one whose path prefixes the file's path
/// under `vendor/`.
fn go_vendor_package(vendor: &Path, file: &Path) -> Option<Provenance> {
    let txt = fs::read_to_string(vendor.join("modules.txt")).ok()?;
    let rel = crate::util::rel_slash(vendor, file);
    let mut best: Option<(usize, String, String)> = None;
    for line in txt.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("# ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let (Some(module), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !version.starts_with('v') {
            continue; // marker lines like "# explicit"
        }
        if rel == module || rel.starts_with(&format!("{module}/")) {
            let len = module.len();
            if best.as_ref().map(|(l, _, _)| len > *l).unwrap_or(true) {
                best = Some((len, module.to_string(), version.to_string()));
            }
        }
    }
    let (_, module, version) = best?;
    Some(Provenance {
        ecosystem: Some("go"),
        package: Some(module.clone()),
        version: Some(version),
        package_root: Some(vendor.join(module)),
    })
}

/// Fallback: the nearest directory holding a recognizable manifest.
fn manifest_fallback(dir: &Path) -> Option<Provenance> {
    if dir.join("package.json").is_file() {
        let src = fs::read_to_string(dir.join("package.json")).unwrap_or_default();
        return Some(Provenance {
            ecosystem: Some("npm"),
            package: json_str_field(&src, "name").or_else(|| dir_name(dir)),
            version: json_str_field(&src, "version"),
            package_root: Some(dir.to_path_buf()),
        });
    }
    if dir.join("Cargo.toml").is_file() {
        return cargo_package(dir);
    }
    if dir.join("pyproject.toml").is_file() || dir.join("setup.py").is_file() {
        return Some(Provenance {
            ecosystem: Some("pip"),
            package: dir_name(dir),
            version: None,
            package_root: Some(dir.to_path_buf()),
        });
    }
    if dir.join("go.mod").is_file() {
        let src = fs::read_to_string(dir.join("go.mod")).unwrap_or_default();
        let module = src.lines().find_map(|l| {
            l.trim()
                .strip_prefix("module ")
                .map(|m| m.trim().to_string())
        });
        return Some(Provenance {
            ecosystem: Some("go"),
            package: module.or_else(|| dir_name(dir)),
            version: None,
            package_root: Some(dir.to_path_buf()),
        });
    }
    if dir.join("composer.json").is_file() {
        let src = fs::read_to_string(dir.join("composer.json")).unwrap_or_default();
        return Some(Provenance {
            ecosystem: Some("composer"),
            package: json_str_field(&src, "name").or_else(|| dir_name(dir)),
            version: json_str_field(&src, "version"),
            package_root: Some(dir.to_path_buf()),
        });
    }
    None
}

/// Resolve provenance for `file`, looking at ancestors up to and including
/// `root`. Layout conventions win over generic manifest fallback, and the
/// nearest ancestor wins within each pass.
pub fn resolve(root: &Path, file: &Path) -> Provenance {
    if let Some(p) = pip_toplevel_module(file) {
        return p;
    }
    // Scans only ever hand over files under `root`, and their attribution is
    // scoped to it. `explain` may be handed a file outside the provenance
    // root; walking up to a root that does not contain the file would pin
    // the finding on whatever manifest happens to live there, so in that
    // case follow the file's real ancestry instead.
    let bounded = file.starts_with(root);
    let ancestors = || -> Box<dyn Iterator<Item = &Path>> {
        if bounded {
            Box::new(
                file.ancestors()
                    .skip(1) // the file itself
                    .take_while(move |a| a.starts_with(root) && *a != root)
                    .chain(std::iter::once(root)),
            )
        } else {
            Box::new(file.ancestors().skip(1))
        }
    };
    // Pass 1: explicit dependency-tree layouts (highest confidence).
    for dir in ancestors() {
        if let Some(p) = npm_package(dir) {
            return p;
        }
        if let Some(p) = pip_package(dir) {
            return p;
        }
        if let Some(p) = gem_package(dir) {
            return p;
        }
        if dir_name(dir).as_deref() == Some("vendor") {
            if let Some(p) = go_vendor_package(dir, file) {
                return p;
            }
            // cargo vendor: vendor/<crate>/Cargo.toml — handled by the
            // manifest fallback below since the crate dir holds a manifest.
        }
    }
    // Pass 2: nearest manifest of any kind.
    for dir in ancestors() {
        if let Some(p) = manifest_fallback(dir) {
            return p;
        }
    }
    Provenance::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("blobfind-prov-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn json_str_field_extracts_values_escapes_and_skips_non_string_hits() {
        let src = r#"{ "name": "sharp", "version": "0.33.4" }"#;
        assert_eq!(json_str_field(src, "name").as_deref(), Some("sharp"));
        assert_eq!(json_str_field(src, "version").as_deref(), Some("0.33.4"));
        assert_eq!(json_str_field(src, "missing"), None);
        assert_eq!(
            json_str_field(r#"{"name": "a\"b\\c"}"#, "name").as_deref(),
            Some("a\"b\\c")
        );
        // A first occurrence with a non-string value must not end the search.
        let src = r#"{"scripts": {"version": {"x": 1}}, "version": "2.0.0"}"#;
        assert_eq!(json_str_field(src, "version").as_deref(), Some("2.0.0"));
    }

    #[test]
    fn toml_package_field_reads_only_the_package_section() {
        let src =
            "[dependencies]\nname = \"decoy\"\n[package]\nname = \"ring\"\nversion = \"0.17.8\"\n";
        assert_eq!(toml_package_field(src, "name").as_deref(), Some("ring"));
        assert_eq!(
            toml_package_field(src, "version").as_deref(),
            Some("0.17.8")
        );
    }

    #[test]
    fn npm_plain_package_with_manifest_version() {
        let d = tempdir("npm");
        let pkg = d.join("node_modules/sharp");
        fs::create_dir_all(pkg.join("build/Release")).unwrap();
        fs::write(
            pkg.join("package.json"),
            r#"{"name": "sharp", "version": "0.33.4"}"#,
        )
        .unwrap();
        let file = pkg.join("build/Release/sharp.node");
        fs::write(&file, "x").unwrap();
        let p = resolve(&d, &file);
        assert_eq!(p.label(), "npm · sharp@0.33.4");
        assert_eq!(p.inner(&file).as_deref(), Some("build/Release/sharp.node"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn npm_scoped_package_resolves_scope_and_name() {
        let d = tempdir("npm-scope");
        let pkg = d.join("node_modules/@img/sharp-linux-x64");
        fs::create_dir_all(pkg.join("lib")).unwrap();
        let file = pkg.join("lib/sharp-linux-x64.node");
        fs::write(&file, "x").unwrap();
        let p = resolve(&d, &file);
        assert_eq!(p.ecosystem, Some("npm"));
        // No package.json — the directory layout still names the package.
        assert_eq!(p.package.as_deref(), Some("@img/sharp-linux-x64"));
        assert_eq!(p.version, None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn npm_nested_node_modules_attributes_to_the_innermost() {
        let d = tempdir("npm-nested");
        let inner = d.join("node_modules/outer/node_modules/inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(
            inner.join("package.json"),
            r#"{"name":"inner","version":"1.0.0"}"#,
        )
        .unwrap();
        let file = inner.join("payload.so");
        fs::write(&file, "x").unwrap();
        assert_eq!(resolve(&d, &file).label(), "npm · inner@1.0.0");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn pip_package_version_comes_from_dist_info() {
        let d = tempdir("pip");
        let site = d.join("venv/lib/python3.12/site-packages");
        fs::create_dir_all(site.join("PIL")).unwrap();
        fs::create_dir_all(site.join("pillow-10.3.0.dist-info")).unwrap();
        let file = site.join("PIL/_imaging.cpython-312-x86_64-linux-gnu.so");
        fs::write(&file, "x").unwrap();
        let p = resolve(&d, &file);
        assert_eq!(p.ecosystem, Some("pip"));
        assert_eq!(p.package.as_deref(), Some("PIL"));
        // PIL's dist-info is named pillow-*; only same-named dists match, so
        // the version stays honest-unknown rather than guessed.
        assert_eq!(p.version, None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn pip_matching_dist_info_supplies_the_version() {
        let d = tempdir("pip-ver");
        let site = d.join("site-packages");
        fs::create_dir_all(site.join("numpy/core")).unwrap();
        fs::create_dir_all(site.join("numpy-1.26.4.dist-info")).unwrap();
        let file = site.join("numpy/core/_multiarray_umath.so");
        fs::write(&file, "x").unwrap();
        assert_eq!(resolve(&d, &file).label(), "pip · numpy@1.26.4");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn pip_toplevel_extension_module_in_site_packages() {
        let d = tempdir("pip-top");
        let site = d.join("site-packages");
        fs::create_dir_all(site.join("_cffi_backend-1.16.0.dist-info")).unwrap();
        let file = site.join("_cffi_backend.cpython-312-x86_64-linux-gnu.so");
        fs::write(&file, "x").unwrap();
        let p = resolve(&d, &file);
        assert_eq!(p.label(), "pip · _cffi_backend@1.16.0");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn cargo_vendored_crate_via_manifest() {
        let d = tempdir("cargo");
        let krate = d.join("vendor/ring");
        fs::create_dir_all(krate.join("pregenerated")).unwrap();
        fs::write(
            krate.join("Cargo.toml"),
            "[package]\nname = \"ring\"\nversion = \"0.17.8\"\n",
        )
        .unwrap();
        let file = krate.join("pregenerated/aesni-x86_64-elf.o");
        fs::write(&file, "x").unwrap();
        assert_eq!(resolve(&d, &file).label(), "cargo · ring@0.17.8");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn go_vendor_longest_module_prefix_wins() {
        let d = tempdir("go");
        let vendor = d.join("vendor");
        fs::create_dir_all(vendor.join("example.test/tool/sub")).unwrap();
        fs::write(
            vendor.join("modules.txt"),
            "# example.test/tool v1.2.3\n## explicit; go 1.22\nexample.test/tool\n# example.test/tool/sub v2.0.0\nexample.test/tool/sub\n",
        )
        .unwrap();
        let file = vendor.join("example.test/tool/sub/blob.bin");
        fs::write(&file, "x").unwrap();
        let p = resolve(&d, &file);
        assert_eq!(p.label(), "go · example.test/tool/sub@v2.0.0");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn gem_layout_splits_name_and_version() {
        let d = tempdir("gem");
        let gem = d.join("gems/nokogiri-1.16.5-x86_64-linux");
        fs::create_dir_all(gem.join("lib")).unwrap();
        let file = gem.join("lib/nokogiri.so");
        fs::write(&file, "x").unwrap();
        let p = resolve(&d, &file);
        assert_eq!(p.ecosystem, Some("gem"));
        assert_eq!(p.package.as_deref(), Some("nokogiri"));
        assert_eq!(p.version.as_deref(), Some("1.16.5-x86_64-linux"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unattributed_when_nothing_matches_and_lookup_stops_at_root() {
        let d = tempdir("none");
        fs::create_dir_all(d.join("assets")).unwrap();
        let file = d.join("assets/blob.bin");
        fs::write(&file, "x").unwrap();
        let p = resolve(&d, &file);
        assert_eq!(p.label(), "unattributed");
        assert_eq!(p.package_root, None);
        // A manifest *above* the scan root must not be consulted: the census
        // is scoped to what was asked for.
        fs::write(
            d.join("package.json"),
            r#"{"name":"app","version":"1.0.0"}"#,
        )
        .unwrap();
        let p = resolve(&d.join("assets"), &file);
        assert_eq!(p.label(), "unattributed");
        // But a file *outside* the root (only `explain` can produce this)
        // follows its own ancestry instead of borrowing whatever manifest
        // happens to live at the unrelated root.
        let elsewhere = d.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let p = resolve(&elsewhere, &file);
        assert_eq!(p.label(), "npm · app@1.0.0");
        let _ = fs::remove_dir_all(&d);
    }
}
