//! The lock file: a deterministic, git-diffable census baseline. One line
//! per blob (`sha256 size kind path`), sorted by path, so `blobfind diff`
//! can prove that nothing executable appeared, vanished or changed between
//! two installs — the check auditors actually ask for.

use std::collections::BTreeMap;

use crate::inventory::{Census, Kind};

pub const HEADER: &str = "# blobfind lock v1";

/// One line of the lock file.
#[derive(Debug, Clone, PartialEq)]
pub struct LockEntry {
    pub sha256: String,
    pub size: u64,
    pub kind: Kind,
    pub path: String,
}

/// Convert a census into lock entries (already sorted by path).
pub fn entries_from(census: &Census) -> Vec<LockEntry> {
    census
        .findings
        .iter()
        .map(|f| LockEntry {
            sha256: f.sha256.clone(),
            size: f.size,
            kind: f.kind,
            path: f.rel.clone(),
        })
        .collect()
}

/// Render entries as the lock file text.
pub fn render(entries: &[LockEntry]) -> String {
    let mut out = String::new();
    out.push_str(HEADER);
    out.push('\n');
    for e in entries {
        out.push_str(&format!(
            "{} {} {} {}\n",
            e.sha256,
            e.size,
            e.kind.as_str(),
            e.path
        ));
    }
    out
}

/// Parse lock file text. Errors carry a 1-based line number so a corrupted
/// baseline is diagnosable, not just "invalid".
pub fn parse(src: &str) -> Result<Vec<LockEntry>, String> {
    let mut entries = Vec::new();
    let mut saw_header = false;
    for (idx, line) in src.lines().enumerate() {
        let lineno = idx + 1;
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            if line == HEADER {
                saw_header = true;
            }
            continue;
        }
        let mut parts = line.splitn(4, ' ');
        let (Some(sha), Some(size), Some(kind), Some(path)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("line {lineno}: expected 'sha256 size kind path'"));
        };
        if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("line {lineno}: '{sha}' is not a sha256 hex digest"));
        }
        let size: u64 = size
            .parse()
            .map_err(|_| format!("line {lineno}: '{size}' is not a size"))?;
        let kind =
            Kind::parse(kind).ok_or_else(|| format!("line {lineno}: unknown kind '{kind}'"))?;
        entries.push(LockEntry {
            sha256: sha.to_string(),
            size,
            kind,
            path: path.to_string(),
        });
    }
    if !saw_header && !entries.is_empty() {
        return Err(format!("missing '{HEADER}' header line"));
    }
    Ok(entries)
}

/// Drift between a baseline and the current census.
#[derive(Debug, Default)]
pub struct Drift {
    /// In the tree now, not in the baseline.
    pub added: Vec<LockEntry>,
    /// In the baseline, gone from the tree.
    pub removed: Vec<LockEntry>,
    /// Same path in both, different content: `(baseline, current)`.
    pub changed: Vec<(LockEntry, LockEntry)>,
}

impl Drift {
    pub fn is_clean(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    pub fn total(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }
}

/// Compare `current` against `baseline`, keyed by path.
pub fn diff(baseline: &[LockEntry], current: &[LockEntry]) -> Drift {
    let base: BTreeMap<&str, &LockEntry> = baseline.iter().map(|e| (e.path.as_str(), e)).collect();
    let cur: BTreeMap<&str, &LockEntry> = current.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut drift = Drift::default();
    for (path, entry) in &cur {
        match base.get(path) {
            None => drift.added.push((*entry).clone()),
            Some(old) if old.sha256 != entry.sha256 => {
                drift.changed.push(((*old).clone(), (*entry).clone()));
            }
            Some(_) => {}
        }
    }
    for (path, entry) in &base {
        if !cur.contains_key(path) {
            drift.removed.push((*entry).clone());
        }
    }
    drift
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, sha_seed: u8) -> LockEntry {
        LockEntry {
            sha256: format!("{:064x}", sha_seed as u128),
            size: 100,
            kind: Kind::Native,
            path: path.to_string(),
        }
    }

    #[test]
    fn render_then_parse_round_trips() {
        let entries = vec![
            entry("node_modules/a/lib.so", 1),
            LockEntry {
                sha256: format!("{:064x}", 2u128),
                size: 4096,
                kind: Kind::Opaque,
                path: "vendor/blob with spaces.bin".into(),
            },
        ];
        let text = render(&entries);
        assert!(text.starts_with(HEADER));
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed, entries);
    }

    #[test]
    fn paths_with_spaces_survive_because_path_is_the_last_field() {
        let text = format!(
            "{HEADER}\n{:064x} 9 archive deep/dir/my archive.tar.gz\n",
            3u128
        );
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed[0].path, "deep/dir/my archive.tar.gz");
    }

    #[test]
    fn parse_rejects_bad_digests_sizes_and_kinds_with_line_numbers() {
        let bad_sha = format!("{HEADER}\nnothex 9 native a\n");
        assert!(parse(&bad_sha).unwrap_err().contains("line 2"));

        let bad_size = format!("{HEADER}\n{:064x} lots native a\n", 1u128);
        assert!(parse(&bad_size).unwrap_err().contains("not a size"));

        let bad_kind = format!("{HEADER}\n{:064x} 9 sneaky a\n", 1u128);
        assert!(parse(&bad_kind).unwrap_err().contains("unknown kind"));

        let short = format!("{HEADER}\n{:064x} 9\n", 1u128);
        assert!(parse(&short).unwrap_err().contains("expected"));
    }

    #[test]
    fn parse_requires_the_version_header() {
        let text = format!("{:064x} 9 native a\n", 1u128);
        assert!(parse(&text).unwrap_err().contains("header"));
        // …but an empty lock (clean tree) needs no entries to be valid.
        assert!(parse(HEADER).unwrap().is_empty());
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn diff_reports_added_removed_changed() {
        let baseline = vec![entry("a.so", 1), entry("b.so", 2), entry("c.so", 3)];
        let mut b_changed = entry("b.so", 9);
        b_changed.size = 200;
        let current = vec![entry("a.so", 1), b_changed, entry("d.so", 4)];
        let drift = diff(&baseline, &current);
        assert_eq!(drift.added.len(), 1);
        assert_eq!(drift.added[0].path, "d.so");
        assert_eq!(drift.removed.len(), 1);
        assert_eq!(drift.removed[0].path, "c.so");
        assert_eq!(drift.changed.len(), 1);
        assert_eq!(drift.changed[0].0.sha256, format!("{:064x}", 2u128));
        assert_eq!(drift.changed[0].1.sha256, format!("{:064x}", 9u128));
        assert!(!drift.is_clean());
        assert_eq!(drift.total(), 3);
        // An empty baseline flags everything as added.
        let fresh = diff(&[], &[entry("new.so", 1)]);
        assert_eq!(fresh.added.len(), 1);
        assert!(fresh.removed.is_empty());
    }

    #[test]
    fn identical_sets_are_clean() {
        let baseline = vec![entry("a.so", 1), entry("b.so", 2)];
        let drift = diff(&baseline, &baseline.clone());
        assert!(drift.is_clean());
        assert_eq!(drift.total(), 0);
    }
}
