//! Human-readable output: the grouped scan report, the single-file
//! `explain` view and the baseline diff. Plain aligned text, no color
//! codes, so output is stable under pipes and in CI logs.

use crate::baseline::Drift;
use crate::inventory::{Census, Finding, Kind};
use crate::util::{count_noun, human_size};

fn count(census: &Census, kind: Kind) -> usize {
    census.findings.iter().filter(|f| f.kind == kind).count()
}

fn short_sha(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

/// Group findings by provenance label, `unattributed` sorted last.
fn grouped(census: &Census) -> Vec<(String, Vec<&Finding>)> {
    let mut groups: Vec<(String, Vec<&Finding>)> = Vec::new();
    for f in &census.findings {
        let label = f.provenance.label();
        match groups.iter_mut().find(|(l, _)| *l == label) {
            Some((_, v)) => v.push(f),
            None => groups.push((label, vec![f])),
        }
    }
    groups.sort_by(|a, b| {
        let a_un = a.0 == "unattributed";
        let b_un = b.0 == "unattributed";
        a_un.cmp(&b_un).then_with(|| a.0.cmp(&b.0))
    });
    groups
}

fn render_table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    let mut widths = vec![0usize; cols];
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in rows {
        let mut line = String::from(" ");
        for (i, cell) in row.iter().enumerate() {
            line.push(' ');
            line.push_str(cell);
            if i + 1 < row.len() {
                for _ in cell.chars().count()..widths[i] {
                    line.push(' ');
                }
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The full `blobfind scan` report.
pub fn scan_report(census: &Census) -> String {
    let mut out = String::new();
    let mut packages = 0usize;
    for (label, findings) in grouped(census) {
        if label != "unattributed" {
            packages += 1;
        }
        out.push_str(&format!(
            "{label} — {}\n",
            count_noun(findings.len() as u64, "finding")
        ));
        let mut rows = vec![vec![
            "KIND".into(),
            "FORMAT".into(),
            "ARCH".into(),
            "SIZE".into(),
            "ENTROPY".into(),
            "PATH".into(),
        ]];
        for f in findings {
            let path = f.inner.clone().unwrap_or_else(|| f.rel.clone());
            rows.push(vec![
                f.kind.as_str().into(),
                f.format.clone(),
                f.arch.clone().unwrap_or_else(|| "-".into()),
                human_size(f.size),
                format!("{:.2}", f.entropy),
                path,
            ]);
        }
        out.push_str(&render_table(&rows));
        out.push('\n');
    }
    for w in &census.warnings {
        out.push_str(&format!("warning: {w}\n"));
    }
    if !census.warnings.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!(
        "summary: {} scanned · {} native · {} · {} · {} affected\n",
        count_noun(census.files_scanned, "file"),
        count(census, Kind::Native),
        count_noun(count(census, Kind::Archive) as u64, "archive"),
        count_noun(count(census, Kind::Opaque) as u64, "opaque blob"),
        count_noun(packages as u64, "package"),
    ));
    out
}

/// The `blobfind explain <file>` detail view.
pub fn explain_report(f: &Finding) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n", f.rel));
    out.push_str(&format!("  kind:     {}\n", f.kind.as_str()));
    out.push_str(&format!("  format:   {}\n", f.format));
    if let Some(arch) = &f.arch {
        out.push_str(&format!("  arch:     {arch}\n"));
    }
    out.push_str(&format!(
        "  size:     {} ({} bytes)\n",
        human_size(f.size),
        f.size
    ));
    out.push_str(&format!("  entropy:  {:.2} bits/byte\n", f.entropy));
    out.push_str(&format!("  sha256:   {}\n", f.sha256));
    out.push_str(&format!("  package:  {}\n", f.provenance.label()));
    if !f.hints.is_empty() {
        out.push_str("  hints:\n");
        for h in &f.hints {
            out.push_str(&format!("    - {h}\n"));
        }
    }
    out
}

/// The `blobfind diff` report.
pub fn diff_report(drift: &Drift, baseline_len: usize) -> String {
    let mut out = String::new();
    if drift.is_clean() {
        out.push_str(&format!(
            "baseline OK — {}, no drift\n",
            count_noun(baseline_len as u64, "blob")
        ));
        return out;
    }
    for e in &drift.added {
        out.push_str(&format!(
            "+ added    {:<7} {}  ({}, sha256 {}…)\n",
            e.kind.as_str(),
            e.path,
            human_size(e.size),
            short_sha(&e.sha256)
        ));
    }
    for e in &drift.removed {
        out.push_str(&format!(
            "- removed  {:<7} {}  (was {}, sha256 {}…)\n",
            e.kind.as_str(),
            e.path,
            human_size(e.size),
            short_sha(&e.sha256)
        ));
    }
    for (old, new) in &drift.changed {
        out.push_str(&format!(
            "~ changed  {:<7} {}  (sha256 {}… -> {}…, {} -> {})\n",
            new.kind.as_str(),
            new.path,
            short_sha(&old.sha256),
            short_sha(&new.sha256),
            human_size(old.size),
            human_size(new.size)
        ));
    }
    out.push_str(&format!(
        "drift: {} added · {} removed · {} changed (baseline had {})\n",
        drift.added.len(),
        drift.removed.len(),
        drift.changed.len(),
        count_noun(baseline_len as u64, "blob")
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::LockEntry;
    use crate::provenance::Provenance;
    use std::path::PathBuf;

    fn finding(rel: &str, kind: Kind, label_pkg: Option<(&str, &str)>) -> Finding {
        Finding {
            rel: rel.into(),
            size: 5_452_595,
            kind,
            format: "ELF shared object".into(),
            arch: Some("x86-64 (64-bit)".into()),
            entropy: 6.31,
            sha256: "ab".repeat(32),
            provenance: match label_pkg {
                Some((pkg, ver)) => Provenance {
                    ecosystem: Some("npm"),
                    package: Some(pkg.into()),
                    version: Some(ver.into()),
                    package_root: None,
                },
                None => Provenance::default(),
            },
            inner: None,
            hints: vec!["Node.js native addon — loaded straight into the node process".into()],
        }
    }

    fn census(findings: Vec<Finding>) -> Census {
        Census {
            root: PathBuf::from("/proj"),
            files_scanned: 42,
            findings,
            warnings: vec![],
        }
    }

    #[test]
    fn scan_report_groups_by_package_and_counts() {
        let mut c = census(vec![
            finding(
                "node_modules/sharp/a.node",
                Kind::Native,
                Some(("sharp", "0.33.4")),
            ),
            finding(
                "node_modules/sharp/b.node",
                Kind::Native,
                Some(("sharp", "0.33.4")),
            ),
            finding("assets/blob.bin", Kind::Opaque, None),
        ]);
        c.warnings
            .push("cannot read /proj/locked: permission denied".into());
        let r = scan_report(&c);
        assert!(r.contains("npm · sharp@0.33.4 — 2 findings"));
        assert!(r.contains("unattributed — 1 finding\n"));
        assert!(r.contains(
            "summary: 42 files scanned · 2 native · 0 archives · 1 opaque blob · 1 package affected"
        ));
        assert!(r.contains("warning: cannot read /proj/locked"));
        // unattributed group must come last.
        assert!(r.find("sharp").unwrap() < r.find("unattributed").unwrap());
    }

    #[test]
    fn scan_report_on_clean_tree_is_just_the_summary() {
        let r = scan_report(&census(vec![]));
        assert_eq!(
            r,
            "summary: 42 files scanned · 0 native · 0 archives · 0 opaque blobs · 0 packages affected\n"
        );
    }

    #[test]
    fn explain_report_lists_all_fields_and_hints() {
        let f = finding(
            "node_modules/sharp/a.node",
            Kind::Native,
            Some(("sharp", "0.33.4")),
        );
        let r = explain_report(&f);
        assert!(r.contains("kind:     native"));
        assert!(r.contains("format:   ELF shared object"));
        assert!(r.contains("arch:     x86-64 (64-bit)"));
        assert!(r.contains("size:     5.2M (5452595 bytes)"));
        assert!(r.contains("entropy:  6.31 bits/byte"));
        assert!(r.contains(&"ab".repeat(32)));
        assert!(r.contains("package:  npm · sharp@0.33.4"));
        assert!(r.contains("- Node.js native addon"));
    }

    #[test]
    fn diff_report_clean_and_dirty() {
        let clean = diff_report(&Drift::default(), 5);
        assert!(clean.contains("baseline OK — 5 blobs, no drift"));
        let single = diff_report(&Drift::default(), 1);
        assert!(single.contains("baseline OK — 1 blob, no drift"));

        let entry = |p: &str| LockEntry {
            sha256: "cd".repeat(32),
            size: 1024,
            kind: Kind::Native,
            path: p.into(),
        };
        let drift = Drift {
            added: vec![entry("new.so")],
            removed: vec![entry("old.so")],
            changed: vec![(entry("mod.so"), entry("mod.so"))],
        };
        let r = diff_report(&drift, 5);
        assert!(r.contains("+ added"));
        assert!(r.contains("new.so"));
        assert!(r.contains("- removed"));
        assert!(r.contains("~ changed"));
        assert!(r.contains("drift: 1 added · 1 removed · 1 changed (baseline had 5 blobs)"));
    }
}
