//! Hand-rolled JSON serialization for `--json` output. Emission only — the
//! lock file (the only format blobfind reads back) is a plain line format,
//! so no JSON parser is needed and the dependency count stays at zero.

use crate::inventory::{Census, Finding, Kind};

/// Escape a string per RFC 8259.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn string(s: &str) -> String {
    format!("\"{}\"", escape(s))
}

fn opt_string(s: &Option<String>) -> String {
    match s {
        Some(v) => string(v),
        None => "null".into(),
    }
}

fn finding_json(f: &Finding, indent: &str) -> String {
    let hints: Vec<String> = f.hints.iter().map(|h| string(h)).collect();
    format!(
        "{indent}{{\n\
         {indent}  \"path\": {},\n\
         {indent}  \"kind\": {},\n\
         {indent}  \"format\": {},\n\
         {indent}  \"arch\": {},\n\
         {indent}  \"size\": {},\n\
         {indent}  \"entropy\": {:.4},\n\
         {indent}  \"sha256\": {},\n\
         {indent}  \"ecosystem\": {},\n\
         {indent}  \"package\": {},\n\
         {indent}  \"version\": {},\n\
         {indent}  \"inner_path\": {},\n\
         {indent}  \"hints\": [{}]\n\
         {indent}}}",
        string(&f.rel),
        string(f.kind.as_str()),
        string(&f.format),
        opt_string(&f.arch),
        f.size,
        f.entropy,
        string(&f.sha256),
        opt_string(&f.provenance.ecosystem.map(|e| e.to_string())),
        opt_string(&f.provenance.package),
        opt_string(&f.provenance.version),
        opt_string(&f.inner),
        hints.join(", "),
    )
}

/// The full `blobfind scan --json` document.
pub fn census_json(census: &Census) -> String {
    let count = |k: Kind| census.findings.iter().filter(|f| f.kind == k).count();
    let findings: Vec<String> = census
        .findings
        .iter()
        .map(|f| finding_json(f, "    "))
        .collect();
    let warnings: Vec<String> = census.warnings.iter().map(|w| string(w)).collect();
    format!(
        "{{\n  \"blobfind\": {},\n  \"root\": {},\n  \"files_scanned\": {},\n  \"summary\": {{ \"native\": {}, \"archive\": {}, \"opaque\": {} }},\n  \"findings\": [\n{}\n  ],\n  \"warnings\": [{}]\n}}\n",
        string(env!("CARGO_PKG_VERSION")),
        string(&census.root.to_string_lossy()),
        census.files_scanned,
        count(Kind::Native),
        count(Kind::Archive),
        count(Kind::Opaque),
        findings.join(",\n"),
        warnings.join(", "),
    )
}

/// Single finding document for `blobfind explain --json`.
pub fn finding_doc(f: &Finding) -> String {
    format!("{}\n", finding_json(f, ""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::Provenance;
    use std::path::PathBuf;

    fn sample_finding() -> Finding {
        Finding {
            rel: "node_modules/sharp/build/Release/sharp.node".into(),
            size: 1024,
            kind: Kind::Native,
            format: "ELF shared object".into(),
            arch: Some("x86-64 (64-bit)".into()),
            entropy: 6.3125,
            sha256: "ab".repeat(32),
            provenance: Provenance {
                ecosystem: Some("npm"),
                package: Some("sharp".into()),
                version: Some("0.33.4".into()),
                package_root: None,
            },
            inner: Some("build/Release/sharp.node".into()),
            hints: vec!["say \"hi\"".into()],
        }
    }

    fn sample_census() -> Census {
        Census {
            root: PathBuf::from("/proj"),
            files_scanned: 10,
            findings: vec![sample_finding()],
            warnings: vec!["cannot read /proj/x".into()],
        }
    }

    #[test]
    fn escape_handles_quotes_backslashes_and_control_chars() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a\"b"), "a\\\"b");
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("a\nb\tc"), "a\\nb\\tc");
        assert_eq!(escape("\u{01}"), "\\u0001");
    }

    #[test]
    fn census_json_contains_all_fields() {
        let doc = census_json(&sample_census());
        assert!(doc.contains(&format!("\"blobfind\": \"{}\"", env!("CARGO_PKG_VERSION"))));
        assert!(doc.contains("\"files_scanned\": 10"));
        assert!(doc.contains("\"summary\": { \"native\": 1, \"archive\": 0, \"opaque\": 0 }"));
        assert!(doc.contains("\"path\": \"node_modules/sharp/build/Release/sharp.node\""));
        assert!(doc.contains("\"entropy\": 6.3125"));
        assert!(doc.contains("\"package\": \"sharp\""));
        assert!(doc.contains("\"inner_path\": \"build/Release/sharp.node\""));
        assert!(doc.contains("\"hints\": [\"say \\\"hi\\\"\"]"));
        assert!(doc.contains("\"warnings\": [\"cannot read /proj/x\"]"));
        // Document shape: balanced braces and brackets, one trailing newline.
        assert_eq!(doc.matches('{').count(), doc.matches('}').count());
        assert_eq!(doc.matches('[').count(), doc.matches(']').count());
        assert!(doc.trim_end().ends_with('}'));
    }

    #[test]
    fn null_fields_are_json_null_not_strings() {
        let mut f = sample_finding();
        f.arch = None;
        f.provenance = Provenance::default();
        f.inner = None;
        let doc = finding_doc(&f);
        assert!(doc.contains("\"arch\": null"));
        assert!(doc.contains("\"ecosystem\": null"));
        assert!(doc.contains("\"package\": null"));
        assert!(doc.contains("\"inner_path\": null"));
    }

    #[test]
    fn empty_census_yields_empty_arrays() {
        let census = Census {
            root: PathBuf::from("/proj"),
            files_scanned: 0,
            findings: vec![],
            warnings: vec![],
        };
        let doc = census_json(&census);
        assert!(doc.contains("\"findings\": [\n\n  ]"));
        assert!(doc.contains("\"warnings\": []"));
    }
}
