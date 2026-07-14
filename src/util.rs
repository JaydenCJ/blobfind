//! Small shared helpers: human-readable sizes, size parsing for flags, and
//! slash-normalized relative paths so reports and lock files are identical
//! across platforms.

use std::path::Path;

/// Format a byte count the way `ls -lh` would: `973B`, `4.0K`, `5.2M`, `1.1G`.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 3] = [("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)];
    for (suffix, unit) in UNITS {
        if bytes >= unit {
            let value = bytes as f64 / unit as f64;
            return if value >= 10.0 {
                format!("{value:.0}{suffix}")
            } else {
                format!("{value:.1}{suffix}")
            };
        }
    }
    format!("{bytes}B")
}

/// Parse a size flag value: a plain integer is bytes; `K`, `M`, `G` suffixes
/// (case-insensitive) multiply by binary units. Used by `--min-blob`.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".into());
    }
    let (digits, mult) = match s.chars().last().unwrap().to_ascii_uppercase() {
        'K' => (&s[..s.len() - 1], 1u64 << 10),
        'M' => (&s[..s.len() - 1], 1u64 << 20),
        'G' => (&s[..s.len() - 1], 1u64 << 30),
        c if c.is_ascii_digit() => (s, 1),
        c => return Err(format!("unknown size suffix '{c}' (use K, M or G)")),
    };
    let n: u64 = digits.parse().map_err(|_| format!("invalid size '{s}'"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size '{s}' overflows"))
}

/// Count plus noun with a plain plural `s`: `1 finding`, `2 findings`.
pub fn count_noun(n: u64, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Relative path from `root` to `path`, `/`-separated regardless of host OS.
/// Falls back to the full path when `path` is not under `root`.
pub fn rel_slash(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(p) => {
            let parts: Vec<String> = p
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            parts.join("/")
        }
        Err(_) => path.to_string_lossy().replace('\\', "/"),
    }
}

/// Lowercased file extension, if any.
pub fn extension(path: &Path) -> Option<String> {
    path.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn human_size_units_and_precision() {
        assert_eq!(human_size(0), "0B");
        assert_eq!(human_size(973), "973B");
        assert_eq!(human_size(1024), "1.0K");
        assert_eq!(human_size(4096), "4.0K");
        assert_eq!(human_size(5_452_595), "5.2M");
        assert_eq!(human_size(11 << 20), "11M");
        assert_eq!(human_size(1_181_116_006), "1.1G");
    }

    #[test]
    fn parse_size_accepts_bytes_and_suffixes() {
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size("4K"), Ok(4096));
        assert_eq!(parse_size("4k"), Ok(4096));
        assert_eq!(parse_size("2M"), Ok(2 << 20));
        assert_eq!(parse_size("1G"), Ok(1 << 30));
    }

    #[test]
    fn parse_size_rejects_garbage() {
        assert!(parse_size("").is_err());
        assert!(parse_size("12Q").is_err());
        assert!(parse_size("K").is_err());
        assert!(parse_size("-4K").is_err());
        // Overflow must be an error, not a silent wrap.
        assert!(parse_size("99999999999G").is_err());
    }

    #[test]
    fn count_noun_pluralizes_everything_but_one() {
        assert_eq!(count_noun(0, "finding"), "0 findings");
        assert_eq!(count_noun(1, "finding"), "1 finding");
        assert_eq!(count_noun(2, "opaque blob"), "2 opaque blobs");
    }

    #[test]
    fn rel_slash_strips_root_and_normalizes() {
        let root = PathBuf::from("/proj");
        let file = PathBuf::from("/proj/node_modules/pkg/lib.so");
        assert_eq!(rel_slash(&root, &file), "node_modules/pkg/lib.so");
    }

    #[test]
    fn rel_slash_falls_back_outside_root() {
        let root = PathBuf::from("/proj");
        let file = PathBuf::from("/elsewhere/x");
        assert_eq!(rel_slash(&root, &file), "/elsewhere/x");
    }

    #[test]
    fn extension_is_lowercased_and_optional() {
        assert_eq!(extension(Path::new("a/B.SO")), Some("so".into()));
        assert_eq!(extension(Path::new("a/noext")), None);
    }
}
