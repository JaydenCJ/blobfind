//! Deterministic, read-only directory walker. Entries are visited in sorted
//! order so two runs over the same tree always produce byte-identical
//! reports and lock files. Symlinks are never followed — a census must count
//! what is physically in the tree, and cycles must be impossible.

use std::fs;
use std::path::{Path, PathBuf};

/// Directory names that never contain dependency payloads and only add noise.
const SKIP_DIRS: [&str; 3] = [".git", ".hg", ".svn"];

/// A regular file found during the walk.
pub struct Entry {
    pub path: PathBuf,
    pub size: u64,
}

/// Walk `root` depth-first in sorted order, calling `visit` for every
/// regular file. Unreadable directories are reported through `warn` and
/// skipped instead of aborting the census.
pub fn walk_files<F, W>(root: &Path, visit: &mut F, warn: &mut W)
where
    F: FnMut(Entry),
    W: FnMut(String),
{
    walk_dir(root, visit, warn);
}

fn walk_dir<F, W>(dir: &Path, visit: &mut F, warn: &mut W)
where
    F: FnMut(Entry),
    W: FnMut(String),
{
    let mut names: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(err) => {
            warn(format!("cannot read {}: {err}", dir.display()));
            return;
        }
    };
    names.sort();
    for path in names {
        // symlink_metadata never follows the link itself.
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(err) => {
                warn(format!("cannot stat {}: {err}", path.display()));
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            if let Some(name) = name {
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
            }
            walk_dir(&path, visit, warn);
        } else if meta.is_file() {
            visit(Entry {
                path,
                size: meta.len(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("blobfind-walk-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn collect(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        walk_files(
            root,
            &mut |e| out.push(crate::util::rel_slash(root, &e.path)),
            &mut |_| {},
        );
        out
    }

    #[test]
    fn visits_files_in_sorted_depth_first_order() {
        let d = tempdir("order");
        fs::create_dir_all(d.join("b/inner")).unwrap();
        fs::write(d.join("z.txt"), "z").unwrap();
        fs::write(d.join("a.txt"), "a").unwrap();
        fs::write(d.join("b/inner/deep.txt"), "d").unwrap();
        fs::write(d.join("b/mid.txt"), "m").unwrap();
        assert_eq!(
            collect(&d),
            vec!["a.txt", "b/inner/deep.txt", "b/mid.txt", "z.txt"]
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn skips_vcs_directories() {
        let d = tempdir("vcs");
        fs::create_dir_all(d.join(".git/objects")).unwrap();
        fs::write(d.join(".git/objects/pack"), "x").unwrap();
        fs::write(d.join("keep.txt"), "k").unwrap();
        assert_eq!(collect(&d), vec!["keep.txt"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn never_follows_symlinks() {
        // A symlinked directory could alias files (double-count) or form a
        // cycle (hang); both are census-fatal, so links are skipped outright.
        let d = tempdir("symlink");
        fs::create_dir_all(d.join("real")).unwrap();
        fs::write(d.join("real/file.bin"), "x").unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("alias")).unwrap();
        std::os::unix::fs::symlink(d.join("real/file.bin"), d.join("link.bin")).unwrap();
        assert_eq!(collect(&d), vec!["real/file.bin"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn reports_size_from_metadata() {
        let d = tempdir("size");
        fs::write(d.join("four.bin"), b"1234").unwrap();
        let mut sizes = Vec::new();
        walk_files(&d, &mut |e| sizes.push(e.size), &mut |_| {});
        assert_eq!(sizes, vec![4]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unreadable_root_warns_instead_of_panicking() {
        let mut warnings = Vec::new();
        walk_files(
            Path::new("/nonexistent/blobfind-test-path"),
            &mut |_| panic!("no files expected"),
            &mut |w| warnings.push(w),
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("cannot read"));
    }
}
