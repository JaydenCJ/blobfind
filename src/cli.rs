//! Argument parsing and command dispatch. Hand-rolled on std: the whole
//! surface is four subcommands and a handful of flags, and keeping it
//! dependency-free is the point of the tool.

use std::path::PathBuf;

use crate::baseline;
use crate::inventory::{self, Config};
use crate::json;
use crate::report;
use crate::util;

const USAGE: &str = "\
blobfind — census of native binaries, shared libraries and high-entropy
blobs inside dependency trees, with provenance hints. Fully offline.

USAGE:
    blobfind <COMMAND> [OPTIONS]

COMMANDS:
    scan [DIR]           Inventory every executable blob under DIR (default .)
    explain <FILE>       Full detail on one file: format, hash, provenance
    snapshot [DIR]       Write the census as a lock-file baseline
    diff [DIR]           Compare the tree against a baseline lock file

OPTIONS (scan / snapshot / diff):
    --entropy <BITS>     Opaque threshold in bits/byte (default 7.5)
    --min-blob <SIZE>    Minimum size for opaque findings (default 4K)
    --all                Consider media/font extensions for opaque findings
    --no-archives        Do not report archive containers

OPTIONS (scan):
    --json               Machine-readable report
    --strict             Exit 1 when there is any finding at all

OPTIONS (explain):
    --json               Machine-readable detail
    --root <DIR>         Provenance search root (default: current directory)

OPTIONS (snapshot):
    -o, --output <FILE>  Lock file path (default: stdout)

OPTIONS (diff):
    --against <FILE>     Baseline lock file (default: <DIR>/blobfind.lock)

EXIT CODES:
    0 clean · 1 findings under --strict, or baseline drift · 2 usage error
";

/// Parsed command line, one variant per subcommand.
#[derive(Debug, PartialEq)]
pub enum Command {
    Scan {
        dir: PathBuf,
        json: bool,
        strict: bool,
        tuning: Tuning,
    },
    Explain {
        file: PathBuf,
        root: Option<PathBuf>,
        json: bool,
    },
    Snapshot {
        dir: PathBuf,
        output: Option<PathBuf>,
        tuning: Tuning,
    },
    Diff {
        dir: PathBuf,
        against: Option<PathBuf>,
        tuning: Tuning,
    },
    Help,
    Version,
}

/// Scan-behavior knobs shared by scan/snapshot/diff.
#[derive(Debug, PartialEq)]
pub struct Tuning {
    pub entropy: f64,
    pub min_blob: u64,
    pub all: bool,
    pub no_archives: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            entropy: 7.5,
            min_blob: 4096,
            all: false,
            no_archives: false,
        }
    }
}

impl Tuning {
    fn into_config(self, dir: PathBuf) -> Config {
        let mut cfg = Config::new(dir);
        cfg.entropy_threshold = self.entropy;
        cfg.min_blob = self.min_blob;
        cfg.include_media = self.all;
        cfg.skip_archives = self.no_archives;
        cfg
    }
}

fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

/// Parse the raw argv (without the program name) into a [`Command`].
pub fn parse(args: &[String]) -> Result<Command, String> {
    let Some(cmd) = args.first() else {
        return Ok(Command::Help);
    };
    match cmd.as_str() {
        "--help" | "-h" | "help" => return Ok(Command::Help),
        "--version" | "-V" | "version" => return Ok(Command::Version),
        _ => {}
    }

    let mut dir: Option<PathBuf> = None;
    let mut file: Option<PathBuf> = None;
    let mut json = false;
    let mut strict = false;
    let mut output: Option<PathBuf> = None;
    let mut against: Option<PathBuf> = None;
    let mut root: Option<PathBuf> = None;
    let mut tuning = Tuning::default();

    let known = ["scan", "explain", "snapshot", "diff"];
    if !known.contains(&cmd.as_str()) {
        return Err(format!("unknown command '{cmd}'"));
    }

    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            // Honor help/version anywhere: `blobfind scan --help` must not
            // be a usage error.
            "--help" | "-h" => return Ok(Command::Help),
            "--version" | "-V" => return Ok(Command::Version),
            "--json" if cmd == "scan" || cmd == "explain" => json = true,
            "--strict" if cmd == "scan" => strict = true,
            "--all" | "--no-archives" | "--entropy" | "--min-blob"
                if cmd == "scan" || cmd == "snapshot" || cmd == "diff" =>
            {
                match arg {
                    "--all" => tuning.all = true,
                    "--no-archives" => tuning.no_archives = true,
                    "--entropy" => {
                        let v = take_value(args, &mut i, "--entropy")?;
                        tuning.entropy = v
                            .parse::<f64>()
                            .map_err(|_| format!("invalid --entropy '{v}'"))?;
                        if !(0.0..=8.0).contains(&tuning.entropy) {
                            return Err(format!("--entropy must be within 0..=8, got {v}"));
                        }
                    }
                    "--min-blob" => {
                        let v = take_value(args, &mut i, "--min-blob")?;
                        tuning.min_blob = util::parse_size(&v)?;
                    }
                    _ => unreachable!(),
                }
            }
            "-o" | "--output" if cmd == "snapshot" => {
                // Report the spelling the user actually typed on error.
                output = Some(PathBuf::from(take_value(args, &mut i, arg)?));
            }
            "--against" if cmd == "diff" => {
                against = Some(PathBuf::from(take_value(args, &mut i, "--against")?));
            }
            "--root" if cmd == "explain" => {
                root = Some(PathBuf::from(take_value(args, &mut i, "--root")?));
            }
            _ if arg.starts_with('-') => {
                return Err(format!("unknown option '{arg}' for '{cmd}'"));
            }
            _ => {
                let slot = if cmd == "explain" {
                    &mut file
                } else {
                    &mut dir
                };
                if slot.is_some() {
                    return Err(format!("unexpected extra argument '{arg}'"));
                }
                *slot = Some(PathBuf::from(arg));
            }
        }
        i += 1;
    }

    let dir = dir.unwrap_or_else(|| PathBuf::from("."));
    Ok(match cmd.as_str() {
        "scan" => Command::Scan {
            dir,
            json,
            strict,
            tuning,
        },
        "explain" => Command::Explain {
            file: file.ok_or("explain requires a <FILE> argument")?,
            root,
            json,
        },
        "snapshot" => Command::Snapshot {
            dir,
            output,
            tuning,
        },
        "diff" => Command::Diff {
            dir,
            against,
            tuning,
        },
        _ => unreachable!(),
    })
}

/// Execute the CLI; returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let command = match parse(args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!("run 'blobfind --help' for usage");
            return 2;
        }
    };
    match execute(command) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            2
        }
    }
}

fn execute(command: Command) -> Result<i32, String> {
    match command {
        Command::Help => {
            print!("{USAGE}");
            Ok(0)
        }
        Command::Version => {
            println!("blobfind {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Command::Scan {
            dir,
            json,
            strict,
            tuning,
        } => {
            require_dir(&dir)?;
            let census = inventory::scan(&tuning.into_config(dir));
            if json {
                print!("{}", json::census_json(&census));
            } else {
                print!("{}", report::scan_report(&census));
            }
            Ok(if strict && !census.findings.is_empty() {
                1
            } else {
                0
            })
        }
        Command::Explain { file, root, json } => {
            if !file.is_file() {
                return Err(format!("'{}' is not a file", file.display()));
            }
            // Canonicalize both sides so a relative FILE still walks the
            // manifests between it and the root when resolving provenance.
            let file = file
                .canonicalize()
                .map_err(|e| format!("cannot resolve '{}': {e}", file.display()))?;
            let root = match root {
                Some(r) => r
                    .canonicalize()
                    .map_err(|e| format!("cannot resolve '{}': {e}", r.display()))?,
                None => std::env::current_dir().map_err(|e| e.to_string())?,
            };
            let finding = inventory::inspect_file(&root, &file)
                .map_err(|e| format!("cannot read '{}': {e}", file.display()))?;
            if json {
                print!("{}", json::finding_doc(&finding));
            } else {
                print!("{}", report::explain_report(&finding));
            }
            Ok(0)
        }
        Command::Snapshot {
            dir,
            output,
            tuning,
        } => {
            require_dir(&dir)?;
            let census = inventory::scan(&tuning.into_config(dir));
            let entries = baseline::entries_from(&census);
            let text = baseline::render(&entries);
            match output {
                Some(path) => {
                    std::fs::write(&path, &text)
                        .map_err(|e| format!("cannot write '{}': {e}", path.display()))?;
                    println!(
                        "wrote {} to {}",
                        util::count_noun(entries.len() as u64, "blob"),
                        path.display()
                    );
                }
                None => print!("{text}"),
            }
            Ok(0)
        }
        Command::Diff {
            dir,
            against,
            tuning,
        } => {
            require_dir(&dir)?;
            let lock_path = against.unwrap_or_else(|| dir.join("blobfind.lock"));
            let lock_text = std::fs::read_to_string(&lock_path)
                .map_err(|e| format!("cannot read baseline '{}': {e}", lock_path.display()))?;
            let baseline_entries = baseline::parse(&lock_text)
                .map_err(|e| format!("baseline '{}': {e}", lock_path.display()))?;
            let census = inventory::scan(&tuning.into_config(dir));
            let current = baseline::entries_from(&census);
            let drift = baseline::diff(&baseline_entries, &current);
            print!("{}", report::diff_report(&drift, baseline_entries.len()));
            Ok(if drift.is_clean() { 0 } else { 1 })
        }
    }
}

fn require_dir(dir: &std::path::Path) -> Result<(), String> {
    if dir.is_dir() {
        Ok(())
    } else {
        Err(format!("'{}' is not a directory", dir.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn help_and_version_forms() {
        assert_eq!(parse(&[]).unwrap(), Command::Help);
        assert_eq!(parse(&argv("--help")).unwrap(), Command::Help);
        assert_eq!(parse(&argv("-h")).unwrap(), Command::Help);
        assert_eq!(parse(&argv("--version")).unwrap(), Command::Version);
        assert_eq!(parse(&argv("-V")).unwrap(), Command::Version);
    }

    #[test]
    fn help_and_version_win_after_a_subcommand_too() {
        // `blobfind scan --help` is what people actually type; it must show
        // usage instead of failing as an unknown scan option.
        assert_eq!(parse(&argv("scan --help")).unwrap(), Command::Help);
        assert_eq!(parse(&argv("diff -h")).unwrap(), Command::Help);
        assert_eq!(
            parse(&argv("snapshot --version")).unwrap(),
            Command::Version
        );
    }

    #[test]
    fn scan_defaults_to_current_dir() {
        match parse(&argv("scan")).unwrap() {
            Command::Scan {
                dir,
                json,
                strict,
                tuning,
            } => {
                assert_eq!(dir, PathBuf::from("."));
                assert!(!json);
                assert!(!strict);
                assert_eq!(tuning, Tuning::default());
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn scan_parses_all_flags() {
        match parse(&argv(
            "scan deps --json --strict --entropy 6.5 --min-blob 1K --all --no-archives",
        ))
        .unwrap()
        {
            Command::Scan {
                dir,
                json,
                strict,
                tuning,
            } => {
                assert_eq!(dir, PathBuf::from("deps"));
                assert!(json && strict);
                assert_eq!(tuning.entropy, 6.5);
                assert_eq!(tuning.min_blob, 1024);
                assert!(tuning.all && tuning.no_archives);
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn entropy_must_be_in_range_and_numeric() {
        assert!(parse(&argv("scan --entropy 9")).is_err());
        assert!(parse(&argv("scan --entropy lots")).is_err());
        assert!(parse(&argv("scan --entropy")).is_err());
    }

    #[test]
    fn explain_requires_a_file_argument() {
        assert!(parse(&argv("explain")).is_err());
        match parse(&argv("explain a/b.so --root proj --json")).unwrap() {
            Command::Explain { file, root, json } => {
                assert_eq!(file, PathBuf::from("a/b.so"));
                assert_eq!(root, Some(PathBuf::from("proj")));
                assert!(json);
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn snapshot_output_flag_short_and_long() {
        for form in [
            "snapshot deps -o out.lock",
            "snapshot deps --output out.lock",
        ] {
            match parse(&argv(form)).unwrap() {
                Command::Snapshot { dir, output, .. } => {
                    assert_eq!(dir, PathBuf::from("deps"));
                    assert_eq!(output, Some(PathBuf::from("out.lock")));
                }
                other => panic!("wrong parse: {other:?}"),
            }
        }
    }

    #[test]
    fn diff_against_is_optional() {
        match parse(&argv("diff deps --against base.lock")).unwrap() {
            Command::Diff { dir, against, .. } => {
                assert_eq!(dir, PathBuf::from("deps"));
                assert_eq!(against, Some(PathBuf::from("base.lock")));
            }
            other => panic!("wrong parse: {other:?}"),
        }
        match parse(&argv("diff")).unwrap() {
            Command::Diff { against, .. } => assert_eq!(against, None),
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn unknown_commands_and_flags_are_usage_errors() {
        assert!(parse(&argv("frobnicate"))
            .unwrap_err()
            .contains("unknown command"));
        assert!(parse(&argv("scan --frob"))
            .unwrap_err()
            .contains("unknown option"));
        // Flags are command-scoped: --strict only applies to scan.
        assert!(parse(&argv("diff --strict")).is_err());
        assert!(parse(&argv("scan --against x")).is_err());
    }

    #[test]
    fn extra_positionals_are_rejected() {
        assert!(parse(&argv("scan a b"))
            .unwrap_err()
            .contains("extra argument"));
    }
}
