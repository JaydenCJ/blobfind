# The blobfind lock file

`blobfind snapshot` freezes a census into a plain-text baseline that
`blobfind diff` later verifies. The format is deliberately boring: it is
meant to be committed next to `package-lock.json` / `Cargo.lock`, reviewed
in pull requests, and diffed by `git` itself.

## Format (v1)

```text
# blobfind lock v1
2c26b46b68ffc68ff99b453c1d304134… 5452595 native node_modules/sharp/build/Release/sharp.node
7d865e959b2466918c9863afca942d0f… 1181116 archive node_modules/leveldown/prebuilds/linux-x64.tar.gz
9f86d081884c7d659a2feaa0c55ad015… 8192 opaque assets/telemetry.bin
```

One line per blob, four space-separated fields:

| Field | Content |
|---|---|
| 1 | full SHA-256 of the file, lowercase hex (64 chars) |
| 2 | file size in bytes |
| 3 | kind: `native`, `archive` or `opaque` |
| 4 | path relative to the scanned root, `/`-separated — **last field, may contain spaces** |

Rules:

- The first non-comment content must be preceded by the `# blobfind lock v1`
  header line. An empty lock (header only, or an empty file) is valid and
  means "this tree has no executable content".
- Lines are sorted by path, so two snapshots of the same tree are
  byte-identical and `git diff` shows exactly what moved.
- `#`-prefixed lines and blank lines are ignored, so the file can carry
  human annotations.
- Parsers must split each line on the **first three spaces only**; the path
  is everything after the third space.

## Diff semantics

`blobfind diff` re-scans the tree with the same tuning flags and compares
by path:

- present now, absent in the baseline → **added**
- absent now, present in the baseline → **removed**
- same path, different SHA-256 → **changed** (size shown for context)

Any of the three makes `diff` exit 1; a clean comparison prints
`baseline OK` and exits 0. Kind and size are informational — identity is
the hash. Scan tuning (`--entropy`, `--min-blob`, `--all`, `--no-archives`)
must match between `snapshot` and `diff`, or the census itself differs and
the drift report will say so honestly.
