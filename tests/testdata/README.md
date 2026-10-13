# Hostile archive corpus

Evil-but-harmless ZIP fixtures for the real `ZipArchiveReader` backend.
Each file encodes one threat against the archive-safety invariants in
`src/packages/archive.rs`. Payloads are inert text (`not a real plugin`,
`x`, `{}`); the threat is always in entry **names, counts, metadata, or
compression methods** — never in payload bytes.

## Status: consumed by reader tests

Every fixture below is opened by a test in
`tests/archive_security.rs` asserting its documented verdict, and
`hostile_corpus_is_present_for_the_future_reader` pins the corpus
contract: every fixture documented here must be checked in, or the suite
fails. The pure confinement policy (`check_entry_path`,
`check_no_duplicate_paths`) is additionally tested against equivalent
hostile *names* in unit and integration tests — fixtures test encoding,
unit tests test logic; both layers know about every threat class.

Pipeline context: the validation stages these fixtures feed are defined in
[src/packages/README.md](../../src/packages/README.md); the package format
they attack is sketched in [Service Packages](../../README.md#service-packages).

## Safety and size budget

- Payloads must stay inert: plain text, no scripts, no executables, no
  polyglots. A fixture that needs a "malicious" payload to prove its point
  is a badly designed fixture — the point is always structural.
- Keep the corpus small. Current total is ~490 KB, of which ~485 KB is
  `entry-bomb.zip` (unavoidable: it needs thousands of central-directory
  records). Everything else is under 400 bytes each.
- Never commit a fixture containing real credentials, real signatures, or
  bytes copied from a genuine attack. Synthetic threats only.

## Fixture reference

Conventions used below: `compress=0` is Stored, `compress=8` is Deflate,
`compress=12` is BZIP2 (per the ZIP spec's compression-method IDs).
`unix_mode` is `external_attr >> 16`. All fixtures below use Stored except
where noted; that is deliberate, so a failure can only be blamed on the
threat being tested, not on decompression.

### `traversal.zip` (365 bytes)

Classic ZipSlip shapes plus a control entry:

| Entry | Size | Notes |
|---|---|---|
| `../../evil.sh` | 17 B | Escapes staging by two levels |
| `a/../../b.dat` | 17 B | Escapes via a nested prefix — naive `starts_with("..")` prefix checks pass this, component-wise rejection must catch it |
| `ok.txt` | 17 B | Benign control; proves the archive parses and isolates the threat to the hostile entries |

Threat: write outside the staging directory during extraction.
Invariant: `check_entry_path` rejects every `..` component, so no caller
can ever obtain an escaping path — but the future reader test must also
prove the *extraction* path joins the staging root with the *validated*
name, never the raw entry name, and that the whole validation fails even
though `ok.txt` is fine (one hostile entry poisons the package).
Expected verdict: `Err(ArchiveError::PathRejected(_))` from `inspect`;
`ok.txt` must not be extracted as a side effect.

### `absolute.zip` (238 bytes)

| Entry | Size | Notes |
|---|---|---|
| `/etc/evil` | 17 B | Absolute path; on extraction without validation this lands outside staging regardless of join logic |
| `ok.txt` | 17 B | Benign control |

Threat: absolute destination escapes staging even with correct
`staging.join(name)` logic on some path APIs.
Invariant: leading-`/` names are rejected at the boundary, before any join.
Expected verdict: `Err(ArchiveError::PathRejected(_))` from `inspect`.

### `duplicate.zip` (213 bytes)

Two central-directory records, both named `dup.txt`:

| Record | Stored bytes | `z.read("dup.txt")` returns |
|---|---|---|
| 1st | `first` (5 B) | — |
| 2nd | `second` (6 B) | `second` (Python, like most readers, resolves to the last record) |

Threat: inventory confusion and overwrite games. A reader that extracts
record-by-record without duplicate detection writes the file twice; a
reader that hashes the first record but extracts the last (or vice versa)
breaks the hash↔bytes agreement the digest stage depends on. This is why
the contract says "create new files without overwriting existing ones" and
"hash bytes as they are extracted" — the *same* byte stream must feed both.
Implementation note: the `zip` backend indexes entries by name and silently
collapses duplicate records, so `inspect` cross-checks its entry view
against the authoritative EOCD record count (`central_directory_count`)
and rejects on any disagreement — duplicates cannot hide behind the
library's index.
Expected verdict: `Err(ArchiveError::PathRejected(_))` (duplicate paths)
from `inspect`, before any payload byte is read. The extraction test must
additionally prove create-new semantics: if duplicates ever reach
extraction (defense in depth), the second write fails instead of replacing
the first.

### `symlink.zip` (223 bytes)

| Entry | `unix_mode` | Content |
|---|---|---|
| `link` | `0o120777` (symlink file-type bits + `rwxrwxrwx`) | `manifest.json` (the link *target*, stored as data) |
| `manifest.json` | `0o600` | `{}` |

Threat: an extracted symlink pointing at `manifest.json` (or, in a
real attack, at `/etc/passwd` or back out of staging) followed by a later
entry write through the link — a write-outside-staging primitive, and a way
to make inventory hash one thing while the filesystem holds another.
Invariant: symlink entries are never extracted and never followed; the
detection signal is the Unix file-type bits in `external_attr`, *not* the
payload. Note the `link` name itself passes `check_entry_path` — the name
is innocent, the metadata is the threat — so the reader must consult the
mode bits for every entry, not just the name policy.
Expected verdict: `Err(ArchiveError::PathRejected(_))` from `inspect`.
The future test asserts this with `is_symlink = true` derived from the
mode bits, and asserts no `link` file of any kind exists in staging after
failure.

### `entry-bomb.zip` (~485 KB, 5,000 entries)

Entries `f00000.txt` … `f04999.txt`, each 1 byte (`x`), Stored,
`unix_mode 0o600`. Total uncompressed payload: 5,000 bytes.

Threat: resource exhaustion via entry *count* rather than entry *size*.
Every name is benign and every payload is trivial; the attack is the
central directory itself — parse time, allocation churn, and (once
extraction exists) thousands of file creations. This fixture deliberately
trips `max_entries` (production default: 1,024) while staying far under
every byte bound, proving the count limit is enforced independently.
Expected verdict: `Err(ArchiveError::LimitExceeded(_))` from `inspect`
*before* payload reads — the test should assert this against an archive
whose total byte size is negligible, so a regression that only checks byte
bounds cannot hide. A companion assertion with a raised `max_entries`
(valid test-only policy, still under `HARD_MAX_ENTRIES = 100_000`) should
get past the count gate, proving the limit — not a parse failure — is what
rejects it under production policy.

### `odd-compression.zip` (273 bytes)

| Entry | Method | Notes |
|---|---|---|
| `weird.dat` | BZIP2 (`compress=12`), 17 → 52 B | Outside the `Stored`/`Deflate` allowlist |
| `ok.txt` | Stored, 17 B | Benign control |

Threat: unexpected codecs widen the attack surface (decompression bugs,
denial of service via pathological ratios) and complicate byte-counting.
Policy is an allowlist: anything not in
`PackageValidationPolicy::allowed_compression_methods` is rejected, never
attempted opportunistically — even when a backend library *could* decode
it.
Expected verdict: `Err(ArchiveError::UnsupportedCompression(_))` from
`inspect`. The future test must also cover the ordering: with production
policy the bzip2 entry is rejected *even though* BZIP2 support may exist in
the dependency — capability must not imply permission.

## What the reader tests prove (checklist)

Per fixture, and across the corpus:

1. **Limits before reads.** `entry-bomb.zip` is rejected without reading
   5,000 payloads; a zeroed `ArchiveLimits` against a missing file yields
   `LimitExceeded`, never I/O. A companion assertion with a raised
   `max_entries` gets past the count gate, proving the limit — not a parse
   failure — is what rejects it under production policy.
2. **Names through the pure policy.** Every entry name is routed through
   `check_entry_path` with the symlink bit from the entry metadata; raw
   names never reach path joins.
3. **Duplicates across the whole listing.** `duplicate.zip` fails at
   listing time via the EOCD count cross-check, including the case-fold
   collision rule (`check_no_duplicate_paths`) for backends that surface
   both records.
4. **Byte counting over actual output.** Decompressed bytes are counted as
   they stream out and checked against `max_uncompressed_bytes` /
   `max_entry_bytes` — central-directory `file_size` fields are hints, not
   authorities (a lying `file_size` is a future fixture candidate; see
   below). The manifest read already enforces its bound during streaming.
5. **No overwrite, no escape, no residue.** Extraction creates new files
   only, inside staging only, and a failed validation leaves staging empty
   (cleanup on failure — owned by `storage::staging`, exercised here once
   extraction lands).
6. **Digest agreement.** The bytes hashed during extraction are the bytes
   written — `duplicate.zip` is the regression case for split-brain
   hash-vs-write bugs.

## Regeneration

Fixtures are generated, not hand-crafted, so any of them can be rebuilt
exactly. The procedure (run from the repo root):

```python
import zipfile

def write(name, entries, compress=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(f"tests/testdata/{name}", "w", compress) as z:
        for arc, data, *extra in entries:
            zi = zipfile.ZipInfo(arc)
            for attr in extra:
                zi.external_attr = attr
            z.writestr(zi, data)

PAYLOAD = b"not a real plugin"
write("traversal.zip", [
    ("../../evil.sh", PAYLOAD),
    ("a/../../b.dat", PAYLOAD),
    ("ok.txt", PAYLOAD),
])
write("absolute.zip", [("/etc/evil", PAYLOAD), ("ok.txt", PAYLOAD)])
write("duplicate.zip", [("dup.txt", b"first"), ("dup.txt", b"second")])  # emits a Duplicate name UserWarning; that is expected
SYMLINK_ATTR = (0o120777 << 16)
write("symlink.zip", [
    ("link", b"manifest.json", SYMLINK_ATTR),
    ("manifest.json", b"{}"),
])
write("entry-bomb.zip", [(f"f{i:05}.txt", b"x") for i in range(5000)])

with zipfile.ZipFile("tests/testdata/odd-compression.zip", "w") as z:
    zi = zipfile.ZipInfo("weird.dat")
    zi.compress_type = zipfile.ZIP_BZIP2
    z.writestr(zi, PAYLOAD)
    zi2 = zipfile.ZipInfo("ok.txt")
    zi2.compress_type = zipfile.ZIP_STORED
    z.writestr(zi2, PAYLOAD)
```

Notes: Python's `zipfile` permits `..`, absolute, and duplicate arc names
without complaint (duplicate emits a `UserWarning`, which is expected, not
a problem). The `0o120777 << 16` attr is what marks `link` as a symlink;
verify with `unzip -l` or the inspection snippet in the previous section.

## Adding a new fixture

1. Name it `kebab-case.zip` after the threat (`overlong-name.zip`,
   `lying-size.zip`), not after the mechanism.
2. Keep payloads inert and the file small — justify anything over ~100 KB
   in the reference section.
3. Document it in the fixture reference above: exact entry table, threat,
   invariant, expected verdict, and which future test consumes it.
4. Add the filename to the presence test in
   `tests/archive_security.rs` and the generation snippet to the
   regeneration section.
5. If the threat is expressible as entry *names* alone, add the names to
   the pure-policy tables too — fixtures test encoding, unit tests test
   logic; both layers should know about every threat class.

## Candidate fixtures (not yet built)

- `lying-size.zip`: central-directory `file_size` fields understating
  actual payloads — regression case for "count actual decompressed bytes,
  not ZIP metadata".
- `case-collision.zip`: `Bin/tool` + `bin/tool` as real entries — the
  on-disk counterpart of the `check_no_duplicate_paths` case-fold rule,
  aimed at case-insensitive staging filesystems.
- `deep-nesting.zip`: ~200 levels of nesting with total path length near
  `MAX_ENTRY_PATH_LEN` — boundary case for the length bound and for
  staging path-length limits.
- `valid-minimal.zip`: deliberately **not** a checked-in fixture. The
  benign golden package is built in-test (`tests/package_validation.rs`
  `golden_package_bytes`) so it can never drift from the schema; a binary
  golden would silently rot every time the manifest gains a field.

## Non-goals

This corpus covers *archive structure* threats only. Signature vectors,
manifest schema goldens, and digest test vectors belong beside their
modules (unit tests with byte literals, as today) — not as ZIP fixtures.
End-to-end signed packages belong in a separate `tests/testdata/packages/`
directory once the full pipeline is wired, so hostile-structure fixtures
and valid-pipeline goldens are never confused.
