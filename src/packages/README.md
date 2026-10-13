# `packages` — package-format rules and security checks

Validates untrusted package archives before anything is staged, trusted, or
executed. This module holds **no lifecycle state** and performs **no
filesystem writes outside what callers direct** — it decides whether bytes
are acceptable, never where they live (that is `storage`) or what happens
next (that is `application`).

## Layout

| File | Owns | Must not |
|---|---|---|
| `archive.rs` | ZIP mechanics: `ArchiveLimits`, `CompressionMethod` allowlist, `ArchiveReader` seam, pure `check_entry_path` / `check_no_duplicate_paths` confinement policy | Decide validation outcomes |
| `manifest.rs` | Bounded manifest parsing, schema-version gating | Trust hashes without checking file bytes |
| `signature.rs` | `SignatureVerifier` + `TrustedKeyProvider` seams, closed `SignatureAlgorithm` enum, key-owned algorithm records | Load or execute plugin code |
| `digest.rs` | `DigestProvider` seam, pinned SHA-256 default | Decide activation policy |
| `inventory.rs` | Declared-files vs. archive-entries comparison | Persist lifecycle state |
| `policy.rs` | `PackageValidationPolicy`: runtime allowlists and bounds, `production()` defaults, startup `validate()` / `ensure_production_ingest()` gates | Filesystem writes |

## Wiring

The pipeline is assembled by `PackageValidationBuilder` and run by
`PackageValidator` in `application/validate_package.rs`: dependencies are
injected as `Arc<dyn Trait>` with secure defaults (`ZipArchiveReader`,
`Ed25519Verifier`, `ConfiguredTrustedKeys`, `Sha256DigestProvider`), and the
validator owns the fixed stage order — policy gate → inspect → authenticate →
inventory/extract+hash → module policy → promote. Stages cannot be omitted;
there is no skip-verification switch.

## What is flexible vs. fixed

- **Injectable**: archive reader, signature verifier, key provider, digest
  backend — swap per deployment or per test via the builder.
- **Runtime policy** (`PackageValidationPolicy`, validated at startup):
  size/entry bounds, accepted signature algorithms, compression methods,
  manifest versions, `max_manifest_bytes`. Deserializable from operator
  config; each validator snapshots one immutable policy.
- **Fixed invariants**: stage order, mandatory signature on the production
  path, traversal/duplicate/symlink rejection, fail-closed backends. These
  live in code, never in config.

## Errors

All error enums derive `Display` + `Error` via `thiserror`; messages are
part of the observable contract. Backends that are not implemented yet fail
closed with `NotImplemented` variants — never silent success.

## Tests

- Unit tests beside each module (bounds, path tables, fail-closed backends,
  injection doubles).
- `tests/archive_security.rs` — confinement invariants through the public
  API, plus a presence check on the hostile corpus.
- `tests/package_validation.rs` — policy gates and validator stage order
  (including a `MustNotRun` reader proving unsigned configs never reach the
  archive stage).
- `tests/testdata/` — evil-but-inert ZIP fixtures (`traversal`,
  `absolute`, `duplicate`, `symlink`, `entry-bomb`, `odd-compression`) with
  their own README; consumed by real-reader tests once the ZIP backend
  lands.
