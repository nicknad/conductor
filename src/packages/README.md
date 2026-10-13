# `packages` — package-format rules and security checks

Validates untrusted package archives before anything is staged, trusted, or
executed. This module holds **no lifecycle state** and performs **no
filesystem writes outside what callers direct** — it decides whether bytes
are acceptable, never where they live (that is `storage`) or what happens
next (that is `application`).

## Layout

| File | Owns | Must not |
|---|---|---|
| `archive.rs` | Real `ZipArchiveReader`: EOCD record-count cross-check (duplicate collapse), path/symlink/compression/size/ratio/depth enforcement, bounded single-entry reads | Decide validation outcomes |
| `manifest.rs` | Real schema-v1 parsing: byte bound, version gating, required-field shape, `entrypoint ∈ files`, `deny_unknown_fields` | Trust hashes without checking file bytes |
| `signature.rs` | Real `Ed25519Verifier` + `ConfiguredTrustedKeys`, closed `SignatureAlgorithm` enum, key-owned algorithm records, `PackageSignature` detached envelope, `canonical_payload` + `authenticate` | Load or execute plugin code |
| `digest.rs` | Real SHA-256 `Sha256DigestProvider`, buffered and streaming | Decide activation policy |
| `inventory.rs` | `DeclaredFile` set comparison vs. actual entries (`MissingFile` / `UnexpectedFile` / `DuplicateDeclaration`), declared paths through the archive confinement policy | Persist lifecycle state; check byte agreement (extraction stage) |
| `policy.rs` | `PackageValidationPolicy`: runtime allowlists and bounds, `production()` defaults, startup `validate()` / `ensure_production_ingest()` gates | Filesystem writes |
| `artifact.rs` | `ArtifactDigest` + `ValidatedArtifact`: capability-like identity minted only by the validation/promotion path | Trust decisions at use time (host must still check registration and authorization) |

## Wiring

The pipeline is assembled by `PackageValidationBuilder` and run by
`PackageValidator` in `application/validate_package.rs`: one concrete
backend per stage (`ZipArchiveReader`, `Ed25519Verifier`,
`ConfiguredTrustedKeys`, `Sha256DigestProvider`), with the policy
(constructor) and trust store (setter) as the configurable inputs.
`build()` fails with `BuildError::MissingTrustStore` when trust is absent.
`validate(archive, signature)` runs the fixed stage order over one open
file handle — policy gate → hash-and-authenticate → inspect →
manifest/inventory → promotion minting `ValidatedArtifact`. Stages cannot
be omitted; there is no skip-verification switch. Tests configure trust by
value; fake verifier/reader backends arrive as `#[cfg(test)]` seams with
their real counterparts.

Two ordering rules are load-bearing:

- **Authenticate before parsing.** The detached `PackageSignature`
  envelope is verified against the trust store before anything inside the
  archive is trusted. A signature establishes the bytes match what the
  signer signed — not that the code is safe to execute.
- **No TOCTOU.** Hashing and inspection operate on the same private
  quarantined file; the implementation must never hash one file and reopen
  an attacker-controlled path for extraction.

## What is configurable vs. fixed

- **Fixed backends**: one concrete implementation per stage — no provider
  traits, nothing to swap. Fake backends for tests arrive as `#[cfg(test)]`
  seams alongside their real counterparts.
- **Configurable values**: trust store contents (`ConfiguredTrustedKeys`,
  supplied by value) and runtime policy (`PackageValidationPolicy`,
  validated at startup): size/entry bounds, compression ratio, nesting
  depth, accepted signature algorithms, compression methods, manifest
  versions, `max_manifest_bytes`. Deserializable from operator config; each
  validator snapshots one immutable policy.
- **Fixed invariants**: stage order, mandatory signature and mandatory
  trust store on the production path, traversal/duplicate/symlink
  rejection, fail-closed backends. These live in code, never in config.

## Errors

All error enums derive `Display` + `Error` via `thiserror`; messages are
part of the observable contract. Every backend is real and fails closed on
rejected input — there are no `NotImplemented` variants left in this
module. Still future: staged extraction with per-file byte agreement
(`storage::staging`) and audit logging of the authorizing signer.

## Tests

- Unit tests beside each module (bounds, path tables, EOCD parser vectors,
  signature roundtrips, manifest shape cases).
- `tests/archive_security.rs` — confinement invariants through the public
  API, plus one reader test per hostile-corpus fixture asserting its
  documented verdict.
- `tests/package_validation.rs` — policy gates, mandatory trust store at
  build, and end-to-end validation of a golden package built in-test
  (in-test construction keeps it in sync with the schema; no binary golden
  fixture to drift).
- `tests/testdata/` — evil-but-inert ZIP fixtures; see [the corpus
  reference](../../tests/testdata/README.md).
