# Storage Design Reconciliation

> **Point-in-time audit.** This compares the recovered *Conductor storage design:
> agreements and open questions* summary against the Rust rewrite as of commit
> `1a53adc` (2026-10-11). It records which parts of that summary the code already
> decides, which it contradicts, and which remain genuinely open. Section 7
> ranks the findings by how much they would improve the Rust version; section 8
> records what is already settled. It is **not a specification** — the
> [repository README](../README.md) and module READMEs are the entry points for
> the current code.

**Status vocabulary**

- **Implemented** — code enforces what the summary states.
- **Partial** — pieces exist; gaps are named.
- **Superseded** — code made a different decision; the summary text is stale.
- **Conflict** — code contradicts the stated agreement; needs explicit resolution.
- **Open** — nothing in code decides it.

## 1. Storage layout

| Summary element | Status | Reality in code |
| --- | --- | --- |
| `incoming/` | Not built | No such directory and no URL ingestion; uploads stream straight into quarantine (`src/api/uploads.rs`) |
| `quarantine/` | **Implemented** | `<storage_root>/quarantine`, `upload-<pid>-<nanos>-<counter>.zip`, `create_new`, guard deletes on every failure path (`src/storage/quarantine.rs`) |
| `staging/` | **Partial** | `extract_verified` creates a caller-supplied root with `0700` permissions and drop-cleanup (`src/storage/staging.rs`); not invoked by the upload flow, no configured staging root, kept directories leak on crash — and see the conflict in §2 |
| `artifacts/sha256/ab/<digest>/` | **Superseded** | Actual layout is `artifacts/{module_id}/{version}/{digest}.zip` (`src/config.rs`, `src/storage/artifact_store.rs`); the digest is the filename, not a pure digest fan-out, so identical digests are not shared across module versions |
| `database/` | **Open** | No database; `ModuleRegistry` is in-memory, and its module docs say "Persistence is future work" (`src/modules/registry.rs`) |
| `logs/` | **Open** | `tracing` to stderr only (`src/server.rs`); no log files, no durable audit |

## 2. Area responsibilities and constraints

| Area | Agreed constraint | Verdict |
| --- | --- | --- |
| Incoming / quarantine | Treat contents as untrusted | Implemented for uploads (signature mandatory, authentication before parsing, quarantine never executed) |
| Staging | Private workspace; **never execute from it** | **Conflict** — the executor spawns workers from the staging root after digest re-verification (`WorkerTarget::resolve` in `src/executions/executor.rs`, `src/executions/mod.rs`). The code's actual invariant is "never execute unverified bytes; re-verify at every use," not "never execute from staging" |
| Artifact store | Immutable, content-addressed | Implemented (`create_new`, re-hash, no overwrite), with the layout caveat above; a version-conflict upload leaves an unreferenced promoted blob |
| Database | Register only after successful validation and artifact promotion | Order implemented (promote → register in `src/api/uploads.rs`); no database, no validation-status persistence, only a `tracing` audit event |
| Logs | Record validation and lifecycle events | Partial: one tracing event in `run_upload_workflow`; nothing durable |

## 3. Lifecycle sequence (eight steps)

1. **Receive ZIP / download from URL** — Partial: upload exists; URL download does not.
2. **Size and processing limits** — Implemented: policy byte/entry/ratio/depth bounds, streaming cap, body/field/header caps, timeouts, upload rate floor, 8 concurrent slots returning `503` (`src/packages/policy.rs`, `src/api/routes.rs`, `src/api/uploads.rs`).
3. **Digest + detached signature** — Implemented, with a different shape: the body streams to quarantine, then digest and signature verification run over one handle (`src/control_plane/validate_package.rs`). The signature is Ed25519 over `domain ‖ zip/v1 ‖ sha256 ‖ archive-digest` — it covers the whole archive, not a separate manifest document, and it is not CMS (`src/packages/signature.rs`).
4. **Archive/manifest/paths/inventory/dependencies/limits** — Partial: everything implemented except dependencies — the manifest has no dependency concept, and unknown fields are rejected (`src/packages/manifest.rs`).
5. **Extract into private staging with content and hash checks** — Implemented as a function (manifest v2 per-file size and SHA-256 enforced during extraction), but **not wired into the production upload path**.
6. **Promote to immutable storage** — Implemented and wired: re-hash quarantine, `create_new`, file fsync, partial-write self-repair, quarantine consumed (`src/storage/artifact_store.rs`).
7. **Register in database** — Partial: in-memory registry stores id/version/digest/signer/runtime/timestamp; no database, no validation report, lost on restart.
8. **Explicit activation; execution resolves a registered artifact** — Partial: `activate()` checks the registry and runtime allowlist and returns digest + signer (`src/control_plane/activate_module.rs`), but has no API/CLI wiring, no persisted activation, and the executor is handed a staged package rather than resolving a registered artifact.

## 4. Additional agreements

| Agreement | Verdict |
| --- | --- |
| Immutable versions | Implemented: registry `VersionConflict`; artifact `create_new`. A version conflict intentionally leaves the promoted blob unreferenced (`src/control_plane/register_package.rs`). |
| Content addressing (SHA-256) | Implemented: SHA-256 over the exact archive bytes — ZIP encoding included, so semantically identical packages can have different digests |
| Version pinning | Partial: the execution protocol pins `module_id`/`version`/`digest_hex` (`src/executions/protocol.rs`), but no dispatcher enforces a registry lookup yet |
| TOCTOU protection | **Implemented, layered**: one handle in validation, re-hash at promotion, re-hash at staging, re-hash of staged files at resolve |
| Crash recovery | Partial: idempotent promotion, partial-write repair, failure-path quarantine cleanup — but no startup reconciliation and no orphan detection; with an in-memory registry, every restart claims no artifacts at all |
| Execution semantics | Open: no retries, attempts, execution store, or idempotency controls |

## 5. Open questions

| Topic | What code already answers | What remains |
| --- | --- | --- |
| Signature format | **Decided**: Ed25519-only detached envelope, fixed canonical payload, key record owns the algorithm (`src/packages/signature.rs`). The CMS question is resolved *no* — the module comment says prefer CMS only if certificate-based interoperability is ever required. | On-disk key format and loading |
| Package schema | **Mostly decided**: manifest v1/v2, unknown fields rejected, `manifest.json` at the archive root, `entrypoint ∈ files`, path-safe ids, ZIP only, stored/deflate, policy allowlists (`src/packages/manifest.rs`, `src/packages/policy.rs`, `src/packages/archive.rs`) | Dependency handling; schema evolution and freeze policy |
| Trust management | Partial: `ConfiguredTrustedKeys` built by value; duplicate and empty ids rejected; the server fails closed until key loading lands (`src/server.rs`) | Provisioning, rotation, revocation, per-module-ID authorization |
| Database | **Open** | Everything |
| Artifact storage | **Decided for now**: local filesystem | Remote/object backend; explicit artifact permissions (staging sets `0700`; artifact files rely on umask) |
| Deduplication | **Open**; identical digests are duplicated under different module/version paths | Sharing layout and reference counting |
| Promotion | **Implemented**: `create_new`, file fsync, same-digest reuse, delete-and-rewrite for partial writes, quarantine consumed (`src/storage/artifact_store.rs`) | Directory fsync; explicit mode bits |
| Crash reconciliation | Partial mechanics only: idempotent promotion and a quarantine sweep helper that **exists but has no caller** (`src/storage/quarantine.rs`) | Startup reconciliation and orphan/missing detection — blocked on persistence |
| Retention | Mostly open: rejected uploads are deleted immediately; the sweep helper is unwired; **no artifact GC**; staging cleanup only via drop | Policies for all four areas |
| Activation and removal | Partial: `activate()` plus runtime allowlist | Persisted active version, deactivate/remove, draining, reference counting (no scheduler yet) |
| Resource limits | Partial: rich upload/worker limits, concurrency cap | Disk quotas and disk-pressure behavior |
| Download security | **Open** | No URL ingestion exists at all in the Rust code |
| Backup and recovery | **Open** | Nothing in the rewrite (the .NET-era design is only in `archive/`) |
| Audit and observability | Partial: tracing events including signer attribution, `/healthz`, request ids | Durable audit, retention, storage exhaustion/corruption reporting, metrics |

## 6. Bottom line

The summary is stale in both directions: several "open questions" are already
decided by the Rust code (signature format, most of the schema, promotion,
TOCTOU), while the "agreed" invariant about staging is contradicted by the
executor. The proposed layout (`incoming/`, pure-digest artifacts, `database/`,
`logs/`) describes a system that does not exist in the Rust rewrite yet; it
reads more like the frozen .NET design.

Genuinely open, in dependency order:

1. **Persistence and crash reconciliation** — the database, registry durability, orphan/missing artifact repair, and validation-status storage all collapse into this one item. It gates retention and reconciliation.
2. **Staging execution invariant** — decide between "staging may host execution copies only after digest re-verification" (matches current code) and "execution always resolves artifact-store copies."
3. **Activation, removal, and drain semantics** — persisted active version, reference counting, drain policy.
4. **Retention, GC, and disk-pressure behavior** — wire the existing sweep, add artifact GC.
5. **Trust key lifecycle** — on-disk key format, rotation, revocation, per-module authorization. Note that `server::run` currently refuses to start until this lands; the upload API is exercised through `router` in tests only.
6. **Download ingestion and SSRF model** — only if URL ingestion is still wanted.
7. **Deduplication and refcounting** — resolvable only together with a layout change if pure digest-addressed storage is desired.
8. **Backup/restore and durable audit.**

## 7. Prioritized enhancements

The audit findings ranked by how much they would improve the Rust version. Items
are independently shippable unless noted. Items 7 and 8 are planned in detail in
[design-persistence.md](design-persistence.md).

### Quick wins (self-contained, no prerequisites)

1. **Wire the quarantine sweep, and add a staging sweep.** `sweep_older_than`
   exists but has no caller (`src/storage/quarantine.rs`), and staged
   directories leak when the host crashes mid-execution (`StagedPackage::keep`).
   A startup sweep makes "leaks bound themselves" true instead of aspirational.
2. **Trusted-key loading so the binary can start.** `server::run` deliberately
   refuses to serve until key loading lands (`src/server.rs`). Today the upload
   API exists only inside tests; this is the largest distance between
   "implemented" and "usable" that needs no new subsystem.
3. **Explicit permissions on the artifact and quarantine roots.** Staging sets
   `0700`; artifacts and quarantine rely on umask
   (`src/storage/artifact_store.rs`). Align writable roots to owner-only and
   refuse world-writable roots at startup.
4. **Directory fsync after promotion.** Promotion fsyncs the file but not the
   containing directory (`src/storage/artifact_store.rs`), so a crash can lose
   the name while the operation claimed success.
5. **Per-module authorization in the trust store.** Any trusted key can
   currently sign any `module_id` (`TrustedSigningKey` has no scope). Adding
   key→allowed-modules (or runtime) mapping now is small; retrofitting it into
   persisted trust state later is migration work.
6. **Disk-pressure preflight.** Nothing checks free space before accepting an
   upload; a full disk surfaces as an internal error mid-stream. A preflight
   plus a defined rejection code bounds the failure mode.
7. **Structured validation-failure events.** Rejected uploads leave only prose
   errors; a reason taxonomy in `tracing` makes them debuggable now and becomes
   the durable audit record's schema later. Taxonomy and tracing landed (PR1 of
   [design-persistence.md](design-persistence.md)); durable rows are PR3.

### Foundation (by far the largest enhancement)

8. **Persist the registry, then reconcile on startup.** The in-memory
   `ModuleRegistry` (`src/modules/registry.rs`) means every restart forgets all
   registrations while artifacts accumulate on disk, so the audit's
   crash-recovery and retention questions are unanswerable today. Persisting
   modules, versions, digests, signers, validation reports, and activation state
   — the SQLite choice from the .NET-era docs is the natural precedent —
   unlocks:
   - meaningful restart semantics;
   - orphan-artifact and missing-artifact detection;
   - artifact GC and retention driven by real references;
   - durable audit and per-execution records.

   §6 items 1, 4, and 8 are gated on this workstream; item 2 (staging invariant)
   and item 7 (dedup) are gated on the decisions below. Registry persistence and
   migrations landed (PR2 of [design-persistence.md](design-persistence.md));
   startup reconciliation is PR4.

### Decide before more artifacts accumulate (order-dependent)

9. **Dedup and layout.** Keep `artifacts/{module_id}/{version}/{digest}.zip` or
   move to digest-addressed storage with refcounts. Deciding after artifacts,
   backups, and reconciliation encode the current layout means a migration;
   deciding now is nearly free.
10. **The staging-execution invariant.** Keep "staging is a re-verified
    execution workspace" (matches the executor today, cheaper) or enforce
    "execution only from artifact-store copies." This shapes the executor, GC,
    and permissions design — and it is currently a contradiction, not a gap.

### Later (once a dispatcher exists)

11. Activation, drain, and removal with reference counting; end-to-end version
    pinning (the protocol carries `module_id`/`version`/`digest_hex`, but
    nothing enforces a registry lookup before spawn); and idempotency and retry
    semantics for jobs.

## 8. Don't re-litigate

Signature format (Ed25519 envelope is decided, CMS deliberately not), package
schema (v1/v2 is real), TOCTOU (already layered), and promotion mechanics
(idempotent and sound). Also, "add an `incoming/` directory" and "add a
`database/` directory" are not enhancements — persistence and URL ingestion are
the underlying items, and both are already represented above.
