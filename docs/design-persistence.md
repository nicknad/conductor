# Persistence and Rejection Events — Design

> **Status:** in progress — **PR1 (structured rejection events)**,
> **PR2 (SQLite registry persistence)**, and **PR3 (durable rejection
> rows)** implemented. Later phases are not yet implemented. Implements audit items 7 and 8 from
> [storage-reconciliation.md](storage-reconciliation.md). Decisions recorded
> here: **SQLite via `rusqlite` (bundled)** for the registry and rejection
> records; rejections go to **structured `tracing` events and `package_rejections`
> rows**; the promote-then-register order is unchanged.

## 1. Scope

- **A. Structured rejection events** — a typed taxonomy for every package
  rejection, emitted as structured tracing and persisted as rows.
- **B. Persistence** — SQLite-backed module registry: modules, versions,
  artifacts, validation state, activation.
- **C. Reconciliation** — startup repair of DB↔filesystem inconsistency plus
  leftover quarantine/staging sweeps.

**Out of scope:** jobs/executions/scheduler tables, artifact GC deletion,
backup/restore, rejection retention limits, trust-key loading, worker staging
wiring.

## 2. Load-bearing invariants

- The validation verdict is the only registrable input; persistence adds no
  trust. (Unchanged from `src/control_plane/register_package.rs`.)
- Promote-then-register stays the order. Registration is **one DB transaction**.
  The DB is authority for *which digest a module version means*; artifacts remain
  content-addressed by digest and re-verified at use.
- A failed audit write must never change or block the HTTP response.
- DB open and migration failure are fail-closed at startup, with the same
  posture as the policy gate in `src/server.rs`.
- Migrations are forward-only; a schema newer than the binary is refused.
- No secrets, signature bytes, or package contents in rows. Explicit paths,
  never the process working directory; owner-only files.

## 3. Rejection events

### 3.1 Event type

`src/audit/event.rs`:

```rust
pub struct RejectionEvent {
    pub event_version: u16,          // 1
    pub occurred_at: SystemTime,
    pub request_id: Option<String>,  // server-issued x-request-id
    pub stage: RejectionStage,
    pub code: &'static str,          // stable; matches the external error codes
    pub detail: String,              // internal reason, bounded to 4 KiB
    pub detail_truncated: bool,
    pub key_id: Option<String>,      // claimed signer, for audit attribution
    pub module_id: Option<String>,
    pub version: Option<String>,
    pub digest: Option<String>,      // set once the digest stage was reached
    pub byte_count: Option<u64>,     // received package bytes
}
```

### 3.2 Stages

```rust
pub enum RejectionStage {
    Transport,   // bearer, headers, timeouts, body limits
    Multipart,   // malformed/missing/duplicate fields, bad base64
    Streaming,   // oversize-while-streaming, rate floor
    Policy, Archive, Digest, Signature, Manifest, Inventory,
    Promotion, Registration, Internal,
}
```

### 3.3 Emission points

| Site | Events |
| --- | --- |
| `post_package` (`src/api/uploads.rs`) | multipart shape, streaming, timeout, validation stages, promotion, registration conflict |
| `require_bearer` (`src/api/uploads.rs`) | 401 unauthenticated |

Typed events record the error's stable code. Responses produced before the
handler runs (wrong content type rejected by the multipart extractor, tower
timeout 503 / body-limit 413 / panic 500 pages, hyper's own 431) are not
audited: there is no fallback middleware.

Two rules encode behavior that would otherwise erode:

1. **Record before unification.** Today `From<ValidationError>` in
   `src/api/errors.rs` hides the internal signature variant while the response
   body stays uniform. The event is recorded from the `ValidationError`
   *before* that conversion, so the row carries `UnknownKey("k9")` or
   `VerificationFailed` while callers still see
   `signature_verification_failed`. No key-enumeration oracle is reintroduced.
2. **Exactly one event per refusal.** Every failure in `post_package` is
   returned as an `UploadFailure` carrying the audit facts and converted
   once into a recorded response; `require_bearer` records inline. Handler
   paths are therefore recorded exactly once by construction.

`request_id` is read from the request's `x-request-id` header —
`SetRequestIdLayer` already issues it before handlers run. `post_package`
takes a `HeaderMap` extractor and `require_bearer` reads request headers
directly.

### 3.4 Sinks and failure isolation

- **Always:** one structured `tracing::warn!` event (`package_rejected`) with
  the event fields.
- **Persisted:** one `package_rejections` row once the store lands (phase 3).
  Writes are best-effort: failures are logged and counted, never propagated;
  status codes and bodies are untouched.
- **Bounds:** `detail` truncated at 4 KiB on a char boundary with
  `detail_truncated` set; no signature bytes, secrets, or package contents.

## 4. Persistence

### 4.1 Engine

SQLite via `rusqlite` (`bundled` feature; latest stable 0.40.2, MIT at plan
time — pin with `cargo add rusqlite --features bundled`). The bundled build
vendors SQLite, so no system library is required on Linux or Windows CI. The
transitive chain (`rusqlite`, `libsqlite3-sys`, `hashlink`, `fallible-iterator`,
`smallvec`) is MIT/Apache and passes `deny.toml`'s allowlist; the PR must still
run `cargo deny check`.

Why not `sqlx` (async and heavier than needed; the store runs on blocking
threads), `redb` (hand-rolled indexes and scans), or files (no transactions or
queries — unacceptable for a registry authority).

### 4.2 Module layout

| Location | Owns |
| --- | --- |
| `src/storage/database.rs` | open, pragmas (WAL, `foreign_keys=ON`, `busy_timeout=5s`, `synchronous=NORMAL`), `PRAGMA user_version` migration runner, transaction helper |
| `src/audit/event.rs`, `src/audit/recorder.rs` | taxonomy, tracing sink, DB sink |
| `src/storage/reconcile.rs` | startup reconciliation and leftover sweeps |
| `src/modules/registry.rs` | backend enum: in-memory (tests) or SQLite (production) |

`ModuleRegistry::new()` stays as the in-memory constructor so every existing
call site and unit test is untouched; `ModuleRegistry::open(path)` is the
production constructor. The two integration state builders
(`tests/upload_api.rs`, `tests/tls_only.rs`) switch to temp-file databases so
the real path is exercised.

### 4.3 Configuration

`src/config.rs` additions, all derived under the configured `storage_root`:

- `database_path()` → `storage_root/database/conductor.db`
- `staging_dir()` → `storage_root/staging` (the staging root is currently
  caller-supplied and unconfigured)
- `quarantine_ttl`, `staging_ttl` for the sweeps

### 4.4 Schema v1

```sql
CREATE TABLE modules (
  module_id  TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE module_versions (
  module_id        TEXT NOT NULL REFERENCES modules(module_id) ON DELETE CASCADE,
  version          TEXT NOT NULL,
  digest           TEXT NOT NULL CHECK (length(digest) = 64),
  signer_key_id    TEXT NOT NULL,
  runtime          TEXT NOT NULL,
  manifest_version INTEGER NOT NULL,
  manifest_json    TEXT NOT NULL,               -- exact validated bytes
  artifact_relpath TEXT NOT NULL,               -- relative to the artifacts root
  artifact_size    INTEGER NOT NULL,
  integrity_state  TEXT NOT NULL DEFAULT 'ok',  -- 'ok' | 'missing' | 'mismatch'
  registered_at    INTEGER NOT NULL,            -- unix millis
  PRIMARY KEY (module_id, version)
);

CREATE TABLE active_versions (
  module_id    TEXT PRIMARY KEY REFERENCES modules(module_id) ON DELETE CASCADE,
  version      TEXT NOT NULL,
  activated_at INTEGER NOT NULL,
  FOREIGN KEY (module_id, version)
    REFERENCES module_versions(module_id, version)
);

CREATE TABLE package_rejections (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at      INTEGER NOT NULL,
  event_version    INTEGER NOT NULL,
  request_id       TEXT,
  stage            TEXT NOT NULL,
  code             TEXT NOT NULL,
  detail           TEXT NOT NULL,
  detail_truncated INTEGER NOT NULL DEFAULT 0,
  key_id           TEXT,
  module_id        TEXT,
  version          TEXT,
  digest           TEXT,
  byte_count       INTEGER
);

CREATE INDEX idx_rejections_occurred_at ON package_rejections(occurred_at);
```

Notes:

- Timestamps are unix millis (`i64`); no `chrono`.
- `manifest_json` stores the exact validated bytes, which requires threading
  the already-read manifest bytes into `ValidatedPackage` (they exist in
  `PackageValidator::validate` today).
- `artifact_relpath` is stored rather than derived so reconciliation does not
  depend on layout code.
- `active_versions` is created now and wired when activation gets a caller.
- The migration runner applies each migration in its own transaction and sets
  `user_version` inside it; a `user_version` newer than the binary is a startup
  error.

### 4.5 Registry semantics

`record()` keeps today's behavior, in SQL, inside one transaction:

1. `INSERT OR IGNORE INTO modules` (created_at).
2. `SELECT digest` for `(module_id, version)`:
   - same digest → `Ok(already_registered = true)`;
   - different digest → `VersionConflict`;
   - absent → insert the full row → `Ok(already_registered = false)`.

Additional read API: `list_versions(module_id)` (landed with PR2);
`all_versions()` and `artifact_state()` land with reconciliation (PR4).

### 4.6 Upload ordering and crash windows

Order is unchanged: **stream → validate → promote (fsync) → register (one DB
tx) → 201**.

| Crash window | Residue | Detection | Action |
| --- | --- | --- | --- |
| during streaming | partial quarantine file | `upload-*.zip` naming + TTL | sweep |
| during validation | quarantine file | same | sweep |
| during promotion | partial file at a digest name | size mismatch; hash won't match the name | report; deletion policy below |
| after promote, before register | complete unreferenced artifact | DB scan vs. artifact tree | report (orphan) |
| after register | none — file and row consistent | — | — |
| future removal (row first, file second) | orphan artifact | same scan | report |

## 5. Reconciliation

### 5.1 Startup sequence

1. Load config; ensure/validate the configured roots.
2. Open the database; run migrations. **Failure aborts startup.**
3. Reconcile (below).
4. Build the registry from DB state.
5. Build the validator and serve (validator construction still fails closed
   until trust-key loading lands — separate work).

### 5.2 Algorithm (idempotent, safe to repeat)

1. Sweep `quarantine/` and `staging/` entries older than their TTLs. This
   wires the existing `sweep_older_than` and adds the staging twin, which also
   closes the crash leak for kept staging directories.
2. For every `module_versions` row, stat the artifact: missing or size
   mismatch sets `integrity_state` to `missing` / `mismatch`. Activation and
   any future execution path refuse rows not in `ok`.
3. Scan the artifact tree for files referenced by no row: report count and
   sample (orphans). No deletion in this pass.
4. Recommended: record one `reconciliation_runs` row per run
   (`started_at`, `finished_at`, `missing_artifacts`, `orphan_artifacts`,
   `swept_quarantine`, `swept_staging`) for the observability surface.

### 5.3 Fail-closed rules

- DB open/migrate errors and reconciliation read errors abort startup.
- Per-row marking and sweep I/O errors log and continue; one bad file must not
  prevent serving the rest.

### 5.4 Deletion policy

No destructive deletes in this pass. The only deletion ever added without a
retention decision: unreferenced files whose bytes do not hash to their digest
name (crashed partials — useless by definition). Complete unreferenced blobs
wait for the retention/GC work.

## 6. Testing

- **Migrations:** fresh database, re-run idempotent, partially applied run
  resumes, newer `user_version` refused.
- **Registry:** reopen round-trip (registration survives restart),
  conflict/idempotency across reopen, `manifest_json` preserved byte-exact.
- **Rejections:** representative 400/401/413/422/409 paths assert row
  stage/code and that the external body is unchanged; accepted uploads write
  no rejection row; recorder failure does not alter the response.
- **Reconciliation:** construct each crash residue directly (artifact without
  row, row without artifact, stale quarantine/staging) and assert detection,
  `integrity_state` marking, and activation refusal.
- **Existing suites:** unchanged in-memory unit tests; the two integration
  builders move to temp-file databases.

## 7. Phases

1. **PR1 — taxonomy and structured tracing (implemented)** (`src/audit/`):
   typed recording sites, response-marker mechanism. No DB, no external
   behavior change.
2. **PR2 — SQLite store (implemented)**: `rusqlite` (bundled),
   `storage/database.rs` with the WAL/pragma policy and forward-only
   migrations, `ModuleRegistry::open` / `open_in_memory` whose records
   survive a reopen, `Config::database_path`, and a Rust CI workflow
   (`fmt`, `clippy`, `test`, `cargo deny`). Wiring the store into
   `server::run` happens with startup assembly (still gated on trust-key
   loading).
3. **PR3 — rejection rows (implemented)**: DB sink
   (`src/audit/store.rs`), request-id plumbing, bounded detail.
   `RejectionRecorder::new()` stays tracing-only; `with_store` attaches
   the `package_rejections` insert (best-effort, never alters the
   response).
4. **PR4 — reconciliation**: integrity states, staging sweep, startup wiring,
   `reconciliation_runs`.
5. **PR5+** — activation persistence wiring, artifact GC and retention, backup,
   execution tables when the dispatcher lands.

## 8. Deferred

- Rejection retention (the table is unbounded until then).
- Full audit log (who/when for operator actions) beyond package rejections.
- Artifact/quarantine permission hardening from audit item 3.
- Trust-key loading (audit item 2) — a prerequisite for `server::run` to
  actually serve, independent of this design.
