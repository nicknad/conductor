# Architecture

> Current as of the Rust rewrite. The frozen .NET 10 implementation under
> `archive/dotnet-original/` and its design notes are reference only; nothing
> below describes them. There is no scheduler, no in-process plugin runtime,
> and no CLI yet — see [Not built yet](#not-built-yet).

Conductor is a single-machine job execution platform: operators upload signed
service packages, the host validates and stores them as immutable artifacts,
and each execution runs the approved artifact as one short-lived worker child
process. Single-crate Rust modular monolith (`src/`, `tests/`).

## Planes

| Plane | Module | Decides | Must never |
| --- | --- | --- | --- |
| Control | `control_plane/` | *What may run*: sequencing, policy checks, lifecycle transitions | Parse archives, do crypto, spawn processes |
| Execution | `executions/` | *How to run*: resolve, spawn, invoke, collect, terminate | Decide trust or policy; it executes exactly what it is handed |
| State | `modules/registry`, `storage/` | *What is true*: registrations, artifacts, quarantine, DB | Execute code or reinterpret policy |

`control_plane` cannot get code execution (no spawn primitive);
`executions` cannot bypass policy (no register/activate path, re-verifies
digests at spawn time). That split is the load-bearing security property.

## Module map

```text
src/
  main.rs / server.rs   Binary entry; fail-closed startup; TLS-only serving
  config.rs             Host configuration (bind, storage root, timeouts, TLS paths, rate floor, slots)
  api/                  HTTP interface: routes, uploads, bearer auth, transport guards, rejections
  control_plane/        Upload workflow, validation, registration, activation, lifecycle transitions
  packages/             Untrusted-bytes rules: zip, manifest, signature, digest, inventory, policy, artifact identity
  modules/registry      Registered module versions (memory or SQLite); idempotent / conflict semantics
  storage/              Quarantine, artifact store, verified staging, SQLite connection + migrations
  executions/           Worker spawn + stdin/stdout IPC protocol + process-group teardown
  audit/                Rejection-event taxonomy + recorder (tracing today, SQLite rows next)
```

Dependency direction: `api → control_plane → {packages, modules, storage}`;
`executions` uses `packages` (digest, archive confinement) and `storage::staging`
only. `packages` holds no lifecycle state and performs no directed writes.

## Upload pipeline

`POST /v1/packages` (`api/uploads.rs`, `api/routes.rs`):

1. **Transport.** TLS-only (`bind_rustls`, no plaintext listener), bearer auth
   on every `/v1` route (`401`, constant-time, indistinguishable
   missing/wrong), header caps (`431`), total-body bound (policy bound + 1 MiB
   slack), per-request timeout, 8 concurrent-upload slots (`503`), minimum
   upload speed (`408`), panic containment (bare `500`), security headers +
   `x-request-id` on every response. `/healthz` is the sole unauthenticated
   route and returns only `ok`.
2. **Stream to quarantine** (`storage::quarantine`). Package bytes stream
   straight to a `create_new` private file; per-chunk byte bound and rate
   floor enforced while writing. A `QuarantineGuard` deletes partial files on
   every failure path.
3. **Validate** (`control_plane::validate_package` over one open
   `QuarantinedFile` — hashing, inspection, and manifest reads share the
   handle, never a reopened path): policy gate → SHA-256 digest →
   Ed25519 detached-signature authentication against `ConfiguredTrustedKeys`
   → archive inspection → bounded manifest parse + inventory set-equality →
   `ValidatedPackage` verdict (artifact identity + exact manifest bytes +
   authorizing signer). Builder fails closed without a trust store; there is
   no skip-verification switch.
4. **Promote** (`storage::artifact_store`). Re-hash quarantine, compare to the
   verdict digest, `create_new` into
   `artifacts/{module_id}/{version}/{digest_hex}.zip`. Idempotent for the
   same digest; never overwrites.
5. **Register** (`control_plane::register_package` → `modules::registry`).
   Idempotent for the identical digest; a version re-registered with different
   bytes is a `409 VersionConflict` (promoted blob left unreferenced,
   harmless). Responds `201 {module_id, version, digest, signer_key_id}`.
6. **Activate** (`control_plane::activate_module`). Registry lookup + runtime
   allowlist; returns an `ActivatedModule` receipt (identity, digest, signer).
   Never re-opens archives or runs package bytes.

Every refusal handled by `post_package` or `require_bearer` produces
exactly one structured `RejectionEvent` (stage, caller-facing code,
internal detail, attribution-so-far) via `audit/`, as a tracing event
plus one `package_rejections` row. Responses produced before the handler
runs (extractor rejections, tower timeout/body-limit/panic pages) are not
audited. Quarantine bytes are deleted on failure.

## Storage layout (`storage_root`, default `data/`)

| Path | Contents | Written by |
| --- | --- | --- |
| `quarantine/` | Untrusted uploads awaiting validation | API streaming; deleted on failure |
| `artifacts/{module}/{version}/{digest}.zip` | Immutable promoted artifacts | Artifact store only |
| `database/conductor.db` | SQLite: module registry (+ activation/rejection rows per schema v1) | Registry / later phases |
| staging temp dirs | Owner-only verified extraction, removed on drop | `extract_verified`; executor re-verifies at spawn |

SQLite (`storage::database`): single mutex-guarded connection, WAL,
foreign keys, busy timeout, forward-only migrations with `user_version`
crash-resume; newer-than-binary DBs are refused. Repositories own queries.

## Execution (`executions/`)

One execution is one worker process (`executor.rs`):

1. **Resolve.** `WorkerTarget::resolve` re-hashes staged files against
   digests recorded at extraction, confines the entrypoint under the staging
   root, marks it owner-executable.
2. **Spawn.** `env_clear()` + explicit allowlist env (never secrets, never
   inherited), piped stdio, own process group, `kill_on_drop`.
3. **Invoke.** One newline-delimited JSON `ExecutionRequest` line on stdin
   (identity, `digest_hex`, configuration, `deadline_ms`, secrets), then EOF.
   Stdout/stderr drained concurrently from the start so a chatty worker
   cannot deadlock the exchange.
4. **Collect.** One `ExecutionResponse` line on stdout (`ok` + result, or
   `failed` + message); strict version/shape gate. Stderr is diagnostics,
   bounded and truncated with byte counts kept.
5. **Terminate.** Deadline/cancel → `SIGTERM` the group, `SIGKILL` after a
   grace period, best-effort descendant cleanup. Outcomes: `Succeeded |
   Failed | TimedOut | Cancelled | WorkerError | ProtocolViolation`.

Trust scope: workers inherit the host `uid`/`gid`/groups by design. The
process boundary is crash/hang/resource containment, **not** a security
sandbox; filesystem/network/credential isolation is a deployment concern.
Secrets ride stdin only (`Debug` redacts them); request/response sizes,
stderr volume, and wall time are all bounded.

## Invariants

1. Authenticate before parsing — nothing inside an archive is trusted before
   the outer bytes verify.
2. No TOCTOU — hash, inspect, extract, promote, and resolve each re-verify;
   a path is never trusted across time.
3. The registry is the authority on what `(module_id, version)` means; the
   artifact store is content-addressed and never the source of truth.
4. A version never silently changes meaning (`VersionConflict`).
5. Fail closed — missing trust store, non-ingestable policy, oversized,
   unauthenticated, or saturated: refuse, never degrade.
6. One rejection, one event; recording never changes a response.

## Not built yet

Scheduler/triggering, CLI, operator trusted-key loading (`server::run`
refuses to serve until it lands — the API is exercised via `router` in
tests), durable audit sink behind `RejectionRecorder::record`, startup
reconciliation/leftover sweeps, artifact GC, and any execution-history or
activation persistence beyond the registry. `control_plane/lifecycle.rs` is
currently a placeholder for deactivate/remove/rollback transitions.
