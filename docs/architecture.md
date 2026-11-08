# Architecture

> Current as of the Rust rewrite. The scheduler supports manual, interval, and
> UTC five-field cron triggers; an in-process plugin runtime and a CLI are not
> built yet — see [Not built yet](#not-built-yet).

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
  metrics.rs            Ephemeral OpenTelemetry metrics, OTLP/HTTP export, views, cached instruments
  api/                  HTTP interface: routes, uploads, bearer auth, transport guards, rejections
  control_plane/        Upload workflow, validation, registration, activation, lifecycle transitions, scheduler
  packages/             Untrusted-bytes rules: zip, manifest, signature, digest, inventory, policy, artifact identity
  modules/registry      Registered module versions (memory or SQLite); idempotent / conflict semantics
  storage/              Quarantine, artifact store, verified staging, SQLite connection + migrations
  executions/           Worker spawn + stdin/stdout IPC protocol + process-group teardown
  audit/                Rejection-event taxonomy + recorder (tracing plus SQLite rows)
```

Dependency direction: `api → control_plane → {packages, modules, storage}`;
`executions` uses `packages` (digest, archive confinement) and `storage::staging`
only. `packages` holds no lifecycle state and performs no directed writes.

## Startup (`server::run`)

Startup is fail-closed and ordered so a rejected configuration leaves no
state behind:

1. `Config::load` merges defaults, the `--config`/`CONDUCTOR_CONFIG` JSON
   file, a token file, a trusted-keys file, and `CONDUCTOR_*` overrides.
2. `Config::validate_for_startup` requires an operator token, usable bind,
   timeout, slot count, and paths, and builds the trust store through
   `Config::trust_store` (standard-base64, 32-byte Ed25519, unique key ids).
3. The production validation policy must be ingestable; the validator is
   built around the configured trust store (no skip-verification path).
   Metrics are built here, after config validation but before any listener:
   an unset `otlp_endpoint` yields a no-reader provider (no network client or
   export thread), otherwise one OTLP/HTTP exporter (base URL plus
   `/v1/metrics`, rustls for HTTPS) and periodic reader. The global handle
   used by storage instrumentation is installed immediately.
4. `Config::ensure_layout` creates/tightens `quarantine/`, `artifacts/`,
   `database/`, and `staging/` under the storage root, refusing a symlinked
   or world-writable existing root.
5. Startup sweeps `quarantine/` files and `staging/` directories older than
   their configured TTLs, removing crash/drop leftovers before any request
   can race the sweep.
6. One `Database` is opened and migrated; the module registry, rejection
   store, and execution-history store share it through `Arc`, so one
   connection owns the WAL/pragma policy.
7. Reconcile every registered version's artifact (classify-only). Each row is
   classified as `ok`, `missing`, or `mismatch` without reading package code
   or rewriting bytes; a read or persist error aborts startup. This runs after
   the registry exists and before readiness, execution services, or the
   router are built.
8. The assembled `Host` builds the router (configured bearer token, upload
   slots, request timeout) and starts the scheduler. Scheduler recovery and
   the loop-ready handshake run before TLS bind; a scheduler start failure
   aborts startup with no listener. The host then serves TLS-only on the
   configured bind.

Failures at any step abort startup without binding a listener.

## Upload pipeline

`POST /v1/packages` (`api/uploads.rs`, `api/routes.rs`):

1. **Transport.** TLS-only (`bind_rustls`, no plaintext listener), bearer auth
   on every `/v1` route (`401`, constant-time, indistinguishable
   missing/wrong), total-body bound (policy bound + 1 MiB slack),
   per-request timeout, 8 concurrent-upload slots (`503`), panic
   containment (bare `500`), security headers + `x-request-id` on every
   response. `/healthz` (liveness) and `/readyz` (cached readiness) are the
   only unauthenticated routes. `/healthz` returns only `ok`; `/readyz` returns
   `ok` only when the cached readiness state says the shared database is
   migrated/probeable and the scheduler hook is ready, otherwise `503
   unavailable` with no detail. The route only reads two atomics.
2. **Stream to quarantine** (`storage::quarantine`). Package bytes stream
   straight to a `create_new` private file with a per-chunk byte bound.
   A `QuarantineGuard` deletes partial files on every failure path.
   Slow bodies are bounded by the total per-request timeout.
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
plus one `package_rejections` row. The route's transport mapper also
audits and JSON-renders multipart-extractor 400s and body-limit 413s.
Tower timeout 503, panic 500, and hyper's own 431 pages still bypass the
mapper. Quarantine bytes are deleted on failure, including when the
request future is dropped after streaming.

## Storage layout (`storage_root`, default `data/`)

| Path | Contents | Written by |
| --- | --- | --- |
| `quarantine/` | Untrusted uploads awaiting validation | API streaming; deleted on failure |
| `artifacts/{module}/{version}/{digest}.zip` | Immutable promoted artifacts | Artifact store only |
| `database/conductor.db` | SQLite: module registry, activation/rejection rows, execution history (schema v2) | Registry / audit / history phases |
| `staging/` | Owner-only verified extraction, removed on drop | `extract_verified`; executor re-verifies at spawn |

`Config::ensure_layout` creates the root and its managed directories with
owner-only permissions at startup, tightening existing directories too.

SQLite (`storage::database`): one mutex-guarded connection shared through
`Arc<Database>` by the registry and rejection store, WAL, foreign keys, busy
timeout, forward-only migrations with `user_version` crash-resume;
newer-than-binary DBs are refused. Repositories own queries.

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
5. **Terminate.** Deadline/cancel → `SIGTERM` the group, `SIGKILL` after the
   2-second grace period, best-effort descendant cleanup. Outcomes: `Succeeded |
   Failed | TimedOut | Cancelled | WorkerError | ProtocolViolation`.

The HTTP request timeout covers request preparation (resolution, artifact
verification, extraction, and spawn setup) as well as the worker run, and
leaves the 2-second termination grace for process-group teardown.

Trust scope: workers inherit the host `uid`/`gid`/groups by design. The
process boundary is crash/hang/resource containment, **not** a security
sandbox; filesystem/network/credential isolation is a deployment concern.
Secrets ride stdin only (`Debug` redacts them); request/response sizes,
stderr volume, and wall time are all bounded.

### Registered-artifact execution (`control_plane::execute_module`)

The execution service closes the restart gap: it resolves an active or
pinned version from the registry, loads the promoted artifact, and hands a
verified staged target to the worker executor. Fail-closed checks before
spawn:

- activation policy (the `allowed_runtimes` metadata filter) is re-applied to
  the record actually used for execution; it is not a sandbox;
- `artifact_relpath` must exactly equal the canonical
  `{module_id}/{version}/{digest}.zip` address and resolve under the artifact
  root (no traversal, symlink escape, or sibling-prefix confusion);
- artifact size is bounded by the package policy before hashing; size and
  SHA-256 must match the registry record;
- execution requires **manifest v2** (v1 has no per-file integrity, so it
  cannot be safely rebound after restart);
- the archive `manifest.json` read from the artifact must match the stored
  manifest identity/runtime/entrypoint/files, and extraction enforces v2
  per-file size/SHA-256;
- `signer_key_id` must be in the current operator allowlist (revocation
  takes effect at execution; this is an id allowlist, not signature
  re-verification);
- concurrency is bounded by a semaphore; preparation runs on the blocking
  pool and the permit survives caller cancellation;
- staged files are re-verified immediately before spawn, with the entrypoint
  checked last.

Residual, documented risks: registry/artifact-store write access is code
execution authority; the signer check is id-only; and pre-spawn verification
is not atomic with `exec`, so a same-uid writer inside the 0700 staging
directory can still race the final path resolution. HTTP exposure must not
weaken these invariants.

### Scheduler slice 3 (`control_plane::scheduler`)

Durable job definitions live in `jobs`; `job_runs.state` is the durable queue.
Scheduler slice 3 supports manual triggers, interval triggers, and UTC
five-field cron triggers. A job pins `(module_id, version, function)` and a
bounded JSON payload. `interval_secs` is bounded to `1..=31_536_000` (one year).
Cron uses a closed grammar: minute `0-59`, hour `0-23`, day-of-month `1-31`,
month `1-12`, day-of-week `0-7` (0 and 7 are Sunday), with `*`, numbers, ranges
`a-b`, lists `a,b`, `*/n`, and `a-b/n`. Names, macros, seconds/6-field or
7-field expressions, and `?`/`L`/`W`/`#` are rejected before the parser crate
runs. When day-of-month and day-of-week are both restricted, a time matches if
either matches (POSIX OR). Evaluation is UTC only. The `croner` parser sits
behind a private `cron.rs` wrapper, and neither its types nor `chrono` types
escape that module.

Each loop iteration first enqueues due interval and cron runs in one immediate
transaction. For every enabled interval or cron job with `next_run_at <= now`
it inserts one `queued` run with the row's `trigger_kind` and
`scheduled_for=next_run_at`, then advances `next_run_at` to the first boundary
strictly after `now` (interval math, or the first matching UTC cron
occurrence). Advancing `next_run_at` prevents repeated ticks for the same
boundary; the partial `idx_job_runs_tick` index is the backstop if a boundary
is seen twice. When the global queued-run bound is full, the due boundary is
left unchanged so a later tick retries it. Restart catch-up therefore enqueues
at most one missed run per job, not a burst. A persisted cron expression that
no longer parses is skipped and counted, not enqueued, and reads of that job
fail closed. A syntactically valid but impossible expression is also skipped
and counted, but the row still reads back; the job does not run until the
expression is repaired. The loop then claims queued runs
with an immediate SQLite transaction, records
`started_at`/`claimed_by`/`lease_expires_at`, and hands the run to a narrow
`ExecutionDispatcher`. That wrapper exposes only `ExecutionService::execute`
with a mandatory pinned version and the host deadline; it has no activation,
registry, artifact, staging, or worker-spawn surface. The scheduler cannot
repoint `active_versions` and cannot bypass the execution checks described
above.

Terminal run states are `succeeded`, `failed`, `refused`, and `interrupted`,
with a closed failure-code vocabulary. Disabling a job clears `next_run_at` and
terminalizes its queued runs; enabling a job recomputes
`next_run_at = now + interval_secs` for an interval job or the first matching
UTC occurrence after `now` for a cron job. A manual trigger on an interval or
cron job stays allowed and does not move `next_run_at`. Startup marks
previously running rows `interrupted` and refuses queued rows for disabled
jobs; slice 3 is at-most-once and does not replay a worker. The loop owns
scheduler readiness and emits job wait/queue/active metrics; due enqueue moves
the queue gauge and logs bounded counts. A loop panic or tick failure flips
readiness false; in-flight run rows remain `running` until restart recovery
marks them `interrupted`. Cron timezone/DST selection, retries, cancellation,
multi-process ownership, and retention are later slices.

### Execution history (`executions::history`)

Every completed worker execution — including `failed`, `timed_out`,
`cancelled`, `worker_error`, and `protocol_violation` outcomes — writes one
metadata receipt to the shared SQLite database before the execute response is
returned. A history write failure is a typed server error (`500`-class), never
a silent success. The row stores the stable registry identity, function,
stable lowercase outcome name, start/finish wall times, and duration. It
deliberately stores no stdout, stderr, configuration, secrets, or
worker-provided failure text; history is metadata only, and pre-spawn
refusals remain in `package_rejections` rather than becoming history rows.

`GET /v1/executions` returns newest-first pages
(`limit` 1..=200, default 50; `offset` 0..=1,000,000, default 0) and
`GET /v1/executions/{execution_id}` returns one receipt. Both are
bearer-authenticated and return only the metadata fields. The history table
has no foreign key to `module_versions`, so history survives a future version
removal. There is no retention policy or GC yet: this table grows without
bound, which is a deliberate residual for a later slice.

## Observability (`metrics.rs`)

Metrics are ephemeral and external by design. With no OTLP endpoint the host
builds an SDK provider with no reader: instruments are cached and recording
stays local, but there is no export thread, HTTP client, or network traffic.
With an endpoint, one `MetricExporter` (HTTP/protobuf, cumulative temporality)
feeds a `PeriodicReader` configured by `metrics_export_interval_secs` /
`metrics_export_timeout_secs`. The configured value is a base URL: trailing
slashes are trimmed and `/v1/metrics` is appended unless the full signal URL is
already present. The blocking client is compiled with the rustls backend, so
`https://` endpoints work; userinfo in the URL is rejected at config
validation. There is no `/metrics` route and no metrics table: SQLite remains
the durable authority only for registry, rejections, and execution history.

Views fix explicit histogram buckets for HTTP request duration, execution
duration, DB lock wait, and job wait. Every stream has a bounded cardinality
limit and cumulative histograms skip min/max. Attributes are closed
vocabularies: matched route templates (or `unmatched`), normalized methods
(standard set or `_OTHER`), status codes, stable outcome names, bounded
refusal/integrity reasons (including `registry_state`), and auth reasons.
Module/version/execution ids, request ids, paths, tokens, configuration,
stdout/stderr, and free-form error text are never attributes.

`DatabaseError::from` classifies SQLite `Busy`/`Locked` errors and
`Database::lock` records mutex wait through a process-global handle installed
at startup; without a host the free functions are no-ops. HTTP middleware
wraps the timeout/panic layers so 401/404/405/413/500/503 responses are
observable, and the active-request guard releases on every path.

**Exemplars:** OpenTelemetry Rust 0.33 has no application-side exemplar
recording API (only exported data structures), so trace-linked exemplars are
not emitted. Execution/history metrics correlate through structured logs and
future tracing; claiming exemplar support would be false.

Readiness (`/readyz`) is unauthenticated and reads a per-host cached state:
`Readiness` holds atomic database and scheduler flags. Startup initializes the
database flag from `Database::check_ready` after migration; a background
watcher re-probes every few seconds through a one-permit semaphore on the
blocking pool, so a hung check cannot accumulate tasks. The scheduler flag
defaults to true (future hook). The route itself does no database work and
cannot false-503 under probe flood. Readiness is not a write/disk-full proof.

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

## Verification layers

- **Example tests** (`tests/*.rs`, unit modules): exact status/body/cleanup
  contracts, including startup assembly and a real TLS serve/upload round
  trip.
- **Property tests** (`tests/properties.rs`, `tests/upload_properties.rs`,
  `proptest` blocks): generated inputs over bearer comparison, digest/hex,
  canonical payload framing, archive path confinement, manifest bounds,
  rejection-detail bounding, and arbitrary endpoint bodies/fields with
  no-server-error, header, slot, and quarantine-cleanup oracles.
- **Fuzzing** (`fuzz/`): libFuzzer targets for the HTTP upload endpoint, the
  signed upload workflow, archive inspection, manifest parsing, and entry
  paths. Oracles assert the same security invariants under arbitrary bytes.
- **Mutation testing** (`mutants.toml`, `.github/workflows/mutants.yml`):
  changed-code mutants gate pull requests; full runs publish survivors.
- **DAST** (`tests/security/`, `.github/workflows/dast.yml`): builds the real
  container, serves TLS-only, and runs OWASP ZAP's API scan with the operator
  bearer attached.

## Not built yet

Interval and UTC five-field cron triggering are implemented in slice 3.
Retries, cancellation, distributed scheduling, CLI, artifact GC, and
execution-history retention/GC remain. Scheduler slice 3 provides durable
manual, interval, and cron jobs, due enqueue for both scheduled kinds, a
single-process dispatcher, readiness, and job metrics. Cron is UTC only; there
is no timezone/DST selection, seconds/7-field syntax, macros, names, or
`?`/`L`/`W`/`#` extensions. Startup reconciliation is classify-only: it sets
`ok`/`missing`/`mismatch` but does not repair artifacts or detect orphans,
and it does not yet record `reconciliation_runs`.
`control_plane/lifecycle.rs` is currently a placeholder for
deactivate/remove/rollback transitions. Leftover quarantine/staging sweeps
and classify-only startup reconciliation already run at startup. See
[statecharts.md](statecharts.md) for per-module state diagrams and the
prioritized remaining-work table.
