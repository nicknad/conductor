# Conductor

> **Unstable:** this repository is being rewritten in Rust. Nothing here is stable yet —
> no API, no storage format, no CLI contract should be relied upon.

> **Development is not finished:** this is an in-progress implementation, not a
> complete job scheduler. Package ingestion, host startup wiring, the
> worker execution library, the activation/execution HTTP endpoints,
> durable execution history, and Scheduler slice 6 (durable manual, interval,
> and UTC five-field cron jobs with bounded retries, a bounded graceful
> drain on host shutdown, and authenticated per-run cancellation) exist, but lifecycle
> transitions and the operator CLI are still outstanding. Do not treat it as a
> finished or production-ready product.

A single-machine job execution platform supporting installing, validating, activating,
updating, disabling, removing, and rolling back job plugin implementations **without
restarting the scheduler host**.

## Service Packages

Services are distributed as versioned ZIP archives containing a manifest, compiled code, and required dependencies.

**.NET service**
```text
reporting-service-1.2.0.zip
├── manifest.json
└── payload/
    ├── ReportingService.dll
    ├── ReportingService.deps.json
    └── ReportingService.runtimeconfig.json
```

**Rust service**
```text
reporting-service-1.2.0.zip
├── manifest.json
└── payload/
    └── reporting-service
```

The Rust executable is built for the target platform and architecture. Any required external runtime libraries must be available in the execution environment or included as permitted dependencies.

The manifest declares the module ID, version, runtime, entry point, and exposed functions. Each package is accompanied by a detached digital signature.

Conductor verifies the signature against trusted publishers, validates the archive and manifest, and stores accepted packages as immutable artifacts before activation.

**Package contents define what can run; Conductor controls whether, where, and under which permissions it runs.**

Details: [package validation pipeline](src/packages/README.md) · [hostile archive corpus](tests/testdata/README.md).

## Upload API (unstable)

`POST /v1/packages` accepts a `multipart/form-data` body:

| Field | Contents |
|---|---|
| `package` | The exact ZIP bytes covered by the detached signature, streamed into quarantine under the policy byte bound |
| `key_id` | Trusted-key id (text) |
| `signature` | Standard-base64 Ed25519 signature over the canonical payload (text) |
| `format_version` | Optional envelope version, defaults to 1 |

Transport security, all fail-closed with no opt-outs:

- **TLS only.** The server binds `bind_rustls` exclusively — there is no
  plaintext listener, and plaintext against the TLS port gets no HTTP
  response (proven in `tests/tls_only.rs`). HSTS
  (`max-age=63072000; includeSubDomains`) is emitted on every response.
  Configure `tls_cert_path`/`tls_key_path`; mismatched identities refuse
  to load.
- **Bearer auth only.** Every `/v1` route requires
  `Authorization: Bearer <operator-token>`, compared in constant time
  (SHA-256 + `subtle`, redacted `Debug`). Missing and wrong tokens are
  indistinguishable (`401`, `Bearer` challenge). `/healthz` (liveness) and
  `/readyz` (readiness) are the only unauthenticated endpoints — probes cannot
  present credentials. `/healthz` returns only `ok`; `/readyz` returns `ok`
  only when the cached readiness state says both the shared database (migrated
  and answering a periodic probe) and the scheduler hook are ready, otherwise
  `503` with a fixed `unavailable` body and no detail. `/readyz` reads two
  atomics and never touches SQLite or the blocking pool per request.
- **Bounded everything.** Total body (policy bound + 1 MiB slack),
  streaming package bytes, text fields, at most 16 multipart fields, and
  at most 8 concurrent uploads (`503 server_busy` instead of unbounded
  queueing). Oversized header sections are rejected at the hyper socket
  layer; slow bodies are bounded by the total per-request timeout.
- **Silent responses.** No `Server`/`Via`/`X-Powered-By` identity
  headers; `nosniff`, `DENY` framing, `no-referrer`, `same-origin` CORP,
  `no-store, no-cache, must-revalidate`, and a server-generated
  `x-request-id` on every response; panics become a bare `500`; error bodies
  are `{code, message}` only.

Responses: `201` with `{module_id, version, digest, signer_key_id}` on
acceptance; `400` malformed, `401` unauthenticated (with the matching
`WWW-Authenticate` challenge), `413` oversized, `422`
semantically invalid, `503` saturated. Rejected bytes are deleted from
quarantine (drop-guaranteed); accepted bytes are kept for the artifact
store to promote. Startup loads operator configuration, builds the trust
store, prepares the storage layout, opens and migrates the shared database,
and only then binds the TLS listener (`conductor::server::run`). Any failure —
bad configuration, unusable key material, non-ingestable policy, or a
database/layout error — aborts before binding. `tests/startup.rs` drives that
wiring end to end; `tests/upload_api.rs` and `tests/tls_only.rs` cover the
API and transport hardening.

## Activation and execution API (unstable)

Both routes are bearer-authenticated and accept a bounded JSON body
(1 MiB route-scoped limit):

- `POST /v1/modules/{module_id}/activate` with `{"version":"1.2.0"}` checks
  the registered version against the runtime allowlist and integrity state,
  persists it as the active version, and returns
  `{module_id, version, digest, signer_key_id}`.
- `POST /v1/modules/{module_id}/executions` with
  `{"version"?, "function", "configuration"?, "deadline_secs"?}` resolves the
  active version (or the pinned `version`), re-verifies the promoted artifact
  and manifest, stages it, and runs one worker process. It returns
  `{execution_id, module_id, version, digest, outcome, stdout, stderr,
  duration_ms}`; `outcome` is a stable lowercase name. `deadline_secs`
  defaults to 30 seconds, clamped to `max_execution_deadline_secs` when that
  is lower; explicit values above the host maximum are refused.

Refusals use the same `{code, message}` contract: `404` for an unregistered
version or missing active pointer, `422` for legacy v1 manifests,
runtime/integrity/manifest/archive refusals, `400` for malformed input or an
over-maximum deadline, `503` when all execution slots are busy, and `500` for
storage/host failures (including a missing registered artifact) with no path
or OS detail. Execution requires manifest v2; upload and activation still
accept v1. Refusals are recorded through the
rejection recorder under the `activation`/`execution` stages without the
request configuration. `tests/execution_api.rs` proves the authenticated
upload → activate → execute path with a real worker.

### Execution history (unstable)

Every completed worker execution writes one durable metadata receipt to the
shared database before the execute response is returned. Two read-only routes
expose it, both bearer-authenticated:

- `GET /v1/executions?limit=<1..=200>&offset=<0..=1000000>` lists receipts
  newest first (`limit` defaults to 50, `offset` to 0).
- `GET /v1/executions/{execution_id}` returns one receipt.

A receipt contains only `execution_id`, `module_id`, `version`, `digest`,
`function`, `outcome`, `started_at_ms`, `finished_at_ms`, and `duration_ms`.
Stdout, stderr, configuration, secrets, and worker failure text are never
stored. A worker that fails still produces a receipt with its stable outcome;
pre-spawn refusals (unknown version, legacy v1 manifest, tampered/missing
artifact, policy denial) stay in `package_rejections` and create no history
row. Invalid pagination and execution ids are `400` with stable codes;
unknown ids are `404`; history read/write failures are generic `500`s. There is
no retention or garbage collection yet, so history grows without bound.

### Jobs API (unstable)

Scheduler slice 4 adds durable manual, interval, and UTC five-field cron jobs
with bounded retries; slice 6 adds authenticated per-run cancellation.
Every route is bearer-authenticated. The job definition pins `module_id`,
`version`, and `function`; dispatch always goes through the same pinned
execution service as `POST /v1/modules/{module_id}/executions`, so activation,
runtime, integrity, signer, manifest, artifact, staging, and target checks
still apply.

- `POST /v1/jobs` with `{module_id, version, function, trigger, payload?,
  enabled?}` creates a durable job. Accepted triggers are:
  - `{"trigger":{"kind":"manual"}}`;
  - `{"trigger":{"kind":"interval","interval_secs":N}}` where `N` is
    `1..=31536000` (one year);
  - `{"trigger":{"kind":"cron","expression":"<5-field cron>"}}` within a closed
    UTC grammar: minute `0-59`, hour `0-23`, day-of-month `1-31`, month
    `1-12`, day-of-week `0-7` (0 and 7 are Sunday), with `*`, numbers, ranges
    `a-b`, lists `a,b`, `*/n`, and `a-b/n`. Names, macros, seconds/6-field or
    7-field expressions, and `?`/`L`/`W`/`#` are rejected. When both
    day-of-month and day-of-week are restricted, a time matches if either
    matches (POSIX OR).
  An enabled interval job starts at `next_run_at = now + interval_secs`; an
  enabled cron job starts at the first matching UTC occurrence strictly after
  `now`. A disabled job has no next run. The payload is bounded to 64 KiB of
  canonical JSON and is never returned by the API.
- `GET /v1/jobs?limit=<1..=200>&offset=<0..=1000000>` lists jobs newest first.
- `POST /v1/jobs/{job_id}/enable` and `POST /v1/jobs/{job_id}/disable` toggle
  the job. Enable recomputes `next_run_at = now + interval_secs` for an
  interval job and the first matching UTC occurrence after `now` for a cron
  job; disable clears it and terminalizes queued runs as
  `refused`/`job_disabled`.
- `POST /v1/jobs/{job_id}/trigger` enqueues one manual run and returns `202
  {job_id, run_id, state:"queued"}`. A manual run on an enabled interval or
  cron job records `trigger_kind="manual"` and does not move `next_run_at`.
  Manual triggers are not idempotent in this slice; two calls are two runs.
- `GET /v1/jobs/{job_id}/runs?limit=...&offset=...` lists durable run rows
  newest first. A run records its stable state, timestamps, linked
  `execution_id`, worker outcome, or bounded scheduler failure code. No payload,
  stdout, or stderr is stored on the run.
- `POST /v1/jobs/{job_id}/runs/{run_id}/cancel` accepts no body and returns
  `202` with the run row. A `queued` run is terminalized in one transaction as
  `failed`/`cancelled` with `finished_at` and no `execution_id`, so it is never
  claimed and no history row is created. A `running` run gets `"cancel
  requested"` through the executor's cancellation channel; the worker process
  group is terminated and the normal dispatch path writes one `failed`/
  `cancelled` terminal row with the real `execution_id` and history receipt.
  Cancelled runs never retry. Cancellation is best-effort at the exchange
  boundary: a cancel that races an execution which already produced its worker
  outcome is accepted, but the already-decided outcome stands. Cancelling one
  run does not change the job's
  `enabled` flag or `next_run_at` and does not touch other runs. An unknown run
  or a run addressed through another job is `404 run_not_found`; an already
  terminal run, or a running row whose dispatch sender is not registered yet,
  is `409 run_not_cancellable`. Invalid path identities are `400
  invalid_job_id` or `400 invalid_run_id`; host-side store failures are a
  generic `500`. The route returns `503 scheduler_unavailable` while the
  scheduler is not running, matching the trigger lifecycle gate.

Each scheduler tick enqueues at most one run for each enabled interval or cron
job whose `next_run_at` is due, using `job_runs` with `trigger_kind="interval"`
or `"cron"` and `scheduled_for=next_run_at`. It then advances `next_run_at` to
the first boundary strictly after `now`. Advancing `next_run_at` prevents
repeated ticks for the same boundary; the partial unique index is the backstop
if a boundary is seen twice. A restart enqueues at most one missed run per job
rather than a burst. When the global queued-run bound is full, the due boundary
is left unchanged so a later tick retries it. An unparseable persisted cron
expression is skipped and counted rather than failing the pass, and a read of
that job fails closed until the row is repaired. A syntactically valid but
impossible expression is likewise skipped and counted, but the row still reads
back; the job does not run until the expression is repaired. Claims honor
`scheduled_for <= now`, so a future-dated retry cannot be claimed early.

Retries are a global policy on `SchedulerConfig`: `max_attempts=3`,
`retry_base_backoff=5s`, and `retry_max_backoff=5m`, so the delay is the
deterministic exponential `base * 2^(attempt-1)` with no jitter. Only a
`failed` run whose worker outcome is `failed`, `timed_out`, or `worker_error` is
retried; refusals, cancellations, `protocol_violation`, interrupted runs, and
every scheduler failure code stay terminal. Under the attempt bound, one new
`queued` run is inserted with `attempt_no+1`, the same `trigger_kind`,
`scheduled_for=now+backoff`, and `created_at=now`; `jobs.next_run_at` does not
move. A full queue drops the retry without an error and without a later
automatic retry, and disabling a job terminalizes its queued retries (a retry
already claimed can still finish). Two overlapping interval/cron attempts of
one job that finish in the same millisecond can collapse into one retry because
the partial tick index is the dedupe backstop. The policy is not per job and
has no API or CLI surface. Retries re-execute the worker, so jobs with
non-idempotent side effects can duplicate them because there are no idempotency
keys; every attempt is a new `job_runs` row, so retries grow the table until a
later retention slice.

A trigger while the scheduler loop is not running returns `503
scheduler_unavailable`; a disabled job returns `409 job_disabled`; a full job
or queue bound returns `503 server_busy`. Startup recovery marks previously
running rows `interrupted` and refuses queued rows for disabled jobs. The
scheduler is single-process and at-most-once: a crash after claim does not
replay the worker, and queued retries survive a restart and dispatch when due.
A loop panic or tick failure flips `/readyz` to `503`.

On host shutdown the scheduler drains instead of aborting immediately. Drain
clears scheduler readiness before the finish window starts, stops claiming new
runs, and gives already-claimed runs up to `SchedulerConfig::drain_timeout`
(30 s default) to finish and write their normal terminal row. A claim already
in flight when drain starts can still commit and is included in that wait;
other queued rows are not claimed and remain `queued` for the next start. When
the window expires, remaining dispatch tasks are aborted; their rows stay
`running` until startup recovery marks them `interrupted`.
HTTP serving stops before drain begins, and HTTP graceful shutdown is bounded
at 30 s, so a worst-case host shutdown can take the sum of the two windows.
Drain reuses `SchedulerState::Stopping` and adds no metric, route, state, or
schema.
Slice 6 adds per-run cancellation without changing drain or stop. Queued
cancellation is a single durable store transaction; running cancellation uses
the executor cancellation channel rather than aborting the dispatch task, so
the terminal row and history receipt are preserved. Cancellation is recorded as
`failed` with outcome `cancelled`, not a first-class cancelled state or failure
code; clients must read both fields. There is no durable pending-cancel marker,
so a cancel that races the claim-to-sender registration returns `409
run_not_cancellable` and the caller may retry. Cancellation during blocking
preparation is observed only when the worker exchange starts; preparation
itself is not interrupted. Queued cancellation creates no history row because
no worker ran. Cancel is per run: queued retries of the same job are separate
runs, and disable remains the job-level kill-switch. Drain and stop still do not
cancel individual runs. Replay of interrupted runs is still not implemented:
in-flight run rows remain `running` after a crash until restart recovery marks
them `interrupted`. There is no job/run retention yet, so terminal rows and job
payloads grow until a later retention slice. Distributed scheduling,
timezone/DST selection, and retention are later slices.

## Host configuration

Configuration loading lives in `src/config.rs` and is consumed at startup by
`server::run`, which assembles the host and refuses to bind on any error. One
JSON file plus `CONDUCTOR_*` environment overrides produce an immutable
`Config`:

- `--config <path>` (highest precedence) or `CONDUCTOR_CONFIG` selects the
  file; without either, built-in defaults apply.
- Environment variables override file fields. See [`.env.example`](.env.example)
  for the complete list.
- `CONDUCTOR_API_TOKEN` or `CONDUCTOR_API_TOKEN_FILE` supplies the operator
  bearer token. The token is redacted from `Debug` output.
- `CONDUCTOR_TRUSTED_KEYS_FILE` replaces the file's `trusted_keys` array with
  its own JSON array.
- `CONDUCTOR_OTLP_ENDPOINT` enables OTLP/HTTP metric export; unset/`null`
  keeps metrics disabled. The value is a **base URL**: trailing slashes are
  trimmed and `/v1/metrics` is appended, unless the full signal URL is already
  supplied. Both `http://` and `https://` are accepted; the blocking exporter
  is built with a rustls TLS backend. Userinfo in the URL
  (`https://user:token@host`) is rejected at startup.
  `CONDUCTOR_METRICS_EXPORT_INTERVAL_SECS` and
  `CONDUCTOR_METRICS_EXPORT_TIMEOUT_SECS` control the periodic reader
  (timeout must be strictly below the interval), and
  `CONDUCTOR_DEPLOYMENT_ENVIRONMENT` sets the resource environment label.
- `Config::validate_for_startup` refuses to proceed without a non-empty token
  and at least one trusted key, and rejects an unusable bind address, zero
  timeout or slot counts, empty runtime allowlists, and empty paths.
- `allowed_runtimes` (non-empty) is a metadata filter over the runtime
  declared in the manifest for activation and execution, not a sandbox;
  `max_execution_deadline_secs` bounds any requested deadline (an omitted
  deadline is clamped down to it), and `max_concurrent_executions` bounds
  in-flight workers (fail fast with `503`, never an unbounded queue).
  `request_timeout_secs` includes request preparation as well as the worker
  run, and must be greater than `max_execution_deadline_secs` plus the
  2-second worker termination grace, so an execution cannot outlive the
  request that owns it.
- `Config::trust_store` converts the configured records into the runtime
  `ConfiguredTrustedKeys`, validating standard base64, the 32-byte Ed25519 key
  size, and non-empty unique key ids.
- `Config::ensure_layout` creates and tightens the managed storage directories
  (`storage_root`, `quarantine/`, `artifacts/`, `database/`, `staging/`) to
  owner-only permissions, and refuses a symlinked or world-writable existing
  root rather than silently adopting it.
- Startup sweeps `quarantine/` and `staging/` entries older than their TTLs,
  bounding space left by crashes and dropped requests.
- `server::Host::assemble` validates the configuration, builds the validator
  from the trust store, creates the layout, opens and migrates one shared
  database, and wires the registry, durable rejection sink, bearer token,
  timeout, upload slots, and the registered-artifact execution service before
  `Host::serve` binds TLS.

Example: [`config/conductor.example.json`](config/conductor.example.json).
Its token and key are placeholders; generate your own and do not commit real
configuration or key material.

| Field | Environment variable | Default |
|---|---|---|
| `http_bind` | `CONDUCTOR_HTTP_BIND` | `127.0.0.1:8080` |
| `storage_root` | `CONDUCTOR_STORAGE_ROOT` | `data` |
| `request_timeout_secs` | `CONDUCTOR_REQUEST_TIMEOUT_SECS` | `360` |
| `tls_cert_path` | `CONDUCTOR_TLS_CERT_PATH` | `tls/cert.pem` |
| `tls_key_path` | `CONDUCTOR_TLS_KEY_PATH` | `tls/key.pem` |
| `max_concurrent_uploads` | `CONDUCTOR_MAX_CONCURRENT_UPLOADS` | `8` |
| `quarantine_ttl_secs` | `CONDUCTOR_QUARANTINE_TTL_SECS` | `3600` |
| `staging_ttl_secs` | `CONDUCTOR_STAGING_TTL_SECS` | `3600` |
| `allowed_runtimes` | `CONDUCTOR_ALLOWED_RUNTIMES` (comma-separated) | `["rust"]` |
| `max_execution_deadline_secs` | `CONDUCTOR_MAX_EXECUTION_DEADLINE_SECS` | `300` |
| `max_concurrent_executions` | `CONDUCTOR_MAX_CONCURRENT_EXECUTIONS` | `4` |
| `otlp_endpoint` | `CONDUCTOR_OTLP_ENDPOINT` | none (metrics disabled) |
| `metrics_export_interval_secs` | `CONDUCTOR_METRICS_EXPORT_INTERVAL_SECS` | `15` |
| `metrics_export_timeout_secs` | `CONDUCTOR_METRICS_EXPORT_TIMEOUT_SECS` | `5` |
| `deployment_environment` | `CONDUCTOR_DEPLOYMENT_ENVIRONMENT` | `development` |
| `api_token` | `CONDUCTOR_API_TOKEN` / `CONDUCTOR_API_TOKEN_FILE` | none (required) |
| `trusted_keys` | `CONDUCTOR_TRUSTED_KEYS_FILE` | none (required) |

Relative paths resolve against the process working directory; prefer absolute
paths in deployed configuration.

## Observability (unstable)

Metrics are ephemeral process telemetry exported to an external OTLP/HTTP
collector. They are **disabled by default** (`otlp_endpoint` unset): the host
builds a no-reader provider, creates no HTTP client or export thread, and
performs no network export. There is deliberately **no `/metrics` scrape
endpoint**, and nothing metric-shaped is written to SQLite. Enable export by
setting `CONDUCTOR_OTLP_ENDPOINT` (or `otlp_endpoint`) to an
`http://`/`https://` base URL; exports use protobuf over OTLP/HTTP with
cumulative temporality. The base URL has `/v1/metrics` appended (trailing
slashes are ignored), and a full `/v1/metrics` URL is used as-is. HTTPS export
is backed by rustls (`reqwest-rustls`); the endpoint must not carry userinfo.

Metric names (attributes are bounded labels only — never module/version or
execution ids, request ids, paths, tokens, configuration, stdout/stderr, or
error text):

| Metric | Type | Unit | Attributes |
|---|---|---|---|
| `http.server.requests` | counter | `{request}` | method, route template, status |
| `http.server.request.duration` | histogram | `s` | method, route template, status |
| `http.server.active_requests` | up-down counter | `{request}` | method, route template |
| `conductor.auth.failures` | counter | `{failure}` | route template, reason (`missing`/`invalid`) |
| `conductor.execution.completed` | counter | `{execution}` | stable outcome |
| `conductor.execution.refused` | counter | `{execution}` | bounded reason |
| `conductor.execution.duration` | histogram | `s` | phase (`prepare`/`run`) |
| `conductor.execution.slots.in_use` | up-down counter | `{slot}` | none |
| `conductor.execution.slots.capacity` | observable gauge | `{slot}` | none |
| `conductor.execution.overload` | counter | `{execution}` | none |
| `conductor.execution.history.write.failures` | counter | `{failure}` | none |
| `conductor.db.busy.errors` | counter | `{error}` | none |
| `conductor.db.lock.wait.duration` | histogram | `s` | none |
| `conductor.storage.free.bytes` | observable gauge | `By` | none (Unix `statvfs`) |
| `conductor.artifact.integrity.failures` | counter | `{failure}` | bounded integrity kind |
| `conductor.job.wait.duration` | histogram | `s` | none |
| `conductor.job.queue.depth` | up-down counter | `{run}` | none |
| `conductor.job.active` | up-down counter | `{run}` | none |

`http.request.method` is normalized to the standard closed set (`GET`, `POST`,
`PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `CONNECT`, `TRACE`); any other
method becomes `_OTHER`, so custom method tokens cannot create unbounded
labels or exhaust the stream cardinality limit.

Histogram buckets are fixed in `src/metrics.rs` (HTTP, execution, DB lock
wait, and job wait). Resource attributes are
`service.name=conductor`, `service.version`, `deployment.environment.name`,
`service.instance.id`, and `host.name`; the instrumentation scope is
`conductor`.

**Exemplars are not emitted.** OpenTelemetry Rust 0.33 exposes exported
exemplar data structures but no application-side exemplar recording API, so
trace-linked exemplars are unsupported by this SDK version. Correlate
execution/history metrics through structured logs today and future tracing
when it lands.

`/readyz` reads a cached readiness state: the host probes the shared database
off the request path every few seconds through a bounded watcher (one probe at
a time on the blocking pool). The scheduler flag becomes true only after the
scheduler loop starts and its ready handshake completes; a failed start keeps
the listener unbound, and a later loop stop/panic makes the host `503`.
Requests never run a database probe and cannot produce a false `503` under
flood. Readiness is not proof that the disk has free space or that writes
succeed; it covers database/migration availability plus scheduler lifecycle.

See [docs/observability.md](docs/observability.md) for metric semantics, proof
recipes, and the agent validation protocol.

## Worker execution (unstable)

Job functions never run in-process. One execution is one worker child process,
started from the entrypoint of a staged, digest-re-verified artifact with an
explicit environment (nothing inherited):

- **Protocol.** One newline-delimited JSON request on stdin — execution id,
  module/function identity, digest, configuration, deadline; secrets only ever
  here, never argv or env — then EOF. The worker answers with exactly one
  response line on stdout (`ok` with a result, or `failed` with a message);
  stderr is diagnostics only.
- **Bounds.** Request and response lines, captured stderr, and wall time are
  all capped, and output is drained concurrently so a chatty worker cannot
  deadlock on a full pipe.
- **Termination.** Deadline overruns and cancellation SIGTERM the worker's
  whole process group, SIGKILL it after a grace period, and clean up
  descendants where the platform supports process groups.
- **Identity & scope.** Workers inherit the host's identity (`uid`, `gid`, and
  supplementary groups are never changed), so package code can reach whatever
  the host process can: the process boundary is fault and resource
  containment, not a sandbox. Stronger filesystem, network, or credential
  isolation would be a separate OS-level design change.

Proven in `tests/execution_worker.rs`: request round trip, secret and
environment handling, host-identity inheritance, failure and
protocol-violation reporting, timeout and cancellation teardown (descendants
included), output bounds, and staged-file tamper detection at resolve time.

## Status

- Active code: single-crate Rust modular monolith (`src/`, `tests/`).
- In progress: package ingestion, validation, promotion, registry persistence,
  startup assembly (configuration, trust store, storage layout, shared
  database, durable rejection sink), the worker execution library,
  activation/execution HTTP endpoints, and durable execution history are
  implemented. Manual, interval, and UTC five-field cron scheduler triggers,
  bounded retries, the bounded shutdown drain, and authenticated per-run
  cancellation are implemented; the operator CLI and interrupted-run replay
  are not built yet — see
  [Not built yet](docs/architecture.md#not-built-yet).
- Specification: [`docs/architecture.md`](docs/architecture.md) describes the
  Rust system as built. `docs/storage-reconciliation.md` and
  `docs/design-persistence.md` are background/planning notes, not specs.

## Repository layout

```text
Cargo.toml                  Single-crate package definition
src/
  main.rs                   Binary entry point (thin wrapper over `server::run`)
  lib.rs                    Library root
  server.rs                 Host startup and TLS-only serving path
  api/                      HTTP interface (routes, uploads, errors)
  control_plane/            Control plane: use cases, workflow orchestration, lifecycle
  packages/                 Package domain and validation
  storage/                  Filesystem persistence
  modules/                  Installed module registry
  executions/               Worker-process execution (spawn, IPC, limits, durable history)
  config.rs                 Host configuration
config/
  conductor.example.json    Example host configuration
tests/
  package_validation.rs     Package validation workflow tests
  archive_security.rs       Archive security tests
  execution_worker.rs       Worker-process execution tests
  execution_service.rs      Registered-artifact execution service tests
  execution_api.rs          Activation/execution HTTP API end-to-end tests
  upload_api.rs             Upload API tests
  upload_properties.rs      Generated endpoint input properties
  properties.rs             Pure crypto/path/manifest properties
  tls_only.rs               TLS-only serving tests
  upload_workflow.rs        Upload workflow tests
  startup.rs                Operator config → assembled host wiring tests
  security/                 Container + OWASP ZAP DAST scan (see its README)
fuzz/                       libFuzzer targets for endpoint and parsers
.cargo/mutants.toml         Mutation-testing scope
docs/                       Current architecture + background notes (see docs/README.md)
.env.example                Environment variable template
LICENSE                     Apache-2.0
```

## Prerequisites

- Recent stable Rust toolchain (`cargo`, `rustc`). No other toolchain required.

## Build, test, verify

```sh
cargo build
cargo test
python3 scripts/check_test_quality.py   # structural test checks (also run in CI)

# Security-focused suites
cargo test --test properties            # pure proptest invariants
cargo test --test upload_properties     # generated endpoint inputs
tests/security/scan.sh                  # container + OWASP ZAP API scan

# Optional heavy checks (also automated in CI)
cargo +nightly fuzz build               # libFuzzer targets under fuzz/
cargo mutants --in-diff <diff>          # mutation testing (mutants.toml)
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
