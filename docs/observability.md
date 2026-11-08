# Observability and agent validation

Status: current as of the Rust rewrite. This is the practical companion to the
[README observability section](../README.md#observability-unstable) and
[architecture.md](architecture.md#observability-metricsrs). It describes what
the host emits, what each signal can prove, and how another agent can use the
signals as evidence.

The short version: metrics, probes, structured logs, durable rejection rows,
and durable execution history exist. A metric proves an instrument fired; it
does not by itself prove the underlying effect. Strong evidence combines a
contract test, a durable row or filesystem observation, the API response, and
the metric.

## 1. What exists

| Signal | Implementation | Answers | Limits |
| --- | --- | --- | --- |
| OTLP metrics | `src/metrics.rs`, push-only OTLP/HTTP | Request rates/latency, auth failures, execution outcomes/refusals, capacity, DB contention, disk headroom, artifact integrity failures | Ephemeral per process; no `/metrics` scrape endpoint; disabled when no endpoint is configured |
| Liveness | `GET /healthz` | Is the process serving? | Does not prove database, artifact, or execution health |
| Readiness | `GET /readyz` | Is the shared database migrated/probeable and is the scheduler hook ready? | Does not cover disk, writes, artifact integrity, or startup reconciliation |
| Structured logs | `tracing` to stderr | Startup, sweeps, request context, rejection detail, execution detail, reconciliation summary | No log files, no trace exporter, no exemplars; retention is the operator's problem |
| Rejection audit | `package_rejections` SQLite table | One handled refusal, one stage/code/detail row | Tower timeout, panic, and hyper's own `431` can bypass the handler mapper |
| Execution history | `executions` SQLite table | One metadata receipt per worker that ran | Pre-spawn refusals are not history rows; no stdout, stderr, config, or secrets |
| Artifact integrity state | `module_versions.integrity_state` | `ok` / `missing` / `mismatch` after startup reconciliation | Not authorization; execution independently re-verifies bytes |

Startup reconciliation currently emits a summary log and persists
`integrity_state`. Its dedicated gauge/histogram is a later slice; do not claim
it exists today.

## 2. Enable and query metrics

Metrics are **push-only** to an OTLP/HTTP collector. With `otlp_endpoint`
unset, the host builds a no-reader provider: no export thread, no HTTP client,
and no network traffic.

```sh
CONDUCTOR_OTLP_ENDPOINT=http://collector:4318
CONDUCTOR_METRICS_EXPORT_INTERVAL_SECS=15
CONDUCTOR_METRICS_EXPORT_TIMEOUT_SECS=5
CONDUCTOR_DEPLOYMENT_ENVIRONMENT=production
```

The configured value is a base URL; the host trims trailing slashes and
appends `/v1/metrics`. A full signal URL is used as-is. HTTPS export uses the
compiled-in rustls backend.

Minimal collector that exposes the pushed metrics to Prometheus:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug: {}
  prometheus:
    endpoint: 0.0.0.0:8889
service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [debug, prometheus]
```

Scrape the collector at `:8889/metrics`. The backend's OTLP-to-Prometheus name
conversion decides the final names; use the names your backend exposes.

### Metric reference

| Metric | Type | Unit | Attributes | Use it to prove |
| --- | --- | --- | --- | --- |
| `http.server.requests` | counter | `{request}` | method, route template, status | A request reached the middleware and returned a status |
| `http.server.request.duration` | histogram | `s` | method, route template, status | Request latency, including timeout/error paths |
| `http.server.active_requests` | up-down counter | `{request}` | method, route template | In-flight request concurrency |
| `conductor.auth.failures` | counter | `{failure}` | route, reason (`missing`/`invalid`) | A bearer check refused a request |
| `conductor.execution.completed` | counter | `{execution}` | stable outcome | A worker finished with an outcome |
| `conductor.execution.refused` | counter | `{execution}` | bounded reason | Execution was refused before a worker ran |
| `conductor.execution.duration` | histogram | `s` | phase (`prepare`/`run`) | Time spent preparing vs running a worker |
| `conductor.execution.slots.in_use` | up-down counter | `{slot}` | none | Current execution slot usage |
| `conductor.execution.slots.capacity` | observable gauge | `{slot}` | none | Configured execution capacity |
| `conductor.execution.overload` | counter | `{execution}` | none | A request was shed because capacity was full |
| `conductor.execution.history.write.failures` | counter | `{failure}` | none | A completed execution failed to persist its history receipt |
| `conductor.db.busy.errors` | counter | `{error}` | none | SQLite refused an operation as busy/locked |
| `conductor.db.lock.wait.duration` | histogram | `s` | none | Time spent waiting for the shared connection mutex |
| `conductor.storage.free.bytes` | observable gauge | `By` | none | Free space under the configured storage root (Unix `statvfs`) |
| `conductor.artifact.integrity.failures` | counter | `{failure}` | bounded kind | Activation/execution refused an artifact integrity check |
| `conductor.job.wait.duration` | histogram | `s` | none | A queued run waited from its due time to claim |
| `conductor.job.queue.depth` | up-down counter | `{run}` | none | Durable queue depth at the last scheduler transition |
| `conductor.job.active` | up-down counter | `{run}` | none | Runs currently claimed by the dispatcher |

Bounded integrity kinds include `path`, `missing`, `unreadable`, `size`,
`digest`, `manifest`, `archive`, `legacy`, `staging`, `target`, and
`registry_state`. Bounded refusal reasons include `not_found`, `not_active`,
`integrity`, `runtime`, `signer`, `legacy_manifest`, `manifest`, `archive`,
`staging`, `target`, `executor`, `deadline`, and `internal`.

Scheduler slice 1 emits `conductor.job.wait.duration` at claim time, plus
`conductor.job.queue.depth` and `conductor.job.active`.

After your backend normalizes OTLP names, useful queries are conceptually:

```promql
# 5xx rate and p99 request latency
sum(rate(http_server_requests_total{status=~"5.."}[5m]))
histogram_quantile(0.99, sum by (le) (rate(http_server_request_duration_bucket[5m])))

# execution refusals by reason and slot saturation
sum by (reason) (rate(conductor_execution_refused_total[5m]))
conductor_execution_slots_in_use / conductor_execution_slots_capacity

# DB contention and disk headroom
rate(conductor_db_busy_errors_total[5m])
conductor_storage_free_bytes

# artifact integrity failures by kind
sum by (kind) (rate(conductor_artifact_integrity_failures_total[5m]))
```

Metrics deliberately carry no module ids, versions, execution ids, request
ids, paths, tokens, configuration, stdout/stderr, or free-form error text.
Use logs and SQLite for those.

## 3. Probes

```sh
curl -sk https://host:port/healthz
# 200 "ok"

curl -sk -o /dev/null -w '%{http_code}\n' https://host:port/readyz
# 200 = ready, 503 = unavailable
```

`/healthz` and `/readyz` are unauthenticated. `/readyz` reads two atomics; it
never probes SQLite on the request path. A bounded background watcher
re-probes the shared database every five seconds through a one-permit
semaphore. The scheduler flag is set by the scheduler lifecycle: false before
start, true only after the loop-ready handshake, and false again on stop,
panic, or a failed tick. Job triggers return `503 scheduler_unavailable` while
the scheduler is not running.

Readiness is not proof that writes succeed, that the disk has room, or that
every registered module is runnable. In particular, an all-`missing` registry
can still report `200`.

## 4. Logs and durable state

Run with structured logs:

```sh
RUST_LOG=conductor=debug ./conductor --config config/conductor.json
```

Every response carries a server-issued `x-request-id`. Use it to correlate the
response with request logs and, for a handled refusal, the rejection row.

Useful events include:

- `startup workspace sweep complete` with quarantine/staging counts;
- `artifact reconciliation complete` with `scanned`, `ok`, `missing`,
  `mismatch`;
- `registered artifact is not intact` with bounded module/version and reason;
- `host assembled; starting TLS listener`;
- execution lifecycle and history-write failure events.

Durable checks (replace the database path with your configured
`storage_root`):

```sh
sqlite3 data/database/conductor.db \
  "select module_id, version, integrity_state from module_versions order by module_id, version;"

sqlite3 data/database/conductor.db \
  "select occurred_at, stage, code, module_id, version, digest
     from package_rejections order by id desc limit 20;"

sqlite3 data/database/conductor.db \
  "select execution_id, module_id, version, outcome, duration_ms
     from executions order by id desc limit 20;"
```

`occurred_at` and history timestamps are Unix milliseconds. History rows
deliberately contain no stdout, stderr, configuration, secrets, or
worker-provided failure text.

## 5. Proof recipes

| Claim | Primary evidence | Probe | Caveat |
| --- | --- | --- | --- |
| The host is alive | `/healthz` 200 | `curl -sk .../healthz` | Liveness only |
| The database is ready | `/readyz` 200 | `curl -sk .../readyz` | Cached; does not cover disk/artifacts/reconciliation |
| An upload succeeded | 201 + no rejection row + artifact file + `module_versions` row | API call, then SQL and filesystem | The metric alone is weaker |
| An upload was refused | 4xx/5xx + exactly one `package_rejections` row | API call, then SQL | Some transport paths bypass the handler mapper |
| An execution succeeded | Response receipt + `conductor.execution.completed{outcome="succeeded"}` + `executions` row | Execute, then metric backend and SQL | Does not prove worker output correctness |
| An execution was refused before spawn | `conductor.execution.refused{reason}` | Metric backend | No history row by design |
| A manual job ran | `202` trigger + `job_runs.state=succeeded` + matching `executions` row + `conductor.job.wait.duration` | Trigger, poll `/v1/jobs/{id}/runs`, SQL, metric backend | Run rows store no payload/stdout/stderr; at-most-once |
| An artifact is damaged | `conductor.artifact.integrity.failures{kind}` + activation/execution refusal | Activate/execute, then metric backend and SQL | `ok` means bytes match the row, not safe-to-execute |
| Startup reconciliation ran | `artifact reconciliation complete scanned=...` log + `integrity_state` rows | Startup log and SQL | No reconciliation metric or readiness signal yet |
| Execution capacity is saturated | `slots.in_use` vs `slots.capacity`, `overload` | Metric backend | No per-module labels |
| SQLite is contended | `db.busy.errors`, `db.lock.wait.duration` | Metric backend | Does not identify the query/table |
| Disk headroom is low | `storage.free.bytes` | Metric backend | No write preflight |
| No package code ran during reconciliation | `tests/reconciliation.rs` sentinel + unchanged bytes + empty staging | `cargo test --test reconciliation` | Test evidence, not a runtime metric |

Example: the strongest simple proof of an accepted upload is the combination
of `201`, `x-request-id`, an `http.server.requests{status="201"}` increment, no
matching rejection row, the artifact file at
`artifacts/{module_id}/{version}/{digest_hex}.zip`, and a `module_versions` row
with `integrity_state = ok`.

## 6. Agent validation protocol

Use the same PASS/FAIL/UNPROVEN discipline as
[agent-workflow.md](agent-workflow.md). For every claim, name the signal, the
command, and the raw observation.

```text
Claim:    startup reconciliation marks a missing artifact
Signal:   startup log + module_versions.integrity_state
Command:  start host; sqlite3 ... "select ..."
Observed: artifact reconciliation complete scanned=1 ok=0 missing=1 ...
          reporting-service|1.2.0|missing
Caveat:   /readyz still returns 200; no reconciliation metric exists yet
Verdict:  PASS
```

Rules:

1. **Do not mark PASS from a metric alone.** A metric proves the instrument
   fired, not that the effect is correct.
2. **Do not mark FAIL from absent metrics unless export is known healthy.** No
   OTLP endpoint means no export by design.
3. **Prefer independent signals.** Contract test + durable row/API response +
   metric is stronger than any one signal.
4. **Record the caveat.** Counters reset on restart; readiness is cached;
   metrics can lag until the export interval; labels are intentionally bounded.
5. **Use the right store.** Metrics for rates and bounded outcomes; SQLite for
   per-row truth; logs for context and correlation; filesystem for artifact
   presence and bytes.

### Validating an observability change

Use the in-process exporter seam rather than a live collector:

- `Metrics::with_exporter(options, exporter)` in `src/metrics.rs`;
- `InMemoryMetricExporter` helpers in `tests/observability.rs`;
- assert metric name, type, attributes, and value after `force_flush`.

For a new or renamed metric, update the metric table in `README.md`, the
instrument constant/view/test in `src/metrics.rs`, and at least one test that
observes it. A compile success is not evidence that the metric is exported.

### Validating a behavior change

1. Run the focused contract test.
2. Exercise the API or startup path.
3. Check the durable row or filesystem effect.
4. Check the metric that should have moved.
5. Report the raw output and the caveat.

### Validating startup reconciliation today

There is no reconciliation gauge/histogram yet. Use:

- the `artifact reconciliation complete` log;
- `module_versions.integrity_state`;
- an activation or execution attempt that must refuse a non-`ok` row;
- `cargo test --test reconciliation` for the no-execution/no-extraction
  invariant.

Do **not** use `/readyz` as proof that reconciliation found healthy artifacts.

## 7. Known gaps

| Gap | Consequence |
| --- | --- |
| No `/metrics` endpoint | Metrics require an OTLP collector/backend |
| No trace exporter or exemplars | Correlate through `x-request-id` and logs, not trace links |
| No alerting rules or SLOs | Define them in the collector/backend |
| Readiness excludes reconciliation/integrity/disk | A host can be `200` with every module missing |
| Reconciliation has no metric yet | Use logs + SQLite + activation refusal |
| Counters are process-lifetime | Use `rate`/`increase`; restarts reset them |
| Bounded metric labels | Module/version/execution diagnosis is via logs/SQL, not metrics |
| No retention/GC for rejections, history, or job runs | All three grow without bound; queue/job counts are capped but terminal `job_runs` are not |
| No interval/cron scheduler metrics | Slice 1 emits only manual-run wait/queue/active signals; due-tick and cron lag are later slices |
| `Readiness::new` defaults the scheduler flag true for fixtures | A direct `Host::into_state()` embedder that never starts the scheduler can report `/readyz` 200; triggers still return `scheduler_unavailable` |
| Metrics are ephemeral | No durable metrics store; SQLite is the durable authority |

## 8. References

- [README: Observability](../README.md#observability-unstable) — configuration
  and the public metric table.
- [architecture.md](architecture.md#observability-metricsrs) — design and
  trust boundaries.
- [agent-workflow.md](agent-workflow.md) — PASS/FAIL/UNPROVEN evidence rules.
- `src/metrics.rs` — metric names, instruments, views, resource identity.
- `tests/observability.rs` — HTTP/auth/readiness metric tests.
- `tests/execution_service.rs` — execution/integrity/history metric tests.
- `tests/reconciliation.rs` — startup classification and no-execution proof.
- `src/audit/store.rs` and `src/executions/history.rs` — durable rows.
