# Handover: Scheduler slice 2 (interval triggers)

Base: `feat/scheduler-slice-1` tip (slice 1 code at `351df8a`; this handover
is on the branch tip). Slice 1 is implemented and
green. This handover is the starting point for interval triggers.

## What slice 1 proved

- Schema v3 in `src/storage/database.rs`: `jobs` and `job_runs`.
  - `job_runs.state` is the durable queue (`queued`, `running`, `succeeded`,
    `failed`, `refused`, `interrupted`).
  - `jobs` already has `trigger_kind`, `interval_secs`, `cron_expr`,
    `timezone`, `payload_json`, `enabled`, `next_run_at`.
  - `idx_job_runs_tick` is a partial unique index on
    `(job_id, trigger_kind, scheduled_for, attempt_no)` for interval/cron.
- `src/control_plane/scheduler/job.rs` already has `Trigger::Interval`,
  interval/next-run validation, run state/failure vocabularies, and bounded
  identities.
- `src/control_plane/scheduler/store.rs` already persists interval fields,
  claims queued runs atomically, finishes runs, recovers startup state, and
  terminalizes queued runs on disable. It does **not** enqueue due runs.
- `src/control_plane/scheduler/service.rs` has one loop, readiness ownership,
  recovery, claim/finish, job wait/queue/active metrics, and a deterministic
  `tick_once(now)` test seam. `tick_once` currently only claims queued runs.
- `src/control_plane/scheduler/dispatch.rs` exposes only pinned
  `ExecutionService::execute`; the scheduler cannot call activation, registry,
  artifact, staging, or worker-spawn internals.
- `/v1/jobs` supports create/list/enable/disable/manual trigger/list runs.
  Interval and cron are currently rejected with `invalid_trigger`.
- Tests: `tests/scheduler_api.rs` (9 tests), `tests/scheduler_service.rs`
  (4 tests), `fuzz/fuzz_targets/http_jobs.rs`, and source-boundary guard test.

## Slice 2 goal

Implement interval triggers end to end:

1. Accept `{"trigger":{"kind":"interval","interval_secs":N}}` on create.
2. Persist `next_run_at` and enqueue due interval runs from the single loop.
3. Dispatch those runs through the same pinned execution path.
4. Keep duplicate ticks, restart catch-up, disable, and queue bounds correct.

## Non-goals for slice 2

Cron evaluation, retries, cancellation/drain, distributed scheduling,
artifact GC, execution-history retention, operator CLI, lifecycle
deactivate/remove/rollback, and timezone handling beyond UTC.

## Decisions to carry forward

- **No schema migration needed.** v3 already has the interval columns, CHECKs,
  and partial tick index. Do not rewrite shipped migrations.
- **Interval bounds:** add `MIN_INTERVAL_SECS = 1` and
  `MAX_INTERVAL_SECS = 31_536_000` (one year) in
  `src/control_plane/scheduler/job.rs`; enforce in the API and store.
- **First run:** on create/enable, `next_run_at = now + interval`.
  Do not enqueue immediately on create.
- **Due tick:** `scheduled_for = jobs.next_run_at`; insert one queued run with
  `trigger_kind='interval'`, then advance `next_run_at` to the first boundary
  strictly after `now`. This is the restart catch-up policy: one missed run,
  not a burst.
- **Queue full:** leave `next_run_at` unchanged and skip the tick; retry on a
  later tick. Do not drop the due time.
- **Duplicate ticks:** rely on `idx_job_runs_tick` with `INSERT OR IGNORE`.
  If the insert is ignored, still advance `next_run_at`; never create a second
  run for the same boundary.
- **Manual trigger of an interval job:** still allowed when enabled; it records
  `trigger_kind='manual'` and does not change `next_run_at`.
- **Disable:** existing behavior clears `next_run_at` and terminalizes queued
  runs as `refused`/`job_disabled`.
- **Enable:** for interval jobs, recompute `next_run_at = now + interval`;
  manual jobs stay null.
- **Cron remains rejected** with `invalid_trigger`; it is slice 3.

## Implementation steps

### 1. Interval math and validation

Add to `src/control_plane/scheduler/job.rs`:

- `MIN_INTERVAL_SECS`, `MAX_INTERVAL_SECS`.
- `next_interval_at(now, interval_secs) -> Option<SystemTime>`.
- `advance_interval_due(scheduled_for, interval_secs, now) -> Option<SystemTime>`:
  return `scheduled_for` if still in the future; otherwise advance by
  `interval - (elapsed % interval)` seconds so the result is strictly after
  `now`. Use checked arithmetic and avoid multiplying by a huge missed count.

Keep the existing `validate_new_job` interval rules: enabled interval jobs
must have `next_run_at`; disabled ones must not.

### 2. API

In `src/api/jobs.rs`:

- `validate_create`: accept `TriggerRequest::Interval` if the value is within
  bounds; still reject cron.
- `post_job`: convert the trigger, compute `next_run_at` for enabled interval
  jobs, and pass it in `NewJob`.
- `post_enable`: read the job or add a service helper that computes the next
  run; for interval pass `now + interval`, for manual pass `None`.
- Update the client-facing `invalid_trigger` message to mention interval
  support and leave cron unsupported.

No route or response-shape change is needed; `TriggerView::Interval` already
exists.

### 3. Store due enqueue

Add to `src/control_plane/scheduler/store.rs`, in one immediate transaction:

```text
DueEnqueueReport { enqueued: usize, deduped: usize, skipped_full: usize }
```

- Select enabled interval jobs with `next_run_at IS NOT NULL AND
  next_run_at <= now`.
- Read the current global queued count once; for each due job:
  - if queued >= `max_queued_runs`, count `skipped_full` and leave
  `next_run_at` unchanged;
  - otherwise `INSERT OR IGNORE` the run:
    `run_id`, `job_id`, `attempt_no=1`, `trigger_kind='interval'`,
    `scheduled_for=next_run_at`, `state='queued'`, `created_at=now`;
  - if inserted, increment the local queued count and `enqueued`;
  - if ignored by the tick unique index, count `deduped`;
  - update `jobs.next_run_at` to the advanced boundary and `updated_at=now`.
- Return the report. Keep this method sync; the service wraps it in
  `spawn_blocking`.

### 4. Service loop

In `src/control_plane/scheduler/service.rs`:

- Add `async fn enqueue_due(&self, now) -> Result<DueEnqueueReport, SchedulerError>`
  using `spawn_blocking`.
- Call it at the start of `tick_once(now)` and in `fill_slots`/the production
  tick before claiming.
- Increment `conductor.job.queue.depth` by `report.enqueued`.
- Keep `tick_once` returning the dispatched count, or reintroduce a small
  report if tests need both counts. Do not change the public API unnecessarily.
- Do not enqueue when the scheduler is not running; the loop only runs while
  `SchedulerState::Running`.

### 5. Metrics and logs

No new metric is required:

- `conductor.job.wait.duration` already measures `claim - scheduled_for`.
- `conductor.job.queue.depth` must move on due enqueue.
- `conductor.job.active` is unchanged.

Log due enqueue counts at info/debug with bounded fields (`enqueued`,
`deduped`, `skipped_full`). Do not log payloads.

## Test plan

Add to `tests/scheduler_service.rs` and/or `tests/scheduler_api.rs`:

- Create interval job (API) -> `201`, trigger view is interval, `next_run_at_ms`
  is in the future.
- `tick_once(now)` at/after `next_run_at` enqueues exactly one queued run,
  dispatches it through the existing path, and advances `next_run_at`.
- Calling `tick_once` twice with the same `now` produces one run for that
  boundary.
- Restart catch-up: seed a due `next_run_at` several intervals in the past;
  tick once; assert one run with the original `scheduled_for`, not a burst.
- Disabled interval job is not enqueued.
- Enable recomputes `next_run_at`; disable clears it.
- Manual trigger still works on an enabled interval job and records a manual
  run.
- Interval bounds: `0` and `MAX+1` -> `400 invalid_trigger`.
- Queue-full: fill the queue; tick leaves `next_run_at` unchanged and creates
  no run.
- Existing slice-1 tests and the source-boundary guard stay green.

## Acceptance commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --test scheduler_service
cargo test --test scheduler_api
cargo test
python3 scripts/check_test_quality.py
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --bins -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --bins
```

CI also runs DAST and `cargo mutants --in-diff`; the existing OpenAPI job paths
and `http_jobs` fuzz target already cover the routes.

## Exact file list for slice 2

Production:
- `src/control_plane/scheduler/job.rs`
- `src/control_plane/scheduler/store.rs`
- `src/control_plane/scheduler/service.rs`
- `src/control_plane/scheduler/mod.rs` (only if new report/helper types are
  re-exported)
- `src/api/jobs.rs`

Tests:
- `tests/scheduler_service.rs`
- `tests/scheduler_api.rs`

Docs:
- `README.md`
- `docs/observability.md`
- `docs/architecture.md`
- `docs/statecharts.md`

No `src/storage/database.rs` change, no `Cargo.toml` change, and no new fuzz
target are expected. If implementation discovers a schema need, stop and
re-plan rather than editing v3.

## Residuals to keep documenting

- At-most-once dispatch; no retries.
- Manual triggers are not idempotent until the idempotency-key slice.
- Single-process only; no distributed lock.
- No job/run retention.
- A loop panic/tick failure flips readiness false; in-flight rows remain
  `running` until restart recovery.
- Pinned jobs are not revoked by activation/rollback.
- Job payloads are plaintext at rest.

## New-session prompt

Paste this into a fresh session:

```text
Work in /home/nnadolski/projects/job-scheduler.

You are picking up Conductor after Scheduler slice 1. Read
docs/handover-scheduler-slice-2.md first; it is the authoritative handover.
The base is the tip of branch feat/scheduler-slice-1 (slice 1 code at
351df8a; this handover is on the tip). Create feat/scheduler-slice-2 from that base (or
rebase onto main if slice 1 has merged).

Implement Scheduler slice 2: interval triggers only.
- Accept interval_secs on job create within the documented bounds.
- Persist next_run_at and enqueue due interval runs from the single loop.
- Advance next_run_at to the first boundary after now; enqueue at most one
  missed run after restart.
- Deduplicate repeated ticks with the existing partial unique index.
- Keep dispatch pinned through ExecutionService::execute; do not add
  activation/registry/artifact/worker access to the scheduler.
- Keep queue bounds, disable kill-switch, readiness, and job metrics correct.
- Add the tests listed in the handover.

Do not implement cron, retries, cancellation, drain, distributed scheduling,
artifact GC, retention, operator CLI, or lifecycle transitions.

Use the project orchestration workflow: poteto-agent for code-writing,
poteto-judge for independent read-only verification, security for the
scheduler/trust-boundary review, and load the deslop skill for the final diff.
Run the acceptance commands in the handover and report raw command results.
If a schema change seems necessary, stop and re-plan instead of editing v3.

Return: what changed, files touched, commands + results, verification table,
security/residual risks, and the next task.
```
