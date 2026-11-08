# Handover: Scheduler slice 4 (bounded retries with backoff)

Base: `feat/scheduler-slice-3` tip (slice 3 code at `533d938`; this handover is
on the tip). Slice 3 is implemented and green. This handover is the starting
point for Scheduler slice 4 (bounded retries with deterministic backoff).

## What slice 3 proved

- Schema v3 already supports cron and retries' per-attempt rows:
  `jobs.cron_expr`, `jobs.timezone` (fixed `UTC`), `jobs.next_run_at`,
  `job_runs.attempt_no`, and `idx_job_runs_tick` on
  `(job_id, trigger_kind, scheduled_for, attempt_no)` for `interval`/`cron`.
  No schema migration is needed for slice 3.
- `src/control_plane/scheduler/cron.rs` is a private wrapper around
  `croner 4.0.3`; it owns the closed five-field UTC grammar, range validation,
  POSIX DOM/DOW OR semantics, a cheap impossible-date pre-check, and a
  3660-day horizon/order guard. `croner`/`chrono` types do not escape it.
- `src/control_plane/scheduler/job.rs` has `Trigger::Cron`,
  `TriggerKind::Cron`, `cron_expr()`, `next_run_at(trigger, now)`, and cron
  syntax validation in `validate_new_job`. `RunCompletion` already carries
  `state`, `outcome`, `execution_id`, and `failure_code`; `JobRun` already
  carries `attempt_no`.
- `src/control_plane/scheduler/store.rs` enqueues due interval and cron runs in
  one immediate transaction. `DueEnqueueReport { enqueued, deduped,
  skipped_full, skipped_invalid }` is the single-pass result. It dedupes with
  `INSERT OR IGNORE`, leaves a full queue's boundary unchanged, advances
  `next_run_at` after every attempted insert, and defensively skips
  unparseable/invalid-UTF-8/BLOB/impossible cron rows rather than failing the
  pass. `row_to_job` validates persisted cron syntax and fails closed on
  unparseable rows.
- `src/control_plane/scheduler/service.rs` has the single loop. `tick_once`
  and `fill_slots` call `enqueue_due(now)` before claiming, increment
  `conductor.job.queue.depth` by `enqueued`, and log bounded counts including
  `skipped_invalid`. Dispatch remains pinned through
  `ExecutionDispatcher -> ExecutionService::execute`.
- `src/api/jobs.rs` accepts manual, interval, and cron triggers. Enabled cron
  create/enable persists the first occurrence strictly after `now`; disable
  clears it; an enabled non-manual trigger with no representable occurrence
  returns `400 invalid_trigger`; a manual trigger on an enabled cron job
  records `trigger_kind='manual'` and does not move `next_run_at`.
- Slice 3 tests prove the cron grammar and errors, strict-after/sub-second
  boundaries, leap day, DOM/DOW OR, impossible-expression skipping, due
  enqueue/advance, dedupe, restart catch-up, queue bound, mixed interval/cron
  ordering, disable kill-switch, API create/enable/disable, and the pinned
  source-boundary guard. Current gates at `533d938` are green:
  49 `cargo test --lib scheduler`, 13 `scheduler_service`, 20 `scheduler_api`,
  597 total tests, test-quality, fuzz format/clippy/check, and `cargo deny`.
- Slice 3 deliberately did not implement retries, attempt policies, backoff,
  cancellation/drain, distributed scheduling, artifact GC, retention, operator
  CLI, lifecycle transitions, timezone/DST, seconds/7-field cron, macros,
  symbolic names, idempotency keys, per-job authorization, or a cron-lag
  metric.

## Slice 4 goal

Implement bounded retries with deterministic backoff for failed worker runs,
using the existing durable queue and `attempt_no`:

1. Classify a completed run as retryable only when the worker reported a
   transient failure (see the closed set below).
2. On a retryable failure with `attempt_no < max_attempts`, enqueue exactly one
   new `queued` run with the same `job_id` and `trigger_kind`,
   `attempt_no = failed.attempt_no + 1`, `scheduled_for = now + backoff`, and
   `created_at = now`. Do not mutate `jobs.next_run_at`.
3. Make the claim path honor `scheduled_for <= now`, so a backoff delay is real
   and a future retry cannot be claimed early.
4. Reuse the global queue bound, disable kill-switch, readiness ownership, job
   metrics, and the pinned `ExecutionDispatcher -> ExecutionService::execute`
   path.
5. Keep startup recovery unchanged: running rows become `interrupted`, queued
   retries survive and dispatch when due, and interrupted runs are not replayed.

## Non-goals for slice 4

Do not implement:

- per-job retry policy, API/CLI retry configuration, or a new retry route;
- jitter, distributed coordination, or a multi-process retry lock;
- retries for `succeeded`, `refused`, `interrupted`, `cancelled`, or
  `protocol_violation` runs;
- retries for scheduler/transport/binding failures (including
  `deadline_exceeded`, `server_busy`, `internal`, `history_write_failed`, and
  every `JobFailureCode` refusal), because those either did not run the worker
  or would risk duplicate side effects;
- replay of `interrupted` runs after a crash;
- cancellation of an individual queued retry, drain, or new lifecycle
  transitions;
- a new job-run state, new schema migration, new metric, or new route;
- artifact GC, execution/job retention, operator CLI, timezone/DST, seconds or
  7-field cron, macros, symbolic names, or idempotency keys.

## Decisions to carry forward

- **No schema migration.** Use the existing `job_runs.attempt_no`,
  `scheduled_for`, `state`, and `idx_job_runs_tick`. Put the retry policy in
  `SchedulerConfig` with defaults. If per-job retry policy appears necessary,
  stop and re-plan a v4 migration instead of editing v3.
- **Retry set is closed and worker-only.** Retry only a `failed` completion
  with a worker `outcome` of `failed`, `timed_out`, or `worker_error`.
  `protocol_violation` and `cancelled` are deterministic/terminal; `refused`
  and every scheduler `failure_code` are not retried in this slice. This keeps
  retries from re-running work that never started or that already produced a
  durable execution/history side effect.
- **Attempts are durable rows, not in-place mutation.** A retry is a new
  `job_runs` row with `attempt_no+1`; the failed row stays terminal. This
  preserves history and the existing `attempt` API field.
- **Backoff is deterministic exponential.** Use
  `base * 2^(attempt_no - 1)`, capped at `max_backoff`, with checked
  arithmetic. Defaults: `max_attempts = 3`, `retry_base_backoff = 5s`,
  `retry_max_backoff = 5m`. Tests may override the config to zero/short
  delays. No jitter in this slice.
- **Retry `scheduled_for` is the retry due time.** Set it to
  `now + backoff`, not the original trigger boundary. `created_at` is the
  enqueue time. This makes `conductor.job.wait.duration` include the backoff
  wait and keeps claim ordering meaningful.
- **Claim must gate on `scheduled_for <= now`.** Add that predicate to
  `claim_next_run`. Existing enqueues are already due, so this is backward
  compatible; it is required for future-dated retries.
- **Full queue drops the retry.** The retry insert checks the shared
  `max_queued_runs` bound. If full, do not insert, do not fail readiness, and
  leave the failed run terminal. Log/count the skip; do not create a later
  automatic retry.
- **Disable is the kill-switch.** The retry transaction re-reads the job and
  does nothing if it is disabled. Existing `set_enabled(false, ...)` already
  terminalizes queued runs as `refused`/`job_disabled`, so queued retries are
  cancelled by disable.
- **Dispatch stays pinned.** Do not add activation, registry, artifact,
  staging, worker-spawn, or `active_versions` access to the scheduler.
- **No new metric.** Reuse `conductor.job.queue.depth`,
  `conductor.job.wait.duration`, and `conductor.job.active`. Extend bounded
  debug logging with retry enqueued/skipped counts. Never log payloads.
- **Authentication is unchanged.** Retries are internal; no new route or
  per-job authorization.

## Implementation steps

### 1. Add retry policy helpers in `job.rs`

Add a closed classification helper, for example
`pub fn is_retryable_completion(completion: &RunCompletion) -> bool`, that
returns true only for `JobRunState::Failed` with
`outcome.as_deref()` in `{"failed", "timed_out", "worker_error"}` and
`failure_code.is_none()`.

Add a backoff helper, for example
`pub fn retry_delay(attempt_no: u32, base: Duration, maximum: Duration) -> Option<Duration>`,
computing `base * 2^(attempt_no - 1)` with checked/saturating arithmetic and a
cap at `maximum`. `attempt_no` is the attempt that just failed. Add unit tests
for the retry set and the delay curve/cap/overflow.

### 2. Extend the store with a retry enqueue and claim gate

In `store.rs`:

- Add a `JobStore::enqueue_retry` method (exact name may vary) that takes
  `job_id`, `trigger_kind`, `next_attempt_no`, `scheduled_for`, and `now`.
  In one immediate transaction:
  - re-read the job with `get_job_tx` and return `Ok(None)` if missing or
    disabled;
  - check the shared `max_queued_runs` bound and return `Ok(None)` if full;
  - insert one `queued` run with a new `run_id`, the same `job_id` and
    `trigger_kind`, `attempt_no = next_attempt_no`, `scheduled_for`,
    `created_at = now`;
  - use `INSERT OR IGNORE` for interval/cron so the tick index is the backstop;
    for manual, a new `run_id` is sufficient. Return the inserted `JobRun` or
    `Ok(None)` when ignored.
- In `claim_next_run`, add `AND scheduled_for <= ?1` (bind `now` in millis) to
  the candidate query. Keep `ORDER BY scheduled_for, id` and the existing
  claim/lease transaction.
- Add store tests: retry row shape and attempt increment; trigger kind
  preserved; queue bound; disabled job; duplicate retry ignored; a future
  `scheduled_for` is not claimed before its time and is claimed at/after it;
  existing due interval/cron/manual claims still work.

### 3. Wire retry policy and completion handling in `service.rs`

In `SchedulerConfig`, add `max_attempts: u32`,
`retry_base_backoff: Duration`, and `retry_max_backoff: Duration` with the
defaults above. `src/server.rs` already uses `..SchedulerConfig::default()`, so
no host wiring change is required.

In `dispatch_claimed`, after `finish_run` succeeds with `Ok(true)`:

- if `is_retryable_completion(&completion)` and
  `claimed.run.attempt_no < self.config.max_attempts`, compute
  `delay = retry_delay(claimed.run.attempt_no, base, max)`, `retry_at = now + delay`;
- enqueue the next attempt through `enqueue_retry` using the same `now`;
- if a run was inserted, increment `conductor.job.queue.depth` once and log
  `retry_attempt = next_attempt_no`;
- if the queue is full/disabled/ignored, do not fail the scheduler; log a
  bounded skip count;
- never change `jobs.next_run_at` from this path.

Keep `finish_run` as the terminal write for the failed attempt. Do not retry
`interrupted` recovery rows. Add service tests listed below.

### 4. Update docs

Update `README.md`, `docs/observability.md`, `docs/architecture.md`, and
`docs/statecharts.md` to describe global bounded retries, the worker-only retry
set, the attempt/backoff semantics, the queue/disable rules, and the residual
that retries re-execute side-effecting workers. Reuse the existing job metrics
and run `attempt` field; do not claim a new metric or route.

## Test plan

- `job.rs` unit tests:
  - retryable: worker outcomes `failed`, `timed_out`, `worker_error`;
  - not retryable: `succeeded`, `refused`, `interrupted`, `cancelled`,
    `protocol_violation`, and scheduler failure codes (`deadline_exceeded`,
    `server_busy`, `internal`, `history_write_failed`, refusals);
  - backoff: attempt 1 = base, attempt 2 = 2x, attempt 3 = 4x, cap at maximum,
    zero/overflow-safe behavior.
- `store.rs` unit tests:
  - retry inserts exactly one `queued` row with `attempt_no+1`, same
    `trigger_kind`, `scheduled_for = retry_at`, `created_at = now`;
  - `jobs.next_run_at` is unchanged;
  - disabled job -> no retry; full queue -> no retry and no error;
  - duplicate `(job_id, trigger_kind, scheduled_for, attempt_no)` is ignored;
  - `claim_next_run` does not claim a future `scheduled_for` before `now`, then
    claims it at/after `now`; existing due claims still pass.
- `tests/scheduler_service.rs`:
  - a retryable worker failure creates attempt 2; `tick_once` before
    `retry_at` dispatches 0; a tick at/after `retry_at` dispatches attempt 2;
  - max attempts stops after the configured count;
  - a non-retryable refusal creates no retry;
  - a disabled job creates no retry;
  - a full queue creates no retry and does not flip readiness;
  - queue depth moves once for the retry enqueue;
  - the pinned refusal path is still used for retries with an unregistered
    module.
- `tests/scheduler_api.rs`:
  - no new route is added; the existing run view already renders `attempt`.
    Keep the existing manual/interval/cron API suite green. Add an API
    assertion only if a real observable (for example a seeded attempt-2 run)
    can be checked without a new broad e2e.
- Keep the test-quality rules: real observables, no tautologies, no duplicate
  bodies, at most one true end-to-end success test for the slice.

## Acceptance commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --lib scheduler
cargo test --test scheduler_service
cargo test --test scheduler_api
cargo test
python3 scripts/check_test_quality.py
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --bins -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Run `cargo deny check` only if `Cargo.toml` or `Cargo.lock` changes. Do not run
`cargo mutants` during the slice; mutation is a final-feature gate. The security
review for this slice is a focused trust-boundary review of the retry/claim/
disable paths, not the full DAST/fuzz/mutation/supply-chain audit.

## Exact file list for slice 4

Production:
- `src/control_plane/scheduler/job.rs` (retryability and backoff helpers)
- `src/control_plane/scheduler/store.rs` (`enqueue_retry`, claim
  `scheduled_for <= now`)
- `src/control_plane/scheduler/service.rs` (`SchedulerConfig` fields, retry
  after completion, queue-depth/logging)
- `src/control_plane/scheduler/mod.rs` only if a new helper needs re-export

Tests:
- `src/control_plane/scheduler/job.rs` unit tests
- `src/control_plane/scheduler/store.rs` unit tests
- `tests/scheduler_service.rs`
- `tests/scheduler_api.rs` only if a real API observable is added

Docs:
- `README.md`
- `docs/observability.md`
- `docs/architecture.md`
- `docs/statecharts.md`

Must not change:
- `src/storage/database.rs` (v3 already supports attempts; stop and re-plan if
  a schema change appears necessary)
- `src/metrics.rs` (no new instrument)
- `src/control_plane/scheduler/dispatch.rs` (pinned boundary stays narrow)
- `src/api/routes.rs` (no new route)
- `fuzz/Cargo.toml` and `fuzz/fuzz_targets/*` (no new target)
- `Cargo.toml`/`Cargo.lock` unless a dependency is unavoidable; prefer none

## Residuals to keep documenting

- Retries apply only to worker-reported transient failures; scheduler,
  transport, refusal, protocol-violation, cancelled, and interrupted runs are
  not retried.
- Retries re-execute the worker. Jobs with non-idempotent side effects can
  duplicate effects; there are no idempotency keys in this slice.
- The retry policy is global (`SchedulerConfig`), not per job, and has no API or
  CLI surface.
- Backoff is deterministic with no jitter; a large fleet can retry in sync.
- A full queue drops the retry; the failed attempt stays terminal and is not
  automatically retried later.
- `finish_run` and the retry insert are separate transactions. A crash between
  them leaves that failure terminal with no retry; startup does not reconstruct
  retries. This slice deliberately does not add a pending-retry state.
- Startup recovery does not replay `interrupted` runs; queued retries survive
  and dispatch when due.
- Disable terminalizes queued retries, but a retry already claimed can still
  run to completion (pre-existing kill-switch race).
- No per-attempt cancellation or drain.
- Retries grow `job_runs`; there is no job/run retention or artifact GC.
- `conductor.job.wait.duration` includes backoff wait; no retry-specific
  metric exists, so use run rows/`attempt` and bounded debug counts.
- Single-process only; no distributed retry ownership.
- Pinned jobs are not revoked by activation/rollback; payloads are plaintext at
  rest.
- A loop panic/tick failure flips readiness false; in-flight rows remain
  `running` until restart recovery marks them `interrupted`.

## New-session prompt

Paste this into a fresh session:

```text
Work in /home/nnadolski/projects/job-scheduler.

You are picking up Conductor after Scheduler slice 3. Read
docs/handover-scheduler-slice-4.md first; it is the authoritative handover.
The base is the tip of feat/scheduler-slice-3 (slice 3 code at 533d938; this
handover is on the tip), or main if slice 3 merged. Create
feat/scheduler-slice-4 from that base.

Implement Scheduler slice 4: bounded retries with backoff.
- Retry only worker-reported transient failures (outcome failed, timed_out, or
  worker_error) for a failed run.
- On a retryable failure under max_attempts, enqueue exactly one new queued run
  with attempt_no+1, the same trigger_kind, scheduled_for=now+backoff, and
  created_at=now. Do not move jobs.next_run_at.
- Gate claim_next_run on scheduled_for <= now so backoff is honored.
- Reuse the global queue bound, disable kill-switch, readiness, and job
  metrics; keep dispatch pinned through ExecutionService::execute.
- Use a global SchedulerConfig policy (defaults max_attempts=3, base=5s,
  cap=5m). No schema migration.

Do not implement per-job/API retry config, jitter, retries for refusals or
scheduler failures, interrupted-run replay, cancellation/drain, distributed
scheduling, retention, artifact GC, operator CLI, lifecycle transitions,
timezone/DST, seconds/7-field cron, macros, symbolic names, idempotency keys,
new routes, new job-run states, or new metrics.

Use the project orchestration workflow in docs/agent-workflow.md: poteto-agent
for code-writing, poteto-judge for independent read-only verification, and a
slice-scoped security review of the retry/claim/disable paths (no full
DAST/mutation/supply-chain audit). Load the deslop skill for the final diff.
Run the acceptance commands in the handover and report raw command results.
Do not run mutation; it is a final-feature gate. If a schema change seems
necessary, stop and re-plan instead of editing v3.

Return: what changed, files touched, commands + results, verification table,
security/residual risks, and the next task.
```
