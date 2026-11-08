# Handover: Scheduler slice 5 (graceful drain on shutdown)

Base: `feat/scheduler-slice-4` tip (slice 4 code at `b441710`; this handover is
on the tip). Slice 4 is implemented and green. This handover is the starting
point for Scheduler slice 5 (bounded graceful drain).

## What slice 4 proved

- Retry classification is closed and worker-only:
  `is_retryable_completion` in `src/control_plane/scheduler/job.rs` returns true
  only for `JobRunState::Failed`, `failure_code.is_none()`, and an outcome of
  `failed`, `timed_out`, or `worker_error`. Succeeded, refused, interrupted,
  cancelled, `protocol_violation`, and every scheduler `JobFailureCode` are
  terminal.
- Backoff is deterministic: `retry_delay(attempt_no, base, maximum)` computes
  `base * 2^(attempt_no - 1)` with saturating/checked math, caps at `maximum`,
  returns `None` for attempt 0, and never wraps. Defaults in
  `SchedulerConfig` are `max_attempts = 3`, `retry_base_backoff = 5s`, and
  `retry_max_backoff = 5m`; there is no jitter.
- `JobStore::enqueue_retry` is one immediate transaction and is
  `pub(crate)`. It re-reads the job, returns `Ok(None)` for a missing/disabled
  job or a full shared `max_queued_runs` queue, rejects `next_attempt_no < 2`,
  inserts one `queued` row with a new `run_id`, and uses `INSERT OR IGNORE`.
  It never updates `jobs.next_run_at`.
- The retry row shape is `attempt_no + 1`, the failed run's `trigger_kind`,
  `scheduled_for = finish_time + backoff`, and `created_at = finish_time`.
  `finish_run` remains the failed attempt's terminal write; the failed row is
  never mutated.
- `claim_next_run` now requires `scheduled_for <= now` (bound millisecond
  parameter) while preserving `ORDER BY scheduled_for, id`, the enabled-job
  subquery, and the atomic claim/lease transaction. A future retry is not
  claimable early and is claimable at exactly `scheduled_for`.
- `SchedulerService::maybe_enqueue_retry` runs only after `finish_run` returns
  `Ok(true)`. `Ok(Some)` moves `conductor.job.queue.depth` once and logs
  `retry_attempt`; `Ok(None)` logs `retry_skipped`; a store/task error goes
  through `fail`. Dispatch is still pinned through
  `ExecutionDispatcher -> ExecutionService::execute`.
- Disable remains the kill-switch: `set_enabled(false, ...)` terminalizes queued
  retries as `refused`/`job_disabled`. A retry already claimed can still run to
  completion. A retry insert that is skipped does not flip readiness.
- No schema change: schema v3 still owns `job_runs.attempt_no`,
  `scheduled_for`, `state`, and the partial unique
  `idx_job_runs_tick(job_id, trigger_kind, scheduled_for, attempt_no)` for
  interval/cron. No new route, metric, job-run state, or dependency.
- `conductor.job.wait.duration` is claim time minus `scheduled_for` (lateness
  past the due time). For a retry, the backoff is visible as
  `scheduled_for - created_at`, not in the wait histogram. The slice 4 handover
  sentence saying the histogram includes the backoff is inaccurate; the
  product docs state the correct semantics.
- Slice 4 gates at `b441710`: 58 `cargo test --lib scheduler`, 16
  `scheduler_service`, 20 `scheduler_api`, 609 total tests, test-quality
  609/68, fuzz format/clippy/check, and clippy `-D warnings`.
- Slice 4 deliberately did not implement per-run cancellation, drain,
  interrupted-run replay, per-job/API retry policy, jitter, distributed
  scheduling, retention, artifact GC, timezone/DST, operator CLI, lifecycle
  transitions, macros/symbolic names, or idempotency keys.
- Current host shutdown behavior: `Host::serve_with_handle` in
  `src/server.rs` lets axum drain HTTP for up to 30 s, then calls
  `scheduler.stop()`. `stop()` sets `SchedulerState::Stopping`, clears
  readiness, notifies the loop, and **aborts** the loop task immediately.
  `run_loop` ends with `join_set.shutdown().await`, which aborts in-flight
  dispatch tasks. Their `job_runs` rows stay `running` until startup recovery
  marks them `interrupted`. A normal restart therefore does not replay those
  workers.

## Slice 5 goal

Implement bounded graceful drain for the scheduler's in-flight runs:

1. Add `SchedulerService::drain()` and a `SchedulerConfig::drain_timeout`
   (default 30 s). Drain stops claiming new runs, clears scheduler readiness,
   and waits up to `drain_timeout` for already-claimed dispatch tasks to finish.
2. Runs that finish during the window write their normal terminal completion.
   Queued rows are not claimed and remain `queued` for the next start.
3. If the window expires, remaining dispatch tasks are aborted; their rows stay
   `running` until startup recovery marks them `interrupted`. This is the
   existing stop/restart behavior, now bounded explicitly.
4. `Host::serve_with_handle` calls `drain()` after HTTP serving ends instead of
   `stop()`. `stop()` keeps its immediate-abort semantics for tests and
   administrative use.
5. Reuse `SchedulerState::Stopping`; do not add a new scheduler state, route,
   metric, or schema.

## Non-goals for slice 5

Do not implement:

- per-run cancellation, a cancel route, a new cancellation failure code/state,
  or a worker cancellation channel through `ExecutionService`/`Executor`;
- replay of `interrupted` runs on startup, or a pending-retry/pending-run state;
- drain on `disable` (disable remains the kill-switch and continues to
  terminalize queued runs);
- per-job/API retry policy, jitter, or retry-policy changes;
- distributed scheduling, lease takeover, retention, artifact GC, operator CLI,
  lifecycle transitions, timezone/DST, seconds/7-field cron, macros, symbolic
  names, or idempotency keys;
- new metrics, a new `/metrics` surface, or a new route;
- changing the schema. If drain appears to need a schema change, stop and
  re-plan a v4 migration instead of editing v3.

## Decisions to carry forward

- **Drain reuses `SchedulerState::Stopping`.** No new state means no API or
  readiness contract change. `drain()` and `stop()` differ only in whether the
  loop is aborted immediately or allowed a bounded finish window.
- **Only already-claimed runs are waited on.** The loop must observe
  `state != Running` before every new claim, including inside `fill_slots`, so a
  drain cannot start a new dispatch after shutdown begins. Queued work is not
  refused; it survives for the next start.
- **The loop owns the timeout.** `run_loop` waits on its own `JoinSet` until
  `Instant::now() + drain_timeout`, then calls `join_set.shutdown().await`.
  `drain()` awaits the loop handle and uses a small safety margin so a bug
  cannot hang host shutdown forever.
- **Readiness flips false at drain entry.** `/readyz` must stop reporting ready
  before the finish window starts; the loop and `LoopGuard` must not flip it
  back.
- **No new metric.** Log bounded counts such as `drained` and `aborted` at info
  level. Keep the existing queue/active/wait instruments unchanged.
- **`stop()` stays an immediate abort.** Tests and emergency paths rely on it.
  Do not make `stop()` silently wait.
- **Host ordering.** HTTP graceful shutdown completes first, then
  `scheduler.drain()`, then metrics shutdown. Do not drain before the listener
  stops, or new manual triggers could race the drain.

## Implementation steps

### 1. Add the drain policy and lifecycle in `service.rs`

In `SchedulerConfig` add:

```rust
pub drain_timeout: Duration,
```

Default it to `Duration::from_secs(30)`. Keep the existing defaults and the
`..SchedulerConfig::default()` construction in `server.rs` and
`in_memory_for_test` working.

Add a shared private helper for the common shutdown preamble (state to
`Stopping`, readiness false, `notify_waiters`, take the loop handle). Use it from
both `stop()` and the new method:

```rust
pub async fn drain(&self)
```

`drain()` must:

- return immediately when `SchedulerState::NotStarted`;
- be safe when already `Stopping` or `Failed` (do not panic, do not double-join);
- set `Stopping`, clear readiness, notify the loop, take the loop handle;
- await the loop handle with a safety bound slightly above `drain_timeout`
  (for example `drain_timeout + 5s`); log and return if that bound trips;
- log that the scheduler drained.

`stop()` keeps aborting the handle immediately; do not route `stop()` through
the drain window.

### 2. Drain the `JoinSet` in `run_loop`

In `run_loop` (`service.rs`), after the loop breaks on `state != Running`:

- if the state is `Stopping`, wait for `join_set` for at most
  `self.config.drain_timeout` using `tokio::time::timeout_at` around
  `join_set.join_next()`;
- handle `Ok(Some(Ok(())))`, `Ok(Some(Err(error)))` (preserve the existing
  panic handling/logging), `Ok(None)` (empty), and `Err(_)` (deadline);
- count completed and remaining tasks for the bounded log;
- always finish with `join_set.shutdown().await` so the timeout path aborts.

Also make `fill_slots` re-check `self.state() == SchedulerState::Running` before
each claim, not only before the call. If drain begins while `fill_slots` is
running, the next iteration must stop claiming. `tick_once` is a test-only
facade and may keep its current behavior.

Do not change the `LoopGuard` contract: a `Stopping` loop drop must not set
`Failed`, and readiness must already be false.

### 3. Wire host shutdown in `server.rs`

In `Host::serve_with_handle`, replace `scheduler.stop().await` with
`scheduler.drain().await` after `serve_with_handle` returns and after
`readiness_watcher.abort()`, before `metrics.shutdown()`. Keep the existing
order and error handling. The HTTP graceful-shutdown timeout (30 s) and the
scheduler drain timeout (30 s default) are separate bounds; document that a
shutdown can take up to their sum in the worst case.

### 4. Update docs

Update `README.md`, `docs/observability.md`, `docs/architecture.md`, and
`docs/statecharts.md` to describe:

- bounded graceful drain on host shutdown;
- the `drain_timeout` default and the relationship to HTTP graceful shutdown;
- in-flight runs finish normally while queued rows remain queued;
- timeout aborts remaining dispatch tasks and leaves rows `running` until
  startup recovery marks them `interrupted`;
- readiness false at drain entry;
- no new metric/route/state;
- the residual that per-run cancellation and interrupted-run replay are still
  not implemented.

Statecharts: show the scheduler shutdown path (`Running -> Stopping -> drained`
with a timeout branch) and keep `SchedulerState` names unchanged. Do not claim a
new `Draining` enum variant.

## Test plan

- `tests/scheduler_service.rs` (reuse the slice 4 fixtures
  `build_scheduler_with_config`, `install_package`, and a slow success worker):
  - `drain` waits for the in-flight run: the claimed attempt reaches
    `succeeded`, and a second enqueued run stays `queued`; readiness is false
    and the scheduler is not running.
  - `drain` does not claim new work after it begins (capacity 1 with two queued
    runs; the second must remain queued).
  - drain timeout: a worker longer than `drain_timeout` is aborted, the row
    remains `running` (startup recovery later marks it `interrupted`), and
    `drain()` returns within the bounded window.
  - `stop()` still aborts immediately: with an in-flight slow worker, the row
    remains `running` and is not allowed to finish.
  - `drain` on a `NotStarted` scheduler is a no-op; a second `drain` does not
    panic.
- Keep the existing 16 `scheduler_service`, 20 `scheduler_api`, and full-suite
  tests green.
- Run `cargo test --test startup` and `cargo test --test tls_only` because
  `server.rs` shutdown wiring changes.
- Test cost: use worker sleeps around 0.5 s for the happy drain and around
  0.2 s for the timeout case. Keep each new test under roughly 2 s and do not
  blanket-serialize the file.

## Acceptance commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --lib scheduler
cargo test --test scheduler_service
cargo test --test scheduler_api
cargo test --test startup
cargo test --test tls_only
cargo test
python3 scripts/check_test_quality.py
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --bins -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Run `cargo deny check` only if `Cargo.toml` or `Cargo.lock` changes. Do not run
`cargo mutants` during the slice; mutation is a final-feature gate. The security
review for this slice is focused on the shutdown/drain/claim boundary, not the
full DAST/fuzz/mutation/supply-chain audit.

## Exact file list for slice 5

Production:
- `src/control_plane/scheduler/service.rs` (`drain_timeout`, `drain()`, shared
  shutdown preamble, `run_loop` bounded `JoinSet` wait, `fill_slots` state
  check)
- `src/server.rs` (call `drain()` on host shutdown)

Tests:
- `tests/scheduler_service.rs` (drain/stop behavior and bounded timeout)

Docs:
- `README.md`
- `docs/observability.md`
- `docs/architecture.md`
- `docs/statecharts.md`

`tests/startup.rs` and `tests/tls_only.rs` are acceptance targets only; change
them only if the host wiring needs a real observable.

Must not change:
- `src/storage/database.rs` (no schema change; stop and re-plan if one appears
  necessary)
- `src/metrics.rs` (no new instrument)
- `src/control_plane/scheduler/dispatch.rs` (pinned boundary stays narrow)
- `src/control_plane/scheduler/job.rs` and `store.rs` unless a drain fix
  strictly requires a read helper; prefer none
- `src/api/routes.rs` and `src/api/jobs.rs` (no new route or API behavior)
- `Cargo.toml`, `Cargo.lock`, `fuzz/Cargo.toml`, `fuzz/fuzz_targets/*`

## Residuals to keep documenting

- Per-run cancellation is still not implemented: no cancel route, no
  cancellation failure code/state, and no worker cancellation channel. Drain
  only bounds host shutdown; it does not cancel an individual run.
- A crash or SIGKILL still leaves `running` rows for startup recovery to mark
  `interrupted`; interrupted runs are not replayed in this slice.
- Queued rows (including queued retries) survive drain and dispatch on the next
  start; drain does not refuse them.
- A retry insert already in progress inside `dispatch_claimed` can still commit
  during drain; it is part of the in-flight task being waited on.
- The existing claim/disable race remains: a run claimed before disable can
  still finish.
- Drain does not change the global queue bound, retry policy, jitter absence,
  single-process ownership, retention, artifact GC, or timezone limits.
- A loop panic or tick failure still flips readiness false; drain does not
  repair a failed loop.
- Host shutdown is bounded by HTTP graceful shutdown plus the scheduler drain
  window; a worker that ignores termination is aborted by the existing
  executor process-group teardown.

## New-session prompt

Paste this into a fresh session:

```text
Work in /home/nnadolski/projects/job-scheduler.

You are picking up Conductor after Scheduler slice 4. Read
docs/handover-scheduler-slice-5.md first; it is the authoritative handover.
The base is the tip of feat/scheduler-slice-4 (slice 4 code at b441710; this
handover is on the tip), or main if slice 4 merged. Create
feat/scheduler-slice-5 from that base.

Implement Scheduler slice 5: bounded graceful drain on host shutdown.
- Add SchedulerConfig::drain_timeout (default 30s) and SchedulerService::drain().
- Drain stops claiming, clears readiness, waits up to drain_timeout for
  already-claimed dispatch tasks, then aborts the remainder.
- Finished in-flight runs write normal terminal completions; queued rows stay
  queued for the next start.
- Call drain() from Host::serve_with_handle instead of stop(); keep stop() as
  the immediate-abort test/administration path.
- Reuse SchedulerState::Stopping; no new state, route, metric, or schema.

Do not implement per-run cancellation, a cancel route or new failure code,
worker cancellation channels, interrupted-run replay, drain on disable,
per-job/API retry policy, jitter, distributed scheduling, retention, artifact GC,
operator CLI, lifecycle transitions, timezone/DST, seconds/7-field cron,
macros, symbolic names, idempotency keys, new routes, new job-run states, or new
metrics.

Use the project orchestration workflow in docs/agent-workflow.md: poteto-agent
for code-writing, poteto-judge for independent read-only verification, security
for the shutdown/drain/claim boundary review, and load the deslop skill for the
final diff. Run the acceptance commands in the handover and report raw command
results. Do not run mutation; it is a final-feature gate. If a schema change
seems necessary, stop and re-plan instead of editing v3.

Return: what changed, files touched, commands + results, verification table,
security/residual risks, and the next task.
```
