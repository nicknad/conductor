# Handover: Scheduler slice 6 (per-run cancellation)

Base: `feat/scheduler-slice-5` tip (slice 5 code at `5787bd9`; this handover is
on the tip). Slice 5 is implemented and green. This handover is the starting
point for Scheduler slice 6 (per-run cancellation).

## What slice 5 proved

- `SchedulerConfig::drain_timeout` defaults to 30 s. `SchedulerService::drain()`
  reuses `SchedulerState::Stopping`, clears readiness at entry, wakes the loop,
  and waits on the loop handle with a `drain_timeout + 5 s` safety bound.
- `stop()` remains the immediate-abort path. It shares only the shutdown
  preamble (`begin_shutdown`) with `drain()`; it does not use the drain window.
- `run_loop` waits on its `JoinSet` for at most `drain_timeout` when the state is
  `Stopping`, preserves dispatch-task panic handling, logs `completed` and
  `remaining`, and always ends with `join_set.shutdown().await`.
- `fill_slots` re-checks `SchedulerState::Running` before each new claim. A
  claim transaction already in flight when drain starts can still commit; that
  run is included in the drain window. Queued rows are not refused and survive
  the shutdown.
- A run that finishes inside the window writes its normal terminal completion,
  including a retry insert. A task still running at the deadline is aborted and
  its row stays `running` until startup recovery marks it `interrupted`.
- `Host::serve_with_handle` calls `scheduler.drain()` after HTTP serving ends,
  after the readiness watcher is aborted, and before metrics shutdown. The HTTP
  graceful-shutdown bound and the scheduler drain bound are separate, so a
  worst-case shutdown is their sum.
- No schema, route, metric, job-run state, scheduler state, or dependency was
  added. Readiness is false before the finish window starts, and `LoopGuard`
  only ever clears the scheduler flag.
- Slice 5 gates at `5787bd9`: 58 `cargo test --lib scheduler`, 21
  `scheduler_service`, 20 `scheduler_api`, 4 `startup`, 4 `tls_only`, 614 total
  tests, test-quality 614/68, fuzz format/clippy/check, and clippy `-D warnings`.
- Slice 5 deliberately did not implement per-run cancellation, a cancel route or
  failure code, worker cancellation channels, interrupted-run replay, drain on
  disable, per-job/API retry policy, jitter, distributed scheduling, retention,
  artifact GC, operator CLI, lifecycle transitions, timezone/DST, seconds/7-field
  cron, macros, symbolic names, or idempotency keys.

## Slice 6 goal

Implement authenticated per-run cancellation for queued and running job runs:

1. Add `POST /v1/jobs/{job_id}/runs/{run_id}/cancel`, bearer-authenticated like
   the existing job routes and with no request body.
2. Cancelling a `queued` row is one durable transaction: the row becomes
   terminal immediately, is never claimed, and no execution history row is
   created.
3. Cancelling a `running` row sends a reason through the existing executor
   cancellation channel, terminates the worker process group, and lets the
   normal dispatch path write one terminal completion with `state="failed"` and
   `outcome="cancelled"` plus the execution history receipt.
4. Cancelled runs never enqueue a retry. Cancelling a run does not change the
   job's `enabled` flag or `next_run_at`, and does not cancel any other run.
5. Reuse the existing terminal vocabulary. Do not add a `cancelled` job-run
   state or failure code; adding either would require a schema change.

## Non-goals for slice 6

Do not implement:

- a new `JobRunState::Cancelled` variant, `JobFailureCode::Cancelled`, a new
  `job_runs.state` value, a new `failure_code` value, or any schema migration;
- job-level or bulk cancellation, a cancel-all route, or cancellation on
  disable/stop/drain;
- idempotent cancel requests, pending-cancel state, or replay of cancel intent
  across restart;
- interrupted-run replay or a pending-retry/pending-run state;
- per-job/API retry policy, jitter, or retry-policy changes;
- distributed scheduling, lease takeover, retention, artifact GC, operator CLI,
  lifecycle transitions, timezone/DST, seconds/7-field cron, macros, symbolic
  names, or idempotency keys;
- new scheduler metrics or a new `/metrics` surface;
- a worker cancellation channel that bypasses `ExecutionService` or the pinned
  dispatcher boundary.

## Decisions to carry forward

- **Cancellation is terminal `failed`/`cancelled`.** A queued cancellation
  writes `state="failed", outcome="cancelled"` with no `execution_id`; a running
  cancellation writes the same pair with the real `execution_id` and history
  receipt. `is_retryable_completion` already excludes `cancelled`, so no retry
  is scheduled. A first-class cancelled state is a later v4 migration.
- **Running cancellation uses the executor channel, not task abort.** Sending
  through `WorkerExecutor::execute_cancellable` preserves the normal terminal
  write and history row. Aborting the dispatch task would leave the row
  `running` until startup recovery and lose the terminal write.
- **The store decides queued versus running in one transaction.** A row that is
  still `queued` is terminalized atomically; a row that is `running` is reported
  to the service without mutation so the dispatch task remains the single
  writer.
- **Cancellation senders are keyed by `run_id`.** `SchedulerService` keeps a
  bounded registry of `oneshot::Sender<String>` entries while dispatch tasks are
  in flight. An RAII guard removes the entry on normal completion, panic, drain
  abort, or stop abort.
- **A claim-to-register gap returns conflict.** If the store reports `running`
  but no sender is registered yet, return `409 run_not_cancellable`. Do not add
  a durable pending-cancel flag just to close a microsecond window.
- **No cancel on shutdown.** Drain and stop keep their existing semantics.
  Cancellation is an explicit authenticated request; it is not a shutdown
  mechanism.
- **The route is pinned and bounded.** Both path identities use
  `is_safe_identity` and the existing run/job byte bounds. There is no body, no
  reason supplied by the caller, and no new metric label.

## Implementation steps

### 1. Thread cancellation through the execution service

In `src/control_plane/execute_module.rs`:

- Keep the public `ExecutionService::execute(...)` signature and make it
  delegate to a new `pub async fn execute_cancellable(..., cancel:
  Option<tokio::sync::oneshot::Receiver<String>>)` with `None`.
- Thread `cancel` through the private `execute_inner` into
  `WorkerExecutor::execute_cancellable`. Preserve the existing refusal and
  integrity metric classification so errors are recorded exactly once.
- Do not change preparation, permit lifetime, deadline, or history-write
  ordering. Cancellation is observed by the worker exchange after preparation;
  a cancel during blocking preparation is observed when the executor starts.

In `src/control_plane/scheduler/dispatch.rs`:

- Add `execute_cancellable` that pins `Some(version)` exactly like `execute` and
  forwards the optional receiver. Keep `execute` as the no-cancel wrapper.

### 2. Make the store's cancel decision atomic

In `src/control_plane/scheduler/store.rs` add one `pub(crate)` transaction
method, for example:

```rust
pub(crate) enum RunCancel {
    Queued(JobRun),
    Running,
    Terminal(JobRun),
    NotFound,
}

pub(crate) fn request_run_cancel(
    &self,
    job_id: &str,
    run_id: &str,
    now: SystemTime,
) -> Result<RunCancel, JobStoreError>
```

- Read the row by `run_id` and require the stored `job_id` to match.
- If `state = 'queued'`, update it in the same transaction to
  `state='failed', outcome='cancelled', finished_at=?`, then return the updated
  row as `Queued`.
- If `state = 'running'`, return `Running` without writing.
- If the row is terminal, return `Terminal(row)`; if missing, return `NotFound`.
- Reuse `row_to_run`/existing validation. Do not add a schema value, a new
  failure code, or a new state.

### 3. Add service cancellation and the sender registry

In `src/control_plane/scheduler/service.rs`:

- Add `cancellations: Mutex<HashMap<String, tokio::sync::oneshot::Sender<String>>>`
  to `SchedulerService`. Use the existing poisoned-mutex recovery pattern.
- Add an RAII registration guard keyed by `run_id` that removes the sender when
  the dispatch task completes or is aborted.
- In `fill_slots`, create a `oneshot::channel` for each claimed run, register the
  sender, and pass the receiver into `dispatch_claimed`. `tick_once` may pass
  `None` because it is a test-only synchronous facade.
- Extend `dispatch_claimed(..., cancel: Option<oneshot::Receiver<String>>)` to
  call the dispatcher's cancellable method. The existing `ExecutionOutcome::
  Cancelled` arm already maps to `RunCompletion::worker_failure(..., "cancelled")`,
  which writes the normal terminal row and skips retries.
- Add `pub async fn cancel_run(&self, job_id: &str, run_id: &str) ->
  Result<CancelResult, SchedulerError>`:
  - call `request_run_cancel`;
  - return the queued row immediately for `Queued`;
  - for `Running`, look up the sender by `run_id`, send a fixed reason such as
    `"cancel requested"`, and return the current run snapshot (use a read helper
    if needed);
  - map `Terminal` and a missing sender to a not-cancellable error, and
    `NotFound` to a not-found error;
  - never abort the `JoinSet` task and never write a running row from this path.
- Define `CancelResult`/mapping so the API can distinguish a queued terminal row,
  an accepted running cancellation, not found, and not cancellable. Add the
  matching `SchedulerError` variants needed by the handler.

### 4. Add the authenticated cancel route

- In `src/api/mod.rs` add
  `JOB_RUN_CANCEL_PATH: &str = "/v1/jobs/{job_id}/runs/{run_id}/cancel";`.
- In `src/api/routes.rs` add a `post(post_cancel_run)` route with the same
  `require_bearer` layer as the other job write routes. No body limit is needed.
- In `src/api/jobs.rs` add `post_cancel_run` taking
  `Path<(String, String)>`, validate both identities with `is_safe_identity`
  and their existing byte bounds, then call `SchedulerService::cancel_run`.
- Return `202 Accepted` with the existing `RunResponse` shape for a durable
  queued cancellation or an accepted running cancel request. Add stable
  `404 run_not_found` and `409 run_not_cancellable` errors; keep
  `503 scheduler_unavailable` for a stopped scheduler.
- Do not change `next_run_at`, `enabled`, job rows, trigger boundaries, or the
  runs listing response shape.

### 5. Update docs

Update `README.md`, `docs/observability.md`, `docs/architecture.md`, and
`docs/statecharts.md` to describe:

- the cancel route and its response/error contract;
- queued versus running cancellation;
- cancelled as terminal `failed`/`cancelled`, with no retry and no new state;
- the executor cancellation channel and process-group teardown;
- the claim-to-register `409` residual;
- no new metric/state/schema and the still-missing interrupted-run replay.

Update `tests/security/openapi.yaml` with the new path and response shapes.

## Test plan

- Store unit tests:
  - a queued row becomes `failed`/`cancelled`, gains `finished_at`, and is never
    claimable or retryable;
  - a running row returns `Running` and is not mutated by the lookup;
  - missing, wrong-job, and terminal rows return the expected variants.
- `tests/scheduler_service.rs`:
  - cancel a queued run before claim: no dispatch, no retry, row terminal;
  - cancel a running slow worker: the executor reports cancelled, the worker is
    terminated, the row is `failed`/`cancelled` with an execution id, and no
    retry row appears;
  - cancellation does not change `enabled` or `next_run_at`;
  - terminal and unknown runs return the not-cancellable/not-found path;
  - a second cancel after terminal completion is rejected.
- `tests/scheduler_api.rs`:
  - the cancel route requires bearer authentication;
  - authenticated queued cancel returns `202` and the run row is terminal;
  - authenticated running cancel returns `202` and eventually records
    `failed`/`cancelled`;
  - terminal/missing/invalid-identity cases map to stable errors;
  - existing trigger/enable/disable/run-list behavior stays unchanged.
- `tests/execution_service.rs`:
  - cancellation through `ExecutionService::execute_cancellable` reaches the
    worker, writes one `cancelled` history receipt, and releases capacity.
- Keep all existing scheduler, startup, TLS, execution, and full-suite tests
  green. Keep new tests under roughly 2 s each and do not blanket-serialize.

## Acceptance commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --lib scheduler
cargo test --test scheduler_service
cargo test --test scheduler_api
cargo test --test execution_service
cargo test --test execution_worker
cargo test --test startup
cargo test --test tls_only
cargo test
python3 scripts/check_test_quality.py
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --bins -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Run `cargo deny check` only if `Cargo.toml` or `Cargo.lock` changes. Do not run
`cargo mutants` during the slice; mutation is a final-feature gate.

## Exact file list for slice 6

Production:
- `src/control_plane/execute_module.rs`
- `src/control_plane/scheduler/dispatch.rs`
- `src/control_plane/scheduler/job.rs` (only a `RunCompletion::cancelled` helper if needed)
- `src/control_plane/scheduler/service.rs`
- `src/control_plane/scheduler/store.rs`
- `src/api/jobs.rs`
- `src/api/mod.rs`
- `src/api/routes.rs`

Tests:
- `tests/scheduler_service.rs`
- `tests/scheduler_api.rs`
- `tests/execution_service.rs`
- `tests/security/openapi.yaml`

Docs:
- `README.md`
- `docs/observability.md`
- `docs/architecture.md`
- `docs/statecharts.md`

Must not change:
- `src/storage/database.rs` (no schema change; stop and re-plan a v4 migration if
  a first-class cancelled state or failure code appears necessary)
- `src/metrics.rs` (no new instrument)
- `Cargo.toml`, `Cargo.lock`, `fuzz/Cargo.toml`, `fuzz/fuzz_targets/*`

## Residuals to keep documenting

- Cancellation is recorded as `failed` with outcome `cancelled`, not a
  first-class cancelled state. Clients must read both fields.
- There is no durable pending-cancel marker. A cancel racing the claim-to-sender
  registration can return `409 run_not_cancellable`; the caller may retry.
- Cancellation during blocking preparation is observed only when the worker
  exchange starts; preparation itself is not interrupted.
- Queued cancellation has no execution history row because no worker ran.
- Cancel is per run, not per job: queued retries of the same job are separate
  runs and disable remains the job-level kill-switch.
- Drain and stop do not cancel individual runs; drain still waits and then
  aborts the remainder.
- A crash or SIGKILL still leaves `running` rows for startup recovery to mark
  `interrupted`, and interrupted runs are still not replayed.
- The executor's process-group teardown is best-effort for a worker that escapes
  its process group.
- Single-process ownership, the global queue bound, retry policy, no jitter,
  retention, artifact GC, timezone/DST, and operator CLI limits are unchanged.

## New-session prompt

Paste this into a fresh session:

```text
Work in /home/nnadolski/projects/job-scheduler.

You are picking up Conductor after Scheduler slice 5. Read
docs/handover-scheduler-slice-6.md first; it is the authoritative handover. The
base is the tip of feat/scheduler-slice-5 (slice 5 code at 5787bd9; this
handover is on the tip), or main if slice 5 merged. Create
feat/scheduler-slice-6 from that base.

Implement Scheduler slice 6: per-run cancellation.
- Add POST /v1/jobs/{job_id}/runs/{run_id}/cancel, bearer-authenticated, no
  request body.
- Cancel queued rows atomically to failed/cancelled; cancel running rows through
  the existing executor cancellation channel so the worker group is terminated
  and the normal terminal write plus history receipt are preserved.
- Add the dispatcher/ExecutionService cancellable path and the run_id-keyed
  sender registry; use an RAII guard so stop/drain abort does not leak entries.
- Cancelled runs never retry and do not change job enabled/next_run_at.
- Reuse failed/cancelled; do not add a new job-run state, failure code, or
  schema. Return 404 run_not_found and 409 run_not_cancellable for the
  non-cancellable cases.

Do not implement job-level or bulk cancellation, cancellation on disable/stop/
drain, idempotent cancel requests, pending-cancel state, interrupted-run replay,
per-job/API retry policy, jitter, distributed scheduling, retention, artifact GC,
operator CLI, lifecycle transitions, timezone/DST, seconds/7-field cron, macros,
symbolic names, idempotency keys, new job-run states, new routes beyond the
cancel route, or new metrics.

Use the project orchestration workflow in docs/agent-workflow.md: poteto-agent
for code-writing, poteto-judge for independent read-only verification, security
for the authenticated cancellation route and worker-teardown boundary review,
and load the deslop skill for the final diff. Run the acceptance commands in the
handover and report raw command results. Do not run mutation; it is a
final-feature gate. If a schema change seems necessary, stop and re-plan a v4
migration instead of editing v3.

Return: what changed, files touched, commands + results, verification table,
security/residual risks, and the next task.
```
