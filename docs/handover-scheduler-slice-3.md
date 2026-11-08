# Handover: Scheduler slice 3 (cron triggers)

Base: `feat/scheduler-slice-2` tip (slice 2 code at `90908cf`; this handover is
on the branch tip). Slice 2 is implemented and green. This handover is the
starting point for Scheduler slice 3 (UTC cron triggers).

## What slice 2 proved

- Schema v3 already has every column and index cron needs:
  `jobs.cron_expr`, `jobs.timezone` (fixed `UTC`), `jobs.next_run_at`, and
  `idx_job_runs_tick` on
  `(job_id, trigger_kind, scheduled_for, attempt_no)` for `interval`/`cron`.
  No schema migration is needed for slice 3.
- `src/control_plane/scheduler/job.rs` already has `Trigger::Cron`,
  `TriggerKind::Cron`, `cron_expr()`, and interval bounds/math. The cron branch
  of `validate_new_job` currently checks only non-empty/bounded syntax; it does
  not parse or evaluate cron.
- `src/control_plane/scheduler/store.rs` persists `cron_expr`, validates the
  trigger/field cross-checks in `row_to_job`, and enforces the queue bound in
  `enqueue_manual_run` and the due path. `enqueue_due_runs` is interval-only
  today: it selects `trigger_kind='interval'`, inserts
  `trigger_kind='interval'`, and advances with `advance_interval_due`.
  `DueEnqueueReport { enqueued, deduped, skipped_full }` is returned from one
  immediate transaction.
- `src/control_plane/scheduler/service.rs` has the single loop. `tick_once`
  and `fill_slots` call `enqueue_due(now)` before claiming, increment
  `conductor.job.queue.depth` by `enqueued`, and log bounded counts. Dispatch
  remains pinned through `ExecutionDispatcher -> ExecutionService::execute`.
- `src/api/jobs.rs` accepts manual and interval triggers. Cron is still
  rejected with `400 invalid_trigger`. `post_job` and `post_enable` compute
  `next_run_at = now + interval_secs` for interval jobs and `None` for manual.
- Slice 2 tests prove interval bounds, create/enable/disable semantics, due
  enqueue/advance, duplicate-tick dedupe, restart catch-up, queue-full retry,
  queue-depth movement, and the source-boundary guard. Current gates are green:
  336 lib tests, 9 `scheduler_service` tests, 14 `scheduler_api` tests, 561
  total tests, plus the fuzz format/clippy/check gates.
- Slice 2 deliberately did not implement cron, retries, cancellation/drain,
  distributed scheduling, retention, operator CLI, lifecycle transitions, or
  timezone/DST handling.

Slice 2 file inventory: `README.md`, `docs/architecture.md`,
`docs/observability.md`, `docs/statecharts.md`, `src/api/jobs.rs`,
`src/control_plane/scheduler/{job,service,store}.rs`,
`tests/scheduler_api.rs`, and `tests/scheduler_service.rs`. Slice 2 added the
interval math/validation unit tests, the due-enqueue/dedupe/queue-bound store
tests, the tick/queue-depth/catch-up service tests, and the API create/bounds/
enable/disable/manual-on-interval tests. There is no schema, `Cargo.toml`, fuzz
target, or route change in slice 2.

## Slice 3 goal

Implement bounded UTC cron triggers end to end:

1. Accept `{"trigger":{"kind":"cron","expression":"<5-field cron>"}}` on
   create.
2. Persist `next_run_at` for enabled cron jobs as the first matching UTC
   occurrence strictly after `now`; recompute it on enable and clear it on
   disable.
3. Enqueue due cron runs from the same single loop, with
   `trigger_kind='cron'` and `scheduled_for=jobs.next_run_at`.
4. Advance `next_run_at` to the first matching occurrence strictly after
   `now`, so a restart enqueues one missed run, not a burst.
5. Reuse the existing partial unique index for duplicate-tick protection, the
   global queue bound, the disable kill-switch, readiness ownership, and job
   metrics.
6. Dispatch every run through the existing pinned execution path.

## Non-goals for slice 3

Do not implement:

- retries, attempt policies, or backoff;
- cancellation, drain, or lifecycle deactivate/remove/rollback;
- distributed scheduling or a multi-process ownership lock;
- artifact GC, execution/job retention, or operator CLI;
- timezone selection, DST handling, or any timezone other than UTC;
- seconds/6-field/7-field cron, `@daily`-style macros, symbolic month/day
  names, `?`, `L`, `W`, or `#` extensions;
- idempotency keys for manual triggers;
- per-job authorization or a new job-run state;
- a new cron-lag metric. Use the existing queue/wait/active instruments and
  bounded debug logs.

## Decisions to carry forward

- **No schema migration.** v3 already has `cron_expr`, `timezone`,
  `next_run_at`, and the tick index. Do not edit shipped migrations. If cron
  evaluation appears to need a schema change, stop and re-plan instead of
  editing v3.
- **Cron grammar is closed and UTC-only.** Accept exactly five
  whitespace-separated fields: minute `0-59`, hour `0-23`, day-of-month
  `1-31`, month `1-12`, day-of-week `0-7` (0 and 7 are Sunday). Allow `*`,
  numbers, ranges `a-b`, lists `a,b`, and steps `*/n` or `a-b/n`. Reject
  names, macros, `?`, `L`, `W`, `#`, seconds, and 6/7-field expressions even
  if the parser crate accepts them.
- **DOM/DOW semantics are POSIX/Vixie-style OR.** When both day-of-month and
  day-of-week are restricted, a time matches if either matches. When one is
  `*`, the other controls. Test this explicitly; do not inherit a crate
  behavior silently if it differs.
- **Use a narrow parser wrapper, not a hand-written calendar engine.** Add
  `croner = "4.0.3"` (MIT) to `Cargo.toml` and keep it behind a private
  `src/control_plane/scheduler/cron.rs` module. Validate the closed 5-field
  grammar before calling croner. Do not expose croner/chrono types outside
  that module. Run `cargo deny check`; if the dependency fails license or
  advisory policy, stop and implement a bounded in-repo evaluator instead of
  weakening `deny.toml`.
- **First run is the next occurrence, not an immediate run.** On create and
  enable, `next_run_at = next_cron_at(expression, now)`; the result must be
  strictly after `now`. A disabled job has `next_run_at = NULL`.
- **Due tick policy is the same as interval.** For each due cron job,
  `scheduled_for = jobs.next_run_at`, insert one queued run with
  `trigger_kind='cron'`, then advance `next_run_at` to
  `next_cron_at(expression, now)`. This is the restart catch-up policy: one
  missed occurrence, not every missed occurrence.
- **Queue full leaves the due time unchanged.** Count `skipped_full` and
  retry on a later tick. Do not drop the boundary or enqueue a partial burst.
- **Dedupe via `idx_job_runs_tick`.** Use `INSERT OR IGNORE`. If the insert is
  ignored, count `deduped` and still advance `next_run_at`; never create a
  second run for the same `(job_id, 'cron', scheduled_for, 1)` boundary. The
  boundary advance is the normal dedupe; the index is the backstop.
- **Invalid/tampered cron rows must not fail the loop.** Validate cron syntax
  in `validate_new_job` and on row read, but in the due path parse the
  persisted expression defensively. If it is unparseable or has no
  representable occurrence, count `skipped_invalid` and skip the row; do not
  enqueue a run, do not advance the boundary, and do not return an error that
  flips readiness false.
- **Manual trigger remains allowed.** An enabled cron job can still be
  triggered manually; that run records `trigger_kind='manual'` and does not
  change `next_run_at`.
- **Enable/disable semantics are unchanged.** Enable recomputes
  `next_run_at` for cron; disable clears it and terminalizes queued runs as
  `refused`/`job_disabled`.
- **Dispatch stays pinned.** Do not add activation, registry, artifact,
  staging, worker-spawn, or `active_versions` access to the scheduler. Every
  cron run goes through `ExecutionDispatcher -> ExecutionService::execute`
  with the job's pinned version.
- **No new metric is required.** `conductor.job.wait.duration`,
  `conductor.job.queue.depth`, and `conductor.job.active` remain the job
  signals. Extend the due-enqueue debug log with bounded
  `enqueued`/`deduped`/`skipped_full`/`skipped_invalid` counts. Never log
  payloads.

## Implementation steps

### 1. Add the cron wrapper

Create `src/control_plane/scheduler/cron.rs` and declare it privately from
`src/control_plane/scheduler/mod.rs`.

Add:

- `pub(crate) fn validate_cron_expr(expression: &str) -> Result<(), CronError>`:
  reject empty/oversized input (the existing 256-byte bound remains), reject
  anything other than exactly five fields, enforce the closed character set and
  field ranges, then parse with croner. This is syntax/range validation only;
  it has no clock and does not prove the expression ever fires.
- `pub(crate) fn next_cron_at(expression: &str, after: SystemTime) -> Option<SystemTime>`:
  return the first matching occurrence strictly after `after` in UTC. Convert
  through `chrono::DateTime<Utc>` inside this module only. Return `None` for
  invalid/impossible expressions or a result outside a bounded horizon.
- `pub(crate) fn advance_cron_due(scheduled_for: SystemTime, expression: &str, now: SystemTime) -> Option<SystemTime>`:
  return `scheduled_for` when it is still in the future; otherwise return
  `next_cron_at(expression, now)`.

Bound impossible-expression searches in `next_cron_at`. Require the next
occurrence to be within a bounded horizon (for example, ten years from `after`)
and return `None` for `0 0 31 2 *` and similar expressions rather than letting a
parser scan indefinitely. The API maps this `None` to `400 invalid_trigger` at
create/enable; the due path maps it to `skipped_invalid`. Add unit tests in this
module for every grammar and boundary case listed below.

### 2. Generalize job validation and next-run selection

In `src/control_plane/scheduler/job.rs`:

- In the `Trigger::Cron` branch of `validate_new_job`, call
  `cron::validate_cron_expr(expression)` and preserve the existing
  enabled-requires-`next_run_at` and disabled-must-not rule.
- Add `pub fn next_run_at(trigger: &Trigger, now: SystemTime) -> Option<SystemTime>`
  that returns:
  - `None` for `Trigger::Manual`;
  - `next_interval_at(now, interval_secs)` for interval;
  - `cron::next_cron_at(expression, now)` for cron.
  Use this one helper from the API and service tests so interval/cron scheduling
  policy is not duplicated.
- Keep `advance_interval_due` and its existing tests. Add cron-specific unit
  tests either in `job.rs` (for `next_run_at`) or in `cron.rs` (for the
  parser/evaluator).

### 3. Extend the store due-enqueue path

In `src/control_plane/scheduler/store.rs`:

- Add `skipped_invalid: usize` to `DueEnqueueReport` and update its
  construction sites/tests.
- Extend `enqueue_due_runs` to process both trigger kinds in one immediate
  transaction. Use one SELECT:
  `job_id, trigger_kind, interval_secs, cron_expr, next_run_at` from enabled
  jobs where `trigger_kind IN ('interval','cron')`,
  `next_run_at IS NOT NULL`, `next_run_at <= now`, and
  `((trigger_kind='interval' AND interval_secs BETWEEN MIN_INTERVAL_SECS AND MAX_INTERVAL_SECS)
  OR (trigger_kind='cron' AND cron_expr IS NOT NULL))`.
  The OR shape is required: a bare interval range predicate would also filter
  out every cron row. Order by `next_run_at, job_id`.
- For each due row, compute the next boundary before inserting:
  - interval: `advance_interval_due(...)`;
  - cron: `advance_cron_due(...)`, requiring a non-null `cron_expr`.
  If the expression is invalid/impossible and the next boundary is `None`,
  increment `skipped_invalid` and `continue` without inserting or advancing.
  Surface the count only in the single due-enqueue debug log; do not emit a
  per-row info/warn line that can flood under a tampered or repeating row.
- Apply the global queue bound exactly once per pass, using the shared local
  `queued` counter. A full queue increments `skipped_full` and leaves
  `next_run_at` unchanged.
- Insert `trigger_kind` from the row (`'interval'` or `'cron'`), `attempt_no=1`,
  `scheduled_for=jobs.next_run_at`, `state='queued'`, `created_at=now`.
- Update `jobs.next_run_at` to the computed boundary and `updated_at=now` after
  every attempted insert, including an ignored/deduped insert.
- In `row_to_job`, validate cron expressions with
  `cron::validate_cron_expr` so a tampered row fails closed on reads. Keep the
  existing trigger/field cross-checks.
- Keep `create_job` calling `validate_new_job`; the store remains the final
  syntax authority.

### 4. Wire the service and API

In `src/control_plane/scheduler/service.rs`, keep `enqueue_due` as the single
spawn-blocking wrapper. Extend its debug log with `skipped_invalid`; still
increment `conductor.job.queue.depth` by `report.enqueued`. Do not change
`tick_once`'s return value or the production `Running` gate.

In `src/api/jobs.rs`:

- `validate_create` accepts `TriggerRequest::Cron` after
  `cron::validate_cron_expr`; update the `invalid_trigger` message to say
  interval and cron are supported while other trigger shapes are not.
- `post_job` uses one `now` for `created_at` and `next_run_at(trigger, now)`.
  For an enabled cron job, if the computed next occurrence is `None`, return
  `400 invalid_trigger`; disabled jobs pass `None`.
- `post_enable` reads the job, computes `next_run_at(&job.trigger, now)`, and
  passes it to `set_enabled`. A cron job with no computable next occurrence
  returns `400 invalid_trigger` (do not flip the scheduler to failed).
- Keep manual and interval behavior unchanged.

### 5. Update docs and the DAST spec

Update `README.md`, `docs/observability.md`, `docs/architecture.md`, and
`docs/statecharts.md` to say cron is implemented with the closed 5-field UTC
grammar, the same queue/dedupe/catch-up rules, and the remaining non-goals.

Update `tests/security/openapi.yaml` so the create-job trigger schema describes
the interval and cron shapes; this is documentation for DAST, not a new fuzz
target. The existing `fuzz/fuzz_targets/http_jobs.rs` already sends
authenticated arbitrary bodies and does not need a new target.

## Test plan

Add coverage at the layer that can fail independently:

- Cron parser unit tests:
  - `* * * * *`, `*/5 * * * *`, `0 0 * * *`, lists, ranges, and steps;
  - minute `60`, hour `24`, DOM `0`/`32`, month `0`/`13`, DOW `8` -> invalid;
  - 4 fields, 6 fields, `@daily`, names, `?`, `L`, `W`, `#` -> invalid;
  - DOM/DOW OR behavior (for example `0 0 1 * 1`);
  - leap-day expression and a non-leap year;
  - impossible expression `0 0 31 2 *` -> `None`, not a hang;
  - `next_cron_at` is strictly after `now`, including when `now` is exactly on
    a boundary and when `now` has sub-second precision;
  - a still-future `advance_cron_due` boundary is returned unchanged.
- Store tests:
  - one due cron job enqueues exactly one queued run with
    `trigger_kind='cron'`, `scheduled_for=old next_run_at`, and advances to the
    first occurrence after `now`;
  - a second tick at the same `now` creates no second run;
  - restart catch-up with a boundary several occurrences in the past creates
    one run at the original `scheduled_for`, not a burst;
  - disabled cron job is not selected;
  - full queue leaves `next_run_at` unchanged and creates no run;
  - a tampered/unparseable cron row returns `skipped_invalid`, creates no run,
    does not fail the pass, and leaves the boundary unchanged;
  - mixed interval and cron jobs both due: `ORDER BY next_run_at, job_id` is
    deterministic, the shared `max_queued_runs` bound holds across both kinds,
    and the local queued counter is exercised.
- Service tests:
  - `tick_once` enqueues and dispatches one due cron run through the pinned
    refusal path with an unregistered module;
  - queue depth moves by `enqueued` (capacity-zero test pattern from slice 2);
  - disabled cron job is not enqueued;
  - a manual trigger on an enabled cron job records a manual run and leaves
    `next_run_at` unchanged.
- API tests:
  - create cron -> `201`, `trigger.kind == "cron"`, `next_run_at_ms` in the
    future and within the expression's next period;
  - invalid/out-of-range cron -> `400 invalid_trigger`;
  - disabled cron create -> `201` with `next_run_at_ms == null`;
  - disable clears and enable recomputes the cron boundary;
  - manual trigger on an enabled cron job keeps the cron boundary;
  - existing manual/interval tests and the source-boundary guard stay green.
- Keep the test-quality rules: every test asserts a real observable, no
  tautologies, no duplicate bodies, and at most one true end-to-end success
  test for the slice.

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
cargo deny check
```

Run `cargo deny check` because slice 3 adds a parsing dependency. The fuzz
workspace has its own `Cargo.lock`; the fuzz commands may update
`fuzz/Cargo.lock` when the new dependency resolves. Do not add a new fuzz
target.

## Exact file list for slice 3

Production:
- `src/control_plane/scheduler/cron.rs` (new parser/evaluator wrapper)
- `src/control_plane/scheduler/mod.rs` (declare the private cron module)
- `src/control_plane/scheduler/job.rs` (`validate_new_job`, `next_run_at`)
- `src/control_plane/scheduler/store.rs` (`DueEnqueueReport`,
  `enqueue_due_runs`, `row_to_job`)
- `src/control_plane/scheduler/service.rs` (debug log only unless a helper is
  needed)
- `src/api/jobs.rs` (`validate_create`, `post_job`, `post_enable`)
- `Cargo.toml`, `Cargo.lock` for `croner`/its chrono dependency

Tests:
- `src/control_plane/scheduler/cron.rs` unit tests
- `src/control_plane/scheduler/job.rs` unit tests
- `src/control_plane/scheduler/store.rs` unit tests
- `tests/scheduler_service.rs`
- `tests/scheduler_api.rs`
- `tests/security/openapi.yaml` (describe the trigger shapes)

Docs:
- `README.md`
- `docs/observability.md`
- `docs/architecture.md`
- `docs/statecharts.md`

Must not change:
- `src/storage/database.rs` (v3 already supports cron; stop and re-plan if a
  schema change appears necessary)
- `src/metrics.rs` (no new instrument)
- `src/control_plane/scheduler/dispatch.rs` (the pinned boundary must stay
  narrow)
- `fuzz/Cargo.toml` and `fuzz/fuzz_targets/*` (no new target)
- `src/api/routes.rs` (no new route)

Potential lockfile change: `fuzz/Cargo.lock` when the fuzz workspace resolves the
new crate. That is expected, not a target change.

Working-tree note: the slice 2 handoff leaves an unrelated
`docs/agent-workflow.md` edit and an untracked `.opencode/skills/slice-handoff/`
directory. Do not fold either into slice 3.

## Residuals to keep documenting

- At-most-once dispatch; no retries and no replay after a crash.
- Cron catch-up enqueues one missed occurrence at its original `scheduled_for`;
  `conductor.job.wait.duration` can therefore be large after a long outage.
- UTC only; no timezone selection, DST handling, seconds, 7-field expressions,
  names, macros, `?`, `L`, `W`, or `#`.
- Single-process only; no distributed lock. A second scheduler instance would
  race the same durable queue.
- No job/run retention or artifact GC; a one-minute cron job grows history and
  artifact usage indefinitely.
- Invalid/tampered cron rows are skipped and counted; that job does not run
  until the row or expression is repaired. Reads of such a row fail closed.
- A full queue can delay or starve cron if interval jobs keep it saturated; due
  order is deterministic (`next_run_at`, then `job_id`).
- Pinned jobs are not revoked by activation/rollback.
- Job payloads are plaintext at rest.
- No cron-lag metric; use the due-enqueue debug counts and SQL until a later
  observability slice.
- A loop panic/tick failure flips readiness false; in-flight rows remain
  `running` until restart recovery marks them `interrupted`.

## New-session prompt

Paste this into a fresh session:

```text
Work in /home/nnadolski/projects/job-scheduler.

You are picking up Conductor after Scheduler slice 2. Read
docs/handover-scheduler-slice-3.md first; it is the authoritative handover.
The base is the tip of feat/scheduler-slice-2 (slice 2 code at 90908cf; this
handover is on the tip), or main if slice 2 merged. Create
feat/scheduler-slice-3 from that base.

Implement Scheduler slice 3: UTC cron triggers.
- Accept bounded 5-field cron expressions on job create within the documented
  grammar.
- Persist next_run_at as the first UTC occurrence after now; recompute on
  enable and clear on disable.
- Enqueue due cron runs from the same single loop with trigger_kind='cron',
  scheduled_for=jobs.next_run_at, and advance to the first occurrence after
  now.
- Enqueue at most one missed run after restart; dedupe repeated ticks with the
  existing partial unique index.
- Reuse the global queue bound, disable kill-switch, readiness, and job
  metrics. Invalid/tampered cron rows must be skipped, never fail the loop.
- Keep dispatch pinned through ExecutionService::execute; do not add
  activation/registry/artifact/worker access to the scheduler.

Do not implement retries, cancellation, drain, distributed scheduling,
artifact GC, retention, operator CLI, lifecycle transitions, timezone/DST,
seconds/7-field cron, macros, or symbolic names.

Use the project orchestration workflow in docs/agent-workflow.md: poteto-agent
for code-writing, poteto-judge for independent read-only verification, security
for the scheduler/trust-boundary review, and load the deslop skill for the
final diff. Run the acceptance commands in the handover and report raw command
results. If a schema change seems necessary, stop and re-plan instead of
editing v3.

Return: what changed, files touched, commands + results, verification table,
security/residual risks, and the next task.
```
