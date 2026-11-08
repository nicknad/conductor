# Next session context

Upload, validation, persistence, activation, execution, history, metrics,
readiness, classify-only startup reconciliation, and Scheduler slices 1-2 are
implemented. Slice 1 added durable manual jobs, manual triggers, queue/dispatch,
recovery, and job metrics. Slice 2 added bounded interval triggers, durable
`next_run_at` scheduling, due-tick enqueue with duplicate-tick protection,
restart catch-up, and the queue-bound retry path.

## Recommended: Scheduler slice 3 (cron triggers)

Start with [handover-scheduler-slice-3.md](handover-scheduler-slice-3.md).
Add bounded 5-field UTC cron triggers on the same durable queue: next-run
computation, due enqueue, duplicate-tick protection, restart catch-up, and the
existing pinned dispatcher. Defer retries, cancellation, drain, distributed
scheduling, retention, timezone/DST, and artifact GC.

## Small wins if scheduler is too large

### Execution-history retention/GC

The `executions` table has no retention policy (`src/storage/database.rs`,
`src/executions/history.rs`) and grows without bound. Pick an age or count
bound, delete in bounded batches, and document the operator-visible policy.
This is isolated from scheduler work.

### Disk-pressure preflight

Uploads accept bytes without checking free space, so a full disk surfaces as an
internal error mid-stream. Add a preflight before accepting an upload, define a
stable rejection code, and keep `conductor.storage.free.bytes` as the
observability signal. Touches `src/api/uploads.rs` and configuration.

### Per-module trust-key scope

Any trusted key can currently sign any module id: `TrustedSigningKey` has no
scope, and execution checks only the signer key id. Add a
key-to-allowed-modules (or runtime) mapping while trust state is still
restart-only configuration. This is small now; retrofitting after trust state is
persisted becomes migration work.

## Decide before artifact GC

Settle two storage decisions before GC or retention encode them:

- **Staging execution invariant** — keep "staging is a re-verified execution
  workspace" (current executor behavior), or require execution only from
  artifact-store copies.
- **Dedup and layout** — keep
  `artifacts/{module_id}/{version}/{digest}.zip`, or move to digest-addressed
  storage with reference counting.

Both are cheap to decide now and expensive after artifacts, backups, and GC
assume the current layout.
