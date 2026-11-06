# Next session prompt: plan the startup reconciliation work item

You are picking up Conductor at `/home/nnadolski/projects/job-scheduler`.
Plan the current work item. Do not implement it yet.

## Read first

- `docs/statecharts.md` (sections 5, 8, 10, and Remaining work)
- `docs/architecture.md` (`Not built yet`)
- `docs/design-persistence.md` (PR4 and reconciliation)
- `docs/storage-reconciliation.md` (sections 4, 6, 7)
- `docs/agent-workflow.md`
- `.opencode/agents/orchestration.md`

## Current state

- Conductor is a Rust modular monolith. Upload, validation, promotion,
  registry persistence, activation, execution, and execution history exist.
- `IntegrityState` (`Ok` / `Missing` / `Mismatch`) and
  `ModuleRegistry::set_integrity_state` exist, but no production caller sets
  anything except `Ok`.
- Startup opens and migrates one shared SQLite database and sweeps stale
  quarantine and staging entries. It does not reconcile registry rows against
  the artifact bytes on disk.
- `control_plane/lifecycle.rs` is a placeholder for
  deactivate/remove/rollback. The scheduler, operator CLI, artifact GC, and
  execution-history retention are not built.
- Check `git status` first. An observability/readiness slice may still be
  uncommitted (`src/metrics.rs`, `src/readiness.rs`, `tests/observability.rs`,
  plus wiring and docs). If it is not committed, make landing that slice
  cleanly step 0 of the plan, including the default gates.

## Work item

Plan startup reconciliation, matching design PR4:

- scan every registered version with `ModuleRegistry::all_versions`
- derive and verify the canonical artifact address
  `{module_id}/{version}/{digest_hex}.zip`
- compare the artifact size and SHA-256 against the registry record
- classify each row as `Ok`, `Missing`, or `Mismatch` and persist the result
  through `set_integrity_state`
- fail closed on reconciliation read errors
- never execute, parse, repair, or delete package bytes in this slice

The first slice should classify only. Decide explicitly whether
`reconciliation_runs` belongs in this slice or a later one.

Keep these out of scope: artifact GC, execution-history retention, lifecycle
transitions, scheduler, operator CLI, and any repair or deletion of bytes.

## Plan deliverables

- Goal and non-goals
- Current-state evidence with file and symbol references
- Numbered slices, each independently verifiable
- Data and schema decision, including migration impact
- Startup ordering and fail-closed behavior
- Test plan: intact, missing, and tampered artifacts; restart behavior;
  reconciliation read failure; proof that no package code runs
- Security review points for the registry-to-artifact trust boundary
- Metrics decision: reuse `conductor.artifact.integrity.failures` or add none
- Exact command for each acceptance criterion
- Risks, open questions, and a recommended first slice
- Exact file list the first slice will touch

## Constraints

- Plan only. Do not edit production code, tests, or docs.
- Use the project orchestration workflow and the global pstack agents:
  `poteto-agent` for any code-writing delegates, `poteto-judge` for read-only
  review, `security` for the reconciliation trust boundary.
- Prefer one small proven slice over a broad rewrite. No opportunistic
  refactors.
- Cite current code, not the old .NET-era documents.
- If the observability/readiness slice is still uncommitted, name exactly how
  it will be committed or stashed before reconciliation work starts.

## Output

Return the plan with numbered slices, acceptance criteria, test commands,
risks, and the first slice you recommend. End with the exact file list that
first slice will touch.
