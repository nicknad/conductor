# Agent workflow

The workflow uses the globally installed pstack agents for code writing and
judgment, plus two project-local roles: the orchestrator and the security
reviewer. No project agent duplicates a pstack role, and no project agent
grades its own work.

| Agent | Source | Mode | May edit | Job |
| --- | --- | --- | --- | --- |
| `orchestration` | project | primary | `.opencode/agents/**`, this file | Specify, dispatch, evaluate evidence, adapt the process |
| `poteto-agent` | global pstack | subagent | production code and tests | Make one scoped change with falsifiable tests and command evidence |
| `poteto-judge` | global pstack | subagent | nothing | Try to falsify the implementation; report PASS/FAIL/UNPROVEN with evidence |
| `security` | project | subagent | nothing | Threat-model and probe for attack/misuse paths; report severity, reachability, and residual risk |
| `comment-sicko` | global pstack | subagent | nothing | Savage narration and workaround comments in the diff |
| `thermo-nuclear-code-quality-review` | global pstack | subagent | nothing | Maintainability, structure, and 1k-line audit |
| `ci-watcher` | global pstack | subagent | nothing | Report PR-attached CI pass/fail with links |

Project definitions live in [`.opencode/agents/`](../.opencode/agents/).
Pstack definitions live in `~/.config/opencode/agents/`.

## Pstack reconciliation

Global pstack is authoritative for code writing, judgment, comment review,
maintainability review, and CI watching. Their models are configured once by
`/setup-pstack` and recorded in
`~/.agents/skills/poteto-mode/references/opencode-models.md`. Project agent
files do not set `model:` lines, so they cannot drift from that budget.

| Work | Agent |
| --- | --- |
| Implementation | `poteto-agent` |
| Independent verification | `poteto-judge` |
| Read-only exploration | `explore` / `general` |
| Comment review before PR | `comment-sicko` |
| Structural review | `thermo-nuclear-code-quality-review` |
| PR CI | `ci-watcher` |
| Security review | project-local `security` |

The project-local `security` agent exists because pstack has no security seat.
It remains mandatory for changes that touch authentication, input parsing,
filesystem or artifact paths, process spawning, secrets, audit, or
persistence.

## Evidence protocol

Every task brief must list acceptance criteria that can be checked by a
command or a concrete probe. Every claim must name the check that proves it.

- **PASS**: an automated check or reproducible probe proves the criterion.
- **FAIL**: a check disproves it; include command and output.
- **UNPROVEN**: no adequate evidence; say what is missing.

No agent may mark PASS from code inspection alone, from a commit message, or
from another agent's summary. A red full-suite result makes the overall verdict
FAIL even if individual criteria pass.

## Default gates

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
python3 scripts/check_test_quality.py
```

Task-specific additions: new endpoint behavior must include an authenticated
end-to-end test and a tamper/negative case; storage changes must include a
restart or leftover-sweep test; security-sensitive changes add the relevant
DAST/fuzz/mutation run and a security-agent review.

The security agent is mandatory when a change touches authentication, input
parsing, filesystem or artifact paths, process spawning, secrets, audit, or
persistence. Its FAIL or unexplained HIGH finding blocks completion even when
functional criteria pass.

## Test cost and scope

Keep the system under test visible in the test layout:

- Put branch and contract coverage in unit or service tests. Keep at most one
  true end-to-end test per vertical slice; do not re-run upload → activate →
  execute in every read-only branch test. Seed registry/history state directly
  when the test is about a read path.
- Use `#[serial(group)]` only for tests that actually spawn processes and can
  race exec/write. Never blanket-serialize an entire integration file; a
  read-only test waiting behind a 3-second timeout test is not 3 seconds of
  work.
- Implementation inner loop: `cargo test --lib` plus the impacted integration
  target. Before commit, run the full default gates above.
- Verification runs each new test in isolation and in the full suite, and
  reports actual body time separately from serial-lock wait. Investigate any
  test over roughly 2 seconds and say whether it is inherently timed, broad
  e2e, or accidental.
- When the suite grows, produce a slow-test table with
  `cargo +nightly test -- -Z unstable-options --report-time` (or an equivalent
  timing tool) and use it to decide what to split or seed directly.
- Mutation runs use `--in-diff` for the changed slice and a scratch directory
  on a filesystem with room for a full tree copy; excluded build directories
  must not be copied into the mutation workspace.

## Adaptation log

The orchestration agent updates this section when evidence shows the workflow
is insufficient. Each entry names the observed failure and the process change.

- **2026-11-01 — initial protocol.** Established the three-role split after
  audits found that implementation summaries alone overclaimed coverage
  (e.g. startup wiring was described as "end-to-end" before a real serve test
  existed). Verification is now independent and read-only.
- **2026-11-01 — security role added.** The execution slice introduces new
  trust boundaries (registry row → artifact path → staging → worker spawn).
  Functional verification alone cannot prove those paths are not exploitable,
  so a separate read-only security agent now threat-models every change in
  that surface; its HIGH/CRITICAL findings block completion.
- **2026-11-01 — security review split the task.** The first execution slice
  passed functional verification but the security agent proved cross-module
  artifact substitution and a v1 mutation race. The orchestration loop split
  the work into scoped hardening passes (canonical path + manifest binding,
  then v1 rejection + pre-spawn re-verification, then permit/path fixes)
  instead of accepting the functional PASS. This is now the default for
  changes that resolve or execute persisted state.
- **2026-11-01 — test isolation required for process-spawning suites.** The
  verifier found a 2% `ETXTBSY` flake that vanished under `--test-threads=1`;
  the fix was test serialization, not production retries or weakened
  assertions. Process-spawning test suites must now either serialize or prove
  their fixtures cannot race.
- **2026-11-01 — HTTP exposure requires audit and status negative tests.** The
  activation/execute API passed functional and DAST gates but verification
  found raw paths/OS errors in durable audit rows and host I/O misclassified
  as `422`. Endpoint tasks now require durable-row leakage tests and explicit
  host-vs-package failure mapping before completion.
- **2026-11-01 — fuzz fixtures are part of the endpoint gate.** Adding
  `AppState` fields broke the fuzz target and would have failed CI. Endpoint
  changes now must compile fuzz targets and run a short fuzz smoke as part of
  the gate, not only `cargo test`.
- **2026-11-02 — test cost is measured, not guessed.** A timing audit of the
  execution-history slice found 11.8s of test execution: `execution_worker`
  6.46s (targeted process/timing tests), `execution_api` 3.68s (broad e2e,
  dominated by a 3.14s timeout test), while the history unit suite ran in
  0.09s and the history API tests took 0.11–0.39s in isolation. The 3.2s
  per-history-test figure in the full report was serial-lock wait, not work.
  New tests are now classified as unit/service/e2e, new tests are timed both
  alone and in the full suite, and `#[serial]` is limited to named
  process-spawning groups instead of whole files.
- **2026-11-06 — reconciled with global pstack.** The project declared its own
  `implementation` and `verification` agents while the global pstack agents
  held the configured model budget, so the project roles inherited the
  session model and the orchestrator could not spawn pstack agents at all.
  The duplicate project agents were retired. Orchestration now spawns
  `poteto-agent` for implementation and `poteto-judge` for verification, and
  wires in `comment-sicko`, `thermo-nuclear-code-quality-review`, and
  `ci-watcher` as pstack review/CI seats. The project-local `security` agent
  remains because pstack has no security seat.
