# Agent workflow

Three roles, separated so that no agent grades its own work:

| Agent | Mode | May edit | Job |
| --- | --- | --- | --- |
| `orchestration` | primary | `.opencode/agents/**`, this file | Specify, dispatch, evaluate evidence, adapt the process |
| `implementation` | subagent | production code and tests | Make one scoped change with falsifiable tests and command evidence |
| `verification` | subagent | nothing | Try to falsify the implementation; report PASS/FAIL/UNPROVEN with evidence |
| `security` | subagent | nothing | Threat-model and probe for attack/misuse paths; report severity, reachability, and residual risk |

Definitions live in [`.opencode/agents/`](../.opencode/agents/).

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
