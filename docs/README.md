# Documentation Index

Condensed, authoritative specifications and the implementation plan for the
runtime-extensible .NET job platform. If code and docs disagree, the docs win;
fix the code or fix the docs in the same change.

| Document | Contents |
| --- | --- |
| [01-architecture.md](01-architecture.md) | Objective, components, planes, architectural rules, non-goals |
| [02-plugin-package.md](02-plugin-package.md) | Package layout, manifest, signatures, validation gates |
| [03-plugin-lifecycle.md](03-plugin-lifecycle.md) | State machine; install/activate/update/rollback/remove semantics |
| [04-job-contract.md](04-job-contract.md) | The stable contract: `IJobPlugin`, `IJobHandler`, `IJobHandlerFactory`, execution context |
| [05-scheduling-execution.md](05-scheduling-execution.md) | Quartz integration, reconciliation, execution tracking, retries, concurrency |
| [06-secrets.md](06-secrets.md) | Secret references, authorization, rotation, process boundaries |
| [07-persistence.md](07-persistence.md) | Data areas, SQLite, outbox, storage roots, backups |
| [08-security.md](08-security.md) | API authentication, signing keys, least privilege, audit |
| [09-observability-operations.md](09-observability-operations.md) | Structured logs, metrics, health checks, recovery, shutdown |
| [10-testing.md](10-testing.md) | Test strategy mapped to the acceptance criteria |
| [11-implementation-plan.md](11-implementation-plan.md) | The phased, resilience- and maintainability-first implementation plan |
| [12-decisions.md](12-decisions.md) | Locked decisions and lightweight ADRs |
| [13-example.md](13-example.md) | Runnable end-to-end example and the operator walkthrough |
| [graphs/plugin-workflows.md](graphs/plugin-workflows.md) | Diagrams: install/store, load/activate, execute, secrets/auth, modules |
| [storage-reconciliation.md](storage-reconciliation.md) | Rust rewrite: audit of the recovered storage design against the current code (background, not a .NET-era spec) |
| [design-persistence.md](design-persistence.md) | Rust rewrite: design plan for structured rejection events, SQLite persistence, and startup reconciliation |

Phases 0–7 of the [implementation plan](11-implementation-plan.md) are implemented: package
install/validation/promotion, the in-process plugin runtime (load → activate → run → drain), the
dispatcher with the durable execution store, the Quartz hosted scheduler with the reconciler that
applies the outbox and repairs drift toward the registry, the CLI-first observability and operations
surface (durable done/not-done summary, execution history, per-execution logs, audit read, health
detail), least-privilege secrets with an authenticated management API, resilient shutdown, backup,
and the [runnable example + end-to-end tests](13-example.md). The workflow graphs mark
**implemented** sections and edges versus those still **planned** for later phases.
