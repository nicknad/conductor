# Documentation Index

| Document | Contents |
| --- | --- |
| [architecture.md](architecture.md) | Current system architecture: planes, module map, upload pipeline, storage, execution, invariants |
| [statecharts.md](statecharts.md) | Mermaid statecharts for startup, API guards, upload/validation, lifecycle, execution, storage, readiness, plus planned scheduler/reconciliation states and the remaining-work backlog |
| [storage-reconciliation.md](storage-reconciliation.md) | Point-in-time audit of an early storage-design summary against the code (background, not a spec) |
| [design-persistence.md](design-persistence.md) | Design plan for rejection events, SQLite persistence, and reconciliation (partially implemented) |

The numbered `0x-*.md` .NET-era specs, `graphs/`, and the frozen .NET
implementation archive were removed: they described the previous .NET/Quartz
design and contradicted the Rust rewrite. If code and docs disagree, fix them
in the same change.
