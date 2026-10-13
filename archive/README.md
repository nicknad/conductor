# Archive

Reference-only copy of the original .NET 10 implementation.

- Location: `dotnet-original/` (moved here with `git mv`, so file history is preserved).
- Status: **frozen**. Do not modify; it exists only to guide the Rust rewrite.
- The active project lives at the repository root (Cargo workspace). Nothing there is
  stable yet.

## Contents (`dotnet-original/`)

- `src/` — `Scheduler.Contracts`, `Scheduler.Application`, `Scheduler.Infrastructure`,
  `Scheduler.Runtime.InProcess`, `Scheduler.Runtime.Worker`, `Scheduler.Host`,
  `Scheduler.Cli`, `Scheduler.Tests`, `Scheduler.Tests.TestPlugins`
- `examples/` — runnable example plugin + signed package builder
- Solution and .NET build configuration: `JobScheduler.slnx`, `Directory.Build.props`,
  `Directory.Packages.props`, `global.json`, `nuget.config`, `packageguard.config.json`

`docs/` was intentionally **not** archived: it remains at the repo root as historical
context, but it describes the .NET design and does not yet describe the Rust rewrite.
Treat it as background, not as the current spec.
