# Conductor

> **Unstable:** this repository is being rewritten in Rust. Nothing here is stable yet —
> no API, no storage format, no CLI contract should be relied upon.

A single-machine job execution platform supporting installing, validating, activating,
updating, disabling, removing, and rolling back job plugin implementations **without
restarting the scheduler host**.

## Service Packages

Services are distributed as versioned ZIP archives containing a manifest, compiled code, and required dependencies.

**.NET service**
```text
reporting-service-1.2.0.zip
├── manifest.json
└── payload/
    ├── ReportingService.dll
    ├── ReportingService.deps.json
    └── ReportingService.runtimeconfig.json
```

**Rust service**
```text
reporting-service-1.2.0.zip
├── manifest.json
└── payload/
    └── reporting-service
```

The Rust executable is built for the target platform and architecture. Any required external runtime libraries must be available in the execution environment or included as permitted dependencies.

The manifest declares the module ID, version, runtime, entry point, and exposed functions. Each package is accompanied by a detached digital signature.

Conductor verifies the signature against trusted publishers, validates the archive and manifest, and stores accepted packages as immutable artifacts before activation.

**Package contents define what can run; Conductor controls whether, where, and under which permissions it runs.**

Details: [package validation pipeline](src/packages/README.md) · [hostile archive corpus](tests/testdata/README.md).

## Status

- Active code: single-crate Rust modular monolith (`src/`, `tests/`).
- Scaffold only: module boundaries and responsibilities are laid out, but no scheduler behavior is
  ported yet.
- Reference: the original .NET 10 implementation is frozen under
  [`archive/dotnet-original/`](archive/README.md) for consultation only.
- Specification: [`docs/`](docs/README.md) describes the **previous .NET design**. It is
  kept as background and does **not** yet describe the Rust rewrite. Do not treat code
  and docs agreement as guaranteed during the rewrite.

## Repository layout

```text
Cargo.toml                  Single-crate package definition
src/
  main.rs                   Binary entry point
  lib.rs                    Library root
  api/                      HTTP interface (routes, uploads, errors)
  application/              Use cases and workflow orchestration
  packages/                 Package domain and validation
  storage/                  Filesystem persistence
  modules/                  Installed module registry/lifecycle
  executions/               Scheduling and execution dispatch
  config.rs                 Host configuration
tests/
  package_validation.rs     Package validation workflow tests
  archive_security.rs       Archive security tests
  upload_workflow.rs        Upload workflow tests
docs/                       Historical .NET-era specs (background only, not current spec)
archive/
  dotnet-original/          Frozen .NET 10 implementation (reference only)
  README.md                 What the archive contains and why
LICENSE                     Apache-2.0
```

## Prerequisites

- Recent stable Rust toolchain (`cargo`, `rustc`). No other toolchain required.

## Build, test, verify

```sh
cargo build
cargo test
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
