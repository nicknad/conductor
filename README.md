# JobScheduler

> **Unstable:** this repository is being rewritten in Rust. Nothing here is stable yet —
> no API, no storage format, no CLI contract should be relied upon.

A single-machine job execution platform supporting installing, validating, activating,
updating, disabling, removing, and rolling back job plugin implementations **without
restarting the scheduler host**.

## Status

- Active code: Rust Cargo workspace at the repo root (`Cargo.toml`, `crates/`).
- Scaffold only: the workspace compiles and tests pass, but no scheduler behavior is
  ported yet.
- Reference: the original .NET 10 implementation is frozen under
  [`archive/dotnet-original/`](archive/README.md) for consultation only.
- Specification: [`docs/`](docs/README.md) describes the **previous .NET design**. It is
  kept as background and does **not** yet describe the Rust rewrite. Do not treat code
  and docs agreement as guaranteed during the rewrite.

## Repository layout

```text
Cargo.toml                  Rust workspace definition
crates/
  conductor-contracts/      Stable API for job modules
  conductor-package/        Manifest, signatures, archive validation
  conductor-host/           HTTP API, workflow, storage, scheduler
apps/
  conductor-worker/         Optional isolated worker executable
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
