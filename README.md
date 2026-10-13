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

## Upload API (unstable)

`POST /v1/packages` accepts a `multipart/form-data` body:

| Field | Contents |
|---|---|
| `package` | The exact ZIP bytes covered by the detached signature, streamed into quarantine under the policy byte bound |
| `key_id` | Trusted-key id (text) |
| `signature` | Standard-base64 Ed25519 signature over the canonical payload (text) |
| `format_version` | Optional envelope version, defaults to 1 |

Responses: `201` with `{module_id, version, digest, signer_key_id}` on
acceptance; `400` for malformed requests, `401` (with `WWW-Authenticate:
Signature`) for authentication failures, `413` for oversized bodies, `422`
for semantically invalid packages. Rejected bytes are deleted from
quarantine; accepted bytes are kept for the artifact store to promote.
`GET /healthz` is a liveness probe. Request timeouts and tracing spans are
wired in; the binary still refuses to serve until operator trusted-key
loading lands (`main` fails closed), so the API is exercised through
`router` in `tests/upload_api.rs`.

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
