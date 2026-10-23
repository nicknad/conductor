# Conductor

> **Unstable:** this repository is being rewritten in Rust. Nothing here is stable yet —
> no API, no storage format, no CLI contract should be relied upon.

> **Development is not finished:** this is an in-progress implementation, not a
> complete job scheduler. Package ingestion and the worker execution library
> exist, but host startup wiring, scheduling, lifecycle endpoints, execution
> history, and the operator CLI are still outstanding. Do not treat it as a
> finished or production-ready product.

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

Transport security, all fail-closed with no opt-outs:

- **TLS only.** The server binds `bind_rustls` exclusively — there is no
  plaintext listener, and plaintext against the TLS port gets no HTTP
  response (proven in `tests/tls_only.rs`). HSTS
  (`max-age=63072000; includeSubDomains`) is emitted on every response.
  Configure `tls_cert_path`/`tls_key_path`; mismatched identities refuse
  to load.
- **Bearer auth only.** Every `/v1` route requires
  `Authorization: Bearer <operator-token>`, compared in constant time
  (SHA-256 + `subtle`, redacted `Debug`). Missing and wrong tokens are
  indistinguishable (`401`, `Bearer` challenge). `/healthz` is the sole
  unauthenticated endpoint — liveness probes cannot present credentials —
  and returns only `ok`.
- **Bounded everything.** Total body (policy bound + 1 MiB slack),
  streaming package bytes, text fields, at most 16 multipart fields, and
  at most 8 concurrent uploads (`503 server_busy` instead of unbounded
  queueing). Oversized header sections are rejected at the hyper socket
  layer; slow bodies are bounded by the total per-request timeout.
- **Silent responses.** No `Server`/`Via`/`X-Powered-By` identity
  headers; `nosniff`, `DENY` framing, `no-referrer`, `no-store`, and a
  server-generated `x-request-id` on every response; panics become a bare
  `500`; error bodies are `{code, message}` only.

Responses: `201` with `{module_id, version, digest, signer_key_id}` on
acceptance; `400` malformed, `401` unauthenticated (with the matching
`WWW-Authenticate` challenge), `413` oversized, `422`
semantically invalid, `503` saturated. Rejected bytes are deleted from
quarantine (drop-guaranteed); accepted bytes are kept for the artifact
store to promote. The binary still refuses to serve until operator
trusted-key loading lands (`conductor::server::run` fails closed), so
the API is exercised through `router` in `tests/upload_api.rs` (one
test per hardening effort) and `tests/tls_only.rs`.

## Host configuration

Configuration loading lives in `src/config.rs`; `server::run` will consume it
when startup assembly lands. One JSON file plus `CONDUCTOR_*` environment
overrides produce an immutable `Config`:

- `--config <path>` (highest precedence) or `CONDUCTOR_CONFIG` selects the
  file; without either, built-in defaults apply.
- Environment variables override file fields. See [`.env.example`](.env.example)
  for the complete list.
- `CONDUCTOR_API_TOKEN` or `CONDUCTOR_API_TOKEN_FILE` supplies the operator
  bearer token. The token is redacted from `Debug` output.
- `CONDUCTOR_TRUSTED_KEYS_FILE` replaces the file's `trusted_keys` array with
  its own JSON array.
- `Config::validate_for_startup` refuses to proceed without a non-empty token
  and at least one trusted key, and rejects an unusable bind address, zero
  timeout or upload slots, and empty paths.

Example: [`config/conductor.example.json`](config/conductor.example.json).
Its token and key are placeholders; generate your own and do not commit real
configuration or key material.

| Field | Environment variable | Default |
|---|---|---|
| `http_bind` | `CONDUCTOR_HTTP_BIND` | `127.0.0.1:8080` |
| `storage_root` | `CONDUCTOR_STORAGE_ROOT` | `data` |
| `request_timeout_secs` | `CONDUCTOR_REQUEST_TIMEOUT_SECS` | `30` |
| `tls_cert_path` | `CONDUCTOR_TLS_CERT_PATH` | `tls/cert.pem` |
| `tls_key_path` | `CONDUCTOR_TLS_KEY_PATH` | `tls/key.pem` |
| `max_concurrent_uploads` | `CONDUCTOR_MAX_CONCURRENT_UPLOADS` | `8` |
| `api_token` | `CONDUCTOR_API_TOKEN` / `CONDUCTOR_API_TOKEN_FILE` | none (required) |
| `trusted_keys` | `CONDUCTOR_TRUSTED_KEYS_FILE` | none (required) |

Relative paths resolve against the process working directory; prefer absolute
paths in deployed configuration.

## Worker execution (unstable)

Job functions never run in-process. One execution is one worker child process,
started from the entrypoint of a staged, digest-re-verified artifact with an
explicit environment (nothing inherited):

- **Protocol.** One newline-delimited JSON request on stdin — execution id,
  module/function identity, digest, configuration, deadline; secrets only ever
  here, never argv or env — then EOF. The worker answers with exactly one
  response line on stdout (`ok` with a result, or `failed` with a message);
  stderr is diagnostics only.
- **Bounds.** Request and response lines, captured stderr, and wall time are
  all capped, and output is drained concurrently so a chatty worker cannot
  deadlock on a full pipe.
- **Termination.** Deadline overruns and cancellation SIGTERM the worker's
  whole process group, SIGKILL it after a grace period, and clean up
  descendants where the platform supports process groups.
- **Identity & scope.** Workers inherit the host's identity (`uid`, `gid`, and
  supplementary groups are never changed), so package code can reach whatever
  the host process can: the process boundary is fault and resource
  containment, not a sandbox. Stronger filesystem, network, or credential
  isolation would be a separate OS-level design change.

Proven in `tests/execution_worker.rs`: request round trip, secret and
environment handling, host-identity inheritance, failure and
protocol-violation reporting, timeout and cancellation teardown (descendants
included), output bounds, and staged-file tamper detection at resolve time.

## Status

- Active code: single-crate Rust modular monolith (`src/`, `tests/`).
- In progress: package ingestion, validation, promotion, registry persistence,
  and the worker execution library are implemented. Host startup wiring,
  scheduler/triggering, lifecycle endpoints, execution history, and the
  operator CLI are not built yet — see
  [Not built yet](docs/architecture.md#not-built-yet).
- Specification: [`docs/architecture.md`](docs/architecture.md) describes the
  Rust system as built. `docs/storage-reconciliation.md` and
  `docs/design-persistence.md` are background/planning notes, not specs.

## Repository layout

```text
Cargo.toml                  Single-crate package definition
src/
  main.rs                   Binary entry point (thin wrapper over `server::run`)
  lib.rs                    Library root
  server.rs                 Host startup and TLS-only serving path
  api/                      HTTP interface (routes, uploads, errors)
  control_plane/            Control plane: use cases, workflow orchestration, lifecycle
  packages/                 Package domain and validation
  storage/                  Filesystem persistence
  modules/                  Installed module registry
  executions/               Worker-process execution (spawn, IPC, limits)
  config.rs                 Host configuration
config/
  conductor.example.json    Example host configuration
tests/
  package_validation.rs     Package validation workflow tests
  archive_security.rs       Archive security tests
  execution_worker.rs       Worker-process execution tests
  upload_api.rs             Upload API tests
  tls_only.rs               TLS-only serving tests
  upload_workflow.rs        Upload workflow tests
docs/                       Current architecture + background notes (see docs/README.md)
.env.example                Environment variable template
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
