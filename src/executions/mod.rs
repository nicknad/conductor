//! Worker-process execution: run a job from a registered, approved
//! artifact.
//!
//! Conductor never executes package code in-process. One execution is one
//! child process, started from the operator-approved entrypoint of a
//! staged, digest-verified artifact:
//!
//! 1. **Resolve** — [`executor::WorkerTarget::resolve`] re-hashes the
//!    staged files against the digests recorded at extraction and pins the
//!    entrypoint to an absolute path under the private staging root.
//! 2. **Spawn** — [`executor::WorkerExecutor`] starts the worker with an
//!    explicit environment (never inherited) and piped stdio.
//! 3. **Invoke** — one [`protocol::ExecutionRequest`] line (execution id,
//!    module/function identity, configuration, deadline; secrets only
//!    here) goes to stdin, then EOF.
//! 4. **Execute/Collect** — the worker answers with one
//!    [`protocol::ExecutionResponse`] line on stdout while stderr
//!    diagnostics are drained concurrently; message size, stderr volume,
//!    and wall time are all bounded.
//! 5. **Terminate** — deadline overruns and cancellations stop the whole
//!    process group (SIGTERM, then SIGKILL after a grace period),
//!    descendants included where the platform supports process groups.
//!
//! Isolation scope: workers run with the host's identity — `uid`, `gid`,
//! and supplementary groups are deliberately inherited and never changed —
//! so package code can reach everything the host process can. The process
//! boundary contains crashes, hangs, and resource abuse; it is not a
//! security sandbox, and stronger isolation would be a deliberate
//! namespaces/cgroup design change, not a flag. The environment is still
//! restricted to an explicit allowlist and secrets never ride argv or env,
//! but under a shared identity those are hygiene, not a credential
//! boundary.
//!
//! Only execution is this module's business: which registered version is
//! active and who may run it is decided by `application::activate_module`
//! against the registry, and this module executes exactly what it is
//! handed.

pub mod executor;
pub mod protocol;
