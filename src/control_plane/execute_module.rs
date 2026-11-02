//! Executes an already-registered module version after a restart.
//!
//! Registration and activation store identity, not a live handle: after a
//! restart, executing a module means resolving the active (or explicitly
//! pinned) registered version, re-reading its promoted artifact, and
//! binding the bytes again before any process starts. [`ExecutionService`]
//! owns that sequence:
//!
//! 1. resolve the active version, or a pinned one, through
//!    [`activate_module`](crate::control_plane::activate_module) so the
//!    runtime allowlist and integrity state are enforced;
//! 2. load the registry record that defines the exact digest, size, stored
//!    manifest bytes, and artifact location;
//! 3. reject a record whose `artifact_relpath` is not the canonical
//!    `{module_id}/{version}/{digest_hex}.zip` form, then confine that path
//!    under the configured artifact directory, and verify the artifact's
//!    size and SHA-256 against the record;
//! 4. require manifest v2 and parse the stored manifest with the package
//!    policy, require its identity to match the record, read `manifest.json`
//!    from the digest-verified archive with the bounded reader, and require
//!    the archive manifest to agree with the stored one (identity,
//!    entrypoint, declared paths, and per-file integrity);
//! 5. stage the declared files from the stored manifest with
//!    [`extract_registered`](crate::storage::staging::extract_registered)
//!    and resolve the manifest entrypoint into a [`WorkerTarget`];
//! 6. run the existing [`WorkerExecutor`], which re-verifies the staged
//!    bytes immediately before spawning the worker.
//!
//! The service is deliberately synchronous on the filesystem operations and
//! async only at the executor boundary: registry reads, hashing, manifest
//! comparison, staging, and target resolution all run inside
//! [`tokio::task::spawn_blocking`], so a slow disk cannot stall the async
//! runtime. A bounded semaphore caps concurrent executions; the owned permit
//! moves into the blocking preparation task, is returned with the prepared
//! target, and is held through worker execution, so a cancelled caller cannot
//! release capacity while preparation is still running. Every integrity
//! failure is a typed error and never a spawned process.
//!
//! The registry is the authority on which digest a `(module_id, version)`
//! means; the record's manifest is only trusted after it parses, matches
//! that record, and agrees byte-for-byte with the archive manifest.
//!
//! **Execution requires manifest v2.** v1 declares paths only, with no
//! per-file size or SHA-256, so an artifact mutated in place between the
//! outer digest check and extraction could still execute different bytes.
//! A v1 registration (or a stored/archive manifest that is not v2) is
//! therefore refused with [`ExecutionError::LegacyManifest`] before any
//! staging directory is created or worker spawned. Upload and validation
//! still accept v1 under the package policy; only production execution is
//! gated.
//!
//! **Residual limitation:** the signer allowlist here is a key-id
//! allowlist, not a signature re-verification. Execution refuses a record
//! whose `signer_key_id` is no longer allowed, but it does not re-check the
//! ed25519 signature over the artifact; that happened once at upload. A
//! trust-store change therefore blocks future executions of the old key
//! without retroactively proving the stored bytes were signed by it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::control_plane::activate_module::{
    activate, activate_active, ActivatedModule, ActivationError, ActivationPolicy,
};
use crate::executions::executor::{
    CapturedOutput, ExecutionError as ExecutorError, ExecutionLimits, ExecutionOutcome,
    TargetError, WorkerExecutor, WorkerTarget,
};
use crate::executions::protocol::{ExecutionRequest, Invocation};
use crate::modules::activation::ActiveError;
use crate::modules::registry::{IntegrityState, ModuleRecord, ModuleRegistry, RegistryError};
use crate::packages::archive::{check_entry_path, ArchiveError, QuarantinedFile, ZipArchiveReader};
use crate::packages::artifact::ArtifactDigest;
use crate::packages::digest::Sha256DigestProvider;
use crate::packages::manifest::{Manifest, ManifestError, MANIFEST_FILE_NAME};
use crate::packages::policy::PackageValidationPolicy;
use crate::storage::artifact_store::canonical_artifact_relpath;
use crate::storage::staging::{extract_registered, StagingError};

static EXECUTION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The only manifest schema production execution accepts. v1 has no
/// per-file integrity, so mutation between the outer digest check and
/// extraction cannot be detected; see the module docs.
const EXECUTION_MANIFEST_VERSION: u32 = 2;

/// Receipt for one completed execution. The identity fields come from the
/// registry record that authorized the run; `stdout`/`stderr` are bounded by
/// the executor's message and diagnostic caps.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionReceipt {
    pub execution_id: String,
    pub module_id: String,
    pub version: String,
    pub digest: ArtifactDigest,
    pub outcome: ExecutionOutcome,
    /// Bounded raw protocol response line (empty when none was read).
    pub stdout: CapturedOutput,
    /// Bounded stderr diagnostics.
    pub stderr: CapturedOutput,
    pub duration: Duration,
}

/// Fail-closed execution failures. A worker that was actually spawned is
/// reported through [`ExecutionOutcome`], never as one of these errors.
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error(transparent)]
    Activation(#[from] ActivationError),
    #[error("failed to persist the active version: {0}")]
    PersistActive(#[from] ActiveError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error("requested deadline {requested:?} exceeds the host maximum {maximum:?}")]
    DeadlineExceeded {
        requested: Duration,
        maximum: Duration,
    },
    #[error("execution capacity is exhausted: at most {maximum} executions may run at once")]
    Overloaded { maximum: usize },
    #[error("execution signer allowlist must not be empty")]
    EmptySignerAllowlist,
    #[error(
        "execution concurrency {value} is outside the supported range 1..={maximum} \
         (semaphore permit ceiling)"
    )]
    InvalidConcurrency { value: usize, maximum: usize },
    #[error("execution storage directory is unusable: {path}: {detail}")]
    InvalidStorageDirectory { path: String, detail: String },
    #[error(
        "execution requires manifest v2 with per-file integrity, but {module_id} {version} \
         declares manifest version {manifest_version}"
    )]
    LegacyManifest {
        module_id: String,
        version: String,
        manifest_version: u32,
    },
    #[error("blocking execution preparation failed: {0}")]
    BlockingTask(String),
    #[error("signer key {key_id} is not allowed to execute {module_id} {version}")]
    SignerNotAllowed {
        module_id: String,
        version: String,
        key_id: String,
    },
    #[error("artifact directory is unavailable: {detail}")]
    ArtifactDirectory { detail: String },
    #[error("registered artifact path escapes the artifact directory: {relpath}")]
    ArtifactPathEscape { relpath: String },
    #[error(
        "registered artifact path is not canonical: stored {relpath:?}, expected {expected:?}"
    )]
    ArtifactPathNotCanonical { relpath: String, expected: String },
    #[error("registered artifact is missing: {relpath}")]
    ArtifactMissing { relpath: String },
    #[error("registered artifact could not be read: {relpath}: {detail}")]
    ArtifactUnreadable { relpath: String, detail: String },
    #[error(
        "registered artifact exceeds the archive size bound: {relpath} is {size} bytes, maximum {maximum}"
    )]
    ArtifactTooLarge {
        relpath: String,
        size: u64,
        maximum: u64,
    },
    #[error(
        "registered artifact size mismatch for {relpath}: registry {expected}, on disk {actual}"
    )]
    ArtifactSizeMismatch {
        relpath: String,
        expected: u64,
        actual: u64,
    },
    #[error("registered artifact digest mismatch for {relpath}")]
    ArtifactDigestMismatch { relpath: String },
    #[error(
        "registry record digest does not match the activated version for {module_id} {version}"
    )]
    RecordDigestMismatch { module_id: String, version: String },
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(
        "stored manifest {field} does not match the registry record for {module_id} {version}: \
         expected {expected:?}, found {actual:?}"
    )]
    ManifestIdentityMismatch {
        module_id: String,
        version: String,
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error(
        "archive manifest {field} does not match the stored manifest for {module_id} {version}: \
         expected {expected:?}, found {actual:?}"
    )]
    ArchiveManifestMismatch {
        module_id: String,
        version: String,
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error(transparent)]
    Staging(#[from] StagingError),
    #[error(transparent)]
    Target(#[from] TargetError),
    #[error(transparent)]
    Executor(#[from] ExecutorError),
}

/// Everything the synchronous preparation phase produced: the registry
/// record that authorized the run, the resolved worker target, and the
/// capacity permit that must stay held until the worker finishes. All of it
/// crosses the `spawn_blocking` boundary, so cancelling the waiting caller
/// cannot release capacity while preparation continues.
struct PreparedExecution {
    record: ModuleRecord,
    target: WorkerTarget,
    permit: OwnedSemaphorePermit,
}

/// Test-only synchronization seam run at the start of blocking preparation.
///
/// Production callers never install one. It exists so a test can hold
/// preparation open deterministically and prove that cancelling the outer
/// future does not release the execution permit.
#[doc(hidden)]
#[derive(Clone)]
pub struct PreparationHook(Arc<dyn Fn() + Send + Sync>);

impl PreparationHook {
    #[doc(hidden)]
    #[must_use]
    pub fn new(run: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(run))
    }

    fn run(&self) {
        (self.0)();
    }
}

impl std::fmt::Debug for PreparationHook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PreparationHook").finish()
    }
}

/// Test-only synchronization seam run at the start of blocking activation.
/// Production callers never install one; it lets a test hold activation open
/// and prove `/healthz` keeps being served while the blocking registry and
/// artifact work runs.
#[doc(hidden)]
#[derive(Clone)]
pub struct ActivationHook(Arc<dyn Fn() + Send + Sync>);

impl ActivationHook {
    #[doc(hidden)]
    #[must_use]
    pub fn new(run: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(run))
    }

    fn run(&self) {
        (self.0)();
    }
}

impl std::fmt::Debug for ActivationHook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ActivationHook").finish()
    }
}

#[cfg(test)]
mod hook_tests {
    use super::*;

    #[test]
    fn activation_hook_debug_is_stable() {
        let hook = ActivationHook::new(|| {});
        assert_eq!(format!("{hook:?}"), "ActivationHook");
    }
}

/// Reusable execution service: resolve a registered version, re-verify its
/// artifact, stage it, and run the worker.
#[derive(Debug, Clone)]
pub struct ExecutionService {
    registry: Arc<ModuleRegistry>,
    artifact_dir: PathBuf,
    staging_dir: PathBuf,
    activation_policy: ActivationPolicy,
    /// Key ids currently permitted to execute. See the module docs: this is
    /// an allowlist, not a signature re-verification.
    allowed_signers: Arc<HashSet<String>>,
    max_concurrent_executions: usize,
    execution_slots: Arc<Semaphore>,
    /// Bounds in-flight activation work. Activation reads and writes the
    /// registry and stats the artifact on the blocking pool; callers that
    /// arrive beyond this bound get `503` instead of an unbounded queue.
    activation_slots: Arc<Semaphore>,
    limits: ExecutionLimits,
    max_deadline: Duration,
    package_policy: PackageValidationPolicy,
    preparation_hook: Option<PreparationHook>,
    activation_hook: Option<ActivationHook>,
}

impl ExecutionService {
    /// Builds a service around one registry handle and immutable policy
    /// snapshot. `max_deadline` is the host-side ceiling for any requested
    /// execution deadline; longer requests are refused before resolution.
    /// `allowed_signers` is the operator trust-store key-id allowlist and
    /// `max_concurrent_executions` bounds in-flight workers.
    ///
    /// Construction fails closed instead of silently repairing policy:
    /// an empty signer allowlist can authorize nothing and is refused; a
    /// concurrency outside `1..=Semaphore::MAX_PERMITS` is refused rather
    /// than clamped (and never reaches a panicking `Semaphore::new`); and
    /// `artifact_dir`/`staging_dir` must already exist as directories that
    /// are neither symlinks nor group-/world-writable, and their raw paths
    /// must not end in a separator (a trailing slash would follow a symlink
    /// before `symlink_metadata` sees it). [`Config::ensure_layout`]
    /// creates and tightens the production layout, but the service validates
    /// the paths it is actually handed so a direct or future caller cannot
    /// bypass that guarantee.
    ///
    /// [`Config::ensure_layout`]: crate::config::Config::ensure_layout
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Arc<ModuleRegistry>,
        artifact_dir: PathBuf,
        staging_dir: PathBuf,
        activation_policy: ActivationPolicy,
        limits: ExecutionLimits,
        max_deadline: Duration,
        package_policy: PackageValidationPolicy,
        allowed_signers: HashSet<String>,
        max_concurrent_executions: usize,
    ) -> Result<Self, ExecutionError> {
        if allowed_signers.is_empty() {
            return Err(ExecutionError::EmptySignerAllowlist);
        }
        if max_concurrent_executions == 0 || max_concurrent_executions > Semaphore::MAX_PERMITS {
            return Err(ExecutionError::InvalidConcurrency {
                value: max_concurrent_executions,
                maximum: Semaphore::MAX_PERMITS,
            });
        }
        validate_execution_dir(&artifact_dir, "artifact")?;
        validate_execution_dir(&staging_dir, "staging")?;
        Ok(Self {
            registry,
            artifact_dir,
            staging_dir,
            activation_policy,
            allowed_signers: Arc::new(allowed_signers),
            max_concurrent_executions,
            execution_slots: Arc::new(Semaphore::new(max_concurrent_executions)),
            activation_slots: Arc::new(Semaphore::new(max_concurrent_executions)),
            limits,
            max_deadline,
            package_policy,
            preparation_hook: None,
            activation_hook: None,
        })
    }

    /// Installs a test-only preparation hook. Production code must not call
    /// this; it exists to make cancellation/permit tests deterministic.
    #[doc(hidden)]
    #[must_use]
    pub fn with_preparation_hook(mut self, hook: PreparationHook) -> Self {
        self.preparation_hook = Some(hook);
        self
    }

    /// Installs a test-only activation hook. Production code must not call
    /// this; it exists to make the blocking-pool test deterministic.
    #[doc(hidden)]
    #[must_use]
    pub fn with_activation_hook(mut self, hook: ActivationHook) -> Self {
        self.activation_hook = Some(hook);
        self
    }

    /// Host ceiling for any requested execution deadline.
    #[must_use]
    pub fn max_deadline(&self) -> Duration {
        self.max_deadline
    }

    /// Activates a registered version, verifies its artifact is present and
    /// intact, and persists the active pointer.
    ///
    /// The registry reads, artifact stat/hash, and pointer write all run
    /// inside [`tokio::task::spawn_blocking`] under a bounded activation
    /// permit, so a slow disk cannot occupy an async runtime worker. The
    /// artifact check happens before [`set_active`](ModuleRegistry::set_active)
    /// so activation cannot report success for an unrunnable version.
    pub async fn activate(
        &self,
        module_id: &str,
        version: &str,
    ) -> Result<ActivatedModule, ExecutionError> {
        let permit = Arc::clone(&self.activation_slots)
            .try_acquire_owned()
            .map_err(|_| ExecutionError::Overloaded {
                maximum: self.max_concurrent_executions,
            })?;
        let registry = Arc::clone(&self.registry);
        let artifact_dir = self.artifact_dir.clone();
        let activation_policy = self.activation_policy.clone();
        let activation_hook = self.activation_hook.clone();
        let module_id_owned = module_id.to_owned();
        let version_owned = version.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if let Some(hook) = &activation_hook {
                hook.run();
            }
            let activated = activate(
                &registry,
                &module_id_owned,
                &version_owned,
                &activation_policy,
            )?;
            let record = registry
                .get(&activated.module_id, &activated.version)?
                .ok_or_else(|| ActivationError::NotRegistered {
                    module_id: activated.module_id.clone(),
                    version: activated.version.clone(),
                })?;
            if record.digest != activated.digest {
                return Err(ExecutionError::RecordDigestMismatch {
                    module_id: activated.module_id,
                    version: activated.version,
                });
            }
            // Bind activation to runnable bytes: a missing, tampered, or
            // unreadable artifact must not persist an active pointer.
            let artifact_path = confine_artifact_path(&artifact_dir, &record)?;
            verify_artifact(&artifact_path, &record)?;
            registry.set_active(&activated.module_id, &activated.version)?;
            Ok(activated)
        })
        .await
        .map_err(|err| ExecutionError::BlockingTask(err.to_string()))?
    }

    /// Executes one function of the active (or pinned) module version.
    ///
    /// A bounded permit is acquired before any work and held until the
    /// worker finishes (or preparation fails). In-flight capacity exhaustion
    /// is a fail-fast [`ExecutionError::Overloaded`], never an unbounded
    /// queue. All integrity work happens before [`WorkerExecutor::execute`]
    /// is called: deadline ceiling, activation policy, record lookup, signer
    /// allowlist, artifact path canonicalization/confinement, size/digest,
    /// stored and archive manifest agreement, extraction, and entrypoint
    /// resolution. Any failure is a typed error and no worker is spawned.
    pub async fn execute(
        &self,
        module_id: &str,
        pinned_version: Option<&str>,
        function: &str,
        configuration: serde_json::Value,
        deadline: Duration,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        if deadline > self.max_deadline {
            return Err(ExecutionError::DeadlineExceeded {
                requested: deadline,
                maximum: self.max_deadline,
            });
        }

        // Fail fast instead of queueing. The owned permit moves into the
        // blocking preparation task and comes back with the prepared target:
        // if this caller is cancelled while preparation runs, the detached
        // task keeps the slot until preparation actually ends.
        let permit = Arc::clone(&self.execution_slots)
            .try_acquire_owned()
            .map_err(|_| ExecutionError::Overloaded {
                maximum: self.max_concurrent_executions,
            })?;

        let module_id_owned = module_id.to_owned();
        let pinned_owned = pinned_version.map(ToOwned::to_owned);
        let registry = Arc::clone(&self.registry);
        let artifact_dir = self.artifact_dir.clone();
        let staging_dir = self.staging_dir.clone();
        let activation_policy = self.activation_policy.clone();
        let package_policy = self.package_policy.clone();
        let allowed_signers = Arc::clone(&self.allowed_signers);
        let preparation_hook = self.preparation_hook.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            if let Some(hook) = &preparation_hook {
                hook.run();
            }
            prepare_execution(
                &registry,
                &artifact_dir,
                &staging_dir,
                &activation_policy,
                &allowed_signers,
                &package_policy,
                &module_id_owned,
                pinned_owned.as_deref(),
                permit,
            )
        })
        .await
        .map_err(|err| ExecutionError::BlockingTask(err.to_string()))??;
        let PreparedExecution {
            record,
            target,
            permit: _permit,
        } = prepared;

        let execution_id = next_execution_id();
        let request = ExecutionRequest::new(
            Invocation {
                execution_id,
                module_id: record.module_id.clone(),
                version: record.version.clone(),
                digest_hex: record.digest.to_hex(),
                function: function.to_owned(),
            },
            configuration,
            deadline,
        );
        let report = WorkerExecutor::new(self.limits)
            .execute(&target, request)
            .await?;
        Ok(ExecutionReceipt {
            execution_id: report.execution_id,
            module_id: record.module_id,
            version: record.version,
            digest: record.digest,
            outcome: report.outcome,
            stdout: report.stdout,
            stderr: report.stderr,
            duration: report.duration,
        })
    }
}

/// Checks one execution storage root at construction. The directory must
/// already exist, be a real directory (not a symlink a later writer could
/// retarget), and not be group- or world-writable (other users must not be
/// able to plant or replace staged/artifact entries).
fn validate_execution_dir(path: &Path, role: &'static str) -> Result<(), ExecutionError> {
    let invalid = |detail: String| ExecutionError::InvalidStorageDirectory {
        path: path.display().to_string(),
        detail: format!("{role} directory {detail}"),
    };
    // Check the raw path before `symlink_metadata`: on Linux a trailing slash
    // follows a symlinked directory, so `symlink_metadata` would report the
    // target as a real directory and hide the link.
    if has_trailing_separator(path) {
        return Err(invalid("must not end with a path separator".to_owned()));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| invalid(format!("is not accessible: {err}")))?;
    if metadata.file_type().is_symlink() {
        return Err(invalid("must not be a symlink".to_owned()));
    }
    if !metadata.is_dir() {
        return Err(invalid("must be a directory".to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(invalid(
                "must not be group-writable or world-writable".to_owned(),
            ));
        }
    }
    Ok(())
}

/// True when the raw path text ends in a separator. `Path` normalizes
/// trailing separators away for most operations, so this must inspect the
/// OS string rather than components.
fn has_trailing_separator(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().last() == Some(&b'/')
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().ends_with(std::path::MAIN_SEPARATOR)
    }
}

/// Synchronous preparation phase, run on the blocking pool.
#[allow(clippy::too_many_arguments)]
fn prepare_execution(
    registry: &ModuleRegistry,
    artifact_dir: &Path,
    staging_dir: &Path,
    activation_policy: &ActivationPolicy,
    allowed_signers: &HashSet<String>,
    package_policy: &PackageValidationPolicy,
    module_id: &str,
    pinned_version: Option<&str>,
    permit: OwnedSemaphorePermit,
) -> Result<PreparedExecution, ExecutionError> {
    let activated = resolve(registry, module_id, pinned_version, activation_policy)?;
    let record = registry
        .get(&activated.module_id, &activated.version)?
        .ok_or_else(|| ActivationError::NotRegistered {
            module_id: activated.module_id.clone(),
            version: activated.version.clone(),
        })?;
    // Activation and record lookup are separate reads. Re-check the
    // properties that decide whether execution is permitted any more.
    if record.digest != activated.digest {
        return Err(ExecutionError::RecordDigestMismatch {
            module_id: activated.module_id,
            version: activated.version,
        });
    }
    if record.integrity_state != IntegrityState::Ok {
        return Err(ActivationError::Integrity {
            module_id: record.module_id.clone(),
            version: record.version.clone(),
            state: record.integrity_state,
        }
        .into());
    }
    // The runtime allowlist was applied to the first read inside activation;
    // this second row read is separate state, so apply it again before any
    // artifact work. A concurrent row change must not bypass activation.
    ensure_runtime_allowed(&record, activation_policy)?;
    if !allowed_signers.contains(&record.signer_key_id) {
        return Err(ExecutionError::SignerNotAllowed {
            module_id: record.module_id.clone(),
            version: record.version.clone(),
            key_id: record.signer_key_id.clone(),
        });
    }
    // v1 has no per-file integrity, so an in-place artifact mutation between
    // the digest check below and extraction could execute different bytes.
    // Refuse before any artifact I/O or staging side effect. Upload and
    // validation still support v1; production execution does not.
    if record.manifest_version != EXECUTION_MANIFEST_VERSION {
        return Err(ExecutionError::LegacyManifest {
            module_id: record.module_id.clone(),
            version: record.version.clone(),
            manifest_version: record.manifest_version,
        });
    }
    // Bound the size before opening or hashing the artifact. The registry
    // value is itself attacker-reachable state, so it is checked against
    // policy like any other record field.
    if record.artifact_size > package_policy.archive.max_compressed_bytes {
        return Err(ExecutionError::ArtifactTooLarge {
            relpath: record.artifact_relpath.clone(),
            size: record.artifact_size,
            maximum: package_policy.archive.max_compressed_bytes,
        });
    }

    let artifact_path = confine_artifact_path(artifact_dir, &record)?;
    verify_artifact(&artifact_path, &record)?;

    let stored_manifest =
        Manifest::parse_with_policy(record.manifest_json.as_bytes(), package_policy)?;
    // Defense in depth: the record already passed the v2 gate above, but the
    // stored bytes are separate state and must independently be v2 before
    // they are trusted to describe extraction.
    if stored_manifest.manifest_version != EXECUTION_MANIFEST_VERSION {
        return Err(ExecutionError::LegacyManifest {
            module_id: record.module_id.clone(),
            version: record.version.clone(),
            manifest_version: stored_manifest.manifest_version,
        });
    }
    verify_manifest_identity(&stored_manifest, &record)?;

    // The digest check above binds the archive bytes. The archive's own
    // manifest must still agree with the stored one: a tampered registry
    // row must not be able to redirect the entrypoint or the declared files.
    let archive_manifest = read_archive_manifest(&artifact_path, &record, package_policy)?;
    verify_archive_manifest(&archive_manifest, &stored_manifest, &record)?;

    let staged = extract_registered(
        staging_dir,
        &artifact_path,
        &record.digest,
        &stored_manifest,
        package_policy,
    )?;
    let target = WorkerTarget::resolve(staged, &stored_manifest.entrypoint)?;
    Ok(PreparedExecution {
        record,
        target,
        permit,
    })
}

/// Re-applies the activation runtime allowlist to the record read after
/// activation. The first read and this one are separate registry snapshots;
/// a concurrent row change must not slip a disallowed runtime through.
fn ensure_runtime_allowed(
    record: &ModuleRecord,
    activation_policy: &ActivationPolicy,
) -> Result<(), ExecutionError> {
    if !activation_policy
        .allowed_runtimes
        .iter()
        .any(|allowed| allowed == &record.runtime)
    {
        return Err(ActivationError::RuntimeNotAllowed {
            module_id: record.module_id.clone(),
            version: record.version.clone(),
            runtime: record.runtime.clone(),
        }
        .into());
    }
    Ok(())
}

fn resolve(
    registry: &ModuleRegistry,
    module_id: &str,
    pinned_version: Option<&str>,
    activation_policy: &ActivationPolicy,
) -> Result<ActivatedModule, ExecutionError> {
    match pinned_version {
        Some(version) => Ok(activate(registry, module_id, version, activation_policy)?),
        None => Ok(activate_active(registry, module_id, activation_policy)?),
    }
}

/// Reads `manifest.json` from the digest-verified artifact through the
/// bounded archive reader and parses it with the same package policy.
fn read_archive_manifest(
    artifact_path: &Path,
    record: &ModuleRecord,
    package_policy: &PackageValidationPolicy,
) -> Result<Manifest, ExecutionError> {
    let mut artifact =
        QuarantinedFile::open(artifact_path).map_err(|err| ExecutionError::ArtifactUnreadable {
            relpath: record.artifact_relpath.clone(),
            detail: err.to_string(),
        })?;
    let bytes = ZipArchiveReader.read_file_from(
        &mut artifact,
        MANIFEST_FILE_NAME,
        package_policy.max_manifest_bytes,
    )?;
    Ok(Manifest::parse_with_policy(&bytes, package_policy)?)
}

/// Resolves `artifact_relpath` under the artifact root. The registry string
/// is not trusted: it must be the canonical `{module_id}/{version}/{
/// digest}.zip` address derived from the record, pass the archive path
/// policy, and canonicalize to a path under the artifact root (which also
/// rejects a symlink pointing outside it).
fn confine_artifact_path(
    artifact_dir: &Path,
    record: &ModuleRecord,
) -> Result<PathBuf, ExecutionError> {
    let normalized = check_entry_path(&record.artifact_relpath, false).map_err(|_| {
        ExecutionError::ArtifactPathEscape {
            relpath: record.artifact_relpath.clone(),
        }
    })?;
    let expected = canonical_artifact_relpath(&record.module_id, &record.version, &record.digest);
    // Exact equality is required. Normalization alone is not enough: paths
    // such as `.../{digest}.zip/` normalize to the canonical address, and a
    // leading component (`artifacts-evil/...`) is a different address even
    // when confinement would place it under the root. The stored string must
    // be the one canonical string the artifact store writes.
    if normalized != expected || record.artifact_relpath != expected {
        return Err(ExecutionError::ArtifactPathNotCanonical {
            relpath: record.artifact_relpath.clone(),
            expected,
        });
    }
    // Build the candidate from the derived value, never the stored string.
    let candidate = artifact_dir.join(&expected);
    if !candidate.starts_with(artifact_dir) {
        return Err(ExecutionError::ArtifactPathEscape {
            relpath: record.artifact_relpath.clone(),
        });
    }
    let root = artifact_dir
        .canonicalize()
        .map_err(|err| ExecutionError::ArtifactDirectory {
            detail: err.to_string(),
        })?;
    let resolved = candidate.canonicalize().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            ExecutionError::ArtifactMissing {
                relpath: record.artifact_relpath.clone(),
            }
        } else {
            ExecutionError::ArtifactUnreadable {
                relpath: record.artifact_relpath.clone(),
                detail: err.to_string(),
            }
        }
    })?;
    if !resolved.starts_with(&root) {
        return Err(ExecutionError::ArtifactPathEscape {
            relpath: record.artifact_relpath.clone(),
        });
    }
    Ok(resolved)
}

/// Checks the on-disk artifact against the registered size and digest.
/// The staging step hashes the same bytes again; this earlier check
/// makes the failure a typed artifact error rather than a staging
/// `SourceChanged`, and refuses before any directory is created.
fn verify_artifact(path: &Path, record: &ModuleRecord) -> Result<(), ExecutionError> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            ExecutionError::ArtifactMissing {
                relpath: record.artifact_relpath.clone(),
            }
        } else {
            ExecutionError::ArtifactUnreadable {
                relpath: record.artifact_relpath.clone(),
                detail: err.to_string(),
            }
        }
    })?;
    if !metadata.is_file() {
        return Err(ExecutionError::ArtifactMissing {
            relpath: record.artifact_relpath.clone(),
        });
    }
    if metadata.len() != record.artifact_size {
        return Err(ExecutionError::ArtifactSizeMismatch {
            relpath: record.artifact_relpath.clone(),
            expected: record.artifact_size,
            actual: metadata.len(),
        });
    }
    let mut file = std::fs::File::open(path).map_err(|err| ExecutionError::ArtifactUnreadable {
        relpath: record.artifact_relpath.clone(),
        detail: err.to_string(),
    })?;
    let actual = Sha256DigestProvider
        .digest_stream(&mut file)
        .map_err(|err| ExecutionError::ArtifactUnreadable {
            relpath: record.artifact_relpath.clone(),
            detail: err.to_string(),
        })?;
    if actual != *record.digest.as_bytes() {
        return Err(ExecutionError::ArtifactDigestMismatch {
            relpath: record.artifact_relpath.clone(),
        });
    }
    Ok(())
}

fn verify_manifest_identity(
    manifest: &Manifest,
    record: &ModuleRecord,
) -> Result<(), ExecutionError> {
    let mismatch = |field: &'static str, expected: String, actual: String| {
        ExecutionError::ManifestIdentityMismatch {
            module_id: record.module_id.clone(),
            version: record.version.clone(),
            field,
            expected,
            actual,
        }
    };
    if manifest.manifest_version != record.manifest_version {
        return Err(mismatch(
            "manifest_version",
            record.manifest_version.to_string(),
            manifest.manifest_version.to_string(),
        ));
    }
    if manifest.module_id != record.module_id {
        return Err(mismatch(
            "module_id",
            record.module_id.clone(),
            manifest.module_id.clone(),
        ));
    }
    if manifest.version != record.version {
        return Err(mismatch(
            "version",
            record.version.clone(),
            manifest.version.clone(),
        ));
    }
    if manifest.runtime != record.runtime {
        return Err(mismatch(
            "runtime",
            record.runtime.clone(),
            manifest.runtime.clone(),
        ));
    }
    Ok(())
}

/// Requires the archive manifest to describe exactly what the stored
/// manifest describes: identity, entrypoint, declared file paths (in order),
/// and per-file integrity. Extraction still uses the stored manifest, but
/// only after this agreement check.
fn verify_archive_manifest(
    archive: &Manifest,
    stored: &Manifest,
    record: &ModuleRecord,
) -> Result<(), ExecutionError> {
    let mismatch = |field: &'static str, expected: String, actual: String| {
        ExecutionError::ArchiveManifestMismatch {
            module_id: record.module_id.clone(),
            version: record.version.clone(),
            field,
            expected,
            actual,
        }
    };
    if archive.manifest_version != stored.manifest_version {
        return Err(mismatch(
            "manifest_version",
            stored.manifest_version.to_string(),
            archive.manifest_version.to_string(),
        ));
    }
    if archive.module_id != stored.module_id {
        return Err(mismatch(
            "module_id",
            stored.module_id.clone(),
            archive.module_id.clone(),
        ));
    }
    if archive.version != stored.version {
        return Err(mismatch(
            "version",
            stored.version.clone(),
            archive.version.clone(),
        ));
    }
    if archive.runtime != stored.runtime {
        return Err(mismatch(
            "runtime",
            stored.runtime.clone(),
            archive.runtime.clone(),
        ));
    }
    if archive.entrypoint != stored.entrypoint {
        return Err(mismatch(
            "entrypoint",
            stored.entrypoint.clone(),
            archive.entrypoint.clone(),
        ));
    }
    if archive.files.len() != stored.files.len() {
        return Err(mismatch(
            "files",
            stored.files.len().to_string(),
            archive.files.len().to_string(),
        ));
    }
    for (index, (stored_file, archive_file)) in stored.files.iter().zip(&archive.files).enumerate()
    {
        if archive_file.path != stored_file.path {
            return Err(mismatch(
                "file path",
                format!("[{index}] {}", stored_file.path),
                format!("[{index}] {}", archive_file.path),
            ));
        }
        if archive_file.integrity != stored_file.integrity {
            return Err(mismatch(
                "file integrity",
                format!("[{index}] {:?}", stored_file.integrity),
                format!("[{index}] {:?}", archive_file.integrity),
            ));
        }
    }
    Ok(())
}

fn next_execution_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let count = EXECUTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("exec-{}-{nanos}-{count}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(runtime: &str) -> ModuleRecord {
        ModuleRecord {
            module_id: "reporting".to_owned(),
            version: "1.0.0".to_owned(),
            digest: ArtifactDigest::new([7u8; 32]),
            signer_key_id: "k1".to_owned(),
            runtime: runtime.to_owned(),
            manifest_version: EXECUTION_MANIFEST_VERSION,
            manifest_json: "{}".to_owned(),
            artifact_relpath: "reporting/1.0.0/pkg.zip".to_owned(),
            artifact_size: 0,
            integrity_state: IntegrityState::Ok,
            registered_at: SystemTime::now(),
        }
    }

    #[test]
    fn second_record_runtime_outside_the_activation_allowlist_is_refused() {
        let policy = ActivationPolicy::new(vec!["rust".to_owned()]).expect("policy");
        let mut record = record("rust");
        assert!(ensure_runtime_allowed(&record, &policy).is_ok());

        record.runtime = "python".to_owned();
        let err = ensure_runtime_allowed(&record, &policy).unwrap_err();
        assert!(
            matches!(
                err,
                ExecutionError::Activation(ActivationError::RuntimeNotAllowed {
                    ref runtime,
                    ..
                }) if runtime == "python"
            ),
            "a runtime changed after activation must be refused: {err:?}"
        );
    }
}
