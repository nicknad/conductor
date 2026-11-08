//! Scheduler domain types and boundary validation.
//!
//! Job definitions and run rows are data, not authorization: dispatch always
//! hands the pinned module identity to [`ExecutionService`] so activation,
//! integrity, signer, manifest, artifact, staging, and target checks run
//! exactly as they do for an HTTP execution request.
//!
//! [`ExecutionService`]: crate::control_plane::execute_module::ExecutionService

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::control_plane::activate_module::ActivationError;
use crate::control_plane::execute_module::ExecutionError;
use crate::executions::executor::{ExecutionError as ExecutorError, TargetError};
use crate::modules::identity::{is_safe_identity, MAX_IDENTITY_BYTES};
use crate::storage::staging::StagingError;

use super::cron;

/// Maximum accepted job id length.
pub const MAX_JOB_ID_BYTES: usize = 128;
/// Maximum accepted run id length.
pub const MAX_RUN_ID_BYTES: usize = 128;
/// Maximum canonical JSON payload bytes persisted with a job.
pub const MAX_JOB_PAYLOAD_BYTES: usize = 64 * 1024;
/// Default execution deadline for a scheduled run, clamped to the host ceiling.
pub const DEFAULT_JOB_DEADLINE_SECS: u64 = 30;
/// Smallest accepted interval trigger, in seconds.
pub const MIN_INTERVAL_SECS: u64 = 1;
/// Largest accepted interval trigger, in seconds (one year).
pub const MAX_INTERVAL_SECS: u64 = 31_536_000;

static JOB_COUNTER: AtomicU64 = AtomicU64::new(0);
static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Server-generated job id, shaped like execution ids.
#[must_use]
pub(crate) fn next_job_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let count = JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("job-{}-{nanos}-{count}", std::process::id())
}

/// Server-generated run id, shaped like execution ids.
#[must_use]
pub(crate) fn next_run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let count = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("run-{}-{nanos}-{count}", std::process::id())
}

/// Durable trigger definition. Timezone handling is UTC-only by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trigger {
    Manual,
    Interval { interval_secs: u64 },
    Cron { expression: String },
}

/// The trigger kind persisted on a run row, where the full trigger definition
/// is not repeated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerKind {
    Manual,
    Interval,
    Cron,
}

impl TriggerKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Interval => "interval",
            Self::Cron => "cron",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "manual" => Some(Self::Manual),
            "interval" => Some(Self::Interval),
            "cron" => Some(Self::Cron),
            _ => None,
        }
    }
}

impl Trigger {
    #[must_use]
    pub fn kind(&self) -> TriggerKind {
        match self {
            Self::Manual => TriggerKind::Manual,
            Self::Interval { .. } => TriggerKind::Interval,
            Self::Cron { .. } => TriggerKind::Cron,
        }
    }

    #[must_use]
    pub fn interval_secs(&self) -> Option<u64> {
        match self {
            Self::Interval { interval_secs } => Some(*interval_secs),
            Self::Manual | Self::Cron { .. } => None,
        }
    }

    #[must_use]
    pub fn cron_expr(&self) -> Option<&str> {
        match self {
            Self::Cron { expression } => Some(expression),
            Self::Manual | Self::Interval { .. } => None,
        }
    }
}

/// First run for a newly enabled interval trigger.
#[must_use]
pub fn next_interval_at(now: SystemTime, interval_secs: u64) -> Option<SystemTime> {
    now.checked_add(Duration::from_secs(interval_secs))
}

/// First run for a newly enabled trigger. Manual jobs have no schedule.
#[must_use]
pub fn next_run_at(trigger: &Trigger, now: SystemTime) -> Option<SystemTime> {
    match trigger {
        Trigger::Manual => None,
        Trigger::Interval { interval_secs } => next_interval_at(now, *interval_secs),
        Trigger::Cron { expression } => cron::next_cron_at(expression, now),
    }
}

/// Boundary for the next interval tick. A still-future boundary is returned
/// unchanged; a due one advances to the first boundary strictly after `now`,
/// so a restart enqueues at most one missed run instead of a burst.
#[must_use]
pub fn advance_interval_due(
    scheduled_for: SystemTime,
    interval_secs: u64,
    now: SystemTime,
) -> Option<SystemTime> {
    if interval_secs == 0 {
        return None;
    }
    if scheduled_for > now {
        return Some(scheduled_for);
    }
    let interval = Duration::from_secs(interval_secs);
    let elapsed = now.duration_since(scheduled_for).ok()?;
    let interval_nanos = interval.as_nanos();
    let remainder = elapsed.as_nanos() % interval_nanos;
    let delay_nanos = interval_nanos - remainder;
    let delay_secs = u64::try_from(delay_nanos / 1_000_000_000).ok()?;
    let delay_subsec_nanos = u32::try_from(delay_nanos % 1_000_000_000).ok()?;
    now.checked_add(Duration::new(delay_secs, delay_subsec_nanos))
}

/// One durable job definition. Payload is intentionally absent from `Debug`
/// output so a state/debug log cannot leak worker configuration.
#[derive(Clone, PartialEq)]
pub struct JobDefinition {
    pub job_id: String,
    pub module_id: String,
    pub version: String,
    pub function: String,
    pub trigger: Trigger,
    pub payload: serde_json::Value,
    pub enabled: bool,
    pub next_run_at: Option<SystemTime>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl fmt::Debug for JobDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobDefinition")
            .field("job_id", &self.job_id)
            .field("module_id", &self.module_id)
            .field("version", &self.version)
            .field("function", &self.function)
            .field("trigger", &self.trigger)
            .field("payload", &"[redacted]")
            .field("enabled", &self.enabled)
            .field("next_run_at", &self.next_run_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// A new job before persistence.
#[derive(Clone, PartialEq)]
pub struct NewJob {
    pub job_id: String,
    pub module_id: String,
    pub version: String,
    pub function: String,
    pub trigger: Trigger,
    pub payload: serde_json::Value,
    pub enabled: bool,
    pub next_run_at: Option<SystemTime>,
    pub created_at: SystemTime,
}

impl fmt::Debug for NewJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewJob")
            .field("job_id", &self.job_id)
            .field("module_id", &self.module_id)
            .field("version", &self.version)
            .field("function", &self.function)
            .field("trigger", &self.trigger)
            .field("payload", &"[redacted]")
            .field("enabled", &self.enabled)
            .field("next_run_at", &self.next_run_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Lifecycle/result state of one run. `job_runs.state` is the durable queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobRunState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Refused,
    Interrupted,
}

impl JobRunState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Refused => "refused",
            Self::Interrupted => "interrupted",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "running" => Some(Self::Running),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "refused" => Some(Self::Refused),
            "interrupted" => Some(Self::Interrupted),
            _ => None,
        }
    }
}

/// Closed scheduler failure vocabulary. Execution errors are mapped here so
/// no raw path, OS message, or worker text reaches a run row or API response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobFailureCode {
    ModuleNotFound,
    ModuleNotActive,
    ArtifactNotIntact,
    RuntimeNotAllowed,
    ExecutionNotPermitted,
    DeadlineExceeded,
    ServerBusy,
    ArtifactIntegrityFailed,
    LegacyManifest,
    ManifestInvalid,
    ArchiveInvalid,
    PackageInvalid,
    HistoryWriteFailed,
    JobDisabled,
    InvalidJobDefinition,
    Internal,
    Interrupted,
}

impl JobFailureCode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModuleNotFound => "module_not_found",
            Self::ModuleNotActive => "module_not_active",
            Self::ArtifactNotIntact => "artifact_not_intact",
            Self::RuntimeNotAllowed => "runtime_not_allowed",
            Self::ExecutionNotPermitted => "execution_not_permitted",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::ServerBusy => "server_busy",
            Self::ArtifactIntegrityFailed => "artifact_integrity_failed",
            Self::LegacyManifest => "legacy_manifest",
            Self::ManifestInvalid => "manifest_invalid",
            Self::ArchiveInvalid => "archive_invalid",
            Self::PackageInvalid => "package_invalid",
            Self::HistoryWriteFailed => "history_write_failed",
            Self::JobDisabled => "job_disabled",
            Self::InvalidJobDefinition => "invalid_job_definition",
            Self::Internal => "internal",
            Self::Interrupted => "interrupted",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "module_not_found" => Some(Self::ModuleNotFound),
            "module_not_active" => Some(Self::ModuleNotActive),
            "artifact_not_intact" => Some(Self::ArtifactNotIntact),
            "runtime_not_allowed" => Some(Self::RuntimeNotAllowed),
            "execution_not_permitted" => Some(Self::ExecutionNotPermitted),
            "deadline_exceeded" => Some(Self::DeadlineExceeded),
            "server_busy" => Some(Self::ServerBusy),
            "artifact_integrity_failed" => Some(Self::ArtifactIntegrityFailed),
            "legacy_manifest" => Some(Self::LegacyManifest),
            "manifest_invalid" => Some(Self::ManifestInvalid),
            "archive_invalid" => Some(Self::ArchiveInvalid),
            "package_invalid" => Some(Self::PackageInvalid),
            "history_write_failed" => Some(Self::HistoryWriteFailed),
            "job_disabled" => Some(Self::JobDisabled),
            "invalid_job_definition" => Some(Self::InvalidJobDefinition),
            "internal" => Some(Self::Internal),
            "interrupted" => Some(Self::Interrupted),
            _ => None,
        }
    }
}

/// Exhaustive mapping from dispatch failures to the bounded stored vocabulary.
#[must_use]
pub(crate) fn classify_execution_error(error: &ExecutionError) -> JobFailureCode {
    match error {
        ExecutionError::Activation(activation) => match activation {
            ActivationError::NotRegistered { .. } => JobFailureCode::ModuleNotFound,
            ActivationError::NoActiveVersion { .. } => JobFailureCode::ModuleNotActive,
            ActivationError::Integrity { .. } => JobFailureCode::ArtifactNotIntact,
            ActivationError::RuntimeNotAllowed { .. } => JobFailureCode::RuntimeNotAllowed,
            ActivationError::EmptyRuntimeAllowlist | ActivationError::Storage(_) => {
                JobFailureCode::Internal
            }
        },
        ExecutionError::PersistActive(_) | ExecutionError::Registry(_) => JobFailureCode::Internal,
        ExecutionError::DeadlineExceeded { .. } => JobFailureCode::DeadlineExceeded,
        ExecutionError::Overloaded { .. } => JobFailureCode::ServerBusy,
        ExecutionError::EmptySignerAllowlist | ExecutionError::SignerNotAllowed { .. } => {
            JobFailureCode::ExecutionNotPermitted
        }
        ExecutionError::InvalidConcurrency { .. }
        | ExecutionError::InvalidStorageDirectory { .. }
        | ExecutionError::BlockingTask(_)
        | ExecutionError::ArtifactDirectory { .. } => JobFailureCode::Internal,
        ExecutionError::LegacyManifest { .. } => JobFailureCode::LegacyManifest,
        ExecutionError::ArtifactPathEscape { .. }
        | ExecutionError::ArtifactPathNotCanonical { .. }
        | ExecutionError::ArtifactTooLarge { .. }
        | ExecutionError::ArtifactSizeMismatch { .. }
        | ExecutionError::ArtifactDigestMismatch { .. }
        | ExecutionError::RecordDigestMismatch { .. } => JobFailureCode::ArtifactIntegrityFailed,
        ExecutionError::ArtifactMissing { .. } | ExecutionError::ArtifactUnreadable { .. } => {
            JobFailureCode::Internal
        }
        ExecutionError::Manifest(_) | ExecutionError::ManifestIdentityMismatch { .. } => {
            JobFailureCode::ManifestInvalid
        }
        ExecutionError::Archive(_) | ExecutionError::ArchiveManifestMismatch { .. } => {
            JobFailureCode::ArchiveInvalid
        }
        ExecutionError::Staging(inner) => match inner {
            StagingError::Io(_) => JobFailureCode::Internal,
            StagingError::SourceChanged | StagingError::Digest(_) | StagingError::Archive(_) => {
                JobFailureCode::PackageInvalid
            }
        },
        ExecutionError::Target(inner) => match inner {
            TargetError::StagedFileUnreadable { .. } | TargetError::EntrypointNotExecutable(_) => {
                JobFailureCode::Internal
            }
            TargetError::StagedFileChanged { .. }
            | TargetError::EntrypointRejected(_)
            | TargetError::EntrypointMissing => JobFailureCode::PackageInvalid,
        },
        ExecutionError::Executor(inner) => match inner {
            ExecutorError::InvalidRequest(_) => JobFailureCode::InvalidJobDefinition,
            ExecutorError::TargetVerification(target) => match target {
                TargetError::StagedFileUnreadable { .. }
                | TargetError::EntrypointNotExecutable(_) => JobFailureCode::Internal,
                TargetError::StagedFileChanged { .. }
                | TargetError::EntrypointRejected(_)
                | TargetError::EntrypointMissing => JobFailureCode::PackageInvalid,
            },
            ExecutorError::Spawn(_) => JobFailureCode::Internal,
        },
        ExecutionError::History(_) => JobFailureCode::HistoryWriteFailed,
    }
}

/// One durable run/attempt row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRun {
    pub run_id: String,
    pub job_id: String,
    pub attempt_no: u32,
    pub trigger: TriggerKind,
    pub scheduled_for: SystemTime,
    pub state: JobRunState,
    pub claimed_by: Option<String>,
    pub lease_expires_at: Option<SystemTime>,
    pub execution_id: Option<String>,
    pub outcome: Option<String>,
    pub failure_code: Option<JobFailureCode>,
    pub created_at: SystemTime,
    pub started_at: Option<SystemTime>,
    pub finished_at: Option<SystemTime>,
}

/// A claimed run plus the job snapshot read in the same transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimedRun {
    pub run: JobRun,
    pub job: JobDefinition,
}

/// Terminal completion written by the dispatcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunCompletion {
    pub state: JobRunState,
    pub execution_id: Option<String>,
    pub outcome: Option<String>,
    pub failure_code: Option<JobFailureCode>,
}

impl RunCompletion {
    #[must_use]
    pub fn succeeded(execution_id: String) -> Self {
        Self {
            state: JobRunState::Succeeded,
            execution_id: Some(execution_id),
            outcome: Some("succeeded".to_owned()),
            failure_code: None,
        }
    }

    #[must_use]
    pub fn worker_failure(execution_id: String, outcome: &'static str) -> Self {
        Self {
            state: JobRunState::Failed,
            execution_id: Some(execution_id),
            outcome: Some(outcome.to_owned()),
            failure_code: None,
        }
    }

    #[must_use]
    pub fn failed(failure_code: JobFailureCode) -> Self {
        Self {
            state: JobRunState::Failed,
            execution_id: None,
            outcome: None,
            failure_code: Some(failure_code),
        }
    }

    #[must_use]
    pub fn refused(failure_code: JobFailureCode) -> Self {
        Self {
            state: JobRunState::Refused,
            execution_id: None,
            outcome: None,
            failure_code: Some(failure_code),
        }
    }
}

/// Validation failures for a job definition or run row.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JobValidationError {
    #[error("{field} {reason}")]
    Field { field: &'static str, reason: String },
    #[error("payload {0}")]
    Payload(String),
    #[error("trigger {0}")]
    Trigger(String),
    #[error("run state {0}")]
    RunState(String),
}

pub(crate) fn validate_new_job(job: &NewJob) -> Result<(), JobValidationError> {
    if !is_safe_identity(&job.job_id) || job.job_id.len() > MAX_JOB_ID_BYTES {
        return Err(JobValidationError::Field {
            field: "job_id",
            reason: "must be a bounded path-safe identity".to_owned(),
        });
    }
    for (field, value) in [
        ("module_id", &job.module_id),
        ("version", &job.version),
        ("function", &job.function),
    ] {
        if !is_safe_identity(value) {
            return Err(JobValidationError::Field {
                field,
                reason: "must be a bounded path-safe identity".to_owned(),
            });
        }
    }
    validate_payload(&job.payload)?;
    match &job.trigger {
        Trigger::Manual => {
            if job.next_run_at.is_some() {
                return Err(JobValidationError::Trigger(
                    "manual jobs must not have next_run_at".to_owned(),
                ));
            }
        }
        Trigger::Interval { interval_secs } => {
            if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(interval_secs) {
                return Err(JobValidationError::Trigger(format!(
                    "interval_secs must be between {MIN_INTERVAL_SECS} and {MAX_INTERVAL_SECS}"
                )));
            }
            if job.enabled && job.next_run_at.is_none() {
                return Err(JobValidationError::Trigger(
                    "enabled interval jobs require next_run_at".to_owned(),
                ));
            }
        }
        Trigger::Cron { expression } => {
            if expression.is_empty() || expression.len() > MAX_IDENTITY_BYTES {
                return Err(JobValidationError::Trigger(
                    "cron expression must be bounded and non-empty".to_owned(),
                ));
            }
            cron::validate_cron_expr(expression)
                .map_err(|error| JobValidationError::Trigger(error.to_string()))?;
            if job.enabled && job.next_run_at.is_none() {
                return Err(JobValidationError::Trigger(
                    "enabled cron jobs require next_run_at".to_owned(),
                ));
            }
        }
    }
    if !job.enabled && job.next_run_at.is_some() {
        return Err(JobValidationError::Trigger(
            "disabled jobs must not have next_run_at".to_owned(),
        ));
    }
    Ok(())
}

/// Validates a payload is a JSON object or null and fits the canonical bound.
pub(crate) fn validate_payload(payload: &serde_json::Value) -> Result<(), JobValidationError> {
    if !payload.is_object() && !payload.is_null() {
        return Err(JobValidationError::Payload(
            "must be a JSON object or null".to_owned(),
        ));
    }
    let json = serde_json::to_string(payload)
        .map_err(|error| JobValidationError::Payload(error.to_string()))?;
    if json.len() > MAX_JOB_PAYLOAD_BYTES {
        return Err(JobValidationError::Payload(format!(
            "must be at most {MAX_JOB_PAYLOAD_BYTES} canonical bytes"
        )));
    }
    Ok(())
}

pub(crate) fn validate_completion(completion: &RunCompletion) -> Result<(), JobValidationError> {
    match completion.state {
        JobRunState::Succeeded => {
            if completion.execution_id.is_none() {
                return Err(JobValidationError::RunState(
                    "succeeded runs require an execution id".to_owned(),
                ));
            }
            if completion.outcome.as_deref() != Some("succeeded") {
                return Err(JobValidationError::RunState(
                    "succeeded runs require outcome=succeeded".to_owned(),
                ));
            }
            if completion.failure_code.is_some() {
                return Err(JobValidationError::RunState(
                    "succeeded runs must not have a failure code".to_owned(),
                ));
            }
        }
        JobRunState::Failed => {
            let has_outcome = completion.outcome.is_some();
            let has_failure = completion.failure_code.is_some();
            if has_outcome == has_failure {
                return Err(JobValidationError::RunState(
                    "failed runs require exactly one of outcome or failure code".to_owned(),
                ));
            }
            if let Some(outcome) = completion.outcome.as_deref() {
                if !matches!(
                    outcome,
                    "failed" | "timed_out" | "cancelled" | "worker_error" | "protocol_violation"
                ) {
                    return Err(JobValidationError::RunState(
                        "failed run outcome is not a stable worker outcome".to_owned(),
                    ));
                }
            }
        }
        JobRunState::Refused => {
            if completion.outcome.is_some()
                || completion.execution_id.is_some()
                || completion.failure_code.is_none()
            {
                return Err(JobValidationError::RunState(
                    "refused runs require only a failure code".to_owned(),
                ));
            }
        }
        JobRunState::Queued | JobRunState::Running | JobRunState::Interrupted => {
            return Err(JobValidationError::RunState(
                "completion must be a terminal success/failure/refusal".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Validates a persisted run row's state/timestamp/failure combinations.
pub(crate) fn validate_run_semantics(run: &JobRun) -> Result<(), JobValidationError> {
    if !is_safe_identity(&run.run_id) || run.run_id.len() > MAX_RUN_ID_BYTES {
        return Err(JobValidationError::Field {
            field: "run_id",
            reason: "must be a bounded path-safe identity".to_owned(),
        });
    }
    if !is_safe_identity(&run.job_id) || run.job_id.len() > MAX_JOB_ID_BYTES {
        return Err(JobValidationError::Field {
            field: "job_id",
            reason: "must be a bounded path-safe identity".to_owned(),
        });
    }
    if let Some(claimed_by) = run.claimed_by.as_deref() {
        if !is_safe_identity(claimed_by) || claimed_by.len() > MAX_RUN_ID_BYTES {
            return Err(JobValidationError::Field {
                field: "claimed_by",
                reason: "must be a bounded path-safe identity".to_owned(),
            });
        }
    }
    if let Some(execution_id) = run.execution_id.as_deref() {
        if !is_safe_identity(execution_id) || execution_id.len() > MAX_RUN_ID_BYTES {
            return Err(JobValidationError::Field {
                field: "execution_id",
                reason: "must be a bounded path-safe identity".to_owned(),
            });
        }
    }
    match run.state {
        JobRunState::Queued => {
            if run.started_at.is_some()
                || run.finished_at.is_some()
                || run.execution_id.is_some()
                || run.outcome.is_some()
                || run.failure_code.is_some()
                || run.claimed_by.is_some()
                || run.lease_expires_at.is_some()
            {
                return Err(JobValidationError::RunState(
                    "queued runs must not carry execution or claim fields".to_owned(),
                ));
            }
        }
        JobRunState::Running => {
            if run.started_at.is_none()
                || run.claimed_by.is_none()
                || run.lease_expires_at.is_none()
                || run.finished_at.is_some()
                || run.execution_id.is_some()
                || run.outcome.is_some()
                || run.failure_code.is_some()
            {
                return Err(JobValidationError::RunState(
                    "running runs require start/claim fields and no terminal fields".to_owned(),
                ));
            }
        }
        JobRunState::Succeeded => {
            if run.finished_at.is_none()
                || run.execution_id.is_none()
                || run.outcome.as_deref() != Some("succeeded")
                || run.failure_code.is_some()
            {
                return Err(JobValidationError::RunState(
                    "succeeded runs require finished, execution id, and outcome".to_owned(),
                ));
            }
        }
        JobRunState::Failed => {
            let has_outcome = run.outcome.is_some();
            let has_failure = run.failure_code.is_some();
            if run.finished_at.is_none() || has_outcome == has_failure {
                return Err(JobValidationError::RunState(
                    "failed runs require finished and exactly one of outcome or failure code"
                        .to_owned(),
                ));
            }
        }
        JobRunState::Refused | JobRunState::Interrupted => {
            if run.finished_at.is_none() || run.outcome.is_some() || run.failure_code.is_none() {
                return Err(JobValidationError::RunState(
                    "terminal refusal/interruption requires finished and a failure code".to_owned(),
                ));
            }
        }
    }
    if let (Some(started), Some(finished)) = (run.started_at, run.finished_at) {
        if finished < started {
            return Err(JobValidationError::RunState(
                "finished_at must not precede started_at".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn next_interval_at_adds_the_interval_and_fails_closed_on_overflow() {
        assert_eq!(next_interval_at(at(100), 60), Some(at(160)));
        assert_eq!(
            next_interval_at(at(10), u64::MAX),
            None,
            "an overflowing boundary must not wrap"
        );
    }

    #[test]
    fn next_run_at_selects_manual_interval_and_cron_policy() {
        assert_eq!(next_run_at(&Trigger::Manual, at(100)), None);
        assert_eq!(
            next_run_at(&Trigger::Interval { interval_secs: 60 }, at(100)),
            Some(at(160))
        );
        assert_eq!(
            next_run_at(
                &Trigger::Cron {
                    expression: "*/5 * * * *".to_owned(),
                },
                at(0)
            ),
            Some(at(300)),
            "the first cron run is the next whole UTC boundary after now"
        );
    }

    #[test]
    fn advance_interval_due_returns_a_future_boundary_unchanged() {
        let scheduled = at(1_000);
        assert_eq!(
            advance_interval_due(scheduled, 60, at(999)),
            Some(scheduled)
        );
    }

    #[test]
    fn advance_interval_due_moves_an_equal_boundary_to_the_next_interval() {
        assert_eq!(
            advance_interval_due(at(1_000), 60, at(1_000)),
            Some(at(1_060))
        );
    }

    #[test]
    fn advance_interval_due_handles_one_missed_boundary() {
        // 65 s after the boundary: the next one is 55 s from now.
        assert_eq!(
            advance_interval_due(at(1_000), 60, at(1_065)),
            Some(at(1_120))
        );
    }

    #[test]
    fn advance_interval_due_collapses_many_missed_boundaries_to_one() {
        let scheduled = at(1_000);
        let interval = 60;
        let now = at(1_000 + 1_000 * interval + 7);
        let next = advance_interval_due(scheduled, interval, now).expect("next boundary");
        assert_eq!(next, at(1_000 + 1_001 * interval));
    }

    #[test]
    fn advance_interval_due_rejects_zero_and_reports_overflow() {
        assert_eq!(advance_interval_due(at(10), 0, at(20)), None);
        assert_eq!(advance_interval_due(at(10), u64::MAX, at(20)), None);
    }

    #[test]
    fn validate_new_job_rejects_out_of_range_interval_bounds() {
        for interval_secs in [0, MAX_INTERVAL_SECS + 1] {
            let job = NewJob {
                job_id: "job-a".to_owned(),
                module_id: "reporting-service".to_owned(),
                version: "1.2.0".to_owned(),
                function: "run".to_owned(),
                trigger: Trigger::Interval { interval_secs },
                payload: serde_json::json!({}),
                enabled: true,
                next_run_at: Some(at(600)),
                created_at: at(0),
            };
            assert!(
                matches!(validate_new_job(&job), Err(JobValidationError::Trigger(_))),
                "interval_secs {interval_secs} must be rejected"
            );
        }
    }

    #[test]
    fn validate_new_job_rejects_an_invalid_cron_expression() {
        let job = NewJob {
            job_id: "job-cron".to_owned(),
            module_id: "reporting-service".to_owned(),
            version: "1.2.0".to_owned(),
            function: "run".to_owned(),
            trigger: Trigger::Cron {
                expression: "0 0 * * MON".to_owned(),
            },
            payload: serde_json::json!({}),
            enabled: false,
            next_run_at: None,
            created_at: at(0),
        };
        assert!(matches!(
            validate_new_job(&job),
            Err(JobValidationError::Trigger(_))
        ));
    }
}
