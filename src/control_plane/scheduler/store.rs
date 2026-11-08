//! Durable job and run persistence.
//!
//! `job_runs.state` is the queue. Every enqueue, claim, and terminal write is
//! one immediate transaction; the shared [`Database`] mutex serializes them
//! with registry and history writes.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rusqlite::{params, OptionalExtension};
use thiserror::Error;

use crate::modules::identity::MAX_IDENTITY_BYTES;
use crate::storage::database::{from_millis, to_millis, Database, DatabaseError};

use super::cron;
use super::job::{
    advance_interval_due, next_run_id, validate_completion, validate_new_job, validate_payload,
    validate_run_semantics, ClaimedRun, JobDefinition, JobFailureCode, JobRun, JobRunState,
    JobValidationError, NewJob, RunCompletion, Trigger, TriggerKind, MAX_INTERVAL_SECS,
    MAX_JOB_ID_BYTES, MAX_JOB_PAYLOAD_BYTES, MAX_RUN_ID_BYTES, MIN_INTERVAL_SECS,
};

/// Bounds enforced in the same transaction as each write.
#[derive(Clone, Copy, Debug)]
pub struct JobStoreLimits {
    pub max_jobs: usize,
    pub max_queued_runs: usize,
}

impl Default for JobStoreLimits {
    fn default() -> Self {
        Self {
            max_jobs: 1024,
            max_queued_runs: 1024,
        }
    }
}

/// Store failures. Callers map these to stable API codes.
#[derive(Debug, Error)]
pub enum JobStoreError {
    #[error("job not found")]
    JobNotFound,
    #[error("job is disabled")]
    JobDisabled,
    #[error("job queue is full")]
    QueueFull,
    #[error("job limit reached")]
    JobLimitReached,
    #[error("invalid job row: {0}")]
    InvalidJob(String),
    #[error("invalid run row: {0}")]
    InvalidRun(String),
    #[error(transparent)]
    Storage(#[from] DatabaseError),
}

impl From<rusqlite::Error> for JobStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(DatabaseError::from(error))
    }
}

impl From<JobValidationError> for JobStoreError {
    fn from(error: JobValidationError) -> Self {
        Self::InvalidJob(error.to_string())
    }
}

/// Result of an idempotent enable/disable transition.
#[derive(Clone, Debug, PartialEq)]
pub struct EnableResult {
    pub job: JobDefinition,
    /// Number of queued runs terminalized because the job was disabled.
    pub cancelled_queued: usize,
}

/// Outcome of one per-run cancellation request.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum RunCancel {
    Queued(JobRun),
    Running,
    Terminal(JobRun),
    NotFound,
}

/// Startup recovery counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub interrupted: usize,
    pub disabled_queued: usize,
}

/// Outcome of one due interval/cron enqueue pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DueEnqueueReport {
    pub enqueued: usize,
    pub deduped: usize,
    pub skipped_full: usize,
    pub skipped_invalid: usize,
}

type DueJobRow = (Vec<u8>, Vec<u8>, Option<i64>, Option<Vec<u8>>, i64);

/// Durable job/run repository over the shared database.
#[derive(Debug)]
pub struct JobStore {
    database: Arc<Database>,
    limits: JobStoreLimits,
}

const SELECT_JOB: &str = "SELECT job_id, module_id, version, function, trigger_kind, \
     interval_secs, cron_expr, timezone, payload_json, enabled, next_run_at, \
     created_at, updated_at FROM jobs";

const SELECT_RUN: &str = "SELECT run_id, job_id, attempt_no, trigger_kind, scheduled_for, \
     state, claimed_by, lease_expires_at, execution_id, outcome, failure_code, \
     created_at, started_at, finished_at FROM job_runs";

impl JobStore {
    #[must_use]
    pub fn new(database: Arc<Database>, limits: JobStoreLimits) -> Self {
        Self { database, limits }
    }

    /// In-memory store with the real schema.
    pub(crate) fn open_in_memory(limits: JobStoreLimits) -> Result<Self, JobStoreError> {
        let database = Arc::new(Database::open_in_memory()?);
        database.migrate()?;
        Ok(Self::new(database, limits))
    }

    /// Inserts a job and returns it. Enforces the job-count bound in the same
    /// transaction.
    pub fn create_job(&self, new: NewJob) -> Result<JobDefinition, JobStoreError> {
        validate_new_job(&new)?;
        let payload_json = serde_json::to_string(&new.payload)
            .map_err(|error| JobStoreError::InvalidJob(format!("payload: {error}")))?;
        let trigger_kind = new.trigger.kind();
        let interval_secs = new
            .trigger
            .interval_secs()
            .map(|value| i64::try_from(value).unwrap_or(i64::MAX));
        let cron_expr = new.trigger.cron_expr().map(ToOwned::to_owned);
        let next_run_at = new.next_run_at.map(to_millis);
        self.database.with_write_tx(|tx| {
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))?;
            if usize::try_from(count).unwrap_or(usize::MAX) >= self.limits.max_jobs {
                return Err(JobStoreError::JobLimitReached);
            }
            tx.execute(
                "INSERT INTO jobs (
                    job_id, module_id, version, function, trigger_kind, interval_secs,
                    cron_expr, timezone, payload_json, enabled, next_run_at, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'UTC', ?8, ?9, ?10, ?11, ?12)",
                params![
                    new.job_id,
                    new.module_id,
                    new.version,
                    new.function,
                    trigger_kind.as_str(),
                    interval_secs,
                    cron_expr,
                    payload_json,
                    if new.enabled { 1 } else { 0 },
                    next_run_at,
                    to_millis(new.created_at),
                    to_millis(new.created_at),
                ],
            )?;
            Ok(JobDefinition {
                job_id: new.job_id,
                module_id: new.module_id,
                version: new.version,
                function: new.function,
                trigger: new.trigger,
                payload: new.payload,
                enabled: new.enabled,
                next_run_at: new.next_run_at,
                created_at: new.created_at,
                updated_at: new.created_at,
            })
        })
    }

    /// Reads one job, validating the persisted row.
    pub fn get_job(&self, job_id: &str) -> Result<Option<JobDefinition>, JobStoreError> {
        self.database.with_connection(|conn| {
            conn.query_row(
                &format!("{SELECT_JOB} WHERE job_id = ?1"),
                params![job_id],
                row_to_job,
            )
            .optional()
            .map_err(JobStoreError::from)
        })
    }

    /// Newest-first page of jobs. `limit` is clamped by the store.
    pub fn list_jobs(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JobDefinition>, JobStoreError> {
        let limit = i64::try_from(limit.min(200)).unwrap_or(200);
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        self.database.with_connection(|conn| {
            let mut statement = conn
                .prepare(&format!(
                    "{SELECT_JOB} ORDER BY created_at DESC, job_id DESC LIMIT ?1 OFFSET ?2"
                ))
                .map_err(JobStoreError::from)?;
            let rows = statement
                .query_map(params![limit, offset], row_to_job)
                .map_err(JobStoreError::from)?;
            let mut jobs = Vec::new();
            for row in rows {
                jobs.push(row.map_err(JobStoreError::from)?);
            }
            Ok(jobs)
        })
    }

    /// Enables or disables a job. Disabling terminalizes all queued runs in
    /// the same transaction, so disabled work cannot execute after re-enable.
    pub fn set_enabled(
        &self,
        job_id: &str,
        enabled: bool,
        next_run_at: Option<SystemTime>,
        now: SystemTime,
    ) -> Result<Option<EnableResult>, JobStoreError> {
        self.database.with_write_tx(|tx| {
            let Some(existing) = get_job_tx(tx, job_id)? else {
                return Ok(None);
            };
            if enabled
                && !matches!(existing.trigger.kind(), TriggerKind::Manual)
                && next_run_at.is_none()
            {
                return Err(JobStoreError::InvalidJob(
                    "enabled interval/cron jobs require next_run_at".to_owned(),
                ));
            }
            if !enabled && next_run_at.is_some() {
                return Err(JobStoreError::InvalidJob(
                    "disabled jobs must not have next_run_at".to_owned(),
                ));
            }
            tx.execute(
                "UPDATE jobs SET enabled = ?1, next_run_at = ?2, updated_at = ?3 WHERE job_id = ?4",
                params![
                    if enabled { 1 } else { 0 },
                    next_run_at.map(to_millis),
                    to_millis(now),
                    job_id
                ],
            )?;
            let cancelled_queued = if enabled {
                0
            } else {
                tx.execute(
                    "UPDATE job_runs SET state = 'refused', failure_code = 'job_disabled', \
                     finished_at = ?1 WHERE job_id = ?2 AND state = 'queued'",
                    params![to_millis(now), job_id],
                )?
            };
            let job = get_job_tx(tx, job_id)?.ok_or(JobStoreError::JobNotFound)?;
            Ok(Some(EnableResult {
                job,
                cancelled_queued,
            }))
        })
    }

    /// Enqueues one manual run in a transaction that re-reads the enabled
    /// flag and the queue bound. Two calls in the same millisecond are two
    /// rows: the tick-unique index only covers interval/cron.
    pub fn enqueue_manual_run(
        &self,
        job_id: &str,
        now: SystemTime,
    ) -> Result<JobRun, JobStoreError> {
        self.database.with_write_tx(|tx| {
            let job = get_job_tx(tx, job_id)?.ok_or(JobStoreError::JobNotFound)?;
            if !job.enabled {
                return Err(JobStoreError::JobDisabled);
            }
            let queued: i64 = tx.query_row(
                "SELECT COUNT(*) FROM job_runs WHERE state = 'queued'",
                [],
                |row| row.get(0),
            )?;
            if usize::try_from(queued).unwrap_or(usize::MAX) >= self.limits.max_queued_runs {
                return Err(JobStoreError::QueueFull);
            }
            let run_id = next_run_id();
            let scheduled_for = to_millis(now);
            let created_at = to_millis(now);
            tx.execute(
                "INSERT INTO job_runs (
                    run_id, job_id, attempt_no, trigger_kind, scheduled_for, state, created_at
                 ) VALUES (?1, ?2, 1, 'manual', ?3, 'queued', ?4)",
                params![run_id, job_id, scheduled_for, created_at],
            )?;
            Ok(JobRun {
                run_id,
                job_id: job_id.to_owned(),
                attempt_no: 1,
                trigger: TriggerKind::Manual,
                scheduled_for: now,
                state: JobRunState::Queued,
                claimed_by: None,
                lease_expires_at: None,
                execution_id: None,
                outcome: None,
                failure_code: None,
                created_at: now,
                started_at: None,
                finished_at: None,
            })
        })
    }

    /// Enqueues the next attempt of a failed run. Returns `Ok(None)` when the
    /// job is missing/disabled, the shared queue bound is full, or the tick
    /// index already holds this attempt. Never moves `jobs.next_run_at`.
    pub(crate) fn enqueue_retry(
        &self,
        job_id: &str,
        trigger: TriggerKind,
        next_attempt_no: u32,
        scheduled_for: SystemTime,
        now: SystemTime,
    ) -> Result<Option<JobRun>, JobStoreError> {
        self.database.with_write_tx(|tx| {
            let Some(job) = get_job_tx(tx, job_id)? else {
                return Ok(None);
            };
            if !job.enabled {
                return Ok(None);
            }
            if next_attempt_no < 2 {
                return Err(JobStoreError::InvalidRun(
                    "retry attempt number must be at least 2".to_owned(),
                ));
            }
            let queued: i64 = tx.query_row(
                "SELECT COUNT(*) FROM job_runs WHERE state = 'queued'",
                [],
                |row| row.get(0),
            )?;
            if usize::try_from(queued).unwrap_or(usize::MAX) >= self.limits.max_queued_runs {
                return Ok(None);
            }
            let run_id = next_run_id();
            let scheduled_for_ms = to_millis(scheduled_for);
            let created_at_ms = to_millis(now);
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO job_runs (
                    run_id, job_id, attempt_no, trigger_kind, scheduled_for, state, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6)",
                params![
                    run_id,
                    job_id,
                    i64::from(next_attempt_no),
                    trigger.as_str(),
                    scheduled_for_ms,
                    created_at_ms,
                ],
            )?;
            if inserted == 0 {
                return Ok(None);
            }
            Ok(Some(JobRun {
                run_id,
                job_id: job_id.to_owned(),
                attempt_no: next_attempt_no,
                trigger,
                scheduled_for,
                state: JobRunState::Queued,
                claimed_by: None,
                lease_expires_at: None,
                execution_id: None,
                outcome: None,
                failure_code: None,
                created_at: now,
                started_at: None,
                finished_at: None,
            }))
        })
    }

    /// Enqueues one queued run for each enabled interval/cron job whose
    /// `next_run_at` is due, then advances every attempted job to the first
    /// boundary after `now`. A full queue leaves `next_run_at` untouched so a
    /// later tick retries instead of dropping the due time. An unparseable or
    /// impossible expression is skipped without failing the pass.
    pub fn enqueue_due_runs(&self, now: SystemTime) -> Result<DueEnqueueReport, JobStoreError> {
        let now_ms = to_millis(now);
        self.database.with_write_tx(|tx| {
            let due: Vec<DueJobRow> = {
                let mut statement = tx.prepare(
                    "SELECT job_id, trigger_kind, interval_secs, cron_expr, next_run_at \
                     FROM jobs WHERE enabled = 1 \
                     AND trigger_kind IN ('interval', 'cron') \
                     AND next_run_at IS NOT NULL AND next_run_at <= ?1 \
                     AND ((trigger_kind = 'interval' \
                           AND interval_secs BETWEEN ?2 AND ?3) \
                          OR (trigger_kind = 'cron' AND cron_expr IS NOT NULL \
                              AND interval_secs IS NULL)) \
                     ORDER BY next_run_at, job_id",
                )?;
                let rows = statement.query_map(
                    params![now_ms, MIN_INTERVAL_SECS as i64, MAX_INTERVAL_SECS as i64],
                    |row| {
                        Ok((
                            bytes_column(row, 0)?,
                            bytes_column(row, 1)?,
                            row.get(2)?,
                            optional_bytes_column(row, 3)?,
                            row.get(4)?,
                        ))
                    },
                )?;
                let mut due = Vec::new();
                for row in rows {
                    due.push(row?);
                }
                due
            };
            let queued: i64 = tx.query_row(
                "SELECT COUNT(*) FROM job_runs WHERE state = 'queued'",
                [],
                |row| row.get(0),
            )?;
            let mut queued = usize::try_from(queued).unwrap_or(usize::MAX);
            let mut report = DueEnqueueReport::default();
            for (
                job_id_bytes,
                trigger_kind_bytes,
                interval_secs,
                cron_expr_bytes,
                scheduled_for_ms,
            ) in due
            {
                let decoded = (
                    String::from_utf8(job_id_bytes),
                    String::from_utf8(trigger_kind_bytes),
                    cron_expr_bytes.map(String::from_utf8).transpose(),
                );
                let (Ok(job_id), Ok(trigger_kind), Ok(cron_expr)) = decoded else {
                    report.skipped_invalid += 1;
                    continue;
                };
                let scheduled_for = from_millis(scheduled_for_ms);
                let next_run_at = match trigger_kind.as_str() {
                    "interval" => interval_secs
                        .and_then(|value| u64::try_from(value).ok())
                        .and_then(|interval_secs| {
                            advance_interval_due(scheduled_for, interval_secs, now)
                        }),
                    "cron" => cron_expr.as_deref().and_then(|expression| {
                        cron::advance_cron_due(scheduled_for, expression, now)
                    }),
                    _ => None,
                };
                let Some(next_run_at) = next_run_at else {
                    report.skipped_invalid += 1;
                    continue;
                };
                if queued >= self.limits.max_queued_runs {
                    report.skipped_full += 1;
                    continue;
                }
                let run_id = next_run_id();
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO job_runs (
                        run_id, job_id, attempt_no, trigger_kind, scheduled_for, state, created_at
                     ) VALUES (?1, ?2, 1, ?3, ?4, 'queued', ?5)",
                    params![run_id, job_id, trigger_kind, scheduled_for_ms, now_ms],
                )?;
                if inserted > 0 {
                    report.enqueued += 1;
                    queued += 1;
                } else {
                    report.deduped += 1;
                }
                tx.execute(
                    "UPDATE jobs SET next_run_at = ?1, updated_at = ?2 WHERE job_id = ?3",
                    params![to_millis(next_run_at), now_ms, job_id],
                )?;
            }
            Ok(report)
        })
    }

    /// Newest-first page of runs for one job.
    pub fn list_runs(
        &self,
        job_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JobRun>, JobStoreError> {
        let limit = i64::try_from(limit.min(200)).unwrap_or(200);
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        self.database.with_connection(|conn| {
            let mut statement = conn
                .prepare(&format!(
                    "{SELECT_RUN} WHERE job_id = ?1 ORDER BY created_at DESC, id DESC \
                     LIMIT ?2 OFFSET ?3"
                ))
                .map_err(JobStoreError::from)?;
            let rows = statement
                .query_map(params![job_id, limit, offset], row_to_run)
                .map_err(JobStoreError::from)?;
            let mut runs = Vec::new();
            for row in rows {
                runs.push(row.map_err(JobStoreError::from)?);
            }
            Ok(runs)
        })
    }

    /// Reads one run scoped to its job. A run that belongs to a different job
    /// is reported as absent so callers cannot probe another job's run ids.
    pub(crate) fn get_run(
        &self,
        job_id: &str,
        run_id: &str,
    ) -> Result<Option<JobRun>, JobStoreError> {
        self.database.with_connection(|conn| {
            let run = conn
                .query_row(
                    &format!("{SELECT_RUN} WHERE run_id = ?1"),
                    params![run_id],
                    row_to_run,
                )
                .optional()
                .map_err(JobStoreError::from)?;
            Ok(run.filter(|run| run.job_id == job_id))
        })
    }

    /// Claims the oldest queued run from an enabled job. The claim and the
    /// queue-state transition are one immediate transaction.
    pub fn claim_next_run(
        &self,
        owner_id: &str,
        now: SystemTime,
        lease_ttl: Duration,
    ) -> Result<Option<ClaimedRun>, JobStoreError> {
        let lease_expires_at = now.checked_add(lease_ttl).unwrap_or(now);
        let now_ms = to_millis(now);
        self.database.with_write_tx(|tx| {
            let candidate: Option<JobRun> = tx
                .query_row(
                    &format!(
                        "{SELECT_RUN} WHERE state = 'queued' AND scheduled_for <= ?1 \
                         AND job_id IN (SELECT job_id FROM jobs WHERE enabled = 1) \
                         ORDER BY scheduled_for, id LIMIT 1"
                    ),
                    params![now_ms],
                    row_to_run,
                )
                .optional()?;
            let Some(mut run) = candidate else {
                return Ok(None);
            };
            let job = get_job_tx(tx, &run.job_id)?.ok_or(JobStoreError::JobNotFound)?;
            let updated = tx.execute(
                "UPDATE job_runs SET state = 'running', claimed_by = ?1, \
                 lease_expires_at = ?2, started_at = ?3 WHERE run_id = ?4 AND state = 'queued'",
                params![
                    owner_id,
                    to_millis(lease_expires_at),
                    to_millis(now),
                    run.run_id
                ],
            )?;
            if updated == 0 {
                return Ok(None);
            }
            run.state = JobRunState::Running;
            run.claimed_by = Some(owner_id.to_owned());
            run.lease_expires_at = Some(lease_expires_at);
            run.started_at = Some(now);
            Ok(Some(ClaimedRun { run, job }))
        })
    }

    /// Writes a terminal completion for a running run.
    pub fn finish_run(
        &self,
        run_id: &str,
        completion: &RunCompletion,
        now: SystemTime,
    ) -> Result<bool, JobStoreError> {
        validate_completion(completion).map_err(|error| {
            JobStoreError::InvalidRun(format!("completion for {run_id}: {error}"))
        })?;
        self.database.with_write_tx(|tx| {
            let updated = tx.execute(
                "UPDATE job_runs SET state = ?1, execution_id = ?2, outcome = ?3, \
                 failure_code = ?4, finished_at = ?5 WHERE run_id = ?6 AND state = 'running'",
                params![
                    completion.state.as_str(),
                    completion.execution_id,
                    completion.outcome,
                    completion.failure_code.map(JobFailureCode::as_str),
                    to_millis(now),
                    run_id
                ],
            )?;
            Ok(updated > 0)
        })
    }

    /// Decision for one per-run cancel request. A queued row is terminalized
    /// atomically; a running row is reported without a write so the dispatch
    /// task stays the single owner of the terminal completion.
    pub(crate) fn request_run_cancel(
        &self,
        job_id: &str,
        run_id: &str,
        now: SystemTime,
    ) -> Result<RunCancel, JobStoreError> {
        self.database.with_write_tx(|tx| {
            let Some(run) = get_run_tx(tx, run_id)? else {
                return Ok(RunCancel::NotFound);
            };
            if run.job_id != job_id {
                return Ok(RunCancel::NotFound);
            }
            match run.state {
                JobRunState::Queued => {
                    let updated = tx.execute(
                        "UPDATE job_runs SET state = 'failed', outcome = 'cancelled', \
                         finished_at = ?1 WHERE run_id = ?2 AND job_id = ?3 AND state = 'queued'",
                        params![to_millis(now), run_id, job_id],
                    )?;
                    if updated == 0 {
                        return Ok(RunCancel::NotFound);
                    }
                    let cancelled = get_run_tx(tx, run_id)?.ok_or_else(|| {
                        JobStoreError::InvalidRun(format!("cancelled run {run_id} disappeared"))
                    })?;
                    Ok(RunCancel::Queued(cancelled))
                }
                JobRunState::Running => Ok(RunCancel::Running),
                _ => Ok(RunCancel::Terminal(run)),
            }
        })
    }

    /// Startup recovery: running rows become interrupted and queued rows for
    /// disabled jobs become refused. No worker is replayed.
    pub fn recover_startup(&self, now: SystemTime) -> Result<RecoveryReport, JobStoreError> {
        self.database.with_write_tx(|tx| {
            let interrupted = tx.execute(
                "UPDATE job_runs SET state = 'interrupted', failure_code = 'interrupted', \
                 finished_at = ?1 WHERE state = 'running'",
                params![to_millis(now)],
            )?;
            let disabled_queued = tx.execute(
                "UPDATE job_runs SET state = 'refused', failure_code = 'job_disabled', \
                 finished_at = ?1 WHERE state = 'queued' AND job_id IN \
                 (SELECT job_id FROM jobs WHERE enabled = 0)",
                params![to_millis(now)],
            )?;
            Ok(RecoveryReport {
                interrupted,
                disabled_queued,
            })
        })
    }

    /// Current durable queue depth.
    pub fn count_queued(&self) -> Result<usize, JobStoreError> {
        self.database.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM job_runs WHERE state = 'queued'",
                    [],
                    |row| row.get(0),
                )
                .map_err(JobStoreError::from)?;
            Ok(usize::try_from(count).unwrap_or(usize::MAX))
        })
    }
}

const INVALID_TEXT: &[u8] = &[0xff];

/// Reads a text column as raw bytes. Any other storage class, including a
/// BLOB, becomes an invalid UTF-8 byte so the caller skips the row instead of
/// enqueuing a run that `row_to_job` would reject later.
fn bytes_column(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Vec<u8>> {
    Ok(match row.get_ref(index)? {
        rusqlite::types::ValueRef::Text(bytes) => bytes.to_vec(),
        _ => INVALID_TEXT.to_vec(),
    })
}

fn optional_bytes_column(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<Vec<u8>>> {
    Ok(match row.get_ref(index)? {
        rusqlite::types::ValueRef::Null => None,
        rusqlite::types::ValueRef::Text(bytes) => bytes.to_vec().into(),
        _ => Some(INVALID_TEXT.to_vec()),
    })
}

fn get_job_tx(
    tx: &rusqlite::Transaction<'_>,
    job_id: &str,
) -> rusqlite::Result<Option<JobDefinition>> {
    tx.query_row(
        &format!("{SELECT_JOB} WHERE job_id = ?1"),
        params![job_id],
        row_to_job,
    )
    .optional()
}

fn get_run_tx(tx: &rusqlite::Transaction<'_>, run_id: &str) -> rusqlite::Result<Option<JobRun>> {
    tx.query_row(
        &format!("{SELECT_RUN} WHERE run_id = ?1"),
        params![run_id],
        row_to_run,
    )
    .optional()
}

fn row_to_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobDefinition> {
    let job_id: String = row.get(0)?;
    let module_id: String = row.get(1)?;
    let version: String = row.get(2)?;
    let function: String = row.get(3)?;
    let trigger_kind: String = row.get(4)?;
    let interval_secs: Option<i64> = row.get(5)?;
    let cron_expr: Option<String> = row.get(6)?;
    let timezone: String = row.get(7)?;
    let payload_json: String = row.get(8)?;
    let enabled: i64 = row.get(9)?;
    let next_run_at: Option<i64> = row.get(10)?;
    let created_at: i64 = row.get(11)?;
    let updated_at: i64 = row.get(12)?;

    if timezone != "UTC" {
        return Err(invalid_row("job timezone is not UTC"));
    }
    let trigger = match trigger_kind.as_str() {
        "manual" => {
            if interval_secs.is_some() || cron_expr.is_some() {
                return Err(invalid_row("manual job carries interval/cron fields"));
            }
            Trigger::Manual
        }
        "interval" => {
            let secs = interval_secs.ok_or_else(|| invalid_row("interval job has no interval"))?;
            let secs = u64::try_from(secs)
                .ok()
                .filter(|value| (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(value))
                .ok_or_else(|| invalid_row("interval job has an out-of-range interval"))?;
            if cron_expr.is_some() {
                return Err(invalid_row("interval job carries a cron expression"));
            }
            Trigger::Interval {
                interval_secs: secs,
            }
        }
        "cron" => {
            let expression = cron_expr.ok_or_else(|| invalid_row("cron job has no expression"))?;
            if expression.is_empty() || expression.len() > MAX_IDENTITY_BYTES {
                return Err(invalid_row(
                    "cron expression is empty or over the byte bound",
                ));
            }
            cron::validate_cron_expr(&expression)
                .map_err(|_| invalid_row("cron expression is not valid"))?;
            if interval_secs.is_some() {
                return Err(invalid_row("cron job carries an interval"));
            }
            Trigger::Cron { expression }
        }
        _ => return Err(invalid_row("job trigger_kind is not a known value")),
    };
    if !matches!(enabled, 0 | 1) {
        return Err(invalid_row("job enabled is not 0 or 1"));
    }
    let enabled = enabled == 1;
    if next_run_at.is_some() && (matches!(trigger, Trigger::Manual) || !enabled) {
        return Err(invalid_row("job has next_run_at but is manual or disabled"));
    }
    if next_run_at.is_none() && !matches!(trigger, Trigger::Manual) && enabled {
        return Err(invalid_row("enabled scheduled job has no next_run_at"));
    }
    if payload_json.len() > MAX_JOB_PAYLOAD_BYTES {
        return Err(invalid_row("job payload exceeds the byte bound"));
    }
    let payload: serde_json::Value = serde_json::from_str(&payload_json)
        .map_err(|_| invalid_row("job payload is not valid JSON"))?;
    validate_payload(&payload).map_err(|_| invalid_row("job payload is not object/null"))?;
    if created_at < 0 || updated_at < 0 {
        return Err(invalid_row("job timestamps are negative"));
    }
    for (field, value) in [
        ("job_id", job_id.as_str()),
        ("module_id", module_id.as_str()),
        ("version", version.as_str()),
        ("function", function.as_str()),
    ] {
        if !crate::modules::identity::is_safe_identity(value)
            || (field == "job_id" && value.len() > MAX_JOB_ID_BYTES)
        {
            return Err(invalid_row("job identity field is not path-safe"));
        }
    }
    Ok(JobDefinition {
        job_id,
        module_id,
        version,
        function,
        trigger,
        payload,
        enabled,
        next_run_at: next_run_at.map(from_millis),
        created_at: from_millis(created_at),
        updated_at: from_millis(updated_at),
    })
}

fn row_to_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRun> {
    let run_id: String = row.get(0)?;
    let job_id: String = row.get(1)?;
    let attempt_no: i64 = row.get(2)?;
    let trigger_kind: String = row.get(3)?;
    let scheduled_for: i64 = row.get(4)?;
    let state: String = row.get(5)?;
    let claimed_by: Option<String> = row.get(6)?;
    let lease_expires_at: Option<i64> = row.get(7)?;
    let execution_id: Option<String> = row.get(8)?;
    let outcome: Option<String> = row.get(9)?;
    let failure_code: Option<String> = row.get(10)?;
    let created_at: i64 = row.get(11)?;
    let started_at: Option<i64> = row.get(12)?;
    let finished_at: Option<i64> = row.get(13)?;

    let attempt_no = u32::try_from(attempt_no)
        .ok()
        .filter(|value| *value >= 1)
        .ok_or_else(|| invalid_row("run attempt number is invalid"))?;
    let trigger = TriggerKind::parse(&trigger_kind)
        .ok_or_else(|| invalid_row("run trigger kind is not known"))?;
    let state = JobRunState::parse(&state).ok_or_else(|| invalid_row("run state is not known"))?;
    if let Some(outcome) = outcome.as_deref() {
        if !matches!(
            outcome,
            "succeeded"
                | "failed"
                | "timed_out"
                | "cancelled"
                | "worker_error"
                | "protocol_violation"
        ) {
            return Err(invalid_row("run outcome is not a stable worker outcome"));
        }
    }
    let failure_code = match failure_code.as_deref() {
        Some(value) => Some(
            JobFailureCode::parse(value)
                .ok_or_else(|| invalid_row("run failure code is not known"))?,
        ),
        None => None,
    };
    if !is_safe_run_identity(&run_id, MAX_RUN_ID_BYTES)
        || !is_safe_run_identity(&job_id, MAX_JOB_ID_BYTES)
    {
        return Err(invalid_row("run identity field is not path-safe"));
    }
    if scheduled_for < 0 || created_at < 0 {
        return Err(invalid_row("run timestamps are negative"));
    }
    let run = JobRun {
        run_id,
        job_id,
        attempt_no,
        trigger,
        scheduled_for: from_millis(scheduled_for),
        state,
        claimed_by,
        lease_expires_at: lease_expires_at.map(from_millis),
        execution_id,
        outcome,
        failure_code,
        created_at: from_millis(created_at),
        started_at: started_at.map(from_millis),
        finished_at: finished_at.map(from_millis),
    };
    validate_run_semantics(&run).map_err(|error| invalid_row(error.to_string()))?;
    Ok(run)
}

fn is_safe_run_identity(value: &str, maximum: usize) -> bool {
    crate::modules::identity::is_safe_identity(value) && value.len() <= maximum
}

fn invalid_row(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message.into(),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn at(millis: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(millis)
    }

    const MINUTE_MS: u64 = 60_000;

    /// 2024-01-01T00:00:00Z.
    const CRON_START_MS: u64 = 1_704_067_200_000;

    fn limits() -> JobStoreLimits {
        JobStoreLimits {
            max_jobs: 4,
            max_queued_runs: 4,
        }
    }

    fn new_job(job_id: &str, enabled: bool) -> NewJob {
        NewJob {
            job_id: job_id.to_owned(),
            module_id: "reporting-service".to_owned(),
            version: "1.2.0".to_owned(),
            function: "run".to_owned(),
            trigger: Trigger::Manual,
            payload: serde_json::json!({"account": "example"}),
            enabled,
            next_run_at: None,
            created_at: at(1_000),
        }
    }

    fn interval_job(job_id: &str, interval_secs: u64, next_run_at: SystemTime) -> NewJob {
        NewJob {
            job_id: job_id.to_owned(),
            module_id: "reporting-service".to_owned(),
            version: "1.2.0".to_owned(),
            function: "run".to_owned(),
            trigger: Trigger::Interval { interval_secs },
            payload: serde_json::json!({}),
            enabled: true,
            next_run_at: Some(next_run_at),
            created_at: at(1_000),
        }
    }

    fn cron_job(job_id: &str, expression: &str, next_run_at: SystemTime) -> NewJob {
        NewJob {
            job_id: job_id.to_owned(),
            module_id: "reporting-service".to_owned(),
            version: "1.2.0".to_owned(),
            function: "run".to_owned(),
            trigger: Trigger::Cron {
                expression: expression.to_owned(),
            },
            payload: serde_json::json!({}),
            enabled: true,
            next_run_at: Some(next_run_at),
            created_at: at(1_000),
        }
    }

    #[test]
    fn create_and_read_round_trips_without_debugging_payload() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let job = store.create_job(new_job("job-1", true)).expect("create");
        assert_eq!(job.module_id, "reporting-service");
        assert_eq!(job.payload["account"], "example");
        assert!(!format!("{job:?}").contains("example"));

        let stored = store.get_job("job-1").expect("get").expect("exists");
        assert_eq!(stored, job);
        assert!(store.get_job("missing").expect("get").is_none());
        assert!(store.list_jobs(10, 0).expect("list").len() == 1);
    }

    #[test]
    fn disabling_terminalizes_queued_runs_and_blocks_triggers() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        let run = store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("enqueue");
        assert_eq!(run.state, JobRunState::Queued);

        let result = store
            .set_enabled("job-1", false, None, at(3_000))
            .expect("disable")
            .expect("exists");
        assert_eq!(result.cancelled_queued, 1);
        assert!(!result.job.enabled);
        assert!(
            !store
                .get_job("job-1")
                .expect("get")
                .expect("exists")
                .enabled
        );
        let runs = store.list_runs("job-1", 10, 0).expect("runs");
        assert_eq!(runs[0].state, JobRunState::Refused);
        assert_eq!(runs[0].failure_code, Some(JobFailureCode::JobDisabled));
        assert_eq!(
            store
                .enqueue_manual_run("job-1", at(4_000))
                .unwrap_err()
                .to_string(),
            "job is disabled"
        );
    }

    #[test]
    fn two_manual_runs_in_the_same_millisecond_are_distinct() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        let first = store.enqueue_manual_run("job-1", at(2_000)).expect("first");
        let second = store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("second");
        assert_ne!(first.run_id, second.run_id);
        assert_eq!(store.list_runs("job-1", 10, 0).expect("runs").len(), 2);
    }

    #[test]
    fn claim_and_finish_round_trip() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("enqueue");

        let claimed = store
            .claim_next_run("owner-1", at(2_500), Duration::from_secs(30))
            .expect("claim")
            .expect("run");
        assert_eq!(claimed.run.state, JobRunState::Running);
        assert_eq!(claimed.run.claimed_by.as_deref(), Some("owner-1"));
        assert!(claimed.run.started_at.is_some());
        assert!(store
            .claim_next_run("owner-2", at(2_600), Duration::from_secs(30))
            .expect("second claim")
            .is_none());

        let finished = store
            .finish_run(
                &claimed.run.run_id,
                &RunCompletion::succeeded("exec-1".to_owned()),
                at(3_000),
            )
            .expect("finish");
        assert!(finished);
        let runs = store.list_runs("job-1", 10, 0).expect("runs");
        assert_eq!(runs[0].state, JobRunState::Succeeded);
        assert_eq!(runs[0].execution_id.as_deref(), Some("exec-1"));
        assert_eq!(runs[0].outcome.as_deref(), Some("succeeded"));
    }

    #[test]
    fn refused_completion_reads_back() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store
            .create_job(new_job("job-refused", true))
            .expect("create");
        store
            .enqueue_manual_run("job-refused", at(2_000))
            .expect("enqueue");
        let claimed = store
            .claim_next_run("owner-1", at(2_500), Duration::from_secs(30))
            .expect("claim")
            .expect("run");
        store
            .finish_run(
                &claimed.run.run_id,
                &RunCompletion::refused(JobFailureCode::ModuleNotFound),
                at(3_000),
            )
            .expect("finish");
        let runs = store.list_runs("job-refused", 10, 0).expect("runs");
        assert_eq!(runs[0].state, JobRunState::Refused);
        assert_eq!(runs[0].failure_code, Some(JobFailureCode::ModuleNotFound));
    }

    #[test]
    fn recovery_interrupts_running_and_refuses_disabled_queued() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("running");
        store
            .claim_next_run("owner-1", at(2_500), Duration::from_secs(30))
            .expect("claim")
            .expect("run");

        store
            .create_job(new_job("job-2", true))
            .expect("create second");
        store
            .enqueue_manual_run("job-2", at(2_000))
            .expect("queued");
        // Simulate a crash after the job row was disabled but before the
        // disable transaction could terminalize its queued runs.
        store
            .database
            .with_connection(|conn| {
                conn.execute("UPDATE jobs SET enabled = 0 WHERE job_id = 'job-2'", [])
                    .map_err(DatabaseError::from)
            })
            .expect("disable row directly");

        let report = store.recover_startup(at(9_000)).expect("recover");
        assert_eq!(report.interrupted, 1);
        assert_eq!(report.disabled_queued, 1);
        let runs = store.list_runs("job-1", 10, 0).expect("runs");
        assert_eq!(runs[0].state, JobRunState::Interrupted);
        assert_eq!(runs[0].failure_code, Some(JobFailureCode::Interrupted));
        let disabled = store.list_runs("job-2", 10, 0).expect("disabled runs");
        assert_eq!(disabled[0].state, JobRunState::Refused);
        assert_eq!(disabled[0].failure_code, Some(JobFailureCode::JobDisabled));
    }

    #[test]
    fn limits_are_enforced() {
        let store = JobStore::open_in_memory(JobStoreLimits {
            max_jobs: 1,
            max_queued_runs: 1,
        })
        .expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        assert_eq!(
            store
                .create_job(new_job("job-2", true))
                .unwrap_err()
                .to_string(),
            "job limit reached"
        );
        store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("enqueue");
        assert_eq!(
            store
                .enqueue_manual_run("job-1", at(2_001))
                .unwrap_err()
                .to_string(),
            "job queue is full"
        );
    }

    #[test]
    fn tampered_claim_and_execution_ids_fail_closed() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("enqueue");
        let claimed = store
            .claim_next_run("owner-1", at(2_500), Duration::from_secs(30))
            .expect("claim")
            .expect("run");
        store
            .database
            .with_connection(|conn| {
                conn.execute_batch("PRAGMA ignore_check_constraints = ON")?;
                conn.execute(
                    "UPDATE job_runs SET execution_id = ?1 WHERE run_id = ?2",
                    params!["e".repeat(MAX_RUN_ID_BYTES + 1), claimed.run.run_id],
                )?;
                conn.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
                Ok::<(), DatabaseError>(())
            })
            .expect("tamper");
        assert!(store.list_runs("job-1", 10, 0).is_err());
    }

    #[test]
    fn tampered_rows_fail_closed_on_read() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("enqueue");
        store
            .database
            .with_connection(|conn| {
                conn.execute_batch("PRAGMA ignore_check_constraints = ON")?;
                conn.execute(
                    "UPDATE job_runs SET state = 'succeeded', outcome = 'pwned' \
                     WHERE job_id = 'job-1'",
                    [],
                )?;
                conn.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
                Ok::<(), DatabaseError>(())
            })
            .expect("tamper");
        assert!(store.list_runs("job-1", 10, 0).is_err());
    }

    #[test]
    fn out_of_range_interval_rows_are_skipped_not_enqueued() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store
            .create_job(interval_job("job-int", 60, at(60_000)))
            .expect("create");
        store
            .database
            .with_connection(|conn| {
                conn.execute(
                    "UPDATE jobs SET interval_secs = ?1 WHERE job_id = ?2",
                    params![MAX_INTERVAL_SECS as i64 + 1, "job-int"],
                )
                .map_err(DatabaseError::from)
            })
            .expect("tamper interval");

        let report = store.enqueue_due_runs(at(65_000)).expect("enqueue");
        assert_eq!(report, DueEnqueueReport::default());
        assert!(
            store.list_runs("job-int", 10, 0).expect("runs").is_empty(),
            "an out-of-range interval must not enqueue a run"
        );
    }

    #[test]
    fn due_interval_job_enqueues_one_run_and_advances_the_boundary() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store
            .create_job(interval_job("job-int", 60, at(60_000)))
            .expect("create");

        let report = store.enqueue_due_runs(at(65_000)).expect("enqueue");
        assert_eq!(
            report,
            DueEnqueueReport {
                enqueued: 1,
                deduped: 0,
                skipped_full: 0,
                skipped_invalid: 0,
            }
        );
        let runs = store.list_runs("job-int", 10, 0).expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].trigger, TriggerKind::Interval);
        assert_eq!(runs[0].scheduled_for, at(60_000));
        assert_eq!(runs[0].state, JobRunState::Queued);
        assert_eq!(runs[0].attempt_no, 1);
        let job = store.get_job("job-int").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(at(120_000)));
        assert_eq!(job.updated_at, at(65_000));
    }

    #[test]
    fn an_ignored_duplicate_tick_advances_without_a_second_run() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store
            .create_job(interval_job("job-int", 60, at(60_000)))
            .expect("create");
        store.enqueue_due_runs(at(60_000)).expect("first tick");

        // Model a competing tick that still sees the original boundary.
        store
            .database
            .with_connection(|conn| {
                conn.execute(
                    "UPDATE jobs SET next_run_at = 60_000 WHERE job_id = 'job-int'",
                    [],
                )
                .map_err(DatabaseError::from)
            })
            .expect("rewind boundary");

        let report = store.enqueue_due_runs(at(60_000)).expect("second tick");
        assert_eq!(report.enqueued, 0);
        assert_eq!(report.deduped, 1);
        assert_eq!(store.list_runs("job-int", 10, 0).expect("runs").len(), 1);
        let job = store.get_job("job-int").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(at(120_000)));
    }

    #[test]
    fn a_full_queue_leaves_the_due_boundary_for_a_later_tick() {
        let store = JobStore::open_in_memory(JobStoreLimits {
            max_jobs: 4,
            max_queued_runs: 1,
        })
        .expect("store");
        store
            .create_job(interval_job("job-int", 60, at(60_000)))
            .expect("create");
        store
            .enqueue_manual_run("job-int", at(50_000))
            .expect("fill queue");

        let report = store.enqueue_due_runs(at(65_000)).expect("full tick");
        assert_eq!(report.skipped_full, 1);
        assert_eq!(report.enqueued, 0);
        assert_eq!(store.list_runs("job-int", 10, 0).expect("runs").len(), 1);
        let job = store.get_job("job-int").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(at(60_000)));

        let claimed = store
            .claim_next_run("owner-1", at(66_000), Duration::from_secs(30))
            .expect("claim")
            .expect("manual run");
        store
            .finish_run(
                &claimed.run.run_id,
                &RunCompletion::succeeded("exec-1".to_owned()),
                at(67_000),
            )
            .expect("finish");

        let report = store.enqueue_due_runs(at(68_000)).expect("retry tick");
        assert_eq!(report.enqueued, 1);

        let runs = store.list_runs("job-int", 10, 0).expect("runs");
        assert_eq!(runs.len(), 2);
        let interval = runs
            .iter()
            .find(|run| run.trigger == TriggerKind::Interval)
            .expect("interval run");
        assert_eq!(interval.scheduled_for, at(60_000));
        let job = store.get_job("job-int").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(at(120_000)));
    }

    #[test]
    fn queued_counter_bounds_multiple_due_jobs_in_one_tick() {
        let store = JobStore::open_in_memory(JobStoreLimits {
            max_jobs: 4,
            max_queued_runs: 1,
        })
        .expect("store");
        store
            .create_job(interval_job("job-a", 60, at(60_000)))
            .expect("create job-a");
        store
            .create_job(interval_job("job-b", 60, at(60_000)))
            .expect("create job-b");

        let report = store.enqueue_due_runs(at(65_000)).expect("enqueue");
        assert_eq!(report.enqueued, 1);
        assert_eq!(report.skipped_full, 1);
        assert_eq!(report.deduped, 0);
        assert_eq!(store.count_queued().expect("queued count"), 1);

        let first = store.get_job("job-a").expect("get").expect("exists");
        assert_eq!(first.next_run_at, Some(at(120_000)));
        let second = store.get_job("job-b").expect("get").expect("exists");
        assert_eq!(second.next_run_at, Some(at(60_000)));
    }

    #[test]
    fn restart_catch_up_enqueues_one_original_boundary_not_a_burst() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let interval_ms = 60_000;
        store
            .create_job(interval_job("job-int", 60, at(10_000)))
            .expect("create");

        let report = store
            .enqueue_due_runs(at(10_000 + 5 * interval_ms + 3_000))
            .expect("catch-up tick");

        assert_eq!(report.enqueued, 1);
        let runs = store.list_runs("job-int", 10, 0).expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].scheduled_for, at(10_000));
        let job = store.get_job("job-int").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(at(10_000 + 6 * interval_ms)));
    }

    #[test]
    fn due_cron_job_enqueues_one_run_and_advances_the_boundary() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let scheduled = at(CRON_START_MS);
        store
            .create_job(cron_job("job-cron", "* * * * *", scheduled))
            .expect("create");
        let now = at(CRON_START_MS + 5_000);

        let report = store.enqueue_due_runs(now).expect("enqueue");
        assert_eq!(
            report,
            DueEnqueueReport {
                enqueued: 1,
                deduped: 0,
                skipped_full: 0,
                skipped_invalid: 0,
            }
        );
        let runs = store.list_runs("job-cron", 10, 0).expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].trigger, TriggerKind::Cron);
        assert_eq!(runs[0].scheduled_for, scheduled);
        assert_eq!(runs[0].state, JobRunState::Queued);
        assert_eq!(runs[0].attempt_no, 1);
        let job = store.get_job("job-cron").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(at(CRON_START_MS + MINUTE_MS)));
        assert_eq!(job.updated_at, now);

        let report = store.enqueue_due_runs(now).expect("second tick");
        assert_eq!(report, DueEnqueueReport::default());
        assert_eq!(
            store.list_runs("job-cron", 10, 0).expect("runs").len(),
            1,
            "the advanced boundary must not enqueue again"
        );
    }

    #[test]
    fn an_ignored_cron_duplicate_tick_advances_without_a_second_run() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let scheduled = at(CRON_START_MS);
        store
            .create_job(cron_job("job-cron", "* * * * *", scheduled))
            .expect("create");
        let now = at(CRON_START_MS + 5_000);
        store.enqueue_due_runs(now).expect("first tick");
        store
            .database
            .with_connection(|conn| {
                conn.execute(
                    "UPDATE jobs SET next_run_at = ?1 WHERE job_id = 'job-cron'",
                    params![CRON_START_MS as i64],
                )
                .map_err(DatabaseError::from)
            })
            .expect("rewind boundary");

        let report = store.enqueue_due_runs(now).expect("second tick");
        assert_eq!(report.enqueued, 0);
        assert_eq!(report.deduped, 1);
        assert_eq!(store.list_runs("job-cron", 10, 0).expect("runs").len(), 1);
        let job = store.get_job("job-cron").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(at(CRON_START_MS + MINUTE_MS)));
    }

    #[test]
    fn cron_restart_catch_up_enqueues_one_original_boundary_not_a_burst() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let scheduled = at(CRON_START_MS);
        store
            .create_job(cron_job("job-cron", "* * * * *", scheduled))
            .expect("create");

        let report = store
            .enqueue_due_runs(at(CRON_START_MS + 5 * MINUTE_MS + 3_000))
            .expect("catch-up tick");

        assert_eq!(report.enqueued, 1);
        let runs = store.list_runs("job-cron", 10, 0).expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].scheduled_for, scheduled);
        let job = store.get_job("job-cron").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(at(CRON_START_MS + 6 * MINUTE_MS)));
    }

    #[test]
    fn a_disabled_cron_job_is_not_selected() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let scheduled = at(CRON_START_MS);
        store
            .create_job(cron_job("job-cron", "* * * * *", scheduled))
            .expect("create");
        store
            .set_enabled("job-cron", false, None, at(CRON_START_MS - 1_000))
            .expect("disable")
            .expect("exists");

        let report = store
            .enqueue_due_runs(at(CRON_START_MS + 5_000))
            .expect("enqueue");
        assert_eq!(report, DueEnqueueReport::default());
        assert!(
            store.list_runs("job-cron", 10, 0).expect("runs").is_empty(),
            "a disabled cron job must not enqueue"
        );
        let job = store.get_job("job-cron").expect("get").expect("exists");
        assert_eq!(job.next_run_at, None);
    }

    #[test]
    fn a_full_queue_leaves_the_due_cron_boundary_for_a_later_tick() {
        let store = JobStore::open_in_memory(JobStoreLimits {
            max_jobs: 4,
            max_queued_runs: 1,
        })
        .expect("store");
        let scheduled = at(CRON_START_MS);
        store
            .create_job(cron_job("job-cron", "* * * * *", scheduled))
            .expect("create");
        let now = at(CRON_START_MS + 5_000);
        store
            .enqueue_manual_run("job-cron", at(CRON_START_MS - 10_000))
            .expect("fill queue");

        let report = store.enqueue_due_runs(now).expect("full tick");
        assert_eq!(report.skipped_full, 1);
        assert_eq!(report.enqueued, 0);
        assert_eq!(
            store
                .list_runs("job-cron", 10, 0)
                .expect("runs")
                .iter()
                .filter(|run| run.trigger == TriggerKind::Cron)
                .count(),
            0
        );
        let job = store.get_job("job-cron").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(scheduled));

        let claimed = store
            .claim_next_run(
                "owner-1",
                at(CRON_START_MS + 6_000),
                Duration::from_secs(30),
            )
            .expect("claim")
            .expect("manual run");
        store
            .finish_run(
                &claimed.run.run_id,
                &RunCompletion::succeeded("exec-1".to_owned()),
                at(CRON_START_MS + 7_000),
            )
            .expect("finish");

        let report = store.enqueue_due_runs(now).expect("retry tick");
        assert_eq!(report.enqueued, 1);
        let runs = store.list_runs("job-cron", 10, 0).expect("runs");
        let cron = runs
            .iter()
            .find(|run| run.trigger == TriggerKind::Cron)
            .expect("cron run");
        assert_eq!(cron.scheduled_for, scheduled);
        let job = store.get_job("job-cron").expect("get").expect("exists");
        assert_eq!(job.next_run_at, Some(at(CRON_START_MS + MINUTE_MS)));
    }

    #[test]
    fn tampered_cron_rows_are_skipped_and_fail_closed_on_read() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let scheduled = at(CRON_START_MS);
        store
            .create_job(cron_job("job-cron", "* * * * *", scheduled))
            .expect("create");
        store
            .database
            .with_connection(|conn| {
                conn.execute(
                    "UPDATE jobs SET cron_expr = 'not a cron' WHERE job_id = 'job-cron'",
                    [],
                )
                .map_err(DatabaseError::from)
            })
            .expect("tamper cron");

        let report = store
            .enqueue_due_runs(at(CRON_START_MS + 5_000))
            .expect("the pass must not fail");
        assert_eq!(report.skipped_invalid, 1);
        assert_eq!(report.enqueued, 0);
        assert!(store.list_runs("job-cron", 10, 0).expect("runs").is_empty());
        assert!(
            store.get_job("job-cron").is_err(),
            "a tampered cron row must fail closed on read"
        );
        let boundary: Option<i64> = store
            .database
            .with_connection(|conn| {
                conn.query_row(
                    "SELECT next_run_at FROM jobs WHERE job_id = 'job-cron'",
                    [],
                    |row| row.get(0),
                )
                .map_err(DatabaseError::from)
            })
            .expect("boundary");
        assert_eq!(boundary, Some(CRON_START_MS as i64));
    }

    #[test]
    fn invalid_utf8_and_blob_cron_rows_are_skipped_not_failed() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let scheduled = at(CRON_START_MS);
        for job_id in ["job-invalid-utf8", "job-blob-cron", "job-blob-id"] {
            store
                .create_job(cron_job(job_id, "* * * * *", scheduled))
                .expect("create");
        }
        store
            .database
            .with_connection(|conn| {
                conn.execute(
                    "UPDATE jobs SET cron_expr = CAST(?1 AS BLOB) WHERE job_id = 'job-invalid-utf8'",
                    params![&[0xffu8][..]],
                )?;
                conn.execute(
                    "UPDATE jobs SET cron_expr = CAST(?1 AS BLOB) WHERE job_id = 'job-blob-cron'",
                    params![&b"* * * * *"[..]],
                )?;
                conn.execute(
                    "UPDATE jobs SET job_id = CAST(?1 AS BLOB) WHERE job_id = 'job-blob-id'",
                    params![&b"job-blob-id"[..]],
                )?;
                Ok::<(), DatabaseError>(())
            })
            .expect("tamper rows");

        let report = store
            .enqueue_due_runs(at(CRON_START_MS + 5_000))
            .expect("the pass must not fail");
        assert_eq!(report.skipped_invalid, 3);
        assert_eq!(report.enqueued, 0);
        assert_eq!(store.count_queued().expect("queued count"), 0);
        assert!(store
            .list_runs("job-invalid-utf8", 10, 0)
            .expect("runs")
            .is_empty());
        assert!(store
            .list_runs("job-blob-cron", 10, 0)
            .expect("runs")
            .is_empty());
        assert!(
            store.get_job("job-invalid-utf8").is_err(),
            "invalid UTF-8 must fail closed on read"
        );
        assert!(
            store.get_job("job-blob-cron").is_err(),
            "a BLOB cron expression must fail closed on read"
        );
        let boundaries: Vec<i64> = store
            .database
            .with_connection(|conn| {
                let mut statement = conn.prepare("SELECT next_run_at FROM jobs ORDER BY rowid")?;
                let rows = statement.query_map([], |row| row.get(0))?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(row?);
                }
                Ok::<_, DatabaseError>(values)
            })
            .expect("boundaries");
        assert_eq!(boundaries, vec![CRON_START_MS as i64; 3]);
    }

    #[test]
    fn impossible_cron_rows_are_skipped_and_keep_the_boundary() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let scheduled = at(CRON_START_MS);
        store
            .create_job(cron_job("job-cron", "0 0 31 2 *", scheduled))
            .expect("create");

        let report = store
            .enqueue_due_runs(at(CRON_START_MS + 5_000))
            .expect("the pass must not fail");
        assert_eq!(report.skipped_invalid, 1);
        assert_eq!(report.enqueued, 0);
        assert!(store.list_runs("job-cron", 10, 0).expect("runs").is_empty());
        let job = store.get_job("job-cron").expect("get").expect("exists");
        assert_eq!(
            job.next_run_at,
            Some(scheduled),
            "an impossible expression must not advance the boundary"
        );
    }

    #[test]
    fn a_tampered_cron_row_carrying_an_interval_is_not_selected() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let scheduled = at(CRON_START_MS);
        store
            .create_job(cron_job("job-cron", "* * * * *", scheduled))
            .expect("create");
        store
            .database
            .with_connection(|conn| {
                conn.execute_batch("PRAGMA ignore_check_constraints = ON")?;
                conn.execute(
                    "UPDATE jobs SET interval_secs = 60 WHERE job_id = 'job-cron'",
                    [],
                )?;
                conn.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
                Ok::<(), DatabaseError>(())
            })
            .expect("tamper interval");

        let report = store
            .enqueue_due_runs(at(CRON_START_MS + 5_000))
            .expect("the pass must not fail");
        assert_eq!(report, DueEnqueueReport::default());
        assert!(store.list_runs("job-cron", 10, 0).expect("runs").is_empty());
        assert!(
            store.get_job("job-cron").is_err(),
            "the malformed row stays fail-closed on read"
        );
        let boundary: Option<i64> = store
            .database
            .with_connection(|conn| {
                conn.query_row(
                    "SELECT next_run_at FROM jobs WHERE job_id = 'job-cron'",
                    [],
                    |row| row.get(0),
                )
                .map_err(DatabaseError::from)
            })
            .expect("boundary");
        assert_eq!(boundary, Some(CRON_START_MS as i64));
    }

    #[test]
    fn equal_boundaries_enqueue_the_lower_job_id_first() {
        let store = JobStore::open_in_memory(JobStoreLimits {
            max_jobs: 4,
            max_queued_runs: 1,
        })
        .expect("store");
        let scheduled = at(CRON_START_MS);
        store
            .create_job(cron_job("job-b", "* * * * *", scheduled))
            .expect("create b");
        store
            .create_job(cron_job("job-a", "* * * * *", scheduled))
            .expect("create a");

        let report = store
            .enqueue_due_runs(at(CRON_START_MS + 5_000))
            .expect("enqueue");
        assert_eq!(report.enqueued, 1);
        assert_eq!(report.skipped_full, 1);
        assert_eq!(
            store.list_runs("job-a", 10, 0).expect("runs a").len(),
            1,
            "the lower job id wins a tied boundary"
        );
        assert!(store.list_runs("job-b", 10, 0).expect("runs b").is_empty());
        let first = store.get_job("job-a").expect("get a").expect("exists");
        assert_eq!(first.next_run_at, Some(at(CRON_START_MS + MINUTE_MS)));
        let second = store.get_job("job-b").expect("get b").expect("exists");
        assert_eq!(second.next_run_at, Some(scheduled));
    }

    #[test]
    fn mixed_interval_and_cron_due_jobs_share_one_queue_bound() {
        let store = JobStore::open_in_memory(JobStoreLimits {
            max_jobs: 4,
            max_queued_runs: 1,
        })
        .expect("store");
        store
            .create_job(interval_job("job-int", 60, at(CRON_START_MS)))
            .expect("create interval");
        store
            .create_job(cron_job(
                "job-cron",
                "* * * * *",
                at(CRON_START_MS + 30_000),
            ))
            .expect("create cron");
        let now = at(CRON_START_MS + 5 * MINUTE_MS);

        let report = store.enqueue_due_runs(now).expect("enqueue");
        assert_eq!(report.enqueued, 1);
        assert_eq!(report.skipped_full, 1);
        assert_eq!(store.count_queued().expect("queued count"), 1);

        let runs = store.list_runs("job-int", 10, 0).expect("interval runs");
        assert_eq!(runs.len(), 1, "the earlier boundary wins the one slot");
        assert_eq!(runs[0].trigger, TriggerKind::Interval);
        assert!(
            store
                .list_runs("job-cron", 10, 0)
                .expect("cron runs")
                .is_empty(),
            "the later cron boundary must not get a run"
        );
        let interval = store.get_job("job-int").expect("get").expect("exists");
        assert_eq!(
            interval.next_run_at,
            Some(at(CRON_START_MS + 6 * MINUTE_MS))
        );
        let cron = store.get_job("job-cron").expect("get").expect("exists");
        assert_eq!(cron.next_run_at, Some(at(CRON_START_MS + 30_000)));
    }

    #[test]
    fn retry_enqueue_inserts_one_queued_attempt_and_keeps_next_run_at() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let cases = [
            (
                "job-manual",
                TriggerKind::Manual,
                new_job("job-manual", true),
            ),
            (
                "job-interval",
                TriggerKind::Interval,
                interval_job("job-interval", 60, at(60_000)),
            ),
            (
                "job-cron",
                TriggerKind::Cron,
                cron_job("job-cron", "* * * * *", at(CRON_START_MS)),
            ),
        ];
        for (job_id, trigger, job) in cases {
            store.create_job(job).expect("create");
            let before = store.get_job(job_id).expect("get").expect("exists");
            let retry_at = at(90_000);
            let now = at(85_000);
            let run = store
                .enqueue_retry(job_id, trigger, 2, retry_at, now)
                .expect("enqueue retry")
                .expect("inserted");

            assert_eq!(run.job_id, job_id);
            assert_eq!(run.attempt_no, 2);
            assert_eq!(run.trigger, trigger);
            assert_eq!(run.scheduled_for, retry_at);
            assert_eq!(run.created_at, now);
            assert_eq!(run.state, JobRunState::Queued);
            assert!(run.claimed_by.is_none());
            assert!(run.execution_id.is_none());
            assert!(run.started_at.is_none());
            assert_eq!(store.list_runs(job_id, 10, 0).expect("runs"), vec![run]);

            let after = store.get_job(job_id).expect("get").expect("exists");
            assert_eq!(after.next_run_at, before.next_run_at);
            assert_eq!(after.updated_at, before.updated_at);
        }
    }

    #[test]
    fn retry_is_not_enqueued_for_a_missing_or_disabled_job() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        assert!(store
            .enqueue_retry("missing", TriggerKind::Manual, 2, at(10_000), at(5_000))
            .expect("missing job")
            .is_none());

        store.create_job(new_job("job-1", true)).expect("create");
        store
            .set_enabled("job-1", false, None, at(2_000))
            .expect("disable")
            .expect("exists");
        assert!(store
            .enqueue_retry("job-1", TriggerKind::Manual, 2, at(10_000), at(5_000))
            .expect("disabled job")
            .is_none());
        assert!(store.list_runs("job-1", 10, 0).expect("runs").is_empty());
    }

    #[test]
    fn retry_is_dropped_when_the_queue_is_full() {
        let store = JobStore::open_in_memory(JobStoreLimits {
            max_jobs: 4,
            max_queued_runs: 1,
        })
        .expect("store");
        store
            .create_job(interval_job("job-int", 60, at(60_000)))
            .expect("create");
        store
            .enqueue_manual_run("job-int", at(50_000))
            .expect("fill queue");

        assert!(store
            .enqueue_retry("job-int", TriggerKind::Interval, 2, at(90_000), at(85_000))
            .expect("a full queue is a skip, not an error")
            .is_none());
        assert_eq!(store.list_runs("job-int", 10, 0).expect("runs").len(), 1);
    }

    #[test]
    fn an_identical_retry_tick_is_ignored() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        let cases = [
            (
                "job-interval",
                TriggerKind::Interval,
                interval_job("job-interval", 60, at(60_000)),
            ),
            (
                "job-cron",
                TriggerKind::Cron,
                cron_job("job-cron", "* * * * *", at(CRON_START_MS)),
            ),
        ];
        for (job_id, trigger, job) in cases {
            store.create_job(job).expect("create");
            assert!(store
                .enqueue_retry(job_id, trigger, 2, at(90_000), at(85_000))
                .expect("first retry")
                .is_some());
            assert!(store
                .enqueue_retry(job_id, trigger, 2, at(90_000), at(85_000))
                .expect("duplicate retry")
                .is_none());
            assert_eq!(store.list_runs(job_id, 10, 0).expect("runs").len(), 1);
        }
    }

    #[test]
    fn retry_rejects_attempt_numbers_below_two() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        for attempt_no in [0, 1] {
            assert!(
                matches!(
                    store.enqueue_retry(
                        "job-1",
                        TriggerKind::Manual,
                        attempt_no,
                        at(10_000),
                        at(5_000)
                    ),
                    Err(JobStoreError::InvalidRun(_))
                ),
                "attempt {attempt_no} is not a retry"
            );
        }
        assert!(store.list_runs("job-1", 10, 0).expect("runs").is_empty());
    }

    #[test]
    fn claim_honors_a_future_retry_scheduled_for() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store
            .create_job(interval_job("job-int", 60, at(60_000)))
            .expect("create");
        let retry = store
            .enqueue_retry("job-int", TriggerKind::Interval, 2, at(10_000), at(5_000))
            .expect("retry")
            .expect("inserted");

        assert!(store
            .claim_next_run("owner-1", at(9_999), Duration::from_secs(30))
            .expect("early claim")
            .is_none());
        let claimed = store
            .claim_next_run("owner-1", at(10_000), Duration::from_secs(30))
            .expect("claim")
            .expect("due retry");
        assert_eq!(claimed.run.run_id, retry.run_id);
        assert_eq!(claimed.run.attempt_no, 2);
        store
            .finish_run(
                &claimed.run.run_id,
                &RunCompletion::succeeded("exec-1".to_owned()),
                at(10_100),
            )
            .expect("finish");

        store
            .enqueue_manual_run("job-int", at(10_000))
            .expect("manual run");
        let manual = store
            .claim_next_run("owner-1", at(10_001), Duration::from_secs(30))
            .expect("claim manual")
            .expect("manual due");
        assert_eq!(manual.run.trigger, TriggerKind::Manual);
    }

    #[test]
    fn cancelling_a_queued_run_terminalizes_it_without_a_claim() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        let run = store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("enqueue");

        let cancelled = store
            .request_run_cancel("job-1", &run.run_id, at(3_000))
            .expect("cancel");
        let RunCancel::Queued(updated) = cancelled else {
            panic!("expected a queued cancellation, got {cancelled:?}");
        };
        assert_eq!(updated.state, JobRunState::Failed);
        assert_eq!(updated.outcome.as_deref(), Some("cancelled"));
        assert_eq!(updated.finished_at, Some(at(3_000)));
        assert!(updated.execution_id.is_none());

        assert!(
            store
                .claim_next_run("owner-1", at(4_000), Duration::from_secs(30))
                .expect("claim")
                .is_none(),
            "a cancelled queued run must not be claimable"
        );
        assert_eq!(
            store.get_run("job-1", &run.run_id).expect("get"),
            Some(updated)
        );
        let job = store.get_job("job-1").expect("get job").expect("exists");
        assert!(job.enabled, "cancelling a run must not disable the job");
    }

    #[test]
    fn cancelling_a_running_run_reports_running_without_mutation() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        let run = store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("enqueue");
        store
            .claim_next_run("owner-1", at(2_500), Duration::from_secs(30))
            .expect("claim")
            .expect("run");
        let before = store
            .get_run("job-1", &run.run_id)
            .expect("get")
            .expect("exists");

        assert_eq!(
            store
                .request_run_cancel("job-1", &run.run_id, at(3_000))
                .expect("cancel"),
            RunCancel::Running
        );
        assert_eq!(
            store.get_run("job-1", &run.run_id).expect("get"),
            Some(before),
            "the running row must be left for the dispatch task to finish"
        );
    }

    #[test]
    fn cancel_requires_matching_job_and_rejects_terminal_or_missing_runs() {
        let store = JobStore::open_in_memory(limits()).expect("store");
        store.create_job(new_job("job-1", true)).expect("create");
        store.create_job(new_job("job-2", true)).expect("create");
        let run = store
            .enqueue_manual_run("job-1", at(2_000))
            .expect("enqueue");
        let claimed = store
            .claim_next_run("owner-1", at(2_500), Duration::from_secs(30))
            .expect("claim")
            .expect("run");
        store
            .finish_run(
                &claimed.run.run_id,
                &RunCompletion::succeeded("exec-1".to_owned()),
                at(3_000),
            )
            .expect("finish");

        assert_eq!(
            store
                .request_run_cancel("job-2", &run.run_id, at(4_000))
                .expect("wrong job"),
            RunCancel::NotFound,
            "a run must not be addressable through another job"
        );
        assert_eq!(
            store
                .request_run_cancel("job-1", "missing-run", at(4_000))
                .expect("missing run"),
            RunCancel::NotFound
        );
        let terminal = store
            .request_run_cancel("job-1", &run.run_id, at(4_000))
            .expect("terminal");
        let RunCancel::Terminal(row) = terminal else {
            panic!("expected a terminal row, got {terminal:?}");
        };
        assert_eq!(row.state, JobRunState::Succeeded);
        assert_eq!(row.execution_id.as_deref(), Some("exec-1"));
    }
}
