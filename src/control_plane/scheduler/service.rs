//! Single-process scheduler lifecycle and dispatcher.
//!
//! One loop claims queued runs and hands them to the pinned execution
//! adapter. It owns readiness, job metrics, and startup recovery; it never
//! touches registry, artifact, staging, or worker-spawn state directly.

use std::fmt;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use thiserror::Error;
use tokio::sync::Notify;
use tokio::task::{JoinError, JoinSet};

use crate::control_plane::execute_module::{ExecutionError, ExecutionService};
use crate::executions::executor::ExecutionOutcome;
use crate::metrics::{JobActiveGuard, Metrics};
use crate::readiness::Readiness;

use super::dispatch::ExecutionDispatcher;
use super::job::{
    classify_execution_error, ClaimedRun, JobDefinition, JobRun, NewJob, RunCompletion,
    DEFAULT_JOB_DEADLINE_SECS,
};
use super::store::{DueEnqueueReport, EnableResult, JobStore, JobStoreError, JobStoreLimits};

/// Scheduler tuning.
#[derive(Clone, Debug)]
pub struct SchedulerConfig {
    pub tick_interval: Duration,
    pub lease_ttl: Duration,
    pub max_concurrent_runs: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(1),
            lease_ttl: Duration::from_secs(30),
            max_concurrent_runs: 4,
        }
    }
}

/// Lifecycle state used to gate manual triggers and readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SchedulerState {
    NotStarted = 0,
    Running = 1,
    Stopping = 2,
    Failed = 3,
}

impl SchedulerState {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::Stopping,
            3 => Self::Failed,
            _ => Self::NotStarted,
        }
    }
}

/// Scheduler failures. Every variant is a host-side condition; API callers
/// map them to stable codes.
#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error(transparent)]
    Store(#[from] JobStoreError),
    #[error("scheduler is already started")]
    AlreadyStarted,
    #[error("scheduler is not running")]
    NotRunning,
    #[error("scheduler task failed: {0}")]
    Task(String),
}

/// One scheduler per host.
pub struct SchedulerService {
    store: Arc<JobStore>,
    dispatcher: Arc<ExecutionDispatcher>,
    metrics: Arc<Metrics>,
    readiness: Arc<Readiness>,
    config: SchedulerConfig,
    state: AtomicU8,
    owner_id: String,
    active: Arc<AtomicUsize>,
    notify: Notify,
    loop_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for SchedulerService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchedulerService")
            .field("state", &self.state())
            .field("max_concurrent_runs", &self.config.max_concurrent_runs)
            .finish_non_exhaustive()
    }
}

impl SchedulerService {
    #[must_use]
    pub fn new(
        store: Arc<JobStore>,
        dispatcher: Arc<ExecutionDispatcher>,
        metrics: Arc<Metrics>,
        readiness: Arc<Readiness>,
        config: SchedulerConfig,
    ) -> Self {
        Self {
            store,
            dispatcher,
            metrics,
            readiness,
            config,
            state: AtomicU8::new(SchedulerState::NotStarted as u8),
            owner_id: format!("scheduler-{}-{}", std::process::id(), next_owner_suffix()),
            active: Arc::new(AtomicUsize::new(0)),
            notify: Notify::new(),
            loop_handle: Mutex::new(None),
        }
    }

    /// Test/embedding facade for router fixtures that do not need the host
    /// database. Production uses [`new`](Self::new) with the shared store.
    #[doc(hidden)]
    pub fn in_memory_for_test(
        execution_service: Arc<ExecutionService>,
        metrics: Arc<Metrics>,
        readiness: Arc<Readiness>,
        max_concurrent_runs: usize,
    ) -> Result<Self, SchedulerError> {
        let store = JobStore::open_in_memory(JobStoreLimits::default())?;
        Ok(Self::new(
            Arc::new(store),
            Arc::new(ExecutionDispatcher::new(execution_service)),
            metrics,
            readiness,
            SchedulerConfig {
                max_concurrent_runs,
                ..SchedulerConfig::default()
            },
        ))
    }

    #[must_use]
    pub fn state(&self) -> SchedulerState {
        SchedulerState::from_u8(self.state.load(Ordering::Relaxed))
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.state() == SchedulerState::Running
    }

    /// Recovers interrupted runs, starts the loop, and awaits its ready
    /// handshake. On failure the host must not bind a listener.
    pub async fn start(self: &Arc<Self>) -> Result<(), SchedulerError> {
        if self
            .state
            .compare_exchange(
                SchedulerState::NotStarted as u8,
                SchedulerState::Running as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(SchedulerError::AlreadyStarted);
        }

        let store = Arc::clone(&self.store);
        let now = SystemTime::now();
        let recovery = match tokio::task::spawn_blocking(move || store.recover_startup(now)).await {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => {
                self.state
                    .store(SchedulerState::Failed as u8, Ordering::Release);
                self.readiness.set_scheduler_ready(false);
                return Err(SchedulerError::Store(error));
            }
            Err(error) => {
                self.state
                    .store(SchedulerState::Failed as u8, Ordering::Release);
                self.readiness.set_scheduler_ready(false);
                return Err(task_error(error));
            }
        };
        if recovery.interrupted > 0 || recovery.disabled_queued > 0 {
            tracing::info!(
                interrupted = recovery.interrupted,
                disabled_queued = recovery.disabled_queued,
                "scheduler recovered interrupted runs"
            );
        }
        let queued = match self.count_queued().await {
            Ok(count) => count,
            Err(error) => {
                self.state
                    .store(SchedulerState::Failed as u8, Ordering::Release);
                self.readiness.set_scheduler_ready(false);
                return Err(error);
            }
        };
        self.metrics.initialize_job_queue_depth(queued);

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let service = Arc::clone(self);
        let handle = tokio::spawn(async move {
            service.run_loop(ready_tx).await;
        });
        *self
            .loop_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle);
        let ready = tokio::time::timeout(Duration::from_secs(5), ready_rx).await;
        match ready {
            Ok(Ok(())) if self.state() == SchedulerState::Running => {
                self.readiness.set_scheduler_ready(true);
                tracing::info!("scheduler loop started");
                Ok(())
            }
            Ok(Ok(())) => {
                self.readiness.set_scheduler_ready(false);
                Err(SchedulerError::Task(
                    "scheduler loop failed during startup".to_owned(),
                ))
            }
            Ok(Err(_)) => {
                self.state
                    .store(SchedulerState::Failed as u8, Ordering::Release);
                self.readiness.set_scheduler_ready(false);
                Err(SchedulerError::Task(
                    "scheduler loop exited before ready".to_owned(),
                ))
            }
            Err(_) => {
                self.state
                    .store(SchedulerState::Failed as u8, Ordering::Release);
                self.readiness.set_scheduler_ready(false);
                Err(SchedulerError::Task(
                    "scheduler loop ready handshake timed out".to_owned(),
                ))
            }
        }
    }

    /// Stops the loop and clears readiness. In-flight dispatch tasks are
    /// aborted; startup recovery will mark their rows interrupted.
    pub async fn stop(&self) {
        if self.state() == SchedulerState::NotStarted {
            return;
        }
        self.state
            .store(SchedulerState::Stopping as u8, Ordering::Release);
        self.readiness.set_scheduler_ready(false);
        self.notify.notify_waiters();
        let handle = self
            .loop_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
        tracing::info!("scheduler loop stopped");
    }

    /// Deterministic one-shot tick used by tests. It enqueues due interval
    /// and cron runs, then claims and awaits dispatch of every run up to
    /// capacity.
    #[doc(hidden)]
    pub async fn tick_once(&self, now: SystemTime) -> Result<usize, SchedulerError> {
        self.enqueue_due(now).await?;
        let mut dispatched = 0;
        while self.active.load(Ordering::Relaxed) < self.config.max_concurrent_runs {
            let Some(claimed) = self.claim_next(now).await? else {
                break;
            };
            let guard = self.begin_run();
            self.dispatch_claimed(claimed, now, guard).await;
            dispatched += 1;
        }
        Ok(dispatched)
    }

    pub async fn create_job(&self, new: NewJob) -> Result<JobDefinition, SchedulerError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.create_job(new))
            .await
            .map_err(task_error)?
            .map_err(SchedulerError::from)
    }

    pub async fn list_jobs(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JobDefinition>, SchedulerError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.list_jobs(limit, offset))
            .await
            .map_err(task_error)?
            .map_err(SchedulerError::from)
    }

    pub async fn set_enabled(
        &self,
        job_id: &str,
        enabled: bool,
        next_run_at: Option<SystemTime>,
    ) -> Result<Option<EnableResult>, SchedulerError> {
        let store = Arc::clone(&self.store);
        let job_id = job_id.to_owned();
        let now = SystemTime::now();
        let result = tokio::task::spawn_blocking(move || {
            store.set_enabled(&job_id, enabled, next_run_at, now)
        })
        .await
        .map_err(task_error)?
        .map_err(SchedulerError::from)?;
        if let Some(result) = &result {
            self.metrics
                .job_terminalized_queued(result.cancelled_queued);
        }
        Ok(result)
    }

    /// Enqueues a manual run, wakes the loop, and updates the queue gauge.
    pub async fn trigger_manual(&self, job_id: &str) -> Result<JobRun, SchedulerError> {
        if !self.is_running() {
            return Err(SchedulerError::NotRunning);
        }
        self.enqueue_manual(job_id).await
    }

    /// Enqueues without the lifecycle gate. Used by the trigger path after
    /// the gate and by deterministic service tests.
    pub async fn enqueue_manual(&self, job_id: &str) -> Result<JobRun, SchedulerError> {
        let store = Arc::clone(&self.store);
        let job_id = job_id.to_owned();
        let now = SystemTime::now();
        let run = tokio::task::spawn_blocking(move || store.enqueue_manual_run(&job_id, now))
            .await
            .map_err(task_error)?
            .map_err(SchedulerError::from)?;
        self.metrics.job_enqueued();
        self.notify.notify_one();
        Ok(run)
    }

    pub async fn list_runs(
        &self,
        job_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<JobRun>, SchedulerError> {
        let store = Arc::clone(&self.store);
        let job_id = job_id.to_owned();
        tokio::task::spawn_blocking(move || store.list_runs(&job_id, limit, offset))
            .await
            .map_err(task_error)?
            .map_err(SchedulerError::from)
    }

    pub async fn get_job(&self, job_id: &str) -> Result<Option<JobDefinition>, SchedulerError> {
        let store = Arc::clone(&self.store);
        let job_id = job_id.to_owned();
        tokio::task::spawn_blocking(move || store.get_job(&job_id))
            .await
            .map_err(task_error)?
            .map_err(SchedulerError::from)
    }

    async fn count_queued(&self) -> Result<usize, SchedulerError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.count_queued())
            .await
            .map_err(task_error)?
            .map_err(SchedulerError::from)
    }

    async fn enqueue_due(&self, now: SystemTime) -> Result<DueEnqueueReport, SchedulerError> {
        let store = Arc::clone(&self.store);
        let report = tokio::task::spawn_blocking(move || store.enqueue_due_runs(now))
            .await
            .map_err(task_error)?
            .map_err(SchedulerError::from)?;
        for _ in 0..report.enqueued {
            self.metrics.job_enqueued();
        }
        tracing::debug!(
            enqueued = report.enqueued,
            deduped = report.deduped,
            skipped_full = report.skipped_full,
            skipped_invalid = report.skipped_invalid,
            "scheduler enqueued due interval/cron runs"
        );
        Ok(report)
    }

    async fn claim_next(&self, now: SystemTime) -> Result<Option<ClaimedRun>, SchedulerError> {
        let store = Arc::clone(&self.store);
        let owner = self.owner_id.clone();
        let lease = self.config.lease_ttl;
        tokio::task::spawn_blocking(move || store.claim_next_run(&owner, now, lease))
            .await
            .map_err(task_error)?
            .map_err(SchedulerError::from)
    }

    fn begin_run(&self) -> ActiveRun {
        self.active.fetch_add(1, Ordering::Relaxed);
        ActiveRun {
            active: Arc::clone(&self.active),
            _metrics: self.metrics.job_claimed(),
        }
    }

    async fn dispatch_claimed(
        &self,
        claimed: ClaimedRun,
        claimed_at: SystemTime,
        guard: ActiveRun,
    ) {
        let wait = claimed_at
            .duration_since(claimed.run.scheduled_for)
            .unwrap_or_default();
        self.metrics.record_job_wait(wait);

        let deadline = self
            .dispatcher
            .max_deadline()
            .min(Duration::from_secs(DEFAULT_JOB_DEADLINE_SECS));
        let completion = match self
            .dispatcher
            .execute(
                &claimed.job.module_id,
                &claimed.job.version,
                &claimed.job.function,
                claimed.job.payload.clone(),
                deadline,
            )
            .await
        {
            Ok(receipt) => match receipt.outcome {
                ExecutionOutcome::Succeeded { .. } => {
                    RunCompletion::succeeded(receipt.execution_id)
                }
                outcome => RunCompletion::worker_failure(receipt.execution_id, outcome.as_str()),
            },
            Err(error) => {
                let code = classify_execution_error(&error);
                if matches!(error, ExecutionError::History(_)) {
                    RunCompletion::failed(code)
                } else {
                    RunCompletion::refused(code)
                }
            }
        };

        let store = Arc::clone(&self.store);
        let run_id = claimed.run.run_id.clone();
        let now = claimed
            .run
            .started_at
            .map(|started| SystemTime::now().max(started))
            .unwrap_or_else(SystemTime::now);
        let state = completion.state.as_str();
        let outcome = completion.outcome.clone();
        let failure_code = completion.failure_code;
        let persisted =
            tokio::task::spawn_blocking(move || store.finish_run(&run_id, &completion, now)).await;
        match persisted {
            Ok(Ok(true)) => {
                tracing::info!(
                    job_id = %claimed.job.job_id,
                    run_id = %claimed.run.run_id,
                    state,
                    outcome = outcome.as_deref().unwrap_or(""),
                    failure_code = failure_code.map(|code| code.as_str()).unwrap_or(""),
                    "job run finished"
                );
            }
            Ok(Ok(false)) => {
                tracing::warn!(
                    run_id = %claimed.run.run_id,
                    "job run completion did not update a running row"
                );
            }
            Ok(Err(error)) => {
                self.fail(SchedulerError::Store(error));
            }
            Err(error) => {
                self.fail(task_error(error));
            }
        }
        drop(guard);
    }

    async fn fill_slots(
        self: &Arc<Self>,
        join_set: &mut JoinSet<()>,
    ) -> Result<(), SchedulerError> {
        self.enqueue_due(SystemTime::now()).await?;
        while self.active.load(Ordering::Relaxed) < self.config.max_concurrent_runs {
            let now = SystemTime::now();
            let Some(claimed) = self.claim_next(now).await? else {
                break;
            };
            let guard = self.begin_run();
            let service = Arc::clone(self);
            join_set.spawn(async move {
                service.dispatch_claimed(claimed, now, guard).await;
            });
        }
        Ok(())
    }

    async fn run_loop(self: Arc<Self>, ready: tokio::sync::oneshot::Sender<()>) {
        let _guard = LoopGuard {
            service: Arc::clone(&self),
        };
        let _ = ready.send(());
        let mut ticker = tokio::time::interval(self.config.tick_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut join_set = JoinSet::new();
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = self.notify.notified() => {}
                Some(result) = join_set.join_next() => {
                    if let Err(error) = result {
                        if error.is_panic() {
                            self.fail(SchedulerError::Task(error.to_string()));
                        }
                    }
                    continue;
                }
            }
            if self.state() != SchedulerState::Running {
                break;
            }
            if let Err(error) = self.fill_slots(&mut join_set).await {
                self.fail(error);
                break;
            }
        }
        join_set.shutdown().await;
    }

    fn fail(&self, error: SchedulerError) {
        tracing::error!(error = %error, "scheduler tick failed");
        self.state
            .store(SchedulerState::Failed as u8, Ordering::Release);
        self.readiness.set_scheduler_ready(false);
        self.notify.notify_waiters();
    }
}

struct LoopGuard {
    service: Arc<SchedulerService>,
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        if self.service.state() == SchedulerState::Running {
            self.service
                .state
                .store(SchedulerState::Failed as u8, Ordering::Release);
        }
        self.service.readiness.set_scheduler_ready(false);
    }
}

struct ActiveRun {
    active: Arc<AtomicUsize>,
    _metrics: JobActiveGuard,
}

impl Drop for ActiveRun {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

fn task_error(error: JoinError) -> SchedulerError {
    SchedulerError::Task(error.to_string())
}

fn next_owner_suffix() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}
