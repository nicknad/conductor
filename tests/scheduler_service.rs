//! Scheduler service lifecycle, dispatch, metrics, and failure paths.
//!
//! These tests use the real in-memory job store and a real `ExecutionService`
//! with an empty registry, so dispatch exercises the pinned execution path
//! without spawning a worker. The success path is covered by
//! `tests/scheduler_api.rs`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use conductor::control_plane::activate_module::ActivationPolicy;
use conductor::control_plane::execute_module::ExecutionService;
use conductor::control_plane::scheduler::{
    JobFailureCode, JobRunState, NewJob, SchedulerError, SchedulerService, Trigger, TriggerKind,
};
use conductor::executions::executor::ExecutionLimits;
use conductor::executions::history::ExecutionHistoryStore;
use conductor::metrics::{Metrics, MetricsOptions};
use conductor::modules::registry::ModuleRegistry;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::readiness::Readiness;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::InMemoryMetricExporter;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "conductor-scheduler-service-{}-{tag}-{count}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn private(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("fixture permissions");
}

#[cfg(not(unix))]
fn private(_path: &Path) {}

fn capture(options: MetricsOptions) -> (Arc<Metrics>, InMemoryMetricExporter) {
    let exporter = InMemoryMetricExporter::default();
    let metrics =
        Metrics::with_exporter(options, exporter.clone()).expect("in-memory metrics must build");
    (metrics, exporter)
}

fn exported(metrics: &Metrics, exporter: &InMemoryMetricExporter) -> Vec<ResourceMetrics> {
    metrics.force_flush().expect("metrics flush");
    exporter
        .get_finished_metrics()
        .expect("in-memory metrics read")
}

fn i64_sum(data: &[ResourceMetrics], name: &str) -> i64 {
    let mut total = 0;
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::I64(MetricData::Sum(sum)) = metric.data() {
                    total += sum.data_points().map(|point| point.value()).sum::<i64>();
                }
            }
        }
    }
    total
}

fn histogram_count(data: &[ResourceMetrics], name: &str) -> u64 {
    let mut total = 0;
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::F64(MetricData::Histogram(histogram)) = metric.data() {
                    total += histogram
                        .data_points()
                        .map(|point| point.count())
                        .sum::<u64>();
                }
            }
        }
    }
    total
}

fn build_scheduler(
    metrics: Arc<Metrics>,
    readiness: Arc<Readiness>,
    tag: &str,
) -> (Arc<SchedulerService>, Scratch) {
    build_scheduler_with_capacity(metrics, readiness, tag, 4)
}

fn build_scheduler_with_capacity(
    metrics: Arc<Metrics>,
    readiness: Arc<Readiness>,
    tag: &str,
    max_concurrent_runs: usize,
) -> (Arc<SchedulerService>, Scratch) {
    let scratch = Scratch::new(tag);
    let artifact_dir = scratch.path().join("artifacts");
    let staging_dir = scratch.path().join("staging");
    std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
    std::fs::create_dir_all(&staging_dir).expect("staging dir");
    private(&artifact_dir);
    private(&staging_dir);
    let registry = Arc::new(ModuleRegistry::new());
    let execution_service = Arc::new(
        ExecutionService::new(
            registry,
            artifact_dir,
            staging_dir,
            ActivationPolicy::new(vec!["rust".to_owned()]).expect("activation policy"),
            ExecutionLimits::default(),
            Duration::from_secs(30),
            PackageValidationPolicy::production(),
            HashSet::from(["k1".to_owned()]),
            4,
            Arc::new(ExecutionHistoryStore::open_in_memory().expect("history")),
            Arc::clone(&metrics),
        )
        .expect("execution service"),
    );
    let scheduler = Arc::new(
        SchedulerService::in_memory_for_test(
            execution_service,
            metrics,
            readiness,
            max_concurrent_runs,
        )
        .expect("scheduler"),
    );
    (scheduler, scratch)
}

fn manual_job(job_id: &str, module_id: &str) -> NewJob {
    NewJob {
        job_id: job_id.to_owned(),
        module_id: module_id.to_owned(),
        version: "1.0.0".to_owned(),
        function: "run".to_owned(),
        trigger: Trigger::Manual,
        payload: serde_json::json!({}),
        enabled: true,
        next_run_at: None,
        created_at: SystemTime::now(),
    }
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn interval_job(job_id: &str, interval_secs: u64, next_run_at: SystemTime) -> NewJob {
    NewJob {
        job_id: job_id.to_owned(),
        module_id: "missing-module".to_owned(),
        version: "1.0.0".to_owned(),
        function: "run".to_owned(),
        trigger: Trigger::Interval { interval_secs },
        payload: serde_json::json!({}),
        enabled: true,
        next_run_at: Some(next_run_at),
        created_at: UNIX_EPOCH,
    }
}

#[test]
fn scheduler_sources_do_not_reference_execution_internals() {
    let sources = [
        (
            "job.rs",
            include_str!("../src/control_plane/scheduler/job.rs"),
        ),
        (
            "store.rs",
            include_str!("../src/control_plane/scheduler/store.rs"),
        ),
        (
            "dispatch.rs",
            include_str!("../src/control_plane/scheduler/dispatch.rs"),
        ),
        (
            "service.rs",
            include_str!("../src/control_plane/scheduler/service.rs"),
        ),
        ("jobs.rs", include_str!("../src/api/jobs.rs")),
    ];
    for (name, source) in sources {
        for forbidden in [
            "WorkerExecutor",
            "extract_registered",
            "set_active",
            "Command::new",
            "artifact_dir",
            "staging_dir",
            "activate_active",
            "ExecutionService::activate",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} must not reference execution-internal symbol {forbidden}"
            );
        }
    }
}

#[tokio::test]
async fn trigger_requires_a_running_scheduler() {
    let (metrics, _exporter) = capture(MetricsOptions::default());
    let readiness = Arc::new(Readiness::new(true));
    let (scheduler, _scratch) =
        build_scheduler(Arc::clone(&metrics), Arc::clone(&readiness), "gate");
    scheduler
        .create_job(manual_job("job-gate", "missing-module"))
        .await
        .expect("create job");

    let error = scheduler
        .trigger_manual("job-gate")
        .await
        .expect_err("not started");
    assert!(matches!(error, SchedulerError::NotRunning));

    scheduler.start().await.expect("start");
    assert!(scheduler.is_running());
    assert!(readiness.is_ready(), "scheduler readiness must be set");
    scheduler
        .trigger_manual("job-gate")
        .await
        .expect("trigger while running");
    scheduler.stop().await;
    assert!(!scheduler.is_running());
    assert!(
        !readiness.is_ready(),
        "stopping the scheduler must clear readiness"
    );
}

#[tokio::test]
async fn tick_dispatches_and_records_a_refusal_for_an_unregistered_module() {
    let (metrics, exporter) = capture(MetricsOptions::default());
    let readiness = Arc::new(Readiness::new(true));
    let (scheduler, _scratch) =
        build_scheduler(Arc::clone(&metrics), Arc::clone(&readiness), "dispatch");
    scheduler
        .create_job(manual_job("job-refused", "missing-module"))
        .await
        .expect("create job");
    scheduler
        .enqueue_manual("job-refused")
        .await
        .expect("enqueue");

    let queued = exported(&metrics, &exporter);
    assert_eq!(i64_sum(&queued, conductor::metrics::JOB_QUEUE_DEPTH), 1);
    exporter.reset();

    let dispatched = scheduler
        .tick_once(SystemTime::now() + Duration::from_secs(1))
        .await
        .expect("tick");
    assert_eq!(dispatched, 1);

    let runs = scheduler
        .list_runs("job-refused", 10, 0)
        .await
        .expect("runs");
    assert_eq!(runs[0].state, JobRunState::Refused);
    assert_eq!(runs[0].failure_code, Some(JobFailureCode::ModuleNotFound));

    let data = exported(&metrics, &exporter);
    assert_eq!(i64_sum(&data, conductor::metrics::JOB_QUEUE_DEPTH), 0);
    assert_eq!(i64_sum(&data, conductor::metrics::JOB_ACTIVE), 0);
    assert!(
        histogram_count(&data, conductor::metrics::JOB_WAIT_DURATION) >= 1,
        "the wait histogram must record a claim"
    );
}

#[tokio::test]
async fn disabling_a_job_terminalizes_its_queued_run() {
    let (metrics, _exporter) = capture(MetricsOptions::default());
    let readiness = Arc::new(Readiness::new(true));
    let (scheduler, _scratch) =
        build_scheduler(Arc::clone(&metrics), Arc::clone(&readiness), "disable");
    scheduler
        .create_job(manual_job("job-disable", "missing-module"))
        .await
        .expect("create job");
    scheduler
        .enqueue_manual("job-disable")
        .await
        .expect("enqueue");

    let result = scheduler
        .set_enabled("job-disable", false, None)
        .await
        .expect("disable")
        .expect("job exists");
    assert_eq!(result.cancelled_queued, 1);

    let dispatched = scheduler
        .tick_once(SystemTime::now() + Duration::from_secs(1))
        .await
        .expect("tick");
    assert_eq!(dispatched, 0, "disabled work must not dispatch");
    let runs = scheduler
        .list_runs("job-disable", 10, 0)
        .await
        .expect("runs");
    assert_eq!(runs[0].state, JobRunState::Refused);
    assert_eq!(runs[0].failure_code, Some(JobFailureCode::JobDisabled));

    scheduler.start().await.expect("start");
    assert!(matches!(
        scheduler
            .trigger_manual("job-disable")
            .await
            .expect_err("disabled trigger"),
        SchedulerError::Store(conductor::control_plane::scheduler::JobStoreError::JobDisabled)
    ));
    scheduler.stop().await;
}

#[tokio::test]
async fn tick_enqueues_a_due_interval_run_and_advances_next_run_at() {
    let (metrics, _exporter) = capture(MetricsOptions::default());
    let readiness = Arc::new(Readiness::new(true));
    let (scheduler, _scratch) =
        build_scheduler(Arc::clone(&metrics), Arc::clone(&readiness), "interval-due");
    let scheduled = at(999_940);
    scheduler
        .create_job(interval_job("job-interval", 60, scheduled))
        .await
        .expect("create job");

    let dispatched = scheduler
        .tick_once(scheduled + Duration::from_secs(5))
        .await
        .expect("tick");
    assert_eq!(dispatched, 1, "the due run must dispatch through the loop");

    let runs = scheduler
        .list_runs("job-interval", 10, 0)
        .await
        .expect("runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].trigger, TriggerKind::Interval);
    assert_eq!(runs[0].scheduled_for, scheduled);
    assert_eq!(runs[0].state, JobRunState::Refused);
    assert_eq!(runs[0].failure_code, Some(JobFailureCode::ModuleNotFound));

    let job = scheduler
        .get_job("job-interval")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(job.next_run_at, Some(at(1_000_000)));
}

#[tokio::test]
async fn queue_depth_tracks_due_enqueues_when_capacity_is_zero() {
    let (metrics, exporter) = capture(MetricsOptions::default());
    let readiness = Arc::new(Readiness::new(true));
    let (scheduler, _scratch) = build_scheduler_with_capacity(
        Arc::clone(&metrics),
        Arc::clone(&readiness),
        "queue-depth",
        0,
    );
    let scheduled = at(1_000_000);
    scheduler
        .create_job(interval_job("job-interval", 60, scheduled))
        .await
        .expect("create job");

    let before = exported(&metrics, &exporter);
    assert_eq!(i64_sum(&before, conductor::metrics::JOB_QUEUE_DEPTH), 0);
    exporter.reset();

    let now = scheduled + Duration::from_secs(5);
    assert_eq!(
        scheduler.tick_once(now).await.expect("tick"),
        0,
        "capacity zero enqueues but cannot claim"
    );

    let after_first = exported(&metrics, &exporter);
    assert_eq!(
        i64_sum(&after_first, conductor::metrics::JOB_QUEUE_DEPTH),
        1,
        "the due enqueue must move the queue gauge"
    );
    let runs = scheduler
        .list_runs("job-interval", 10, 0)
        .await
        .expect("runs");
    assert_eq!(runs.len(), 1, "exactly one interval run must be queued");
    assert_eq!(runs[0].trigger, TriggerKind::Interval);
    assert_eq!(runs[0].state, JobRunState::Queued);
    let job = scheduler
        .get_job("job-interval")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(job.next_run_at, Some(scheduled + Duration::from_secs(60)));

    exporter.reset();
    assert_eq!(
        scheduler.tick_once(now).await.expect("second tick"),
        0,
        "the advanced boundary must not enqueue again"
    );
    let after_second = exported(&metrics, &exporter);
    assert_eq!(
        i64_sum(&after_second, conductor::metrics::JOB_QUEUE_DEPTH),
        1,
        "the second tick must not enqueue or claim"
    );
    assert_eq!(
        scheduler
            .list_runs("job-interval", 10, 0)
            .await
            .expect("runs")
            .len(),
        1
    );
    let job = scheduler
        .get_job("job-interval")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(
        job.next_run_at,
        Some(scheduled + Duration::from_secs(60)),
        "the boundary advanced past the tick time"
    );
}

#[tokio::test]
async fn two_ticks_at_the_same_time_enqueue_one_run_for_the_boundary() {
    let (metrics, _exporter) = capture(MetricsOptions::default());
    let readiness = Arc::new(Readiness::new(true));
    let (scheduler, _scratch) = build_scheduler(
        Arc::clone(&metrics),
        Arc::clone(&readiness),
        "interval-twice",
    );
    let now = at(1_000_000);
    scheduler
        .create_job(interval_job("job-interval", 60, now))
        .await
        .expect("create job");

    assert_eq!(scheduler.tick_once(now).await.expect("first tick"), 1);
    assert_eq!(
        scheduler.tick_once(now).await.expect("second tick"),
        0,
        "the advanced boundary must not enqueue again"
    );
    assert_eq!(
        scheduler
            .list_runs("job-interval", 10, 0)
            .await
            .expect("runs")
            .len(),
        1
    );
    let job = scheduler
        .get_job("job-interval")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(job.next_run_at, Some(now + Duration::from_secs(60)));
}

#[tokio::test]
async fn restart_catch_up_enqueues_one_original_run_not_a_burst() {
    let (metrics, _exporter) = capture(MetricsOptions::default());
    let readiness = Arc::new(Readiness::new(true));
    let (scheduler, _scratch) = build_scheduler(
        Arc::clone(&metrics),
        Arc::clone(&readiness),
        "interval-catchup",
    );
    let now = at(1_000_000);
    let scheduled = now - Duration::from_secs(5 * 60 + 3);
    scheduler
        .create_job(interval_job("job-interval", 60, scheduled))
        .await
        .expect("create job");

    assert_eq!(scheduler.tick_once(now).await.expect("tick"), 1);

    let runs = scheduler
        .list_runs("job-interval", 10, 0)
        .await
        .expect("runs");
    assert_eq!(runs.len(), 1, "catch-up must not replay every missed run");
    assert_eq!(runs[0].scheduled_for, scheduled);
    let job = scheduler
        .get_job("job-interval")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(
        job.next_run_at,
        Some(now + Duration::from_secs(57)),
        "the boundary lands on the first interval after now"
    );
}

#[tokio::test]
async fn a_disabled_interval_job_is_not_enqueued() {
    let (metrics, _exporter) = capture(MetricsOptions::default());
    let readiness = Arc::new(Readiness::new(true));
    let (scheduler, _scratch) = build_scheduler(
        Arc::clone(&metrics),
        Arc::clone(&readiness),
        "interval-disabled",
    );
    let now = at(1_000_000);
    scheduler
        .create_job(interval_job("job-interval", 60, now))
        .await
        .expect("create job");
    scheduler
        .set_enabled("job-interval", false, None)
        .await
        .expect("disable")
        .expect("exists");

    assert_eq!(scheduler.tick_once(now).await.expect("tick"), 0);
    assert!(
        scheduler
            .list_runs("job-interval", 10, 0)
            .await
            .expect("runs")
            .is_empty(),
        "a disabled interval job must not enqueue"
    );
    let job = scheduler
        .get_job("job-interval")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(job.next_run_at, None);
}
