//! Ephemeral OpenTelemetry metrics with OTLP/HTTP export.
//!
//! Metrics are process telemetry, not durable state: nothing in this module
//! writes to SQLite, and the host deliberately exposes no `/metrics` scrape
//! endpoint. When [`MetricsOptions::endpoint`] is `None`, [`Metrics::new`]
//! builds an SDK provider with no reader, so recording stays local and cheap
//! and no HTTP client or export thread is created. When an endpoint is
//! configured, a [`PeriodicReader`] exports cumulative protobuf over OTLP/HTTP
//! to an external collector.
//!
//! Every instrument is created once at construction and cached in [`Metrics`];
//! request paths only record measurements. Attribute values are bounded,
//! low-cardinality labels (route templates, methods, status codes, stable
//! outcome/reason names). Module ids, versions, execution ids, request ids,
//! paths, tokens, configuration, and free-form error text are never used as
//! attributes.
//!
//! # Exemplars
//!
//! The OpenTelemetry Rust 0.33 metrics SDK exposes exported exemplar data
//! structures but no application-side exemplar recording API. Trace-linked
//! exemplars are therefore **not emitted** by this version. Correlate
//! execution/history metrics through structured logs and future tracing.

use std::fmt;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry::metrics::{Meter, MeterProvider as _};
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{
    Aggregation, Instrument, PeriodicReader, SdkMeterProvider, Stream, Temporality,
};
use opentelemetry_sdk::Resource;
use thiserror::Error;

/// Stable metric names. Changing one is an observable contract change.
pub const HTTP_SERVER_REQUESTS: &str = "http.server.requests";
pub const HTTP_SERVER_REQUEST_DURATION: &str = "http.server.request.duration";
pub const HTTP_SERVER_ACTIVE_REQUESTS: &str = "http.server.active_requests";
pub const AUTH_FAILURES: &str = "conductor.auth.failures";
pub const EXECUTION_COMPLETED: &str = "conductor.execution.completed";
pub const EXECUTION_REFUSED: &str = "conductor.execution.refused";
pub const EXECUTION_DURATION: &str = "conductor.execution.duration";
pub const EXECUTION_SLOTS_IN_USE: &str = "conductor.execution.slots.in_use";
pub const EXECUTION_SLOTS_CAPACITY: &str = "conductor.execution.slots.capacity";
pub const EXECUTION_OVERLOAD: &str = "conductor.execution.overload";
pub const EXECUTION_HISTORY_WRITE_FAILURES: &str = "conductor.execution.history.write.failures";
pub const DB_BUSY_ERRORS: &str = "conductor.db.busy.errors";
pub const DB_LOCK_WAIT_DURATION: &str = "conductor.db.lock.wait.duration";
pub const STORAGE_FREE_BYTES: &str = "conductor.storage.free.bytes";
pub const ARTIFACT_INTEGRITY_FAILURES: &str = "conductor.artifact.integrity.failures";

/// Future instrument (not emitted by this slice) viewed with job-wait buckets.
pub const JOB_WAIT_DURATION: &str = "conductor.job.wait.duration";

const INSTRUMENTATION_SCOPE: &str = "conductor";
const SERVICE_NAME: &str = "conductor";
const CARDINALITY_LIMIT: usize = 256;
/// OTLP/HTTP metrics signal path appended to a configured base URL.
const OTLP_METRICS_PATH: &str = "/v1/metrics";

const HTTP_SERVER_REQUEST_DURATION_BUCKETS: [f64; 15] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
];
const EXECUTION_DURATION_BUCKETS: [f64; 10] =
    [0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0];
const DB_LOCK_WAIT_DURATION_BUCKETS: [f64; 8] = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0];
const JOB_WAIT_DURATION_BUCKETS: [f64; 8] = [0.01, 0.1, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0];

/// Bounded reason vocabulary for [`EXECUTION_REFUSED`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    NotFound,
    NotActive,
    Integrity,
    Runtime,
    Signer,
    LegacyManifest,
    Manifest,
    Archive,
    Staging,
    Target,
    Executor,
    Deadline,
    Internal,
}

impl RefusalReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotActive => "not_active",
            Self::Integrity => "integrity",
            Self::Runtime => "runtime",
            Self::Signer => "signer",
            Self::LegacyManifest => "legacy_manifest",
            Self::Manifest => "manifest",
            Self::Archive => "archive",
            Self::Staging => "staging",
            Self::Target => "target",
            Self::Executor => "executor",
            Self::Deadline => "deadline",
            Self::Internal => "internal",
        }
    }
}

/// Bounded artifact-integrity vocabulary for [`ARTIFACT_INTEGRITY_FAILURES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityKind {
    Path,
    Missing,
    Unreadable,
    Size,
    Digest,
    Manifest,
    Archive,
    Legacy,
    Staging,
    Target,
    RegistryState,
}

impl IntegrityKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
            Self::Size => "size",
            Self::Digest => "digest",
            Self::Manifest => "manifest",
            Self::Archive => "archive",
            Self::Legacy => "legacy",
            Self::Staging => "staging",
            Self::Target => "target",
            Self::RegistryState => "registry_state",
        }
    }
}

/// Stable outcome names for [`EXECUTION_COMPLETED`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionOutcomeName {
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    WorkerError,
    ProtocolViolation,
}

impl ExecutionOutcomeName {
    /// The six stable names from [`ExecutionOutcome::as_str`]. An unknown
    /// value is not recorded, keeping the label set bounded.
    ///
    /// [`ExecutionOutcome::as_str`]: crate::executions::executor::ExecutionOutcome::as_str
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "timed_out" => Some(Self::TimedOut),
            "cancelled" => Some(Self::Cancelled),
            "worker_error" => Some(Self::WorkerError),
            "protocol_violation" => Some(Self::ProtocolViolation),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::WorkerError => "worker_error",
            Self::ProtocolViolation => "protocol_violation",
        }
    }
}

/// Execution duration phase for [`EXECUTION_DURATION`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionPhase {
    Prepare,
    Run,
}

impl ExecutionPhase {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Run => "run",
        }
    }
}

/// Why bearer authentication failed. Tokens never appear here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthFailure {
    Missing,
    Invalid,
}

impl AuthFailure {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invalid => "invalid",
        }
    }
}

/// Metrics build/operation failures. Fatal at startup; not per-request.
#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("failed to build the OTLP metric exporter: {0}")]
    Exporter(String),
    #[error("metrics provider operation failed: {0}")]
    Provider(String),
}

/// Operator configuration needed to build [`Metrics`].
#[derive(Clone, Debug)]
pub struct MetricsOptions {
    /// OTLP/HTTP endpoint. `None` disables export entirely.
    pub endpoint: Option<String>,
    pub export_interval: Duration,
    pub export_timeout: Duration,
    pub deployment_environment: String,
    pub execution_capacity: usize,
    pub storage_root: PathBuf,
}

impl Default for MetricsOptions {
    fn default() -> Self {
        Self {
            endpoint: None,
            export_interval: Duration::from_secs(15),
            export_timeout: Duration::from_secs(5),
            deployment_environment: "development".to_owned(),
            execution_capacity: 4,
            storage_root: PathBuf::from("data"),
        }
    }
}

/// Treats the configured OTLP endpoint as a **base URL**: trailing slashes are
/// removed and the `/v1/metrics` signal path is appended unless the caller
/// already supplied the full signal URL. `opentelemetry-otlp`'s
/// `with_endpoint` is a full-URL API and does not append the signal path, so
/// passing `http://collector:4318` straight through would post to `/` and the
/// collector would drop the request.
#[must_use]
fn normalize_otlp_endpoint(endpoint: &str) -> String {
    let base = endpoint.trim_end_matches('/');
    if base.ends_with(OTLP_METRICS_PATH) {
        base.to_owned()
    } else {
        format!("{base}{OTLP_METRICS_PATH}")
    }
}

/// Normalizes an HTTP method to the standard closed set. Non-standard or
/// extension methods collapse to `_OTHER`, so a client cannot create an
/// unbounded metric label (or exhaust the stream cardinality limit) by
/// inventing method tokens.
#[must_use]
fn normalize_http_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "PATCH" => "PATCH",
        "CONNECT" => "CONNECT",
        "TRACE" => "TRACE",
        _ => "_OTHER",
    }
}

/// Guard that keeps [`HTTP_SERVER_ACTIVE_REQUESTS`] accurate. Dropping it
/// decrements exactly once, including on cancellation.
pub struct HttpRequestGuard {
    metrics: Arc<Metrics>,
    method: String,
    route: String,
}

impl Drop for HttpRequestGuard {
    fn drop(&mut self) {
        self.metrics
            .instruments
            .http_active_requests
            .add(-1, &request_attributes(&self.method, &self.route));
    }
}

/// Guard that tracks [`EXECUTION_SLOTS_IN_USE`]. Dropping it releases the
/// gauge exactly once.
pub struct ExecutionSlotGuard {
    metrics: Arc<Metrics>,
}

impl Drop for ExecutionSlotGuard {
    fn drop(&mut self) {
        self.metrics.instruments.execution_slots_in_use.add(-1, &[]);
    }
}

#[derive(Clone)]
struct Instruments {
    http_requests: opentelemetry::metrics::Counter<u64>,
    http_request_duration: opentelemetry::metrics::Histogram<f64>,
    http_active_requests: opentelemetry::metrics::UpDownCounter<i64>,
    auth_failures: opentelemetry::metrics::Counter<u64>,
    execution_completed: opentelemetry::metrics::Counter<u64>,
    execution_refused: opentelemetry::metrics::Counter<u64>,
    execution_duration: opentelemetry::metrics::Histogram<f64>,
    execution_slots_in_use: opentelemetry::metrics::UpDownCounter<i64>,
    execution_overload: opentelemetry::metrics::Counter<u64>,
    history_write_failures: opentelemetry::metrics::Counter<u64>,
    db_busy_errors: opentelemetry::metrics::Counter<u64>,
    db_lock_wait_duration: opentelemetry::metrics::Histogram<f64>,
    artifact_integrity_failures: opentelemetry::metrics::Counter<u64>,
    // Observable handles are retained with the rest of the cached instruments.
    _execution_slots_capacity: opentelemetry::metrics::ObservableGauge<u64>,
    _storage_free_bytes: opentelemetry::metrics::ObservableGauge<u64>,
}

/// Built metrics provider and its cached instruments.
///
/// `Debug` is manual: it reports only whether export is enabled, never
/// addresses or token-like configuration.
pub struct Metrics {
    _provider: SdkMeterProvider,
    instruments: Instruments,
    enabled: bool,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metrics")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl Metrics {
    /// Builds the provider. With no endpoint this creates no reader and no
    /// network client; with an endpoint it builds the OTLP/HTTP protobuf
    /// exporter and a periodic reader with the configured interval/timeout.
    pub fn new(options: MetricsOptions) -> Result<Arc<Self>, MetricsError> {
        let provider = match options.endpoint.as_deref() {
            Some(endpoint) => {
                let endpoint = normalize_otlp_endpoint(endpoint);
                // Userinfo (`scheme://user:secret@host`) is rejected by
                // configuration validation, but `Metrics::new` is also a
                // public seam. Refuse before the exporter can echo the
                // credential in a build error.
                if crate::config::endpoint_authority_has_userinfo(&endpoint) {
                    return Err(MetricsError::Exporter(
                        "OTLP endpoint must not contain userinfo".to_owned(),
                    ));
                }
                let exporter = opentelemetry_otlp::MetricExporter::builder()
                    .with_http()
                    .with_endpoint(endpoint.as_str())
                    .with_timeout(options.export_timeout)
                    .with_temporality(Temporality::Cumulative)
                    .build()
                    .map_err(|error| MetricsError::Exporter(error.to_string()))?;
                let reader = PeriodicReader::builder(exporter)
                    .with_interval(options.export_interval)
                    .build();
                build_provider(&options, |builder| builder.with_reader(reader))
            }
            None => build_provider(&options, |builder| builder),
        };
        Ok(build_metrics(
            provider,
            &options,
            options.endpoint.is_some(),
        ))
    }

    /// Builds a provider around an externally supplied exporter. This is the
    /// test/embedding seam used to capture metrics with
    /// `InMemoryMetricExporter`; production uses [`Metrics::new`].
    #[doc(hidden)]
    pub fn with_exporter<E>(options: MetricsOptions, exporter: E) -> Result<Arc<Self>, MetricsError>
    where
        E: PushMetricExporter,
    {
        let reader = PeriodicReader::builder(exporter)
            .with_interval(options.export_interval)
            .build();
        let provider = build_provider(&options, |builder| builder.with_reader(reader));
        Ok(build_metrics(provider, &options, true))
    }

    /// Installs the process-global handle used by storage instrumentation.
    /// Absent in tests unless a host (or a test) installs one.
    pub fn install_global(metrics: Arc<Self>) {
        *global_slot()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(metrics);
    }

    /// True when an OTLP reader/exporter was configured.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Starts an active-request gauge guard. The method is normalized to the
    /// standard closed set before it can become a label.
    #[must_use]
    pub fn http_request_guard(self: &Arc<Self>, method: &str, route: &str) -> HttpRequestGuard {
        let method = normalize_http_method(method);
        self.instruments
            .http_active_requests
            .add(1, &request_attributes(method, route));
        HttpRequestGuard {
            metrics: Arc::clone(self),
            method: method.to_owned(),
            route: route.to_owned(),
        }
    }

    /// Records one completed HTTP request.
    pub fn record_http_request(
        &self,
        method: &str,
        route: &str,
        status_code: u16,
        duration: Duration,
    ) {
        let attributes = [
            KeyValue::new("http.request.method", normalize_http_method(method)),
            KeyValue::new("http.route", route.to_owned()),
            KeyValue::new("http.response.status_code", i64::from(status_code)),
        ];
        self.instruments.http_requests.add(1, &attributes);
        self.instruments
            .http_request_duration
            .record(duration.as_secs_f64(), &attributes);
    }

    /// Records a bearer-auth refusal. `reason` is a closed vocabulary.
    pub fn record_auth_failure(&self, route: &str, reason: AuthFailure) {
        self.instruments.auth_failures.add(
            1,
            &[
                KeyValue::new("http.route", route.to_owned()),
                KeyValue::new("conductor.auth.reason", reason.as_str()),
            ],
        );
    }

    /// Records a completed worker and its run-phase duration.
    pub fn record_execution_completed(&self, outcome: ExecutionOutcomeName, duration: Duration) {
        self.instruments.execution_completed.add(
            1,
            &[KeyValue::new(
                "conductor.execution.outcome",
                outcome.as_str(),
            )],
        );
        self.record_execution_duration(ExecutionPhase::Run, duration);
    }

    /// Records one execution-duration phase.
    pub fn record_execution_duration(&self, phase: ExecutionPhase, duration: Duration) {
        self.instruments.execution_duration.record(
            duration.as_secs_f64(),
            &[KeyValue::new("conductor.execution.phase", phase.as_str())],
        );
    }

    /// Records a pre-spawn refusal with its bounded reason.
    pub fn record_execution_refused(&self, reason: RefusalReason) {
        self.instruments.execution_refused.add(
            1,
            &[KeyValue::new("conductor.execution.reason", reason.as_str())],
        );
    }

    /// Starts an execution-slot gauge guard.
    #[must_use]
    pub fn execution_slot_guard(self: &Arc<Self>) -> ExecutionSlotGuard {
        self.instruments.execution_slots_in_use.add(1, &[]);
        ExecutionSlotGuard {
            metrics: Arc::clone(self),
        }
    }

    /// Records a fail-fast capacity refusal.
    pub fn record_execution_overload(&self) {
        self.instruments.execution_overload.add(1, &[]);
    }

    /// Records a failed durable history insert.
    pub fn record_history_write_failure(&self) {
        self.instruments.history_write_failures.add(1, &[]);
    }

    /// Records an artifact/manifest/archive/staging/target integrity refusal.
    pub fn record_artifact_integrity_failure(&self, kind: IntegrityKind) {
        self.instruments.artifact_integrity_failures.add(
            1,
            &[KeyValue::new("conductor.integrity.kind", kind.as_str())],
        );
    }

    /// Records a SQLite busy/locked error classification.
    pub fn record_db_busy_error(&self) {
        self.instruments.db_busy_errors.add(1, &[]);
    }

    /// Records the time spent acquiring the shared database mutex.
    pub fn record_db_lock_wait(&self, duration: Duration) {
        self.instruments
            .db_lock_wait_duration
            .record(duration.as_secs_f64(), &[]);
    }

    /// Flushes all readers. Used by tests and optional operator hooks.
    pub fn force_flush(&self) -> Result<(), MetricsError> {
        self._provider
            .force_flush()
            .map_err(|error| MetricsError::Provider(error.to_string()))
    }

    /// Flushes and shuts down the provider. Idempotent per the SDK.
    pub fn shutdown(&self) -> Result<(), MetricsError> {
        self._provider
            .shutdown()
            .map_err(|error| MetricsError::Provider(error.to_string()))
    }
}

fn request_attributes(method: &str, route: &str) -> [KeyValue; 2] {
    [
        KeyValue::new("http.request.method", normalize_http_method(method)),
        KeyValue::new("http.route", route.to_owned()),
    ]
}

/// Builds the provider with the fixed resource and views, letting the caller
/// add a reader when export is configured.
fn build_provider(
    options: &MetricsOptions,
    configure: impl FnOnce(
        opentelemetry_sdk::metrics::MeterProviderBuilder,
    ) -> opentelemetry_sdk::metrics::MeterProviderBuilder,
) -> SdkMeterProvider {
    let builder = SdkMeterProvider::builder()
        .with_resource(resource(options))
        .with_view(view);
    configure(builder).build()
}

fn build_metrics(
    provider: SdkMeterProvider,
    options: &MetricsOptions,
    enabled: bool,
) -> Arc<Metrics> {
    let scope = InstrumentationScope::builder(INSTRUMENTATION_SCOPE).build();
    let meter = provider.meter_with_scope(scope);
    let instruments = create_instruments(&meter, options);
    Arc::new(Metrics {
        _provider: provider,
        instruments,
        enabled,
    })
}

fn create_instruments(meter: &Meter, options: &MetricsOptions) -> Instruments {
    let capacity = u64::try_from(options.execution_capacity).unwrap_or(u64::MAX);
    let capacity_gauge = meter
        .u64_observable_gauge(EXECUTION_SLOTS_CAPACITY)
        .with_unit("{slot}")
        .with_callback(move |observer| observer.observe(capacity, &[]))
        .build();

    let storage_root = options.storage_root.clone();
    let storage_gauge = meter
        .u64_observable_gauge(STORAGE_FREE_BYTES)
        .with_unit("By")
        .with_callback(move |observer| {
            #[cfg(unix)]
            if let Some(free) = storage_free_bytes(&storage_root) {
                observer.observe(free, &[]);
            }
            #[cfg(not(unix))]
            {
                let _ = (&storage_root, observer);
            }
        })
        .build();

    Instruments {
        http_requests: meter
            .u64_counter(HTTP_SERVER_REQUESTS)
            .with_unit("{request}")
            .build(),
        http_request_duration: meter
            .f64_histogram(HTTP_SERVER_REQUEST_DURATION)
            .with_unit("s")
            .build(),
        http_active_requests: meter
            .i64_up_down_counter(HTTP_SERVER_ACTIVE_REQUESTS)
            .with_unit("{request}")
            .build(),
        auth_failures: meter
            .u64_counter(AUTH_FAILURES)
            .with_unit("{failure}")
            .build(),
        execution_completed: meter
            .u64_counter(EXECUTION_COMPLETED)
            .with_unit("{execution}")
            .build(),
        execution_refused: meter
            .u64_counter(EXECUTION_REFUSED)
            .with_unit("{execution}")
            .build(),
        execution_duration: meter
            .f64_histogram(EXECUTION_DURATION)
            .with_unit("s")
            .build(),
        execution_slots_in_use: meter
            .i64_up_down_counter(EXECUTION_SLOTS_IN_USE)
            .with_unit("{slot}")
            .build(),
        execution_overload: meter
            .u64_counter(EXECUTION_OVERLOAD)
            .with_unit("{execution}")
            .build(),
        history_write_failures: meter
            .u64_counter(EXECUTION_HISTORY_WRITE_FAILURES)
            .with_unit("{failure}")
            .build(),
        db_busy_errors: meter
            .u64_counter(DB_BUSY_ERRORS)
            .with_unit("{error}")
            .build(),
        db_lock_wait_duration: meter
            .f64_histogram(DB_LOCK_WAIT_DURATION)
            .with_unit("s")
            .build(),
        artifact_integrity_failures: meter
            .u64_counter(ARTIFACT_INTEGRITY_FAILURES)
            .with_unit("{failure}")
            .build(),
        _execution_slots_capacity: capacity_gauge,
        _storage_free_bytes: storage_gauge,
    }
}

fn resource(options: &MetricsOptions) -> Resource {
    let host_name = host_name(
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .ok(),
    );
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let instance_id = format!("{}-{started}", std::process::id());

    // Start from the SDK defaults so `telemetry.sdk.name`, language, and
    // version are exported; `builder_empty` would drop that identity.
    Resource::builder()
        .with_service_name(SERVICE_NAME)
        .with_attributes([
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new(
                "deployment.environment.name",
                options.deployment_environment.clone(),
            ),
            KeyValue::new("service.instance.id", instance_id),
            KeyValue::new("host.name", host_name),
        ])
        .build()
}

/// Selects the exported host name, falling back when the environment value
/// is absent or whitespace-only.
fn host_name(value: Option<String>) -> String {
    value
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn buckets_for(name: &str) -> Option<&'static [f64]> {
    match name {
        HTTP_SERVER_REQUEST_DURATION => Some(&HTTP_SERVER_REQUEST_DURATION_BUCKETS),
        EXECUTION_DURATION => Some(&EXECUTION_DURATION_BUCKETS),
        DB_LOCK_WAIT_DURATION => Some(&DB_LOCK_WAIT_DURATION_BUCKETS),
        JOB_WAIT_DURATION => Some(&JOB_WAIT_DURATION_BUCKETS),
        _ => None,
    }
}

fn view(instrument: &Instrument) -> Option<Stream> {
    let builder = Stream::builder().with_cardinality_limit(CARDINALITY_LIMIT);
    let builder = match buckets_for(instrument.name()) {
        Some(boundaries) => builder.with_aggregation(histogram(boundaries)),
        None => builder,
    };
    builder.build().ok()
}

fn histogram(boundaries: &[f64]) -> Aggregation {
    Aggregation::ExplicitBucketHistogram {
        boundaries: boundaries.to_vec(),
        record_min_max: false,
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn storage_free_bytes(root: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let path = CString::new(root.as_os_str().as_bytes()).ok()?;
    // SAFETY: `libc::statvfs` is a plain C struct whose fields are integer
    // types, so all-zero bytes are a valid initial value before the call
    // fills them in.
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is a valid NUL-terminated C string that outlives the
    // call, and `stats` is a valid, writable pointer for the call's
    // duration; a nonzero return reports failure instead of using the
    // partially initialized struct.
    let result = unsafe { libc::statvfs(path.as_ptr(), &mut stats) };
    if result != 0 {
        return None;
    }
    let available = u128::from(stats.f_bavail);
    let block_size = u128::from(stats.f_frsize);
    u64::try_from(available.saturating_mul(block_size)).ok()
}

fn global_slot() -> &'static RwLock<Option<Arc<Metrics>>> {
    static GLOBAL: OnceLock<RwLock<Option<Arc<Metrics>>>> = OnceLock::new();
    GLOBAL.get_or_init(|| RwLock::new(None))
}

fn global_metrics() -> Option<Arc<Metrics>> {
    global_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Records a SQLite busy/locked error through the installed global handle.
/// A no-op when no host installed metrics.
pub fn record_db_busy_error() {
    if let Some(metrics) = global_metrics() {
        metrics.record_db_busy_error();
    }
}

/// Records a shared-mutex lock wait through the installed global handle.
/// A no-op when no host installed metrics.
pub fn record_db_lock_wait(duration: Duration) {
    if let Some(metrics) = global_metrics() {
        metrics.record_db_lock_wait(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::Key;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::InMemoryMetricExporter;
    use serial_test::serial;

    fn finished_metrics(
        metrics: &Metrics,
        exporter: &InMemoryMetricExporter,
    ) -> Vec<ResourceMetrics> {
        metrics.force_flush().expect("export must succeed");
        exporter
            .get_finished_metrics()
            .expect("in-memory metrics must read")
    }

    fn capture(options: MetricsOptions) -> (Arc<Metrics>, InMemoryMetricExporter) {
        let exporter = InMemoryMetricExporter::default();
        let metrics =
            Metrics::with_exporter(options, exporter.clone()).expect("metrics must build");
        (metrics, exporter)
    }

    fn metric_value(data: &[ResourceMetrics], name: &str) -> Option<u64> {
        for resource in data {
            for scope in resource.scope_metrics() {
                for metric in scope.metrics() {
                    if metric.name() != name {
                        continue;
                    }
                    if let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() {
                        return sum.data_points().map(|point| point.value()).next();
                    }
                }
            }
        }
        None
    }

    #[test]
    fn disabled_metrics_build_without_a_reader() {
        let metrics = Metrics::new(MetricsOptions::default()).expect("disabled metrics must build");
        assert!(!metrics.is_enabled());
        metrics
            .force_flush()
            .expect("disabled force_flush must be a no-op");
        metrics
            .shutdown()
            .expect("disabled shutdown must be a no-op");
    }

    #[test]
    fn execution_outcome_names_round_trip_through_their_stable_labels() {
        let names = [
            ExecutionOutcomeName::Succeeded,
            ExecutionOutcomeName::Failed,
            ExecutionOutcomeName::TimedOut,
            ExecutionOutcomeName::Cancelled,
            ExecutionOutcomeName::WorkerError,
            ExecutionOutcomeName::ProtocolViolation,
        ];
        for name in names {
            assert_eq!(
                ExecutionOutcomeName::from_name(name.as_str()),
                Some(name),
                "{} must parse back to itself",
                name.as_str()
            );
        }
        assert_eq!(ExecutionOutcomeName::from_name("unknown"), None);
        assert_eq!(ExecutionOutcomeName::from_name(""), None);
    }

    #[test]
    fn debug_reports_only_whether_export_is_enabled() {
        let metrics = Metrics::new(MetricsOptions::default()).expect("disabled metrics must build");
        let rendered = format!("{metrics:?}");
        assert!(
            rendered.contains("Metrics"),
            "debug output must name the type: {rendered}"
        );
        assert!(
            rendered.contains("enabled: false"),
            "debug output must report the export state: {rendered}"
        );
    }

    #[test]
    fn resource_and_scope_carry_the_documented_identity() {
        let (metrics, exporter) = capture(MetricsOptions {
            deployment_environment: "staging".to_owned(),
            ..MetricsOptions::default()
        });
        metrics.record_execution_overload();
        let data = finished_metrics(&metrics, &exporter);
        let latest = data.last().expect("one exported batch");
        let resource = latest.resource();
        assert_eq!(
            resource
                .get(&Key::new("service.name"))
                .expect("service.name")
                .as_str(),
            "conductor"
        );
        assert_eq!(
            resource
                .get(&Key::new("service.version"))
                .expect("service.version")
                .as_str(),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            resource
                .get(&Key::new("deployment.environment.name"))
                .expect("deployment env")
                .as_str(),
            "staging"
        );
        assert!(!resource
            .get(&Key::new("service.instance.id"))
            .expect("instance id")
            .as_str()
            .is_empty());
        assert!(!resource
            .get(&Key::new("host.name"))
            .expect("host name")
            .as_str()
            .is_empty());
        assert_eq!(
            resource
                .get(&Key::new("telemetry.sdk.name"))
                .expect("sdk name")
                .as_str(),
            "opentelemetry"
        );
        assert_eq!(
            resource
                .get(&Key::new("telemetry.sdk.language"))
                .expect("sdk language")
                .as_str(),
            "rust"
        );
        assert!(!resource
            .get(&Key::new("telemetry.sdk.version"))
            .expect("sdk version")
            .as_str()
            .is_empty());
        for scope in latest.scope_metrics() {
            assert_eq!(scope.scope().name(), "conductor");
        }
    }

    #[test]
    fn resource_host_name_falls_back_for_missing_or_blank_values() {
        assert_eq!(
            host_name(Some("runner-1".to_owned())),
            "runner-1",
            "a non-empty host environment value must be exported verbatim"
        );
        assert_eq!(
            host_name(Some("   ".to_owned())),
            "unknown",
            "a whitespace-only host name must not become the exported value"
        );
        assert_eq!(host_name(None), "unknown");
    }

    #[test]
    fn db_helpers_record_busy_and_lock_wait() {
        let (metrics, exporter) = capture(MetricsOptions::default());
        metrics.record_db_busy_error();
        metrics.record_db_lock_wait(Duration::from_millis(2));
        let data = finished_metrics(&metrics, &exporter);
        assert_eq!(metric_value(&data, DB_BUSY_ERRORS), Some(1));
        let mut saw_histogram = false;
        for resource in &data {
            for scope in resource.scope_metrics() {
                for metric in scope.metrics() {
                    if metric.name() != DB_LOCK_WAIT_DURATION {
                        continue;
                    }
                    match metric.data() {
                        AggregatedMetrics::F64(MetricData::Histogram(histogram)) => {
                            for point in histogram.data_points() {
                                saw_histogram = true;
                                assert_eq!(point.count(), 1);
                                assert!(point.sum() > 0.0, "the recorded wait must be positive");
                            }
                        }
                        other => panic!("unexpected metric data: {other:?}"),
                    }
                }
            }
        }
        assert!(saw_histogram, "lock wait histogram must be exported");
    }

    /// Exporter whose shutdown always fails, pinning error propagation from
    /// `Metrics::shutdown` rather than only the happy path.
    struct FailingShutdownExporter;

    impl PushMetricExporter for FailingShutdownExporter {
        async fn export(
            &self,
            _metrics: &ResourceMetrics,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            Ok(())
        }

        fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
            Ok(())
        }

        fn shutdown_with_timeout(
            &self,
            _timeout: Duration,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            Err(opentelemetry_sdk::error::OTelSdkError::InternalFailure(
                "forced shutdown failure".to_owned(),
            ))
        }

        fn temporality(&self) -> Temporality {
            Temporality::Cumulative
        }
    }

    #[test]
    fn shutdown_surfaces_exporter_failure() {
        let metrics = Metrics::with_exporter(MetricsOptions::default(), FailingShutdownExporter)
            .expect("metrics must build");
        metrics
            .shutdown()
            .expect_err("an exporter shutdown failure must be reported");
    }

    #[test]
    #[serial]
    fn global_handle_records_through_the_module_helpers() {
        let clear = || {
            *global_slot()
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        };

        clear();
        let (metrics, exporter) = capture(MetricsOptions::default());
        Metrics::install_global(Arc::clone(&metrics));
        assert!(
            global_metrics().is_some_and(|installed| Arc::ptr_eq(&installed, &metrics)),
            "install_global must publish the exact handle global_metrics reads"
        );
        record_db_busy_error();
        record_db_lock_wait(Duration::from_millis(2));
        clear();
        let data = finished_metrics(&metrics, &exporter);
        assert!(
            metric_value(&data, DB_BUSY_ERRORS).is_some_and(|value| value >= 1),
            "the installed handle must receive the global busy-error sample"
        );
        let mut lock_wait_samples = 0;
        for resource in &data {
            for scope in resource.scope_metrics() {
                for metric in scope.metrics() {
                    if metric.name() != DB_LOCK_WAIT_DURATION {
                        continue;
                    }
                    if let AggregatedMetrics::F64(MetricData::Histogram(histogram)) = metric.data()
                    {
                        for point in histogram.data_points() {
                            lock_wait_samples += point.count();
                        }
                    }
                }
            }
        }
        assert!(
            lock_wait_samples >= 1,
            "the installed handle must receive the global lock-wait sample"
        );
    }

    #[cfg(unix)]
    #[test]
    fn storage_free_bytes_is_observed_for_an_existing_root() {
        let root = std::env::temp_dir();
        let (metrics, exporter) = capture(MetricsOptions {
            storage_root: root,
            ..MetricsOptions::default()
        });
        let data = finished_metrics(&metrics, &exporter);
        let mut observed = None;
        for resource in &data {
            for scope in resource.scope_metrics() {
                for metric in scope.metrics() {
                    if metric.name() != STORAGE_FREE_BYTES {
                        continue;
                    }
                    if let AggregatedMetrics::U64(MetricData::Gauge(gauge)) = metric.data() {
                        observed = gauge.data_points().map(|point| point.value()).next();
                    }
                }
            }
        }
        assert!(
            observed.is_some_and(|bytes| bytes > 1),
            "storage free bytes must be the observed value, not a placeholder: {observed:?}"
        );
    }

    #[test]
    fn every_histogram_name_pins_its_configured_buckets() {
        let expected: [(&str, &[f64]); 4] = [
            (
                HTTP_SERVER_REQUEST_DURATION,
                &HTTP_SERVER_REQUEST_DURATION_BUCKETS,
            ),
            (EXECUTION_DURATION, &EXECUTION_DURATION_BUCKETS),
            (DB_LOCK_WAIT_DURATION, &DB_LOCK_WAIT_DURATION_BUCKETS),
            (JOB_WAIT_DURATION, &JOB_WAIT_DURATION_BUCKETS),
        ];
        for (name, boundaries) in expected {
            assert_eq!(
                buckets_for(name),
                Some(boundaries),
                "{name} must use its pinned buckets"
            );
        }
        assert_eq!(
            buckets_for("conductor.unconfigured"),
            None,
            "unknown instruments must keep the default aggregation"
        );
        assert_eq!(
            JOB_WAIT_DURATION_BUCKETS,
            [0.01, 0.1, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0],
            "the future job-wait buckets are pinned for the next slice"
        );
    }

    #[test]
    fn http_methods_normalize_to_the_standard_closed_set() {
        for method in [
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
        ] {
            assert_eq!(normalize_http_method(method), method);
        }
        for method in ["get", "X-CARD-1", "PROPFIND", "", "M-SEARCH"] {
            assert_eq!(
                normalize_http_method(method),
                "_OTHER",
                "{method:?} must not become a raw label"
            );
        }
    }

    #[test]
    fn otlp_endpoint_normalization_uses_base_url_semantics() {
        assert_eq!(
            normalize_otlp_endpoint("http://collector:4318"),
            "http://collector:4318/v1/metrics"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://collector:4318/"),
            "http://collector:4318/v1/metrics"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://collector:4318/v1/metrics"),
            "http://collector:4318/v1/metrics"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://collector:4318/v1/metrics/"),
            "http://collector:4318/v1/metrics"
        );
        assert_eq!(
            normalize_otlp_endpoint("https://collector:4318/custom-base"),
            "https://collector:4318/custom-base/v1/metrics"
        );
    }

    /// Starts a one-shot local HTTP collector, exports one metric, and returns
    /// the raw request text (request line plus headers/body prefix).
    fn capture_otlp_request(make_endpoint: impl FnOnce(&str) -> String) -> String {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::sync::mpsc;

        // A blocking listener on a dedicated thread, not the async runtime.
        // nosemgrep: rust.std-net-in-async
        let listener = TcpListener::bind("127.0.0.1:0").expect("collector must bind");
        let address = listener.local_addr().expect("collector address");
        let (tx, rx) = mpsc::channel();
        let collector = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("collector must accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read timeout must set");
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            // Read headers.
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => request.extend_from_slice(&buffer[..read]),
                    Err(error) => {
                        tx.send(Err(format!("collector read failed: {error}"))).ok();
                        return;
                    }
                }
            }
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
                .unwrap_or(request.len());
            let headers = String::from_utf8_lossy(&request[..header_end]).into_owned();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            // Read the body so closing the socket does not reset the client.
            while request.len().saturating_sub(header_end) < content_length {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => request.extend_from_slice(&buffer[..read]),
                    Err(error) => {
                        tx.send(Err(format!("collector body read failed: {error}")))
                            .ok();
                        return;
                    }
                }
            }
            tx.send(Ok(String::from_utf8_lossy(&request).into_owned()))
                .ok();
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });

        let endpoint = make_endpoint(&format!("http://{address}"));
        let metrics = Metrics::new(MetricsOptions {
            endpoint: Some(endpoint),
            export_interval: Duration::from_millis(50),
            export_timeout: Duration::from_secs(5),
            ..MetricsOptions::default()
        })
        .expect("endpoint exporter must build");
        metrics.record_execution_overload();
        metrics.force_flush().expect("flush must export a batch");
        let captured = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("collector must receive an export")
            .expect("collector must read the request");
        collector.join().expect("collector thread must finish");
        // The collector has stopped; shutdown's final flush may fail to reach
        // it and is not part of what this test pins.
        let _ = metrics.shutdown();
        captured
    }

    #[test]
    fn base_endpoint_posts_to_the_metrics_signal_path() {
        let request = capture_otlp_request(ToOwned::to_owned);
        assert!(
            request.starts_with("POST /v1/metrics HTTP/1.1\r\n"),
            "a base URL must post to /v1/metrics, got: {:?}",
            request.lines().next()
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/x-protobuf"),
            "OTLP/HTTP must use protobuf content type: {request}"
        );
    }

    #[test]
    fn full_signal_url_is_not_double_appended() {
        let request = capture_otlp_request(|base| format!("{base}/v1/metrics"));
        assert!(
            request.starts_with("POST /v1/metrics HTTP/1.1\r\n"),
            "the full signal URL must not be appended again, got: {:?}",
            request.lines().next()
        );
        assert!(
            !request.starts_with("POST /v1/metrics/v1/metrics"),
            "double-appended signal path: {request}"
        );
    }

    #[test]
    fn https_endpoint_builds_with_the_rustls_backend() {
        // Building the exporter constructs the TLS-capable blocking client.
        // A real handshake is not exercised here; see the known-gaps note in
        // the observability docs.
        let metrics = Metrics::new(MetricsOptions {
            endpoint: Some("https://collector.example:4318".to_owned()),
            export_interval: Duration::from_secs(3600),
            export_timeout: Duration::from_millis(10),
            ..MetricsOptions::default()
        })
        .expect("an https endpoint must build a TLS-capable exporter");
        assert!(metrics.is_enabled());
        // No collector exists; shutdown's final export is expected to fail.
        let _ = metrics.shutdown();
    }

    #[test]
    fn userinfo_in_a_direct_metrics_endpoint_is_rejected_without_echo() {
        let marker = "exporter-secret-marker";
        let error = Metrics::new(MetricsOptions {
            endpoint: Some(format!("http://operator:{marker}@[")),
            ..MetricsOptions::default()
        })
        .expect_err("userinfo must be rejected before exporter construction");
        let rendered = error.to_string();
        assert!(
            !rendered.contains(marker),
            "error leaked userinfo: {rendered}"
        );
    }

    #[test]
    fn disabled_metrics_never_connect_to_a_listening_socket() {
        use std::net::TcpListener;

        // Synchronous test guard; no async runtime is involved here.
        // nosemgrep: rust.std-net-in-async
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener must bind");
        listener
            .set_nonblocking(true)
            .expect("nonblocking mode must set");
        let metrics = Metrics::new(MetricsOptions {
            endpoint: None,
            export_interval: Duration::from_millis(10),
            ..MetricsOptions::default()
        })
        .expect("disabled metrics must build");
        metrics.record_execution_overload();
        metrics
            .force_flush()
            .expect("disabled flush must be a no-op");
        std::thread::sleep(Duration::from_millis(50));
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("disabled metrics opened a connection: {other:?}"),
        }
        metrics.shutdown().expect("disabled shutdown must succeed");
    }

    #[test]
    fn histogram_views_use_the_configured_buckets() {
        let (metrics, exporter) = capture(MetricsOptions::default());
        metrics.record_http_request("GET", "/healthz", 200, Duration::from_millis(1));
        metrics.record_execution_duration(ExecutionPhase::Prepare, Duration::from_millis(1));
        metrics.record_db_lock_wait(Duration::from_millis(1));
        let data = finished_metrics(&metrics, &exporter);
        let expected = [
            (
                HTTP_SERVER_REQUEST_DURATION,
                HTTP_SERVER_REQUEST_DURATION_BUCKETS.as_slice(),
            ),
            (EXECUTION_DURATION, EXECUTION_DURATION_BUCKETS.as_slice()),
            (
                DB_LOCK_WAIT_DURATION,
                DB_LOCK_WAIT_DURATION_BUCKETS.as_slice(),
            ),
        ];
        for (name, bounds) in expected {
            let mut found = false;
            for resource in &data {
                for scope in resource.scope_metrics() {
                    for metric in scope.metrics() {
                        if metric.name() != name {
                            continue;
                        }
                        if let AggregatedMetrics::F64(MetricData::Histogram(histogram)) =
                            metric.data()
                        {
                            for point in histogram.data_points() {
                                found = true;
                                assert_eq!(
                                    point.bounds().collect::<Vec<_>>(),
                                    bounds.to_vec(),
                                    "{name} must use its configured buckets"
                                );
                            }
                        }
                    }
                }
            }
            assert!(found, "{name} must be exported");
        }
    }
}
