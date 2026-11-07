//! Observability integration: HTTP/auth metrics through the real router,
//! OTLP-provider resource/scope identity, and the unauthenticated readiness
//! probe. Metrics are captured with the dev-only `InMemoryMetricExporter`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::prelude::*;
use conductor::api::routes::router;
use conductor::api::uploads::{ApiToken, AppState};
use conductor::audit::recorder::RejectionRecorder;
use conductor::config::{Config, TrustedKeyConfig};
use conductor::control_plane::activate_module::ActivationPolicy;
use conductor::control_plane::execute_module::ExecutionService;
use conductor::control_plane::validate_package::PackageValidationBuilder;
use conductor::executions::executor::ExecutionLimits;
use conductor::executions::history::ExecutionHistoryStore;
use conductor::metrics::{Metrics, MetricsOptions};
use conductor::modules::registry::ModuleRegistry;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    ConfiguredTrustedKeys, SignatureAlgorithm, TrustedSigningKey,
};
use conductor::readiness::Readiness;
use conductor::server::Host;
use conductor::storage::database::Database;
use opentelemetry::Key;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::InMemoryMetricExporter;
use tokio::sync::Semaphore;
use tower::ServiceExt as _;

const TOKEN: &str = "observability-test-token";

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(tag: &str) -> PathBuf {
    let count = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "conductor-observability-{}-{tag}-{count}-{nanos}",
        std::process::id()
    ))
}

#[cfg(unix)]
fn tighten_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("fixture permissions must be settable");
}

#[cfg(not(unix))]
fn tighten_private(_path: &Path) {}

fn capture(options: MetricsOptions) -> (Arc<Metrics>, InMemoryMetricExporter) {
    let exporter = InMemoryMetricExporter::default();
    let metrics =
        Metrics::with_exporter(options, exporter.clone()).expect("in-memory metrics must build");
    (metrics, exporter)
}

fn exported(metrics: &Metrics, exporter: &InMemoryMetricExporter) -> Vec<ResourceMetrics> {
    metrics.force_flush().expect("metrics flush must succeed");
    exporter
        .get_finished_metrics()
        .expect("in-memory metrics must read")
}

fn attributes_match<'a>(
    attributes: impl Iterator<Item = &'a opentelemetry::KeyValue>,
    key: &str,
    value: &str,
) -> bool {
    attributes
        .into_iter()
        .any(|attribute| attribute.key.as_str() == key && attribute.value.as_str() == value)
}

fn u64_sum(data: &[ResourceMetrics], name: &str, key: &str, value: &str) -> Option<u64> {
    u64_sum_all(data, name, &[(key, value)])
}

fn u64_sum_all(data: &[ResourceMetrics], name: &str, wanted: &[(&str, &str)]) -> Option<u64> {
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() {
                    for point in sum.data_points() {
                        if wanted
                            .iter()
                            .all(|(key, value)| attributes_match(point.attributes(), key, value))
                        {
                            return Some(point.value());
                        }
                    }
                }
            }
        }
    }
    None
}

fn i64_sum(data: &[ResourceMetrics], name: &str, key: &str, value: &str) -> Option<i64> {
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::I64(MetricData::Sum(sum)) = metric.data() {
                    for point in sum.data_points() {
                        if attributes_match(point.attributes(), key, value) {
                            return Some(point.value());
                        }
                    }
                }
            }
        }
    }
    None
}

fn histogram_bounds(
    data: &[ResourceMetrics],
    name: &str,
    key: &str,
    value: &str,
) -> Option<Vec<f64>> {
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::F64(MetricData::Histogram(histogram)) = metric.data() {
                    for point in histogram.data_points() {
                        if attributes_match(point.attributes(), key, value) {
                            return Some(point.bounds().collect());
                        }
                    }
                }
            }
        }
    }
    None
}

fn build_state(metrics: Arc<Metrics>, database: Arc<Database>, tag: &str) -> (AppState, PathBuf) {
    let readiness = Arc::new(Readiness::new(database.check_ready().is_ok()));
    let root = temp_root(tag);
    let quarantine_dir = root.join("quarantine");
    let artifact_dir = root.join("artifacts");
    let staging_dir = root.join("staging");
    for dir in [&quarantine_dir, &artifact_dir, &staging_dir] {
        std::fs::create_dir_all(dir).expect("fixture dir must be created");
        tighten_private(dir);
    }

    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        vec![0u8; 32],
    )])
    .expect("fixed key");
    let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(keys)
        .build()
        .expect("test validator must build");
    let registry = Arc::new(ModuleRegistry::new());
    let history_database =
        Arc::new(Database::open_in_memory().expect("history database must open"));
    history_database
        .migrate()
        .expect("history database must migrate");
    let execution_service = Arc::new(
        ExecutionService::new(
            Arc::clone(&registry),
            artifact_dir.clone(),
            staging_dir,
            ActivationPolicy::new(vec!["rust".to_owned()]).expect("activation policy"),
            ExecutionLimits::default(),
            Duration::from_secs(30),
            PackageValidationPolicy::production(),
            HashSet::from(["k1".to_owned()]),
            4,
            Arc::new(ExecutionHistoryStore::new(history_database)),
            Arc::clone(&metrics),
        )
        .expect("execution service must build"),
    );

    let state = AppState {
        validator: Arc::new(validator),
        quarantine_dir,
        artifact_dir,
        registry,
        recorder: Arc::new(RejectionRecorder::new()),
        request_timeout: Duration::from_secs(10),
        api_token: ApiToken::new(TOKEN),
        upload_slots: Arc::new(Semaphore::new(4)),
        execution_service,
        metrics,
        database,
        readiness,
    };
    (state, root)
}

async fn send(state: &AppState, uri: &str, bearer: Option<&str>) -> Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).expect("request must build"))
        .await
        .expect("router must respond")
}

async fn body_text(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must read");
    String::from_utf8(bytes.to_vec()).expect("body must be UTF-8")
}

fn migrated_database() -> Arc<Database> {
    let database = Arc::new(Database::open_in_memory().expect("database must open"));
    database.migrate().expect("database must migrate");
    database
}

#[tokio::test]
async fn http_metrics_use_the_matched_template_and_release_active_requests() {
    let root = temp_root("http");
    std::fs::create_dir_all(&root).expect("root must be created");
    let (metrics, exporter) = capture(MetricsOptions {
        deployment_environment: "test".to_owned(),
        storage_root: root.clone(),
        ..MetricsOptions::default()
    });
    let (state, _state_root) = build_state(Arc::clone(&metrics), migrated_database(), "http");

    exporter.reset();
    let response = send(
        &state,
        "/v1/executions/exec-observability-secret",
        Some(TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum(
            &data,
            "http.server.requests",
            "http.route",
            "/v1/executions/{execution_id}"
        ),
        Some(1),
        "the matched template must be the route label"
    );
    assert_eq!(
        u64_sum(
            &data,
            "http.server.requests",
            "http.route",
            "/v1/executions/exec-observability-secret"
        ),
        None,
        "the raw path must never be a label"
    );
    assert_eq!(
        histogram_bounds(
            &data,
            "http.server.request.duration",
            "http.route",
            "/v1/executions/{execution_id}"
        )
        .as_deref(),
        Some(
            [
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0,
                300.0,
            ]
            .as_slice()
        ),
        "the HTTP duration histogram must use the configured buckets"
    );
    assert_eq!(
        i64_sum(
            &data,
            "http.server.active_requests",
            "http.route",
            "/v1/executions/{execution_id}"
        ),
        Some(0),
        "the active-request gauge must return to zero"
    );

    let rendered = format!("{data:?}");
    for leaked in [
        "exec-observability-secret",
        "/v1/executions/exec-observability-secret",
        TOKEN,
        ".zip",
    ] {
        assert!(
            !rendered.contains(leaked),
            "metric data leaked {leaked:?}: {rendered}"
        );
    }
}

#[tokio::test]
async fn http_metrics_observe_unmatched_and_method_not_allowed_requests() {
    let (metrics, exporter) = capture(MetricsOptions::default());
    let (state, _root) = build_state(Arc::clone(&metrics), migrated_database(), "transport");

    exporter.reset();
    let unmatched = send(&state, "/definitely-not-a-route", None).await;
    assert_eq!(unmatched.status(), StatusCode::NOT_FOUND);
    let wrong_method = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/healthz")
                .body(Body::empty())
                .expect("request must build"),
        )
        .await
        .expect("router must respond");
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum_all(
            &data,
            "http.server.requests",
            &[
                ("http.route", "unmatched"),
                ("http.request.method", "GET"),
                ("http.response.status_code", "404"),
            ]
        ),
        Some(1),
        "unmatched routes must be observable without the raw path"
    );
    assert_eq!(
        u64_sum_all(
            &data,
            "http.server.requests",
            &[
                ("http.route", "/healthz"),
                ("http.request.method", "POST"),
                ("http.response.status_code", "405"),
            ]
        ),
        Some(1),
        "method-not-allowed responses must keep the matched template"
    );
}

#[tokio::test]
async fn auth_failure_metrics_distinguish_missing_and_invalid_without_tokens() {
    let (metrics, exporter) = capture(MetricsOptions::default());
    let (state, _root) = build_state(Arc::clone(&metrics), migrated_database(), "auth");

    exporter.reset();
    let missing = send(&state, "/v1/executions", None).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let invalid = send(&state, "/v1/executions", Some("wrong-token-value")).await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum(
            &data,
            "conductor.auth.failures",
            "conductor.auth.reason",
            "missing"
        ),
        Some(1),
        "a missing bearer must be labelled missing"
    );
    assert_eq!(
        u64_sum(
            &data,
            "conductor.auth.failures",
            "conductor.auth.reason",
            "invalid"
        ),
        Some(1),
        "a wrong bearer must be labelled invalid"
    );
    assert_eq!(
        u64_sum(
            &data,
            "conductor.auth.failures",
            "http.route",
            "/v1/executions"
        ),
        Some(1),
        "auth failures must carry the matched route label"
    );
    let rendered = format!("{data:?}");
    assert!(
        !rendered.contains("wrong-token-value") && !rendered.contains(TOKEN),
        "auth metrics must never carry token values: {rendered}"
    );
}

#[tokio::test]
async fn provider_resource_and_scope_carry_the_service_identity() {
    let (metrics, exporter) = capture(MetricsOptions {
        deployment_environment: "staging".to_owned(),
        ..MetricsOptions::default()
    });
    let (state, _root) = build_state(Arc::clone(&metrics), migrated_database(), "resource");

    exporter.reset();
    let response = send(&state, "/healthz", None).await;
    assert_eq!(response.status(), StatusCode::OK);

    let data = exported(&metrics, &exporter);
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
    let mut saw_scope = false;
    for scope in latest.scope_metrics() {
        assert_eq!(scope.scope().name(), "conductor");
        saw_scope = true;
    }
    assert!(
        saw_scope,
        "at least one scope must carry the conductor name"
    );
}

#[tokio::test]
async fn readyz_is_unauthenticated_and_reports_ok_for_an_assembled_host() {
    let root = temp_root("readyz-ok");
    std::fs::create_dir_all(&root).expect("root must be created");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let config = Config {
        http_bind: "127.0.0.1:0".to_owned(),
        storage_root: root.join("data"),
        request_timeout_secs: 30,
        max_execution_deadline_secs: 5,
        api_token: Some(TOKEN.to_owned()),
        trusted_keys: vec![TrustedKeyConfig {
            key_id: "k1".to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_base64: BASE64_STANDARD.encode(signing.verifying_key().to_bytes()),
        }],
        ..Config::default()
    };
    let state = Host::assemble(config)
        .expect("test configuration must assemble")
        .into_state();

    let response = send(&state, "/readyz", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, "ok");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn custom_http_methods_collapse_to_other_without_cardinality_overflow() {
    let (metrics, exporter) = capture(MetricsOptions::default());
    let (state, root) = build_state(Arc::clone(&metrics), migrated_database(), "methods");

    exporter.reset();
    for index in 0..300 {
        let method = format!("X-CARD-{index}");
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method(method.as_str())
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request must build"),
            )
            .await
            .expect("router must respond");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum_all(
            &data,
            "http.server.requests",
            &[
                ("http.route", "/healthz"),
                ("http.request.method", "_OTHER"),
                ("http.response.status_code", "405"),
            ]
        ),
        Some(300),
        "every custom method must collapse to _OTHER"
    );
    let rendered = format!("{data:?}");
    assert!(
        !rendered.contains("X-CARD-"),
        "custom methods must not become labels: {rendered}"
    );
    assert!(
        !rendered.contains("otel.metric.overflow"),
        "normalized methods must not exhaust the cardinality limit: {rendered}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readyz_serves_many_concurrent_probes_from_cached_state() {
    let (metrics, _exporter) = capture(MetricsOptions::default());
    let (state, root) = build_state(metrics, migrated_database(), "readyz-flood");

    let mut probes = Vec::new();
    for _ in 0..128 {
        let state = state.clone();
        probes.push(tokio::spawn(async move {
            send(&state, "/readyz", None).await.status()
        }));
    }
    for probe in probes {
        assert_eq!(
            probe.await.expect("probe task must join"),
            StatusCode::OK,
            "a cached ready state must not 503 under concurrent probes"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn readyz_is_unavailable_for_an_unmigrated_database_without_details() {
    let (metrics, _exporter) = capture(MetricsOptions::default());
    let unmigrated = Arc::new(Database::open_in_memory().expect("database must open"));
    let (state, root) = build_state(metrics, unmigrated, "readyz-unavailable");

    let response = send(&state, "/readyz", None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_text(response).await;
    assert_eq!(body, "unavailable", "readiness must not leak details");
    let _ = std::fs::remove_dir_all(&root);
}
