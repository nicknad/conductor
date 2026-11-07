#![no_main]

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use conductor::api::routes::router;
use conductor::api::uploads::{ApiToken, AppState};
use conductor::audit::recorder::RejectionRecorder;
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
use conductor::storage::database::Database;
use libfuzzer_sys::fuzz_target;
use tokio::sync::Semaphore;
use tower::ServiceExt as _;

// Harness fixture accepted by the test-only trust store, not a credential.
// nosemgrep: generic.hardcoded-secret
const TOKEN: &str = "fuzz-token";

/// Arbitrary input is routed across the activation/execution JSON endpoints
/// and both history reads. No module is registered, so valid requests are
/// expected to reach a `4xx`; the oracles are that input never produces a
/// server error against the healthy fixture and never loses the transport
/// guarantees.
fn state() -> &'static AppState {
    static STATE: OnceLock<AppState> = OnceLock::new();
    STATE.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("conductor-fuzz-json-{}", std::process::id()));
        let quarantine_dir = root.join("quarantine");
        let artifact_dir = root.join("artifacts");
        let staging_dir = root.join("staging");
        for dir in [&quarantine_dir, &artifact_dir, &staging_dir] {
            std::fs::create_dir_all(dir).expect("fuzz fixture dir");
            private_dir(dir);
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
            .expect("fixed validator");
        let registry = Arc::new(ModuleRegistry::new());
        let metrics = Metrics::new(MetricsOptions::default()).expect("fixed in-memory metrics");
        let execution_service = Arc::new(
            ExecutionService::new(
                Arc::clone(&registry),
                artifact_dir.clone(),
                staging_dir,
                ActivationPolicy::new(vec!["rust".to_owned()]).expect("fixed policy"),
                ExecutionLimits::default(),
                Duration::from_secs(30),
                PackageValidationPolicy::production(),
                HashSet::from(["k1".to_owned()]),
                4,
                Arc::new(
                    ExecutionHistoryStore::open_in_memory()
                        .expect("fixed in-memory execution history"),
                ),
                Arc::clone(&metrics),
            )
            .expect("fixed execution service"),
        );
        let database = Arc::new(Database::open_in_memory().expect("fixed database"));
        database.migrate().expect("fixed database migration");
        let readiness = Arc::new(Readiness::new(database.check_ready().is_ok()));

        AppState {
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
        }
    })
}

#[cfg(unix)]
fn private_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("fuzz fixture directory must be owner-only");
}

#[cfg(not(unix))]
fn private_dir(_path: &std::path::Path) {}

/// Percent-encodes every byte so an arbitrary input can be embedded in a URI
/// path or query value without producing an invalid `http::Uri`.
fn percent_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(bytes.len() * 3);
    for byte in bytes {
        encoded.push('%');
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// `GET /v1/executions` pages, including boundary, duplicate, and overflowing
/// values, plus one arbitrary percent-encoded value.
fn list_uri(data: &[u8]) -> String {
    const FIXED: [&str; 12] = [
        "/v1/executions",
        "/v1/executions?limit=0",
        "/v1/executions?limit=1",
        "/v1/executions?limit=200",
        "/v1/executions?limit=201",
        "/v1/executions?offset=0",
        "/v1/executions?offset=1000000",
        "/v1/executions?offset=1000001",
        "/v1/executions?limit=1&limit=2",
        "/v1/executions?offset=0&offset=1",
        "/v1/executions?limit=999999999999999999999999999999",
        "/v1/executions?limit=18446744073709551616",
    ];
    let selector = data.get(1).copied().unwrap_or(0);
    let index = usize::from(selector) % (FIXED.len() + 1);
    if index == FIXED.len() {
        let value = percent_encode(data.get(2..).unwrap_or_default());
        match selector % 3 {
            0 => format!("/v1/executions?limit={value}"),
            1 => format!("/v1/executions?offset={value}"),
            _ => format!("/v1/executions?limit={value}&offset={value}"),
        }
    } else {
        FIXED[index].to_owned()
    }
}

/// `GET /v1/executions/{id}` with safe, percent-encoded, invalid-UTF-8,
/// control-character, and traversal ids, plus one arbitrary encoded id.
fn detail_uri(data: &[u8]) -> String {
    const FIXED: [&str; 12] = [
        "/v1/executions/exec-123",
        "/v1/executions/exec_ABC-9",
        "/v1/executions/%FF",
        "/v1/executions/%C3%28",
        "/v1/executions/%80",
        "/v1/executions/%ED%A0%80",
        "/v1/executions/exec%0Acontrol",
        "/v1/executions/exec%00nul",
        "/v1/executions/exec%1Bescape",
        "/v1/executions/..%2F..%2Fetc%2Fpasswd",
        "/v1/executions/%2e%2e%2f",
        "/v1/executions/exec%2Fescape",
    ];
    let selector = data.get(1).copied().unwrap_or(0);
    let index = usize::from(selector) % (FIXED.len() + 1);
    if index == FIXED.len() {
        format!(
            "/v1/executions/{}",
            percent_encode(data.get(2..).unwrap_or_default())
        )
    } else {
        FIXED[index].to_owned()
    }
}

fn request_for(data: &[u8]) -> (Method, String, Body) {
    match data.first().copied().unwrap_or(0) % 4 {
        0 => (
            Method::POST,
            "/v1/modules/fuzz-module/activate".to_owned(),
            Body::from(data.to_vec()),
        ),
        1 => (
            Method::POST,
            "/v1/modules/fuzz-module/executions".to_owned(),
            Body::from(data.to_vec()),
        ),
        2 => (Method::GET, list_uri(data), Body::empty()),
        _ => (Method::GET, detail_uri(data), Body::empty()),
    }
}

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let app_state = state().clone();

    let (method, uri, body) = request_for(data);
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(body)
        .expect("request");

    let (status, headers) = runtime.block_on(async move {
        let response = router(app_state)
            .oneshot(request)
            .await
            .expect("router must respond");
        (response.status(), response.headers().clone())
    });

    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "arbitrary input produced {status}"
    );
    assert!(headers.contains_key("x-request-id"));
    assert!(headers.contains_key("strict-transport-security"));
    assert!(headers.contains_key("x-content-type-options"));
});
