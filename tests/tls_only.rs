//! TLS-only proof: the operator PEM identity loads as a rustls server
//! config, mismatched identities fail closed, and plaintext HTTP against
//! the TLS port receives no HTTP response.
//!
//! Certificates are generated in-test with `rcgen` (test-only, never
//! trusted outside this file), so no fixture key material can drift or
//! leak. A full TLS-client round-trip is deliberately out of scope: it
//! would need client-side PKI machinery in dev-dependencies, while the
//! property under test — no plaintext service — is proven by driving the
//! production `server::serve_with_handle` path and probing it with
//! plaintext.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum_server::tls_rustls::RustlsConfig;
use conductor::api::routes::router;
use conductor::api::uploads::{ApiToken, AppState};
use conductor::audit::recorder::RejectionRecorder;
use conductor::control_plane::activate_module::ActivationPolicy;
use conductor::control_plane::execute_module::ExecutionService;
use conductor::control_plane::scheduler::SchedulerService;
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
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Semaphore;

/// Tightens a fixture directory to the owner-only mode ExecutionService
/// validates, independent of the runner's umask.
#[cfg(unix)]
fn tighten_private(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("fixture directory permissions must be settable");
}

#[cfg(not(unix))]
fn tighten_private(_path: &std::path::Path) {}

/// Generates a self-signed `localhost` identity and writes it to a
/// process-unique temp directory. Returns the cert path, key path, and
/// directory (removed by the caller).
fn test_identity(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("test certificate must generate");
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "conductor-tls-{}-{}-{tag}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).expect("tls dir must be created");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, key.cert.pem()).expect("cert must be writable");
    std::fs::write(&key_path, key.signing_key.serialize_pem()).expect("key must be writable");
    (cert_path, key_path, dir)
}

fn minimal_state(tag: &str) -> (AppState, PathBuf, PathBuf) {
    // Health probes need no real trust: the router only serves /healthz in
    // these tests, and every /v1 route additionally demands the bearer.
    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        vec![0u8; 32],
    )])
    .expect("distinct test keys must build");
    let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(keys)
        .build()
        .expect("test validator must build");
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let quarantine_dir = std::env::temp_dir().join(format!(
        "conductor-tls-q-{}-{}-{tag}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&quarantine_dir).expect("quarantine dir must be created");
    let artifact_dir = std::env::temp_dir().join(format!(
        "conductor-tls-a-{}-{}-{tag}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&artifact_dir).expect("artifact dir must be created");
    let staging_dir = artifact_dir.join("staging");
    std::fs::create_dir_all(&staging_dir).expect("staging dir must be created");
    tighten_private(&quarantine_dir);
    tighten_private(&artifact_dir);
    tighten_private(&staging_dir);
    let registry = Arc::new(ModuleRegistry::new());
    let metrics = Metrics::new(MetricsOptions::default()).expect("metrics must build");
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
            Arc::new(ExecutionHistoryStore::open_in_memory().expect("execution history must open")),
            Arc::clone(&metrics),
        )
        .expect("execution service must build"),
    );
    let database = Arc::new(Database::open_in_memory().expect("database must open"));
    database.migrate().expect("database must migrate");
    let readiness = Arc::new(Readiness::new(database.check_ready().is_ok()));
    let scheduler = Arc::new(
        SchedulerService::in_memory_for_test(
            Arc::clone(&execution_service),
            Arc::clone(&metrics),
            Arc::clone(&readiness),
            4,
        )
        .expect("test scheduler must build"),
    );
    (
        AppState {
            validator: Arc::new(validator),
            quarantine_dir: quarantine_dir.clone(),
            artifact_dir: artifact_dir.clone(),
            registry,
            recorder: Arc::new(RejectionRecorder::new()),
            request_timeout: Duration::from_secs(10),
            api_token: ApiToken::new("test-bearer-upload"),
            upload_slots: Arc::new(Semaphore::new(8)),
            execution_service,
            scheduler,
            metrics,
            database,
            readiness,
        },
        quarantine_dir,
        artifact_dir,
    )
}

#[tokio::test]
async fn operator_tls_identity_loads() {
    let (cert, key, dir) = test_identity("loads");
    RustlsConfig::from_pem_file(&cert, &key)
        .await
        .expect("matching PEM identity must load as a rustls server config");
    std::fs::remove_dir_all(&dir).expect("tls dir must clean up");
}

#[tokio::test]
async fn mismatched_tls_identity_fails_closed() {
    // Cert from one identity, key from another: loading must fail rather
    // than serve with half an identity.
    let (cert_a, _, dir_a) = test_identity("mismatch-a");
    let (_, key_b, dir_b) = test_identity("mismatch-b");
    assert!(
        RustlsConfig::from_pem_file(&cert_a, &key_b).await.is_err(),
        "mismatched cert/key must not load"
    );
    std::fs::remove_dir_all(&dir_a).expect("tls dir must clean up");
    std::fs::remove_dir_all(&dir_b).expect("tls dir must clean up");
}

#[tokio::test]
async fn serve_propagates_tls_configuration_errors() {
    let missing = std::env::temp_dir().join(format!(
        "conductor-missing-tls-identity-{}.pem",
        std::process::id()
    ));
    let result =
        conductor::server::serve(axum::Router::new(), "127.0.0.1:0", &missing, &missing).await;
    assert!(
        result.is_err(),
        "serve must not report success when TLS identity loading fails"
    );
}

#[tokio::test]
async fn plaintext_http_gets_no_response() {
    let (cert, key, tls_dir) = test_identity("plaintext");
    let (state, quarantine_dir, artifact_dir) = minimal_state("plaintext");

    // Drive the real serving path, not a test-local reconstruction. Port 0
    // lets the OS choose; the handle reports the actual address after bind.
    let handle = axum_server::Handle::new();
    let serving_handle = handle.clone();
    let serving = tokio::spawn(async move {
        let _ = conductor::server::serve_with_handle(
            router(state),
            "127.0.0.1:0",
            &cert,
            &key,
            serving_handle,
        )
        .await;
    });
    let addr = tokio::time::timeout(Duration::from_secs(5), handle.listening())
        .await
        .expect("server must start promptly")
        .expect("server must report its bound address");

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect must succeed");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("plaintext write must send");
    let mut bytes = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes)).await;
    // The TLS stack cannot parse plaintext as a handshake, so the
    // connection dies with EOF or reset — but never an HTTP response.
    match read {
        Ok(Ok(_)) => assert!(
            !bytes.starts_with(b"HTTP/"),
            "plaintext must never receive an HTTP response, got {bytes:?}"
        ),
        Ok(Err(_)) => {}
        Err(_) => panic!("server must close the plaintext connection promptly"),
    }

    serving.abort();
    std::fs::remove_dir_all(&tls_dir).expect("tls dir must clean up");
    std::fs::remove_dir_all(&quarantine_dir).expect("quarantine dir must clean up");
    std::fs::remove_dir_all(&artifact_dir).expect("artifact dir must clean up");
}
