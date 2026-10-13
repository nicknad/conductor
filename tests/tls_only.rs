//! TLS-only proof: the operator PEM identity loads as a rustls server
//! config, mismatched identities fail closed, and plaintext HTTP against
//! the TLS port receives no HTTP response.
//!
//! Certificates are generated in-test with `rcgen` (test-only, never
//! trusted outside this file), so no fixture key material can drift or
//! leak. A full TLS-client round-trip is deliberately out of scope: it
//! would need client-side PKI machinery in dev-dependencies, while the
//! property under test — no plaintext service — is proven by the
//! plaintext probe plus `bind_rustls` being the only serving path.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum_server::tls_rustls::RustlsConfig;
use conductor::api::routes::router;
use conductor::api::uploads::{ApiToken, AppState};
use conductor::audit::recorder::RejectionRecorder;
use conductor::control_plane::validate_package::PackageValidationBuilder;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    ConfiguredTrustedKeys, SignatureAlgorithm, TrustedSigningKey,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Semaphore;

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
    (
        AppState {
            validator: Arc::new(validator),
            quarantine_dir: quarantine_dir.clone(),
            artifact_dir: artifact_dir.clone(),
            registry: Arc::new(conductor::modules::registry::ModuleRegistry::new()),
            recorder: Arc::new(RejectionRecorder::new()),
            request_timeout: Duration::from_secs(10),
            api_token: ApiToken::new("test-bearer-upload"),
            upload_slots: Arc::new(Semaphore::new(8)),
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
async fn plaintext_http_gets_no_response() {
    let (cert, key, tls_dir) = test_identity("plaintext");
    let tls = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .expect("test identity must load");
    // Ephemeral loopback port, read before serving so the probe knows it.
    // Non-blocking mode is required: axum-server hands the socket to the
    // tokio runtime, which refuses blocking sockets.
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must be non-blocking");
    let port = listener.local_addr().expect("port must read").port();
    let (state, quarantine_dir, artifact_dir) = minimal_state("plaintext");
    let server = axum_server::from_tcp_rustls(listener, tls).expect("TLS server must build");
    let serving = tokio::spawn(async move {
        let _ = server.serve(router(state).into_make_service()).await;
    });

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
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
