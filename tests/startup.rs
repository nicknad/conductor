//! Operator startup wiring: a configuration file becomes a live host, and
//! that host's router authenticates with the configured bearer token and
//! verifies packages against the configured trusted key.
//!
//! The assertions deliberately cross boundaries: a `201` proves the token
//! and trust store reached `AppState`; the artifact on disk and the registry
//! row prove the storage layout and shared database were assembled; the
//! durable rejection row proves the rejection sink was attached at startup.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::prelude::*;
use conductor::api::routes::router;
use conductor::config::Config;
use conductor::packages::artifact::ArtifactDigest;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::signature::canonical_payload;
use conductor::server::Host;
use ed25519_dalek::{Signer as _, SigningKey};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tower::ServiceExt as _;

/// Test-only signing key. Must never sign anything outside these tests.
const TEST_SIGNING_KEY: [u8; 32] = [7u8; 32];
const BOUNDARY: &str = "conductor-startup-boundary";
const OPERATOR_TOKEN: &str = "startup-wiring-token";

fn temp_root(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "conductor-startup-{}-{nanos}-{tag}",
        std::process::id()
    ))
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

/// Writes a real operator config file whose trusted key is the test signing
/// key, so a successful upload also proves the configured key was loaded.
fn write_config(root: &Path) -> PathBuf {
    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let public_key = BASE64_STANDARD.encode(signing.verifying_key().to_bytes());
    std::fs::create_dir_all(root).expect("config dir must be created");
    let path = root.join("conductor.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "http_bind": "127.0.0.1:0",
            "storage_root": root.join("data").display().to_string(),
            "api_token": OPERATOR_TOKEN,
            "trusted_keys": [{
                "key_id": "k1",
                "algorithm": "ed25519",
                "public_key_base64": public_key,
            }],
        })
        .to_string(),
    )
    .expect("config must be writable");
    path
}

fn golden_package_bytes() -> Vec<u8> {
    let manifest = serde_json::json!({
        "manifest_version": 1,
        "module_id": "reporting-service",
        "version": "1.2.0",
        "runtime": "rust",
        "entrypoint": "payload/reporting-service",
        "files": ["payload/reporting-service"],
    });
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("manifest.json", options)
        .expect("zip must accept the manifest");
    std::io::Write::write_all(
        &mut writer,
        &serde_json::to_vec(&manifest).expect("manifest must serialize"),
    )
    .expect("zip must accept manifest bytes");
    writer
        .start_file("payload/reporting-service", options)
        .expect("zip must accept the payload");
    std::io::Write::write_all(&mut writer, b"not a real executable")
        .expect("zip must accept payload bytes");
    writer.finish().expect("zip must finalize");
    cursor.into_inner()
}

fn text_part(body: &mut Vec<u8>, name: &str, value: &str) {
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(value.as_bytes());
    body.extend_from_slice(b"\r\n");
}

fn file_part(body: &mut Vec<u8>, name: &str, filename: &str, bytes: &[u8]) {
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/zip\r\n\r\n");
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
}

fn upload_body(package: &[u8]) -> Vec<u8> {
    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let digest: [u8; 32] = Sha256DigestProvider
        .digest(package)
        .expect("hashing must succeed");
    let signature = BASE64_STANDARD.encode(signing.sign(&canonical_payload(&digest)).to_bytes());

    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", package);
    text_part(&mut body, "key_id", "k1");
    text_part(&mut body, "signature", &signature);
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn post_upload(
    state: &conductor::api::uploads::AppState,
    package: &[u8],
    bearer: Option<&str>,
) -> StatusCode {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/packages")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        );
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(Body::from(upload_body(package)))
        .expect("request must build");
    router(state.clone())
        .oneshot(request)
        .await
        .expect("router must respond")
        .status()
}

async fn post_json(
    state: &conductor::api::uploads::AppState,
    uri: &str,
    body: serde_json::Value,
    bearer: &str,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::from(
            serde_json::to_vec(&body).expect("request body must serialize"),
        ))
        .expect("request must build");
    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("router must respond");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must read");
    let json = serde_json::from_slice(&bytes).expect("response body must be JSON");
    (status, json)
}

#[tokio::test]
async fn assembled_host_uses_the_operator_token_key_and_storage() {
    let root = temp_root("wired");
    let config = Config::from_file(&write_config(&root)).expect("operator config must parse");
    let state = Host::assemble(config)
        .expect("valid operator config must assemble")
        .into_state();

    let package = golden_package_bytes();
    let expected_digest = ArtifactDigest::new(
        Sha256DigestProvider
            .digest(&package)
            .expect("hashing must succeed"),
    );
    let status = post_upload(&state, &package, Some(OPERATOR_TOKEN)).await;
    assert_eq!(status, StatusCode::CREATED);

    let registered = state
        .registry
        .get("reporting-service", "1.2.0")
        .expect("registry lookup must succeed")
        .expect("the upload must be registered through the assembled database");
    assert_eq!(registered.digest, expected_digest);
    assert_eq!(registered.signer_key_id, "k1");

    let artifact = state
        .artifact_dir
        .join("reporting-service")
        .join("1.2.0")
        .join(format!("{}.zip", expected_digest.to_hex()));
    assert_eq!(
        std::fs::read(&artifact).expect("promoted artifact must read"),
        package
    );
    assert_eq!(
        state
            .recorder
            .store()
            .expect("startup must attach the durable rejection sink")
            .list()
            .expect("rejection rows must read")
            .len(),
        0
    );
    assert_eq!(
        std::fs::read_dir(&state.quarantine_dir)
            .expect("quarantine must exist")
            .count(),
        0,
        "a successful upload must consume its quarantine file"
    );
    cleanup(&root);
}

#[tokio::test]
async fn assembled_host_serves_tls_on_the_configured_bind_and_identity() {
    let root = temp_root("serve-tls");
    std::fs::create_dir_all(&root).expect("root must be created");
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("test certificate must generate");
    let cert_path = root.join("cert.pem");
    let key_path = root.join("key.pem");
    std::fs::write(&cert_path, identity.cert.pem()).expect("cert must be writable");
    std::fs::write(&key_path, identity.signing_key.serialize_pem()).expect("key must be writable");

    let mut config = Config::from_file(&write_config(&root)).expect("operator config must parse");
    config.http_bind = "127.0.0.1:0".to_owned();
    config.tls_cert_path = cert_path;
    config.tls_key_path = key_path;
    let host = Host::assemble(config).expect("valid operator config must assemble");

    // Drive the production serve path, not a rebuilt router: the host must
    // use its configured bind and TLS identity.
    let handle = axum_server::Handle::new();
    let serving = tokio::spawn(host.serve_with_handle(handle.clone()));
    let addr = tokio::time::timeout(Duration::from_secs(5), handle.listening())
        .await
        .expect("server must start promptly")
        .expect("server must report its bound address");

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(identity.cert.der().to_vec()))
        .expect("test certificate must be a valid root");
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect must reach the configured bind");
    let server_name =
        ServerName::try_from("localhost".to_owned()).expect("localhost is a valid server name");
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake must trust the configured identity");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request must send");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("response must read");
    let text = String::from_utf8(response).expect("HTTP response must be UTF-8");
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "healthz must answer over the configured TLS identity: {text}"
    );
    assert!(
        text.contains("\r\n\r\nok"),
        "body must be only `ok`: {text}"
    );
    assert!(
        text.to_ascii_lowercase()
            .contains("strict-transport-security:"),
        "TLS responses must carry HSTS: {text}"
    );

    handle.graceful_shutdown(Some(Duration::from_secs(5)));
    let served = tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("server must shut down promptly")
        .expect("serve task must not panic");
    assert!(served.is_ok(), "graceful shutdown must succeed: {served:?}");
    cleanup(&root);
}

#[tokio::test]
async fn assembled_host_persists_activation_through_its_service() {
    let root = temp_root("activation-wiring");
    let config = Config::from_file(&write_config(&root)).expect("operator config must parse");
    let first = Host::assemble(config.clone())
        .expect("valid operator config must assemble")
        .into_state();
    let package = golden_package_bytes();
    let status = post_upload(&first, &package, Some(OPERATOR_TOKEN)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = post_json(
        &first,
        "/v1/modules/reporting-service/activate",
        serde_json::json!({"version": "1.2.0"}),
        OPERATOR_TOKEN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activation body: {body}");
    assert_eq!(body["module_id"], "reporting-service");
    assert_eq!(body["signer_key_id"], "k1");
    assert_eq!(
        first
            .registry
            .get_active("reporting-service")
            .expect("active lookup must succeed")
            .expect("activation must persist the pointer")
            .version,
        "1.2.0"
    );
    drop(first);

    let second = Host::assemble(config)
        .expect("restart assembly must succeed")
        .into_state();
    assert_eq!(
        second
            .registry
            .get_active("reporting-service")
            .expect("active lookup must succeed")
            .expect("activation must survive the restart")
            .version,
        "1.2.0",
        "the assembled execution service must use the shared persistent registry"
    );
    cleanup(&root);
}

#[tokio::test]
async fn assembled_host_rejects_a_token_the_config_does_not_authorize() {
    let root = temp_root("wrong-token");
    let config = Config::from_file(&write_config(&root)).expect("operator config must parse");
    let state = Host::assemble(config)
        .expect("valid operator config must assemble")
        .into_state();

    let status = post_upload(&state, &golden_package_bytes(), Some("not-the-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let rows = state
        .recorder
        .store()
        .expect("startup must attach the durable rejection sink")
        .list()
        .expect("rejection rows must read");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].code, "missing_or_invalid_bearer");
    assert_eq!(rows[0].stage, "transport");
    cleanup(&root);
}
