//! Startup reconciliation through the real host assembly path.
//!
//! Each test seeds the file-backed registry and artifact tree before
//! `Host::assemble`, then asserts the integrity states the assembled host
//! persisted. No listener is bound and no worker runs.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use conductor::config::{Config, TrustedKeyConfig};
use conductor::control_plane::activate_module::ActivationError;
use conductor::control_plane::execute_module::ExecutionError;
use conductor::modules::registry::{IntegrityState, ModuleRecord, ModuleRegistry};
use conductor::packages::artifact::ArtifactDigest;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::SignatureAlgorithm;
use conductor::server::{Host, StartupError};
use conductor::storage::artifact_store::canonical_artifact_relpath;
use conductor::storage::database::{Database, DatabaseError};

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "conductor-reconciliation-{}-{nanos}-{count}-{tag}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("temp root");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn test_config(root: &Path) -> Config {
    Config {
        api_token: Some("reconciliation-test-token".to_owned()),
        trusted_keys: vec![TrustedKeyConfig {
            key_id: "k1".to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_base64: BASE64_STANDARD.encode([9u8; 32]),
        }],
        storage_root: root.to_path_buf(),
        ..Config::default()
    }
}

fn record(module: &str, version: &str, bytes: &[u8]) -> ModuleRecord {
    let digest = ArtifactDigest::new(Sha256DigestProvider.digest(bytes).expect("hash bytes"));
    ModuleRecord {
        module_id: module.to_owned(),
        version: version.to_owned(),
        digest,
        signer_key_id: "k1".to_owned(),
        runtime: "rust".to_owned(),
        manifest_version: 2,
        manifest_json: "{}".to_owned(),
        artifact_relpath: canonical_artifact_relpath(module, version, &digest),
        artifact_size: bytes.len() as u64,
        integrity_state: IntegrityState::Ok,
        registered_at: SystemTime::UNIX_EPOCH,
    }
}

fn write_artifact(config: &Config, record: &ModuleRecord, bytes: &[u8]) -> PathBuf {
    let path = config.artifact_dir().join(canonical_artifact_relpath(
        &record.module_id,
        &record.version,
        &record.digest,
    ));
    std::fs::create_dir_all(path.parent().expect("artifact parent")).expect("artifact directory");
    std::fs::write(&path, bytes).expect("artifact bytes");
    path
}

fn seed_registry(config: &Config, records: Vec<ModuleRecord>) {
    let registry = ModuleRegistry::open(&config.database_path()).expect("open registry");
    for record in records {
        registry.record(record).expect("register seeded row");
    }
}

fn state(host: &Host, module: &str, version: &str) -> IntegrityState {
    host.state()
        .registry
        .get_integrity_state(module, version)
        .expect("integrity state lookup")
        .expect("seeded version must be registered")
}

#[test]
fn assembled_host_classifies_intact_missing_and_tampered_rows() {
    let root = TempRoot::new("three-rows");
    let config = test_config(root.path());
    let intact_bytes = b"intact artifact bytes";
    let missing_bytes = b"missing artifact bytes";
    let expected_bytes = b"expected artifact bytes";
    let intact = record("intact-module", "1.0.0", intact_bytes);
    let missing = record("missing-module", "1.0.0", missing_bytes);
    let tampered = record("tampered-module", "1.0.0", expected_bytes);
    write_artifact(&config, &intact, intact_bytes);
    write_artifact(&config, &tampered, b"tampered artifact bytes");
    seed_registry(&config, vec![intact, missing, tampered]);

    let host = Host::assemble(config).expect("host must assemble");

    assert_eq!(state(&host, "intact-module", "1.0.0"), IntegrityState::Ok);
    assert_eq!(
        state(&host, "missing-module", "1.0.0"),
        IntegrityState::Missing
    );
    assert_eq!(
        state(&host, "tampered-module", "1.0.0"),
        IntegrityState::Mismatch
    );
}

#[test]
fn startup_aborts_when_registry_scan_fails() {
    let root = TempRoot::new("scan-fails");
    let config = test_config(root.path());
    let database = Database::open(&config.database_path()).expect("database opens");
    database
        .with_connection(|conn| {
            conn.pragma_update(None, "user_version", 2)
                .map_err(|err| DatabaseError::Migration(err.to_string()))
        })
        .expect("schema version is settable");
    drop(database);

    let result = Host::assemble(config);

    assert!(
        matches!(result, Err(StartupError::Reconciliation(_))),
        "a registry scan failure must abort startup"
    );
}

#[test]
fn restart_reclassifies_missing_then_ok() {
    let root = TempRoot::new("restart-reclassify");
    let config = test_config(root.path());
    let bytes = b"restart artifact bytes";
    let record = record("reporting-service", "1.2.0", bytes);
    let path = write_artifact(&config, &record, bytes);
    seed_registry(&config, vec![record.clone()]);

    let first = Host::assemble(config.clone()).expect("first start");
    assert_eq!(
        state(&first, "reporting-service", "1.2.0"),
        IntegrityState::Ok
    );
    drop(first);

    std::fs::remove_file(&path).expect("artifact removal");
    let second = Host::assemble(config.clone()).expect("second start");
    assert_eq!(
        state(&second, "reporting-service", "1.2.0"),
        IntegrityState::Missing
    );
    drop(second);

    write_artifact(&config, &record, bytes);
    let third = Host::assemble(config.clone()).expect("third start");
    assert_eq!(
        state(&third, "reporting-service", "1.2.0"),
        IntegrityState::Ok
    );
}

#[test]
fn mismatch_then_ok_after_restore() {
    let root = TempRoot::new("mismatch-restore");
    let config = test_config(root.path());
    let expected = b"expected artifact bytes";
    let record = record("reporting-service", "2.0.0", expected);
    let path = write_artifact(&config, &record, b"wrong artifact bytes");
    seed_registry(&config, vec![record]);

    let first = Host::assemble(config.clone()).expect("first start");
    assert_eq!(
        state(&first, "reporting-service", "2.0.0"),
        IntegrityState::Mismatch
    );
    drop(first);

    std::fs::write(&path, expected).expect("restore correct bytes");
    let second = Host::assemble(config.clone()).expect("second start");
    assert_eq!(
        state(&second, "reporting-service", "2.0.0"),
        IntegrityState::Ok
    );
}

#[tokio::test]
async fn reconciled_missing_row_refuses_activation() {
    let root = TempRoot::new("activation-refused");
    let config = test_config(root.path());
    seed_registry(
        &config,
        vec![record("reporting-service", "1.2.0", b"absent bytes")],
    );

    let host = Host::assemble(config).expect("host must assemble");
    assert_eq!(
        state(&host, "reporting-service", "1.2.0"),
        IntegrityState::Missing
    );

    let error = host
        .state()
        .execution_service
        .activate("reporting-service", "1.2.0")
        .await
        .expect_err("activation must refuse a missing artifact");

    assert!(matches!(
        error,
        ExecutionError::Activation(ActivationError::Integrity { .. })
    ));
}

#[test]
fn mixed_rows_continue() {
    let root = TempRoot::new("mixed-rows");
    let config = test_config(root.path());
    let missing = record("a-missing", "1.0.0", b"absent bytes");
    let intact = record("b-intact", "2.0.0", b"present bytes");
    write_artifact(&config, &intact, b"present bytes");
    seed_registry(&config, vec![missing, intact]);

    let host = Host::assemble(config).expect("host must assemble");
    assert_eq!(state(&host, "a-missing", "1.0.0"), IntegrityState::Missing);
    assert_eq!(state(&host, "b-intact", "2.0.0"), IntegrityState::Ok);
}

#[test]
fn legacy_non_canonical_row_is_mismatch() {
    let root = TempRoot::new("legacy-row");
    let config = test_config(root.path());
    let mut record = record("reporting-service", "1.0.0", b"legacy bytes");
    record.artifact_relpath = "reporting-service/1.0.0/pkg.zip".to_owned();
    seed_registry(&config, vec![record]);

    let host = Host::assemble(config).expect("host must assemble");

    assert_eq!(
        state(&host, "reporting-service", "1.0.0"),
        IntegrityState::Mismatch
    );
}

#[test]
fn unsafe_identity_row_is_mismatch() {
    let root = TempRoot::new("unsafe-row");
    let config = test_config(root.path());
    seed_registry(&config, vec![record("../..", "1.0.0", b"outside bytes")]);

    let host = Host::assemble(config).expect("host must assemble");

    assert_eq!(state(&host, "../..", "1.0.0"), IntegrityState::Mismatch);
}

#[test]
fn artifact_above_policy_bound_is_mismatch() {
    let root = TempRoot::new("over-bound");
    let config = test_config(root.path());
    let bytes = b"bound artifact bytes";
    let mut record = record("reporting-service", "1.0.0", bytes);
    record.artifact_size = PackageValidationPolicy::production()
        .archive
        .max_compressed_bytes
        + 1;
    write_artifact(&config, &record, bytes);
    seed_registry(&config, vec![record]);

    let host = Host::assemble(config).expect("host must assemble");

    assert_eq!(
        state(&host, "reporting-service", "1.0.0"),
        IntegrityState::Mismatch
    );
}

#[test]
fn no_package_code_runs_during_reconciliation() {
    let root = TempRoot::new("no-exec");
    let config = test_config(root.path());
    let sentinel = root.path().join("reconciliation-executed");
    let script = format!("#!/bin/sh\ntouch {}\n", sentinel.display()).into_bytes();
    let record = record("reporting-service", "1.0.0", &script);
    let path = write_artifact(&config, &record, &script);
    let staging = config.staging_dir();
    seed_registry(&config, vec![record]);

    let host = Host::assemble(config).expect("host must assemble");

    assert_eq!(
        state(&host, "reporting-service", "1.0.0"),
        IntegrityState::Ok
    );
    assert!(
        !sentinel.exists(),
        "reconciliation must never execute artifact bytes"
    );
    assert_eq!(
        std::fs::read(&path).expect("artifact bytes"),
        script,
        "reconciliation must never rewrite artifact bytes"
    );
    assert!(
        std::fs::read_dir(&staging)
            .expect("staging directory")
            .next()
            .is_none(),
        "reconciliation must not extract into staging"
    );
}

#[test]
fn empty_registry_assembles() {
    let root = TempRoot::new("empty-only");
    let host = Host::assemble(test_config(root.path())).expect("empty registry must assemble");

    assert!(
        host.state()
            .registry
            .is_empty()
            .expect("registry emptiness"),
        "an assembled host with no rows must have an empty registry"
    );
}
