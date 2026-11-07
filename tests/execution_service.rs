//! Execution of a registered module version end to end: a signed package is
//! validated, promoted, recorded in an on-disk registry, and executed
//! through [`ExecutionService`] after the registry is reopened.
//!
//! Unix-gated: the worker fixtures are `#!/bin/sh` entrypoints, and the
//! executor only controls process groups on Unix.

#![cfg(unix)]

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use conductor::control_plane::activate_module::{ActivationError, ActivationPolicy};
use conductor::control_plane::execute_module::{
    ActivationHook, ExecutionError, ExecutionService, PreparationHook,
};
use conductor::control_plane::register_package::register;
use conductor::control_plane::validate_package::{PackageValidationBuilder, ValidatedPackage};
use conductor::executions::executor::{ExecutionLimits, ExecutionOutcome};
use conductor::executions::history::ExecutionHistoryStore;
use conductor::metrics::{Metrics, MetricsOptions};
use conductor::modules::registry::{IntegrityState, ModuleRecord, ModuleRegistry};
use conductor::packages::archive::QuarantinedFile;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    canonical_payload, ConfiguredTrustedKeys, PackageSignature, SignatureAlgorithm,
    TrustedSigningKey, SUPPORTED_SIGNATURE_FORMAT_VERSION,
};
use conductor::storage::artifact_store::{
    artifact_relative_path, canonical_artifact_relpath, promote_quarantined,
};
use conductor::storage::database::Database;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::InMemoryMetricExporter;

/// Test-only signing key. This private key must never sign anything outside
/// these tests.
const TEST_SIGNING_KEY: [u8; 32] = [42u8; 32];
const MODULE_ID: &str = "worker-fixture";
const VERSION: &str = "1.0.0";

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Process-unique scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let count = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "conductor-execution-service-{}-{tag}-{count}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir must be creatable");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn validator() -> (
    conductor::control_plane::validate_package::PackageValidator,
    ed25519_dalek::SigningKey,
) {
    use ed25519_dalek::SigningKey;

    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )])
    .expect("distinct test keys must build");
    let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(keys)
        .build()
        .expect("test validator must build");
    (validator, signing)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256DigestProvider
        .digest(bytes)
        .expect("hash must succeed")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Builds a manifest-v2 package whose entrypoint is the supplied shell
/// script, with real per-file integrity declarations.
fn package_bytes(module_id: &str, version: &str, script: &str) -> Vec<u8> {
    package_bytes_with_extra(module_id, version, script, None)
}

/// Like [`package_bytes`], optionally carrying a second declared file. Used
/// to prove that a stored manifest cannot redirect the entrypoint to another
/// file that is genuinely present in the archive.
fn package_bytes_with_extra(
    module_id: &str,
    version: &str,
    script: &str,
    extra: Option<&str>,
) -> Vec<u8> {
    let mut files = vec![serde_json::json!({
        "path": "payload/worker",
        "size": script.len() as u64,
        "sha256": sha256_hex(script.as_bytes()),
    })];
    if let Some(extra) = extra {
        files.push(serde_json::json!({
            "path": "payload/extra",
            "size": extra.len() as u64,
            "sha256": sha256_hex(extra.as_bytes()),
        }));
    }
    let manifest = serde_json::json!({
        "manifest_version": 2,
        "module_id": module_id,
        "version": version,
        "runtime": "rust",
        "entrypoint": "payload/worker",
        "files": files,
    });
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("manifest.json", options)
        .expect("manifest entry must be writable");
    writer
        .write_all(&serde_json::to_vec(&manifest).expect("manifest must serialize"))
        .expect("manifest bytes must be writable");
    writer
        .start_file("payload/worker", options)
        .expect("payload entry must be writable");
    writer
        .write_all(script.as_bytes())
        .expect("payload bytes must be writable");
    if let Some(extra) = extra {
        writer
            .start_file("payload/extra", options)
            .expect("extra entry must be writable");
        writer
            .write_all(extra.as_bytes())
            .expect("extra bytes must be writable");
    }
    writer.finish().expect("zip must finalize");
    cursor.into_inner()
}

/// Builds a package with caller-controlled manifest identity, schema
/// version, runtime, entrypoint, and payload files. v2 declarations carry
/// real per-file integrity; v1 lists paths only.
fn package_bytes_custom(
    manifest_version: u32,
    module_id: &str,
    version: &str,
    runtime: &str,
    entrypoint: &str,
    files: &[(&str, &str)],
) -> Vec<u8> {
    let declared: Vec<serde_json::Value> = files
        .iter()
        .map(|(path, contents)| {
            if manifest_version == 2 {
                serde_json::json!({
                    "path": path,
                    "size": contents.len() as u64,
                    "sha256": sha256_hex(contents.as_bytes()),
                })
            } else {
                serde_json::json!(path)
            }
        })
        .collect();
    let manifest = serde_json::json!({
        "manifest_version": manifest_version,
        "module_id": module_id,
        "version": version,
        "runtime": runtime,
        "entrypoint": entrypoint,
        "files": declared,
    });
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("manifest.json", options)
        .expect("manifest entry must be writable");
    writer
        .write_all(&serde_json::to_vec(&manifest).expect("manifest must serialize"))
        .expect("manifest bytes must be writable");
    for (path, contents) in files {
        writer
            .start_file(*path, options)
            .expect("payload entry must be writable");
        writer
            .write_all(contents.as_bytes())
            .expect("payload bytes must be writable");
    }
    writer.finish().expect("zip must finalize");
    cursor.into_inner()
}

fn validated(scratch: &Scratch, bytes: &[u8]) -> ValidatedPackage {
    use ed25519_dalek::Signer as _;

    let (validator, signing) = validator();
    let digest: [u8; 32] = Sha256DigestProvider
        .digest(bytes)
        .expect("hashing must succeed");
    let envelope = PackageSignature {
        format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
        key_id: "k1".to_owned(),
        signature: signing
            .sign(&canonical_payload(&digest))
            .to_bytes()
            .to_vec(),
    };
    let archive = scratch.file("pkg.zip");
    std::fs::write(&archive, bytes).expect("package must be writable");
    let mut handle = QuarantinedFile::open(&archive).expect("quarantine must open");
    validator
        .validate(&mut handle, &envelope)
        .expect("package must validate")
}

/// One validated, promoted package plus its staging/artifact layout.
struct Fixture {
    verdict: ValidatedPackage,
    relpath: String,
    artifact_path: PathBuf,
    artifact_dir: PathBuf,
    staging_dir: PathBuf,
}

fn fixture(scratch: &Scratch, module_id: &str, version: &str, script: &str) -> Fixture {
    fixture_from_bytes(scratch, &package_bytes(module_id, version, script))
}

fn fixture_with_extra(
    scratch: &Scratch,
    module_id: &str,
    version: &str,
    script: &str,
    extra: &str,
) -> Fixture {
    fixture_from_bytes(
        scratch,
        &package_bytes_with_extra(module_id, version, script, Some(extra)),
    )
}

/// Tightens a fixture directory to the owner-only mode the service requires,
/// so a permissive test-runner umask cannot turn valid fixtures into
/// world-writable directories.
fn tighten_private(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(dir)
        .expect("fixture directory must exist")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(dir, permissions).expect("fixture permissions must be settable");
}

fn fixture_from_bytes(scratch: &Scratch, bytes: &[u8]) -> Fixture {
    let verdict = validated(scratch, bytes);
    let artifact_dir = scratch.path().join("artifacts");
    let artifact_path =
        promote_quarantined(&artifact_dir, &scratch.file("pkg.zip"), &verdict).expect("promote");
    let staging_dir = scratch.path().join("staging");
    std::fs::create_dir_all(&staging_dir).expect("staging dir must be creatable");
    tighten_private(&artifact_dir);
    tighten_private(&staging_dir);
    let relpath = artifact_relative_path(&verdict);
    Fixture {
        verdict,
        relpath,
        artifact_path,
        artifact_dir,
        staging_dir,
    }
}

impl Fixture {
    fn service(&self, registry: Arc<ModuleRegistry>, max_deadline: Duration) -> ExecutionService {
        self.service_with(
            registry,
            max_deadline,
            HashSet::from(["k1".to_owned()]),
            4,
            PackageValidationPolicy::production(),
        )
    }

    fn try_service_with(
        &self,
        registry: Arc<ModuleRegistry>,
        max_deadline: Duration,
        allowed_signers: HashSet<String>,
        max_concurrent_executions: usize,
        package_policy: PackageValidationPolicy,
    ) -> Result<ExecutionService, ExecutionError> {
        self.try_service_with_history(
            registry,
            max_deadline,
            allowed_signers,
            max_concurrent_executions,
            package_policy,
            Arc::new(ExecutionHistoryStore::open_in_memory().expect("execution history must open")),
        )
    }

    fn try_service_with_history(
        &self,
        registry: Arc<ModuleRegistry>,
        max_deadline: Duration,
        allowed_signers: HashSet<String>,
        max_concurrent_executions: usize,
        package_policy: PackageValidationPolicy,
        history: Arc<ExecutionHistoryStore>,
    ) -> Result<ExecutionService, ExecutionError> {
        let metrics = Metrics::new(MetricsOptions::default()).expect("metrics must build");
        self.try_service_with_history_and_metrics(
            registry,
            max_deadline,
            allowed_signers,
            max_concurrent_executions,
            package_policy,
            history,
            metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_service_with_history_and_metrics(
        &self,
        registry: Arc<ModuleRegistry>,
        max_deadline: Duration,
        allowed_signers: HashSet<String>,
        max_concurrent_executions: usize,
        package_policy: PackageValidationPolicy,
        history: Arc<ExecutionHistoryStore>,
        metrics: Arc<Metrics>,
    ) -> Result<ExecutionService, ExecutionError> {
        ExecutionService::new(
            registry,
            self.artifact_dir.clone(),
            self.staging_dir.clone(),
            ActivationPolicy::new(vec!["rust".to_owned()]).expect("activation policy"),
            ExecutionLimits::default(),
            max_deadline,
            package_policy,
            allowed_signers,
            max_concurrent_executions,
            history,
            metrics,
        )
    }

    fn service_with_metrics(
        &self,
        registry: Arc<ModuleRegistry>,
        max_deadline: Duration,
        allowed_signers: HashSet<String>,
        max_concurrent_executions: usize,
        package_policy: PackageValidationPolicy,
        metrics: Arc<Metrics>,
    ) -> ExecutionService {
        self.try_service_with_history_and_metrics(
            registry,
            max_deadline,
            allowed_signers,
            max_concurrent_executions,
            package_policy,
            Arc::new(ExecutionHistoryStore::open_in_memory().expect("execution history must open")),
            metrics,
        )
        .expect("execution service must build")
    }

    fn service_with(
        &self,
        registry: Arc<ModuleRegistry>,
        max_deadline: Duration,
        allowed_signers: HashSet<String>,
        max_concurrent_executions: usize,
        package_policy: PackageValidationPolicy,
    ) -> ExecutionService {
        self.try_service_with(
            registry,
            max_deadline,
            allowed_signers,
            max_concurrent_executions,
            package_policy,
        )
        .expect("execution service must build")
    }

    fn record(&self) -> ModuleRecord {
        let registry = ModuleRegistry::new();
        register(&registry, &self.verdict, &self.relpath)
            .expect("registration must succeed")
            .record
    }

    /// The exact validated manifest bytes as mutable JSON, for tests that
    /// tamper with registry-side state.
    fn stored_manifest(&self) -> serde_json::Value {
        serde_json::from_str(&self.record().manifest_json)
            .expect("stored manifest must be valid JSON")
    }

    /// Builds a record whose registry identity and stored manifest come from
    /// `manifest`, while the artifact bytes stay those of this fixture. When
    /// the identity changes, the artifact is copied to the new canonical
    /// address so only the manifest comparison can refuse it.
    fn record_with_identity(
        &self,
        module_id: &str,
        version: &str,
        manifest: serde_json::Value,
    ) -> ModuleRecord {
        let digest = *self.verdict.artifact().digest();
        let relpath = canonical_artifact_relpath(module_id, version, &digest);
        let destination = self.artifact_dir.join(&relpath);
        if destination != self.artifact_path {
            std::fs::create_dir_all(destination.parent().expect("artifact parent"))
                .expect("artifact identity directories must be creatable");
            std::fs::copy(&self.artifact_path, &destination)
                .expect("artifact must be copyable to its identity address");
        }
        let mut record = self.record();
        record.module_id = module_id.to_owned();
        record.version = version.to_owned();
        record.manifest_version = manifest["manifest_version"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .expect("stored manifest_version must fit u32");
        record.runtime = manifest["runtime"]
            .as_str()
            .expect("stored runtime must be a string")
            .to_owned();
        record.manifest_json = manifest.to_string();
        record.artifact_relpath = relpath;
        record.digest = digest;
        record.artifact_size = self.verdict.artifact_size();
        record.registered_at = SystemTime::now();
        record
    }

    fn active_registry(&self, record: ModuleRecord) -> Arc<ModuleRegistry> {
        let module_id = record.module_id.clone();
        let version = record.version.clone();
        self.active_registry_for(&module_id, &version, record)
    }

    fn active_registry_for(
        &self,
        module_id: &str,
        version: &str,
        record: ModuleRecord,
    ) -> Arc<ModuleRegistry> {
        let registry = ModuleRegistry::new();
        registry.record(record).expect("record must register");
        registry
            .set_active(module_id, version)
            .expect("record must activate");
        Arc::new(registry)
    }
}

fn capture_metrics() -> (Arc<Metrics>, InMemoryMetricExporter) {
    let exporter = InMemoryMetricExporter::default();
    let metrics = Metrics::with_exporter(MetricsOptions::default(), exporter.clone())
        .expect("in-memory metrics must build");
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
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() {
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

fn u64_sum_no_attributes(data: &[ResourceMetrics], name: &str) -> Option<u64> {
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() {
                    return sum
                        .data_points()
                        .find(|point| point.attributes().next().is_none())
                        .map(|point| point.value());
                }
            }
        }
    }
    None
}

/// Total of every data point for `name`, regardless of attributes. Used to
/// assert that an instrument emitted no point at all.
fn u64_sum_overall(data: &[ResourceMetrics], name: &str) -> Option<u64> {
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() {
                    let mut total = None;
                    for point in sum.data_points() {
                        total = Some(total.unwrap_or(0) + point.value());
                    }
                    if total.is_some() {
                        return total;
                    }
                }
            }
        }
    }
    None
}

fn i64_sum(data: &[ResourceMetrics], name: &str) -> Option<i64> {
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::I64(MetricData::Sum(sum)) = metric.data() {
                    return sum.data_points().map(|point| point.value()).next();
                }
            }
        }
    }
    None
}

fn histogram_has_attributes(data: &[ResourceMetrics], name: &str, key: &str, value: &str) -> bool {
    for resource in data {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name {
                    continue;
                }
                if let AggregatedMetrics::F64(MetricData::Histogram(histogram)) = metric.data() {
                    for point in histogram.data_points() {
                        if point.count() > 0 && attributes_match(point.attributes(), key, value) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

const SCRIPT_OK: &str = r#"#!/bin/sh
read -r line
printf 'diagnostic: reopened worker\n' >&2
printf '{"protocol_version":1,"status":"ok","result":{"rows":3}}\n'
"#;

/// Runs an execution that is expected to be refused and returns the typed
/// error. Keeps each refusal test focused on the error it pins.
async fn refused_execution(service: &ExecutionService, module_id: &str) -> ExecutionError {
    service
        .execute(
            module_id,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err()
}

#[tokio::test]
async fn registered_worker_executes_after_the_registry_is_reopened() {
    let scratch = Scratch::new("reopen");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let db = scratch.path().join("database").join("conductor.db");
    {
        let registry = ModuleRegistry::open(&db).expect("registry must open");
        register(&registry, &fixture.verdict, &fixture.relpath).expect("register");
        registry
            .set_active(MODULE_ID, VERSION)
            .expect("active version must persist");
    }

    let registry = Arc::new(ModuleRegistry::open(&db).expect("registry must reopen"));
    assert!(
        registry
            .get_active(MODULE_ID)
            .expect("active lookup")
            .is_some(),
        "the active pointer must survive the restart"
    );
    let service = fixture.service(Arc::clone(&registry), Duration::from_secs(30));

    let receipt = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({"batch": 7}),
            Duration::from_secs(10),
        )
        .await
        .expect("execution must succeed");

    assert_eq!(
        receipt.outcome,
        ExecutionOutcome::Succeeded {
            result: serde_json::json!({"rows": 3}),
        }
    );
    assert_eq!(receipt.module_id, MODULE_ID);
    assert_eq!(receipt.version, VERSION);
    assert_eq!(receipt.digest, *fixture.verdict.artifact().digest());
    assert!(!receipt.execution_id.is_empty());
    assert!(
        receipt.stdout.text_lossy().contains("\"rows\":3"),
        "the bounded stdout must carry the protocol response"
    );
    assert!(receipt
        .stderr
        .text_lossy()
        .contains("diagnostic: reopened worker"));
}

#[tokio::test]
async fn completed_execution_persists_a_metadata_receipt() {
    let scratch = Scratch::new("history-receipt");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );

    let receipt = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({"batch": 7}),
            Duration::from_secs(10),
        )
        .await
        .expect("execution must succeed");

    let record = service
        .find_execution(&receipt.execution_id)
        .await
        .expect("history lookup must succeed")
        .expect("a completed execution must persist a receipt");
    assert_eq!(record.execution_id, receipt.execution_id);
    assert_eq!(record.module_id, MODULE_ID);
    assert_eq!(record.version, VERSION);
    assert_eq!(record.digest, receipt.digest.to_hex());
    assert_eq!(record.function, "run");
    assert_eq!(record.outcome, "succeeded");
    assert!(
        record.started_at <= record.finished_at,
        "started_at must not be after finished_at"
    );
    assert!(
        record.duration_ms < 60_000,
        "a fixture worker cannot run for a minute: {}",
        record.duration_ms
    );

    let listed = service
        .list_executions(10, 0)
        .await
        .expect("history list must succeed");
    assert_eq!(listed, vec![record]);
}

#[tokio::test]
async fn failed_worker_persists_a_failed_outcome() {
    const SCRIPT_FAILED: &str = r#"#!/bin/sh
read -r line
printf '{"protocol_version":1,"status":"failed","message":"boom"}\n'
"#;
    let scratch = Scratch::new("history-failed");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_FAILED);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );

    let receipt = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .expect("a spawned worker reports through its outcome, not an error");
    assert_eq!(receipt.outcome.as_str(), "failed");

    let record = service
        .find_execution(&receipt.execution_id)
        .await
        .expect("history lookup must succeed")
        .expect("a failed worker must still persist a receipt");
    assert_eq!(record.outcome, "failed");
    assert_eq!(record.execution_id, receipt.execution_id);
}

#[tokio::test]
async fn nonzero_worker_exit_persists_worker_error() {
    let scratch = Scratch::new("history-nonzero-exit");
    let fixture = fixture(
        &scratch,
        MODULE_ID,
        VERSION,
        "#!/bin/sh\nread -r line\nexit 3\n",
    );
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );

    let receipt = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .expect("a spawned worker reports through its outcome, not an error");
    assert_eq!(receipt.outcome.as_str(), "worker_error");

    let record = service
        .find_execution(&receipt.execution_id)
        .await
        .expect("history lookup must succeed")
        .expect("a nonzero worker exit must still persist a receipt");
    assert_eq!(record.outcome, "worker_error");
}

#[tokio::test]
async fn pre_spawn_refusals_do_not_create_history_rows() {
    let scratch = Scratch::new("history-refusals");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, "missing-module").await;
    assert!(matches!(
        err,
        ExecutionError::Activation(ActivationError::NoActiveVersion { .. })
    ));
    assert!(
        service
            .list_executions(10, 0)
            .await
            .expect("history list must succeed")
            .is_empty(),
        "a pre-spawn refusal must not create a history row"
    );

    let mut bytes = std::fs::read(&fixture.artifact_path).expect("artifact must be readable");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xFF;
    std::fs::write(&fixture.artifact_path, &bytes).expect("tampered bytes must be writable");
    let err = refused_execution(&service, MODULE_ID).await;
    assert!(matches!(err, ExecutionError::ArtifactDigestMismatch { .. }));
    assert!(
        service
            .list_executions(10, 0)
            .await
            .expect("history list must succeed")
            .is_empty(),
        "an integrity refusal must not create a history row"
    );
}

#[tokio::test]
async fn history_write_failure_fails_the_execution_without_a_receipt() {
    let scratch = Scratch::new("history-write-failure");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    // An unmigrated database has no `executions` table, so the insert can
    // only fail. The worker still runs; the missing durable receipt must
    // fail the request instead of returning a successful receipt.
    let unmigrated = Database::open_in_memory().expect("in-memory database must open");
    let history = Arc::new(ExecutionHistoryStore::new(Arc::new(unmigrated)));
    let service = fixture
        .try_service_with_history(
            Arc::clone(&fixture.active_registry(fixture.record())),
            Duration::from_secs(30),
            HashSet::from(["k1".to_owned()]),
            4,
            PackageValidationPolicy::production(),
            history,
        )
        .expect("execution service must build");

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .expect_err("a history write failure must not return a receipt");
    assert!(
        matches!(err, ExecutionError::History(_)),
        "expected a typed history failure, got {err:?}"
    );
    assert_eq!(err.to_string(), "failed to record execution history");
}

#[tokio::test]
async fn successful_execution_emits_completion_duration_and_slot_gauges() {
    let scratch = Scratch::new("metrics-success");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let (metrics, exporter) = capture_metrics();
    let service = fixture.service_with_metrics(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
        HashSet::from(["k1".to_owned()]),
        4,
        PackageValidationPolicy::production(),
        Arc::clone(&metrics),
    );

    exporter.reset();
    let receipt = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({"batch": 7}),
            Duration::from_secs(10),
        )
        .await
        .expect("execution must succeed");

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum(
            &data,
            "conductor.execution.completed",
            "conductor.execution.outcome",
            "succeeded"
        ),
        Some(1),
        "a successful worker must increment the completed counter"
    );
    assert!(
        histogram_has_attributes(
            &data,
            "conductor.execution.duration",
            "conductor.execution.phase",
            "run"
        ),
        "the run phase must be recorded"
    );
    assert_eq!(
        i64_sum(&data, "conductor.execution.slots.in_use"),
        Some(0),
        "the slot gauge must return to zero"
    );

    // No identity, path, token, or configuration may be an attribute.
    let rendered = format!("{data:?}");
    for leaked in [
        MODULE_ID,
        VERSION,
        receipt.execution_id.as_str(),
        fixture.artifact_dir.to_str().expect("temp path"),
        ".zip",
        "k1",
        "batch",
    ] {
        assert!(
            !rendered.contains(leaked),
            "metric data leaked {leaked:?}: {rendered}"
        );
    }
}

#[tokio::test]
async fn execution_overload_emits_the_overload_counter() {
    let scratch = Scratch::new("metrics-overload");
    let marker = scratch.file("started");
    let release = scratch.file("release");
    let script = format!(
        "#!/bin/sh\nread -r line\nprintf started > '{}'\ni=0\nwhile [ ! -e '{}' ]; do i=$((i+1)); [ \"$i\" -ge 1000 ] && break; sleep 0.01; done\nprintf '{{\"protocol_version\":1,\"status\":\"ok\",\"result\":null}}\\n'\n",
        marker.display(),
        release.display()
    );
    let fixture = fixture(&scratch, MODULE_ID, VERSION, &script);
    let (metrics, exporter) = capture_metrics();
    let service = fixture.service_with_metrics(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
        HashSet::from(["k1".to_owned()]),
        1,
        PackageValidationPolicy::production(),
        Arc::clone(&metrics),
    );

    exporter.reset();
    let background = {
        let service = service.clone();
        tokio::spawn(async move {
            service
                .execute(
                    MODULE_ID,
                    None,
                    "run",
                    serde_json::json!({}),
                    Duration::from_secs(10),
                )
                .await
        })
    };
    assert!(
        wait_for_path(&marker, Duration::from_secs(10)).await,
        "the first execution must start before capacity is probed"
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::Overloaded { maximum: 1 }));

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum_no_attributes(&data, "conductor.execution.overload"),
        Some(1),
        "a fail-fast capacity refusal must be counted"
    );
    assert_eq!(
        u64_sum_overall(&data, "conductor.execution.refused"),
        None,
        "overload is authoritative and must not also count as a generic refusal"
    );

    std::fs::write(&release, b"go").expect("release marker must be writable");
    let first = background
        .await
        .expect("background task must join")
        .expect("the first execution must succeed");
    assert!(matches!(first.outcome, ExecutionOutcome::Succeeded { .. }));
}

#[tokio::test]
async fn history_write_failure_emits_the_failure_counter() {
    let scratch = Scratch::new("metrics-history-failure");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let (metrics, exporter) = capture_metrics();
    let unmigrated = Database::open_in_memory().expect("in-memory database must open");
    let service = fixture
        .try_service_with_history_and_metrics(
            Arc::clone(&fixture.active_registry(fixture.record())),
            Duration::from_secs(30),
            HashSet::from(["k1".to_owned()]),
            4,
            PackageValidationPolicy::production(),
            Arc::new(ExecutionHistoryStore::new(Arc::new(unmigrated))),
            Arc::clone(&metrics),
        )
        .expect("execution service must build");

    exporter.reset();
    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .expect_err("history failure must fail the execution");
    assert!(matches!(err, ExecutionError::History(_)));

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum_no_attributes(&data, "conductor.execution.history.write.failures"),
        Some(1),
        "a failed history insert must be counted"
    );
    assert_eq!(
        u64_sum(
            &data,
            "conductor.execution.completed",
            "conductor.execution.outcome",
            "succeeded"
        ),
        Some(1),
        "the completed worker must remain observable before the failed insert"
    );
    assert_eq!(
        u64_sum_overall(&data, "conductor.execution.refused"),
        None,
        "the history failure counter is authoritative; completion must not also be a refusal"
    );
    assert_eq!(i64_sum(&data, "conductor.execution.slots.in_use"), Some(0));
}

#[tokio::test]
async fn tampered_artifact_emits_integrity_and_refusal_metrics() {
    let scratch = Scratch::new("metrics-tamper");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let (metrics, exporter) = capture_metrics();
    let service = fixture.service_with_metrics(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
        HashSet::from(["k1".to_owned()]),
        4,
        PackageValidationPolicy::production(),
        Arc::clone(&metrics),
    );

    let mut bytes = std::fs::read(&fixture.artifact_path).expect("artifact must be readable");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xFF;
    std::fs::write(&fixture.artifact_path, &bytes).expect("tampered bytes must be writable");

    exporter.reset();
    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::ArtifactDigestMismatch { .. }));

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum(
            &data,
            "conductor.artifact.integrity.failures",
            "conductor.integrity.kind",
            "digest"
        ),
        Some(1),
        "a digest mismatch must be classified"
    );
    assert_eq!(
        u64_sum(
            &data,
            "conductor.execution.refused",
            "conductor.execution.reason",
            "integrity"
        ),
        Some(1),
        "the refusal must be classified as integrity"
    );
    let rendered = format!("{data:?}");
    for leaked in [
        MODULE_ID,
        VERSION,
        fixture.artifact_path.to_str().expect("temp path"),
        ".zip",
        "k1",
    ] {
        assert!(
            !rendered.contains(leaked),
            "metric data leaked {leaked:?}: {rendered}"
        );
    }
}

#[tokio::test]
async fn activation_tamper_emits_integrity_metrics() {
    let scratch = Scratch::new("metrics-activate-tamper");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let (metrics, exporter) = capture_metrics();
    let registry = Arc::new(ModuleRegistry::new());
    registry
        .record(fixture.record())
        .expect("record must register");
    let service = fixture.service_with_metrics(
        registry,
        Duration::from_secs(30),
        HashSet::from(["k1".to_owned()]),
        4,
        PackageValidationPolicy::production(),
        Arc::clone(&metrics),
    );

    let bytes = std::fs::read(&fixture.artifact_path).expect("artifact must be readable");
    std::fs::write(&fixture.artifact_path, &bytes[..bytes.len() - 1])
        .expect("truncated bytes must be writable");

    exporter.reset();
    let err = service
        .activate(MODULE_ID, VERSION)
        .await
        .expect_err("activation must verify artifact bytes");
    assert!(matches!(err, ExecutionError::ArtifactSizeMismatch { .. }));

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum(
            &data,
            "conductor.artifact.integrity.failures",
            "conductor.integrity.kind",
            "size"
        ),
        Some(1),
        "activation must classify artifact damage"
    );
}

#[tokio::test]
async fn registry_integrity_state_emits_integrity_metrics_for_activate_and_execute() {
    let scratch = Scratch::new("metrics-registry-state");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let (metrics, exporter) = capture_metrics();
    let registry = Arc::new(ModuleRegistry::new());
    registry
        .record(fixture.record())
        .expect("record must register");
    registry
        .set_integrity_state(MODULE_ID, VERSION, IntegrityState::Missing)
        .expect("integrity state must be markable");
    let service = fixture.service_with_metrics(
        registry,
        Duration::from_secs(30),
        HashSet::from(["k1".to_owned()]),
        4,
        PackageValidationPolicy::production(),
        Arc::clone(&metrics),
    );

    exporter.reset();
    let err = service
        .activate(MODULE_ID, VERSION)
        .await
        .expect_err("a registry state of Missing must refuse activation");
    assert!(
        matches!(
            err,
            ExecutionError::Activation(ActivationError::Integrity {
                state: IntegrityState::Missing,
                ..
            })
        ),
        "unexpected activation error: {err:?}"
    );
    let err = service
        .execute(
            MODULE_ID,
            Some(VERSION),
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .expect_err("a registry state of Missing must refuse execution");
    assert!(
        matches!(
            err,
            ExecutionError::Activation(ActivationError::Integrity {
                state: IntegrityState::Missing,
                ..
            })
        ),
        "unexpected execution error: {err:?}"
    );

    let data = exported(&metrics, &exporter);
    assert_eq!(
        u64_sum(
            &data,
            "conductor.artifact.integrity.failures",
            "conductor.integrity.kind",
            "registry_state"
        ),
        Some(2),
        "activation and execution must both count the registry integrity state"
    );
    assert_eq!(
        u64_sum(
            &data,
            "conductor.execution.refused",
            "conductor.execution.reason",
            "integrity"
        ),
        Some(1),
        "the execution refusal keeps its integrity reason"
    );
}

#[tokio::test]
async fn activate_persists_the_active_version_across_a_reopen() {
    let scratch = Scratch::new("activate-persist");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let db = scratch.path().join("database").join("conductor.db");
    {
        let registry = Arc::new(ModuleRegistry::open(&db).expect("registry must open"));
        register(&registry, &fixture.verdict, &fixture.relpath).expect("register");
        let service = fixture.service(Arc::clone(&registry), Duration::from_secs(30));
        let activated = service
            .activate(MODULE_ID, VERSION)
            .await
            .expect("activation must succeed");
        assert_eq!(activated.version, VERSION);
    }

    let reopened = ModuleRegistry::open(&db).expect("registry must reopen");
    let active = reopened
        .get_active(MODULE_ID)
        .expect("active lookup")
        .expect("the service must have persisted the pointer");
    assert_eq!(active.version, VERSION);
}

#[tokio::test]
async fn activation_capacity_is_bounded_and_released() {
    let scratch = Scratch::new("activation-capacity");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let registry = Arc::new(ModuleRegistry::new());
    registry
        .record(fixture.record())
        .expect("record must register");
    let service = fixture.service_with(
        Arc::clone(&registry),
        Duration::from_secs(30),
        HashSet::from(["k1".to_owned()]),
        1,
        PackageValidationPolicy::production(),
    );

    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let started_tx = std::sync::Mutex::new(Some(started_tx));
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let first_activation = Arc::new(AtomicBool::new(true));
    let hook = ActivationHook::new({
        let first_activation = Arc::clone(&first_activation);
        move || {
            if first_activation.swap(false, Ordering::SeqCst) {
                if let Some(started_tx) = started_tx
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    let _ = started_tx.send(());
                }
                let _ = release_rx
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .recv();
            }
        }
    });
    let service = service.with_activation_hook(hook);

    let first = tokio::spawn({
        let service = service.clone();
        async move { service.activate(MODULE_ID, VERSION).await }
    });
    started_rx
        .await
        .expect("the first activation must start before capacity is probed");

    let err = service.activate(MODULE_ID, VERSION).await.unwrap_err();
    assert!(
        matches!(err, ExecutionError::Overloaded { maximum: 1 }),
        "activation must fail fast at its bound: {err:?}"
    );

    release_tx
        .send(())
        .expect("activation must still be waiting");
    let activated = first
        .await
        .expect("background task must join")
        .expect("the first activation must succeed");
    assert_eq!(activated.version, VERSION);

    // The permit is returned after both success and failure paths.
    let again = service
        .activate(MODULE_ID, VERSION)
        .await
        .expect("capacity must return after the first activation");
    assert_eq!(again.version, VERSION);
}

#[tokio::test]
async fn tampered_artifact_bytes_are_refused_before_spawn() {
    let scratch = Scratch::new("tamper-bytes");
    let marker = scratch.file("spawned");
    let script = format!(
        "#!/bin/sh\nread -r line\nprintf ran > '{}'\nprintf '{{\"protocol_version\":1,\"status\":\"ok\"}}\\n'\n",
        marker.display()
    );
    let fixture = fixture(&scratch, MODULE_ID, VERSION, &script);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );

    // Same length, different bytes: only the digest can catch this.
    let mut bytes = std::fs::read(&fixture.artifact_path).expect("artifact must be readable");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xFF;
    std::fs::write(&fixture.artifact_path, &bytes).expect("tampered bytes must be writable");

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::ArtifactDigestMismatch { .. }));
    assert!(
        !marker.exists(),
        "no worker may spawn after an artifact integrity failure"
    );
    assert_eq!(
        std::fs::read_dir(&fixture.staging_dir)
            .expect("staging root must be readable")
            .count(),
        0,
        "integrity failures must not create staging directories"
    );
}

#[tokio::test]
async fn truncated_artifact_is_refused_by_the_size_check() {
    let scratch = Scratch::new("tamper-size");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );

    let bytes = std::fs::read(&fixture.artifact_path).expect("artifact must be readable");
    std::fs::write(&fixture.artifact_path, &bytes[..bytes.len() - 1])
        .expect("truncated bytes must be writable");

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::ArtifactSizeMismatch { .. }));
}

#[tokio::test]
async fn missing_artifact_is_refused() {
    let scratch = Scratch::new("missing-artifact");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );
    std::fs::remove_file(&fixture.artifact_path).expect("artifact must be removable");

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::ArtifactMissing { .. }));
}

#[tokio::test]
async fn artifact_path_escape_is_refused() {
    let scratch = Scratch::new("path-escape");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let mut record = fixture.record();
    record.artifact_relpath = "../../etc/passwd".to_owned();
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::ArtifactPathEscape { .. }));
}

#[tokio::test]
async fn manifest_identity_mismatch_is_refused() {
    let scratch = Scratch::new("manifest-identity");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let mut record = fixture.record();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&record.manifest_json).expect("stored manifest must be JSON");
    manifest["module_id"] = serde_json::json!("other-module");
    record.manifest_json = manifest.to_string();
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::ManifestIdentityMismatch {
            field: "module_id",
            ..
        }
    ));
}

#[tokio::test]
async fn execution_without_an_active_version_is_refused() {
    let scratch = Scratch::new("no-active");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let registry = ModuleRegistry::new();
    registry
        .record(fixture.record())
        .expect("record must register, but not activate");
    let service = fixture.service(Arc::new(registry), Duration::from_secs(30));

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::Activation(ActivationError::NoActiveVersion { .. })
    ));
}

#[tokio::test]
async fn pinned_unregistered_version_is_refused() {
    let scratch = Scratch::new("unregistered");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let service = fixture.service(Arc::new(ModuleRegistry::new()), Duration::from_secs(30));

    let err = service
        .execute(
            MODULE_ID,
            Some("9.9.9"),
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::Activation(ActivationError::NotRegistered { .. })
    ));
}

#[tokio::test]
async fn deadline_above_the_host_maximum_is_refused() {
    let scratch = Scratch::new("deadline");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_millis(500),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
    match err {
        ExecutionError::DeadlineExceeded { requested, maximum } => {
            assert_eq!(requested, Duration::from_secs(2));
            assert_eq!(maximum, Duration::from_millis(500));
        }
        other => panic!("expected a deadline refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn execution_refuses_runtime_and_integrity_policy_violations() {
    let scratch = Scratch::new("policy");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");

    let mut wrong_runtime = fixture.record();
    wrong_runtime.runtime = "python".to_owned();
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(wrong_runtime)),
        Duration::from_secs(30),
    );
    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::Activation(ActivationError::RuntimeNotAllowed { .. })
    ));

    let registry = ModuleRegistry::new();
    registry
        .record(fixture.record())
        .expect("record must register");
    registry
        .set_integrity_state(MODULE_ID, VERSION, IntegrityState::Missing)
        .expect("integrity state must be markable");
    let service = fixture.service(Arc::new(registry), Duration::from_secs(30));
    let err = service
        .execute(
            MODULE_ID,
            Some(VERSION),
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::Activation(ActivationError::Integrity { .. })
    ));
}

#[tokio::test]
async fn absolute_artifact_path_is_refused() {
    let scratch = Scratch::new("absolute-path");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let mut record = fixture.record();
    record.artifact_relpath = fixture.artifact_path.display().to_string();
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::ArtifactPathEscape { .. }));
}

#[tokio::test]
async fn artifact_path_prefix_confusion_with_a_sibling_directory_is_refused() {
    let scratch = Scratch::new("prefix-confusion");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    // A sibling of the artifact root shares its string prefix. Copy the
    // genuine bytes there so only confinement (not hashing) can refuse it.
    let sibling = scratch.file("artifacts-evil");
    let sibling_artifact = sibling.join(&fixture.relpath);
    std::fs::create_dir_all(sibling_artifact.parent().expect("parent"))
        .expect("sibling directories must be creatable");
    std::fs::copy(&fixture.artifact_path, &sibling_artifact).expect("copy artifact");
    let mut record = fixture.record();
    record.artifact_relpath = format!("../artifacts-evil/{}", fixture.relpath);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::ArtifactPathEscape { .. }));
}

#[tokio::test]
async fn non_canonical_artifact_path_is_refused() {
    let scratch = Scratch::new("non-canonical");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let mut record = fixture.record();
    record.artifact_relpath = format!("elsewhere/{}", fixture.relpath);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    match err {
        ExecutionError::ArtifactPathNotCanonical { relpath, expected } => {
            assert_eq!(relpath, format!("elsewhere/{}", fixture.relpath));
            assert_eq!(expected, fixture.relpath);
        }
        other => panic!("expected a canonical-path refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn artifact_symlink_escaping_the_root_is_refused() {
    let scratch = Scratch::new("symlink-escape");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    // Same bytes and size, but reachable only through a symlink that leaves
    // the artifact root: digest checks alone would accept it.
    let outside = scratch.file("outside.zip");
    std::fs::copy(&fixture.artifact_path, &outside).expect("copy artifact");
    std::fs::remove_file(&fixture.artifact_path).expect("remove original");
    std::os::unix::fs::symlink(&outside, &fixture.artifact_path).expect("symlink");
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::ArtifactPathEscape { .. }));
}

#[tokio::test]
async fn stored_manifest_entrypoint_swap_is_refused() {
    let scratch = Scratch::new("entrypoint-swap");
    let fixture = fixture_with_extra(
        &scratch,
        MODULE_ID,
        VERSION,
        "#!/bin/sh\nexit 0\n",
        "#!/bin/sh\nexit 9\n",
    );
    let mut record = fixture.record();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&record.manifest_json).expect("stored manifest must be JSON");
    // `payload/extra` is a genuinely declared file, so only the archive
    // manifest agreement can catch the redirect.
    manifest["entrypoint"] = serde_json::json!("payload/extra");
    record.manifest_json = manifest.to_string();
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::ArchiveManifestMismatch {
            field: "entrypoint",
            ..
        }
    ));
    assert_eq!(
        std::fs::read_dir(&fixture.staging_dir)
            .expect("staging root must be readable")
            .count(),
        0,
        "manifest disagreement must refuse before extraction"
    );
}

#[tokio::test]
async fn stored_manifest_file_integrity_swap_is_refused() {
    let scratch = Scratch::new("integrity-swap");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let mut record = fixture.record();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&record.manifest_json).expect("stored manifest must be JSON");
    manifest["files"][0]["sha256"] = serde_json::json!("aa".repeat(32));
    record.manifest_json = manifest.to_string();
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::ArchiveManifestMismatch {
            field: "file integrity",
            ..
        }
    ));
}

#[tokio::test]
async fn worker_receives_the_registered_invocation_and_deadline() {
    let scratch = Scratch::new("request-fields");
    let capture = scratch.file("request.jsonl");
    let script = format!(
        "#!/bin/sh\nread -r line\nprintf '%s' \"$line\" > '{}'\nprintf '{{\"protocol_version\":1,\"status\":\"ok\",\"result\":null}}\\n'\n",
        capture.display()
    );
    let fixture = fixture(&scratch, MODULE_ID, VERSION, &script);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );

    let receipt = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({"batch": 7}),
            Duration::from_millis(750),
        )
        .await
        .expect("execution must succeed");
    assert_eq!(
        receipt.outcome,
        ExecutionOutcome::Succeeded {
            result: serde_json::Value::Null,
        }
    );

    let captured = std::fs::read_to_string(&capture).expect("worker must echo the request");
    let received: serde_json::Value =
        serde_json::from_str(&captured).expect("captured request must be JSON");
    assert_eq!(received["protocol_version"], 1);
    assert_eq!(received["module_id"], MODULE_ID);
    assert_eq!(received["version"], VERSION);
    assert_eq!(received["digest_hex"], receipt.digest.to_hex());
    assert_eq!(received["function"], "run");
    assert_eq!(received["configuration"], serde_json::json!({"batch": 7}));
    assert_eq!(received["deadline_ms"], 750);
    assert!(
        received["execution_id"]
            .as_str()
            .is_some_and(|id| id == receipt.execution_id),
        "the request must carry the receipt's execution id"
    );
}

#[tokio::test]
async fn pinned_version_executes_without_an_active_pointer() {
    let scratch = Scratch::new("pinned-no-active");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let registry = ModuleRegistry::new();
    registry
        .record(fixture.record())
        .expect("record must register without activation");
    let service = fixture.service(Arc::new(registry), Duration::from_secs(30));

    let receipt = service
        .execute(
            MODULE_ID,
            Some(VERSION),
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .expect("a pinned version must execute without an active pointer");
    assert_eq!(receipt.version, VERSION);
}

#[tokio::test]
async fn pinned_version_overrides_the_active_pointer() {
    let scratch = Scratch::new("pinned-overrides-active");
    let version_one = "1.0.0";
    let version_two = "1.1.0";
    let script_one = r#"#!/bin/sh
read -r line
printf '{"protocol_version":1,"status":"ok","result":{"version":"one"}}\n'
"#;
    let script_two = r#"#!/bin/sh
read -r line
printf '{"protocol_version":1,"status":"ok","result":{"version":"two"}}\n'
"#;
    let fixture_one = fixture(&scratch, MODULE_ID, version_one, script_one);
    let fixture_two = fixture(&scratch, MODULE_ID, version_two, script_two);
    let registry = ModuleRegistry::new();
    registry
        .record(fixture_one.record())
        .expect("first version must register");
    registry
        .record(fixture_two.record())
        .expect("second version must register");
    registry
        .set_active(MODULE_ID, version_two)
        .expect("second version must activate");
    let service = fixture_one.service(Arc::new(registry), Duration::from_secs(30));

    let active = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .expect("the active version must execute");
    assert_eq!(active.version, version_two);
    assert_eq!(
        active.outcome,
        ExecutionOutcome::Succeeded {
            result: serde_json::json!({"version": "two"}),
        }
    );

    let pinned = service
        .execute(
            MODULE_ID,
            Some(version_one),
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .expect("the pinned version must override the active pointer");
    assert_eq!(pinned.version, version_one);
    assert_eq!(
        pinned.outcome,
        ExecutionOutcome::Succeeded {
            result: serde_json::json!({"version": "one"}),
        }
    );
}

#[tokio::test]
async fn artifact_above_the_package_size_bound_is_refused() {
    let scratch = Scratch::new("size-bound");
    let marker = scratch.file("spawned");
    let script = format!(
        "#!/bin/sh\nread -r line\nprintf ran > '{}'\nprintf '{{\"protocol_version\":1,\"status\":\"ok\"}}\\n'\n",
        marker.display()
    );
    let fixture = fixture(&scratch, MODULE_ID, VERSION, &script);
    let mut package_policy = PackageValidationPolicy::production();
    package_policy.archive.max_compressed_bytes = 1;
    let service = fixture.service_with(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
        HashSet::from(["k1".to_owned()]),
        4,
        package_policy,
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    match err {
        ExecutionError::ArtifactTooLarge {
            size,
            maximum,
            relpath,
        } => {
            assert_eq!(size, fixture.verdict.artifact_size());
            assert_eq!(maximum, 1);
            assert_eq!(relpath, fixture.relpath);
        }
        other => panic!("expected an artifact size refusal, got {other:?}"),
    }
    assert!(
        !marker.exists(),
        "an oversized artifact must be refused before any spawn"
    );
}

/// Bounded wait for a worker-side marker. Returning the last observation
/// keeps the caller's assertion the authority on failure.
async fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    path.exists()
}

#[tokio::test]
async fn concurrency_limit_is_enforced_and_permits_are_released() {
    let scratch = Scratch::new("concurrency");
    let marker = scratch.file("started");
    let release = scratch.file("release");
    // Synchronization, not a sleep: the first worker stays alive until the
    // test creates `release`, so the overload probe can never race a worker
    // that has already exited. The iteration cap is only a failure backstop.
    let script = format!(
        "#!/bin/sh\nread -r line\nprintf started > '{}'\ni=0\nwhile [ ! -e '{}' ]; do i=$((i+1)); [ \"$i\" -ge 1000 ] && break; sleep 0.01; done\nprintf '{{\"protocol_version\":1,\"status\":\"ok\",\"result\":null}}\\n'\n",
        marker.display(),
        release.display()
    );
    let fixture = fixture(&scratch, MODULE_ID, VERSION, &script);
    let service = fixture.service_with(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
        HashSet::from(["k1".to_owned()]),
        1,
        PackageValidationPolicy::production(),
    );

    let background = {
        let service = service.clone();
        tokio::spawn(async move {
            service
                .execute(
                    MODULE_ID,
                    None,
                    "run",
                    serde_json::json!({}),
                    Duration::from_secs(10),
                )
                .await
        })
    };
    assert!(
        wait_for_path(&marker, Duration::from_secs(10)).await,
        "the first execution must start before capacity is probed"
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ExecutionError::Overloaded { maximum: 1 }));

    // The first worker cannot finish before this write: it is parked in the
    // release-file loop.
    std::fs::write(&release, b"go").expect("release marker must be writable");

    let first = background
        .await
        .expect("background task must join")
        .expect("the first execution must succeed");
    assert!(matches!(first.outcome, ExecutionOutcome::Succeeded { .. }));

    // An error path also returns the permit: resolution fails after the
    // permit was acquired, then a real execution still gets capacity.
    let failed = service
        .execute(
            MODULE_ID,
            Some("9.9.9"),
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        failed,
        ExecutionError::Activation(ActivationError::NotRegistered { .. })
    ));

    let again = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .expect("the permit must be released after a completed execution");
    assert!(matches!(again.outcome, ExecutionOutcome::Succeeded { .. }));
}

#[tokio::test]
async fn cancelled_preparation_keeps_the_permit_until_preparation_ends() {
    let scratch = Scratch::new("cancel-preparation");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, SCRIPT_OK);
    let service = fixture.service_with(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
        HashSet::from(["k1".to_owned()]),
        1,
        PackageValidationPolicy::production(),
    );

    // The hook holds the first preparation open until `release` is sent, so
    // the timing below never depends on how fast hashing or staging is.
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let started_tx = std::sync::Mutex::new(Some(started_tx));
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let first_preparation = Arc::new(AtomicBool::new(true));
    let hook = PreparationHook::new({
        let first_preparation = Arc::clone(&first_preparation);
        move || {
            if first_preparation.swap(false, Ordering::SeqCst) {
                if let Some(started_tx) = started_tx
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    let _ = started_tx.send(());
                }
                let _ = release_rx
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .recv();
            }
        }
    });
    let service = service.with_preparation_hook(hook);

    let mut background = tokio::spawn({
        let service = service.clone();
        async move {
            service
                .execute(
                    MODULE_ID,
                    None,
                    "run",
                    serde_json::json!({}),
                    Duration::from_secs(10),
                )
                .await
        }
    });
    started_rx
        .await
        .expect("preparation must start before the caller is cancelled");
    let timed_out = tokio::time::timeout(Duration::from_millis(100), &mut background).await;
    assert!(
        timed_out.is_err(),
        "the deliberately blocked preparation must not complete"
    );
    background.abort();
    let _ = background.await;

    // The outer future is gone, but the detached blocking task still owns the
    // only permit: capacity must stay exhausted until it actually returns.
    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, ExecutionError::Overloaded { maximum: 1 }),
        "a cancelled preparation must not release capacity: {err:?}"
    );

    release_tx
        .send(())
        .expect("the blocked preparation must still be waiting");

    // Only after the detached preparation ends is its permit returned.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match service
            .execute(
                MODULE_ID,
                None,
                "run",
                serde_json::json!({}),
                Duration::from_secs(10),
            )
            .await
        {
            Ok(receipt) => {
                assert!(matches!(
                    receipt.outcome,
                    ExecutionOutcome::Succeeded { .. }
                ));
                break;
            }
            Err(ExecutionError::Overloaded { maximum: 1 }) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(other) => {
                panic!("capacity must return after the detached preparation ends, got {other:?}")
            }
        }
    }
}

#[tokio::test]
async fn signer_outside_the_allowlist_is_refused() {
    let scratch = Scratch::new("signer-allowlist");
    let marker = scratch.file("spawned");
    let script = format!(
        "#!/bin/sh\nread -r line\nprintf ran > '{}'\nprintf '{{\"protocol_version\":1,\"status\":\"ok\"}}\\n'\n",
        marker.display()
    );
    let fixture = fixture(&scratch, MODULE_ID, VERSION, &script);
    let service = fixture.service_with(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
        HashSet::from(["rotated-out-key".to_owned()]),
        4,
        PackageValidationPolicy::production(),
    );

    let err = service
        .execute(
            MODULE_ID,
            None,
            "run",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ExecutionError::SignerNotAllowed { key_id, .. } if key_id == "k1"
    ));
    assert!(
        !marker.exists(),
        "a revoked signer must be refused before any spawn"
    );
}

#[tokio::test]
async fn legacy_v1_registration_is_refused_before_staging_or_spawn() {
    let scratch = Scratch::new("legacy-v1");
    let marker = scratch.file("spawned");
    let script = format!(
        "#!/bin/sh\nread -r line\nprintf ran > '{}'\nprintf '{{\"protocol_version\":1,\"status\":\"ok\"}}\\n'\n",
        marker.display()
    );
    let fixture = fixture_from_bytes(
        &scratch,
        &package_bytes_custom(
            1,
            MODULE_ID,
            VERSION,
            "rust",
            "payload/worker",
            &[("payload/worker", script.as_str())],
        ),
    );
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(fixture.record())),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, MODULE_ID).await;
    match err {
        ExecutionError::LegacyManifest {
            module_id,
            version,
            manifest_version,
        } => {
            assert_eq!(module_id, MODULE_ID);
            assert_eq!(version, VERSION);
            assert_eq!(manifest_version, 1);
        }
        other => panic!("expected a legacy-manifest refusal, got {other:?}"),
    }
    assert!(
        !marker.exists(),
        "a v1 package must never reach a worker spawn"
    );
    assert_eq!(
        std::fs::read_dir(&fixture.staging_dir)
            .expect("staging root must be readable")
            .count(),
        0,
        "a v1 package must be refused before extraction creates a stage directory"
    );
}

#[tokio::test]
async fn archive_manifest_module_id_mismatch_is_refused() {
    let scratch = Scratch::new("archive-module-id");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let mut stored = fixture.stored_manifest();
    stored["module_id"] = serde_json::json!("worker-tampered");
    let record = fixture.record_with_identity("worker-tampered", VERSION, stored);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry_for("worker-tampered", VERSION, record)),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, "worker-tampered").await;
    match err {
        ExecutionError::ArchiveManifestMismatch {
            module_id,
            field,
            expected,
            actual,
            ..
        } => {
            assert_eq!(module_id, "worker-tampered");
            assert_eq!(field, "module_id");
            assert_eq!(expected, "worker-tampered");
            assert_eq!(actual, MODULE_ID);
        }
        other => panic!("expected an archive manifest refusal, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_dir(&fixture.staging_dir)
            .expect("staging root must be readable")
            .count(),
        0,
        "manifest disagreement must refuse before extraction"
    );
}

#[tokio::test]
async fn archive_manifest_version_mismatch_is_refused() {
    let scratch = Scratch::new("archive-version");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let mut stored = fixture.stored_manifest();
    stored["version"] = serde_json::json!("2.0.0");
    let record = fixture.record_with_identity(MODULE_ID, "2.0.0", stored);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry_for(MODULE_ID, "2.0.0", record)),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, MODULE_ID).await;
    match err {
        ExecutionError::ArchiveManifestMismatch {
            field,
            expected,
            actual,
            ..
        } => {
            assert_eq!(field, "version");
            assert_eq!(expected, "2.0.0");
            assert_eq!(actual, VERSION);
        }
        other => panic!("expected an archive manifest refusal, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_dir(&fixture.staging_dir)
            .expect("staging root must be readable")
            .count(),
        0,
        "manifest disagreement must refuse before extraction"
    );
}

#[tokio::test]
async fn archive_manifest_schema_version_mismatch_is_refused() {
    let scratch = Scratch::new("archive-schema");
    let script = "#!/bin/sh\nexit 0\n";
    let fixture = fixture_from_bytes(
        &scratch,
        &package_bytes_custom(
            1,
            MODULE_ID,
            VERSION,
            "rust",
            "payload/worker",
            &[("payload/worker", script)],
        ),
    );
    // The registry carries a v2 stored manifest for the same identity, so
    // the archive's legacy schema is caught by the agreement check rather
    // than by the v2 execution gate.
    let stored = serde_json::json!({
        "manifest_version": 2,
        "module_id": MODULE_ID,
        "version": VERSION,
        "runtime": "rust",
        "entrypoint": "payload/worker",
        "files": [{
            "path": "payload/worker",
            "size": script.len() as u64,
            "sha256": sha256_hex(script.as_bytes()),
        }],
    });
    let record = fixture.record_with_identity(MODULE_ID, VERSION, stored);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, MODULE_ID).await;
    match err {
        ExecutionError::ArchiveManifestMismatch {
            field,
            expected,
            actual,
            ..
        } => {
            assert_eq!(field, "manifest_version");
            assert_eq!(expected, "2");
            assert_eq!(actual, "1");
        }
        other => panic!("expected an archive manifest refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn archive_manifest_runtime_mismatch_is_refused() {
    let scratch = Scratch::new("archive-runtime");
    let fixture = fixture_from_bytes(
        &scratch,
        &package_bytes_custom(
            2,
            MODULE_ID,
            VERSION,
            "python",
            "payload/worker",
            &[("payload/worker", "#!/bin/sh\nexit 0\n")],
        ),
    );
    // The record and stored manifest declare an allowed runtime; only the
    // archive's runtime disagrees.
    let mut stored = fixture.stored_manifest();
    stored["runtime"] = serde_json::json!("rust");
    let record = fixture.record_with_identity(MODULE_ID, VERSION, stored);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, MODULE_ID).await;
    match err {
        ExecutionError::ArchiveManifestMismatch {
            field,
            expected,
            actual,
            ..
        } => {
            assert_eq!(field, "runtime");
            assert_eq!(expected, "rust");
            assert_eq!(actual, "python");
        }
        other => panic!("expected an archive manifest refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn archive_manifest_file_path_mismatch_is_refused() {
    let scratch = Scratch::new("archive-file-path");
    let fixture = fixture_with_extra(
        &scratch,
        MODULE_ID,
        VERSION,
        "#!/bin/sh\nexit 0\n",
        "#!/bin/sh\nexit 9\n",
    );
    let mut stored = fixture.stored_manifest();
    // Same count and same entrypoint, but a different non-entrypoint path.
    stored["files"][1]["path"] = serde_json::json!("payload/tampered");
    let record = fixture.record_with_identity(MODULE_ID, VERSION, stored);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, MODULE_ID).await;
    match err {
        ExecutionError::ArchiveManifestMismatch {
            field,
            expected,
            actual,
            ..
        } => {
            assert_eq!(field, "file path");
            assert_eq!(expected, "[1] payload/tampered");
            assert_eq!(actual, "[1] payload/extra");
        }
        other => panic!("expected an archive manifest refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn archive_manifest_file_count_mismatch_is_refused() {
    let scratch = Scratch::new("archive-file-count");
    let fixture = fixture_with_extra(
        &scratch,
        MODULE_ID,
        VERSION,
        "#!/bin/sh\nexit 0\n",
        "#!/bin/sh\nexit 9\n",
    );
    let mut stored = fixture.stored_manifest();
    stored["files"]
        .as_array_mut()
        .expect("stored files must be an array")
        .pop();
    let record = fixture.record_with_identity(MODULE_ID, VERSION, stored);
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, MODULE_ID).await;
    match err {
        ExecutionError::ArchiveManifestMismatch {
            field,
            expected,
            actual,
            ..
        } => {
            assert_eq!(field, "files");
            assert_eq!(expected, "1");
            assert_eq!(actual, "2");
        }
        other => panic!("expected an archive manifest refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn artifact_relpath_with_a_trailing_separator_is_refused() {
    let scratch = Scratch::new("trailing-separator");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let mut record = fixture.record();
    let tampered = format!("{}/", fixture.relpath);
    record.artifact_relpath = tampered.clone();
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, MODULE_ID).await;
    match err {
        ExecutionError::ArtifactPathNotCanonical { relpath, expected } => {
            assert_eq!(relpath, tampered);
            assert_eq!(expected, fixture.relpath);
        }
        other => panic!("expected a canonical-path refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn artifact_relpath_with_a_leading_prefix_component_is_refused() {
    let scratch = Scratch::new("prefixed-component");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    // Same bytes under a different relative address inside the artifact
    // root, with no `..`: only exact equality with the derived canonical
    // string can refuse it.
    let tampered = format!("artifacts-evil/{}", fixture.relpath);
    let prefixed_artifact = fixture.artifact_dir.join(&tampered);
    std::fs::create_dir_all(prefixed_artifact.parent().expect("artifact parent"))
        .expect("prefixed directories must be creatable");
    std::fs::copy(&fixture.artifact_path, &prefixed_artifact).expect("copy artifact");
    let mut record = fixture.record();
    record.artifact_relpath = tampered.clone();
    let service = fixture.service(
        Arc::clone(&fixture.active_registry(record)),
        Duration::from_secs(30),
    );

    let err = refused_execution(&service, MODULE_ID).await;
    match err {
        ExecutionError::ArtifactPathNotCanonical { relpath, expected } => {
            assert_eq!(relpath, tampered);
            assert_eq!(expected, fixture.relpath);
        }
        other => panic!("expected a canonical-path refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn execution_service_rejects_an_empty_signer_allowlist() {
    let scratch = Scratch::new("empty-signers");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");

    let err = fixture
        .try_service_with(
            Arc::new(ModuleRegistry::new()),
            Duration::from_secs(30),
            HashSet::new(),
            4,
            PackageValidationPolicy::production(),
        )
        .unwrap_err();
    assert!(matches!(err, ExecutionError::EmptySignerAllowlist));
}

#[tokio::test]
async fn execution_service_rejects_zero_and_excessive_concurrency() {
    let scratch = Scratch::new("bad-concurrency");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let maximum = tokio::sync::Semaphore::MAX_PERMITS;

    for value in [0, maximum.saturating_add(1)] {
        let err = fixture
            .try_service_with(
                Arc::new(ModuleRegistry::new()),
                Duration::from_secs(30),
                HashSet::from(["k1".to_owned()]),
                value,
                PackageValidationPolicy::production(),
            )
            .unwrap_err();
        match err {
            ExecutionError::InvalidConcurrency {
                value: got,
                maximum: got_maximum,
            } => {
                assert_eq!(got, value);
                assert_eq!(got_maximum, maximum);
            }
            other => panic!("expected a concurrency refusal, got {other:?}"),
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn execution_service_rejects_unusable_storage_directories() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("storage-validation");
    let fixture = fixture(&scratch, MODULE_ID, VERSION, "#!/bin/sh\nexit 0\n");
    let build = |artifact_dir: PathBuf, staging_dir: PathBuf| {
        ExecutionService::new(
            Arc::new(ModuleRegistry::new()),
            artifact_dir,
            staging_dir,
            ActivationPolicy::new(vec!["rust".to_owned()]).expect("activation policy"),
            ExecutionLimits::default(),
            Duration::from_secs(30),
            PackageValidationPolicy::production(),
            HashSet::from(["k1".to_owned()]),
            4,
            Arc::new(ExecutionHistoryStore::open_in_memory().expect("execution history must open")),
            Metrics::new(MetricsOptions::default()).expect("metrics must build"),
        )
    };

    let missing = scratch.file("missing-artifacts");
    let err = build(missing.clone(), fixture.staging_dir.clone()).unwrap_err();
    match err {
        ExecutionError::InvalidStorageDirectory { path, detail } => {
            assert!(path.contains("missing-artifacts"), "path: {path}");
            assert!(detail.contains("not accessible"), "detail: {detail}");
        }
        other => panic!("expected a storage-directory refusal, got {other:?}"),
    }

    let link = scratch.file("staging-link");
    std::os::unix::fs::symlink(&fixture.staging_dir, &link).expect("symlink must be creatable");
    let err = build(fixture.artifact_dir.clone(), link.clone()).unwrap_err();
    match err {
        ExecutionError::InvalidStorageDirectory { detail, .. } => {
            assert!(detail.contains("symlink"), "detail: {detail}");
        }
        other => panic!("expected a storage-directory refusal, got {other:?}"),
    }

    // On Linux a trailing slash follows the symlink, so `symlink_metadata`
    // would report the target as a real directory unless the raw path is
    // rejected first.
    let mut trailing_link = link.into_os_string();
    trailing_link.push("/");
    let err = build(fixture.artifact_dir.clone(), PathBuf::from(trailing_link)).unwrap_err();
    match err {
        ExecutionError::InvalidStorageDirectory { detail, .. } => {
            assert!(
                detail.contains("path separator"),
                "trailing separator must be rejected before symlink lookup: {detail}"
            );
        }
        other => panic!("expected a storage-directory refusal, got {other:?}"),
    }

    let group_writable = scratch.file("group-writable-staging");
    std::fs::create_dir_all(&group_writable).expect("directory must be creatable");
    std::fs::set_permissions(&group_writable, std::fs::Permissions::from_mode(0o770))
        .expect("permissions must be group-writable");
    let err = build(fixture.artifact_dir.clone(), group_writable).unwrap_err();
    match err {
        ExecutionError::InvalidStorageDirectory { detail, .. } => {
            assert!(detail.contains("group-writable"), "detail: {detail}");
        }
        other => panic!("expected a storage-directory refusal, got {other:?}"),
    }

    let world_writable = scratch.file("world-writable-staging");
    std::fs::create_dir_all(&world_writable).expect("directory must be creatable");
    std::fs::set_permissions(&world_writable, std::fs::Permissions::from_mode(0o777))
        .expect("permissions must be widenable");
    let err = build(fixture.artifact_dir.clone(), world_writable).unwrap_err();
    match err {
        ExecutionError::InvalidStorageDirectory { detail, .. } => {
            assert!(detail.contains("world-writable"), "detail: {detail}");
        }
        other => panic!("expected a storage-directory refusal, got {other:?}"),
    }
}
