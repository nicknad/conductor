//! Host startup and the TLS-only serving path.
//!
//! The binary is a thin wrapper over [`run`]. Startup is fail-closed and
//! ordered so no persistent side effect precedes usable configuration:
//! [`Config`] is validated (including its trusted-key trust store), the
//! production validation policy is checked, the managed storage layout is
//! created, one migrated SQLite database is opened and shared by the module
//! registry and rejection store, and the validator is assembled around the
//! configured trust store. Only then does [`Host::serve`] build the router
//! and bind TLS. Any failure aborts startup with no listener and no
//! partially wired state.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::api::routes::router;
use crate::api::uploads::{ApiToken, AppState};
use crate::audit::recorder::RejectionRecorder;
use crate::audit::store::RejectionStore;
use crate::config::{Config, ConfigError};
use crate::control_plane::activate_module::{ActivationError, ActivationPolicy};
use crate::control_plane::execute_module::{ExecutionError, ExecutionService};
use crate::control_plane::reconcile::{reconcile_registry, ReconcileError};
use crate::control_plane::validate_package::{BuildError, PackageValidationBuilder};
use crate::executions::executor::ExecutionLimits;
use crate::executions::history::ExecutionHistoryStore;
use crate::metrics::{Metrics, MetricsError, MetricsOptions};
use crate::modules::registry::ModuleRegistry;
use crate::packages::policy::{PackageValidationPolicy, PolicyError};
use crate::readiness::Readiness;
use crate::storage::database::{Database, DatabaseError};

/// How often the background readiness watcher probes the shared database.
const READINESS_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Startup assembly failures. Every variant is fatal: the host never binds
/// a listener or serves with partial state.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    Validator(#[from] BuildError),
    #[error(transparent)]
    Activation(#[from] ActivationError),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error(transparent)]
    Metrics(#[from] MetricsError),
    #[error(transparent)]
    Reconciliation(#[from] ReconcileError),
}

/// Fully assembled host: one immutable configuration plus the state the
/// router serves. Construction performs every startup side effect exactly
/// once; [`serve`](Self::serve) only builds the router and binds.
#[derive(Debug)]
pub struct Host {
    config: Config,
    state: AppState,
}

impl Host {
    /// Validates `config`, prepares storage, opens and migrates the shared
    /// database, and assembles the router state.
    ///
    /// Configuration and trust-store failures are detected before the
    /// storage layout is touched, so a rejected configuration leaves no
    /// partial directories behind. The registry and rejection store share
    /// one [`Database`] handle and therefore one WAL/pragma policy.
    pub fn assemble(config: Config) -> Result<Self, StartupError> {
        config.validate_for_startup()?;
        // Build metrics before any listener exists. With no endpoint this is a
        // local no-reader provider; otherwise it owns the only OTLP client.
        let metrics = Metrics::new(MetricsOptions {
            endpoint: config.otlp_endpoint.clone(),
            export_interval: Duration::from_secs(config.metrics_export_interval_secs),
            export_timeout: Duration::from_secs(config.metrics_export_timeout_secs),
            deployment_environment: config.deployment_environment.clone(),
            execution_capacity: config.max_concurrent_executions,
            storage_root: config.storage_root.clone(),
        })?;
        Metrics::install_global(Arc::clone(&metrics));
        let package_policy = PackageValidationPolicy::production();
        package_policy.ensure_production_ingest()?;
        let validator = PackageValidationBuilder::new(package_policy.clone())
            .trusted_keys(config.trust_store()?)
            .build()?;
        let activation_policy = ActivationPolicy::new(config.allowed_runtimes.clone())?;

        config.ensure_layout()?;
        // Startup is single-writer, so stale crash leftovers can be removed
        // before any request can race the sweep.
        let swept_quarantine = crate::storage::quarantine::sweep_older_than(
            &config.quarantine_dir(),
            Duration::from_secs(config.quarantine_ttl_secs),
        );
        let swept_staging = match crate::storage::staging::sweep_older_than(
            &config.staging_dir(),
            Duration::from_secs(config.staging_ttl_secs),
        ) {
            Ok(removed) => removed,
            Err(error) => {
                tracing::warn!(error = %error, "staging sweep failed; continuing");
                0
            }
        };
        tracing::info!(
            swept_quarantine,
            swept_staging,
            "startup workspace sweep complete"
        );
        let database = Arc::new(Database::open(&config.database_path())?);
        database.migrate()?;
        let registry = Arc::new(ModuleRegistry::from_database(Arc::clone(&database)));
        // Classify before readiness/execution so no consumer sees a stale
        // integrity state.
        let artifact_dir = config.artifact_dir();
        reconcile_registry(
            &registry,
            &artifact_dir,
            package_policy.archive.max_compressed_bytes,
        )?;
        // Cache the post-migration probe result. A later divergence is picked
        // up by the bounded watcher started in `serve_with_handle`.
        let readiness = Arc::new(Readiness::new(database.check_ready().is_ok()));
        let rejection_store = Arc::new(RejectionStore::new(Arc::clone(&database)));
        let execution_history = Arc::new(ExecutionHistoryStore::new(Arc::clone(&database)));

        // The signer allowlist is the configured trust-store ids, trimmed to
        // the same form uploads and activation use. Trust-store construction
        // above already rejected empty and duplicate ids.
        let allowed_signers: HashSet<String> = config
            .trusted_keys
            .iter()
            .map(|key| key.key_id.trim().to_owned())
            .collect();
        let execution_service = Arc::new(ExecutionService::new(
            Arc::clone(&registry),
            artifact_dir.clone(),
            config.staging_dir(),
            activation_policy,
            ExecutionLimits::default(),
            Duration::from_secs(config.max_execution_deadline_secs),
            package_policy,
            allowed_signers,
            config.max_concurrent_executions,
            execution_history,
            Arc::clone(&metrics),
        )?);

        // `validate_for_startup` guarantees a token; do not panic if that
        // invariant is ever weakened — fail closed instead.
        let api_token = config
            .api_token
            .as_deref()
            .ok_or(ConfigError::Missing("api_token"))?;
        let state = AppState {
            validator: Arc::new(validator),
            quarantine_dir: config.quarantine_dir(),
            artifact_dir,
            registry,
            recorder: Arc::new(RejectionRecorder::with_store(rejection_store)),
            request_timeout: Duration::from_secs(config.request_timeout_secs),
            api_token: ApiToken::new(api_token),
            upload_slots: Arc::new(Semaphore::new(config.max_concurrent_uploads)),
            execution_service,
            metrics,
            database,
            readiness,
        };
        Ok(Self { config, state })
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    #[must_use]
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Consumes the host, yielding the router state. Integration tests drive
    /// the assembled state through `api::routes::router` this way.
    #[must_use]
    pub fn into_state(self) -> AppState {
        self.state
    }

    /// Serves the assembled router over the configured TLS identity and
    /// bind until Ctrl-C or SIGTERM. There is deliberately no plaintext
    /// listener.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.serve_with_handle(axum_server::Handle::new()).await
    }

    /// [`serve`](Self::serve) with an externally owned shutdown handle, so a
    /// supervisor can discover the bound address (useful with port 0) and
    /// request shutdown. Pins that the production host uses the configured
    /// bind and TLS identity; the integration test drives this path.
    pub async fn serve_with_handle(
        self,
        handle: axum_server::Handle<SocketAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Self { config, state } = self;
        let metrics = Arc::clone(&state.metrics);
        // Readiness is refreshed off the request path. The watcher is bounded
        // to one in-flight probe and is aborted once serving ends, whether it
        // succeeded or failed during bind.
        let readiness_watcher = spawn_readiness_watcher(
            Arc::clone(&state.database),
            Arc::clone(&state.readiness),
            READINESS_REFRESH_INTERVAL,
        );
        let served = serve_with_handle(
            router(state),
            &config.http_bind,
            &config.tls_cert_path,
            &config.tls_key_path,
            handle,
        )
        .await;
        readiness_watcher.abort();
        // Flush on both success and failure. Run shutdown off the async worker:
        // the periodic reader's docs warn that current-thread runtimes can
        // deadlock if shutdown blocks the runtime thread.
        match tokio::task::spawn_blocking(move || metrics.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(error = %error, "metrics shutdown failed"),
            Err(error) => tracing::warn!(error = %error, "metrics shutdown task failed"),
        }
        served
    }
}

/// Starts the bounded readiness watcher. Each tick tries to acquire the one
/// permit; if the previous probe is still running (for example a hung SQLite
/// call), the tick is skipped rather than queueing another blocking task. The
/// permit lives inside the blocking task, so it is released only when the
/// probe actually ends.
fn spawn_readiness_watcher(
    database: Arc<Database>,
    readiness: Arc<Readiness>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let probe_slots = Arc::new(Semaphore::new(1));
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Ok(permit) = Arc::clone(&probe_slots).try_acquire_owned() else {
                continue;
            };
            let database = Arc::clone(&database);
            let readiness = Arc::clone(&readiness);
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                readiness.set_db_ready(database.check_ready().is_ok());
            });
        }
    })
}

/// Starts the host: initializes tracing, loads operator configuration,
/// assembles the trust store, storage, and database, then serves TLS-only.
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("conductor=info")),
        )
        .init();

    // Render startup failures with their operator-facing `Display` text
    // rather than the enum `Debug` shape that `main` would otherwise print.
    let config = Config::load().map_err(|error| error.to_string())?;
    tracing::info!(
        http_bind = %config.http_bind,
        storage_root = %config.storage_root.display(),
        "configuration loaded"
    );
    let host = Host::assemble(config).map_err(|error| error.to_string())?;
    tracing::info!(
        http_bind = %host.config().http_bind,
        trusted_keys = host.config().trusted_keys.len(),
        "host assembled; starting TLS listener"
    );
    host.serve().await
}

/// Serves `router` over TLS-only HTTP/1 until Ctrl-C or SIGTERM. There is
/// deliberately no plaintext listener: `bind_rustls` is the only bind, and
/// HSTS is emitted on every response (see the route table). Socket-level
/// header bounds (`max_headers`, `max_buf_size`) reject oversized head
/// sections before buffering.
pub async fn serve(
    router: axum::Router,
    bind: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_with_handle(
        router,
        bind,
        cert_path,
        key_path,
        axum_server::Handle::new(),
    )
    .await
}

/// Lower-level serving entry point behind [`serve`].
///
/// The externally-owned [`axum_server::Handle`] lets a supervisor discover
/// the actual bound address through [`axum_server::Handle::listening`] (useful
/// when `bind` uses port 0) and request shutdown. Production calls this via
/// [`serve`]; the TLS-only integration test drives this function directly so
/// it exercises the real serving path rather than rebuilding it in the test.
pub async fn serve_with_handle(
    router: axum::Router,
    bind: &str,
    cert_path: &Path,
    key_path: &Path,
    handle: axum_server::Handle<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum_server::tls_rustls::RustlsConfig;

    let addr: SocketAddr = bind.parse()?;
    let tls = RustlsConfig::from_pem_file(cert_path, key_path).await?;
    let shutdown_handle = handle.clone();
    let shutdown = tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });
    tracing::info!(%addr, "conductor listening (TLS only, HTTP/1)");
    // Socket-level header bounds: oversized head sections get hyper's own
    // 431 before buffering. `max_buf_size` panics below 8 KiB; ours is
    // 16 KiB.
    let mut server = axum_server::bind_rustls(addr, tls);
    server.http_builder().http1().max_headers(32);
    server.http_builder().http1().max_buf_size(16 * 1024);
    let served = server
        .handle(handle)
        .http1_only()
        .serve(router.into_make_service())
        .await;
    // A failed bind/serve must not leave the signal watcher waiting for a
    // signal that may never come (one task per failed startup otherwise).
    shutdown.abort();
    served?;
    Ok(())
}

/// Resolves on Ctrl-C or SIGTERM so [`serve`] can shut down gracefully.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::prelude::*;

    use crate::audit::event::{RejectionEvent, RejectionStage};
    use crate::config::TrustedKeyConfig;
    use crate::modules::registry::{IntegrityState, ModuleRecord};
    use crate::packages::artifact::ArtifactDigest;
    use crate::packages::signature::SignatureAlgorithm;
    use crate::storage::artifact_store::canonical_artifact_relpath;

    fn temp_root(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "conductor-server-{}-{nanos}-{count}-{tag}",
            std::process::id()
        ))
    }

    fn test_config(root: &Path) -> Config {
        Config {
            api_token: Some("server-test-token".to_owned()),
            trusted_keys: vec![TrustedKeyConfig {
                key_id: "k1".to_owned(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_base64: BASE64_STANDARD.encode([9u8; 32]),
            }],
            storage_root: root.to_path_buf(),
            request_timeout_secs: 11,
            max_execution_deadline_secs: 5,
            max_concurrent_uploads: 3,
            ..Config::default()
        }
    }

    fn cleanup(root: &Path) {
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn assemble_prepares_storage_database_and_runtime_limits() {
        let root = temp_root("assemble");
        let config = test_config(&root);
        let host = Host::assemble(config.clone()).expect("valid config must assemble");

        for dir in [
            config.storage_root.clone(),
            config.quarantine_dir(),
            config.artifact_dir(),
            config.database_dir(),
            config.staging_dir(),
        ] {
            assert!(dir.is_dir(), "{} must be created at startup", dir.display());
        }
        assert!(
            config.database_path().is_file(),
            "startup must create the migrated database file"
        );
        assert_eq!(host.config().storage_root, root);
        assert!(host.state().api_token.verify("server-test-token"));
        assert!(!host.state().api_token.verify("wrong-token"));
        assert_eq!(host.state().request_timeout, Duration::from_secs(11));
        assert_eq!(host.state().upload_slots.available_permits(), 3);
        cleanup(&root);
    }

    #[test]
    fn assemble_sweeps_stale_workspace_leftovers() {
        let root = temp_root("startup-sweep");
        let config = test_config(&root);
        config
            .ensure_layout()
            .expect("layout must exist for fixtures");
        let stale_upload = config.quarantine_dir().join("upload-stale.zip");
        let fresh_upload = config.quarantine_dir().join("upload-fresh.zip");
        let stale_stage = config.staging_dir().join("stale-stage");
        let fresh_stage = config.staging_dir().join("fresh-stage");
        std::fs::create_dir_all(&stale_stage).expect("stale stage");
        std::fs::create_dir_all(&fresh_stage).expect("fresh stage");
        std::fs::write(&stale_upload, b"stale").expect("stale upload");
        std::fs::write(&fresh_upload, b"fresh").expect("fresh upload");

        let old = SystemTime::now()
            - Duration::from_secs(2 * config.quarantine_ttl_secs.max(config.staging_ttl_secs));
        for path in [&stale_upload, &stale_stage] {
            std::fs::File::open(path)
                .expect("path must open")
                .set_times(std::fs::FileTimes::new().set_modified(old))
                .expect("mtime must be set");
        }

        let _host = Host::assemble(config.clone()).expect("config must assemble");

        assert!(!stale_upload.exists(), "stale quarantine must be swept");
        assert!(
            !stale_stage.exists(),
            "stale staging directory must be swept"
        );
        assert!(fresh_upload.exists(), "fresh quarantine must survive");
        assert!(fresh_stage.is_dir(), "fresh staging directory must survive");
        cleanup(&root);
    }

    #[test]
    fn assemble_attaches_the_durable_rejection_sink() {
        let root = temp_root("rejection-sink");
        let host = Host::assemble(test_config(&root)).expect("valid config must assemble");
        let store = Arc::clone(
            host.state()
                .recorder
                .store()
                .expect("startup must attach the durable sink"),
        );

        host.state().recorder.record(&RejectionEvent::new(
            RejectionStage::Transport,
            "startup_wiring_test",
            "assembled recorder must persist",
        ));
        let rows = store.list().expect("rejection rows must read back");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].stage, "transport");
        assert_eq!(rows[0].code, "startup_wiring_test");
        cleanup(&root);
    }

    #[tokio::test]
    async fn assemble_wires_execution_history_to_the_shared_database() {
        use crate::executions::history::ExecutionRecord;

        let root = temp_root("history-wiring");
        let host = Host::assemble(test_config(&root)).expect("valid config must assemble");
        let database_path = host.config().database_path();

        // Write through a separate handle to the assembled database file. If
        // the service were backed by a different database (or an in-memory
        // store), it could not read this row.
        let database = Arc::new(Database::open(&database_path).expect("database must open"));
        database.migrate().expect("database must migrate");
        let store = ExecutionHistoryStore::new(Arc::clone(&database));
        let record = ExecutionRecord {
            execution_id: "exec-startup-wiring".to_owned(),
            module_id: "reporting-service".to_owned(),
            version: "1.2.0".to_owned(),
            digest: "ab".repeat(32),
            function: "run".to_owned(),
            outcome: "succeeded".to_owned(),
            started_at: SystemTime::UNIX_EPOCH + Duration::from_millis(1_000),
            finished_at: SystemTime::UNIX_EPOCH + Duration::from_millis(1_025),
            duration_ms: 25,
        };
        store.record(&record).expect("history insert must succeed");

        let rows = host
            .state()
            .execution_service
            .list_executions(10, 0)
            .await
            .expect("the assembled service must read execution history");
        assert_eq!(rows, vec![record]);
        cleanup(&root);
    }

    #[test]
    fn assemble_uses_the_configured_trust_store() {
        let root = temp_root("trust-store");
        let host = Host::assemble(test_config(&root)).expect("valid config must assemble");
        let keys = host.state().validator.trusted_keys();

        let key = keys
            .key("k1")
            .expect("the configured key must reach the validator");
        assert_eq!(key.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(key.public_key, vec![9u8; 32]);
        assert!(keys.key("unconfigured").is_none());
        cleanup(&root);
    }

    #[test]
    fn assembled_registry_survives_a_restart() {
        let root = temp_root("persistence");
        let config = test_config(&root);
        let digest = ArtifactDigest::new([7u8; 32]);
        let record = ModuleRecord {
            module_id: "reporting-service".to_owned(),
            version: "1.2.0".to_owned(),
            digest,
            signer_key_id: "k1".to_owned(),
            runtime: "rust".to_owned(),
            manifest_version: 1,
            manifest_json: "{}".to_owned(),
            artifact_relpath: canonical_artifact_relpath("reporting-service", "1.2.0", &digest),
            artifact_size: 123,
            integrity_state: IntegrityState::Ok,
            registered_at: SystemTime::now(),
        };

        let first = Host::assemble(config.clone()).expect("first start must assemble");
        first
            .state()
            .registry
            .record(record.clone())
            .expect("registration must persist");
        drop(first.into_state());

        let second = Host::assemble(config).expect("restart must assemble");
        let stored = second
            .state()
            .registry
            .get("reporting-service", "1.2.0")
            .expect("registry lookup must succeed")
            .expect("the registered version must survive a restart");
        assert_eq!(stored.digest, record.digest);
        assert_eq!(stored.signer_key_id, "k1");
        assert_eq!(stored.artifact_relpath, record.artifact_relpath);
        assert_eq!(
            stored.integrity_state,
            IntegrityState::Missing,
            "restart reconciliation must classify the absent artifact"
        );
        cleanup(&root);
    }

    #[test]
    fn assemble_rejects_invalid_configuration_before_touching_storage() {
        let root = temp_root("invalid-config");
        let config = Config {
            api_token: Some(String::new()),
            ..test_config(&root)
        };

        let result = Host::assemble(config);
        assert!(matches!(
            result,
            Err(StartupError::Config(ConfigError::Invalid {
                field: "api_token",
                ..
            }))
        ));
        assert!(
            !root.exists(),
            "rejected configuration must not create the storage layout"
        );
        cleanup(&root);
    }

    #[test]
    fn assemble_rejects_an_unusable_metrics_endpoint_before_touching_storage() {
        let root = temp_root("metrics-endpoint");
        let config = Config {
            otlp_endpoint: Some("http://[".to_owned()),
            ..test_config(&root)
        };

        let result = Host::assemble(config);
        assert!(
            matches!(result, Err(StartupError::Metrics(_))),
            "an unbuildable OTLP exporter must be a startup error"
        );
        assert!(
            !root.exists(),
            "an unusable metrics endpoint must not create the storage layout"
        );
        cleanup(&root);
    }

    #[test]
    fn assemble_rejects_duplicate_key_ids_before_touching_storage() {
        let root = temp_root("duplicate-keys");
        let mut config = test_config(&root);
        let duplicate = config.trusted_keys[0].clone();
        config.trusted_keys.push(duplicate);

        let result = Host::assemble(config);
        assert!(matches!(
            result,
            Err(StartupError::Config(ConfigError::Invalid {
                field: "trusted_keys.key_id",
                ..
            }))
        ));
        assert!(
            !root.exists(),
            "an unusable trust store must not create the storage layout"
        );
        cleanup(&root);
    }

    #[tokio::test]
    async fn readiness_watcher_tracks_database_migration() {
        let database = Arc::new(Database::open_in_memory().expect("database must open"));
        let readiness = Arc::new(Readiness::new(database.check_ready().is_ok()));
        assert!(!readiness.is_ready(), "an unmigrated database is not ready");

        let watcher = spawn_readiness_watcher(
            Arc::clone(&database),
            Arc::clone(&readiness),
            Duration::from_millis(10),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !readiness.is_ready(),
            "the watcher must not report an unmigrated database as ready"
        );

        database.migrate().expect("database must migrate");
        for _ in 0..100 {
            if readiness.is_ready() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            readiness.is_ready(),
            "the watcher must pick up the migrated database"
        );
        watcher.abort();
    }

    #[tokio::test]
    async fn serve_aborts_when_the_configured_tls_identity_is_missing() {
        let root = temp_root("missing-tls");
        let missing = root.join("missing.pem");
        let config = Config {
            tls_cert_path: missing.clone(),
            tls_key_path: missing,
            ..test_config(&root)
        };
        let host = Host::assemble(config).expect("assembly does not need the TLS files");

        let result = host.serve().await;
        assert!(
            result.is_err(),
            "serving must fail closed when the configured TLS identity cannot load"
        );
        cleanup(&root);
    }
}
