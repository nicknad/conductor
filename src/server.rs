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
use crate::control_plane::validate_package::{BuildError, PackageValidationBuilder};
use crate::modules::registry::ModuleRegistry;
use crate::packages::policy::{PackageValidationPolicy, PolicyError};
use crate::storage::database::{Database, DatabaseError};

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
        let policy = PackageValidationPolicy::production();
        policy.ensure_production_ingest()?;
        let validator = PackageValidationBuilder::new(policy)
            .trusted_keys(config.trust_store()?)
            .build()?;

        config.ensure_layout()?;
        let database = Arc::new(Database::open(&config.database_path())?);
        database.migrate()?;
        let registry = Arc::new(ModuleRegistry::from_database(Arc::clone(&database)));
        let rejection_store = Arc::new(RejectionStore::new(database));

        // `validate_for_startup` guarantees a token; do not panic if that
        // invariant is ever weakened — fail closed instead.
        let api_token = config
            .api_token
            .as_deref()
            .ok_or(ConfigError::Missing("api_token"))?;
        let state = AppState {
            validator: Arc::new(validator),
            quarantine_dir: config.quarantine_dir(),
            artifact_dir: config.artifact_dir(),
            registry,
            recorder: Arc::new(RejectionRecorder::with_store(rejection_store)),
            request_timeout: Duration::from_secs(config.request_timeout_secs),
            api_token: ApiToken::new(api_token),
            upload_slots: Arc::new(Semaphore::new(config.max_concurrent_uploads)),
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
        serve_with_handle(
            router(state),
            &config.http_bind,
            &config.tls_cert_path,
            &config.tls_key_path,
            handle,
        )
        .await
    }
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
        let record = ModuleRecord {
            module_id: "reporting-service".to_owned(),
            version: "1.2.0".to_owned(),
            digest: ArtifactDigest::new([7u8; 32]),
            signer_key_id: "k1".to_owned(),
            runtime: "rust".to_owned(),
            manifest_version: 1,
            manifest_json: "{}".to_owned(),
            artifact_relpath: "reporting-service/1.2.0/pkg.zip".to_owned(),
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
