//! Host startup and the TLS-only serving path.
//!
//! The binary is a thin wrapper over [`run`]. Startup is fail-closed: the
//! validation policy is checked and the trust store is required before
//! binding. Trusted-key loading from operator configuration has not landed
//! yet, so [`run`] currently reports that gap and exits instead of serving
//! unverifiable uploads — the API itself is exercised through `router` in
//! tests with trust configured by value. Once key loading lands, [`run`]
//! will build the validator from configuration and serve `router` over TLS
//! via [`serve`].

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use crate::config::Config;
use crate::packages::policy::PackageValidationPolicy;

/// Starts the host: initializes tracing, loads configuration, and checks
/// the production policy is ingestable. Until operator key loading lands
/// this fails closed instead of serving unverifiable uploads.
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("conductor=info")),
        )
        .init();

    let config = Config::default();
    let policy = PackageValidationPolicy::production();
    if let Err(e) = policy.ensure_production_ingest() {
        tracing::error!(error = %e, "production policy is not ingestable; refusing to start");
        return Err(e.into());
    }

    // Fail closed until operator key loading lands: serving without a trust
    // store would accept nothing (builder) or, worse, invite a
    // skip-verification flag. Report the gap instead of binding.
    tracing::error!(
        "no trusted-key source configured yet (http_bind={}); refusing to serve unverifiable uploads",
        config.http_bind
    );
    Err("trusted-key loading from operator configuration is not implemented yet".into())
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
    use axum_server::tls_rustls::RustlsConfig;

    let addr: SocketAddr = bind.parse()?;
    let tls = RustlsConfig::from_pem_file(cert_path, key_path).await?;
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
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
    server
        .handle(handle)
        .http1_only()
        .serve(router.into_make_service())
        .await?;
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
