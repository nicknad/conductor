//! Conductor binary: serves the upload API until signaled to stop.
//!
//! Startup is fail-closed: the validation policy is checked and the trust
//! store is required before binding. Trusted-key loading from operator
//! configuration has not landed yet, so this binary currently reports that
//! gap and exits instead of serving unverifiable uploads — the API itself
//! is exercised through `router` in tests with trust configured by value. Once key loading lands, `main` will build the validator from
//! config here and serve `router`.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("conductor=info")),
        )
        .init();

    let config = conductor::config::Config::default();
    let policy = conductor::packages::policy::PackageValidationPolicy::production();
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

/// Binds and serves `router` until Ctrl-C or SIGTERM. Kept beside `main`
/// so the serving path is reviewed with the fail-closed stub above; it is
/// exercised once key loading lands.
#[allow(dead_code)]
async fn serve(
    router: axum::Router,
    bind: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "conductor listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[allow(dead_code)]
async fn shutdown_signal() {
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
