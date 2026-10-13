//! Conductor binary entry point. Process behavior lives in
//! `conductor::server`.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    conductor::server::run().await
}
