use control_server::{build_router, AppState, Database, ServiceConfig};
use std::error::Error;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = ServiceConfig::from_env()?;
    let database = Database::open(&config.database_path, &config.network_display_name)?;
    let state = AppState::new(
        database,
        config.bootstrap_token.clone(),
        config.request_timeout,
    );
    let app = build_router(state);
    let listener = TcpListener::bind(config.bind_address).await?;

    tracing::info!(
        bind_address = %config.bind_address,
        database_path = %config.database_path.display(),
        "control service listening"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to install shutdown signal handler");
    }
}
