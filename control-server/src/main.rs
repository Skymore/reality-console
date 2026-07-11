use control_server::probe::{run_local_tcp_until, run_remote_tcp_until};
use control_server::{build_router, AppState, Database, ProbeMode, ServiceConfig};
use std::error::Error;
use std::future::IntoFuture as _;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut config = ServiceConfig::from_env()?;
    let probe_mode = config.probe_mode;
    let probe_options = config.probe_options;
    let remote_probe = config.remote_probe.take();
    let database = Database::open(&config.database_path, &config.network_display_name)?;
    let state = AppState::new(
        database.clone(),
        config.bootstrap_token.clone(),
        config.controller_origin,
        config.request_timeout,
    );
    let app = build_router(state);
    let listener = TcpListener::bind(config.bind_address).await?;

    tracing::info!(
        bind_address = %config.bind_address,
        database_path = %config.database_path.display(),
        "control service listening"
    );

    let (shutdown_sender, _) = watch::channel(false);
    let signal_sender = shutdown_sender.clone();
    let signal_task = tokio::spawn(async move {
        shutdown_signal().await;
        let _ = signal_sender.send(true);
    });
    let probe_task = match probe_mode {
        ProbeMode::Disabled => None,
        ProbeMode::LocalTcp => {
            tracing::warn!(
                "local TCP probing is enabled; results are valid only when this controller is outside the node LAN"
            );
            let mut probe_shutdown = shutdown_sender.subscribe();
            Some(tokio::spawn(run_local_tcp_until(
                database,
                probe_options,
                async move { wait_for_shutdown(&mut probe_shutdown).await },
            )))
        }
        ProbeMode::RemoteHttp => {
            let Some(remote_probe) = remote_probe else {
                return Err("remote TCP probe configuration is missing".into());
            };
            tracing::info!("external HTTP TCP probing is enabled");
            let mut probe_shutdown = shutdown_sender.subscribe();
            Some(tokio::spawn(run_remote_tcp_until(
                database,
                probe_options,
                remote_probe,
                async move { wait_for_shutdown(&mut probe_shutdown).await },
            )))
        }
    };
    let mut http_shutdown = shutdown_sender.subscribe();
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            wait_for_shutdown(&mut http_shutdown).await;
        })
        .into_future();
    tokio::pin!(server);

    if let Some(mut probe_task) = probe_task {
        tokio::select! {
            server_result = &mut server => {
                let _ = shutdown_sender.send(true);
                signal_task.abort();
                let probe_result = probe_task.await;
                server_result?;
                probe_result??;
            }
            probe_result = &mut probe_task => {
                let shutdown_was_requested = *shutdown_sender.borrow();
                let _ = shutdown_sender.send(true);
                signal_task.abort();
                let server_result = server.await;
                server_result?;
                probe_result??;
                if !shutdown_was_requested {
                    return Err("TCP probe worker stopped unexpectedly".into());
                }
            }
        }
    } else {
        let server_result = server.await;
        let _ = shutdown_sender.send(true);
        signal_task.abort();
        server_result?;
    }
    Ok(())
}

async fn wait_for_shutdown(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow_and_update() {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!(%error, "failed to install SIGTERM handler");
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "failed to install Ctrl-C handler");
            }
            return;
        }
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(%error, "failed to install Ctrl-C handler");
            }
        }
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to install Ctrl-C handler");
    }
}
