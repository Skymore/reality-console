use control_server::probe::{run_local_tcp_until, run_remote_tcp_until};
use control_server::protocol_canary::{run_protocol_canary_until, XrayProtocolCanaryExecutor};
use control_server::relay::{run_relay_reconciliation_until, RelayProvisioner};
use control_server::{build_router, operations, AppState, Database, ProbeMode, ServiceConfig};
use std::error::Error;
use std::ffi::OsString;
use std::future::IntoFuture as _;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("control-server: {error}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
async fn run() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let config_path = if arguments
        .first()
        .is_some_and(|argument| argument == "serve")
    {
        arguments.remove(0);
        match arguments.as_slice() {
            [] => None,
            [flag, path] if flag == "--config" => Some(PathBuf::from(path)),
            _ => return Err("usage: control-server serve [--config ABSOLUTE_JSON_PATH]".into()),
        }
    } else if is_operation_command(arguments.first()) {
        operations::run_operation_command(arguments)?;
        return Ok(());
    } else if !arguments.is_empty() {
        return Err(operations::OperationCliError::Usage.into());
    } else {
        None
    };

    let mut config = match config_path {
        Some(path) => ServiceConfig::from_file(&path)?,
        None => ServiceConfig::from_env()?,
    };
    let probe_mode = config.probe_mode;
    let probe_options = config.probe_options;
    let remote_probe = config.remote_probe.take();
    let protocol_canary = config.protocol_canary.take();
    let protocol_canary_options = config.protocol_canary_options;
    let database = Database::open(&config.database_path, &config.network_display_name)?;
    let relay = config
        .relay_provisioning
        .take()
        .map(|relay_config| {
            RelayProvisioner::new(
                database.clone(),
                database.controller_identity(),
                relay_config,
            )
        })
        .transpose()?;
    let mut state = AppState::new(
        database.clone(),
        config.bootstrap_token.clone(),
        config.controller_origin,
        config.request_timeout,
    );
    if let Some(relay) = relay.clone() {
        state = state.with_relay(relay);
    }
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
    let mut workers: JoinSet<Result<(), String>> = JoinSet::new();
    match probe_mode {
        ProbeMode::Disabled => {}
        ProbeMode::LocalTcp => {
            tracing::warn!(
                "local TCP probing is enabled; results are valid only when this controller is outside the node LAN"
            );
            let mut probe_shutdown = shutdown_sender.subscribe();
            let database = database.clone();
            workers.spawn(async move {
                run_local_tcp_until(database, probe_options, async move {
                    wait_for_shutdown(&mut probe_shutdown).await;
                })
                .await
                .map_err(|error| error.to_string())
            });
        }
        ProbeMode::RemoteHttp => {
            let Some(remote_probe) = remote_probe else {
                return Err("remote TCP probe configuration is missing".into());
            };
            tracing::info!("external HTTP TCP probing is enabled");
            let mut probe_shutdown = shutdown_sender.subscribe();
            let database = database.clone();
            workers.spawn(async move {
                run_remote_tcp_until(database, probe_options, remote_probe, async move {
                    wait_for_shutdown(&mut probe_shutdown).await;
                })
                .await
                .map_err(|error| error.to_string())
            });
        }
    }
    if let Some(protocol_canary) = protocol_canary {
        tracing::info!("protocol-aware VLESS+REALITY endpoint canary is enabled");
        let database = database.clone();
        let executor = XrayProtocolCanaryExecutor::new(protocol_canary);
        let mut canary_shutdown = shutdown_sender.subscribe();
        workers.spawn(async move {
            run_protocol_canary_until(database, executor, protocol_canary_options, async move {
                wait_for_shutdown(&mut canary_shutdown).await;
            })
            .await
            .map_err(|error| error.to_string())
        });
    } else {
        tracing::warn!(
            "protocol canary is disabled; TCP evidence cannot make endpoints publishable"
        );
    }
    let retention_database = database.clone();
    let mut retention_shutdown = shutdown_sender.subscribe();
    workers.spawn(async move {
        run_retention_until(retention_database, &mut retention_shutdown).await;
        Ok(())
    });
    if let Some(relay) = relay {
        let mut relay_shutdown = shutdown_sender.subscribe();
        workers.spawn(async move {
            run_relay_reconciliation_until(relay, async move {
                wait_for_shutdown(&mut relay_shutdown).await;
            })
            .await;
            Ok(())
        });
    }
    let mut http_shutdown = shutdown_sender.subscribe();
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            wait_for_shutdown(&mut http_shutdown).await;
        })
        .into_future();
    tokio::pin!(server);

    tokio::select! {
        server_result = &mut server => {
            let _ = shutdown_sender.send(true);
            signal_task.abort();
            server_result?;
        }
        worker_result = workers.join_next() => {
            let shutdown_was_requested = *shutdown_sender.borrow();
            let _ = shutdown_sender.send(true);
            signal_task.abort();
            server.await?;
            match worker_result {
                Some(Ok(Ok(()))) if shutdown_was_requested => {}
                Some(Ok(Ok(()))) => return Err("background worker stopped unexpectedly".into()),
                Some(Ok(Err(error))) => return Err(error.into()),
                Some(Err(error)) => return Err(error.into()),
                None => return Err("background worker set became empty".into()),
            }
        }
    }
    while let Some(result) = workers.join_next().await {
        result??;
    }
    Ok(())
}

fn is_operation_command(argument: Option<&OsString>) -> bool {
    matches!(
        argument.and_then(|value| value.to_str()),
        Some("backup" | "restore")
    )
}

async fn run_retention_until(database: Database, shutdown: &mut watch::Receiver<bool>) {
    loop {
        if let Err(error) = database.enforce_telemetry_retention().await {
            tracing::warn!(%error, "telemetry retention pass failed; will retry");
        }
        tokio::select! {
            () = wait_for_shutdown(shutdown) => return,
            () = tokio::time::sleep(std::time::Duration::from_secs(24 * 60 * 60)) => {}
        }
    }
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
