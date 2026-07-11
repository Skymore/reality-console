use crate::activation::{ActivationOptions, XraySupervisor};
use crate::local_api::{
    phase_for_runtime, LocalServiceError, LocalServiceErrorCode, LocalServicePhase,
    LocalServiceStatus, LocalStatusServer,
};
use crate::mapping::RouterMappingSupervisor;
use crate::{
    status_locked, sync::sync_once_locked_with_runtime_probe, DataDirLock, EnrollmentState,
};
use anyhow::{anyhow, bail, Context as _, Result};
use control_protocol::node::NodeRuntimeState;
use rand_core::{OsRng, RngCore as _};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;
use uuid::Uuid;

const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
const MAX_CONFIGURED_DELAY: Duration = Duration::from_secs(24 * 60 * 60);
const RUNTIME_POLL_INTERVAL: Duration = Duration::from_secs(1);

enum ServiceEvent {
    Shutdown {
        signal: Result<()>,
        cycle: Result<()>,
    },
    Cycle(Result<()>),
}

enum WaitEvent {
    Deadline,
    Shutdown(Result<()>),
    RuntimeFailed,
}

/// Timing policy for the resilient outbound synchronization loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncLoopOptions {
    /// Base interval after a successful synchronization cycle.
    pub success_interval: Duration,
    /// First retry delay after a failed cycle.
    pub initial_backoff: Duration,
    /// Maximum retry delay after consecutive failures.
    pub max_backoff: Duration,
}

impl Default for SyncLoopOptions {
    fn default() -> Self {
        Self {
            success_interval: DEFAULT_SYNC_INTERVAL,
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
        }
    }
}

impl SyncLoopOptions {
    fn validate(self) -> Result<Self> {
        if self.success_interval.is_zero()
            || self.initial_backoff.is_zero()
            || self.max_backoff.is_zero()
            || self.success_interval > MAX_CONFIGURED_DELAY
            || self.initial_backoff > MAX_CONFIGURED_DELAY
            || self.max_backoff > MAX_CONFIGURED_DELAY
            || self.initial_backoff > self.max_backoff
        {
            bail!("sync loop delays must be non-zero, at most 24 hours, and initial backoff must not exceed its maximum");
        }
        Ok(self)
    }
}

/// Runs outbound synchronization until Ctrl-C or process termination.
///
/// # Errors
///
/// Returns an error when local state is unavailable, the node is not enrolled,
/// timing options are invalid, or OS shutdown handlers cannot be installed.
pub async fn run(data_dir: &Path, options: SyncLoopOptions) -> Result<()> {
    run_until(data_dir, options, shutdown_signal()).await
}

/// Runs outbound synchronization until the supplied shutdown future resolves.
///
/// This entry point lets a desktop wrapper or service manager provide its own
/// cancellation lifecycle while retaining the same retry behavior.
///
/// # Errors
///
/// Returns an error before entering the loop when local state is unavailable,
/// the node is not enrolled, or timing options are invalid. Individual sync
/// failures are retried with bounded exponential backoff.
pub async fn run_until<F>(data_dir: &Path, options: SyncLoopOptions, shutdown: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let options = options.validate()?;
    let _lock = DataDirLock::acquire(data_dir, false)?;
    let initial_host = status_locked(data_dir)?;
    if initial_host.enrollment_state != EnrollmentState::Enrolled {
        bail!("node host must be enrolled before starting its sync service");
    }
    let mut supervisor = XraySupervisor::new(ActivationOptions::default())?;
    let mut router_mapping = RouterMappingSupervisor::new();
    let service_instance_id = Uuid::new_v4();
    let initial_status = LocalServiceStatus::from_host(
        service_instance_id,
        &initial_host,
        LocalServicePhase::Starting,
        NodeRuntimeState::Idle,
        None,
    )?;
    let local_status = LocalStatusServer::start(data_dir, initial_status)?;
    if let Err(recovery_error) = supervisor.recover(data_dir).await {
        publish_local_status(
            &local_status,
            service_instance_id,
            data_dir,
            &mut supervisor,
            Some(LocalServicePhase::Retrying),
            Some(LocalServiceError::now(
                LocalServiceErrorCode::XrayRecoveryFailed,
            )),
        );
        if let Err(cleanup_error) =
            shutdown_all(data_dir, &mut router_mapping, &mut supervisor, local_status).await
        {
            return Err(anyhow!(
                "Xray recovery failed ({recovery_error:#}); service cleanup also failed ({cleanup_error:#})"
            ));
        }
        return Err(recovery_error);
    }
    publish_local_status(
        &local_status,
        service_instance_id,
        data_dir,
        &mut supervisor,
        None,
        None,
    );

    run_service_loop(
        data_dir,
        options,
        shutdown,
        supervisor,
        router_mapping,
        local_status,
        service_instance_id,
    )
    .await
}

async fn run_service_loop<F>(
    data_dir: &Path,
    options: SyncLoopOptions,
    shutdown: F,
    mut supervisor: XraySupervisor,
    mut router_mapping: RouterMappingSupervisor,
    local_status: LocalStatusServer,
    service_instance_id: Uuid,
) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    tokio::pin!(shutdown);
    let mut backoff = options.initial_backoff;
    let mut last_error = None;
    loop {
        publish_local_status(
            &local_status,
            service_instance_id,
            data_dir,
            &mut supervisor,
            Some(LocalServicePhase::Syncing),
            last_error.clone(),
        );
        let event = {
            let cycle = run_cycle(data_dir, &mut supervisor, &mut router_mapping);
            tokio::pin!(cycle);
            tokio::select! {
                signal = &mut shutdown => {
                    // Mapping side effects are finite but not cancellation-safe.
                    let cycle = cycle.await;
                    ServiceEvent::Shutdown { signal, cycle }
                }
                result = &mut cycle => ServiceEvent::Cycle(result),
            }
        };
        let result = match event {
            ServiceEvent::Shutdown { signal, cycle } => {
                if let Err(error) = cycle {
                    tracing::warn!(error = %error, "node cycle failed while shutdown was pending");
                    last_error = Some(LocalServiceError::now(
                        LocalServiceErrorCode::SyncCycleFailed,
                    ));
                }
                return finish_shutdown(
                    signal,
                    data_dir,
                    &mut router_mapping,
                    &mut supervisor,
                    local_status,
                    service_instance_id,
                    last_error,
                )
                .await;
            }
            ServiceEvent::Cycle(result) => result,
        };
        let (base_delay, cycle_error) = record_cycle_result(result, options, &mut backoff);
        last_error = cycle_error;
        publish_local_status(
            &local_status,
            service_instance_id,
            data_dir,
            &mut supervisor,
            last_error.as_ref().map(|_| LocalServicePhase::Retrying),
            last_error.clone(),
        );
        match wait_for_next_cycle(
            data_dir,
            &mut supervisor,
            &mut router_mapping,
            shutdown.as_mut(),
            base_delay,
        )
        .await
        {
            WaitEvent::Deadline => {}
            WaitEvent::RuntimeFailed => {
                last_error = Some(LocalServiceError::now(
                    LocalServiceErrorCode::RuntimeHealthFailed,
                ));
                publish_local_status(
                    &local_status,
                    service_instance_id,
                    data_dir,
                    &mut supervisor,
                    Some(LocalServicePhase::Retrying),
                    last_error.clone(),
                );
            }
            WaitEvent::Shutdown(signal) => {
                return finish_shutdown(
                    signal,
                    data_dir,
                    &mut router_mapping,
                    &mut supervisor,
                    local_status,
                    service_instance_id,
                    last_error,
                )
                .await;
            }
        }
    }
}

fn record_cycle_result(
    result: Result<()>,
    options: SyncLoopOptions,
    backoff: &mut Duration,
) -> (Duration, Option<LocalServiceError>) {
    match result {
        Ok(()) => {
            *backoff = options.initial_backoff;
            (options.success_interval, None)
        }
        Err(error) => {
            tracing::warn!(error = %error, "node synchronization failed; retrying");
            let current = *backoff;
            *backoff = backoff.saturating_mul(2).min(options.max_backoff);
            (
                current,
                Some(LocalServiceError::now(
                    LocalServiceErrorCode::SyncCycleFailed,
                )),
            )
        }
    }
}

async fn wait_for_next_cycle<F>(
    data_dir: &Path,
    supervisor: &mut XraySupervisor,
    router_mapping: &mut RouterMappingSupervisor,
    mut shutdown: Pin<&mut F>,
    base_delay: Duration,
) -> WaitEvent
where
    F: Future<Output = Result<()>>,
{
    let deadline = tokio::time::Instant::now() + jitter(base_delay, OsRng.next_u64());
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return WaitEvent::Deadline;
        }
        let wait = (deadline - now).min(RUNTIME_POLL_INTERVAL);
        tokio::select! {
            shutdown_result = shutdown.as_mut() => return WaitEvent::Shutdown(shutdown_result),
            () = tokio::time::sleep(wait) => {}
        }
        if let Err(error) = supervisor.poll(data_dir).await {
            if let Err(mapping_error) = router_mapping.reconcile(data_dir, None).await {
                tracing::warn!(error = %mapping_error, "router mapping cleanup failed after runtime health failure");
            }
            tracing::warn!(error = %error, "managed Xray health check failed; retrying");
            return WaitEvent::RuntimeFailed;
        }
    }
}

async fn finish_shutdown(
    signal: Result<()>,
    data_dir: &Path,
    router_mapping: &mut RouterMappingSupervisor,
    supervisor: &mut XraySupervisor,
    local_status: LocalStatusServer,
    service_instance_id: Uuid,
    last_error: Option<LocalServiceError>,
) -> Result<()> {
    publish_local_status(
        &local_status,
        service_instance_id,
        data_dir,
        supervisor,
        Some(LocalServicePhase::Stopping),
        last_error,
    );
    shutdown_all(data_dir, router_mapping, supervisor, local_status).await?;
    signal
}

fn publish_local_status(
    local_status: &LocalStatusServer,
    service_instance_id: Uuid,
    data_dir: &Path,
    supervisor: &mut XraySupervisor,
    phase: Option<LocalServicePhase>,
    last_error: Option<LocalServiceError>,
) {
    let result = (|| -> Result<()> {
        let runtime_state = supervisor.observe_runtime_state()?;
        let host = status_locked(data_dir)?;
        let phase = phase.unwrap_or_else(|| phase_for_runtime(runtime_state));
        local_status.publish(LocalServiceStatus::from_host(
            service_instance_id,
            &host,
            phase,
            runtime_state,
            last_error,
        )?)
    })();
    if let Err(error) = result {
        tracing::warn!(error = %error, "failed to publish local Node Host status");
    }
}

async fn run_cycle(
    data_dir: &Path,
    supervisor: &mut XraySupervisor,
    router_mapping: &mut RouterMappingSupervisor,
) -> Result<()> {
    supervisor.poll(data_dir).await?;
    // A previously acknowledged candidate can activate even if the controller
    // is temporarily unavailable after a service restart.
    supervisor.reconcile(data_dir).await?;
    router_mapping
        .reconcile(data_dir, supervisor.router_mapping_target()?)
        .await?;
    sync_once_locked_with_runtime_probe(data_dir, || supervisor.observe_runtime_state()).await?;
    supervisor.reconcile(data_dir).await?;
    router_mapping
        .reconcile(data_dir, supervisor.router_mapping_target()?)
        .await
}

async fn shutdown_services(
    data_dir: &Path,
    router_mapping: &mut RouterMappingSupervisor,
    supervisor: &mut XraySupervisor,
) -> Result<()> {
    let mapping_result = router_mapping.shutdown(data_dir).await;
    let runtime_result = supervisor.shutdown().await;
    if let Err(mapping_error) = mapping_result {
        runtime_result.context("managed Xray shutdown also failed")?;
        return Err(mapping_error).context("router mapping shutdown failed");
    }
    runtime_result
}

async fn shutdown_all(
    data_dir: &Path,
    router_mapping: &mut RouterMappingSupervisor,
    supervisor: &mut XraySupervisor,
    local_status: LocalStatusServer,
) -> Result<()> {
    let service_result = shutdown_services(data_dir, router_mapping, supervisor).await;
    let local_status_result = local_status.shutdown().await;
    match (service_result, local_status_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(service_error), Ok(())) => Err(service_error),
        (Ok(()), Err(status_error)) => Err(status_error),
        (Err(service_error), Err(status_error)) => Err(anyhow!(
            "managed service cleanup failed ({service_error:#}); local status cleanup also failed ({status_error:#})"
        )),
    }
}

fn jitter(base: Duration, random: u64) -> Duration {
    let base_millis = base.as_millis();
    let window = base_millis / 5;
    if window == 0 {
        return base;
    }
    let span = window.saturating_mul(2).saturating_add(1);
    let offset = u128::from(random) % span;
    let jittered = base_millis.saturating_sub(window).saturating_add(offset);
    Duration::from_millis(
        u64::try_from(jittered).expect("validated sync delays fit in duration milliseconds"),
    )
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{jitter, SyncLoopOptions};
    use std::time::Duration;

    #[test]
    fn options_reject_zero_unbounded_and_inverted_delays() {
        assert!(SyncLoopOptions::default().validate().is_ok());
        assert!(SyncLoopOptions {
            success_interval: Duration::ZERO,
            ..SyncLoopOptions::default()
        }
        .validate()
        .is_err());
        assert!(SyncLoopOptions {
            initial_backoff: Duration::from_secs(10),
            max_backoff: Duration::from_secs(5),
            ..SyncLoopOptions::default()
        }
        .validate()
        .is_err());
        assert!(SyncLoopOptions {
            max_backoff: Duration::from_secs(24 * 60 * 60 + 1),
            ..SyncLoopOptions::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn jitter_stays_within_twenty_percent_and_is_deterministic() {
        let base = Duration::from_secs(100);
        assert_eq!(jitter(base, 0), Duration::from_secs(80));
        let high = jitter(base, u64::MAX);
        assert!(high >= Duration::from_secs(80));
        assert!(high <= Duration::from_secs(120));
        assert_eq!(
            jitter(Duration::from_millis(4), 7),
            Duration::from_millis(4)
        );
    }
}
