use crate::activation::{ActivationOptions, XraySupervisor};
use crate::local_api::{
    phase_for_runtime, LocalServiceError, LocalServiceErrorCode, LocalServicePhase,
    LocalServiceStatus, LocalStatusServer,
};
use crate::mapping::RouterMappingSupervisor;
use crate::policy::{ProviderAvailability, ProviderPolicyStatus};
use crate::relay::{RelaySupervisor, RelayTarget};
use crate::{
    status_locked,
    sync::{sync_once_locked_with_runtime_snapshot, RuntimeHeartbeatSnapshot},
    DataDirLock, EnrollmentState,
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
    RelayChanged,
}

struct ManagedRuntime {
    xray: XraySupervisor,
    direct: RouterMappingSupervisor,
    relay: RelaySupervisor,
}

impl ManagedRuntime {
    fn new() -> Result<Self> {
        Ok(Self {
            xray: XraySupervisor::new(ActivationOptions::default())?,
            direct: RouterMappingSupervisor::new(),
            relay: RelaySupervisor::new(),
        })
    }
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
    let mut runtime = ManagedRuntime::new()?;
    let initial_policy = crate::policy::evaluate(data_dir)?;
    runtime
        .xray
        .configure_admission_limits(
            initial_policy.policy.max_concurrent_sessions,
            initial_policy.policy.bandwidth_limit_bps,
        )
        .await?;
    let initial_runtime_state = policy_runtime_state(&initial_policy, NodeRuntimeState::Idle);
    let service_instance_id = Uuid::new_v4();
    let initial_status = LocalServiceStatus::from_host(
        service_instance_id,
        &initial_host,
        LocalServicePhase::Starting,
        initial_runtime_state,
        runtime.relay.runtime_state(),
        runtime.xray.admission_counters(),
        None,
    )?;
    let local_status = LocalStatusServer::start(data_dir, initial_status)?;
    let recovery = if policy_is_available(&initial_policy) {
        runtime.xray.recover(data_dir).await
    } else {
        withdraw_data_paths(data_dir, &mut runtime).await
    };
    if let Err(recovery_error) = recovery {
        publish_local_status(
            &local_status,
            service_instance_id,
            data_dir,
            &mut runtime,
            Some(LocalServicePhase::Retrying),
            Some(LocalServiceError::now(
                LocalServiceErrorCode::XrayRecoveryFailed,
            )),
        );
        if let Err(cleanup_error) = shutdown_all(data_dir, &mut runtime, local_status).await {
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
        &mut runtime,
        None,
        None,
    );

    run_service_loop(
        data_dir,
        options,
        shutdown,
        runtime,
        local_status,
        service_instance_id,
    )
    .await
}

async fn run_service_loop<F>(
    data_dir: &Path,
    options: SyncLoopOptions,
    shutdown: F,
    mut runtime: ManagedRuntime,
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
            &mut runtime,
            Some(LocalServicePhase::Syncing),
            last_error.clone(),
        );
        let event = {
            let cycle = run_cycle(data_dir, &mut runtime);
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
                    &mut runtime,
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
            &mut runtime,
            last_error.as_ref().map(|_| LocalServicePhase::Retrying),
            last_error.clone(),
        );
        match wait_for_next_cycle(data_dir, &mut runtime, shutdown.as_mut(), base_delay).await {
            WaitEvent::Deadline => {}
            WaitEvent::RuntimeFailed => {
                last_error = Some(LocalServiceError::now(
                    LocalServiceErrorCode::RuntimeHealthFailed,
                ));
                publish_local_status(
                    &local_status,
                    service_instance_id,
                    data_dir,
                    &mut runtime,
                    Some(LocalServicePhase::Retrying),
                    last_error.clone(),
                );
            }
            WaitEvent::RelayChanged => {
                publish_local_status(
                    &local_status,
                    service_instance_id,
                    data_dir,
                    &mut runtime,
                    None,
                    last_error.clone(),
                );
            }
            WaitEvent::Shutdown(signal) => {
                return finish_shutdown(
                    signal,
                    data_dir,
                    &mut runtime,
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
    runtime: &mut ManagedRuntime,
    mut shutdown: Pin<&mut F>,
    base_delay: Duration,
) -> WaitEvent
where
    F: Future<Output = Result<()>>,
{
    let initially_available = crate::policy::evaluate(data_dir)
        .map(|status| policy_is_available(&status))
        .unwrap_or(false);
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
        match crate::policy::evaluate(data_dir) {
            Ok(status) if policy_is_available(&status) != initially_available => {
                return WaitEvent::Deadline;
            }
            Ok(_) => {}
            Err(error) => {
                if let Err(cleanup_error) = withdraw_data_paths(data_dir, runtime).await {
                    tracing::warn!(error = %cleanup_error, "data-path cleanup failed after provider policy error");
                }
                tracing::warn!(error = %error, "provider policy evaluation failed closed");
                return WaitEvent::RuntimeFailed;
            }
        }
        if initially_available {
            if let Err(error) = runtime.xray.poll(data_dir).await {
                if let Err(mapping_error) = runtime.direct.reconcile(data_dir, None).await {
                    tracing::warn!(error = %mapping_error, "router mapping cleanup failed after runtime health failure");
                }
                if let Err(relay_error) = runtime.relay.reconcile(data_dir, None).await {
                    tracing::warn!(error = %relay_error, "relay cleanup failed after runtime health failure");
                }
                tracing::warn!(error = %error, "managed Xray health check failed; retrying");
                return WaitEvent::RuntimeFailed;
            }
        }
        if runtime.relay.poll_status_change() {
            return WaitEvent::RelayChanged;
        }
    }
}

async fn finish_shutdown(
    signal: Result<()>,
    data_dir: &Path,
    runtime: &mut ManagedRuntime,
    local_status: LocalStatusServer,
    service_instance_id: Uuid,
    last_error: Option<LocalServiceError>,
) -> Result<()> {
    publish_local_status(
        &local_status,
        service_instance_id,
        data_dir,
        runtime,
        Some(LocalServicePhase::Stopping),
        last_error,
    );
    shutdown_all(data_dir, runtime, local_status).await?;
    signal
}

fn publish_local_status(
    local_status: &LocalStatusServer,
    service_instance_id: Uuid,
    data_dir: &Path,
    runtime: &mut ManagedRuntime,
    phase: Option<LocalServicePhase>,
    last_error: Option<LocalServiceError>,
) {
    let result = (|| -> Result<()> {
        let policy = crate::policy::evaluate(data_dir)?;
        let runtime_state = policy_runtime_state(&policy, runtime.xray.observe_runtime_state()?);
        let host = status_locked(data_dir)?;
        let phase = phase.unwrap_or_else(|| phase_for_runtime(runtime_state));
        local_status.publish(LocalServiceStatus::from_host(
            service_instance_id,
            &host,
            phase,
            runtime_state,
            runtime.relay.runtime_state(),
            runtime.xray.admission_counters(),
            last_error,
        )?)
    })();
    if let Err(error) = result {
        tracing::warn!(error = %error, "failed to publish local Node Host status");
    }
}

async fn run_cycle(data_dir: &Path, runtime: &mut ManagedRuntime) -> Result<()> {
    let mut policy = match crate::policy::evaluate(data_dir) {
        Ok(policy) => policy,
        Err(error) => {
            withdraw_data_paths(data_dir, runtime).await?;
            return Err(error).context("provider policy failed closed");
        }
    };
    if !policy_is_available(&policy) {
        withdraw_data_paths(data_dir, runtime).await?;
        return sync_once_locked_with_runtime_snapshot(data_dir, || {
            Ok(RuntimeHeartbeatSnapshot {
                runtime_state: NodeRuntimeState::ProviderPaused,
                relay_candidate: None,
            })
        })
        .await
        .map(|_| ());
    }
    runtime
        .xray
        .configure_admission_limits(
            policy.policy.max_concurrent_sessions,
            policy.policy.bandwidth_limit_bps,
        )
        .await?;
    runtime.xray.poll(data_dir).await?;
    // A previously acknowledged candidate can activate even if the controller
    // is temporarily unavailable after a service restart.
    runtime.xray.reconcile(data_dir).await?;
    let target = runtime.xray.router_mapping_target()?;
    carry_manual_endpoint_for_target(data_dir, target)?;
    let mapping_error = runtime.direct.reconcile(data_dir, target).await.err();
    let relay_target = consented_relay_target(data_dir, target);
    let relay_error = runtime.relay.reconcile(data_dir, relay_target).await.err();
    if matches!(
        runtime.xray.observe_runtime_state()?,
        NodeRuntimeState::Serving | NodeRuntimeState::Degraded
    ) {
        if let Err(error) = crate::telemetry::collect_xray_traffic(data_dir).await {
            tracing::warn!(error = %error, "Xray traffic collection state could not be persisted");
        }
    }
    policy = crate::policy::evaluate(data_dir)?;
    if !policy_is_available(&policy) {
        withdraw_data_paths(data_dir, runtime).await?;
        return sync_once_locked_with_runtime_snapshot(data_dir, || {
            Ok(RuntimeHeartbeatSnapshot {
                runtime_state: NodeRuntimeState::ProviderPaused,
                relay_candidate: None,
            })
        })
        .await
        .map(|_| ());
    }
    acknowledge_registered_relay(data_dir, runtime, relay_target).await?;
    let sync_result = sync_once_locked_with_runtime_snapshot(data_dir, || {
        runtime_heartbeat_snapshot(data_dir, runtime)
    })
    .await;
    // Relay withdrawal and authentication denial must stop the connector even
    // when the rest of the control cycle returns an error.
    if runtime
        .relay
        .reconcile(data_dir, relay_target)
        .await
        .is_err()
    {
        tracing::warn!(
            error_code = "relay_runtime_reconcile_failed",
            "relay runtime reconciliation failed closed independently"
        );
    }
    sync_result?;
    policy = crate::policy::evaluate(data_dir)?;
    if !policy_is_available(&policy) {
        withdraw_data_paths(data_dir, runtime).await?;
        return Ok(());
    }
    runtime.xray.reconcile(data_dir).await?;
    let target = runtime.xray.router_mapping_target()?;
    carry_manual_endpoint_for_target(data_dir, target)?;
    if let Err(error) = runtime.direct.reconcile(data_dir, target).await {
        tracing::warn!(error = %error, "direct mapping reconciliation failed after sync");
    }
    let relay_target = consented_relay_target(data_dir, target);
    if let Err(error) = runtime.relay.reconcile(data_dir, relay_target).await {
        tracing::warn!(error = %error, "relay reconciliation failed after sync");
    }
    if let Some(error) = mapping_error {
        tracing::warn!(error = %error, "direct mapping failed independently of relay and heartbeat");
    }
    if let Some(error) = relay_error {
        tracing::warn!(error = %error, "relay failed independently of direct mapping and heartbeat");
    }
    Ok(())
}

fn carry_manual_endpoint_for_target(
    data_dir: &Path,
    target: Option<crate::mapping::MappingTarget>,
) -> Result<()> {
    if let Some(target) = target {
        crate::policy::carry_manual_endpoint_forward(
            data_dir,
            target.revision,
            target.internal_port,
        )?;
    }
    Ok(())
}

fn runtime_heartbeat_snapshot(
    data_dir: &Path,
    runtime: &mut ManagedRuntime,
) -> Result<RuntimeHeartbeatSnapshot> {
    let relay_candidate = match runtime.relay.candidate_for_state(data_dir) {
        Ok(candidate) => candidate,
        Err(_error) => {
            tracing::warn!(
                error_code = "relay_candidate_state_failed",
                "relay candidate state failed closed independently"
            );
            None
        }
    };
    Ok(RuntimeHeartbeatSnapshot {
        runtime_state: runtime.xray.observe_runtime_state()?,
        relay_candidate,
    })
}

async fn acknowledge_registered_relay(
    data_dir: &Path,
    runtime: &mut ManagedRuntime,
    relay_target: Option<RelayTarget>,
) -> Result<()> {
    let acknowledgement = match runtime.relay.acknowledgement_candidate(data_dir) {
        Ok(acknowledgement) => acknowledgement,
        Err(_error) => {
            tracing::warn!(
                error_code = "relay_acknowledgement_state_failed",
                "relay acknowledgement state failed closed independently"
            );
            return Ok(());
        }
    };
    let Some(acknowledgement) = acknowledgement else {
        return Ok(());
    };
    match crate::sync::acknowledge_relay_assignment(data_dir, acknowledgement).await {
        Ok(()) => {
            if RelaySupervisor::acknowledgement_succeeded(data_dir, acknowledgement).is_err() {
                tracing::warn!(
                    error_code = "relay_acknowledgement_commit_failed",
                    "relay acknowledgement committed remotely but local promotion will retry"
                );
            }
            Ok(())
        }
        Err(_error) => {
            tracing::warn!(
                error_code = "relay_acknowledgement_failed",
                "relay acknowledgement failed; retaining predecessor and retrying"
            );
            if runtime
                .relay
                .reconcile(data_dir, relay_target)
                .await
                .is_err()
            {
                tracing::warn!(
                    error_code = "relay_runtime_reconcile_failed",
                    "relay runtime reconciliation failed closed independently"
                );
            }
            Ok(())
        }
    }
}

fn consented_relay_target(
    data_dir: &Path,
    target: Option<crate::mapping::MappingTarget>,
) -> Option<RelayTarget> {
    match crate::relay::provider_relay_consented(data_dir) {
        Ok(true) => target.map(|target| RelayTarget {
            revision: target.revision,
            admission_port: target.internal_port,
        }),
        Ok(false) => None,
        Err(_error) => {
            tracing::warn!(
                error_code = "relay_consent_state_failed",
                "relay consent state failed closed independently"
            );
            None
        }
    }
}

async fn withdraw_data_paths(data_dir: &Path, runtime: &mut ManagedRuntime) -> Result<()> {
    let mapping_error = runtime.direct.reconcile(data_dir, None).await.err();
    let relay_error = runtime.relay.reconcile(data_dir, None).await.err();
    let runtime_error = runtime.xray.shutdown().await.err();
    if let Some(error) = mapping_error {
        return Err(error).context("provider policy could not withdraw router mapping");
    }
    if let Some(error) = relay_error {
        return Err(error).context("provider policy could not withdraw relay candidate");
    }
    if let Some(error) = runtime_error {
        return Err(error).context("provider policy could not stop member traffic");
    }
    Ok(())
}

const fn policy_is_available(status: &ProviderPolicyStatus) -> bool {
    matches!(status.availability, ProviderAvailability::Available)
}

const fn policy_runtime_state(
    status: &ProviderPolicyStatus,
    runtime_state: NodeRuntimeState,
) -> NodeRuntimeState {
    if policy_is_available(status) {
        runtime_state
    } else {
        NodeRuntimeState::ProviderPaused
    }
}

async fn shutdown_services(data_dir: &Path, runtime: &mut ManagedRuntime) -> Result<()> {
    let mapping_result = runtime.direct.shutdown(data_dir).await;
    runtime.relay.shutdown().await;
    let runtime_result = runtime.xray.shutdown().await;
    if let Err(mapping_error) = mapping_result {
        runtime_result.context("managed Xray shutdown also failed")?;
        return Err(mapping_error).context("router mapping shutdown failed");
    }
    runtime_result
}

async fn shutdown_all(
    data_dir: &Path,
    runtime: &mut ManagedRuntime,
    local_status: LocalStatusServer,
) -> Result<()> {
    let service_result = shutdown_services(data_dir, runtime).await;
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
