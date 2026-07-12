use crate::admission::{AdmissionCounters, AdmissionGate, AdmissionOptions};
use crate::xray::{insert_revision_result, load_validated_candidate, ValidatedXrayCandidate};
use crate::{migrate, open_database, unix_timestamp};
use anyhow::{bail, Context, Result};
use control_protocol::error::ErrorCode;
use control_protocol::id::{Revision, Timestamp};
use control_protocol::node::{RevisionResult, RevisionResultState};
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, Instant};
use xray_runtime::{
    start_managed, ManagedXrayChild, Sha256Digest as RuntimeSha256Digest, XrayBinarySpec,
    XrayConfigSpec,
};

const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_STABILIZATION_DURATION: Duration = Duration::from_secs(5);
const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_millis(100);
const RUNTIME_ADMISSION_PROBE_INTERVAL: Duration = Duration::from_secs(30);
const MAX_ACTIVATION_ATTEMPTS_WITHOUT_PREDECESSOR: i64 = 3;
const MAX_RUNTIME_DELAY: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy)]
pub(crate) struct ActivationOptions {
    startup_timeout: Duration,
    stabilization_duration: Duration,
    probe_interval: Duration,
    admission: AdmissionOptions,
}

impl Default for ActivationOptions {
    fn default() -> Self {
        Self {
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            stabilization_duration: DEFAULT_STABILIZATION_DURATION,
            probe_interval: DEFAULT_PROBE_INTERVAL,
            admission: AdmissionOptions::default(),
        }
    }
}

impl ActivationOptions {
    fn validate(self) -> Result<Self> {
        if self.startup_timeout.is_zero()
            || self.stabilization_duration.is_zero()
            || self.probe_interval.is_zero()
            || self.startup_timeout > MAX_RUNTIME_DELAY
            || self.stabilization_duration > MAX_RUNTIME_DELAY
            || self.probe_interval > self.startup_timeout
        {
            bail!("Xray activation timing options are invalid");
        }
        self.admission.validate()?;
        Ok(self)
    }
}

pub(crate) struct XraySupervisor {
    child: Option<ManagedXrayChild>,
    admission: Option<AdmissionGate>,
    running_revision: Option<Revision>,
    running_public_port: Option<u16>,
    last_admission_probe: Option<Instant>,
    last_admission_counters: AdmissionCounters,
    options: ActivationOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivationStatus {
    pub applied_revision: Option<Revision>,
    pub latest_phase: Option<String>,
}

pub(crate) fn load_activation_status(connection: &Connection) -> Result<ActivationStatus> {
    let has_table: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'xray_active_state'
         )",
        [],
        |row| row.get(0),
    )?;
    if !has_table {
        return Ok(ActivationStatus {
            applied_revision: None,
            latest_phase: None,
        });
    }
    let applied_revision = connection
        .query_row(
            "SELECT applied_revision FROM xray_active_state WHERE singleton = 1",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .map(Revision::new)
        .transpose()
        .context("stored applied revision is invalid")?;
    let latest_phase = connection
        .query_row(
            "SELECT phase FROM xray_activation_journal ORDER BY revision DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|phase| JournalPhase::parse(&phase).map(|value| value.as_str().to_string()))
        .transpose()?;
    Ok(ActivationStatus {
        applied_revision,
        latest_phase,
    })
}

impl XraySupervisor {
    pub(crate) fn new(options: ActivationOptions) -> Result<Self> {
        Ok(Self {
            child: None,
            admission: None,
            running_revision: None,
            running_public_port: None,
            last_admission_probe: None,
            last_admission_counters: AdmissionCounters::default(),
            options: options.validate()?,
        })
    }

    pub(crate) async fn configure_admission_limits(
        &mut self,
        max_connections: u16,
        bandwidth_limit_bps: Option<u64>,
    ) -> Result<()> {
        let mut admission = self.options.admission;
        admission.max_connections = usize::from(max_connections);
        admission.bandwidth_limit_bps = bandwidth_limit_bps;
        admission.validate()?;
        if admission != self.options.admission {
            self.options.admission = admission;
            if self.child.is_some() || self.admission.is_some() {
                self.stop_runtime().await?;
            }
        }
        Ok(())
    }

    pub(crate) fn admission_counters(&self) -> AdmissionCounters {
        self.admission
            .as_ref()
            .map_or(self.last_admission_counters, AdmissionGate::counters)
    }

    pub(crate) async fn recover(&mut self, data_dir: &Path) -> Result<()> {
        let (active, interrupted) = {
            let mut connection = open_database(data_dir, false)?;
            migrate(&mut connection)?;
            (
                load_active_state(&connection)?,
                load_incomplete_journal(&connection)?,
            )
        };

        if let Some(journal) = interrupted {
            self.recover_interrupted(data_dir, active.as_ref(), &journal)
                .await?;
        }
        self.ensure_active_running(data_dir).await
    }

    pub(crate) async fn reconcile(&mut self, data_dir: &Path) -> Result<()> {
        self.ensure_active_running(data_dir).await?;
        let (pending_revision, active) = {
            let connection = open_database(data_dir, false)?;
            (
                load_pending_revision(&connection)?,
                load_active_state(&connection)?,
            )
        };
        let Some(revision) = pending_revision else {
            return Ok(());
        };
        if active
            .as_ref()
            .is_some_and(|state| state.revision == revision)
        {
            return Ok(());
        }

        let incomplete = {
            let connection = open_database(data_dir, false)?;
            load_incomplete_journal(&connection)?
        };
        if let Some(journal) = incomplete.as_ref() {
            if journal.revision != revision {
                resolve_superseded_journal(data_dir, journal)?;
            }
        }

        let candidate = load_candidate(data_dir, revision)?;
        let previous = active
            .as_ref()
            .map(|state| load_candidate(data_dir, state.revision))
            .transpose()?;
        let previous_revision = previous.as_ref().map(|candidate| candidate.revision);
        let attempt = begin_activation(data_dir, revision, previous_revision)?;
        if let Err(error) = self.stop_runtime().await {
            mark_recovery_required(data_dir, revision, &ErrorCode::RollbackFailed)?;
            return Err(error).context("existing node runtime could not be stopped safely");
        }

        let child = match self.spawn_candidate(&candidate).await {
            Ok(child) => child,
            Err(failure) => {
                return self
                    .handle_activation_failure(
                        data_dir,
                        &candidate,
                        previous.as_ref(),
                        attempt,
                        failure,
                    )
                    .await;
            }
        };
        self.own_child(child);
        self.stabilize_and_commit_candidate(data_dir, &candidate, previous.as_ref(), attempt)
            .await
    }

    async fn stabilize_and_commit_candidate(
        &mut self,
        data_dir: &Path,
        candidate: &ValidatedXrayCandidate,
        previous: Option<&ValidatedXrayCandidate>,
        attempt: i64,
    ) -> Result<()> {
        if let Err(journal_error) = update_journal_phase(
            data_dir,
            candidate.revision,
            JournalPhase::Stabilizing,
            None,
        ) {
            if let Err(restore_error) = self.restore_after_commit_failure(previous).await {
                mark_recovery_required(data_dir, candidate.revision, &ErrorCode::RollbackFailed)?;
                return Err(restore_error).with_context(|| {
                    format!(
                        "candidate journal transition also failed before rollback: {journal_error:#}"
                    )
                });
            }
            return Err(journal_error)
                .context("candidate journal transition failed; previous runtime restored");
        }
        let activation_result = match self.prove_owned_child_healthy(candidate.listen_port).await {
            Ok(()) => self.start_admission(candidate).await,
            Err(failure) => Err(failure),
        };
        match activation_result {
            Ok(()) => {
                if let Err(commit_error) = finalize_applied(data_dir, candidate) {
                    return self
                        .resolve_commit_failure(data_dir, candidate, previous, commit_error)
                        .await;
                }
                self.mark_running(candidate);
                Ok(())
            }
            Err(failure) => {
                self.handle_activation_failure(data_dir, candidate, previous, attempt, failure)
                    .await
            }
        }
    }

    pub(crate) async fn poll(&mut self, data_dir: &Path) -> Result<()> {
        let state = self.observe_runtime_state()?;
        if matches!(
            state,
            control_protocol::node::NodeRuntimeState::Serving
                | control_protocol::node::NodeRuntimeState::Degraded
        ) {
            if state == control_protocol::node::NodeRuntimeState::Serving
                && self.admission_probe_is_due()
            {
                let probe_result = self
                    .admission
                    .as_ref()
                    .context("serving runtime lost admission ownership")?
                    .prove_backend_ready()
                    .await;
                if let Err(probe_error) = probe_result {
                    let cleanup_result = self.stop_runtime().await;
                    cleanup_result.context("unhealthy admission runtime could not be stopped")?;
                    return Err(probe_error)
                        .context("applied admission backend failed its runtime health check");
                }
                self.last_admission_probe = Some(Instant::now());
            }
            return Ok(());
        }
        self.ensure_active_running(data_dir).await
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        self.stop_runtime().await
    }

    pub(crate) fn observe_runtime_state(
        &mut self,
    ) -> Result<control_protocol::node::NodeRuntimeState> {
        let Some(child) = self.child.as_mut() else {
            self.clear_running_marker();
            return Ok(control_protocol::node::NodeRuntimeState::Idle);
        };
        if child.try_wait()?.is_some() {
            self.child = None;
            self.clear_running_marker();
            return Ok(control_protocol::node::NodeRuntimeState::Idle);
        }
        if self.running_revision.is_none() {
            return Ok(control_protocol::node::NodeRuntimeState::Idle);
        }
        if self.running_public_port.is_some()
            && !self
                .admission
                .as_ref()
                .is_some_and(AdmissionGate::is_running)
        {
            self.clear_running_marker();
            return Ok(control_protocol::node::NodeRuntimeState::Idle);
        }
        Ok(if self.running_public_port.is_some() {
            control_protocol::node::NodeRuntimeState::Serving
        } else {
            control_protocol::node::NodeRuntimeState::Degraded
        })
    }

    pub(crate) fn router_mapping_target(
        &mut self,
    ) -> Result<Option<crate::mapping::MappingTarget>> {
        if self.observe_runtime_state()? != control_protocol::node::NodeRuntimeState::Serving {
            return Ok(None);
        }
        let revision = self
            .running_revision
            .context("serving Xray runtime has no applied revision")?;
        let internal_port = self
            .running_public_port
            .context("serving Xray runtime has no admission port")?;
        Ok(Some(crate::mapping::MappingTarget {
            revision,
            internal_port,
        }))
    }

    async fn recover_interrupted(
        &mut self,
        data_dir: &Path,
        active: Option<&ActiveState>,
        journal: &ActivationJournal,
    ) -> Result<()> {
        if journal.phase.is_terminal() {
            bail!("terminal Xray activation journal cannot enter recovery");
        }
        if let Some(previous_revision) = journal.previous_revision {
            let active_revision = active
                .map(|state| state.revision)
                .context("activation journal predecessor has no active-state pointer")?;
            if active_revision != previous_revision {
                mark_recovery_required(data_dir, journal.revision, &ErrorCode::RollbackFailed)?;
                bail!("activation journal predecessor does not match active state");
            }
            if let Err(recovery_error) = self.ensure_active_running(data_dir).await {
                let cleanup_result = self.stop_runtime().await;
                mark_recovery_required(data_dir, journal.revision, &ErrorCode::RollbackFailed)?;
                cleanup_result.context("failed recovery runtime could not be cleaned up")?;
                return Err(recovery_error)
                    .context("activation predecessor could not be restored during recovery");
            }
            let previous = load_candidate(data_dir, previous_revision)?;
            finalize_rolled_back(data_dir, journal, &previous, &ErrorCode::XrayUnhealthy)?;
            return Ok(());
        }

        if journal.attempt_count >= MAX_ACTIVATION_ATTEMPTS_WITHOUT_PREDECESSOR {
            finalize_rejected(data_dir, journal, &ErrorCode::XrayStartFailed)
        } else {
            update_journal_phase(
                data_dir,
                journal.revision,
                JournalPhase::RetryPending,
                Some(&ErrorCode::XrayStartFailed),
            )
        }
    }

    async fn ensure_active_running(&mut self, data_dir: &Path) -> Result<()> {
        let active = {
            let connection = open_database(data_dir, false)?;
            load_active_state(&connection)?
        };
        let Some(active) = active else {
            if self.child.is_some() || self.admission.is_some() {
                self.stop_runtime().await?;
            }
            return Ok(());
        };
        if self.running_revision == Some(active.revision) {
            let state = self.observe_runtime_state()?;
            if matches!(
                state,
                control_protocol::node::NodeRuntimeState::Serving
                    | control_protocol::node::NodeRuntimeState::Degraded
            ) {
                return Ok(());
            }
        }
        self.stop_runtime().await?;
        let candidate = load_candidate(data_dir, active.revision)?;
        if candidate.config_digest.as_str() != active.config_digest
            || candidate.binary_digest.to_string() != active.binary_digest
        {
            bail!("active Xray pointer does not match its verified candidate");
        }
        self.start_proven_candidate(&candidate)
            .await
            .map_err(|failure| failure.error)?;
        record_active_restart(data_dir, active.revision)?;
        Ok(())
    }

    async fn start_proven_candidate(
        &mut self,
        candidate: &ValidatedXrayCandidate,
    ) -> std::result::Result<(), ActivationFailure> {
        let child = self.spawn_candidate(candidate).await?;
        self.own_child(child);
        if let Err(failure) = self.prove_owned_child_healthy(candidate.listen_port).await {
            return Err(self.stop_after_health_failure(failure).await);
        }
        if let Err(failure) = self.start_admission(candidate).await {
            return Err(self.stop_after_health_failure(failure).await);
        }
        self.mark_running(candidate);
        Ok(())
    }

    async fn restore_after_commit_failure(
        &mut self,
        previous: Option<&ValidatedXrayCandidate>,
    ) -> Result<()> {
        self.stop_runtime()
            .await
            .context("uncommitted candidate runtime could not be stopped")?;
        let Some(previous) = previous else {
            return Ok(());
        };
        self.start_proven_candidate(previous)
            .await
            .map_err(|failure| failure.error)
            .context("previous runtime could not be restored after commit failure")
    }

    async fn resolve_commit_failure(
        &mut self,
        data_dir: &Path,
        candidate: &ValidatedXrayCandidate,
        previous: Option<&ValidatedXrayCandidate>,
        commit_error: anyhow::Error,
    ) -> Result<()> {
        let durable_revision = match (|| -> Result<Option<Revision>> {
            let connection = open_database(data_dir, false)?;
            Ok(load_active_state(&connection)?.map(|state| state.revision))
        })() {
            Ok(revision) => revision,
            Err(state_error) => {
                let cleanup_result = self.stop_runtime().await;
                cleanup_result
                    .context("unconfirmed candidate runtime could not be stopped safely")?;
                return Err(state_error).with_context(|| {
                    format!(
                        "candidate commit failed and durable state cannot be confirmed: {commit_error:#}"
                    )
                });
            }
        };
        if durable_revision == Some(candidate.revision) {
            self.mark_running(candidate);
            return Err(commit_error).context(
                "candidate commit returned an error but durable state confirms it applied",
            );
        }
        let expected_previous = previous.map(|candidate| candidate.revision);
        if durable_revision == expected_previous {
            if let Err(restore_error) = self.restore_after_commit_failure(previous).await {
                mark_recovery_required(data_dir, candidate.revision, &ErrorCode::RollbackFailed)?;
                return Err(restore_error).with_context(|| {
                    format!(
                        "candidate durable commit also failed before rollback: {commit_error:#}"
                    )
                });
            }
            return Err(commit_error)
                .context("candidate durable commit failed; previous runtime restored");
        }

        let cleanup_result = self.stop_runtime().await;
        mark_recovery_required(data_dir, candidate.revision, &ErrorCode::StateConflict)?;
        cleanup_result.context("inconsistent post-commit runtime could not be stopped")?;
        Err(commit_error).context("candidate commit left an unexpected durable active revision")
    }

    async fn start_admission(
        &mut self,
        candidate: &ValidatedXrayCandidate,
    ) -> std::result::Result<(), ActivationFailure> {
        let Some(public_port) = candidate.public_port else {
            return Ok(());
        };
        let gate = AdmissionGate::start(public_port, candidate.listen_port, self.options.admission)
            .map_err(|error| {
                ActivationFailure::from_error(ErrorCode::AdmissionBindFailed, error)
            })?;
        debug_assert!(self.admission.is_none());
        self.last_admission_counters = AdmissionCounters::default();
        self.admission = Some(gate);
        self.admission
            .as_ref()
            .expect("admission gate was just installed")
            .prove_ready()
            .await
            .map_err(|error| ActivationFailure::from_error(ErrorCode::AdmissionUnhealthy, error))?;
        match self.owned_child_status() {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(ActivationFailure::new(
                ErrorCode::XrayUnhealthy,
                "managed Xray exited while the admission gate was starting",
            )),
            Err(error) => Err(ActivationFailure::from_error(
                ErrorCode::XrayUnhealthy,
                error,
            )),
        }
    }

    async fn spawn_candidate(
        &self,
        candidate: &ValidatedXrayCandidate,
    ) -> std::result::Result<ManagedXrayChild, ActivationFailure> {
        let config_hex = candidate
            .config_digest
            .as_str()
            .strip_prefix("sha256:")
            .ok_or_else(|| {
                ActivationFailure::new(ErrorCode::XrayStartFailed, "invalid config digest")
            })?;
        let config_digest = RuntimeSha256Digest::from_hex(config_hex)
            .map_err(|error| ActivationFailure::from_error(ErrorCode::XrayStartFailed, error))?;
        let binary_spec =
            XrayBinarySpec::new(candidate.binary_path.clone(), candidate.binary_digest).map_err(
                |error| ActivationFailure::from_error(ErrorCode::XrayStartFailed, error),
            )?;
        let config_spec = XrayConfigSpec::new(candidate.config_path.clone(), config_digest)
            .map_err(|error| ActivationFailure::from_error(ErrorCode::XrayStartFailed, error))?;
        let verified = tokio::task::spawn_blocking(move || -> Result<_> {
            Ok((binary_spec.verify()?, config_spec.verify()?))
        })
        .await
        .map_err(|_| {
            ActivationFailure::new(
                ErrorCode::XrayStartFailed,
                "runtime verification task failed",
            )
        })?
        .map_err(|error| ActivationFailure::from_error(ErrorCode::XrayStartFailed, error))?;
        start_managed(&verified.0, &verified.1)
            .await
            .map_err(|error| ActivationFailure::from_error(ErrorCode::XrayStartFailed, error))
    }

    async fn prove_owned_child_healthy(
        &mut self,
        listen_port: u16,
    ) -> std::result::Result<(), ActivationFailure> {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);
        let startup_deadline = Instant::now() + self.options.startup_timeout;
        loop {
            match self.owned_child_status() {
                Ok(Some(_)) => {
                    return Err(ActivationFailure::new(
                        ErrorCode::XrayStartFailed,
                        "managed Xray exited during startup",
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(ActivationFailure::from_error(
                        ErrorCode::XrayStartFailed,
                        error,
                    ));
                }
            }
            if listener_is_ready(address, self.options.probe_interval).await {
                break;
            }
            if Instant::now() >= startup_deadline {
                return Err(self
                    .stop_after_health_failure(ActivationFailure::new(
                        ErrorCode::XrayUnhealthy,
                        "managed Xray loopback listener did not become ready",
                    ))
                    .await);
            }
            sleep(self.options.probe_interval).await;
        }

        let stabilization_deadline = Instant::now() + self.options.stabilization_duration;
        while Instant::now() < stabilization_deadline {
            match self.owned_child_status() {
                Ok(Some(_)) => {
                    return Err(ActivationFailure::new(
                        ErrorCode::XrayUnhealthy,
                        "managed Xray exited during stabilization",
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(ActivationFailure::from_error(
                        ErrorCode::XrayUnhealthy,
                        error,
                    ));
                }
            }
            sleep(self.options.probe_interval).await;
        }
        if !listener_is_ready(address, self.options.probe_interval).await {
            return Err(self
                .stop_after_health_failure(ActivationFailure::new(
                    ErrorCode::XrayUnhealthy,
                    "managed Xray loopback listener became unavailable",
                ))
                .await);
        }
        Ok(())
    }

    async fn handle_activation_failure(
        &mut self,
        data_dir: &Path,
        candidate: &ValidatedXrayCandidate,
        previous: Option<&ValidatedXrayCandidate>,
        attempt: i64,
        failure: ActivationFailure,
    ) -> Result<()> {
        if let Err(error) = self.stop_runtime().await {
            mark_recovery_required(data_dir, candidate.revision, &ErrorCode::RollbackFailed)?;
            return Err(error).context("failed node runtime could not be stopped safely");
        }
        if let Some(previous) = previous {
            if self.start_proven_candidate(previous).await.is_err() {
                let cleanup_result = self.stop_runtime().await;
                mark_recovery_required(data_dir, candidate.revision, &ErrorCode::RollbackFailed)?;
                cleanup_result.context("failed rollback runtime could not be cleaned up")?;
                bail!("previous runtime failed rollback health checks");
            }
            update_journal_phase(
                data_dir,
                candidate.revision,
                JournalPhase::RollingBack,
                Some(&failure.code),
            )
            .context("previous runtime restored but rollback journal update failed")?;
            let journal = load_journal(data_dir, candidate.revision)?;
            finalize_rolled_back(data_dir, &journal, previous, &failure.code)?;
            record_active_restart(data_dir, previous.revision)?;
            return Ok(());
        }

        if attempt >= MAX_ACTIVATION_ATTEMPTS_WITHOUT_PREDECESSOR {
            let journal = load_journal(data_dir, candidate.revision)?;
            finalize_rejected(data_dir, &journal, &failure.code)
        } else {
            update_journal_phase(
                data_dir,
                candidate.revision,
                JournalPhase::RetryPending,
                Some(&failure.code),
            )?;
            Err(failure.error).context("initial Xray activation failed; retry scheduled")
        }
    }

    async fn stop_runtime(&mut self) -> Result<()> {
        self.clear_running_marker();
        let admission_error = if let Some(admission) = self.admission.as_mut() {
            self.last_admission_counters = admission.counters();
            admission.shutdown().await.err()
        } else {
            None
        };
        self.admission = None;
        if let Some(child) = self.child.as_mut() {
            if let Err(error) = child.kill_and_wait().await {
                return match admission_error {
                    Some(admission_error) => Err(error).with_context(|| {
                        format!(
                            "admission cleanup also failed before Xray cleanup: {admission_error:#}"
                        )
                    }),
                    None => Err(error.into()),
                };
            }
        }
        self.child = None;
        match admission_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn own_child(&mut self, child: ManagedXrayChild) {
        debug_assert!(self.child.is_none());
        debug_assert!(self.admission.is_none());
        self.child = Some(child);
        self.clear_running_marker();
    }

    fn owned_child_status(&mut self) -> Result<Option<std::process::ExitStatus>> {
        let status = self
            .child
            .as_mut()
            .context("managed Xray child ownership was lost")?
            .try_wait()?;
        if status.is_some() {
            self.child = None;
            self.clear_running_marker();
        }
        Ok(status)
    }

    fn mark_running(&mut self, candidate: &ValidatedXrayCandidate) {
        debug_assert!(self.child.is_some());
        debug_assert!(
            candidate.public_port.is_none()
                || self
                    .admission
                    .as_ref()
                    .is_some_and(AdmissionGate::is_running)
        );
        self.running_revision = Some(candidate.revision);
        self.running_public_port = candidate.public_port;
        self.last_admission_probe = candidate.public_port.map(|_| Instant::now());
    }

    fn clear_running_marker(&mut self) {
        self.running_revision = None;
        self.running_public_port = None;
        self.last_admission_probe = None;
    }

    fn admission_probe_is_due(&self) -> bool {
        match self.last_admission_probe {
            Some(last_probe) => {
                Instant::now().duration_since(last_probe) >= RUNTIME_ADMISSION_PROBE_INTERVAL
            }
            None => true,
        }
    }

    async fn stop_after_health_failure(&mut self, failure: ActivationFailure) -> ActivationFailure {
        match self.stop_runtime().await {
            Ok(()) => failure,
            Err(error) => ActivationFailure::from_error(ErrorCode::RollbackFailed, error),
        }
    }
}

struct ActivationFailure {
    code: ErrorCode,
    error: anyhow::Error,
}

impl ActivationFailure {
    fn new(code: ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            error: anyhow::anyhow!(message),
        }
    }

    fn from_error(code: ErrorCode, error: impl Into<anyhow::Error>) -> Self {
        Self {
            code,
            error: error.into(),
        }
    }
}

#[derive(Debug, Clone)]
struct ActiveState {
    revision: Revision,
    config_digest: String,
    binary_digest: String,
}

#[derive(Debug, Clone)]
struct ActivationJournal {
    revision: Revision,
    previous_revision: Option<Revision>,
    phase: JournalPhase,
    attempt_count: i64,
    started_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalPhase {
    Activating,
    Stabilizing,
    RetryPending,
    Applied,
    RollingBack,
    RolledBack,
    Rejected,
    RecoveryRequired,
}

impl JournalPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Activating => "activating",
            Self::Stabilizing => "stabilizing",
            Self::RetryPending => "retryPending",
            Self::Applied => "applied",
            Self::RollingBack => "rollingBack",
            Self::RolledBack => "rolledBack",
            Self::Rejected => "rejected",
            Self::RecoveryRequired => "recoveryRequired",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "activating" => Ok(Self::Activating),
            "stabilizing" => Ok(Self::Stabilizing),
            "retryPending" => Ok(Self::RetryPending),
            "applied" => Ok(Self::Applied),
            "rollingBack" => Ok(Self::RollingBack),
            "rolledBack" => Ok(Self::RolledBack),
            "rejected" => Ok(Self::Rejected),
            "recoveryRequired" => Ok(Self::RecoveryRequired),
            _ => bail!("stored Xray activation phase is invalid"),
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Applied | Self::RolledBack | Self::Rejected | Self::RecoveryRequired
        )
    }
}

async fn listener_is_ready(address: SocketAddr, limit: Duration) -> bool {
    timeout(limit, TcpStream::connect(address))
        .await
        .is_ok_and(|result| result.is_ok())
}

fn load_candidate(data_dir: &Path, revision: Revision) -> Result<ValidatedXrayCandidate> {
    let connection = open_database(data_dir, false)?;
    load_validated_candidate(&connection, data_dir, revision)
}

fn load_active_state(connection: &Connection) -> Result<Option<ActiveState>> {
    let stored = connection.query_row(
        "SELECT applied_revision, config_digest, binary_digest
         FROM xray_active_state WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, Option<i64>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    )?;
    let Some(revision) = stored.0 else {
        if stored.1.is_some() || stored.2.is_some() {
            bail!("empty Xray active state contains candidate metadata");
        }
        return Ok(None);
    };
    Ok(Some(ActiveState {
        revision: Revision::new(revision).context("stored applied revision is invalid")?,
        config_digest: stored.1.context("active config digest is missing")?,
        binary_digest: stored.2.context("active binary digest is missing")?,
    }))
}

fn load_pending_revision(connection: &Connection) -> Result<Option<Revision>> {
    let desired_revision: i64 = connection.query_row(
        "SELECT desired_revision_cursor FROM control_sync_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if desired_revision == 0 {
        return Ok(None);
    }
    let latest_result = connection
        .query_row(
            "SELECT state, reported_at FROM local_revision_results
             WHERE revision = ?1
             ORDER BY CASE state
                 WHEN 'received' THEN 10
                 WHEN 'validated' THEN 20
                 ELSE 30
             END DESC, state DESC
             LIMIT 1",
            [desired_revision],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    if !matches!(latest_result, Some((ref state, Some(_))) if state == "validated") {
        return Ok(None);
    }
    Revision::new(desired_revision)
        .context("pending desired revision is invalid")
        .map(Some)
}

fn load_incomplete_journal(connection: &Connection) -> Result<Option<ActivationJournal>> {
    let mut statement = connection.prepare(
        "SELECT revision, previous_revision, phase, attempt_count, started_at
         FROM xray_activation_journal
         WHERE phase NOT IN ('applied', 'rolledBack', 'rejected', 'recoveryRequired')
         ORDER BY revision DESC",
    )?;
    let rows = statement
        .query_map([], journal_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() > 1 {
        bail!("multiple incomplete Xray activation journals require recovery");
    }
    Ok(rows.into_iter().next())
}

fn resolve_superseded_journal(data_dir: &Path, journal: &ActivationJournal) -> Result<()> {
    if let Some(previous_revision) = journal.previous_revision {
        let connection = open_database(data_dir, false)?;
        let active = load_active_state(&connection)?
            .context("superseded activation journal has no active predecessor")?;
        if active.revision != previous_revision {
            bail!("superseded activation predecessor does not match active state");
        }
        let previous = load_candidate(data_dir, previous_revision)?;
        finalize_rolled_back(data_dir, journal, &previous, &ErrorCode::StateStale)
    } else {
        finalize_rejected(data_dir, journal, &ErrorCode::StateStale)
    }
}

fn load_journal(data_dir: &Path, revision: Revision) -> Result<ActivationJournal> {
    let connection = open_database(data_dir, false)?;
    connection
        .query_row(
            "SELECT revision, previous_revision, phase, attempt_count, started_at
             FROM xray_activation_journal WHERE revision = ?1",
            [revision.get()],
            journal_from_row,
        )
        .context("Xray activation journal is missing")
}

fn journal_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActivationJournal> {
    let revision = row.get::<_, i64>(0)?;
    let previous_revision = row.get::<_, Option<i64>>(1)?;
    let phase = row.get::<_, String>(2)?;
    Ok(ActivationJournal {
        revision: Revision::new(revision).map_err(|_| rusqlite::Error::InvalidQuery)?,
        previous_revision: previous_revision
            .map(Revision::new)
            .transpose()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        phase: JournalPhase::parse(&phase).map_err(|_| rusqlite::Error::InvalidQuery)?,
        attempt_count: row.get(3)?,
        started_at: row.get(4)?,
    })
}

fn begin_activation(
    data_dir: &Path,
    revision: Revision,
    previous_revision: Option<Revision>,
) -> Result<i64> {
    let mut connection = open_database(data_dir, false)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing = transaction
        .query_row(
            "SELECT previous_revision, phase, attempt_count
             FROM xray_activation_journal WHERE revision = ?1",
            [revision.get()],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let now = unix_timestamp()?;
    let attempt = if let Some((stored_previous, phase, attempt_count)) = existing {
        if stored_previous != previous_revision.map(Revision::get) {
            bail!("Xray activation predecessor changed across retries");
        }
        let phase = JournalPhase::parse(&phase)?;
        if phase.is_terminal() {
            bail!("terminal Xray activation journal cannot be retried");
        }
        let attempt = attempt_count
            .checked_add(1)
            .context("Xray activation attempt count overflowed")?;
        transaction.execute(
            "UPDATE xray_activation_journal
                 SET phase = 'activating', attempt_count = ?1, updated_at = ?2,
                     completed_at = NULL, error_code = NULL
                 WHERE revision = ?3",
            params![attempt, now, revision.get()],
        )?;
        attempt
    } else {
        transaction.execute(
            "INSERT INTO xray_activation_journal(
                    revision, previous_revision, phase, attempt_count,
                    started_at, updated_at, completed_at, error_code
                 ) VALUES (?1, ?2, 'activating', 1, ?3, ?3, NULL, NULL)",
            params![revision.get(), previous_revision.map(Revision::get), now,],
        )?;
        1
    };
    transaction.commit()?;
    Ok(attempt)
}

fn update_journal_phase(
    data_dir: &Path,
    revision: Revision,
    phase: JournalPhase,
    error_code: Option<&ErrorCode>,
) -> Result<()> {
    if phase.is_terminal() {
        bail!("terminal activation phases require an atomic result transition");
    }
    let connection = open_database(data_dir, false)?;
    let updated = connection.execute(
        "UPDATE xray_activation_journal
         SET phase = ?1, updated_at = ?2, error_code = ?3
         WHERE revision = ?4
           AND phase NOT IN ('applied', 'rolledBack', 'rejected', 'recoveryRequired')",
        params![
            phase.as_str(),
            unix_timestamp()?,
            error_code.map(ErrorCode::as_str),
            revision.get(),
        ],
    )?;
    if updated != 1 {
        bail!("Xray activation journal transition did not update one row");
    }
    Ok(())
}

fn finalize_applied(data_dir: &Path, candidate: &ValidatedXrayCandidate) -> Result<()> {
    let now = unix_timestamp()?;
    let timestamp = timestamp_from_unix(now)?;
    let result = RevisionResult {
        state: RevisionResultState::Applied,
        config_digest: Some(candidate.config_digest.clone()),
        started_at: journal_started_timestamp(data_dir, candidate.revision)?,
        completed_at: timestamp,
        error_code: None,
        rollback_revision: None,
    };
    let mut connection = open_database(data_dir, false)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    insert_revision_result(&transaction, candidate.revision, &result)?;
    let active_updated = transaction.execute(
        "UPDATE xray_active_state
         SET applied_revision = ?1, config_digest = ?2, binary_digest = ?3,
             generation = generation + 1, restart_count = 0,
             applied_at = ?4, updated_at = ?4
         WHERE singleton = 1",
        params![
            candidate.revision.get(),
            candidate.config_digest.as_str(),
            candidate.binary_digest.to_string(),
            now,
        ],
    )?;
    if active_updated != 1 {
        bail!("Xray active state is missing");
    }
    finish_journal(
        &transaction,
        candidate.revision,
        JournalPhase::Applied,
        None,
        now,
    )?;
    transaction.commit()?;
    Ok(())
}

fn finalize_rolled_back(
    data_dir: &Path,
    journal: &ActivationJournal,
    previous: &ValidatedXrayCandidate,
    error_code: &ErrorCode,
) -> Result<()> {
    let now = unix_timestamp()?;
    let result = RevisionResult {
        state: RevisionResultState::RolledBack,
        config_digest: Some(previous.config_digest.clone()),
        started_at: timestamp_from_unix(journal.started_at)?,
        completed_at: timestamp_from_unix(now)?,
        error_code: Some(error_code.clone()),
        rollback_revision: Some(previous.revision),
    };
    let mut connection = open_database(data_dir, false)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    insert_revision_result(&transaction, journal.revision, &result)?;
    finish_journal(
        &transaction,
        journal.revision,
        JournalPhase::RolledBack,
        Some(error_code),
        now,
    )?;
    transaction.commit()?;
    Ok(())
}

fn finalize_rejected(
    data_dir: &Path,
    journal: &ActivationJournal,
    error_code: &ErrorCode,
) -> Result<()> {
    let now = unix_timestamp()?;
    let result = RevisionResult {
        state: RevisionResultState::Rejected,
        config_digest: None,
        started_at: timestamp_from_unix(journal.started_at)?,
        completed_at: timestamp_from_unix(now)?,
        error_code: Some(error_code.clone()),
        rollback_revision: None,
    };
    let mut connection = open_database(data_dir, false)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    insert_revision_result(&transaction, journal.revision, &result)?;
    finish_journal(
        &transaction,
        journal.revision,
        JournalPhase::Rejected,
        Some(error_code),
        now,
    )?;
    transaction.commit()?;
    Ok(())
}

fn mark_recovery_required(
    data_dir: &Path,
    revision: Revision,
    error_code: &ErrorCode,
) -> Result<()> {
    let mut connection = open_database(data_dir, false)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    finish_journal(
        &transaction,
        revision,
        JournalPhase::RecoveryRequired,
        Some(error_code),
        unix_timestamp()?,
    )?;
    transaction.commit()?;
    Ok(())
}

fn finish_journal(
    connection: &Connection,
    revision: Revision,
    phase: JournalPhase,
    error_code: Option<&ErrorCode>,
    completed_at: i64,
) -> Result<()> {
    if !phase.is_terminal() {
        bail!("nonterminal activation phase cannot finish a journal");
    }
    let updated = connection.execute(
        "UPDATE xray_activation_journal
         SET phase = ?1, updated_at = ?2, completed_at = ?2, error_code = ?3
         WHERE revision = ?4
           AND phase NOT IN ('applied', 'rolledBack', 'rejected', 'recoveryRequired')",
        params![
            phase.as_str(),
            completed_at,
            error_code.map(ErrorCode::as_str),
            revision.get(),
        ],
    )?;
    if updated != 1 {
        bail!("Xray activation journal completion did not update one row");
    }
    Ok(())
}

fn journal_started_timestamp(data_dir: &Path, revision: Revision) -> Result<Timestamp> {
    let connection = open_database(data_dir, false)?;
    let started_at: i64 = connection.query_row(
        "SELECT started_at FROM xray_activation_journal WHERE revision = ?1",
        [revision.get()],
        |row| row.get(0),
    )?;
    timestamp_from_unix(started_at)
}

fn record_active_restart(data_dir: &Path, revision: Revision) -> Result<()> {
    let connection = open_database(data_dir, false)?;
    let updated = connection.execute(
        "UPDATE xray_active_state
         SET generation = generation + 1, restart_count = restart_count + 1, updated_at = ?1
         WHERE singleton = 1 AND applied_revision = ?2",
        params![unix_timestamp()?, revision.get()],
    )?;
    if updated != 1 {
        bail!("Xray active restart raced with an active-state change");
    }
    Ok(())
}

fn timestamp_from_unix(value: i64) -> Result<Timestamp> {
    Ok(Timestamp::from_datetime(
        OffsetDateTime::from_unix_timestamp(value)?,
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        begin_activation, ActivationOptions, AdmissionGate, AdmissionOptions, JournalPhase,
        XraySupervisor, MAX_ACTIVATION_ATTEMPTS_WITHOUT_PREDECESSOR,
    };
    use crate::test_support::{
        bind_unique_loopback, bind_unique_wildcard, lock_network_tests, unique_unused_port,
    };
    use crate::xray::validate_desired_state;
    use crate::{configure_xray, initialize, open_database, unix_timestamp};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use control_protocol::crypto::{Ed25519Signature, Sha256Digest};
    use control_protocol::desired::desired_state_transcript;
    use control_protocol::error::ErrorCode;
    use control_protocol::id::{
        ControllerInstanceId, NetworkId, NodeId, Revision, SigningKeyId, Timestamp,
    };
    use control_protocol::node::{
        DesiredStateDocument, DesiredXrayState, NodeRuntimeState, RevisionResult,
        RevisionResultState, SignedDesiredState,
    };
    use rusqlite::{params, Connection, TransactionBehavior};
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use time::OffsetDateTime;
    use tokio::net::{TcpListener, TcpStream};

    #[derive(Debug, Clone, Copy)]
    enum FakeMode {
        Valid,
        FailRevisionTwo,
        FailEveryManagedStart,
    }

    struct FakeXray {
        _directory: tempfile::TempDir,
        path: PathBuf,
        digest: String,
    }

    impl FakeXray {
        fn new(mode: FakeMode) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("xray");
            let managed_behavior = match mode {
                FakeMode::Valid => String::new(),
                FakeMode::FailRevisionTwo => {
                    "case \"$3\" in *revision-2.json) exit 72 ;; esac\n".to_string()
                }
                FakeMode::FailEveryManagedStart => "exit 73\n".to_string(),
            };
            let script = format!(
                "#!/bin/sh\n\
                 if [ \"$#\" -eq 1 ] && [ \"$1\" = \"version\" ]; then\n\
                   printf 'Xray 25.7.1\\n'\n\
                   exit 0\n\
                 fi\n\
                 if [ \"$#\" -eq 4 ] && [ \"$1\" = \"run\" ] && [ \"$2\" = \"-test\" ] && [ \"$3\" = \"-config\" ]; then\n\
                   exit 0\n\
                 fi\n\
                 if [ \"$#\" -eq 3 ] && [ \"$1\" = \"run\" ] && [ \"$2\" = \"-config\" ]; then\n\
                   {managed_behavior}\
                   exec /bin/sleep 30\n\
                 fi\n\
                 exit 64\n"
            );
            fs::write(&path, script.as_bytes()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                _directory: directory,
                path,
                digest: sha256_hex(script.as_bytes()),
            }
        }
    }

    struct Fixture {
        _network_test_lock: tokio::sync::MutexGuard<'static, ()>,
        _directory: tempfile::TempDir,
        _fake: FakeXray,
        listener: Option<TcpListener>,
        data_dir: PathBuf,
        listen_port: u16,
        public_port: u16,
    }

    impl Fixture {
        async fn new(mode: FakeMode) -> Self {
            let network_test_lock = lock_network_tests().await;
            let directory = tempfile::tempdir().unwrap();
            let data_dir = directory.path().join("state");
            initialize(&data_dir, "https://controller.example").unwrap();
            let fake = FakeXray::new(mode);
            configure_xray(&data_dir, &fake.path, &fake.digest, false)
                .await
                .unwrap();
            let listener = bind_unique_loopback().await;
            let listen_port = listener.local_addr().unwrap().port();
            let public_port = unique_unused_port().await;
            assert_ne!(listen_port, public_port);
            Self {
                _network_test_lock: network_test_lock,
                _directory: directory,
                _fake: fake,
                listener: Some(listener),
                data_dir,
                listen_port,
                public_port,
            }
        }

        async fn validate_revision(&self, revision: i64) {
            self.validate_revision_at(revision, self.public_port).await;
        }

        async fn validate_revision_at(&self, revision: i64, public_port: u16) {
            let envelope = desired_state(revision, self.listen_port, Some(public_port));
            self.validate_envelope(revision, &envelope).await;
        }

        async fn validate_legacy_revision(&self, revision: i64) {
            let envelope = desired_state(revision, self.listen_port, None);
            self.validate_envelope(revision, &envelope).await;
        }

        async fn validate_envelope(&self, revision: i64, envelope: &SignedDesiredState) {
            persist_received(&self.data_dir, envelope);
            let mut connection = open_database(&self.data_dir, false).unwrap();
            validate_desired_state(&self.data_dir, &mut connection, envelope)
                .await
                .unwrap();
            let now = unix_timestamp().unwrap();
            connection
                .execute(
                    "UPDATE local_revision_results SET reported_at = ?1
                     WHERE revision = ?2 AND state IN ('received', 'validated')",
                    params![now, revision],
                )
                .unwrap();
        }

        fn close_loopback_backend(&mut self) {
            self.listener.take();
        }
    }

    fn fast_options() -> ActivationOptions {
        // Keep process/socket checks above scheduler jitter when the full test
        // binary runs many child-process fixtures in parallel on macOS CI.
        ActivationOptions {
            startup_timeout: Duration::from_secs(1),
            stabilization_duration: Duration::from_millis(100),
            probe_interval: Duration::from_millis(25),
            admission: AdmissionOptions {
                max_connections: 4,
                bandwidth_limit_bps: None,
                connect_timeout: Duration::from_millis(250),
                canary_timeout: Duration::from_secs(1),
                probe_interval: Duration::from_millis(25),
                accept_error_backoff: Duration::from_millis(10),
            },
        }
    }

    fn desired_state(
        revision: i64,
        listen_port: u16,
        public_port: Option<u16>,
    ) -> SignedDesiredState {
        let document = DesiredStateDocument {
            schema_version: if public_port.is_some() { 2 } else { 1 },
            network_id: "11111111-1111-4111-8111-111111111111"
                .parse::<NetworkId>()
                .unwrap(),
            node_id: "22222222-2222-4222-8222-222222222222"
                .parse::<NodeId>()
                .unwrap(),
            revision: Revision::new(revision).unwrap(),
            created_at: Timestamp::from_datetime(OffsetDateTime::now_utc()),
            min_agent_version: "0.1.0".to_string(),
            users: Vec::new(),
            xray: DesiredXrayState {
                listen_port,
                public_port,
                server_names: vec!["www.microsoft.com".to_string()],
                target: "www.microsoft.com:443".to_string(),
            },
            signing_key_id: "44444444-4444-4444-8444-444444444444"
                .parse::<SigningKeyId>()
                .unwrap(),
            controller_instance_id: "33333333-3333-4333-8333-333333333333"
                .parse::<ControllerInstanceId>()
                .unwrap(),
        };
        let signature: Ed25519Signature = URL_SAFE_NO_PAD.encode([0_u8; 64]).parse().unwrap();
        SignedDesiredState {
            document,
            signature,
        }
    }

    fn persist_received(data_dir: &Path, envelope: &SignedDesiredState) {
        let canonical = serde_json::to_string(envelope).unwrap();
        let signed_transcript = desired_state_transcript(&envelope.document).unwrap();
        let envelope_digest = digest(canonical.as_bytes());
        let now = unix_timestamp().unwrap();
        let timestamp = Timestamp::from_datetime(OffsetDateTime::from_unix_timestamp(now).unwrap());
        let result = RevisionResult {
            state: RevisionResultState::Received,
            config_digest: None,
            started_at: timestamp,
            completed_at: timestamp,
            error_code: None,
            rollback_revision: None,
        };
        let report_json = serde_json::to_string(&result).unwrap();
        let report_digest = digest(report_json.as_bytes());
        let mut connection = open_database(data_dir, false).unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "INSERT INTO desired_state_artifacts(
                    revision, network_id, node_id, controller_instance_id, signing_key_id,
                    envelope_json, envelope_digest, transcript_digest, received_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    envelope.document.revision.get(),
                    envelope.document.network_id.to_string(),
                    envelope.document.node_id.to_string(),
                    envelope.document.controller_instance_id.to_string(),
                    envelope.document.signing_key_id.to_string(),
                    canonical,
                    envelope_digest.as_str(),
                    digest(&signed_transcript).as_str(),
                    now,
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO local_revision_results(
                    revision, state, report_json, report_digest, reported_at, created_at
                 ) VALUES (?1, 'received', ?2, ?3, NULL, ?4)",
                params![
                    envelope.document.revision.get(),
                    report_json,
                    report_digest.as_str(),
                    now,
                ],
            )
            .unwrap();
        transaction
            .execute(
                "UPDATE control_sync_state SET desired_revision_cursor = ?1 WHERE singleton = 1",
                [envelope.document.revision.get()],
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    fn digest(value: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(value).into())
    }

    fn sha256_hex(value: &[u8]) -> String {
        Sha256::digest(value)
            .iter()
            .fold(String::with_capacity(64), |mut output, byte| {
                write!(output, "{byte:02x}").unwrap();
                output
            })
    }

    fn stored_active_revision(data_dir: &Path) -> Option<i64> {
        Connection::open(data_dir.join("node-host.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT applied_revision FROM xray_active_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn stored_journal(data_dir: &Path, revision: i64) -> (String, i64) {
        Connection::open(data_dir.join("node-host.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT phase, attempt_count FROM xray_activation_journal WHERE revision = ?1",
                [revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    fn stored_result(data_dir: &Path, revision: i64, state: &str) -> RevisionResult {
        let report_json: String = Connection::open(data_dir.join("node-host.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT report_json FROM local_revision_results
                 WHERE revision = ?1 AND state = ?2",
                params![revision, state],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_str(&report_json).unwrap()
    }

    #[tokio::test]
    async fn validated_revision_becomes_active_only_after_health() {
        let fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_revision(1).await;
        let mut supervisor = XraySupervisor::new(fast_options()).unwrap();

        supervisor.recover(&fixture.data_dir).await.unwrap();
        supervisor.reconcile(&fixture.data_dir).await.unwrap();

        assert_eq!(
            supervisor.observe_runtime_state().unwrap(),
            NodeRuntimeState::Serving
        );
        assert_eq!(stored_active_revision(&fixture.data_dir), Some(1));
        assert_eq!(
            stored_journal(&fixture.data_dir, 1),
            ("applied".to_string(), 1)
        );
        let result = stored_result(&fixture.data_dir, 1, "applied");
        assert_eq!(result.state, RevisionResultState::Applied);
        assert!(result.config_digest.is_some());
        assert!(supervisor
            .admission
            .as_ref()
            .is_some_and(AdmissionGate::is_running));
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn failed_candidate_restores_the_previous_applied_revision() {
        let fixture = Fixture::new(FakeMode::FailRevisionTwo).await;
        fixture.validate_revision(1).await;
        let mut supervisor = XraySupervisor::new(fast_options()).unwrap();
        supervisor.recover(&fixture.data_dir).await.unwrap();
        supervisor.reconcile(&fixture.data_dir).await.unwrap();
        fixture.validate_revision(2).await;

        supervisor.reconcile(&fixture.data_dir).await.unwrap();

        assert_eq!(
            supervisor.observe_runtime_state().unwrap(),
            NodeRuntimeState::Serving
        );
        assert_eq!(stored_active_revision(&fixture.data_dir), Some(1));
        assert_eq!(stored_journal(&fixture.data_dir, 2).0, "rolledBack");
        let result = stored_result(&fixture.data_dir, 2, "rolledBack");
        assert_eq!(result.state, RevisionResultState::RolledBack);
        assert_eq!(result.rollback_revision.unwrap().get(), 1);
        assert!(matches!(
            result.error_code,
            Some(ErrorCode::XrayStartFailed | ErrorCode::XrayUnhealthy)
        ));
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn occupied_candidate_admission_port_restores_the_previous_gate() {
        let fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_revision(1).await;
        let mut supervisor = XraySupervisor::new(fast_options()).unwrap();
        supervisor.recover(&fixture.data_dir).await.unwrap();
        supervisor.reconcile(&fixture.data_dir).await.unwrap();
        let occupied = bind_unique_wildcard().await;
        let occupied_port = occupied.local_addr().unwrap().port();
        fixture.validate_revision_at(2, occupied_port).await;

        supervisor.reconcile(&fixture.data_dir).await.unwrap();

        assert_eq!(
            supervisor.observe_runtime_state().unwrap(),
            NodeRuntimeState::Serving
        );
        assert_eq!(stored_active_revision(&fixture.data_dir), Some(1));
        assert_eq!(stored_journal(&fixture.data_dir, 2).0, "rolledBack");
        assert_eq!(
            stored_result(&fixture.data_dir, 2, "rolledBack").error_code,
            Some(ErrorCode::AdmissionBindFailed)
        );
        assert!(TcpStream::connect(("127.0.0.1", fixture.public_port))
            .await
            .is_ok());
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn durable_commit_failure_immediately_restores_the_previous_runtime() {
        let fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_revision(1).await;
        let mut supervisor = XraySupervisor::new(fast_options()).unwrap();
        supervisor.recover(&fixture.data_dir).await.unwrap();
        supervisor.reconcile(&fixture.data_dir).await.unwrap();
        fixture.validate_revision(2).await;
        let connection = Connection::open(fixture.data_dir.join("node-host.sqlite3")).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER inject_revision_two_commit_failure
                 BEFORE UPDATE OF applied_revision ON xray_active_state
                 WHEN NEW.applied_revision = 2
                 BEGIN
                    SELECT RAISE(ABORT, 'injected active-state failure');
                 END;",
            )
            .unwrap();

        let error = supervisor.reconcile(&fixture.data_dir).await.unwrap_err();

        assert!(format!("{error:#}").contains("previous runtime restored"));
        assert_eq!(stored_active_revision(&fixture.data_dir), Some(1));
        assert_eq!(stored_journal(&fixture.data_dir, 2).0, "stabilizing");
        assert_eq!(
            supervisor.observe_runtime_state().unwrap(),
            NodeRuntimeState::Serving
        );

        connection
            .execute_batch("DROP TRIGGER inject_revision_two_commit_failure;")
            .unwrap();
        drop(connection);
        supervisor.reconcile(&fixture.data_dir).await.unwrap();
        assert_eq!(stored_active_revision(&fixture.data_dir), Some(2));
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn runtime_backend_failure_stops_the_public_gate_and_reports_idle() {
        let mut fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_revision(1).await;
        let mut supervisor = XraySupervisor::new(fast_options()).unwrap();
        supervisor.recover(&fixture.data_dir).await.unwrap();
        supervisor.reconcile(&fixture.data_dir).await.unwrap();
        fixture.close_loopback_backend();
        supervisor.last_admission_probe = None;

        let error = supervisor.poll(&fixture.data_dir).await.unwrap_err();

        assert!(format!("{error:#}").contains("runtime health check"));
        assert_eq!(
            supervisor.observe_runtime_state().unwrap(),
            NodeRuntimeState::Idle
        );
        assert!(supervisor.child.is_none());
        assert!(supervisor.admission.is_none());
    }

    #[tokio::test]
    async fn legacy_revision_runs_loopback_only_and_reports_degraded() {
        let fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_legacy_revision(1).await;
        let mut supervisor = XraySupervisor::new(fast_options()).unwrap();
        supervisor.recover(&fixture.data_dir).await.unwrap();
        supervisor.reconcile(&fixture.data_dir).await.unwrap();

        assert_eq!(
            supervisor.observe_runtime_state().unwrap(),
            NodeRuntimeState::Degraded
        );
        assert!(supervisor.admission.is_none());
        supervisor.poll(&fixture.data_dir).await.unwrap();
        assert_eq!(supervisor.running_revision.unwrap().get(), 1);
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn first_revision_is_rejected_after_three_failed_starts() {
        let fixture = Fixture::new(FakeMode::FailEveryManagedStart).await;
        fixture.validate_revision(1).await;
        let mut supervisor = XraySupervisor::new(fast_options()).unwrap();
        supervisor.recover(&fixture.data_dir).await.unwrap();

        for expected_attempt in 1..MAX_ACTIVATION_ATTEMPTS_WITHOUT_PREDECESSOR {
            assert!(supervisor.reconcile(&fixture.data_dir).await.is_err());
            assert_eq!(
                stored_journal(&fixture.data_dir, 1),
                ("retryPending".to_string(), expected_attempt)
            );
        }
        supervisor.reconcile(&fixture.data_dir).await.unwrap();

        assert_eq!(
            supervisor.observe_runtime_state().unwrap(),
            NodeRuntimeState::Idle
        );
        assert_eq!(stored_active_revision(&fixture.data_dir), None);
        assert_eq!(
            stored_journal(&fixture.data_dir, 1),
            (
                "rejected".to_string(),
                MAX_ACTIVATION_ATTEMPTS_WITHOUT_PREDECESSOR
            )
        );
        let result = stored_result(&fixture.data_dir, 1, "rejected");
        assert!(matches!(
            result.error_code,
            Some(ErrorCode::XrayStartFailed | ErrorCode::XrayUnhealthy)
        ));
    }

    #[tokio::test]
    async fn interrupted_switch_conservatively_restores_its_predecessor() {
        let fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_revision(1).await;
        let mut first = XraySupervisor::new(fast_options()).unwrap();
        first.recover(&fixture.data_dir).await.unwrap();
        first.reconcile(&fixture.data_dir).await.unwrap();
        fixture.validate_revision(2).await;
        begin_activation(
            &fixture.data_dir,
            Revision::new(2).unwrap(),
            Some(Revision::new(1).unwrap()),
        )
        .unwrap();
        first.shutdown().await.unwrap();
        drop(first);

        let mut recovered = XraySupervisor::new(fast_options()).unwrap();
        recovered.recover(&fixture.data_dir).await.unwrap();

        assert_eq!(
            recovered.observe_runtime_state().unwrap(),
            NodeRuntimeState::Serving
        );
        assert_eq!(stored_active_revision(&fixture.data_dir), Some(1));
        assert_eq!(stored_journal(&fixture.data_dir, 2).0, "rolledBack");
        assert_eq!(
            stored_result(&fixture.data_dir, 2, "rolledBack")
                .rollback_revision
                .unwrap()
                .get(),
            1
        );
        recovered.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn interrupted_recovery_failure_becomes_recovery_required() {
        let fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_revision(1).await;
        let mut first = XraySupervisor::new(fast_options()).unwrap();
        first.recover(&fixture.data_dir).await.unwrap();
        first.reconcile(&fixture.data_dir).await.unwrap();
        fixture.validate_revision(2).await;
        begin_activation(
            &fixture.data_dir,
            Revision::new(2).unwrap(),
            Some(Revision::new(1).unwrap()),
        )
        .unwrap();
        first.shutdown().await.unwrap();
        drop(first);
        let _occupied = TcpListener::bind(("0.0.0.0", fixture.public_port))
            .await
            .unwrap();

        let mut recovered = XraySupervisor::new(fast_options()).unwrap();
        let error = recovered.recover(&fixture.data_dir).await.unwrap_err();

        assert!(format!("{error:#}").contains("could not be restored during recovery"));
        assert_eq!(stored_journal(&fixture.data_dir, 2).0, "recoveryRequired");
        assert_eq!(stored_active_revision(&fixture.data_dir), Some(1));
        assert_eq!(
            recovered.observe_runtime_state().unwrap(),
            NodeRuntimeState::Idle
        );
    }

    #[tokio::test]
    async fn cancelled_activation_keeps_the_child_owned_for_bounded_reaping() {
        let fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_revision(1).await;
        let mut supervisor = XraySupervisor::new(ActivationOptions {
            stabilization_duration: Duration::from_secs(2),
            ..fast_options()
        })
        .unwrap();
        supervisor.recover(&fixture.data_dir).await.unwrap();

        {
            let activation = supervisor.reconcile(&fixture.data_dir);
            tokio::pin!(activation);
            tokio::select! {
                result = &mut activation => panic!("activation completed before cancellation: {result:?}"),
                () = tokio::time::sleep(Duration::from_millis(200)) => {}
            }
        }

        assert!(supervisor.child.is_some());
        assert!(supervisor.running_revision.is_none());
        assert_eq!(stored_journal(&fixture.data_dir, 1).0, "stabilizing");
        supervisor.shutdown().await.unwrap();
        assert!(supervisor.child.is_none());
    }

    #[tokio::test]
    async fn runtime_observation_reaps_an_exited_child_and_reports_idle() {
        let fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_revision(1).await;
        let mut supervisor = XraySupervisor::new(fast_options()).unwrap();
        supervisor.recover(&fixture.data_dir).await.unwrap();
        supervisor.reconcile(&fixture.data_dir).await.unwrap();
        supervisor
            .child
            .as_mut()
            .unwrap()
            .kill_and_wait()
            .await
            .unwrap();

        assert_eq!(
            supervisor.observe_runtime_state().unwrap(),
            NodeRuntimeState::Idle
        );
        assert!(supervisor.child.is_none());
        assert!(supervisor.running_revision.is_none());
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn runtime_replacement_cannot_invalidate_a_validated_candidate() {
        let fixture = Fixture::new(FakeMode::Valid).await;
        fixture.validate_revision(1).await;
        let replacement = FakeXray::new(FakeMode::Valid);

        let error = configure_xray(
            &fixture.data_dir,
            &replacement.path,
            &replacement.digest,
            true,
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("cannot be replaced while validated revisions are retained"));
    }

    #[test]
    fn activation_options_are_bounded() {
        assert!(ActivationOptions {
            startup_timeout: Duration::ZERO,
            ..fast_options()
        }
        .validate()
        .is_err());
        assert!(JournalPhase::Applied.is_terminal());
        assert!(!JournalPhase::Activating.is_terminal());
    }
}
