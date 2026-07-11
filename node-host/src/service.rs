use crate::{status_locked, sync::sync_once_locked, DataDirLock, EnrollmentState};
use anyhow::{bail, Result};
use rand_core::{OsRng, RngCore as _};
use std::future::Future;
use std::path::Path;
use std::time::Duration;

const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
const MAX_CONFIGURED_DELAY: Duration = Duration::from_secs(24 * 60 * 60);

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
    if status_locked(data_dir)?.enrollment_state != EnrollmentState::Enrolled {
        bail!("node host must be enrolled before starting its sync service");
    }

    tokio::pin!(shutdown);
    let mut backoff = options.initial_backoff;
    loop {
        let result = tokio::select! {
            shutdown_result = &mut shutdown => return shutdown_result,
            result = sync_once_locked(data_dir) => result,
        };
        let base_delay = match result {
            Ok(_) => {
                backoff = options.initial_backoff;
                options.success_interval
            }
            Err(error) => {
                tracing::warn!(error = %error, "node synchronization failed; retrying");
                let current = backoff;
                backoff = backoff.saturating_mul(2).min(options.max_backoff);
                current
            }
        };
        let delay = jitter(base_delay, OsRng.next_u64());
        tokio::select! {
            shutdown_result = &mut shutdown => return shutdown_result,
            () = tokio::time::sleep(delay) => {}
        }
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
