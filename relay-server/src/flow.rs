use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::error::{ErrorCode, RelayError, Result};

#[derive(Debug)]
pub struct Credit {
    available: Mutex<u64>,
    notify: Notify,
}

impl Credit {
    pub fn new(initial: u32) -> Self {
        Self {
            available: Mutex::new(u64::from(initial)),
            notify: Notify::new(),
        }
    }

    pub fn add(&self, amount: u32) -> Result<()> {
        if amount == 0 {
            return Err(RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "flow-control update cannot be zero",
            ));
        }
        let mut available = self
            .available
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *available = available.checked_add(u64::from(amount)).ok_or_else(|| {
            RelayError::stable(ErrorCode::ProtocolInvalid, "flow-control credit overflow")
        })?;
        self.notify.notify_waiters();
        Ok(())
    }

    pub async fn consume(&self, amount: usize, cancel: &CancellationToken) -> Result<()> {
        let amount = u64::try_from(amount).map_err(|_| {
            RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "flow-control amount is unsupported",
            )
        })?;
        loop {
            let notified = self.notify.notified();
            {
                let mut available = self
                    .available
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if *available >= amount {
                    *available -= amount;
                    return Ok(());
                }
            }
            tokio::select! {
                () = cancel.cancelled() => {
                    return Err(RelayError::stable(ErrorCode::TunnelLost, "stream was cancelled"));
                }
                () = notified => {}
            }
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    bytes_per_second: u64,
    state: Mutex<RateState>,
}

#[derive(Debug)]
struct RateState {
    available: u64,
    updated_at: Instant,
}

impl RateLimiter {
    #[must_use]
    pub fn new(bytes_per_second: u64) -> Arc<Self> {
        Arc::new(Self {
            bytes_per_second,
            state: Mutex::new(RateState {
                available: bytes_per_second,
                updated_at: Instant::now(),
            }),
        })
    }

    pub async fn acquire(&self, bytes: usize, cancel: &CancellationToken) -> Result<()> {
        let requested = u64::try_from(bytes).map_err(|_| {
            RelayError::stable(ErrorCode::LimitReached, "rate-limit amount is unsupported")
        })?;
        loop {
            let wait = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let now = Instant::now();
                let elapsed_nanos = now.duration_since(state.updated_at).as_nanos();
                let replenished =
                    elapsed_nanos.saturating_mul(u128::from(self.bytes_per_second)) / 1_000_000_000;
                let replenished = u64::try_from(replenished).unwrap_or(u64::MAX);
                state.available = state
                    .available
                    .saturating_add(replenished)
                    .min(self.bytes_per_second);
                state.updated_at = now;
                if state.available >= requested {
                    state.available -= requested;
                    None
                } else {
                    let missing = requested - state.available;
                    state.available = 0;
                    let wait_nanos = u128::from(missing)
                        .saturating_mul(1_000_000_000)
                        .div_ceil(u128::from(self.bytes_per_second));
                    Some(Duration::from_nanos(
                        u64::try_from(wait_nanos).unwrap_or(u64::MAX),
                    ))
                }
            };
            let Some(wait) = wait else {
                return Ok(());
            };
            tokio::select! {
                () = cancel.cancelled() => {
                    return Err(RelayError::stable(ErrorCode::RouteRevoked, "route was revoked"));
                }
                () = tokio::time::sleep(wait) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn credit_blocks_without_buffer_growth_until_window_update() {
        let credit = Arc::new(Credit::new(4));
        let cancel = CancellationToken::new();
        let task_credit = credit.clone();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move { task_credit.consume(5, &task_cancel).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished());
        credit.add(1).unwrap();
        task.await.unwrap().unwrap();
    }
}
