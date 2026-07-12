use std::{collections::BTreeMap, fmt, net::SocketAddrV4};

use serde::Deserialize;
use thiserror::Error;
use tokio::process::Command;

use crate::process::{configure_command, non_zero_error, revalidate_binary, run_bounded};
use crate::{ExecutionLimits, RuntimeError, UserEmail, VerifiedXrayBinary};

const STATS_QUERY_OPERATION: &str = "Stats API query";
const MAX_STATS: usize = 20_000;

/// One complete cumulative Xray counter pair for a configured user label.
#[derive(Clone, PartialEq, Eq)]
pub struct UserTrafficCounter {
    email: UserEmail,
    uplink: i64,
    downlink: i64,
}

impl UserTrafficCounter {
    /// Returns the Xray user label associated with this counter.
    #[must_use]
    pub fn email(&self) -> &UserEmail {
        &self.email
    }

    /// Returns cumulative uploaded bytes since the current Xray process started.
    #[must_use]
    pub const fn uplink(&self) -> i64 {
        self.uplink
    }

    /// Returns cumulative downloaded bytes since the current Xray process started.
    #[must_use]
    pub const fn downlink(&self) -> i64 {
        self.downlink
    }
}

impl fmt::Debug for UserTrafficCounter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserTrafficCounter")
            .field("email", &self.email)
            .field("uplink", &self.uplink)
            .field("downlink", &self.downlink)
            .finish()
    }
}

/// Queries cumulative per-user counters from a loopback Xray Stats API.
///
/// The explicit, previously verified Xray binary is revalidated and invoked
/// directly with fixed arguments. No shell or `PATH` lookup is involved, both
/// output streams are bounded, and the outer timeout is authoritative.
///
/// # Errors
///
/// Returns a redacted error for binary/process failures or malformed, excessive,
/// duplicate, negative, or incomplete Stats API output.
pub async fn query_user_traffic(
    binary: &VerifiedXrayBinary,
    endpoint: SocketAddrV4,
    limits: ExecutionLimits,
) -> Result<Vec<UserTrafficCounter>, StatsQueryError> {
    if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
        return Err(StatsQueryError::NonLoopbackEndpoint);
    }
    revalidate_binary(binary).await?;

    let internal_timeout_seconds = limits.timeout().as_secs().max(1).to_string();
    let mut command = Command::new(binary.path());
    command
        .arg("api")
        .arg("statsquery")
        .arg("--server")
        .arg(endpoint.to_string())
        .arg("-timeout")
        .arg(internal_timeout_seconds)
        .arg("-pattern")
        .arg("user>>>")
        .arg("-reset=false");
    configure_command(&mut command, binary.path().parent());
    let output = run_bounded(command, STATS_QUERY_OPERATION, limits).await?;
    if !output.status.success() {
        return Err(StatsQueryError::Runtime(non_zero_error(
            STATS_QUERY_OPERATION,
            &output,
        )));
    }
    parse_stats(&output.stdout)
}

/// Stable, output-redacting failures from one Stats API query.
#[derive(Debug, Error)]
pub enum StatsQueryError {
    /// The caller attempted to contact a non-loopback API.
    #[error("Xray Stats API endpoint must be IPv4 loopback")]
    NonLoopbackEndpoint,
    /// The verified process boundary rejected or failed the query.
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    /// The API response was not a supported bounded JSON document.
    #[error("Xray Stats API response was invalid")]
    InvalidOutput,
    /// The API returned more entries than this collector accepts.
    #[error("Xray Stats API response contained too many counters")]
    TooManyCounters,
    /// The API returned a malformed or duplicate per-user counter.
    #[error("Xray Stats API response contained inconsistent user counters")]
    InconsistentCounters,
}

#[derive(Deserialize)]
struct StatsResponse {
    #[serde(default)]
    stat: Vec<RawStat>,
}

#[derive(Deserialize)]
struct RawStat {
    name: String,
    value: RawValue,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawValue {
    Number(i64),
    String(String),
}

#[derive(Default)]
struct CounterPair {
    uplink: Option<i64>,
    downlink: Option<i64>,
}

fn parse_stats(bytes: &[u8]) -> Result<Vec<UserTrafficCounter>, StatsQueryError> {
    let response: StatsResponse =
        serde_json::from_slice(bytes).map_err(|_| StatsQueryError::InvalidOutput)?;
    if response.stat.len() > MAX_STATS {
        return Err(StatsQueryError::TooManyCounters);
    }

    let mut counters = BTreeMap::<UserEmail, CounterPair>::new();
    for stat in response.stat {
        let (email, direction) = parse_counter_name(&stat.name)?;
        let value = match stat.value {
            RawValue::Number(value) => value,
            RawValue::String(value) => value
                .parse::<i64>()
                .map_err(|_| StatsQueryError::InvalidOutput)?,
        };
        if value < 0 {
            return Err(StatsQueryError::InconsistentCounters);
        }
        let pair = counters.entry(email).or_default();
        let slot = match direction {
            "uplink" => &mut pair.uplink,
            "downlink" => &mut pair.downlink,
            _ => return Err(StatsQueryError::InconsistentCounters),
        };
        if slot.replace(value).is_some() {
            return Err(StatsQueryError::InconsistentCounters);
        }
    }

    counters
        .into_iter()
        .map(|(email, pair)| {
            Ok(UserTrafficCounter {
                email,
                uplink: pair.uplink.unwrap_or(0),
                downlink: pair.downlink.unwrap_or(0),
            })
        })
        .collect()
}

fn parse_counter_name(name: &str) -> Result<(UserEmail, &str), StatsQueryError> {
    if name.len() > 256 {
        return Err(StatsQueryError::InconsistentCounters);
    }
    let mut parts = name.split(">>>");
    let (Some("user"), Some(email), Some("traffic"), Some(direction), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(StatsQueryError::InconsistentCounters);
    };
    let email = UserEmail::parse(email).map_err(|_| StatsQueryError::InconsistentCounters)?;
    Ok((email, direction))
}

#[cfg(test)]
mod tests {
    use super::{parse_stats, StatsQueryError};

    #[test]
    fn parses_string_and_numeric_counters_into_complete_pairs() {
        let counters = parse_stats(
            br#"{"stat":[
                {"name":"user>>>user-a@example.com>>>traffic>>>uplink","value":"12"},
                {"name":"user>>>user-a@example.com>>>traffic>>>downlink","value":34},
                {"name":"user>>>user-b@example.com>>>traffic>>>uplink","value":"5"}
            ]}"#,
        )
        .unwrap();

        assert_eq!(counters.len(), 2);
        assert_eq!(counters[0].email().as_str(), "user-a@example.com");
        assert_eq!((counters[0].uplink(), counters[0].downlink()), (12, 34));
        assert_eq!((counters[1].uplink(), counters[1].downlink()), (5, 0));
    }

    #[test]
    fn rejects_duplicate_negative_and_non_user_counters() {
        for body in [
            br#"{"stat":[{"name":"user>>>a@example.com>>>traffic>>>uplink","value":1},{"name":"user>>>a@example.com>>>traffic>>>uplink","value":2}]}"#.as_slice(),
            br#"{"stat":[{"name":"user>>>a@example.com>>>traffic>>>uplink","value":-1}]}"#.as_slice(),
            br#"{"stat":[{"name":"inbound>>>api>>>traffic>>>uplink","value":1}]}"#.as_slice(),
        ] {
            assert!(matches!(
                parse_stats(body),
                Err(StatsQueryError::InconsistentCounters)
            ));
        }
    }
}
