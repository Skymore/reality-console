use crate::{migrate, open_database, timestamp_from_unix, unix_timestamp};
use anyhow::{bail, Context as _, Result};
use control_protocol::id::{EndpointId, Revision, Timestamp};
use control_protocol::node::{EndpointCandidate, EndpointMode, EndpointSource};
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr as _;
use time::{OffsetDateTime, Weekday};

pub const PROVIDER_POLICY_SCHEMA_VERSION: u16 = 1;
const MAX_SCHEDULE_WINDOWS: usize = 64;
const MAX_CONCURRENT_SESSIONS: u16 = 4_096;
const MIN_MONTHLY_CAP_BYTES: u64 = 1024 * 1024;
const MAX_BANDWIDTH_LIMIT_BPS: u64 = 10_000_000_000;
const MIN_BANDWIDTH_LIMIT_BPS: u64 = 8_000;
const MIN_MANUAL_ENDPOINT_TTL_SECONDS: u32 = 60;
const MAX_MANUAL_ENDPOINT_TTL_SECONDS: u32 = 30 * 24 * 60 * 60;
const USAGE_COVERAGE: &str = "xrayObservedLowerBound";

/// Provider-owned hard limits. Schedule windows are UTC and use the start
/// weekday. `startMinute > endMinute` crosses midnight into the next UTC day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderPolicy {
    pub schema_version: u16,
    pub paused: bool,
    #[serde(default)]
    pub weekly_schedule: Vec<WeeklyScheduleWindow>,
    pub monthly_transfer_cap_bytes: Option<u64>,
    pub max_concurrent_sessions: u16,
    pub bandwidth_limit_bps: Option<u64>,
}

impl Default for ProviderPolicy {
    fn default() -> Self {
        Self {
            schema_version: PROVIDER_POLICY_SCHEMA_VERSION,
            paused: false,
            weekly_schedule: Vec::new(),
            monthly_transfer_cap_bytes: Some(100 * 1024 * 1024 * 1024),
            max_concurrent_sessions: 16,
            bandwidth_limit_bps: Some(20_000_000),
        }
    }
}

impl ProviderPolicy {
    /// Validates the closed schema and all locally enforceable bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, ambiguous schedule, or an
    /// unsafe transfer, session, or bandwidth bound.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != PROVIDER_POLICY_SCHEMA_VERSION {
            bail!("unsupported provider policy schema version");
        }
        if self.weekly_schedule.len() > MAX_SCHEDULE_WINDOWS {
            bail!("provider policy has too many weekly schedule windows");
        }
        for window in &self.weekly_schedule {
            window.validate()?;
        }
        if self
            .monthly_transfer_cap_bytes
            .is_some_and(|cap| !(MIN_MONTHLY_CAP_BYTES..=i64::MAX as u64).contains(&cap))
        {
            bail!("monthly transfer cap must be at least 1 MiB and fit local counters");
        }
        if self.max_concurrent_sessions == 0
            || self.max_concurrent_sessions > MAX_CONCURRENT_SESSIONS
        {
            bail!("maximum concurrent sessions must be between 1 and 4096");
        }
        if self.bandwidth_limit_bps.is_some_and(|limit| {
            !(MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&limit)
        }) {
            bail!("bandwidth limit must be between 8000 and 10000000000 bits per second");
        }
        Ok(())
    }

    fn schedule_allows(&self, now: OffsetDateTime) -> bool {
        self.weekly_schedule.is_empty()
            || self
                .weekly_schedule
                .iter()
                .any(|window| window.contains(now))
    }
}

/// One UTC weekly availability window. Weekdays are ISO 1 (Monday) through 7
/// (Sunday), and minute bounds are in 0..=1439. Equal bounds are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WeeklyScheduleWindow {
    pub weekday: u8,
    pub start_minute: u16,
    pub end_minute: u16,
}

impl WeeklyScheduleWindow {
    fn validate(self) -> Result<()> {
        if !(1..=7).contains(&self.weekday) {
            bail!("weekly schedule weekday must be between 1 and 7");
        }
        if self.start_minute > 1439 || self.end_minute > 1439 {
            bail!("weekly schedule minutes must be between 0 and 1439");
        }
        if self.start_minute == self.end_minute {
            bail!("weekly schedule window cannot have equal start and end minutes");
        }
        Ok(())
    }

    fn contains(self, now: OffsetDateTime) -> bool {
        let weekday = iso_weekday(now.weekday());
        let minute = u16::from(now.hour()) * 60 + u16::from(now.minute());
        if self.start_minute < self.end_minute {
            weekday == self.weekday && minute >= self.start_minute && minute < self.end_minute
        } else {
            (weekday == self.weekday && minute >= self.start_minute)
                || (weekday == next_weekday(self.weekday) && minute < self.end_minute)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAvailability {
    Available,
    ProviderPaused,
    OutsideSchedule,
    TransferCapReached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderMonthUsage {
    pub utc_month: String,
    pub observed_bytes: u64,
    pub cap_bytes: Option<u64>,
    pub remaining_bytes: Option<u64>,
    pub coverage: String,
    pub last_observed_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManualEndpointStatus {
    pub configured: bool,
    pub current: bool,
    pub applied_revision: Option<Revision>,
    pub expires_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderPolicyStatus {
    pub policy: ProviderPolicy,
    pub generation: u64,
    pub updated_at: Timestamp,
    pub availability: ProviderAvailability,
    pub month_usage: ProviderMonthUsage,
    pub manual_endpoint: ManualEndpointStatus,
}

impl ProviderPolicyStatus {
    pub(crate) fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        if self.generation == 0
            || self.month_usage.utc_month.len() != 7
            || self.month_usage.utc_month.as_bytes().get(4) != Some(&b'-')
            || self.month_usage.coverage != USAGE_COVERAGE
        {
            bail!("provider policy status metadata is invalid");
        }
        let expected_remaining = self
            .month_usage
            .cap_bytes
            .map(|cap| cap.saturating_sub(self.month_usage.observed_bytes));
        if self.month_usage.cap_bytes != self.policy.monthly_transfer_cap_bytes
            || self.month_usage.remaining_bytes != expected_remaining
            || (self.manual_endpoint.current && !self.manual_endpoint.configured)
            || (self.manual_endpoint.configured != self.manual_endpoint.applied_revision.is_some())
            || (self.manual_endpoint.configured != self.manual_endpoint.expires_at.is_some())
        {
            bail!("provider policy status is inconsistent");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManualEndpointInput {
    pub address: String,
    pub public_port: u16,
    pub forwarded_local_port: u16,
    pub ttl_seconds: u32,
}

impl ManualEndpointInput {
    fn validate(&self) -> Result<()> {
        validate_endpoint_address(&self.address)?;
        if self.public_port == 0 || self.forwarded_local_port == 0 {
            bail!("manual endpoint ports must be non-zero");
        }
        if !(MIN_MANUAL_ENDPOINT_TTL_SECONDS..=MAX_MANUAL_ENDPOINT_TTL_SECONDS)
            .contains(&self.ttl_seconds)
        {
            bail!("manual endpoint TTL must be between 60 seconds and 30 days");
        }
        Ok(())
    }
}

/// Returns current redacted provider policy and usage state.
///
/// # Errors
///
/// Returns an error when local state is unavailable, corrupt, or unsupported.
pub fn provider_policy_status(data_dir: &Path) -> Result<ProviderPolicyStatus> {
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    evaluate_and_checkpoint(&mut connection, OffsetDateTime::now_utc())
}

/// Atomically replaces the complete provider-owned hard-limit policy.
///
/// # Errors
///
/// Returns an error for an invalid DTO or unavailable/corrupt local state.
pub fn configure_provider_policy(
    data_dir: &Path,
    policy: &ProviderPolicy,
) -> Result<ProviderPolicyStatus> {
    policy.validate()?;
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let now = unix_timestamp()?;
    let policy_json = serde_json::to_string(&policy)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = transaction.execute(
        "UPDATE provider_policy SET policy_json = ?1, generation = generation + 1,
                updated_at = ?2 WHERE singleton = 1",
        params![policy_json, now],
    )?;
    if changed != 1 {
        bail!("provider policy is missing");
    }
    transaction.commit()?;
    evaluate_and_checkpoint(&mut connection, OffsetDateTime::now_utc())
}

/// Persists an immediate local pause without contacting Control.
///
/// # Errors
///
/// Returns an error when local policy state cannot be read or persisted.
pub fn pause_provider(data_dir: &Path) -> Result<ProviderPolicyStatus> {
    set_pause(data_dir, true)
}

/// Clears explicit pause while retaining schedule and quota enforcement.
///
/// # Errors
///
/// Returns an error when local policy state cannot be read or persisted.
pub fn resume_provider(data_dir: &Path) -> Result<ProviderPolicyStatus> {
    set_pause(data_dir, false)
}

fn set_pause(data_dir: &Path, paused: bool) -> Result<ProviderPolicyStatus> {
    let current = provider_policy_status(data_dir)?;
    let mut policy = current.policy;
    policy.paused = paused;
    configure_provider_policy(data_dir, &policy)
}

/// Installs a finite manual public endpoint for the current applied revision.
///
/// # Errors
///
/// Returns an error for an invalid/publicly unroutable endpoint, a forwarding
/// port mismatch, no current public revision, or unavailable local state.
pub fn configure_manual_endpoint(
    data_dir: &Path,
    input: &ManualEndpointInput,
) -> Result<ManualEndpointStatus> {
    input.validate()?;
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let (revision, expected_port) = current_admission_target(&connection, data_dir)?;
    if input.forwarded_local_port != expected_port {
        bail!("manual forwarding local port does not match the current applied revision");
    }
    let now = unix_timestamp()?;
    let expires_at = now
        .checked_add(i64::from(input.ttl_seconds))
        .context("manual endpoint expiry overflow")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO provider_manual_endpoint(
            singleton, endpoint_id, address, public_port, forwarded_local_port,
            applied_revision, observed_at, expires_at, configured_at
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6)
         ON CONFLICT(singleton) DO UPDATE SET
            endpoint_id = excluded.endpoint_id, address = excluded.address,
            public_port = excluded.public_port,
            forwarded_local_port = excluded.forwarded_local_port,
            applied_revision = excluded.applied_revision,
            observed_at = excluded.observed_at, expires_at = excluded.expires_at,
            configured_at = excluded.configured_at",
        params![
            EndpointId::new().to_string(),
            &input.address,
            input.public_port,
            input.forwarded_local_port,
            revision.get(),
            now,
            expires_at
        ],
    )?;
    transaction.commit()?;
    load_manual_status(&connection, Some(revision), now)
}

/// Withdraws the manual endpoint candidate without changing enrollment.
///
/// # Errors
///
/// Returns an error when local state is unavailable or cannot be updated.
pub fn clear_manual_endpoint(data_dir: &Path) -> Result<()> {
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    connection.execute(
        "DELETE FROM provider_manual_endpoint WHERE singleton = 1",
        [],
    )?;
    Ok(())
}

pub(crate) fn evaluate(data_dir: &Path) -> Result<ProviderPolicyStatus> {
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    evaluate_and_checkpoint(&mut connection, OffsetDateTime::now_utc())
}

pub(crate) fn load_status_readonly(connection: &Connection) -> Result<ProviderPolicyStatus> {
    load_status_at(connection, OffsetDateTime::now_utc())
}

/// Returns whether this local database permits endpoint advertisement now.
///
/// Databases predating the provider-policy migration remain permissive only
/// while they are being upgraded. Every initialized Node Host has the policy
/// table, so a missing table cannot bypass an installed policy.
pub(crate) fn allows_advertising(connection: &Connection) -> Result<bool> {
    if !has_provider_policy_table(connection)? {
        return Ok(true);
    }
    Ok(matches!(
        load_status_readonly(connection)?.availability,
        ProviderAvailability::Available
    ))
}

fn evaluate_and_checkpoint(
    connection: &mut Connection,
    observed_now: OffsetDateTime,
) -> Result<ProviderPolicyStatus> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let observed_unix = observed_now.unix_timestamp();
    let (_, _, high_watermark, _) = load_usage_row(&transaction)?;
    let effective_unix = observed_unix.max(high_watermark);
    let effective_now = OffsetDateTime::from_unix_timestamp(effective_unix)?;
    let effective_month = month_key(effective_now);
    let (stored_month, stored_bytes, _, last_observed_at) = load_usage_row(&transaction)?;
    let bytes = if stored_month.is_empty() || stored_month < effective_month {
        0
    } else {
        stored_bytes
    };
    let month = if stored_month.is_empty() || stored_month < effective_month {
        effective_month
    } else {
        stored_month
    };
    transaction.execute(
        "UPDATE provider_month_usage SET utc_month = ?1, observed_bytes = ?2,
            clock_high_watermark = ?3 WHERE singleton = 1",
        params![month, bytes, effective_unix],
    )?;
    let status =
        load_status_components(&transaction, effective_now, month, bytes, last_observed_at)?;
    transaction.commit()?;
    Ok(status)
}

fn load_status_at(
    connection: &Connection,
    observed_now: OffsetDateTime,
) -> Result<ProviderPolicyStatus> {
    let (stored_month, stored_bytes, high_watermark, last_observed_at) =
        load_usage_row(connection)?;
    let effective_now =
        OffsetDateTime::from_unix_timestamp(observed_now.unix_timestamp().max(high_watermark))?;
    let effective_month = month_key(effective_now);
    let (month, bytes) = if stored_month.is_empty() || stored_month < effective_month {
        (effective_month, 0)
    } else {
        (stored_month, stored_bytes)
    };
    load_status_components(connection, effective_now, month, bytes, last_observed_at)
}

fn load_status_components(
    connection: &Connection,
    effective_now: OffsetDateTime,
    month: String,
    bytes: i64,
    last_observed_at: Option<i64>,
) -> Result<ProviderPolicyStatus> {
    let (policy_json, generation, updated_at): (String, i64, i64) = connection.query_row(
        "SELECT policy_json, generation, updated_at FROM provider_policy WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let policy: ProviderPolicy =
        serde_json::from_str(&policy_json).context("stored provider policy is invalid")?;
    policy.validate()?;
    let observed_bytes = u64::try_from(bytes).context("stored provider usage is invalid")?;
    let availability = if policy.paused {
        ProviderAvailability::ProviderPaused
    } else if !policy.schedule_allows(effective_now) {
        ProviderAvailability::OutsideSchedule
    } else if policy
        .monthly_transfer_cap_bytes
        .is_some_and(|cap| observed_bytes >= cap)
    {
        ProviderAvailability::TransferCapReached
    } else {
        ProviderAvailability::Available
    };
    let cap = policy.monthly_transfer_cap_bytes;
    let applied_revision = current_applied_revision(connection)?;
    let mut manual_endpoint =
        load_manual_status(connection, applied_revision, effective_now.unix_timestamp())?;
    if availability != ProviderAvailability::Available {
        manual_endpoint.current = false;
    }
    let status = ProviderPolicyStatus {
        policy,
        generation: u64::try_from(generation).context("stored policy generation is invalid")?,
        updated_at: timestamp_from_unix(updated_at)?,
        availability,
        month_usage: ProviderMonthUsage {
            utc_month: month,
            observed_bytes,
            cap_bytes: cap,
            remaining_bytes: cap.map(|value| value.saturating_sub(observed_bytes)),
            coverage: USAGE_COVERAGE.to_string(),
            last_observed_at: last_observed_at.map(timestamp_from_unix).transpose()?,
        },
        manual_endpoint,
    };
    status.validate()?;
    Ok(status)
}

pub(crate) fn record_usage_delta_in_transaction(
    connection: &Connection,
    delta_bytes: i64,
    observed_at: i64,
) -> Result<()> {
    if delta_bytes < 0 {
        bail!("provider usage delta cannot be negative");
    }
    let (stored_month, stored_bytes, high_watermark, _) = load_usage_row(connection)?;
    let effective_unix = observed_at.max(high_watermark);
    let effective_month = month_key(OffsetDateTime::from_unix_timestamp(effective_unix)?);
    let base = if stored_month.is_empty() || stored_month < effective_month {
        0
    } else {
        stored_bytes
    };
    let total = base
        .checked_add(delta_bytes)
        .context("provider monthly usage counter overflow")?;
    connection.execute(
        "UPDATE provider_month_usage SET utc_month = ?1, observed_bytes = ?2,
            clock_high_watermark = ?3, last_observed_at = ?4 WHERE singleton = 1",
        params![effective_month, total, effective_unix, observed_at],
    )?;
    Ok(())
}

pub(crate) fn load_manual_candidate(
    connection: &Connection,
    applied_revision: Revision,
) -> Result<Option<EndpointCandidate>> {
    if !has_provider_manual_endpoint_table(connection)? || !allows_advertising(connection)? {
        return Ok(None);
    }
    let now = unix_timestamp()?;
    let row: Option<(String, String, i64, i64, i64, i64)> = connection
        .query_row(
            "SELECT endpoint_id, address, public_port, applied_revision, observed_at, expires_at
             FROM provider_manual_endpoint
             WHERE singleton = 1 AND applied_revision = ?1 AND expires_at > ?2",
            params![applied_revision.get(), now],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(endpoint_id, address, port, revision, observed_at, expires_at)| {
            Ok(EndpointCandidate {
                endpoint_id: EndpointId::from_str(&endpoint_id)
                    .context("stored manual endpoint identity is invalid")?,
                mode: EndpointMode::Direct,
                source: EndpointSource::Manual,
                address,
                port: u16::try_from(port).context("stored manual endpoint port is invalid")?,
                applied_revision: Revision::new(revision)
                    .context("stored manual endpoint revision is invalid")?,
                observed_at: timestamp_from_unix(observed_at)?,
                expires_at: Some(timestamp_from_unix(expires_at)?),
            })
        },
    )
    .transpose()
}

fn load_usage_row(connection: &Connection) -> Result<(String, i64, i64, Option<i64>)> {
    connection
        .query_row(
            "SELECT utc_month, observed_bytes, clock_high_watermark, last_observed_at
             FROM provider_month_usage WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .context("provider month usage state is missing")
}

fn has_provider_policy_table(connection: &Connection) -> Result<bool> {
    has_table(connection, "provider_policy")
}

fn has_provider_manual_endpoint_table(connection: &Connection) -> Result<bool> {
    has_table(connection, "provider_manual_endpoint")
}

fn has_table(connection: &Connection, table: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )
        .context("failed to inspect local provider-policy schema")
}

fn current_applied_revision(connection: &Connection) -> Result<Option<Revision>> {
    connection
        .query_row(
            "SELECT applied_revision FROM xray_active_state WHERE singleton = 1",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .map(Revision::new)
        .transpose()
        .context("stored applied revision is invalid")
}

fn current_admission_target(connection: &Connection, data_dir: &Path) -> Result<(Revision, u16)> {
    let revision = current_applied_revision(connection)?
        .context("manual endpoint requires a current applied revision")?;
    let candidate = crate::xray::load_validated_candidate(connection, data_dir, revision)?;
    Ok((revision, admission_forward_port(&candidate)))
}

const fn admission_forward_port(candidate: &crate::xray::ValidatedXrayCandidate) -> u16 {
    candidate.listen_port
}

fn load_manual_status(
    connection: &Connection,
    applied_revision: Option<Revision>,
    now: i64,
) -> Result<ManualEndpointStatus> {
    let row: Option<(i64, i64)> = connection
        .query_row(
            "SELECT applied_revision, expires_at FROM provider_manual_endpoint WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((revision, expires_at)) = row else {
        return Ok(ManualEndpointStatus {
            configured: false,
            current: false,
            applied_revision: None,
            expires_at: None,
        });
    };
    let revision = Revision::new(revision).context("stored manual endpoint revision is invalid")?;
    Ok(ManualEndpointStatus {
        configured: true,
        current: applied_revision == Some(revision) && expires_at > now,
        applied_revision: Some(revision),
        expires_at: Some(timestamp_from_unix(expires_at)?),
    })
}

fn validate_endpoint_address(address: &str) -> Result<()> {
    if address.is_empty()
        || address.len() > 253
        || address.contains('/')
        || address.contains(char::is_whitespace)
    {
        bail!("manual endpoint address must be a hostname or unbracketed IP address");
    }
    if let Ok(ip) = address.parse::<IpAddr>() {
        if !is_public_ip(ip) {
            bail!("manual endpoint IP address must be publicly routable");
        }
        return Ok(());
    }
    let labels = address.split('.').collect::<Vec<_>>();
    if address.contains(':')
        || address.ends_with('.')
        || labels.len() < 2
        || labels
            .last()
            .is_some_and(|label| label.eq_ignore_ascii_case("local"))
        || !labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        bail!("manual endpoint hostname is invalid");
    }
    Ok(())
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || octets[0] == 0
                || octets[0] >= 224
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 198 && (18..=19).contains(&octets[1])))
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] & 0xffc0) == 0xfec0)
        }
    }
}

fn month_key(value: OffsetDateTime) -> String {
    format!("{:04}-{:02}", value.year(), u8::from(value.month()))
}

const fn iso_weekday(day: Weekday) -> u8 {
    match day {
        Weekday::Monday => 1,
        Weekday::Tuesday => 2,
        Weekday::Wednesday => 3,
        Weekday::Thursday => 4,
        Weekday::Friday => 5,
        Weekday::Saturday => 6,
        Weekday::Sunday => 7,
    }
}

const fn next_weekday(day: u8) -> u8 {
    if day == 7 {
        1
    } else {
        day + 1
    }
}

#[cfg(test)]
mod tests {
    use super::{
        admission_forward_port, allows_advertising, evaluate_and_checkpoint, load_manual_candidate,
        pause_provider, record_usage_delta_in_transaction, resume_provider, ProviderAvailability,
        ProviderPolicy, WeeklyScheduleWindow,
    };
    use crate::{initialize, migrate, open_database, xray::ValidatedXrayCandidate};
    use control_protocol::crypto::Sha256Digest;
    use control_protocol::id::{EndpointId, Revision};
    use rusqlite::params;
    use std::path::PathBuf;
    use time::macros::datetime;
    use xray_runtime::Sha256Digest as RuntimeSha256Digest;

    #[test]
    fn manual_forwarding_targets_the_local_listener_not_the_public_port() {
        let candidate = ValidatedXrayCandidate {
            revision: Revision::new(1).unwrap(),
            config_path: PathBuf::from("config.json"),
            config_digest: Sha256Digest::from_bytes([0; 32]),
            binary_path: PathBuf::from("xray"),
            binary_digest: RuntimeSha256Digest::from_hex(&"0".repeat(64)).unwrap(),
            listen_port: 10_443,
            public_port: Some(442),
        };

        assert_eq!(admission_forward_port(&candidate), 10_443);
    }

    #[test]
    fn same_day_window_is_left_closed_and_right_open() {
        let policy = policy_with(WeeklyScheduleWindow {
            weekday: 1,
            start_minute: 60,
            end_minute: 120,
        });
        assert!(policy.schedule_allows(datetime!(2026-07-06 1:00 UTC)));
        assert!(policy.schedule_allows(datetime!(2026-07-06 1:59 UTC)));
        assert!(!policy.schedule_allows(datetime!(2026-07-06 2:00 UTC)));
    }

    #[test]
    fn overnight_window_belongs_to_its_start_weekday() {
        let policy = policy_with(WeeklyScheduleWindow {
            weekday: 7,
            start_minute: 23 * 60,
            end_minute: 60,
        });
        assert!(policy.schedule_allows(datetime!(2026-07-05 23:30 UTC)));
        assert!(policy.schedule_allows(datetime!(2026-07-06 0:30 UTC)));
        assert!(!policy.schedule_allows(datetime!(2026-07-06 1:00 UTC)));
    }

    #[test]
    fn closed_dto_rejects_unknown_fields_and_ambiguous_windows() {
        let json = r#"{"schemaVersion":1,"paused":false,"weeklySchedule":[],"monthlyTransferCapBytes":null,"maxConcurrentSessions":1,"bandwidthLimitBps":null,"extra":true}"#;
        assert!(serde_json::from_str::<ProviderPolicy>(json).is_err());
        let policy = policy_with(WeeklyScheduleWindow {
            weekday: 1,
            start_minute: 100,
            end_minute: 100,
        });
        assert!(policy.validate().is_err());
    }

    #[test]
    fn manual_endpoint_accepts_public_ipv6_and_rejects_non_public_targets() {
        for valid in ["1.1.1.1", "2606:4700:4700::1111", "node.example.com"] {
            assert!(
                super::validate_endpoint_address(valid).is_ok(),
                "rejected {valid}"
            );
        }
        for invalid in [
            "127.0.0.1",
            "100.64.0.1",
            "198.18.0.1",
            "::1",
            "::ffff:192.168.1.1",
            "2001:db8::1",
            "localhost",
            "node.local",
        ] {
            assert!(
                super::validate_endpoint_address(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn month_rollover_resets_usage_and_clock_rollback_never_restores_old_month() {
        let directory = tempfile::tempdir().unwrap();
        initialize(directory.path(), "https://controller.example").unwrap();
        let mut connection = open_database(directory.path(), false).unwrap();
        migrate(&mut connection).unwrap();
        evaluate_and_checkpoint(&mut connection, datetime!(2026-01-31 23:59 UTC)).unwrap();
        record_usage_delta_in_transaction(
            &connection,
            1_048_576,
            datetime!(2026-01-31 23:59 UTC).unix_timestamp(),
        )
        .unwrap();

        let february =
            evaluate_and_checkpoint(&mut connection, datetime!(2026-02-01 0:00 UTC)).unwrap();
        assert_eq!(february.month_usage.utc_month, "2026-02");
        assert_eq!(february.month_usage.observed_bytes, 0);
        record_usage_delta_in_transaction(
            &connection,
            42,
            datetime!(2026-02-01 0:01 UTC).unix_timestamp(),
        )
        .unwrap();

        let rolled_back =
            evaluate_and_checkpoint(&mut connection, datetime!(2026-01-01 0:00 UTC)).unwrap();
        assert_eq!(rolled_back.month_usage.utc_month, "2026-02");
        assert_eq!(rolled_back.month_usage.observed_bytes, 42);
    }

    #[test]
    fn exact_cap_boundary_closes_admission_and_pause_is_offline_local_state() {
        let directory = tempfile::tempdir().unwrap();
        initialize(directory.path(), "https://controller.invalid").unwrap();
        let paused = pause_provider(directory.path()).unwrap();
        assert_eq!(paused.availability, ProviderAvailability::ProviderPaused);
        let resumed = resume_provider(directory.path()).unwrap();
        assert_eq!(resumed.availability, ProviderAvailability::Available);

        let mut connection = open_database(directory.path(), false).unwrap();
        let mut policy = resumed.policy;
        policy.monthly_transfer_cap_bytes = Some(1_048_576);
        let json = serde_json::to_string(&policy).unwrap();
        connection
            .execute(
                "UPDATE provider_policy SET policy_json = ?1 WHERE singleton = 1",
                [json],
            )
            .unwrap();
        record_usage_delta_in_transaction(
            &connection,
            1_048_576,
            datetime!(2026-07-11 0:00 UTC).unix_timestamp(),
        )
        .unwrap();
        let status =
            evaluate_and_checkpoint(&mut connection, datetime!(2026-07-11 0:01 UTC)).unwrap();
        assert_eq!(
            status.availability,
            ProviderAvailability::TransferCapReached
        );
        assert_eq!(status.month_usage.remaining_bytes, Some(0));
    }

    #[test]
    fn manual_candidate_is_finite_and_bound_to_the_current_revision() {
        let directory = tempfile::tempdir().unwrap();
        initialize(directory.path(), "https://controller.example").unwrap();
        let connection = open_database(directory.path(), false).unwrap();
        let revision = Revision::new(7).unwrap();
        connection
            .execute(
                "INSERT INTO desired_state_artifacts(
                    revision, network_id, node_id, controller_instance_id, signing_key_id,
                    envelope_json, envelope_digest, transcript_digest, received_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, '{}', ?6, ?6, 1)",
                params![
                    revision.get(),
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string(),
                    format!("sha256:{}", "0".repeat(64)),
                ],
            )
            .unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        connection
            .execute(
                "INSERT INTO provider_manual_endpoint(
                    singleton, endpoint_id, address, public_port, forwarded_local_port,
                    applied_revision, observed_at, expires_at, configured_at
                 ) VALUES (1, ?1, '203.0.113.10', 443, 8443, ?2, ?3, ?4, ?3)",
                params![EndpointId::new().to_string(), revision.get(), now, now + 60],
            )
            .unwrap();
        let candidate = load_manual_candidate(&connection, revision)
            .unwrap()
            .unwrap();
        assert_eq!(candidate.applied_revision, revision);
        assert_eq!(
            candidate.expires_at.unwrap().as_datetime().unix_timestamp(),
            now + 60
        );
        assert!(
            load_manual_candidate(&connection, Revision::new(8).unwrap())
                .unwrap()
                .is_none()
        );
        pause_provider(directory.path()).unwrap();
        assert!(!allows_advertising(&connection).unwrap());
        assert!(load_manual_candidate(&connection, revision)
            .unwrap()
            .is_none());
    }

    fn policy_with(window: WeeklyScheduleWindow) -> ProviderPolicy {
        ProviderPolicy {
            weekly_schedule: vec![window],
            monthly_transfer_cap_bytes: None,
            bandwidth_limit_bps: None,
            ..ProviderPolicy::default()
        }
    }
}
