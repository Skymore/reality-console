use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, UtcOffset};

use crate::error::{RelayError, Result};

const STATE_SCHEMA_VERSION: u16 = 1;
const STATE_FILE_NAME: &str = "monthly-quotas.json";
const TEMP_FILE_NAME: &str = "monthly-quotas.json.next";
const MAX_STATE_FILE_BYTES: u64 = 8 * 1024 * 1024;
const RETENTION_DAYS: i64 = 62;
const RECORDS_PER_CONFIGURED_ROUTE: usize = 8;
const MAX_QUOTA_RECORDS: usize = 65_536;

#[derive(Clone)]
pub(crate) struct QuotaStore {
    inner: Arc<QuotaStoreInner>,
}

pub(crate) struct RouteQuota {
    store: QuotaStore,
    route_id: String,
    limit: u64,
}

struct QuotaStoreInner {
    directory: PathBuf,
    state_path: PathBuf,
    max_records: usize,
    status: Mutex<StoreStatus>,
}

struct StoreStatus {
    state: QuotaState,
    poisoned: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuotaState {
    schema_version: u16,
    #[serde(with = "time::serde::rfc3339")]
    clock_high_watermark: OffsetDateTime,
    records: BTreeMap<String, QuotaRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuotaRecord {
    year: i32,
    month: u8,
    bytes: u64,
    #[serde(default, with = "time::serde::rfc3339::option")]
    retired_at: Option<OffsetDateTime>,
}

impl QuotaStore {
    pub(crate) async fn open(
        directory: PathBuf,
        max_routes: usize,
        now: OffsetDateTime,
    ) -> Result<Self> {
        tokio::task::spawn_blocking(move || Self::open_blocking(directory, max_routes, now))
            .await
            .map_err(|_| quota_error("relay_quota_worker_failed"))?
    }

    fn open_blocking(directory: PathBuf, max_routes: usize, now: OffsetDateTime) -> Result<Self> {
        validate_directory(&directory)?;
        if max_routes > MAX_QUOTA_RECORDS / RECORDS_PER_CONFIGURED_ROUTE {
            return Err(quota_error("relay_quota_route_capacity_exceeded"));
        }
        let state_path = directory.join(STATE_FILE_NAME);
        let temporary_path = directory.join(TEMP_FILE_NAME);
        if fs::symlink_metadata(&temporary_path).is_ok() {
            return Err(quota_error("relay_quota_incomplete_write"));
        }
        let max_records = max_routes
            .saturating_mul(RECORDS_PER_CONFIGURED_ROUTE)
            .min(MAX_QUOTA_RECORDS)
            .max(max_routes);
        let state = match fs::symlink_metadata(&state_path) {
            Ok(metadata) => read_state(&state_path, &metadata, max_records)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let state = QuotaState {
                    schema_version: STATE_SCHEMA_VERSION,
                    clock_high_watermark: utc(now),
                    records: BTreeMap::new(),
                };
                persist_state(&directory, &state_path, &state)?;
                state
            }
            Err(_) => return Err(quota_error("relay_quota_state_unavailable")),
        };
        Ok(Self {
            inner: Arc::new(QuotaStoreInner {
                directory,
                state_path,
                max_records,
                status: Mutex::new(StoreStatus {
                    state,
                    poisoned: false,
                }),
            }),
        })
    }

    pub(crate) async fn reconcile(
        &self,
        active_route_ids: Vec<String>,
        now: OffsetDateTime,
    ) -> Result<()> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.reconcile(&active_route_ids, now))
            .await
            .map_err(|_| quota_error("relay_quota_worker_failed"))?
    }

    #[must_use]
    pub(crate) fn route(&self, route_id: String, limit: u64) -> RouteQuota {
        RouteQuota {
            store: self.clone(),
            route_id,
            limit,
        }
    }
}

impl RouteQuota {
    pub(crate) async fn permits_new_stream(&self, now: OffsetDateTime) -> Result<bool> {
        let inner = self.store.inner.clone();
        let route_id = self.route_id.clone();
        let limit = self.limit;
        tokio::task::spawn_blocking(move || inner.permits_new_stream(&route_id, limit, now))
            .await
            .map_err(|_| quota_error("relay_quota_worker_failed"))?
    }

    /// Durably reserves at most `requested` bytes before the caller forwards them.
    pub(crate) async fn reserve(&self, requested: usize, now: OffsetDateTime) -> Result<usize> {
        let requested =
            u64::try_from(requested).map_err(|_| quota_error("relay_quota_reservation_invalid"))?;
        let inner = self.store.inner.clone();
        let route_id = self.route_id.clone();
        let limit = self.limit;
        let granted =
            tokio::task::spawn_blocking(move || inner.reserve(&route_id, limit, requested, now))
                .await
                .map_err(|_| quota_error("relay_quota_worker_failed"))??;
        usize::try_from(granted).map_err(|_| quota_error("relay_quota_reservation_invalid"))
    }
}

impl QuotaStoreInner {
    fn reconcile(&self, active_route_ids: &[String], now: OffsetDateTime) -> Result<()> {
        let active: HashSet<&str> = active_route_ids.iter().map(String::as_str).collect();
        if active.len() > self.max_records {
            return Err(quota_error("relay_quota_record_capacity_exceeded"));
        }
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_healthy(&status)?;
        let mut candidate = status.state.clone();
        let effective_now = effective_now(&candidate, now);
        let current_month = month_key(effective_now);
        let cutoff = effective_now - Duration::days(RETENTION_DAYS);
        let before_len = candidate.records.len();
        candidate.records.retain(|_, record| {
            record
                .retired_at
                .is_none_or(|retired_at| retired_at > cutoff)
        });
        let mut changed = candidate.records.len() != before_len;

        for (route_id, record) in &mut candidate.records {
            if active.contains(route_id.as_str()) {
                changed |= roll_record(record, current_month);
                if record.retired_at.take().is_some() {
                    changed = true;
                }
            } else if record.retired_at.is_none() {
                record.retired_at = Some(effective_now);
                changed = true;
            }
        }
        for route_id in active_route_ids {
            if !candidate.records.contains_key(route_id) {
                if candidate.records.len() >= self.max_records {
                    return Err(quota_error("relay_quota_record_capacity_exceeded"));
                }
                candidate.records.insert(
                    route_id.clone(),
                    QuotaRecord {
                        year: current_month.0,
                        month: current_month.1,
                        bytes: 0,
                        retired_at: None,
                    },
                );
                changed = true;
            }
        }
        if changed {
            candidate.clock_high_watermark = effective_now;
            self.commit(&mut status, candidate)?;
        }
        Ok(())
    }

    fn permits_new_stream(&self, route_id: &str, limit: u64, now: OffsetDateTime) -> Result<bool> {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_healthy(&status)?;
        let mut candidate = status.state.clone();
        let effective_now = effective_now(&candidate, now);
        let current_month = month_key(effective_now);
        let record = active_record_mut(&mut candidate, route_id)?;
        let changed = roll_record(record, current_month);
        let permitted = record.bytes < limit;
        if changed {
            candidate.clock_high_watermark = effective_now;
            self.commit(&mut status, candidate)?;
        }
        Ok(permitted)
    }

    fn reserve(
        &self,
        route_id: &str,
        limit: u64,
        requested: u64,
        now: OffsetDateTime,
    ) -> Result<u64> {
        if requested == 0 {
            return Ok(0);
        }
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_healthy(&status)?;
        let mut candidate = status.state.clone();
        let effective_now = effective_now(&candidate, now);
        let current_month = month_key(effective_now);
        let record = active_record_mut(&mut candidate, route_id)?;
        roll_record(record, current_month);
        let granted = requested.min(limit.saturating_sub(record.bytes));
        if granted == 0 {
            return Ok(0);
        }
        record.bytes = record
            .bytes
            .checked_add(granted)
            .ok_or_else(|| quota_error("relay_quota_counter_overflow"))?;
        candidate.clock_high_watermark = effective_now;
        self.commit(&mut status, candidate)?;
        Ok(granted)
    }

    fn commit(&self, status: &mut StoreStatus, candidate: QuotaState) -> Result<()> {
        if let Err(error) = persist_state(&self.directory, &self.state_path, &candidate) {
            status.poisoned = true;
            return Err(error);
        }
        status.state = candidate;
        Ok(())
    }
}

fn active_record_mut<'a>(state: &'a mut QuotaState, route_id: &str) -> Result<&'a mut QuotaRecord> {
    state
        .records
        .get_mut(route_id)
        .filter(|record| record.retired_at.is_none())
        .ok_or_else(|| quota_error("relay_quota_route_unavailable"))
}

fn roll_record(record: &mut QuotaRecord, current_month: (i32, u8)) -> bool {
    if (record.year, record.month) < current_month {
        record.year = current_month.0;
        record.month = current_month.1;
        record.bytes = 0;
        true
    } else {
        false
    }
}

fn effective_now(state: &QuotaState, now: OffsetDateTime) -> OffsetDateTime {
    utc(now).max(state.clock_high_watermark)
}

fn month_key(value: OffsetDateTime) -> (i32, u8) {
    (value.year(), u8::from(value.month()))
}

fn utc(value: OffsetDateTime) -> OffsetDateTime {
    value.to_offset(UtcOffset::UTC)
}

fn ensure_healthy(status: &StoreStatus) -> Result<()> {
    if status.poisoned {
        Err(quota_error("relay_quota_state_poisoned"))
    } else {
        Ok(())
    }
}

fn read_state(path: &Path, metadata: &fs::Metadata, max_records: usize) -> Result<QuotaState> {
    validate_state_file_metadata(metadata)?;
    let file = open_state_no_follow(path)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| quota_error("relay_quota_state_unavailable"))?;
    validate_state_file_metadata(&opened_metadata)?;
    validate_same_file(metadata, &opened_metadata)?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| quota_error("relay_quota_state_unreadable"))?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STATE_FILE_BYTES {
        return Err(quota_error("relay_quota_state_size_invalid"));
    }
    let state: QuotaState =
        serde_json::from_slice(&bytes).map_err(|_| quota_error("relay_quota_state_invalid"))?;
    validate_state(&state, max_records)?;
    Ok(state)
}

fn validate_state(state: &QuotaState, max_records: usize) -> Result<()> {
    if state.schema_version != STATE_SCHEMA_VERSION
        || state.clock_high_watermark.offset() != UtcOffset::UTC
        || state.records.len() > max_records
    {
        return Err(quota_error("relay_quota_state_invalid"));
    }
    let highest_month = month_key(state.clock_high_watermark);
    for (route_id, record) in &state.records {
        if route_id.len() < 16
            || route_id.len() > 128
            || !route_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !(1..=12).contains(&record.month)
            || (record.year, record.month) > highest_month
            || record.retired_at.is_some_and(|retired_at| {
                retired_at.offset() != UtcOffset::UTC || retired_at > state.clock_high_watermark
            })
        {
            return Err(quota_error("relay_quota_state_invalid"));
        }
    }
    Ok(())
}

fn persist_state(directory: &Path, state_path: &Path, state: &QuotaState) -> Result<()> {
    validate_directory(directory)?;
    let mut bytes =
        serde_json::to_vec(state).map_err(|_| quota_error("relay_quota_state_serialize_failed"))?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STATE_FILE_BYTES {
        return Err(quota_error("relay_quota_state_size_invalid"));
    }
    let temporary_path = directory.join(TEMP_FILE_NAME);
    let write_result = (|| -> Result<()> {
        let mut temporary = create_temporary(&temporary_path)?;
        temporary
            .write_all(&bytes)
            .map_err(|_| quota_error("relay_quota_state_write_failed"))?;
        temporary
            .sync_all()
            .map_err(|_| quota_error("relay_quota_state_sync_failed"))?;
        drop(temporary);
        fs::rename(&temporary_path, state_path)
            .map_err(|_| quota_error("relay_quota_state_replace_failed"))?;
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| quota_error("relay_quota_directory_sync_failed"))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(temporary_path);
    }
    write_result
}

#[cfg(unix)]
fn create_temporary(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| quota_error("relay_quota_temporary_create_failed"))
}

#[cfg(not(unix))]
fn create_temporary(_path: &Path) -> Result<File> {
    Err(quota_error("relay_quota_platform_unsupported"))
}

#[cfg(unix)]
fn open_state_no_follow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| quota_error("relay_quota_state_unavailable"))
}

#[cfg(not(unix))]
fn open_state_no_follow(_path: &Path) -> Result<File> {
    Err(quota_error("relay_quota_platform_unsupported"))
}

#[cfg(unix)]
fn validate_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata =
        fs::symlink_metadata(path).map_err(|_| quota_error("relay_quota_directory_unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(quota_error("relay_quota_directory_permissions_invalid"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory(_path: &Path) -> Result<()> {
    Err(quota_error("relay_quota_platform_unsupported"))
}

#[cfg(unix)]
fn validate_state_file_metadata(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > MAX_STATE_FILE_BYTES
    {
        return Err(quota_error("relay_quota_state_permissions_invalid"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_state_file_metadata(_metadata: &fs::Metadata) -> Result<()> {
    Err(quota_error("relay_quota_platform_unsupported"))
}

#[cfg(unix)]
fn validate_same_file(before: &fs::Metadata, after: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(quota_error("relay_quota_state_changed"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_file(_before: &fs::Metadata, _after: &fs::Metadata) -> Result<()> {
    Ok(())
}

fn quota_error(code: &'static str) -> RelayError {
    RelayError::Config(code.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct Fixture {
        directory: TempDir,
        store: QuotaStore,
    }

    impl Fixture {
        async fn new(now: OffsetDateTime) -> Self {
            Self::new_with_max_routes(now, 16).await
        }

        async fn new_with_max_routes(now: OffsetDateTime, max_routes: usize) -> Self {
            let directory = tempfile::tempdir().unwrap();
            set_owner_only_directory(directory.path());
            let store = QuotaStore::open(directory.path().to_owned(), max_routes, now)
                .await
                .unwrap();
            Self { directory, store }
        }

        async fn activate(&self, route_ids: &[&str], now: OffsetDateTime) {
            self.store
                .reconcile(
                    route_ids.iter().map(|value| (*value).to_owned()).collect(),
                    now,
                )
                .await
                .unwrap();
        }
    }

    const ROUTE_ONE: &str = "grant_0123456789abcdef";
    const ROUTE_TWO: &str = "grant_fedcba9876543210";

    #[tokio::test]
    async fn reserves_exact_boundary_across_concurrent_directions() {
        let now = OffsetDateTime::from_unix_timestamp(1_751_328_000).unwrap();
        let fixture = Fixture::new(now).await;
        fixture.activate(&[ROUTE_ONE], now).await;
        let upload = fixture.store.route(ROUTE_ONE.to_owned(), 100);
        let download = fixture.store.route(ROUTE_ONE.to_owned(), 100);
        let (first, second) = tokio::join!(upload.reserve(70, now), download.reserve(70, now));
        assert_eq!(first.unwrap() + second.unwrap(), 100);
        assert!(!upload.permits_new_stream(now).await.unwrap());
        assert_eq!(upload.reserve(1, now).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn usage_survives_restart_and_hot_reconcile() {
        let now = OffsetDateTime::from_unix_timestamp(1_751_328_000).unwrap();
        let fixture = Fixture::new(now).await;
        fixture.activate(&[ROUTE_ONE], now).await;
        let quota = fixture.store.route(ROUTE_ONE.to_owned(), 100);
        assert_eq!(quota.reserve(61, now).await.unwrap(), 61);
        fixture.activate(&[], now).await;
        fixture.activate(&[ROUTE_ONE], now).await;
        let Fixture { directory, store } = fixture;
        let path = directory.path().to_owned();
        drop(store);

        let reopened = QuotaStore::open(path, 16, now).await.unwrap();
        reopened
            .reconcile(vec![ROUTE_ONE.to_owned()], now)
            .await
            .unwrap();
        let quota = reopened.route(ROUTE_ONE.to_owned(), 100);
        assert_eq!(quota.reserve(100, now).await.unwrap(), 39);
    }

    #[tokio::test]
    async fn utc_rollover_is_monotonic_across_clock_rollback() {
        let july = OffsetDateTime::parse(
            "2026-07-31T23:59:59Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let august = july + Duration::seconds(2);
        let fixture = Fixture::new(july).await;
        fixture.activate(&[ROUTE_ONE], july).await;
        let quota = fixture.store.route(ROUTE_ONE.to_owned(), 10);
        assert_eq!(quota.reserve(10, july).await.unwrap(), 10);
        assert_eq!(quota.reserve(4, august).await.unwrap(), 4);
        assert_eq!(quota.reserve(10, july).await.unwrap(), 6);
        assert!(!quota.permits_new_stream(july).await.unwrap());
    }

    #[tokio::test]
    async fn generation_scoped_routes_account_independently() {
        let now = OffsetDateTime::from_unix_timestamp(1_751_328_000).unwrap();
        let fixture = Fixture::new(now).await;
        fixture.activate(&[ROUTE_ONE, ROUTE_TWO], now).await;
        let first = fixture.store.route(ROUTE_ONE.to_owned(), 10);
        let second = fixture.store.route(ROUTE_TWO.to_owned(), 10);
        assert_eq!(first.reserve(10, now).await.unwrap(), 10);
        assert_eq!(second.reserve(6, now).await.unwrap(), 6);
        assert!(!first.permits_new_stream(now).await.unwrap());
        assert!(second.permits_new_stream(now).await.unwrap());
    }

    #[tokio::test]
    async fn corrupt_state_fails_closed() {
        let now = OffsetDateTime::from_unix_timestamp(1_751_328_000).unwrap();
        let fixture = Fixture::new(now).await;
        let Fixture { directory, store } = fixture;
        let path = directory.path().to_owned();
        drop(store);
        let state_path = path.join(STATE_FILE_NAME);
        fs::write(&state_path, b"{").unwrap();
        set_owner_only_file(&state_path);
        assert!(QuotaStore::open(path, 16, now).await.is_err());
    }

    #[tokio::test]
    async fn retired_records_are_bounded_and_expire_conservatively() {
        let now = OffsetDateTime::from_unix_timestamp(1_751_328_000).unwrap();
        let fixture = Fixture::new_with_max_routes(now, 1).await;
        for index in 0..RECORDS_PER_CONFIGURED_ROUTE {
            fixture
                .activate(&[&format!("grant_rotation_{index:016}")], now)
                .await;
        }
        assert!(fixture
            .store
            .reconcile(vec!["grant_rotation_over_capacity".to_owned()], now,)
            .await
            .is_err());

        fixture
            .activate(
                &["grant_rotation_after_retention"],
                now + Duration::days(RETENTION_DAYS + 1),
            )
            .await;
    }

    #[cfg(unix)]
    fn set_owner_only_directory(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_owner_only_directory(_path: &Path) {}

    #[cfg(unix)]
    fn set_owner_only_file(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_owner_only_file(_path: &Path) {}
}
