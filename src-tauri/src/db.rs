use chrono::{Local, NaiveDateTime, TimeZone, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

const DEFAULT_MONTHLY_QUOTA: i64 = 53_687_091_200; // 50 GB
const CONNECTION_RETENTION_SECS: i64 = 30 * 86_400;
const TRAFFIC_RETENTION_SECS: i64 = 90 * 86_400;
const SCHEMA_VERSION: i64 = 3;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
    log_sync: Arc<Mutex<()>>,
    node_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionLog {
    pub id: i64,
    pub user_id: String,
    pub user_email: String,
    pub timestamp: String,
    pub client_ip: String,
    pub destination: String,
    pub network: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserQuota {
    pub user_id: String,
    pub monthly_quota_bytes: i64,
    pub used_this_month: i64,
    pub last_reset_month: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsSeriesPoint {
    pub day: String,
    pub uplink_bytes: i64,
    pub downlink_bytes: i64,
    pub connection_count: i64,
    pub unique_client_ips: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsRankedItem {
    pub value: String,
    pub count: i64,
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAnalytics {
    pub node_id: String,
    pub user_id: String,
    pub from: i64,
    pub to: i64,
    pub uplink_bytes: i64,
    pub downlink_bytes: i64,
    pub connection_count: i64,
    pub unique_client_ips: i64,
    pub first_seen_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub active_days: i64,
    pub recently_active: bool,
    pub quota: Option<UserQuota>,
    pub daily: Vec<AnalyticsSeriesPoint>,
    pub top_client_ips: Vec<AnalyticsRankedItem>,
    pub top_destinations: Vec<AnalyticsRankedItem>,
    pub recent_connections: Vec<ConnectionLog>,
    pub last_traffic_sample_at: Option<i64>,
    pub last_log_import_at: Option<i64>,
}

#[derive(Debug, PartialEq)]
struct ParsedAccessEvent {
    email: String,
    occurred_at: i64,
    timestamp_text: String,
    client_ip: String,
    client_port: Option<u16>,
    network: String,
    destination_host: String,
    destination_port: Option<u16>,
    raw_destination: String,
}

impl Db {
    pub fn open(dir: &Path) -> Result<Self, String> {
        let db_path = dir.join("xray-plane.db");
        let mut conn =
            Connection::open(&db_path).map_err(|e| format!("Failed to open database: {e}"))?;
        migrate_schema(&mut conn)?;

        let node_id = conn
            .query_row(
                "SELECT value FROM kv WHERE key = 'local_node_id'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| format!("Failed to read local node ID: {e}"))?
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        conn.execute(
            "INSERT INTO kv (key, value) VALUES ('local_node_id', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![node_id],
        )
        .map_err(|e| format!("Failed to store local node ID: {e}"))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            log_sync: Arc::new(Mutex::new(())),
            node_id,
        })
    }

    pub fn sync_identities(&self, identities: &[(String, String)]) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let month = Local::now().format("%Y-%m").to_string();
        let mut conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("DB transaction: {e}"))?;
        tx.execute("UPDATE user_identities SET active = 0", [])
            .map_err(|e| format!("DB identity reset: {e}"))?;

        for (user_id, email) in identities {
            tx.execute(
                "DELETE FROM user_identities WHERE xray_email = ?1 AND user_id <> ?2",
                params![email, user_id],
            )
            .map_err(|e| format!("DB identity conflict cleanup: {e}"))?;
            tx.execute(
                "INSERT INTO user_identities
                   (user_id, xray_email, active, first_seen_at, last_seen_at)
                 VALUES (?1, ?2, 1, ?3, ?3)
                 ON CONFLICT(user_id, xray_email) DO UPDATE SET
                   active = 1, last_seen_at = excluded.last_seen_at",
                params![user_id, email, now],
            )
            .map_err(|e| format!("DB identity upsert: {e}"))?;
            migrate_legacy_usage(&tx, &self.node_id, user_id, email, &month)?;
        }

        migrate_legacy_connections(&tx, &self.node_id, now)?;
        prune_retained_data(&tx, now)?;
        tx.commit().map_err(|e| format!("DB commit: {e}"))
    }

    pub fn sync_traffic(
        &self,
        live_stats: &[(String, String, u64, u64)],
        current_month: &str,
    ) -> Result<Vec<UserQuota>, String> {
        let now = Utc::now().timestamp();
        let bucket_start = now - now.rem_euclid(1800);
        let mut conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("DB transaction: {e}"))?;

        for (user_id, email, up, down) in live_stats {
            let resolved = resolve_user_id(&tx, email)?
                .ok_or_else(|| format!("No stable user identity for Xray email `{email}`."))?;
            if resolved != *user_id {
                return Err(format!(
                    "Xray email `{email}` maps to `{resolved}`, not `{user_id}`."
                ));
            }

            migrate_legacy_usage(&tx, &self.node_id, user_id, email, current_month)?;
            tx.execute(
                "INSERT OR IGNORE INTO user_usage_v2 (user_id, last_reset_month)
                 VALUES (?1, ?2)",
                params![user_id, current_month],
            )
            .map_err(|e| format!("DB usage insert: {e}"))?;

            let (last_up, last_down) = tx
                .query_row(
                    "SELECT last_known_uplink, last_known_downlink
                     FROM usage_counters WHERE node_id = ?1 AND user_id = ?2",
                    params![self.node_id, user_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()
                .map_err(|e| format!("DB counter query: {e}"))?
                .unwrap_or((0, 0));
            let up = i64::try_from(*up).unwrap_or(i64::MAX);
            let down = i64::try_from(*down).unwrap_or(i64::MAX);
            let delta_up = if up >= last_up { up - last_up } else { up };
            let delta_down = if down >= last_down {
                down - last_down
            } else {
                down
            };

            let (used, stored_month): (i64, String) = tx
                .query_row(
                    "SELECT used_this_month, last_reset_month
                     FROM user_usage_v2 WHERE user_id = ?1",
                    params![user_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|e| format!("DB usage query: {e}"))?;
            let next_used = if stored_month == current_month {
                used.saturating_add(delta_up).saturating_add(delta_down)
            } else {
                delta_up.saturating_add(delta_down)
            };

            tx.execute(
                "UPDATE user_usage_v2 SET
                   used_this_month = ?1, last_reset_month = ?2,
                   last_known_uplink = ?3, last_known_downlink = ?4,
                   last_sample_at = ?5
                 WHERE user_id = ?6",
                params![next_used, current_month, up, down, now, user_id],
            )
            .map_err(|e| format!("DB usage update: {e}"))?;
            tx.execute(
                "INSERT INTO usage_counters
                   (node_id, user_id, last_known_uplink, last_known_downlink, last_sample_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(node_id, user_id) DO UPDATE SET
                   last_known_uplink = excluded.last_known_uplink,
                   last_known_downlink = excluded.last_known_downlink,
                   last_sample_at = excluded.last_sample_at",
                params![self.node_id, user_id, up, down, now],
            )
            .map_err(|e| format!("DB counter update: {e}"))?;
            tx.execute(
                "INSERT INTO traffic_samples
                   (node_id, user_id, bucket_start, uplink_bytes, downlink_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(node_id, user_id, bucket_start) DO UPDATE SET
                   uplink_bytes = uplink_bytes + excluded.uplink_bytes,
                   downlink_bytes = downlink_bytes + excluded.downlink_bytes",
                params![self.node_id, user_id, bucket_start, delta_up, delta_down],
            )
            .map_err(|e| format!("DB traffic sample: {e}"))?;
        }

        prune_retained_data(&tx, now)?;
        set_kv(
            &tx,
            &format!("last_traffic_sample_at:{}", self.node_id),
            &now.to_string(),
        )?;
        tx.commit().map_err(|e| format!("DB commit: {e}"))?;
        drop(conn);
        self.get_quotas()
    }

    pub fn set_quota(&self, user_id: &str, quota_bytes: i64) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        conn.execute(
            "INSERT INTO user_usage_v2
               (user_id, monthly_quota_bytes, last_reset_month)
             VALUES (?1, ?2, '')
             ON CONFLICT(user_id) DO UPDATE SET monthly_quota_bytes = excluded.monthly_quota_bytes",
            params![user_id, quota_bytes],
        )
        .map_err(|e| format!("DB set quota: {e}"))?;
        Ok(())
    }

    pub fn get_quotas(&self) -> Result<Vec<UserQuota>, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        get_quotas_inner(&conn)
    }

    pub fn sync_access_log(&self, log_path: &str) -> Result<usize, String> {
        let _sync_guard = self
            .log_sync
            .lock()
            .map_err(|e| format!("Log sync lock: {e}"))?;
        let offset_key = format!("log_offset:{}:{log_path}", self.node_id);
        let last_offset = {
            let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
            get_kv_i64(&conn, &offset_key)?.unwrap_or(0)
        };

        let file = fs::File::open(log_path).map_err(|e| format!("Cannot open access log: {e}"))?;
        let file_len = file.metadata().map(|m| m.len() as i64).unwrap_or(0);
        let start = if file_len < last_offset {
            0
        } else {
            last_offset
        };
        let mut reader = BufReader::new(file);
        reader
            .seek(SeekFrom::Start(start as u64))
            .map_err(|e| format!("Seek failed: {e}"))?;

        let mut entries = Vec::new();
        let mut line = String::new();
        while reader
            .read_line(&mut line)
            .map_err(|e| format!("Read failed: {e}"))?
            > 0
        {
            if let Some(entry) = parse_access_line(&line) {
                entries.push(entry);
            }
            line.clear();
        }
        let new_offset = reader.stream_position().unwrap_or(file_len as u64) as i64;
        let now = Utc::now().timestamp();

        let mut conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("DB transaction: {e}"))?;
        let mut inserted = 0;
        for entry in entries {
            let Some(user_id) = resolve_user_id(&tx, &entry.email)? else {
                continue;
            };
            insert_connection_event(&tx, &self.node_id, &user_id, &entry, None)?;
            inserted += 1;
        }
        set_kv(&tx, &offset_key, &new_offset.to_string())?;
        set_kv(
            &tx,
            &format!("last_log_import_at:{}", self.node_id),
            &now.to_string(),
        )?;
        prune_retained_data(&tx, now)?;
        tx.commit().map_err(|e| format!("DB commit: {e}"))?;
        Ok(inserted)
    }

    pub fn get_connections(
        &self,
        user_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ConnectionLog>, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        let limit = limit.clamp(1, 1000);
        let sql = if user_id.is_some() {
            "SELECT id, user_id, user_email_snapshot, timestamp_text, client_ip,
                    raw_destination, network
             FROM connection_events
             WHERE node_id = ?1 AND user_id = ?2
             ORDER BY occurred_at DESC, id DESC LIMIT ?3"
        } else {
            "SELECT id, user_id, user_email_snapshot, timestamp_text, client_ip,
                    raw_destination, network
             FROM connection_events
             WHERE node_id = ?1
             ORDER BY occurred_at DESC, id DESC LIMIT ?2"
        };
        let mut stmt = conn.prepare(sql).map_err(|e| format!("DB prepare: {e}"))?;
        let rows = if let Some(user_id) = user_id {
            stmt.query_map(params![self.node_id, user_id, limit], connection_from_row)
        } else {
            stmt.query_map(params![self.node_id, limit], connection_from_row)
        }
        .map_err(|e| format!("DB query: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("DB row: {e}"))
    }

    pub fn get_user_analytics(
        &self,
        user_id: &str,
        from: i64,
        to: i64,
    ) -> Result<UserAnalytics, String> {
        if from >= to {
            return Err("Analytics range must have `from` before `to`.".to_string());
        }
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        let mut daily = BTreeMap::<String, AnalyticsSeriesPoint>::new();

        {
            let mut stmt = conn
                .prepare(
                    "SELECT strftime('%Y-%m-%d', bucket_start, 'unixepoch', 'localtime'),
                            SUM(uplink_bytes), SUM(downlink_bytes)
                     FROM traffic_samples
                     WHERE node_id = ?1 AND user_id = ?2
                       AND bucket_start >= ?3 AND bucket_start < ?4
                     GROUP BY 1 ORDER BY 1",
                )
                .map_err(|e| format!("DB analytics traffic prepare: {e}"))?;
            let rows = stmt
                .query_map(params![self.node_id, user_id, from, to], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| format!("DB analytics traffic query: {e}"))?;
            for row in rows {
                let (day, uplink_bytes, downlink_bytes) =
                    row.map_err(|e| format!("DB analytics traffic row: {e}"))?;
                daily.insert(
                    day.clone(),
                    AnalyticsSeriesPoint {
                        day,
                        uplink_bytes,
                        downlink_bytes,
                        connection_count: 0,
                        unique_client_ips: 0,
                    },
                );
            }
        }
        {
            let mut stmt = conn
                .prepare(
                    "SELECT strftime('%Y-%m-%d', occurred_at, 'unixepoch', 'localtime'),
                            COUNT(*), COUNT(DISTINCT client_ip)
                     FROM connection_events
                     WHERE node_id = ?1 AND user_id = ?2
                       AND occurred_at >= ?3 AND occurred_at < ?4
                     GROUP BY 1 ORDER BY 1",
                )
                .map_err(|e| format!("DB analytics connection prepare: {e}"))?;
            let rows = stmt
                .query_map(params![self.node_id, user_id, from, to], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| format!("DB analytics connection query: {e}"))?;
            for row in rows {
                let (day, connection_count, unique_client_ips) =
                    row.map_err(|e| format!("DB analytics connection row: {e}"))?;
                let point = daily.entry(day.clone()).or_insert(AnalyticsSeriesPoint {
                    day,
                    uplink_bytes: 0,
                    downlink_bytes: 0,
                    connection_count: 0,
                    unique_client_ips: 0,
                });
                point.connection_count = connection_count;
                point.unique_client_ips = unique_client_ips;
            }
        }

        let (uplink_bytes, downlink_bytes): (i64, i64) = conn
            .query_row(
                "SELECT COALESCE(SUM(uplink_bytes), 0), COALESCE(SUM(downlink_bytes), 0)
                 FROM traffic_samples
                 WHERE node_id = ?1 AND user_id = ?2
                   AND bucket_start >= ?3 AND bucket_start < ?4",
                params![self.node_id, user_id, from, to],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| format!("DB analytics traffic totals: {e}"))?;
        let (connection_count, unique_client_ips, event_first, event_last): (
            i64,
            i64,
            Option<i64>,
            Option<i64>,
        ) = conn
            .query_row(
                "SELECT COUNT(*), COUNT(DISTINCT client_ip), MIN(occurred_at), MAX(occurred_at)
                 FROM connection_events
                 WHERE node_id = ?1 AND user_id = ?2
                   AND occurred_at >= ?3 AND occurred_at < ?4",
                params![self.node_id, user_id, from, to],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|e| format!("DB analytics connection totals: {e}"))?;
        let (traffic_first, traffic_last): (Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT MIN(bucket_start), MAX(bucket_start) FROM traffic_samples
                 WHERE node_id = ?1 AND user_id = ?2
                   AND bucket_start >= ?3 AND bucket_start < ?4",
                params![self.node_id, user_id, from, to],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| format!("DB analytics activity bounds: {e}"))?;
        let first_seen_at = min_option(event_first, traffic_first);
        let last_seen_at = max_option(event_last, traffic_last);
        let quota = conn
            .query_row(
                "SELECT user_id, monthly_quota_bytes, used_this_month, last_reset_month
                 FROM user_usage_v2 WHERE user_id = ?1",
                params![user_id],
                quota_from_row,
            )
            .optional()
            .map_err(|e| format!("DB analytics quota: {e}"))?;

        Ok(UserAnalytics {
            node_id: self.node_id.clone(),
            user_id: user_id.to_string(),
            from,
            to,
            uplink_bytes,
            downlink_bytes,
            connection_count,
            unique_client_ips,
            first_seen_at,
            last_seen_at,
            active_days: daily.len() as i64,
            recently_active: last_seen_at
                .is_some_and(|seen| seen >= Utc::now().timestamp() - 86_400),
            quota,
            daily: daily.into_values().collect(),
            top_client_ips: ranked_items(&conn, &self.node_id, user_id, from, to, "client_ip")?,
            top_destinations: ranked_items(
                &conn,
                &self.node_id,
                user_id,
                from,
                to,
                "raw_destination",
            )?,
            recent_connections: self.get_connections_locked(&conn, Some(user_id), 50)?,
            last_traffic_sample_at: conn
                .query_row(
                    "SELECT last_sample_at FROM usage_counters
                     WHERE node_id = ?1 AND user_id = ?2",
                    params![self.node_id, user_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| format!("DB analytics sample status: {e}"))?
                .flatten(),
            last_log_import_at: get_kv_i64(&conn, &format!("last_log_import_at:{}", self.node_id))?,
        })
    }

    fn get_connections_locked(
        &self,
        conn: &Connection,
        user_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ConnectionLog>, String> {
        let sql = "SELECT id, user_id, user_email_snapshot, timestamp_text, client_ip,
                          raw_destination, network
                   FROM connection_events
                   WHERE node_id = ?1 AND user_id = ?2
                   ORDER BY occurred_at DESC, id DESC LIMIT ?3";
        let mut stmt = conn.prepare(sql).map_err(|e| format!("DB prepare: {e}"))?;
        let rows = stmt
            .query_map(
                params![self.node_id, user_id.unwrap_or_default(), limit],
                connection_from_row,
            )
            .map_err(|e| format!("DB query: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("DB row: {e}"))
    }
}

fn migrate_schema(conn: &mut Connection) -> Result<(), String> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = FAST;",
    )
    .map_err(|e| format!("Failed to configure database: {e}"))?;
    let current: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| format!("Failed to read schema version: {e}"))?;
    if current > SCHEMA_VERSION {
        return Err(format!(
            "Database schema version {current} is newer than supported version {SCHEMA_VERSION}."
        ));
    }

    if current < 1 {
        let tx = conn
            .transaction()
            .map_err(|e| format!("Migration 1: {e}"))?;
        tx.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS user_traffic (
                 user_id TEXT PRIMARY KEY,
                 monthly_quota_bytes INTEGER NOT NULL DEFAULT {DEFAULT_MONTHLY_QUOTA},
                 used_this_month INTEGER NOT NULL DEFAULT 0,
                 last_reset_month TEXT NOT NULL DEFAULT '',
                 last_known_uplink INTEGER NOT NULL DEFAULT 0,
                 last_known_downlink INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS connection_logs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_email TEXT NOT NULL,
                 timestamp TEXT NOT NULL,
                 client_ip TEXT NOT NULL,
                 destination TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS kv (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             PRAGMA user_version = 1;"
        ))
        .map_err(|e| format!("Migration 1 failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Migration 1 commit: {e}"))?;
    }

    if current < 2 {
        let tx = conn
            .transaction()
            .map_err(|e| format!("Migration 2: {e}"))?;
        tx.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS user_identities (
                 user_id TEXT NOT NULL,
                 xray_email TEXT NOT NULL,
                 active INTEGER NOT NULL DEFAULT 1,
                 first_seen_at INTEGER NOT NULL,
                 last_seen_at INTEGER NOT NULL,
                 PRIMARY KEY (user_id, xray_email)
             );
             CREATE TABLE IF NOT EXISTS user_usage_v2 (
                 user_id TEXT PRIMARY KEY,
                 monthly_quota_bytes INTEGER NOT NULL DEFAULT {DEFAULT_MONTHLY_QUOTA},
                 used_this_month INTEGER NOT NULL DEFAULT 0,
                 last_reset_month TEXT NOT NULL DEFAULT '',
                 last_known_uplink INTEGER NOT NULL DEFAULT 0,
                 last_known_downlink INTEGER NOT NULL DEFAULT 0,
                 last_sample_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS usage_counters (
                 node_id TEXT NOT NULL,
                 user_id TEXT NOT NULL,
                 last_known_uplink INTEGER NOT NULL DEFAULT 0,
                 last_known_downlink INTEGER NOT NULL DEFAULT 0,
                 last_sample_at INTEGER,
                 PRIMARY KEY (node_id, user_id)
             );
             CREATE TABLE IF NOT EXISTS traffic_samples (
                 node_id TEXT NOT NULL,
                 user_id TEXT NOT NULL,
                 bucket_start INTEGER NOT NULL,
                 uplink_bytes INTEGER NOT NULL DEFAULT 0,
                 downlink_bytes INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (node_id, user_id, bucket_start)
             );
             CREATE TABLE IF NOT EXISTS connection_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 node_id TEXT NOT NULL,
                 user_id TEXT NOT NULL,
                 user_email_snapshot TEXT NOT NULL,
                 occurred_at INTEGER NOT NULL,
                 timestamp_text TEXT NOT NULL,
                 client_ip TEXT NOT NULL,
                 client_port INTEGER,
                 network TEXT NOT NULL,
                 destination_host TEXT NOT NULL,
                 destination_port INTEGER,
                 raw_destination TEXT NOT NULL,
                 legacy_connection_log_id INTEGER
             );
             PRAGMA user_version = 2;"
        ))
        .map_err(|e| format!("Migration 2 failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Migration 2 commit: {e}"))?;
    }

    if current < 3 {
        let tx = conn
            .transaction()
            .map_err(|e| format!("Migration 3: {e}"))?;
        ensure_column(
            &tx,
            "connection_events",
            "legacy_connection_log_id",
            "INTEGER",
        )?;
        tx.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_user_identity_email
                 ON user_identities(xray_email, active);
             CREATE INDEX IF NOT EXISTS idx_traffic_samples_user_time
                 ON traffic_samples(node_id, user_id, bucket_start DESC);
             CREATE INDEX IF NOT EXISTS idx_connection_events_user_time
                 ON connection_events(node_id, user_id, occurred_at DESC);
             CREATE INDEX IF NOT EXISTS idx_connection_events_time
                 ON connection_events(occurred_at DESC);
             CREATE UNIQUE INDEX IF NOT EXISTS idx_connection_events_legacy
                 ON connection_events(legacy_connection_log_id)
                 WHERE legacy_connection_log_id IS NOT NULL;
             PRAGMA user_version = 3;",
        )
        .map_err(|e| format!("Migration 3 failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Migration 3 commit: {e}"))?;
    }
    Ok(())
}

fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| format!("Failed to inspect `{table}`: {e}"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| format!("Failed to inspect `{table}`: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to inspect `{table}`: {e}"))?;
    if !columns.iter().any(|existing| existing == column) {
        conn.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition};"
        ))
        .map_err(|e| format!("Failed to add `{table}.{column}`: {e}"))?;
    }
    Ok(())
}

fn migrate_legacy_usage(
    conn: &Connection,
    node_id: &str,
    user_id: &str,
    email: &str,
    current_month: &str,
) -> Result<(), String> {
    let legacy = conn
        .query_row(
            "SELECT monthly_quota_bytes, used_this_month, last_reset_month,
                    last_known_uplink, last_known_downlink
             FROM user_traffic WHERE user_id = ?1 OR user_id = ?2
             ORDER BY CASE WHEN user_id = ?1 THEN 0 ELSE 1 END LIMIT 1",
            params![user_id, email],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|e| format!("DB legacy usage query: {e}"))?;

    if let Some((quota, used, month, up, down)) = legacy {
        conn.execute(
            "INSERT OR IGNORE INTO user_usage_v2
               (user_id, monthly_quota_bytes, used_this_month, last_reset_month,
                last_known_uplink, last_known_downlink)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                user_id,
                quota,
                used,
                if month.is_empty() {
                    current_month
                } else {
                    &month
                },
                up,
                down
            ],
        )
        .map_err(|e| format!("DB legacy usage migration: {e}"))?;
        conn.execute(
            "INSERT OR IGNORE INTO usage_counters
               (node_id, user_id, last_known_uplink, last_known_downlink)
             VALUES (?1, ?2, ?3, ?4)",
            params![node_id, user_id, up, down],
        )
        .map_err(|e| format!("DB legacy counter migration: {e}"))?;
    }
    Ok(())
}

fn migrate_legacy_connections(tx: &Transaction<'_>, node_id: &str, now: i64) -> Result<(), String> {
    let mut stmt = tx
        .prepare(
            "SELECT id, user_email, timestamp, client_ip, destination
             FROM connection_logs
             WHERE id NOT IN (
                 SELECT legacy_connection_log_id FROM connection_events
                 WHERE legacy_connection_log_id IS NOT NULL
             )",
        )
        .map_err(|e| format!("DB legacy connection prepare: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| format!("DB legacy connection query: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("DB legacy connection row: {e}"))?;
    drop(stmt);

    for (legacy_id, email, timestamp, client, destination) in rows {
        let Some(user_id) = resolve_user_id(tx, &email)? else {
            continue;
        };
        let Some(event) = parse_access_parts(&email, &timestamp, &client, &destination) else {
            continue;
        };
        if event.occurred_at >= now - CONNECTION_RETENTION_SECS {
            insert_connection_event(tx, node_id, &user_id, &event, Some(legacy_id))?;
        }
    }
    Ok(())
}

fn insert_connection_event(
    conn: &Connection,
    node_id: &str,
    user_id: &str,
    event: &ParsedAccessEvent,
    legacy_id: Option<i64>,
) -> Result<(), String> {
    conn.execute(
        "INSERT OR IGNORE INTO connection_events
           (node_id, user_id, user_email_snapshot, occurred_at, timestamp_text,
            client_ip, client_port, network, destination_host, destination_port,
            raw_destination, legacy_connection_log_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            node_id,
            user_id,
            event.email,
            event.occurred_at,
            event.timestamp_text,
            event.client_ip,
            event.client_port,
            event.network,
            event.destination_host,
            event.destination_port,
            event.raw_destination,
            legacy_id
        ],
    )
    .map_err(|e| format!("DB connection event insert: {e}"))?;
    Ok(())
}

fn resolve_user_id(conn: &Connection, email: &str) -> Result<Option<String>, String> {
    conn.query_row(
        "SELECT user_id FROM user_identities
         WHERE xray_email = ?1 AND active = 1
         ORDER BY last_seen_at DESC LIMIT 1",
        params![email],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| format!("DB identity lookup: {e}"))
}

fn prune_retained_data(conn: &Connection, now: i64) -> Result<(), String> {
    conn.execute(
        "DELETE FROM connection_events WHERE occurred_at < ?1",
        params![now - CONNECTION_RETENTION_SECS],
    )
    .map_err(|e| format!("DB connection retention: {e}"))?;
    conn.execute(
        "DELETE FROM traffic_samples WHERE bucket_start < ?1",
        params![now - TRAFFIC_RETENTION_SECS],
    )
    .map_err(|e| format!("DB traffic retention: {e}"))?;
    Ok(())
}

fn get_quotas_inner(conn: &Connection) -> Result<Vec<UserQuota>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT user_id, monthly_quota_bytes, used_this_month, last_reset_month
             FROM user_usage_v2",
        )
        .map_err(|e| format!("DB prepare: {e}"))?;
    let rows = stmt
        .query_map([], quota_from_row)
        .map_err(|e| format!("DB query: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("DB row: {e}"))
}

fn quota_from_row(row: &Row<'_>) -> rusqlite::Result<UserQuota> {
    Ok(UserQuota {
        user_id: row.get(0)?,
        monthly_quota_bytes: row.get(1)?,
        used_this_month: row.get(2)?,
        last_reset_month: row.get(3)?,
    })
}

fn connection_from_row(row: &Row<'_>) -> rusqlite::Result<ConnectionLog> {
    Ok(ConnectionLog {
        id: row.get(0)?,
        user_id: row.get(1)?,
        user_email: row.get(2)?,
        timestamp: row.get(3)?,
        client_ip: row.get(4)?,
        destination: row.get(5)?,
        network: row.get(6)?,
    })
}

fn ranked_items(
    conn: &Connection,
    node_id: &str,
    user_id: &str,
    from: i64,
    to: i64,
    column: &str,
) -> Result<Vec<AnalyticsRankedItem>, String> {
    let sql = format!(
        "SELECT {column}, COUNT(*), MAX(occurred_at)
         FROM connection_events
         WHERE node_id = ?1 AND user_id = ?2
           AND occurred_at >= ?3 AND occurred_at < ?4
         GROUP BY {column} ORDER BY COUNT(*) DESC, MAX(occurred_at) DESC LIMIT 10"
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("DB analytics ranking prepare: {e}"))?;
    let rows = stmt
        .query_map(params![node_id, user_id, from, to], |row| {
            Ok(AnalyticsRankedItem {
                value: row.get(0)?,
                count: row.get(1)?,
                last_seen_at: row.get(2)?,
            })
        })
        .map_err(|e| format!("DB analytics ranking query: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("DB analytics ranking row: {e}"))
}

fn set_kv(conn: &Connection, key: &str, value: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO kv (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )
    .map_err(|e| format!("DB state update: {e}"))?;
    Ok(())
}

fn get_kv_i64(conn: &Connection, key: &str) -> Result<Option<i64>, String> {
    conn.query_row("SELECT value FROM kv WHERE key = ?1", params![key], |row| {
        row.get::<_, String>(0)
    })
    .optional()
    .map_err(|e| format!("DB state query: {e}"))
    .map(|value| value.and_then(|raw| raw.parse().ok()))
}

fn min_option(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

fn max_option(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    }
}

/// Parse a single Xray access log line.
/// Format: "2026/04/12 20:00:00 1.2.3.4:5678 accepted tcp:www.google.com:443 email: user-id"
fn parse_access_line(line: &str) -> Option<ParsedAccessEvent> {
    let line = line.trim();
    let email_marker = line.rfind("email:")?;
    let email = line.get(email_marker + "email:".len()..)?.trim();
    let prefix = line.get(..email_marker)?.trim_end();
    let timestamp = prefix.get(..19)?;
    let after_timestamp = prefix.get(19..)?.trim();
    let (client, destination) = after_timestamp.split_once(" accepted ")?;
    parse_access_parts(email, timestamp, client.trim(), destination.trim())
}

fn parse_access_parts(
    email: &str,
    timestamp: &str,
    client: &str,
    destination: &str,
) -> Option<ParsedAccessEvent> {
    let occurred_at = parse_xray_timestamp(timestamp)?;
    let (client_ip, client_port) = parse_endpoint(client);
    if email.is_empty() || client_ip.is_empty() {
        return None;
    }
    let (network, endpoint) = destination.split_once(':')?;
    if network.is_empty() || endpoint.is_empty() {
        return None;
    }
    let (destination_host, destination_port) = parse_endpoint(endpoint);
    if destination_host.is_empty() {
        return None;
    }
    Some(ParsedAccessEvent {
        email: email.to_string(),
        occurred_at,
        timestamp_text: timestamp.to_string(),
        client_ip,
        client_port,
        network: network.to_ascii_lowercase(),
        destination_host,
        destination_port,
        raw_destination: destination.to_string(),
    })
}

fn parse_xray_timestamp(value: &str) -> Option<i64> {
    let naive = NaiveDateTime::parse_from_str(value, "%Y/%m/%d %H:%M:%S").ok()?;
    Local
        .from_local_datetime(&naive)
        .single()
        .or_else(|| Local.from_local_datetime(&naive).earliest())
        .map(|time| time.timestamp())
}

fn parse_endpoint(value: &str) -> (String, Option<u16>) {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            return (host.to_string(), port.parse().ok());
        }
        return (rest.trim_end_matches(']').to_string(), None);
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (host.to_string(), Some(port));
        }
    }
    (value.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path()).unwrap();
        (dir, db)
    }

    #[test]
    fn parses_network_endpoints_and_stable_email() {
        let parsed = parse_access_line(
            "2026/04/12 20:00:00 [2001:db8::1]:5678 accepted udp:[2606:4700:4700::1111]:53 email: user-abc",
        )
        .unwrap();
        assert_eq!(parsed.email, "user-abc");
        assert_eq!(parsed.client_ip, "2001:db8::1");
        assert_eq!(parsed.client_port, Some(5678));
        assert_eq!(parsed.network, "udp");
        assert_eq!(parsed.destination_host, "2606:4700:4700::1111");
        assert_eq!(parsed.destination_port, Some(53));
        assert!(parse_access_line("ignored line").is_none());
    }

    #[test]
    fn migrates_legacy_usage_and_connections_to_stable_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xray-plane.db");
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE user_traffic (
                 user_id TEXT PRIMARY KEY,
                 monthly_quota_bytes INTEGER NOT NULL DEFAULT {DEFAULT_MONTHLY_QUOTA},
                 used_this_month INTEGER NOT NULL DEFAULT 0,
                 last_reset_month TEXT NOT NULL DEFAULT '',
                 last_known_uplink INTEGER NOT NULL DEFAULT 0,
                 last_known_downlink INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE connection_logs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_email TEXT NOT NULL, timestamp TEXT NOT NULL,
                 client_ip TEXT NOT NULL, destination TEXT NOT NULL
             );
             INSERT INTO user_traffic VALUES ('friend-1', 1000, 250, '2026-04', 100, 150);
             INSERT INTO connection_logs (user_email, timestamp, client_ip, destination)
             VALUES ('friend-1', strftime('%Y/%m/%d %H:%M:%S', 'now', 'localtime'),
                     '1.2.3.4:1234', 'tcp:example.com:443');"
        ))
        .unwrap();
        drop(conn);

        let db = Db::open(dir.path()).unwrap();
        db.sync_identities(&[("stable-id".into(), "friend-1".into())])
            .unwrap();
        let quotas = db.get_quotas().unwrap();
        assert_eq!(quotas[0].user_id, "stable-id");
        assert_eq!(quotas[0].used_this_month, 250);
        let events = db.get_connections(Some("stable-id"), 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].user_id, "stable-id");
        assert_eq!(events[0].network, "tcp");
    }

    #[test]
    fn upgrades_partially_created_analytics_schema() {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("xray-plane.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE connection_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 node_id TEXT NOT NULL, user_id TEXT NOT NULL,
                 user_email_snapshot TEXT NOT NULL, occurred_at INTEGER NOT NULL,
                 timestamp_text TEXT NOT NULL, client_ip TEXT NOT NULL,
                 client_port INTEGER, network TEXT NOT NULL,
                 destination_host TEXT NOT NULL, destination_port INTEGER,
                 raw_destination TEXT NOT NULL
             );",
        )
        .unwrap();
        drop(conn);

        let db = Db::open(dir.path()).unwrap();
        let conn = db.conn.lock().unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let has_legacy_column: bool = conn
            .prepare("PRAGMA table_info(connection_events)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .any(|column| column.unwrap() == "legacy_connection_log_id");
        assert!(has_legacy_column);
    }

    #[test]
    fn configures_durable_and_hardened_sqlite_connection() {
        let (_dir, db) = test_db();
        let conn = db.conn.lock().unwrap();

        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        let foreign_keys: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        let trusted_schema: i64 = conn
            .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
            .unwrap();
        let secure_delete: i64 = conn
            .query_row("PRAGMA secure_delete", [], |row| row.get(0))
            .unwrap();

        assert_eq!(journal_mode, "wal");
        assert_eq!(synchronous, 2);
        assert_eq!(foreign_keys, 1);
        assert_eq!(trusted_schema, 0);
        assert_eq!(secure_delete, 2);
    }

    #[test]
    fn traffic_counter_baselines_are_node_scoped() {
        let (_dir, db) = test_db();
        db.sync_identities(&[("stable-id".into(), "user-stable".into())])
            .unwrap();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO usage_counters
                   (node_id, user_id, last_known_uplink, last_known_downlink)
                 VALUES ('another-node', 'stable-id', 900, 900)",
                [],
            )
            .unwrap();
        }
        db.sync_traffic(
            &[("stable-id".into(), "user-stable".into(), 100, 200)],
            "2026-04",
        )
        .unwrap();
        db.sync_traffic(
            &[("stable-id".into(), "user-stable".into(), 130, 260)],
            "2026-04",
        )
        .unwrap();
        let quota = db.get_quotas().unwrap().remove(0);
        assert_eq!(quota.used_this_month, 390);
    }

    #[test]
    fn log_ingestion_maps_identity_retains_by_time_and_feeds_analytics() {
        let (dir, db) = test_db();
        db.sync_identities(&[("stable-id".into(), "user-stable".into())])
            .unwrap();
        let log_path = dir.path().join("access.log");
        let now = Local::now().format("%Y/%m/%d %H:%M:%S");
        let mut log = fs::File::create(&log_path).unwrap();
        writeln!(
            log,
            "{now} 10.0.0.1:5555 accepted tcp:example.com:443 email: user-stable"
        )
        .unwrap();
        writeln!(
            log,
            "{now} 10.0.0.2:5556 accepted udp:1.1.1.1:53 email: unknown"
        )
        .unwrap();

        assert_eq!(db.sync_access_log(log_path.to_str().unwrap()).unwrap(), 1);
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO connection_events
                   (node_id, user_id, user_email_snapshot, occurred_at, timestamp_text,
                    client_ip, network, destination_host, raw_destination)
                 VALUES (?1, 'stable-id', 'user-stable', ?2, 'old', 'old-ip',
                         'tcp', 'old.example', 'tcp:old.example:443')",
                params![
                    db.node_id,
                    Utc::now().timestamp() - CONNECTION_RETENTION_SECS - 1
                ],
            )
            .unwrap();
        }
        assert_eq!(db.sync_access_log(log_path.to_str().unwrap()).unwrap(), 0);
        let events = db.get_connections(Some("stable-id"), 10).unwrap();
        assert_eq!(events.len(), 1);
        let analytics = db
            .get_user_analytics(
                "stable-id",
                Utc::now().timestamp() - 86_400,
                Utc::now().timestamp() + 1,
            )
            .unwrap();
        assert_eq!(analytics.connection_count, 1);
        assert_eq!(analytics.unique_client_ips, 1);
        assert_eq!(analytics.top_destinations[0].value, "tcp:example.com:443");
    }
}
