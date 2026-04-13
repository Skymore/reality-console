use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};

const DEFAULT_MONTHLY_QUOTA: i64 = 53_687_091_200; // 50 GB

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionLog {
    pub id: i64,
    pub user_email: String,
    pub timestamp: String,
    pub client_ip: String,
    pub destination: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserQuota {
    pub user_id: String,
    pub monthly_quota_bytes: i64,
    pub used_this_month: i64,
    pub last_reset_month: String,
}

impl Db {
    pub fn open(dir: &Path) -> Result<Self, String> {
        let db_path = dir.join("xray-plane.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("Failed to open database: {e}"))?;

        conn.execute_batch(&format!(
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
            CREATE INDEX IF NOT EXISTS idx_connlog_user ON connection_logs(user_email);
            CREATE INDEX IF NOT EXISTS idx_connlog_ts ON connection_logs(timestamp DESC);"
        ))
        .map_err(|e| format!("Failed to create tables: {e}"))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn sync_traffic(
        &self,
        live_stats: &[(String, u64, u64)],
        current_month: &str,
    ) -> Result<Vec<UserQuota>, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;

        for (email, up, down) in live_stats {
            let up = *up as i64;
            let down = *down as i64;

            conn.execute(
                "INSERT OR IGNORE INTO user_traffic (user_id, last_reset_month) VALUES (?1, ?2)",
                params![email, current_month],
            ).map_err(|e| format!("DB insert: {e}"))?;

            let (last_up, last_down, stored_month): (i64, i64, String) = conn
                .query_row(
                    "SELECT last_known_uplink, last_known_downlink, last_reset_month FROM user_traffic WHERE user_id = ?1",
                    params![email],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|e| format!("DB query: {e}"))?;

            if stored_month != current_month {
                // Month rollover
                let total = up + down;
                conn.execute(
                    "UPDATE user_traffic SET used_this_month = ?1, last_reset_month = ?2, last_known_uplink = ?3, last_known_downlink = ?4 WHERE user_id = ?5",
                    params![total, current_month, up, down, email],
                ).map_err(|e| format!("DB reset: {e}"))?;
            } else {
                // Delta calculation (handle xray restart)
                let delta_up = if up >= last_up { up - last_up } else { up };
                let delta_down = if down >= last_down { down - last_down } else { down };
                let delta = delta_up + delta_down;

                conn.execute(
                    "UPDATE user_traffic SET used_this_month = used_this_month + ?1, last_known_uplink = ?2, last_known_downlink = ?3 WHERE user_id = ?4",
                    params![delta, up, down, email],
                ).map_err(|e| format!("DB update: {e}"))?;
            }
        }

        self.get_quotas_inner(&conn)
    }

    pub fn set_quota(&self, user_id: &str, quota_bytes: i64) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        conn.execute(
            "INSERT INTO user_traffic (user_id, monthly_quota_bytes, last_reset_month) VALUES (?1, ?2, '')
             ON CONFLICT(user_id) DO UPDATE SET monthly_quota_bytes = ?2",
            params![user_id, quota_bytes],
        ).map_err(|e| format!("DB set quota: {e}"))?;
        Ok(())
    }

    pub fn get_quotas(&self) -> Result<Vec<UserQuota>, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        self.get_quotas_inner(&conn)
    }

    /// Read new lines from xray access log and store parsed connections.
    pub fn sync_access_log(&self, log_path: &str) -> Result<usize, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;

        // Get last read offset
        let last_offset: i64 = conn
            .query_row(
                "SELECT value FROM kv WHERE key = 'log_offset'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let file = fs::File::open(log_path).map_err(|e| format!("Cannot open access log: {e}"))?;
        let file_len = file.metadata().map(|m| m.len() as i64).unwrap_or(0);

        // If file is smaller than last offset, it was rotated/truncated
        let start = if file_len < last_offset { 0 } else { last_offset };

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(start as u64)).map_err(|e| format!("Seek failed: {e}"))?;

        let mut count = 0;
        let mut line = String::new();

        while reader.read_line(&mut line).map_err(|e| format!("Read failed: {e}"))? > 0 {
            if let Some(entry) = parse_access_line(&line) {
                conn.execute(
                    "INSERT INTO connection_logs (user_email, timestamp, client_ip, destination) VALUES (?1, ?2, ?3, ?4)",
                    params![entry.0, entry.1, entry.2, entry.3],
                ).map_err(|e| format!("DB insert log: {e}"))?;
                count += 1;
            }
            line.clear();
        }

        // Save new offset
        let new_offset = reader.stream_position().unwrap_or(file_len as u64) as i64;
        conn.execute(
            "INSERT INTO kv (key, value) VALUES ('log_offset', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1",
            params![new_offset],
        ).map_err(|e| format!("DB save offset: {e}"))?;

        // Keep only last 1000 entries per user to avoid unbounded growth
        conn.execute(
            "DELETE FROM connection_logs WHERE id NOT IN (SELECT id FROM connection_logs ORDER BY id DESC LIMIT 5000)",
            [],
        ).map_err(|_| "".to_string()).ok();

        Ok(count)
    }

    /// Get recent connection logs for a specific user, or all users.
    pub fn get_connections(&self, user_email: Option<&str>, limit: i64) -> Result<Vec<ConnectionLog>, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;

        let mut logs = Vec::new();

        if let Some(email) = user_email {
            let mut stmt = conn
                .prepare("SELECT id, user_email, timestamp, client_ip, destination FROM connection_logs WHERE user_email = ?1 ORDER BY id DESC LIMIT ?2")
                .map_err(|e| format!("DB prepare: {e}"))?;
            let rows = stmt.query_map(params![email, limit], |row| {
                Ok(ConnectionLog {
                    id: row.get(0)?,
                    user_email: row.get(1)?,
                    timestamp: row.get(2)?,
                    client_ip: row.get(3)?,
                    destination: row.get(4)?,
                })
            }).map_err(|e| format!("DB query: {e}"))?;
            for row in rows {
                logs.push(row.map_err(|e| format!("DB row: {e}"))?);
            }
        } else {
            let mut stmt = conn
                .prepare("SELECT id, user_email, timestamp, client_ip, destination FROM connection_logs ORDER BY id DESC LIMIT ?1")
                .map_err(|e| format!("DB prepare: {e}"))?;
            let rows = stmt.query_map(params![limit], |row| {
                Ok(ConnectionLog {
                    id: row.get(0)?,
                    user_email: row.get(1)?,
                    timestamp: row.get(2)?,
                    client_ip: row.get(3)?,
                    destination: row.get(4)?,
                })
            }).map_err(|e| format!("DB query: {e}"))?;
            for row in rows {
                logs.push(row.map_err(|e| format!("DB row: {e}"))?);
            }
        }

        Ok(logs)
    }

    pub fn delete_user(&self, user_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        conn.execute("DELETE FROM user_traffic WHERE user_id = ?1", params![user_id])
            .map_err(|e| format!("DB delete: {e}"))?;
        conn.execute("DELETE FROM connection_logs WHERE user_email = ?1", params![user_id])
            .map_err(|e| format!("DB delete logs: {e}"))?;
        Ok(())
    }

    fn get_quotas_inner(&self, conn: &Connection) -> Result<Vec<UserQuota>, String> {
        let mut stmt = conn
            .prepare("SELECT user_id, monthly_quota_bytes, used_this_month, last_reset_month FROM user_traffic")
            .map_err(|e| format!("DB prepare: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(UserQuota {
                    user_id: row.get(0)?,
                    monthly_quota_bytes: row.get(1)?,
                    used_this_month: row.get(2)?,
                    last_reset_month: row.get(3)?,
                })
            })
            .map_err(|e| format!("DB query: {e}"))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("DB row: {e}"))?);
        }
        Ok(result)
    }
}

/// Parse a single xray access log line.
/// Format: "2026/04/12 20:00:00 1.2.3.4:5678 accepted tcp:www.google.com:443 email: friend-1"
fn parse_access_line(line: &str) -> Option<(String, String, String, String)> {
    let line = line.trim();
    if line.is_empty() || !line.contains("accepted") {
        return None;
    }

    // Extract email
    let email = line.rsplit("email: ").next()?.trim().to_string();
    if email.is_empty() || email == line {
        return None;
    }

    // Extract timestamp (first 19 chars: "2026/04/12 20:00:00")
    if line.len() < 20 {
        return None;
    }
    let timestamp = line[..19].to_string();

    // Extract client IP (after timestamp, before "accepted")
    let after_ts = line[20..].trim();
    let client_ip = after_ts.split_whitespace().next().unwrap_or("").to_string();

    // Extract destination (after "accepted", before "email:")
    let dest = after_ts
        .split("accepted")
        .nth(1)?
        .split("email:")
        .next()?
        .trim()
        .to_string();

    Some((email, timestamp, client_ip, dest))
}
