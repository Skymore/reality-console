use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

const DEFAULT_MONTHLY_QUOTA: i64 = 53_687_091_200; // 50 GB

pub struct Db {
    conn: Mutex<Connection>,
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
            );"
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

    pub fn delete_user(&self, user_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock: {e}"))?;
        conn.execute("DELETE FROM user_traffic WHERE user_id = ?1", params![user_id])
            .map_err(|e| format!("DB delete: {e}"))?;
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
