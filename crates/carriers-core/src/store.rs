//! SQLite-backed membership and operational state.
//!
//! rusqlite is synchronous; the pipeline touches the store in short, non-awaiting bursts,
//! so a plain `Mutex<Connection>` is sufficient and avoids pulling in an async SQL runtime.

use std::path::Path;
use std::sync::Mutex;

use crate::error::Result;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS members (
    list    TEXT NOT NULL,
    address TEXT NOT NULL,
    PRIMARY KEY (list, address)
);
CREATE TABLE IF NOT EXISTS seen_messages (
    list       TEXT NOT NULL,
    message_id TEXT NOT NULL,
    seen_at    INTEGER NOT NULL,
    PRIMARY KEY (list, message_id)
);
";

pub struct Store {
    conn: Mutex<rusqlite::Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    pub fn add_member(&self, list: &str, address: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO members(list, address) VALUES(?1, ?2)",
            (list, address.trim().to_ascii_lowercase()),
        )?;
        Ok(())
    }

    pub fn remove_member(&self, list: &str, address: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "DELETE FROM members WHERE list = ?1 AND address = ?2",
            (list, address.trim().to_ascii_lowercase()),
        )?;
        Ok(())
    }

    pub fn is_member(&self, list: &str, address: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM members WHERE list = ?1 AND address = ?2",
            (list, address.trim().to_ascii_lowercase()),
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn members(&self, list: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT address FROM members WHERE list = ?1 ORDER BY address")?;
        let rows = stmt.query_map([list], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Record a `Message-ID` for loop/duplicate suppression.
    ///
    /// Returns `true` if it was newly inserted, `false` if we have already processed it.
    pub fn record_message(&self, list: &str, message_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let changed = conn.execute(
            "INSERT OR IGNORE INTO seen_messages(list, message_id, seen_at) \
             VALUES(?1, ?2, strftime('%s','now'))",
            (list, message_id),
        )?;
        Ok(changed > 0)
    }
}
