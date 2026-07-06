//! SQLite-backed membership and operational state, using sqlx (async, typed, pooled).

use std::path::Path;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

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
    pool: SqlitePool,
}

impl Store {
    /// Open (creating if necessary) a file-backed database and apply the schema.
    pub async fn open(path: &Path) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new().connect_with(options).await?;
        Self::init(pool).await
    }

    /// Open a private in-memory database (used by tests). A single connection keeps the
    /// in-memory database alive and shared across queries.
    pub async fn open_in_memory() -> Result<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        Self::init(pool).await
    }

    async fn init(pool: SqlitePool) -> Result<Self> {
        sqlx::raw_sql(SCHEMA).execute(&pool).await?;
        Ok(Store { pool })
    }

    pub async fn add_member(&self, list: &str, address: &str) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO members(list, address) VALUES(?, ?)")
            .bind(list)
            .bind(address.trim().to_ascii_lowercase())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn remove_member(&self, list: &str, address: &str) -> Result<()> {
        sqlx::query("DELETE FROM members WHERE list = ? AND address = ?")
            .bind(list)
            .bind(address.trim().to_ascii_lowercase())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn is_member(&self, list: &str, address: &str) -> Result<bool> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM members WHERE list = ? AND address = ?")
                .bind(list)
                .bind(address.trim().to_ascii_lowercase())
                .fetch_one(&self.pool)
                .await?;
        Ok(count > 0)
    }

    pub async fn members(&self, list: &str) -> Result<Vec<String>> {
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT address FROM members WHERE list = ? ORDER BY address")
                .bind(list)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows)
    }

    /// Record a `Message-ID` for loop/duplicate suppression.
    ///
    /// Returns `true` if it was newly inserted, `false` if we have already processed it.
    pub async fn record_message(&self, list: &str, message_id: &str) -> Result<bool> {
        let result = sqlx::query(
            "INSERT OR IGNORE INTO seen_messages(list, message_id, seen_at) \
             VALUES(?, ?, strftime('%s','now'))",
        )
        .bind(list)
        .bind(message_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
