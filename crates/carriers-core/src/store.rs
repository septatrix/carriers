//! SQLite-backed membership, moderation queue and operational state, using sqlx.
//!
//! Schema changes live in `migrations/` (embedded into the binary at compile time via
//! [`sqlx::migrate!`]) and are applied automatically, and tracked in sqlx's own
//! `_sqlx_migrations` table, whenever a [`Store`] is opened.

use std::path::Path;
use std::str::FromStr;

use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

use crate::error::Result;

static MIGRATOR: Migrator = sqlx::migrate!();

/// A member of a list, with their roles and bounce state.
///
/// The three roles are independent flags, not a hierarchy: a subscriber is not automatically a
/// poster, and a poster is not automatically a subscriber. An address can hold any combination.
pub struct Member {
    pub address: String,
    /// True if the member receives the list (a subscriber).
    pub subscribed: bool,
    /// True if the member may post directly under the `posters` policy (see
    /// [`crate::policy`]), independent of whether they are subscribed.
    pub poster: bool,
    /// True if the member is a moderator of the list.
    pub moderator: bool,
    /// Running bounce score.
    pub bounce_score: f64,
    /// True if delivery has been disabled due to bounces.
    pub bounce_disabled: bool,
}

/// A summary row of the moderation queue (without the message body).
pub struct HeldSummary {
    pub id: i64,
    pub list: String,
    pub sender: Option<String>,
    pub subject: Option<String>,
    pub received_at: i64,
}

/// Row shape returned by the moderation-queue summary query.
type HeldRow = (i64, String, Option<String>, Option<String>, i64);

/// Row shape returned by the member query: (address, subscribed, poster, moderator, score,
/// disabled).
type MemberRow = (String, i64, i64, i64, f64, i64);

/// A full held message, including everything needed to distribute it on approval.
pub struct HeldMessage {
    pub id: i64,
    pub list: String,
    pub mail_from: String,
    pub helo: String,
    pub remote_ip: String,
    pub raw: Vec<u8>,
}

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
        MIGRATOR.run(&pool).await.map_err(sqlx::Error::from)?;
        Ok(Store { pool })
    }

    // --- Membership ---------------------------------------------------------------------

    /// Add a member with the given independent roles (see [`Member`]). Re-adding updates all
    /// three roles.
    pub async fn add_member(
        &self,
        list: &str,
        address: &str,
        subscribed: bool,
        poster: bool,
        moderator: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO members(list, address, subscribed, poster, moderator) \
             VALUES(?, ?, ?, ?, ?) \
             ON CONFLICT(list, address) DO UPDATE SET \
                 subscribed = excluded.subscribed, \
                 poster = excluded.poster, \
                 moderator = excluded.moderator",
        )
        .bind(list)
        .bind(address.trim().to_ascii_lowercase())
        .bind(subscribed as i64)
        .bind(poster as i64)
        .bind(moderator as i64)
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

    /// True if the address is recorded for the list at all, under any role.
    pub async fn is_member(&self, list: &str, address: &str) -> Result<bool> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM members WHERE list = ? AND address = ?")
                .bind(list)
                .bind(address.trim().to_ascii_lowercase())
                .fetch_one(&self.pool)
                .await?;
        Ok(count > 0)
    }

    /// True if the address is a subscriber of the list (receives mail).
    pub async fn is_subscriber(&self, list: &str, address: &str) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM members WHERE list = ? AND address = ? AND subscribed = 1",
        )
        .bind(list)
        .bind(address.trim().to_ascii_lowercase())
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }

    /// True if the address is a poster of the list (may post directly under the `posters`
    /// policy), independent of whether it is also a subscriber.
    pub async fn is_poster(&self, list: &str, address: &str) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM members WHERE list = ? AND address = ? AND poster = 1",
        )
        .bind(list)
        .bind(address.trim().to_ascii_lowercase())
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }

    /// Deliverable subscriber addresses: subscribed and not bounce-disabled.
    pub async fn subscribers(&self, list: &str) -> Result<Vec<String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT address FROM members \
             WHERE list = ? AND subscribed = 1 AND bounce_disabled = 0 ORDER BY address",
        )
        .bind(list)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// All members of the list with their roles and bounce state.
    pub async fn all_members(&self, list: &str) -> Result<Vec<Member>> {
        let rows: Vec<MemberRow> = sqlx::query_as(
            "SELECT address, subscribed, poster, moderator, bounce_score, bounce_disabled \
             FROM members WHERE list = ? ORDER BY address",
        )
        .bind(list)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(address, subscribed, poster, moderator, bounce_score, bounce_disabled)| Member {
                    address,
                    subscribed: subscribed != 0,
                    poster: poster != 0,
                    moderator: moderator != 0,
                    bounce_score,
                    bounce_disabled: bounce_disabled != 0,
                },
            )
            .collect())
    }

    /// Record a bounce for a subscriber, adding `weight` to their score and disabling delivery
    /// once the score reaches `threshold`.
    ///
    /// Returns `None` if the address is not a member of the list, otherwise `Some(disabled)`
    /// reflecting whether delivery is now disabled.
    pub async fn record_bounce(
        &self,
        list: &str,
        address: &str,
        weight: f64,
        threshold: f64,
    ) -> Result<Option<bool>> {
        let disabled: Option<i64> = sqlx::query_scalar(
            "UPDATE members SET \
                 bounce_score = bounce_score + ?3, \
                 last_bounce_at = strftime('%s','now'), \
                 bounce_disabled = CASE WHEN bounce_score + ?3 >= ?4 THEN 1 ELSE bounce_disabled END \
             WHERE list = ?1 AND address = ?2 \
             RETURNING bounce_disabled",
        )
        .bind(list)
        .bind(address.trim().to_ascii_lowercase())
        .bind(weight)
        .bind(threshold)
        .fetch_optional(&self.pool)
        .await?;
        Ok(disabled.map(|d| d != 0))
    }

    /// Clear a member's bounce state and re-enable delivery.
    pub async fn enable_member(&self, list: &str, address: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE members SET bounce_score = 0, bounce_disabled = 0, last_bounce_at = NULL \
             WHERE list = ? AND address = ?",
        )
        .bind(list)
        .bind(address.trim().to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // --- Deduplication ------------------------------------------------------------------

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

    // --- Moderation queue ---------------------------------------------------------------

    /// Store a message held for moderation. Returns the new queue id.
    #[allow(clippy::too_many_arguments)]
    pub async fn enqueue_held(
        &self,
        list: &str,
        mail_from: &str,
        helo: &str,
        remote_ip: &str,
        sender: Option<&str>,
        subject: Option<&str>,
        raw: &[u8],
    ) -> Result<i64> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO moderation_queue(list, mail_from, helo, remote_ip, sender, subject, raw, received_at) \
             VALUES(?, ?, ?, ?, ?, ?, ?, strftime('%s','now')) RETURNING id",
        )
        .bind(list)
        .bind(mail_from)
        .bind(helo)
        .bind(remote_ip)
        .bind(sender)
        .bind(subject)
        .bind(raw)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// List held messages, optionally filtered to a single list.
    pub async fn held_messages(&self, list: Option<&str>) -> Result<Vec<HeldSummary>> {
        let rows: Vec<HeldRow> = match list {
            Some(list) => {
                sqlx::query_as(
                    "SELECT id, list, sender, subject, received_at FROM moderation_queue \
                 WHERE list = ? ORDER BY id",
                )
                .bind(list)
                .fetch_all(&self.pool)
                .await?
            }
            None => sqlx::query_as(
                "SELECT id, list, sender, subject, received_at FROM moderation_queue ORDER BY id",
            )
            .fetch_all(&self.pool)
            .await?,
        };
        Ok(rows
            .into_iter()
            .map(|(id, list, sender, subject, received_at)| HeldSummary {
                id,
                list,
                sender,
                subject,
                received_at,
            })
            .collect())
    }

    /// Fetch a full held message by id.
    pub async fn get_held(&self, id: i64) -> Result<Option<HeldMessage>> {
        let row: Option<(i64, String, String, String, String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, list, mail_from, helo, remote_ip, raw FROM moderation_queue WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(
            row.map(|(id, list, mail_from, helo, remote_ip, raw)| HeldMessage {
                id,
                list,
                mail_from,
                helo,
                remote_ip,
                raw,
            }),
        )
    }

    /// Remove a held message from the queue. Returns true if a row was deleted.
    pub async fn delete_held(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM moderation_queue WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}
