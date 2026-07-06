//! Membership access behind an async provider trait.
//!
//! Membership is read through [`MemberProvider`] so the source can change without touching
//! the pipeline. Today the only implementation is [`SqliteMemberProvider`] (backed by
//! [`Store`]); a future pull-based provider that queries an external member database over the
//! network can slot in here — the trait is already async — using the same SQLite store as its
//! offline cache.
//!
//! Two distinct roles are exposed: a *subscriber* receives the list, while a *member* is merely
//! recorded in the database and may be permitted to post without receiving (a superset of
//! subscribers). The posting policy decides which role is required to post directly.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;
use crate::store::{Member, Store};

#[async_trait]
pub trait MemberProvider: Send + Sync {
    /// True if the address is recorded for the list at all (subscriber or posting-only member).
    async fn is_member(&self, list: &str, address: &str) -> Result<bool>;
    /// True if the address is a subscriber (receives the list).
    async fn is_subscriber(&self, list: &str, address: &str) -> Result<bool>;
    /// Subscriber addresses to deliver to.
    async fn recipients(&self, list: &str) -> Result<Vec<String>>;
    /// Add a member; `subscribed` marks whether they receive the list, `moderator` the role.
    async fn add(&self, list: &str, address: &str, subscribed: bool, moderator: bool)
        -> Result<()>;
    async fn remove(&self, list: &str, address: &str) -> Result<()>;
    /// All members with their subscription state.
    async fn members(&self, list: &str) -> Result<Vec<Member>>;
}

pub struct SqliteMemberProvider {
    store: Arc<Store>,
}

impl SqliteMemberProvider {
    pub fn new(store: Arc<Store>) -> Self {
        SqliteMemberProvider { store }
    }

    /// Import subscriber addresses from a flat file (one per line, `#` comments and blanks
    /// ignored). Returns the number of addresses imported.
    pub async fn seed_from_file(&self, list: &str, path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(path)?;
        let mut n = 0;
        for line in text.lines() {
            let addr = line.trim();
            if addr.is_empty() || addr.starts_with('#') {
                continue;
            }
            self.store.add_member(list, addr, true, false).await?;
            n += 1;
        }
        Ok(n)
    }
}

#[async_trait]
impl MemberProvider for SqliteMemberProvider {
    async fn is_member(&self, list: &str, address: &str) -> Result<bool> {
        self.store.is_member(list, address).await
    }
    async fn is_subscriber(&self, list: &str, address: &str) -> Result<bool> {
        self.store.is_subscriber(list, address).await
    }
    async fn recipients(&self, list: &str) -> Result<Vec<String>> {
        self.store.subscribers(list).await
    }
    async fn add(
        &self,
        list: &str,
        address: &str,
        subscribed: bool,
        moderator: bool,
    ) -> Result<()> {
        self.store
            .add_member(list, address, subscribed, moderator)
            .await
    }
    async fn remove(&self, list: &str, address: &str) -> Result<()> {
        self.store.remove_member(list, address).await
    }
    async fn members(&self, list: &str) -> Result<Vec<Member>> {
        self.store.all_members(list).await
    }
}
