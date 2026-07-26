//! Membership access behind an async provider trait.
//!
//! Membership is read through [`MemberProvider`] so the source can change without touching
//! the pipeline. Today the only implementation is [`SqliteMemberProvider`] (backed by
//! [`Store`]); a future pull-based provider that queries an external member database over the
//! network can slot in here — the trait is already async — using the same SQLite store as its
//! offline cache.
//!
//! Three roles are exposed, each an independent flag rather than a hierarchy: a *subscriber*
//! receives the list; a *poster* may post directly under the `posters` policy (see
//! [`crate::policy`]); a *moderator* is exposed to Sieve policies as the `moderators` list.
//! None of these implies another — subscribing does not grant posting rights, and being a
//! poster does not imply receiving the list.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;
use crate::store::{Member, Store};

#[async_trait]
pub trait MemberProvider: Send + Sync {
    /// True if the address is recorded for the list at all, under any role.
    async fn is_member(&self, list: &str, address: &str) -> Result<bool>;
    /// True if the address is a subscriber (receives the list).
    async fn is_subscriber(&self, list: &str, address: &str) -> Result<bool>;
    /// True if the address is a poster (may post directly), independent of subscription.
    async fn is_poster(&self, list: &str, address: &str) -> Result<bool>;
    /// Subscriber addresses to deliver to.
    async fn recipients(&self, list: &str) -> Result<Vec<String>>;
    /// Add a member with the given independent roles (see the module docs).
    async fn add(
        &self,
        list: &str,
        address: &str,
        subscribed: bool,
        poster: bool,
        moderator: bool,
    ) -> Result<()>;
    async fn remove(&self, list: &str, address: &str) -> Result<()>;
    /// All members with their roles.
    async fn members(&self, list: &str) -> Result<Vec<Member>>;
}

pub struct SqliteMemberProvider {
    store: Arc<Store>,
}

impl SqliteMemberProvider {
    pub fn new(store: Arc<Store>) -> Self {
        SqliteMemberProvider { store }
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
    async fn is_poster(&self, list: &str, address: &str) -> Result<bool> {
        self.store.is_poster(list, address).await
    }
    async fn recipients(&self, list: &str) -> Result<Vec<String>> {
        self.store.subscribers(list).await
    }
    async fn add(
        &self,
        list: &str,
        address: &str,
        subscribed: bool,
        poster: bool,
        moderator: bool,
    ) -> Result<()> {
        self.store
            .add_member(list, address, subscribed, poster, moderator)
            .await
    }
    async fn remove(&self, list: &str, address: &str) -> Result<()> {
        self.store.remove_member(list, address).await
    }
    async fn members(&self, list: &str) -> Result<Vec<Member>> {
        self.store.all_members(list).await
    }
}
