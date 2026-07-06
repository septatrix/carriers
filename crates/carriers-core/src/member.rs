//! Membership access behind a provider trait.
//!
//! Membership is read through [`MemberProvider`] so the source can change without touching
//! the pipeline. Today the only implementation is [`SqliteMemberProvider`] (backed by
//! [`Store`]); a future pull-based provider that queries an external member database can slot
//! in here, using the same SQLite store as its offline cache.

use std::path::Path;
use std::sync::Arc;

use crate::error::Result;
use crate::store::Store;

pub trait MemberProvider: Send + Sync {
    fn is_member(&self, list: &str, address: &str) -> Result<bool>;
    fn recipients(&self, list: &str) -> Result<Vec<String>>;
    fn add(&self, list: &str, address: &str) -> Result<()>;
    fn remove(&self, list: &str, address: &str) -> Result<()>;
}

pub struct SqliteMemberProvider {
    store: Arc<Store>,
}

impl SqliteMemberProvider {
    pub fn new(store: Arc<Store>) -> Self {
        SqliteMemberProvider { store }
    }

    /// Import addresses from a flat file (one per line, `#` comments and blanks ignored).
    /// Returns the number of addresses imported.
    pub fn seed_from_file(&self, list: &str, path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(path)?;
        let mut n = 0;
        for line in text.lines() {
            let addr = line.trim();
            if addr.is_empty() || addr.starts_with('#') {
                continue;
            }
            self.store.add_member(list, addr)?;
            n += 1;
        }
        Ok(n)
    }
}

impl MemberProvider for SqliteMemberProvider {
    fn is_member(&self, list: &str, address: &str) -> Result<bool> {
        self.store.is_member(list, address)
    }
    fn recipients(&self, list: &str) -> Result<Vec<String>> {
        self.store.members(list)
    }
    fn add(&self, list: &str, address: &str) -> Result<()> {
        self.store.add_member(list, address)
    }
    fn remove(&self, list: &str, address: &str) -> Result<()> {
        self.store.remove_member(list, address)
    }
}
