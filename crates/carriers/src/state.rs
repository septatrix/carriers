//! Shared, immutable-after-startup application state.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

use carriers_core::config::Config;
use carriers_core::list::List;
use carriers_core::member::{MemberProvider, SqliteMemberProvider};
use carriers_core::policy::PolicyEngine;
use carriers_core::store::Store;
use carriers_core::MessageAuthenticator;

pub struct AppState {
    pub config: Config,
    pub authenticator: MessageAuthenticator,
    pub store: Arc<Store>,
    pub members: Arc<dyn MemberProvider>,
    /// Compiled Sieve moderation policies, if a policies directory is configured.
    pub policy: Option<PolicyEngine>,
    /// Lists keyed by their lowercased posting address.
    pub lists: HashMap<String, Arc<List>>,
}

impl AppState {
    pub async fn load(config: Config) -> Result<Self> {
        let store = Arc::new(
            Store::open(&config.db_path)
                .await
                .with_context(|| format!("opening database {}", config.db_path.display()))?,
        );
        let members: Arc<dyn MemberProvider> = Arc::new(SqliteMemberProvider::new(store.clone()));
        let authenticator = MessageAuthenticator::new_system_conf()
            .context("initialising DNS resolver from system configuration")?;

        let policy = match &config.policies_dir {
            Some(dir) => {
                let engine = PolicyEngine::load(dir)
                    .with_context(|| format!("loading Sieve policies from {}", dir.display()))?;
                info!(count = engine.names().count(), "loaded Sieve policies");
                Some(engine)
            }
            None => None,
        };

        let lists = load_lists(&config)?;
        info!(count = lists.len(), "loaded lists");
        validate_policies(&lists, policy.as_ref())?;

        Ok(AppState {
            config,
            authenticator,
            store,
            members,
            policy,
            lists,
        })
    }

    /// Find a list by an incoming recipient address (case-insensitive).
    pub fn list_for_address(&self, address: &str) -> Option<&Arc<List>> {
        self.lists.get(&address.trim().to_ascii_lowercase())
    }

    /// Find a loaded list by its short name (the `<name>.toml` stem).
    pub fn list_by_name(&self, name: &str) -> Option<&Arc<List>> {
        self.lists.values().find(|list| list.name == name)
    }
}

/// Fail fast if a list references a Sieve policy that was not loaded.
fn validate_policies(
    lists: &HashMap<String, Arc<List>>,
    policy: Option<&PolicyEngine>,
) -> Result<()> {
    for list in lists.values() {
        if let Some(name) = &list.cfg.policy.sieve {
            match policy {
                Some(engine) if engine.contains(name) => {}
                Some(_) => anyhow::bail!(
                    "list `{}` references unknown Sieve policy `{name}`",
                    list.name
                ),
                None => anyhow::bail!(
                    "list `{}` references Sieve policy `{name}` but no policies_dir is configured",
                    list.name
                ),
            }
        }
    }
    Ok(())
}

/// Load every `<name>.toml` from the configured lists directory.
pub fn load_lists(config: &Config) -> Result<HashMap<String, Arc<List>>> {
    let mut lists = HashMap::new();
    if !config.lists_dir.is_dir() {
        return Ok(lists);
    }
    for entry in std::fs::read_dir(&config.lists_dir)
        .with_context(|| format!("reading lists dir {}", config.lists_dir.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let list =
            List::load(&name, &path).with_context(|| format!("loading list {}", path.display()))?;
        lists.insert(
            list.cfg.posting_address.to_ascii_lowercase(),
            Arc::new(list),
        );
    }
    Ok(lists)
}
