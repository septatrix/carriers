//! Shared, immutable-after-startup application state.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

use carriers_core::MessageAuthenticator;
use carriers_core::config::Config;
use carriers_core::list::List;
use carriers_core::member::{MemberProvider, SqliteMemberProvider};
use carriers_core::policy::PolicyEngine;
use carriers_core::store::Store;

pub struct AppState {
    pub config: Config,
    pub authenticator: MessageAuthenticator,
    pub store: Arc<Store>,
    pub members: Arc<dyn MemberProvider>,
    /// Sieve moderation policies: the built-ins plus any custom scripts from `policies_dir`.
    pub policy: PolicyEngine,
    /// Lists keyed by their lowercased posting address.
    pub lists: HashMap<String, Arc<List>>,
}

impl AppState {
    /// Assemble the shared state. The DNS resolver used for inbound authentication is injected
    /// as `authenticator` so callers choose the resolver: the daemon passes one built from the
    /// system configuration, while tests (`carriers-testkit`) pass one aimed at a mock resolver.
    pub async fn load(config: Config, authenticator: MessageAuthenticator) -> Result<Self> {
        let store = Arc::new(
            Store::open(&config.db_path)
                .await
                .with_context(|| format!("opening database {}", config.db_path.display()))?,
        );
        let members: Arc<dyn MemberProvider> = Arc::new(SqliteMemberProvider::new(store.clone()));

        let policy = load_policy_engine(&config)?;
        info!(
            custom_policies = policy.names().count(),
            global_before = config.global_policy.before.is_some(),
            global_after = config.global_policy.after.is_some(),
            domains = config.global_policy.domains.len(),
            "loaded policies"
        );

        let lists = load_lists(&config)?;
        info!(count = lists.len(), "loaded lists");
        validate_policies(&lists, &policy)?;

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

/// Compile the policy engine named by `config`: built-ins, any custom scripts in
/// `policies_dir`, and the global/domain scripts from `config.global_policy`.
pub fn load_policy_engine(config: &Config) -> Result<PolicyEngine> {
    let mut policy = match &config.policies_dir {
        Some(dir) => PolicyEngine::load(dir)
            .with_context(|| format!("loading Sieve policies from {}", dir.display()))?,
        None => PolicyEngine::new().context("compiling built-in policies")?,
    };
    if let Some(path) = &config.global_policy.before {
        policy = policy
            .with_global_before(path)
            .with_context(|| format!("loading global before-policy {}", path.display()))?;
    }
    if let Some(path) = &config.global_policy.after {
        policy = policy
            .with_global_after(path)
            .with_context(|| format!("loading global after-policy {}", path.display()))?;
    }
    for (domain, scripts) in &config.global_policy.domains {
        if let Some(path) = &scripts.before {
            policy = policy.with_domain_before(domain, path).with_context(|| {
                format!("loading domain `{domain}` before-policy {}", path.display())
            })?;
        }
        if let Some(path) = &scripts.after {
            policy = policy.with_domain_after(domain, path).with_context(|| {
                format!("loading domain `{domain}` after-policy {}", path.display())
            })?;
        }
    }
    Ok(policy)
}

/// Fail fast if a list references a policy name that was not loaded (built-in or custom).
fn validate_policies(lists: &HashMap<String, Arc<List>>, policy: &PolicyEngine) -> Result<()> {
    for list in lists.values() {
        if !policy.contains(&list.cfg.policy) {
            anyhow::bail!(
                "list `{}` references unknown policy `{}`",
                list.name,
                list.cfg.policy
            );
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
