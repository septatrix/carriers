//! Global daemon configuration, loaded from `carriers.toml`.

use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::error::Result;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Hostname of this host. Used as the EHLO/LHLO name, in `Authentication-Results`,
    /// and as the `helo` identity when checking inbound SPF.
    pub hostname: String,

    /// Address to listen on for inbound LMTP/SMTP.
    pub listen: SocketAddr,

    /// Ingress protocol spoken on the listener.
    #[serde(default)]
    pub protocol: Protocol,

    /// Where outbound copies are relayed. A local MTA (Postfix/Exim) is the intended target;
    /// it owns queueing, retries, MX resolution and outbound TLS.
    pub smarthost: Smarthost,

    /// Path to the SQLite database (membership + operational state).
    pub db_path: PathBuf,

    /// Directory containing per-list `<name>.toml` files.
    pub lists_dir: PathBuf,

    /// Directory of custom Sieve moderation policies (`<name>.sieve`). Required only if any
    /// list's `policy` names a custom script rather than a built-in policy.
    #[serde(default)]
    pub policies_dir: Option<PathBuf>,

    /// Directory under which archived posts are written, as `<archive_dir>/<list>/<file>.eml`,
    /// when a policy files a message into the `archive` pseudo-mailbox
    /// (`fileinto :copy "archive"`). If unset, such a `fileinto` is a no-op.
    #[serde(default)]
    pub archive_dir: Option<PathBuf>,

    /// Global and per-domain Sieve scripts run around every list's own `policy` — see the
    /// README's "Global policy" section.
    #[serde(default)]
    pub global_policy: GlobalPolicyConfig,

    /// Bounce-handling thresholds.
    #[serde(default)]
    pub bounce: BounceConfig,
}

/// Sieve scripts that run for every list, before and/or after that list's own `policy` — see
/// [`crate::policy::PolicyEngine`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalPolicyConfig {
    /// Runs ahead of every list's own policy, regardless of the list's domain. Optional: if
    /// unset, [`Config::load`] falls back to a `global-before.sieve` file next to this config
    /// file, if one exists.
    #[serde(default)]
    pub before: Option<PathBuf>,

    /// Runs after every list's own policy, regardless of the list's domain. Optional: if unset,
    /// [`Config::load`] falls back to a `global-after.sieve` file next to this config file, if
    /// one exists.
    #[serde(default)]
    pub after: Option<PathBuf>,

    /// Additional before/after scripts scoped to one list domain (e.g. `lists.example.com`),
    /// keyed by that domain. These run in addition to `before`/`after` above, closer to the
    /// list's own policy: `before` (global) -> `before` (this domain) -> the list's own policy
    /// -> `after` (this domain) -> `after` (global). Unlike `before`/`after` above, there is no
    /// sibling-file auto-discovery for these — they must be configured explicitly.
    #[serde(default)]
    pub domains: HashMap<String, DomainPolicyConfig>,
}

/// Before/after Sieve scripts scoped to one list domain — see [`GlobalPolicyConfig::domains`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainPolicyConfig {
    #[serde(default)]
    pub before: Option<PathBuf>,
    #[serde(default)]
    pub after: Option<PathBuf>,
}

/// Controls when a repeatedly-bouncing subscriber has delivery disabled.
///
/// Each bounce adds a weight to the subscriber's running score; when the score reaches
/// `threshold`, delivery to that address is disabled until an operator re-enables it with
/// `carriers member enable`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BounceConfig {
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    /// Weight added for a permanent (`5.x.x`) failure.
    #[serde(default = "default_hard_weight")]
    pub hard_weight: f64,
    /// Weight added for a transient (`4.x.x`) failure.
    #[serde(default = "default_soft_weight")]
    pub soft_weight: f64,
}

impl Default for BounceConfig {
    fn default() -> Self {
        BounceConfig {
            threshold: default_threshold(),
            hard_weight: default_hard_weight(),
            soft_weight: default_soft_weight(),
        }
    }
}

fn default_threshold() -> f64 {
    5.0
}
fn default_hard_weight() -> f64 {
    3.0
}
fn default_soft_weight() -> f64 {
    1.0
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// LMTP (RFC 2033) — the intended mode when a front MTA relays to carriers.
    #[default]
    Lmtp,
    /// Plain ESMTP.
    Smtp,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Smarthost {
    pub host: String,
    #[serde(default = "default_smarthost_port")]
    pub port: u16,
    /// Use implicit TLS (SMTPS) when connecting to the smarthost.
    #[serde(default)]
    pub implicit_tls: bool,
    /// Permit plaintext delivery to the smarthost. Only sensible for a trusted local relay
    /// (e.g. `127.0.0.1`), where the hop never leaves the host.
    #[serde(default)]
    pub allow_plaintext: bool,
}

fn default_smarthost_port() -> u16 {
    25
}

impl Config {
    /// Load and parse `path`. If `global_policy.before`/`.after` are not set, `global.sieve` /
    /// `global-after.sieve` files next to `path` are used automatically if present.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&text)?;
        if config.global_policy.before.is_none() {
            let sibling = path.with_file_name("global-before.sieve");
            if sibling.is_file() {
                config.global_policy.before = Some(sibling);
            }
        }
        if config.global_policy.after.is_none() {
            let sibling = path.with_file_name("global-after.sieve");
            if sibling.is_file() {
                config.global_policy.after = Some(sibling);
            }
        }
        Ok(config)
    }
}
