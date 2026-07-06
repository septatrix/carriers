//! Global daemon configuration, loaded from `carriers.toml`.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::error::Result;

#[derive(Debug, Clone, Deserialize)]
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

    /// Directory of Sieve moderation policies (`<name>.sieve`). Required only if any list
    /// selects a `[policy] sieve` script.
    #[serde(default)]
    pub policies_dir: Option<PathBuf>,

    /// Bounce-handling thresholds.
    #[serde(default)]
    pub bounce: BounceConfig,
}

/// Controls when a repeatedly-bouncing subscriber has delivery disabled.
///
/// Each bounce adds a weight to the subscriber's running score; when the score reaches
/// `threshold`, delivery to that address is disabled until an operator re-enables it with
/// `carriers member enable`.
#[derive(Debug, Clone, Deserialize)]
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
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }
}
