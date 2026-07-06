//! Per-list configuration and the loaded [`List`] with its DKIM signer and ARC sealer.

use serde::Deserialize;
use std::path::{Path, PathBuf};

use mail_auth::arc::ArcSealer;
use mail_auth::common::crypto::DkimKey;
use mail_auth::dkim::{DkimSigner, Done};

use crate::crypto::load_dkim_key;
use crate::error::{Error, Result};

/// Headers covered by our own DKIM signature and the ARC message signature.
///
/// This deliberately excludes `DKIM-Signature` and the `ARC-*` headers so the two
/// signatures stay independent, and it includes the `List-*` headers we add so they
/// are protected. The author's *original* DKIM signature is never recomputed — we only
/// prepend headers — so it stays valid and DMARC passes at the receiver via DKIM alignment.
pub const SIGNED_HEADERS: &[&str] = &[
    "From",
    "Sender",
    "Reply-To",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "List-Id",
    "List-Post",
    "List-Unsubscribe",
    "List-Subscribe",
    "List-Help",
    "List-Archive",
    "List-Owner",
];

#[derive(Debug, Clone, Deserialize)]
pub struct ListConfig {
    /// Posting address, e.g. `dev@lists.example.org`.
    pub posting_address: String,

    /// Human-readable description used in `List-Id`.
    #[serde(default)]
    pub display_name: Option<String>,

    /// `List-Id` namespace (RFC 2919), e.g. `dev.lists.example.org`.
    /// Defaults to the posting address with `@` replaced by `.`.
    #[serde(default)]
    pub list_id: Option<String>,

    /// Owner address, published as `List-Owner`.
    #[serde(default)]
    pub owner: Option<String>,

    #[serde(default)]
    pub archive_url: Option<String>,
    #[serde(default)]
    pub help_url: Option<String>,
    #[serde(default)]
    pub subscribe_url: Option<String>,
    #[serde(default)]
    pub unsubscribe_url: Option<String>,

    /// One-click unsubscribe target (RFC 8058). When set, a `List-Unsubscribe` plus
    /// `List-Unsubscribe-Post: List-Unsubscribe=One-Click` pair is emitted, as required by
    /// Google/Yahoo bulk-sender rules.
    #[serde(default)]
    pub unsubscribe_oneclick: Option<String>,

    /// DKIM signing key for the list domain.
    pub dkim: KeyConfig,
    /// ARC sealing key for the list domain.
    pub arc: KeyConfig,

    #[serde(default)]
    pub policy: Policy,

    /// Optional flat member seed file (one address per line, `#` comments), imported into
    /// SQLite on `carriers list sync`.
    #[serde(default)]
    pub members_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyConfig {
    pub selector: String,
    pub key_file: PathBuf,
    #[serde(default)]
    pub algorithm: Algorithm,
    /// Signing domain. Defaults to the posting address domain (keeps it aligned).
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    #[default]
    Rsa,
    Ed25519,
}

/// Who may post to a list, and what happens to posts from anyone else.
///
/// Under `Subscribers` and `Members`, a post from a sender who is *not* permitted is held for
/// moderation rather than dropped, so a moderator can approve it. `Moderated` holds every post.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PostingPolicy {
    /// Anyone may post; nothing is moderated (an open list).
    Open,
    /// Subscribers (addresses that receive the list) may post directly; others are held.
    #[default]
    Subscribers,
    /// Any address recorded in the member database may post directly (a superset of
    /// subscribers, since a member need not be subscribed to receive mail); others are held.
    Members,
    /// Every post is held for moderation, regardless of sender.
    Moderated,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    /// Who may post, and how non-permitted posts are handled. Used when `sieve` is unset.
    #[serde(default)]
    pub posting: PostingPolicy,

    /// Name of a Sieve moderation policy (a `<name>.sieve` file in `policies_dir`). When set,
    /// it decides approve/moderate/reject and takes precedence over `posting`.
    #[serde(default)]
    pub sieve: Option<String>,
}

/// A loaded mailing list, with its signer and sealer constructed once at load time.
pub struct List {
    pub name: String,
    pub cfg: ListConfig,
    /// Domain of the posting address (e.g. `lists.example.org`).
    pub domain: String,
    signer: DkimSigner<DkimKey, Done>,
    sealer: ArcSealer<DkimKey, Done>,
}

impl List {
    /// Load `<name>.toml` from `path`, parsing keys and building the signer/sealer.
    pub fn load(name: &str, path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let cfg: ListConfig = toml::from_str(&text)?;
        Self::from_config(name, cfg)
    }

    pub fn from_config(name: &str, cfg: ListConfig) -> Result<Self> {
        let domain = cfg
            .posting_address
            .rsplit('@')
            .next()
            .filter(|d| !d.is_empty() && d.len() < cfg.posting_address.len())
            .ok_or_else(|| {
                Error::Config(format!("invalid posting_address `{}`", cfg.posting_address))
            })?
            .to_string();

        let signer = DkimSigner::from_key(load_dkim_key(&cfg.dkim)?)
            .domain(cfg.dkim.domain.clone().unwrap_or_else(|| domain.clone()))
            .selector(cfg.dkim.selector.clone())
            .headers(SIGNED_HEADERS.iter().map(|s| s.to_string()));

        let sealer = ArcSealer::from_key(load_dkim_key(&cfg.arc)?)
            .domain(cfg.arc.domain.clone().unwrap_or_else(|| domain.clone()))
            .selector(cfg.arc.selector.clone())
            .headers(SIGNED_HEADERS.iter().map(|s| s.to_string()));

        Ok(List {
            name: name.to_string(),
            cfg,
            domain,
            signer,
            sealer,
        })
    }

    pub fn signer(&self) -> &DkimSigner<DkimKey, Done> {
        &self.signer
    }

    pub fn sealer(&self) -> &ArcSealer<DkimKey, Done> {
        &self.sealer
    }

    /// The `List-Id` namespace used for this list.
    pub fn list_id(&self) -> String {
        self.cfg
            .list_id
            .clone()
            .unwrap_or_else(|| self.cfg.posting_address.replace('@', "."))
    }
}
