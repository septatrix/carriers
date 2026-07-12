//! Per-list configuration and the loaded [`List`] with its DKIM signer and ARC sealer.

use serde::Deserialize;
use std::path::{Path, PathBuf};

use mail_auth::arc::ArcSealer;
use mail_auth::common::crypto::DkimKey;
use mail_auth::dkim::{DkimSigner, Done};
use mail_auth::dkim2::{Dkim2Signer, Done as Dkim2Done};

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
#[serde(deny_unknown_fields)]
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
    /// DKIM2 signing key for the list domain (draft-ietf-dkim-dkim2-spec), configured like
    /// `dkim`/`arc` above. Whether it is actually used is not a config choice: carriers only ever
    /// extends a DKIM2 chain the inbound message already carried, never originates one — see
    /// `sign::should_sign_dkim2`.
    pub dkim2: KeyConfig,

    /// The moderation policy: either a built-in name (see [`crate::policy`]) or the name of a
    /// custom `<name>.sieve` file in `policies_dir`. Built-in and custom policies are compiled
    /// into the same [`crate::policy::PolicyEngine`] and looked up by this one name — there is
    /// no separate configuration shape for "use a built-in mode" vs. "use a custom script".
    #[serde(default = "default_policy")]
    pub policy: String,

    /// Optional flat member seed file (one address per line, `#` comments), imported into
    /// SQLite on `carriers list sync`.
    #[serde(default)]
    pub members_file: Option<PathBuf>,
}

fn default_policy() -> String {
    crate::policy::BUILTIN_SUBSCRIBERS.to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// A loaded mailing list, with its signer and sealer constructed once at load time.
pub struct List {
    pub name: String,
    pub cfg: ListConfig,
    /// Domain of the posting address (e.g. `lists.example.org`).
    pub domain: String,
    signer: DkimSigner<DkimKey, Done>,
    sealer: ArcSealer<DkimKey, Done>,
    dkim2_signer: Dkim2Signer<Dkim2Done>,
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

        let dkim2_signer = Dkim2Signer::from_key(load_dkim_key(&cfg.dkim2)?)
            .domain(cfg.dkim2.domain.clone().unwrap_or_else(|| domain.clone()))
            .selector(cfg.dkim2.selector.clone());

        Ok(List {
            name: name.to_string(),
            cfg,
            domain,
            signer,
            sealer,
            dkim2_signer,
        })
    }

    pub fn signer(&self) -> &DkimSigner<DkimKey, Done> {
        &self.signer
    }

    pub fn sealer(&self) -> &ArcSealer<DkimKey, Done> {
        &self.sealer
    }

    /// The list's DKIM2 signer. Whether it is actually used for a given delivery is decided
    /// per-message — see [`crate::sign::should_sign_dkim2`].
    pub fn dkim2_signer(&self) -> &Dkim2Signer<Dkim2Done> {
        &self.dkim2_signer
    }

    /// The `List-Id` namespace used for this list.
    pub fn list_id(&self) -> String {
        self.cfg
            .list_id
            .clone()
            .unwrap_or_else(|| self.cfg.posting_address.replace('@', "."))
    }
}
