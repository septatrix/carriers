//! Sieve-based moderation policies.
//!
//! A custom policy is a Sieve script file (`<name>.sieve`) placed in the configured policies
//! directory by the administrator; a list selects a policy — built-in or custom — by name via
//! its single `policy = "<name>"` config field. Policies are global and static — compiled once
//! at startup.
//!
//! The four built-in policies (`open`, `subscribers`, `posters`, `moderated`) are themselves
//! Sieve scripts, one file each under `src/builtin_policies/` (embedded into the binary at
//! compile time via `include_str!`, see [`BUILTIN_SCRIPTS`]), so every list — whether it names
//! a built-in policy or a custom script — is moderated through this one engine, looked up by
//! the same name. The actual Sieve compiling/running mechanics live in
//! [`crate::sieve_engine`]; this module only adds the carriers-specific vocabulary on top:
//! named policies, membership lists, and the decision a script reaches.
//!
//! A script decides what happens to a post through ordinary Sieve actions:
//!
//! - `keep;` (or doing nothing) — **approve**: distribute the post now.
//! - `fileinto "moderate";` — **hold** the post for moderation.
//! - `discard;` — **silently drop** the post; the sender is told nothing.
//! - `reject "reason";` / `ereject "reason";` — **refuse** the post, replying to the sender's
//!   MTA with the given reason (a real-time SMTP rejection, not a bounce, so this does not
//!   generate backscatter).
//!
//! Membership is exposed as Sieve external lists, resolved against the *current* list, so a
//! single global script adapts per mailing list. These are independent flags, not a hierarchy —
//! a subscriber is not automatically a poster, and a poster is not automatically a subscriber:
//!
//! - `subscribers` — addresses that receive the list.
//! - `posters` — addresses that may post directly, independent of subscription.
//! - `moderators` — addresses flagged as moderators.
//!
//! ```sieve
//! require ["envelope", "extlists", "fileinto", "reject"];
//! if address :list "from" "subscribers" { keep; }
//! elsif address :list "from" "posters" { fileinto "moderate"; }
//! else { reject "Only subscribers and posters may write to this list."; }
//! ```
//!
//! ## Global policy
//!
//! One further, optional script (see [`PolicyEngine::evaluate_global`]) may run for *every*
//! list, ahead of that list's own `policy`. It runs after loop/duplicate detection, once the
//! current list is already known, so it still sees that list's membership sets — unlike the
//! list-independent tier sketched in the README's roadmap, which would run before a list is
//! even resolved.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use sieve::Sieve;

use crate::error::{Error, Result};
use crate::sieve_engine::{ExternalLists, SieveEngine, SieveOutcome};

/// External list names exposed to policy scripts via the Sieve `:list` match.
pub const LIST_SUBSCRIBERS: &str = "subscribers";
pub const LIST_POSTERS: &str = "posters";
pub const LIST_MODERATORS: &str = "moderators";

/// Names of the built-in policies. These are reserved: an administrator's `<name>.sieve` file
/// may not use them.
pub const BUILTIN_OPEN: &str = "open";
pub const BUILTIN_SUBSCRIBERS: &str = "subscribers";
pub const BUILTIN_POSTERS: &str = "posters";
pub const BUILTIN_MODERATED: &str = "moderated";

/// The built-in policies, each a standalone Sieve script embedded at compile time, as
/// `(name, source)` pairs.
const BUILTIN_SCRIPTS: &[(&str, &str)] = &[
    (BUILTIN_OPEN, include_str!("builtin_policies/open.sieve")),
    (
        BUILTIN_SUBSCRIBERS,
        include_str!("builtin_policies/subscribers.sieve"),
    ),
    (
        BUILTIN_POSTERS,
        include_str!("builtin_policies/posters.sieve"),
    ),
    (
        BUILTIN_MODERATED,
        include_str!("builtin_policies/moderated.sieve"),
    ),
];

/// True if `name` is a reserved built-in policy name.
pub fn is_builtin(name: &str) -> bool {
    BUILTIN_SCRIPTS.iter().any(|(n, _)| *n == name)
}

/// The decision a policy reached for a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Distribute the message now.
    Approve,
    /// Hold the message for moderation.
    Moderate,
    /// Silently drop the message (Sieve `discard`); the sender is told nothing.
    Discard,
    /// Refuse the message with a reason (Sieve `reject`/`ereject`), to be surfaced to the
    /// sender as a real-time SMTP rejection.
    Reject { reason: String },
}

/// Membership facts for the current list, resolved before evaluating a (synchronous) script.
/// Addresses are stored lowercased. These are independent sets, not a hierarchy: an address in
/// `subscribers` need not be in `posters`, and vice versa.
#[derive(Default)]
pub struct MembershipSets {
    pub subscribers: HashSet<String>,
    pub posters: HashSet<String>,
    pub moderators: HashSet<String>,
}

impl ExternalLists for MembershipSets {
    fn contains(&self, list: &str, value: &str) -> bool {
        let value = value.to_ascii_lowercase();
        match list {
            LIST_SUBSCRIBERS => self.subscribers.contains(&value),
            LIST_POSTERS => self.posters.contains(&value),
            LIST_MODERATORS => self.moderators.contains(&value),
            _ => false,
        }
    }
}

/// A registry of compiled Sieve policies: the built-ins plus any custom scripts loaded from a
/// directory of `*.sieve` files, plus an optional global script (see
/// [`PolicyEngine::evaluate_global`]).
pub struct PolicyEngine {
    engine: SieveEngine,
    policies: HashMap<String, Arc<Sieve>>,
    global: Option<Arc<Sieve>>,
}

impl PolicyEngine {
    /// An engine with only the built-in policies compiled.
    pub fn new() -> Result<Self> {
        let engine = SieveEngine::new(&[LIST_SUBSCRIBERS, LIST_POSTERS, LIST_MODERATORS]);
        let mut policies = HashMap::new();
        for (name, script) in BUILTIN_SCRIPTS {
            let compiled = engine
                .compile(script.as_bytes())
                .map_err(|e| Error::Config(format!("compiling built-in policy `{name}`: {e}")))?;
            policies.insert((*name).to_string(), compiled);
        }
        Ok(PolicyEngine {
            engine,
            policies,
            global: None,
        })
    }

    /// Compile and attach the global policy script from `path`, run by
    /// [`PolicyEngine::evaluate_global`] ahead of every list's own policy.
    pub fn with_global(mut self, path: &Path) -> Result<Self> {
        let text = std::fs::read(path)?;
        let compiled = self.engine.compile(&text).map_err(|e| {
            Error::Config(format!("compiling global policy {}: {e}", path.display()))
        })?;
        self.global = Some(compiled);
        Ok(self)
    }

    /// The built-in policies plus every custom `*.sieve` file in `dir` (the file stem is the
    /// policy name). Custom policies may not reuse a built-in name.
    pub fn load(dir: &Path) -> Result<Self> {
        let mut this = Self::new()?;
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) != Some("sieve") {
                    continue;
                }
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string();
                if is_builtin(&name) {
                    return Err(Error::Config(format!(
                        "policy `{name}` ({}) uses a reserved built-in name",
                        path.display()
                    )));
                }
                let text = std::fs::read(&path)?;
                let script = this.engine.compile(&text).map_err(|e| {
                    Error::Config(format!("compiling policy {}: {e}", path.display()))
                })?;
                this.policies.insert(name, script);
            }
        }
        Ok(this)
    }

    /// Whether a policy with this name exists (built-in or custom).
    pub fn contains(&self, name: &str) -> bool {
        self.policies.contains_key(name)
    }

    /// Names of the custom (non-built-in) policies.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.policies
            .keys()
            .map(String::as_str)
            .filter(|name| !is_builtin(name))
    }

    /// Evaluate the named policy against a message.
    ///
    /// `list_name` is exposed to the script as the `vnd.carriers.list` environment variable;
    /// `mail_from` is the envelope sender; `sets` resolves the membership `:list` tests.
    pub fn evaluate(
        &self,
        name: &str,
        list_name: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
    ) -> Result<PolicyDecision> {
        let script = self
            .policies
            .get(name)
            .ok_or_else(|| Error::Config(format!("unknown policy `{name}`")))?;
        let outcome = self.engine.run(
            name,
            script,
            raw,
            mail_from,
            &[("vnd.carriers.list", list_name)],
            sets,
        )?;
        Ok(decision_from_outcome(outcome))
    }

    /// Evaluate the global policy (if one is configured) against a message, for `list_name`'s
    /// membership sets. Returns `None` if no global policy was attached via
    /// [`PolicyEngine::with_global`].
    ///
    /// A result of [`PolicyDecision::Approve`] means the global script found no reason to act —
    /// it is *not* authoritative, and the list's own policy still runs normally afterwards. Any
    /// other decision (`Moderate`, `Discard`, `Reject`) is authoritative and short-circuits the
    /// list's own policy.
    pub fn evaluate_global(
        &self,
        list_name: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
    ) -> Result<Option<PolicyDecision>> {
        let Some(script) = &self.global else {
            return Ok(None);
        };
        let outcome = self.engine.run(
            "global",
            script,
            raw,
            mail_from,
            &[("vnd.carriers.list", list_name)],
            sets,
        )?;
        Ok(Some(decision_from_outcome(outcome)))
    }
}

/// Map a [`SieveOutcome`] to the carriers-specific [`PolicyDecision`] it represents.
fn decision_from_outcome(outcome: SieveOutcome) -> PolicyDecision {
    match outcome {
        SieveOutcome::Keep => PolicyDecision::Approve,
        SieveOutcome::Discard => PolicyDecision::Discard,
        SieveOutcome::Reject { reason } => PolicyDecision::Reject { reason },
        SieveOutcome::FileInto { folder } => classify_folder(&folder),
    }
}

/// Any `fileinto` destination named like a moderation folder holds the message; anything else
/// is treated as ordinary delivery (approve) — a real MDA would just file it into that mailbox.
fn classify_folder(folder: &str) -> PolicyDecision {
    match folder.to_ascii_lowercase().as_str() {
        "moderate" | "moderation" | "hold" => PolicyDecision::Moderate,
        _ => PolicyDecision::Approve,
    }
}
