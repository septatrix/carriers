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
//! Further, optional scripts (see [`PolicyEngine::evaluate_for_list`]) may run for *every* list,
//! wrapped around that list's own `policy`: a global one, plus an additional one per list
//! domain. All of these run after loop/duplicate detection, once the current list is already
//! known, so they still see that list's membership sets — unlike the list-independent tier
//! sketched in the README's roadmap, which would run before a list is even resolved.
//!
//! The full chain, outside-in for the "before" scripts and inside-out for "after":
//!
//! ```text
//! global before -> domain before -> the list's own policy -> domain after -> global after
//! ```
//!
//! At every step, an implicit keep is *not* authoritative: it means that script found no reason
//! to act, so the decision made so far (`Approve` unless an earlier step already decided
//! otherwise) carries through unchanged. `Moderate`, `Discard`, and `Reject` *are* authoritative
//! and become the new decision so far. Once a step reaches `Discard` or `Reject`, the chain
//! stops immediately — there is nothing left for a later step to add. A `Moderate` reached
//! before the list's own policy skips straight to the "after" scripts, since the list's own
//! policy has nothing to add once the message is already held; a `Moderate` reached at or after
//! the list's own policy still lets the remaining "after" scripts tighten it further (e.g. to
//! `Reject`), since `after` is specifically the tier for such last-word, domain- or
//! instance-wide checks.

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

/// Before/after Sieve scripts scoped to one list domain — see
/// [`PolicyEngine::with_domain_before`]/[`PolicyEngine::with_domain_after`].
#[derive(Default)]
struct DomainScripts {
    before: Option<Arc<Sieve>>,
    after: Option<Arc<Sieve>>,
}

/// A registry of compiled Sieve policies: the built-ins plus any custom scripts loaded from a
/// directory of `*.sieve` files, plus the optional global/domain scripts run around them (see
/// [`PolicyEngine::evaluate_for_list`]).
pub struct PolicyEngine {
    engine: SieveEngine,
    policies: HashMap<String, Arc<Sieve>>,
    global_before: Option<Arc<Sieve>>,
    global_after: Option<Arc<Sieve>>,
    domains: HashMap<String, DomainScripts>,
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
            global_before: None,
            global_after: None,
            domains: HashMap::new(),
        })
    }

    /// Compile and attach the global "before" script, run ahead of every list's own policy,
    /// regardless of domain — see [`PolicyEngine::evaluate_for_list`].
    pub fn with_global_before(mut self, path: &Path) -> Result<Self> {
        self.global_before = Some(self.compile_file(path, "global before")?);
        Ok(self)
    }

    /// Compile and attach the global "after" script, run after every list's own policy,
    /// regardless of domain — see [`PolicyEngine::evaluate_for_list`].
    pub fn with_global_after(mut self, path: &Path) -> Result<Self> {
        self.global_after = Some(self.compile_file(path, "global after")?);
        Ok(self)
    }

    /// Compile and attach a "before" script scoped to `domain`, run between the global "before"
    /// script and the list's own policy, for lists in that domain only.
    pub fn with_domain_before(mut self, domain: &str, path: &Path) -> Result<Self> {
        let compiled = self.compile_file(path, &format!("domain `{domain}` before"))?;
        self.domains.entry(domain.to_string()).or_default().before = Some(compiled);
        Ok(self)
    }

    /// Compile and attach an "after" script scoped to `domain`, run between the list's own
    /// policy and the global "after" script, for lists in that domain only.
    pub fn with_domain_after(mut self, domain: &str, path: &Path) -> Result<Self> {
        let compiled = self.compile_file(path, &format!("domain `{domain}` after"))?;
        self.domains.entry(domain.to_string()).or_default().after = Some(compiled);
        Ok(self)
    }

    fn compile_file(&self, path: &Path, what: &str) -> Result<Arc<Sieve>> {
        let text = std::fs::read(path)?;
        self.engine
            .compile(&text)
            .map_err(|e| Error::Config(format!("compiling {what} policy {}: {e}", path.display())))
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
        self.run_tier(script, name, list_name, mail_from, raw, sets)
    }

    /// Run the full policy chain for one inbound post: the global "before" script, this domain's
    /// "before" script, the named list policy, this domain's "after" script, and the global
    /// "after" script — see the module docs for exactly how these compose. Any tier that was
    /// never configured (via [`PolicyEngine::with_global_before`] and friends, or because
    /// `domain` has no entry) is simply skipped.
    pub fn evaluate_for_list(
        &self,
        policy_name: &str,
        list_name: &str,
        domain: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
    ) -> Result<PolicyDecision> {
        let domain_scripts = self.domains.get(domain);
        let mut decision = PolicyDecision::Approve;

        if let Some(script) = &self.global_before {
            decision = merge(
                decision,
                self.run_tier(script, "global-before", list_name, mail_from, raw, sets)?,
            );
        }
        if is_terminal(&decision) {
            return Ok(decision);
        }

        if let Some(script) = domain_scripts.and_then(|d| d.before.as_ref()) {
            decision = merge(
                decision,
                self.run_tier(script, "domain-before", list_name, mail_from, raw, sets)?,
            );
        }
        if is_terminal(&decision) {
            return Ok(decision);
        }

        // An earlier `Moderate` already means the message is held; the list's own policy has
        // nothing to add, so it only runs while the decision so far is still `Approve`.
        if matches!(decision, PolicyDecision::Approve) {
            decision = merge(
                decision,
                self.evaluate(policy_name, list_name, mail_from, raw, sets)?,
            );
        }
        if is_terminal(&decision) {
            return Ok(decision);
        }

        // `after` is the last-word tier: it still runs while the decision is `Approve` or
        // `Moderate`, and may tighten either one further (e.g. escalate a hold to a reject).
        if let Some(script) = domain_scripts.and_then(|d| d.after.as_ref()) {
            decision = merge(
                decision,
                self.run_tier(script, "domain-after", list_name, mail_from, raw, sets)?,
            );
        }
        if is_terminal(&decision) {
            return Ok(decision);
        }

        if let Some(script) = &self.global_after {
            decision = merge(
                decision,
                self.run_tier(script, "global-after", list_name, mail_from, raw, sets)?,
            );
        }
        Ok(decision)
    }

    fn run_tier(
        &self,
        script: &Arc<Sieve>,
        name: &str,
        list_name: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
    ) -> Result<PolicyDecision> {
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
}

/// Fold a tier's decision into the one reached so far: an implicit keep (`Approve`) carries the
/// prior decision through unchanged, since it means that tier found no reason to act; anything
/// else is authoritative and becomes the new decision so far.
fn merge(so_far: PolicyDecision, tier: PolicyDecision) -> PolicyDecision {
    match tier {
        PolicyDecision::Approve => so_far,
        other => other,
    }
}

/// Whether a decision is final and no later tier has anything left to add — reached only by an
/// explicit `discard` or `reject`/`ereject`, never by `Approve` or `Moderate`.
fn is_terminal(decision: &PolicyDecision) -> bool {
    matches!(
        decision,
        PolicyDecision::Discard | PolicyDecision::Reject { .. }
    )
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
