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
//! `fileinto` destinations are read as pseudo-mailboxes, not real folders. Besides the
//! moderation folders above, `fileinto :copy "archive"` writes a copy of the post to the
//! configured archive (see [`crate::config::Config::archive_dir`]); the `:copy` keeps the
//! message flowing, so this is a side effect that does not by itself change the decision, and
//! can be used before moderation (to capture everything, including rejects) or after it.
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
//! ## Built-in loop and duplicate checks
//!
//! Two further built-in scripts run ahead of everything else, once per inbound message, via
//! [`PolicyEngine::check_loop`] and [`PolicyEngine::check_duplicate`]:
//!
//! - `loop.sieve` — a header check: if the message already carries this list's own `List-Id`
//!   (exposed to the script as the `vnd.carriers.list_id` environment variable) it has looped
//!   back through the list and is discarded.
//! - `duplicate.sieve` — the RFC 7352 `duplicate` test: a message whose `Message-ID` this list
//!   has already seen is discarded. The seen-set is answered by a [`DuplicateStore`].
//!
//! These are ordinary Sieve scripts (embedded via `include_str!`) rather than hand-written Rust,
//! so the loop/dedup rules live in the same place, and same language, as every other policy. The
//! `List-*` header injection ([`PolicyEngine::apply_list_headers`], `list-headers.sieve`) is a
//! built-in script in the same spirit — it uses `addheader` to prepend the headers, DKIM-safely.
//!
//! ## Global policy
//!
//! Further, optional scripts may run for *every* list, wrapped around that list's own `policy`:
//! a global one, plus an additional one per list domain. All of these run after the
//! loop/duplicate checks, once the current list is already known, so they still see that list's
//! membership sets — unlike the list-independent tier sketched in the README's roadmap, which
//! would run before a list is even resolved.
//!
//! The full chain, outside-in for the "before" scripts and inside-out for "after":
//!
//! ```text
//! global before -> domain before -> the list's own policy -> domain after -> global after
//! ```
//!
//! This splits across two moments in a message's life. The **before** half — global before,
//! domain before, the list's own policy — is decided at intake, in
//! [`PolicyEngine::evaluate_before`]: it determines whether to distribute, hold, discard, or
//! reject. The **after** half — domain after, global after — runs later, at distribution time,
//! in [`PolicyEngine::evaluate_after`] (called from [`crate::pipeline::finalize`]), *after* any
//! moderation, so it has the last word on a message that is actually about to go out.
//!
//! At every step, an implicit keep is *not* authoritative: it means that script found no reason
//! to act, so the decision made so far (`Approve` unless an earlier step already decided
//! otherwise) carries through unchanged. `Moderate`, `Discard`, and `Reject` *are* authoritative
//! and become the new decision so far. Once a "before" step reaches `Discard` or `Reject`, the
//! rest of the before half is skipped; a `Moderate` there holds the message for moderation. The
//! after half then starts fresh from `Approve` and may still tighten it (e.g. escalate to a
//! `Reject`), which is why `after` is the tier for last-word, domain- or instance-wide checks.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use sieve::Sieve;

use crate::error::{Error, Result};
use crate::sieve_engine::{
    DuplicateStore, ExternalLists, NoDuplicates, SieveEngine, SieveOutcome, SieveRun,
};

/// External list names exposed to policy scripts via the Sieve `:list` match.
pub const LIST_SUBSCRIBERS: &str = "subscribers";
pub const LIST_POSTERS: &str = "posters";
pub const LIST_MODERATORS: &str = "moderators";

/// Environment variable exposing the current list's short name to scripts.
pub const ENV_LIST: &str = "vnd.carriers.list";
/// Environment variable exposing the current list's `List-Id` to scripts (used by the built-in
/// loop check).
pub const ENV_LIST_ID: &str = "vnd.carriers.list_id";

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

/// What one or more policy tiers decided for a message: the moderation [`PolicyDecision`], plus
/// whether any tier that ran filed the message into the `archive` pseudo-mailbox
/// (`fileinto :copy "archive"`). Archiving is independent of the decision — a message can be
/// archived and then held, distributed, discarded, or rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub decision: PolicyDecision,
    pub archive: bool,
}

/// `fileinto` pseudo-mailbox names that hold a message for moderation.
const MODERATE_FOLDERS: &[&str] = &["moderate", "moderation", "hold"];
/// `fileinto` pseudo-mailbox name that archives a copy of the message.
pub const ARCHIVE_FOLDER: &str = "archive";

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

/// A registry of compiled Sieve policies: the built-in loop/dedup checks and posting policies,
/// plus any custom scripts loaded from a directory of `*.sieve` files, plus the optional
/// global/domain scripts run around them (see [`PolicyEngine::evaluate_before`] and
/// [`PolicyEngine::evaluate_after`]).
pub struct PolicyEngine {
    engine: SieveEngine,
    loop_check: Arc<Sieve>,
    duplicate_check: Arc<Sieve>,
    list_headers: Arc<Sieve>,
    policies: HashMap<String, Arc<Sieve>>,
    global_before: Option<Arc<Sieve>>,
    global_after: Option<Arc<Sieve>>,
    domains: HashMap<String, DomainScripts>,
}

impl PolicyEngine {
    /// An engine with only the built-in scripts compiled.
    pub fn new() -> Result<Self> {
        let engine = SieveEngine::new(&[LIST_SUBSCRIBERS, LIST_POSTERS, LIST_MODERATORS]);
        let compile_builtin = |name: &str, src: &str| {
            engine
                .compile(src.as_bytes())
                .map_err(|e| Error::Config(format!("compiling built-in `{name}`: {e}")))
        };

        let loop_check = compile_builtin("loop", include_str!("builtin_policies/loop.sieve"))?;
        let duplicate_check = compile_builtin(
            "duplicate",
            include_str!("builtin_policies/duplicate.sieve"),
        )?;
        let list_headers = compile_builtin(
            "list-headers",
            include_str!("builtin_policies/list-headers.sieve"),
        )?;

        let mut policies = HashMap::new();
        for (name, script) in BUILTIN_SCRIPTS {
            policies.insert((*name).to_string(), compile_builtin(name, script)?);
        }
        Ok(PolicyEngine {
            engine,
            loop_check,
            duplicate_check,
            list_headers,
            policies,
            global_before: None,
            global_after: None,
            domains: HashMap::new(),
        })
    }

    /// Compile and attach the global "before" script, run ahead of every list's own policy,
    /// regardless of domain — see [`PolicyEngine::evaluate_before`].
    pub fn with_global_before(mut self, path: &Path) -> Result<Self> {
        self.global_before = Some(self.compile_file(path, "global before")?);
        Ok(self)
    }

    /// Compile and attach the global "after" script, run after every list's own policy,
    /// regardless of domain — see [`PolicyEngine::evaluate_after`].
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

    /// Run the built-in loop check (`loop.sieve`): a header check against this list's own
    /// `List-Id`. Returns `true` if the message loops back through the list and must be dropped.
    ///
    /// `list_id` is the list's `List-Id` value, exposed to the script as the
    /// `vnd.carriers.list_id` environment variable.
    pub async fn check_loop(
        &self,
        list_name: &str,
        list_id: &str,
        mail_from: &str,
        raw: &[u8],
    ) -> Result<bool> {
        let run = self
            .run_script(
                &self.loop_check,
                "loop",
                list_name,
                list_id,
                mail_from,
                raw,
                &NO_LISTS,
                &NoDuplicates,
            )
            .await?;
        Ok(matches!(run.outcome, SieveOutcome::Discard))
    }

    /// Run the built-in duplicate check (`duplicate.sieve`, the RFC 7352 `duplicate` test).
    /// Returns `true` if `duplicates` reports this message's `Message-ID` as already seen.
    pub async fn check_duplicate(
        &self,
        list_name: &str,
        list_id: &str,
        mail_from: &str,
        raw: &[u8],
        duplicates: &dyn DuplicateStore,
    ) -> Result<bool> {
        let run = self
            .run_script(
                &self.duplicate_check,
                "duplicate",
                list_name,
                list_id,
                mail_from,
                raw,
                &NO_LISTS,
                duplicates,
            )
            .await?;
        Ok(matches!(run.outcome, SieveOutcome::Discard))
    }

    /// Apply the built-in `list-headers.sieve` script to `raw`, prepending the `List-*` headers
    /// whose values are supplied in `header_env` (see [`crate::transform::list_header_env`]).
    /// Returns the rewritten message bytes (or `raw` unchanged if the script added nothing).
    pub async fn apply_list_headers(
        &self,
        list_name: &str,
        list_id: &str,
        header_env: &[(&str, &str)],
        raw: &[u8],
    ) -> Result<Vec<u8>> {
        let mut env = vec![(ENV_LIST, list_name), (ENV_LIST_ID, list_id)];
        env.extend_from_slice(header_env);
        let run = self
            .engine
            .run(
                "list-headers",
                &self.list_headers,
                raw,
                "",
                &env,
                &NO_LISTS,
                &NoDuplicates,
            )
            .await?;
        Ok(run.message.unwrap_or_else(|| raw.to_vec()))
    }

    /// Evaluate the named policy against a message.
    ///
    /// `list_name`/`list_id` are exposed to the script as the `vnd.carriers.list` /
    /// `vnd.carriers.list_id` environment variables; `mail_from` is the envelope sender; `sets`
    /// resolves the membership `:list` tests.
    pub async fn evaluate(
        &self,
        name: &str,
        list_name: &str,
        list_id: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
    ) -> Result<PolicyOutcome> {
        let script = self
            .policies
            .get(name)
            .ok_or_else(|| Error::Config(format!("unknown policy `{name}`")))?;
        self.run_tier(script, name, list_name, list_id, mail_from, raw, sets)
            .await
    }

    /// The "before" half of the policy chain, decided at intake: the global "before" script,
    /// this domain's "before" script, then the named list policy. See the module docs for how
    /// these compose. Any tier that was never configured (via
    /// [`PolicyEngine::with_global_before`] and friends, or because `domain` has no entry) is
    /// simply skipped. The "after" half runs later, in [`PolicyEngine::evaluate_after`].
    ///
    /// The returned `archive` flag is the union across every tier that ran, so a message is
    /// archived if any of them filed it into the `archive` pseudo-mailbox.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_before(
        &self,
        policy_name: &str,
        list_name: &str,
        list_id: &str,
        domain: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
    ) -> Result<PolicyOutcome> {
        let domain_scripts = self.domains.get(domain);
        let mut decision = PolicyDecision::Approve;
        let mut archive = false;

        if let Some(script) = &self.global_before {
            let out = self
                .run_tier(
                    script,
                    "global-before",
                    list_name,
                    list_id,
                    mail_from,
                    raw,
                    sets,
                )
                .await?;
            archive |= out.archive;
            decision = merge(decision, out.decision);
        }
        if is_terminal(&decision) {
            return Ok(PolicyOutcome { decision, archive });
        }

        if let Some(script) = domain_scripts.and_then(|d| d.before.as_ref()) {
            let out = self
                .run_tier(
                    script,
                    "domain-before",
                    list_name,
                    list_id,
                    mail_from,
                    raw,
                    sets,
                )
                .await?;
            archive |= out.archive;
            decision = merge(decision, out.decision);
        }
        if is_terminal(&decision) {
            return Ok(PolicyOutcome { decision, archive });
        }

        // An earlier `Moderate` already means the message will be held; the list's own policy
        // has nothing to add, so it only runs while the decision so far is still `Approve`.
        if matches!(decision, PolicyDecision::Approve) {
            let out = self
                .evaluate(policy_name, list_name, list_id, mail_from, raw, sets)
                .await?;
            archive |= out.archive;
            decision = merge(decision, out.decision);
        }
        Ok(PolicyOutcome { decision, archive })
    }

    /// The "after" half of the policy chain, decided at distribution time — after moderation —
    /// so it has the final word on a message about to go out (see
    /// [`crate::pipeline::finalize`]): this domain's "after" script, then the global "after"
    /// script. It starts from `Approve` (only about-to-distribute messages reach it) and may
    /// tighten that to a hold, discard, or reject — or archive it.
    pub async fn evaluate_after(
        &self,
        list_name: &str,
        list_id: &str,
        domain: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
    ) -> Result<PolicyOutcome> {
        let domain_scripts = self.domains.get(domain);
        let mut decision = PolicyDecision::Approve;
        let mut archive = false;

        if let Some(script) = domain_scripts.and_then(|d| d.after.as_ref()) {
            let out = self
                .run_tier(
                    script,
                    "domain-after",
                    list_name,
                    list_id,
                    mail_from,
                    raw,
                    sets,
                )
                .await?;
            archive |= out.archive;
            decision = merge(decision, out.decision);
        }
        if is_terminal(&decision) {
            return Ok(PolicyOutcome { decision, archive });
        }

        if let Some(script) = &self.global_after {
            let out = self
                .run_tier(
                    script,
                    "global-after",
                    list_name,
                    list_id,
                    mail_from,
                    raw,
                    sets,
                )
                .await?;
            archive |= out.archive;
            decision = merge(decision, out.decision);
        }
        Ok(PolicyOutcome { decision, archive })
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_tier(
        &self,
        script: &Arc<Sieve>,
        name: &str,
        list_name: &str,
        list_id: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
    ) -> Result<PolicyOutcome> {
        // A policy tier never tracks duplicates; only the built-in duplicate check does (see the
        // `NoDuplicates` docs), so a stray `duplicate` test in a policy script is inert.
        let run = self
            .run_script(
                script,
                name,
                list_name,
                list_id,
                mail_from,
                raw,
                sets,
                &NoDuplicates,
            )
            .await?;
        Ok(outcome_from_run(run))
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_script(
        &self,
        script: &Arc<Sieve>,
        name: &str,
        list_name: &str,
        list_id: &str,
        mail_from: &str,
        raw: &[u8],
        lists: &dyn ExternalLists,
        duplicates: &dyn DuplicateStore,
    ) -> Result<SieveRun> {
        self.engine
            .run(
                name,
                script,
                raw,
                mail_from,
                &[(ENV_LIST, list_name), (ENV_LIST_ID, list_id)],
                lists,
                duplicates,
            )
            .await
    }
}

/// An [`ExternalLists`] with no lists — for the built-in loop/dedup checks, which never use the
/// `:list` test.
static NO_LISTS: NoLists = NoLists;

struct NoLists;

impl ExternalLists for NoLists {
    fn contains(&self, _list: &str, _value: &str) -> bool {
        false
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

/// Interpret a completed [`SieveRun`] as a [`PolicyOutcome`].
///
/// `discard`/`reject` are terminal. Otherwise the `fileinto` destinations decide: filing into a
/// moderation pseudo-mailbox holds the message, filing into `archive` requests an archive copy
/// (independent of the decision), and anything else is ordinary delivery (approve).
fn outcome_from_run(run: SieveRun) -> PolicyOutcome {
    let archive = run.filed_into.iter().any(|f| is_archive_folder(f));
    let decision = match run.outcome {
        SieveOutcome::Discard => PolicyDecision::Discard,
        SieveOutcome::Reject { reason } => PolicyDecision::Reject { reason },
        SieveOutcome::Keep => {
            if run.filed_into.iter().any(|f| is_moderate_folder(f)) {
                PolicyDecision::Moderate
            } else {
                PolicyDecision::Approve
            }
        }
    };
    PolicyOutcome { decision, archive }
}

fn is_moderate_folder(folder: &str) -> bool {
    MODERATE_FOLDERS
        .iter()
        .any(|m| folder.eq_ignore_ascii_case(m))
}

fn is_archive_folder(folder: &str) -> bool {
    folder.eq_ignore_ascii_case(ARCHIVE_FOLDER)
}
