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
//! `fileinto "no-dkim"` withholds the list's own DKIM signature from the outgoing message (see
//! "Built-in DMARC gate" below); `fileinto "munge-from"` requests From/Reply-To munging (see
//! [`PolicyEngine::apply_munge_from`]). Like `archive`, both are independent side effects, not
//! decisions.
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
//! ## Built-in DMARC gate
//!
//! carriers must never sign an unauthenticated message with its own reputation. Two more built-in
//! scripts, `dmarc-before.sieve` and `dmarc-after.sieve`, run first in [`PolicyEngine::evaluate_before`]
//! and [`PolicyEngine::evaluate_after`] respectively: a message failing DMARC against an enforcing
//! domain policy (`p=quarantine`/`p=reject`) is rejected outright — as early as `evaluate_before`,
//! before it can even reach moderation, and again, defensively, in `evaluate_after` (DNS/policy
//! can change while a message sits held). A message that fails DMARC but whose domain does not
//! request enforcement is still distributed, but is filed into the `no-dkim` pseudo-mailbox so it
//! never carries the list's own signature — only an honest ARC seal. See
//! [`crate::sign::AuthVerdict`] for the computed facts these scripts test (exposed as
//! `vnd.carriers.dmarc_*`/`dkim_result`/`spf_result` environment variables to every tier, not just
//! these two built-ins).
//!
//! ## Global policy
//!
//! Further, optional scripts may run for *every* list, wrapped around that list's own `policy`:
//! a global set, plus an additional set per list domain. Each set is a `.d` drop-in directory —
//! every `*.sieve` file in it runs, in filename order (like a systemd drop-in directory), so
//! rules can be layered by dropping in numbered files (`10-abuse.sieve`, `20-archive.sieve`, …).
//! All of these run after the loop/duplicate checks, once the current list is already known, so
//! they still see that list's membership sets — unlike the list-independent tier sketched in the
//! README's roadmap, which would run before a list is even resolved.
//!
//! The full chain, outside-in for the "before" scripts and inside-out for "after" (each of
//! `global before` / `domain before` / `domain after` / `global after` being a whole directory
//! of drop-ins run in order):
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
    DuplicateStore, ExternalLists, NoDuplicates, SieveAction, SieveEngine, SieveOutcome, SieveRun,
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
/// independent side-effect flags any tier that ran may have requested by filing into a
/// pseudo-mailbox — a message can be archived and/or have its own signature withheld and/or be
/// scheduled for From/Reply-To munging regardless of whether it is held, distributed, discarded,
/// or rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub decision: PolicyDecision,
    /// Filed into `archive` (`fileinto :copy "archive"`).
    pub archive: bool,
    /// Filed into `no-dkim`: the message must not carry the list's own `DKIM-Signature` when
    /// distributed (see `builtin_policies/dmarc-after.sieve`). Only consulted from
    /// [`PolicyEngine::evaluate_after`]'s outcome, since that is the tier immediately preceding
    /// signing; a "before" tier filing into this pseudo-mailbox has no effect.
    pub no_own_dkim: bool,
    /// Filed into `munge-from`: rewrite `From`/`Reply-To` to the list's own address before
    /// signing (see [`PolicyEngine::apply_munge_from`]). Nothing built-in sets this yet; it is an
    /// available mechanism for custom scripts. Same "after"-tier-only caveat as `no_own_dkim`.
    pub munge_from: bool,
}

/// The full record of running one script against a message, for debugging: the interpreted
/// [`PolicyOutcome`], every raw Sieve action the script performed in order (see [`SieveAction`]),
/// and the rewritten message bytes if it edited headers (`None` if it left them untouched). See
/// [`PolicyEngine::trace_source`] and the `carriers-sieve` binary.
pub struct PolicyTrace {
    pub outcome: PolicyOutcome,
    pub actions: Vec<SieveAction>,
    pub rewritten: Option<Vec<u8>>,
}

/// `fileinto` pseudo-mailbox names that hold a message for moderation.
const MODERATE_FOLDERS: &[&str] = &["moderate", "moderation", "hold"];
/// `fileinto` pseudo-mailbox name that archives a copy of the message.
pub const ARCHIVE_FOLDER: &str = "archive";
/// `fileinto` pseudo-mailbox name that withholds the list's own DKIM signature.
pub const NO_DKIM_FOLDER: &str = "no-dkim";
/// `fileinto` pseudo-mailbox name that requests From/Reply-To munging.
pub const MUNGE_FROM_FOLDER: &str = "munge-from";

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

/// Before/after Sieve drop-in scripts scoped to one list domain — see
/// [`PolicyEngine::with_domain_before`]/[`PolicyEngine::with_domain_after`]. Each is the
/// compiled contents of a `.d` directory, in filename order.
#[derive(Default)]
struct DomainScripts {
    before: Vec<Arc<Sieve>>,
    after: Vec<Arc<Sieve>>,
}

/// A registry of compiled Sieve policies: the built-in loop/dedup checks and posting policies,
/// plus any custom scripts loaded from a directory of `*.sieve` files, plus the optional
/// global/domain drop-in scripts run around them (see [`PolicyEngine::evaluate_before`] and
/// [`PolicyEngine::evaluate_after`]). The global/domain scripts are each a `.d` directory's
/// worth of `.sieve` files, run in filename order.
pub struct PolicyEngine {
    engine: SieveEngine,
    loop_check: Arc<Sieve>,
    duplicate_check: Arc<Sieve>,
    list_headers: Arc<Sieve>,
    dmarc_before_gate: Arc<Sieve>,
    dmarc_after_gate: Arc<Sieve>,
    munge_from_script: Arc<Sieve>,
    policies: HashMap<String, Arc<Sieve>>,
    global_before: Vec<Arc<Sieve>>,
    global_after: Vec<Arc<Sieve>>,
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
        let dmarc_before_gate = compile_builtin(
            "dmarc-before",
            include_str!("builtin_policies/dmarc-before.sieve"),
        )?;
        let dmarc_after_gate = compile_builtin(
            "dmarc-after",
            include_str!("builtin_policies/dmarc-after.sieve"),
        )?;
        let munge_from_script = compile_builtin(
            "munge-from",
            include_str!("builtin_policies/munge-from.sieve"),
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
            dmarc_before_gate,
            dmarc_after_gate,
            munge_from_script,
            policies,
            global_before: Vec::new(),
            global_after: Vec::new(),
            domains: HashMap::new(),
        })
    }

    /// Compile and attach the global "before" drop-in directory: every `*.sieve` file in `dir`,
    /// run in filename order ahead of every list's own policy, regardless of domain — see
    /// [`PolicyEngine::evaluate_before`].
    pub fn with_global_before(mut self, dir: &Path) -> Result<Self> {
        self.global_before = self.compile_dir(dir, "global before")?;
        Ok(self)
    }

    /// Compile and attach the global "after" drop-in directory: every `*.sieve` file in `dir`,
    /// run in filename order after every list's own policy, regardless of domain — see
    /// [`PolicyEngine::evaluate_after`].
    pub fn with_global_after(mut self, dir: &Path) -> Result<Self> {
        self.global_after = self.compile_dir(dir, "global after")?;
        Ok(self)
    }

    /// Compile and attach a "before" drop-in directory scoped to `domain`, run (in filename
    /// order) between the global "before" scripts and the list's own policy, for lists in that
    /// domain only.
    pub fn with_domain_before(mut self, domain: &str, dir: &Path) -> Result<Self> {
        let scripts = self.compile_dir(dir, &format!("domain `{domain}` before"))?;
        self.domains.entry(domain.to_string()).or_default().before = scripts;
        Ok(self)
    }

    /// Compile and attach an "after" drop-in directory scoped to `domain`, run (in filename
    /// order) between the list's own policy and the global "after" scripts, for lists in that
    /// domain only.
    pub fn with_domain_after(mut self, domain: &str, dir: &Path) -> Result<Self> {
        let scripts = self.compile_dir(dir, &format!("domain `{domain}` after"))?;
        self.domains.entry(domain.to_string()).or_default().after = scripts;
        Ok(self)
    }

    /// Compile every `*.sieve` file directly in `dir`, returned in filename order (like a
    /// systemd `.d` drop-in directory). Nested directories are ignored.
    fn compile_dir(&self, dir: &Path, what: &str) -> Result<Vec<Arc<Sieve>>> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| {
                Error::Config(format!(
                    "reading {what} drop-in directory {}: {e}",
                    dir.display()
                ))
            })?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("sieve"))
            .collect();
        // Filenames share the parent, so sorting the full paths orders them by name.
        paths.sort();

        paths
            .iter()
            .map(|path| self.compile_file(path, what))
            .collect()
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

    /// Load an entire Sieve-scripts root directory with a fixed, conventional layout — the single
    /// knob a deployment configures (`sieve_scripts` in `carriers.toml`):
    ///
    /// ```text
    /// <root>/
    ///   moderation_policies/<name>.sieve    # per-list moderation policies, by file stem
    ///   before.d/*.sieve                    # global "before" drop-ins
    ///   after.d/*.sieve                     # global "after" drop-ins
    ///   domains/<domain>/before.d/*.sieve   # per-domain before
    ///   domains/<domain>/after.d/*.sieve    # per-domain after
    /// ```
    ///
    /// Every part is optional: a missing subdirectory is simply skipped. This just discovers the
    /// conventional paths and feeds them to [`load`](Self::load) / the `with_global_*` /
    /// `with_domain_*` builders — the evaluation model is unchanged.
    pub fn load_root(root: &Path) -> Result<Self> {
        let moderation = root.join("moderation_policies");
        let mut this = if moderation.is_dir() {
            Self::load(&moderation)?
        } else {
            Self::new()?
        };

        let before = root.join("before.d");
        if before.is_dir() {
            this = this.with_global_before(&before)?;
        }
        let after = root.join("after.d");
        if after.is_dir() {
            this = this.with_global_after(&after)?;
        }

        let domains = root.join("domains");
        if domains.is_dir() {
            // Sort so domains attach (and any diagnostics report) in a stable order.
            let mut domain_dirs: Vec<_> = std::fs::read_dir(&domains)
                .map_err(|e| {
                    Error::Config(format!(
                        "reading domains directory {}: {e}",
                        domains.display()
                    ))
                })?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p| p.is_dir())
                .collect();
            domain_dirs.sort();

            for domain_dir in domain_dirs {
                let Some(domain) = domain_dir.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                let domain = domain.to_string();
                let before = domain_dir.join("before.d");
                if before.is_dir() {
                    this = this.with_domain_before(&domain, &before)?;
                }
                let after = domain_dir.join("after.d");
                if after.is_dir() {
                    this = this.with_domain_after(&domain, &after)?;
                }
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

    /// Number of compiled global "before" drop-in scripts.
    pub fn global_before_count(&self) -> usize {
        self.global_before.len()
    }

    /// Number of compiled global "after" drop-in scripts.
    pub fn global_after_count(&self) -> usize {
        self.global_after.len()
    }

    /// Domains that have their own before/after drop-in scripts.
    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.domains.keys().map(String::as_str)
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
                &[],
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
                &[],
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

    /// Apply the built-in `munge-from.sieve` script to `raw`, rewriting `From`/`Reply-To` to the
    /// values supplied in `munge_env` (see [`crate::transform::munge_from_env`]). Returns the
    /// rewritten message bytes (or `raw` unchanged if the script made no edits).
    pub async fn apply_munge_from(
        &self,
        list_name: &str,
        list_id: &str,
        munge_env: &[(&str, &str)],
        raw: &[u8],
    ) -> Result<Vec<u8>> {
        let mut env = vec![(ENV_LIST, list_name), (ENV_LIST_ID, list_id)];
        env.extend_from_slice(munge_env);
        let run = self
            .engine
            .run(
                "munge-from",
                &self.munge_from_script,
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
    /// resolves the membership `:list` tests; `extra_env` is appended as further environment
    /// variables (e.g. the `vnd.carriers.dmarc_*` facts — see [`crate::sign::AuthVerdict`]).
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate(
        &self,
        name: &str,
        list_name: &str,
        list_id: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
        extra_env: &[(&str, &str)],
    ) -> Result<PolicyOutcome> {
        let script = self
            .policies
            .get(name)
            .ok_or_else(|| Error::Config(format!("unknown policy `{name}`")))?;
        self.run_tier(
            script, name, list_name, list_id, mail_from, raw, sets, extra_env,
        )
        .await
    }

    /// Compile `source` and evaluate it as a single policy tier against `raw`, returning the same
    /// [`PolicyOutcome`] a loaded, named policy would (see [`evaluate`](Self::evaluate)). Unlike
    /// [`evaluate`](Self::evaluate) this does not require the script to be pre-loaded — it compiles
    /// the given bytes on the spot — so it is meant for ad-hoc script debugging outside the daemon
    /// (see the `carriers-sieve` binary), not for the daemon's own evaluation chain. `display_name`
    /// is used only for error messages and Sieve's script cache key.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_source(
        &self,
        display_name: &str,
        source: &[u8],
        list_name: &str,
        list_id: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
        extra_env: &[(&str, &str)],
    ) -> Result<PolicyOutcome> {
        let script = self
            .engine
            .compile(source)
            .map_err(|e| Error::Config(format!("compiling `{display_name}`: {e}")))?;
        self.run_tier(
            &script,
            display_name,
            list_name,
            list_id,
            mail_from,
            raw,
            sets,
            extra_env,
        )
        .await
    }

    /// Like [`evaluate_source`](Self::evaluate_source), but also returns everything the script did:
    /// the interpreted [`PolicyOutcome`], the ordered list of raw Sieve actions it performed (see
    /// [`SieveAction`]), and the rewritten message bytes if it edited headers. For inspecting a
    /// script's full behaviour (see the `carriers-sieve` binary), not part of the daemon's chain.
    #[allow(clippy::too_many_arguments)]
    pub async fn trace_source(
        &self,
        display_name: &str,
        source: &[u8],
        list_name: &str,
        list_id: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
        extra_env: &[(&str, &str)],
    ) -> Result<PolicyTrace> {
        let script = self
            .engine
            .compile(source)
            .map_err(|e| Error::Config(format!("compiling `{display_name}`: {e}")))?;
        // Mirror `run_script`'s environment assembly: the list identity first, then the caller's
        // extra items.
        let mut env = vec![(ENV_LIST, list_name), (ENV_LIST_ID, list_id)];
        env.extend_from_slice(extra_env);
        let (run, actions) = self
            .engine
            .run_traced(
                display_name,
                &script,
                raw,
                mail_from,
                &env,
                sets,
                &NoDuplicates,
            )
            .await?;
        let rewritten = run.message.clone();
        Ok(PolicyTrace {
            outcome: outcome_from_run(run),
            actions,
            rewritten,
        })
    }

    /// The "before" half of the policy chain, decided at intake: the global "before" drop-ins,
    /// this domain's "before" drop-ins, then the named list policy — each group of drop-ins run
    /// in filename order. See the module docs for how these compose. Any group that is empty
    /// (unconfigured, or the domain has no entry) is simply skipped. The "after" half runs later,
    /// in [`PolicyEngine::evaluate_after`].
    ///
    /// The returned `archive` flag is the union across every script that ran, so a message is
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
        extra_env: &[(&str, &str)],
    ) -> Result<PolicyOutcome> {
        let domain_scripts = self.domains.get(domain);
        let mut acc = Accumulator::default();

        // The built-in DMARC gate runs first, ahead of every configurable tier — a message
        // failing DMARC against an enforcing domain policy is rejected before it can even reach
        // moderation. See `builtin_policies/dmarc-before.sieve` and `crate::sign::AuthVerdict`.
        self.run_scripts(
            std::slice::from_ref(&self.dmarc_before_gate),
            "dmarc-before",
            list_name,
            list_id,
            mail_from,
            raw,
            sets,
            extra_env,
            &mut acc,
        )
        .await?;

        self.run_scripts(
            &self.global_before,
            "global-before",
            list_name,
            list_id,
            mail_from,
            raw,
            sets,
            extra_env,
            &mut acc,
        )
        .await?;
        if let Some(d) = domain_scripts {
            self.run_scripts(
                &d.before,
                "domain-before",
                list_name,
                list_id,
                mail_from,
                raw,
                sets,
                extra_env,
                &mut acc,
            )
            .await?;
        }

        // An earlier `Moderate`/terminal already decided the message's fate; the list's own
        // policy only runs while the decision so far is still `Approve`.
        if matches!(acc.decision, PolicyDecision::Approve) {
            let out = self
                .evaluate(
                    policy_name,
                    list_name,
                    list_id,
                    mail_from,
                    raw,
                    sets,
                    extra_env,
                )
                .await?;
            acc.merge(out);
        }
        Ok(acc.into_outcome())
    }

    /// The "after" half of the policy chain, decided at distribution time — after moderation —
    /// so it has the final word on a message about to go out (see
    /// [`crate::pipeline::finalize`]): this domain's "after" drop-ins, then the global "after"
    /// drop-ins, each run in filename order. It starts from `Approve` (only about-to-distribute
    /// messages reach it) and may tighten that to a hold, discard, or reject — or archive it.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_after(
        &self,
        list_name: &str,
        list_id: &str,
        domain: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
        extra_env: &[(&str, &str)],
    ) -> Result<PolicyOutcome> {
        let domain_scripts = self.domains.get(domain);
        let mut acc = Accumulator::default();

        // The built-in DMARC gate runs first: the last-word check on whether this message may
        // carry the list's own DKIM signature (or must be rejected outright, if the author
        // domain's DNS/policy state changed since an earlier "before"-tier pass let it through —
        // see `builtin_policies/dmarc-after.sieve`).
        self.run_scripts(
            std::slice::from_ref(&self.dmarc_after_gate),
            "dmarc-after",
            list_name,
            list_id,
            mail_from,
            raw,
            sets,
            extra_env,
            &mut acc,
        )
        .await?;

        if let Some(d) = domain_scripts {
            self.run_scripts(
                &d.after,
                "domain-after",
                list_name,
                list_id,
                mail_from,
                raw,
                sets,
                extra_env,
                &mut acc,
            )
            .await?;
        }
        self.run_scripts(
            &self.global_after,
            "global-after",
            list_name,
            list_id,
            mail_from,
            raw,
            sets,
            extra_env,
            &mut acc,
        )
        .await?;
        Ok(acc.into_outcome())
    }

    /// Run each script in `scripts` in order, folding its outcome into `acc`, until one reaches a
    /// terminal (`Discard`/`Reject`) decision — after which the remaining scripts are skipped, as
    /// there is nothing left for them to decide.
    #[allow(clippy::too_many_arguments)]
    async fn run_scripts(
        &self,
        scripts: &[Arc<Sieve>],
        tier_name: &str,
        list_name: &str,
        list_id: &str,
        mail_from: &str,
        raw: &[u8],
        sets: &MembershipSets,
        extra_env: &[(&str, &str)],
        acc: &mut Accumulator,
    ) -> Result<()> {
        for script in scripts {
            if is_terminal(&acc.decision) {
                break;
            }
            let out = self
                .run_tier(
                    script, tier_name, list_name, list_id, mail_from, raw, sets, extra_env,
                )
                .await?;
            acc.merge(out);
        }
        Ok(())
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
        extra_env: &[(&str, &str)],
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
                extra_env,
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
        extra_env: &[(&str, &str)],
    ) -> Result<SieveRun> {
        let mut env = vec![(ENV_LIST, list_name), (ENV_LIST_ID, list_id)];
        env.extend_from_slice(extra_env);
        self.engine
            .run(name, script, raw, mail_from, &env, lists, duplicates)
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

/// Running state while folding a sequence of policy tiers/drop-in scripts together: the decision
/// reached so far and whether any of them requested each independent side effect.
struct Accumulator {
    decision: PolicyDecision,
    archive: bool,
    no_own_dkim: bool,
    munge_from: bool,
}

impl Default for Accumulator {
    fn default() -> Self {
        Accumulator {
            decision: PolicyDecision::Approve,
            archive: false,
            no_own_dkim: false,
            munge_from: false,
        }
    }
}

impl Accumulator {
    fn merge(&mut self, out: PolicyOutcome) {
        self.archive |= out.archive;
        self.no_own_dkim |= out.no_own_dkim;
        self.munge_from |= out.munge_from;
        self.decision = merge(
            std::mem::replace(&mut self.decision, PolicyDecision::Approve),
            out.decision,
        );
    }

    fn into_outcome(self) -> PolicyOutcome {
        PolicyOutcome {
            decision: self.decision,
            archive: self.archive,
            no_own_dkim: self.no_own_dkim,
            munge_from: self.munge_from,
        }
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
/// moderation pseudo-mailbox holds the message; filing into `archive`/`no-dkim`/`munge-from`
/// requests that independent side effect (independent of the decision); anything else is
/// ordinary delivery (approve).
fn outcome_from_run(run: SieveRun) -> PolicyOutcome {
    let archive = run.filed_into.iter().any(|f| is_archive_folder(f));
    let no_own_dkim = run.filed_into.iter().any(|f| is_no_dkim_folder(f));
    let munge_from = run.filed_into.iter().any(|f| is_munge_from_folder(f));
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
    PolicyOutcome {
        decision,
        archive,
        no_own_dkim,
        munge_from,
    }
}

fn is_moderate_folder(folder: &str) -> bool {
    MODERATE_FOLDERS
        .iter()
        .any(|m| folder.eq_ignore_ascii_case(m))
}

fn is_archive_folder(folder: &str) -> bool {
    folder.eq_ignore_ascii_case(ARCHIVE_FOLDER)
}

fn is_no_dkim_folder(folder: &str) -> bool {
    folder.eq_ignore_ascii_case(NO_DKIM_FOLDER)
}

fn is_munge_from_folder(folder: &str) -> bool {
    folder.eq_ignore_ascii_case(MUNGE_FROM_FOLDER)
}
