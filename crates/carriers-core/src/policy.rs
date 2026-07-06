//! Sieve-based moderation policies.
//!
//! A policy is a Sieve script file (`<name>.sieve`) placed in the configured policies directory
//! by the administrator; a list selects one by name via `[policy] sieve = "<name>"`. Policies
//! are global and static — compiled once at startup.
//!
//! The four built-in `[policy] posting` modes (`open`, `subscribers`, `members`, `moderated`)
//! are themselves compiled Sieve scripts (see [`BUILTIN_SCRIPTS`]), so every list — whether it
//! uses a built-in mode or a custom script — is moderated through this one engine.
//!
//! A script decides what happens to a post through ordinary Sieve actions:
//!
//! - `keep;` (or doing nothing) — **approve**: distribute the post now.
//! - `fileinto "moderate";` — **hold** the post for moderation.
//! - `discard;` or `reject "…";` — **reject** (drop) the post.
//!
//! Membership is exposed as Sieve external lists, resolved against the *current* list, so a
//! single global script adapts per mailing list:
//!
//! - `subscribers` — addresses that receive the list.
//! - `members` — every address in the member database (a superset of subscribers).
//! - `moderators` — addresses flagged as moderators.
//!
//! ```sieve
//! require ["envelope", "extlists", "fileinto"];
//! if address :list "from" "subscribers" { keep; }
//! elsif address :list "from" "members" { fileinto "moderate"; }
//! else { discard; }
//! ```

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use sieve::{Compiler, Envelope, Event, Input, Runtime, Script, Sieve};

use crate::error::{Error, Result};

/// External list names exposed to policy scripts via the Sieve `:list` match.
pub const LIST_SUBSCRIBERS: &str = "subscribers";
pub const LIST_MEMBERS: &str = "members";
pub const LIST_MODERATORS: &str = "moderators";

/// Names of the built-in policies. These mirror the `[policy] posting` modes and are reserved:
/// an administrator's `<name>.sieve` file may not use them. Each is itself a Sieve script (see
/// [`BUILTIN_SCRIPTS`]), so built-in and custom policies share one evaluation path.
pub const BUILTIN_OPEN: &str = "open";
pub const BUILTIN_SUBSCRIBERS: &str = "subscribers";
pub const BUILTIN_MEMBERS: &str = "members";
pub const BUILTIN_MODERATED: &str = "moderated";

/// The built-in policies, expressed as Sieve scripts, as `(name, script)` pairs.
const BUILTIN_SCRIPTS: &[(&str, &str)] = &[
    // Anyone may post: an empty script leaves the implicit keep in place (approve).
    (BUILTIN_OPEN, "# open: anyone may post\n"),
    // Subscribers post directly; anyone else is held for moderation.
    (
        BUILTIN_SUBSCRIBERS,
        "require [\"extlists\", \"fileinto\"];\n\
         if not address :list \"from\" \"subscribers\" { fileinto \"moderate\"; }\n",
    ),
    // Any member of the database posts directly; anyone else is held for moderation.
    (
        BUILTIN_MEMBERS,
        "require [\"extlists\", \"fileinto\"];\n\
         if not address :list \"from\" \"members\" { fileinto \"moderate\"; }\n",
    ),
    // Every post is held for moderation.
    (
        BUILTIN_MODERATED,
        "require [\"fileinto\"];\nfileinto \"moderate\";\n",
    ),
];

/// True if `name` is a reserved built-in policy name.
pub fn is_builtin(name: &str) -> bool {
    BUILTIN_SCRIPTS.iter().any(|(n, _)| *n == name)
}

/// The decision a policy reached for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Distribute the message now.
    Approve,
    /// Hold the message for moderation.
    Moderate,
    /// Reject (drop) the message.
    Reject,
}

/// Membership facts for the current list, resolved before evaluating a (synchronous) script.
/// Addresses are stored lowercased.
#[derive(Default)]
pub struct MembershipSets {
    pub subscribers: HashSet<String>,
    pub members: HashSet<String>,
    pub moderators: HashSet<String>,
}

impl MembershipSets {
    fn contains(&self, list: &str, value: &str) -> bool {
        let value = value.to_ascii_lowercase();
        match list {
            LIST_SUBSCRIBERS => self.subscribers.contains(&value),
            LIST_MEMBERS => self.members.contains(&value),
            LIST_MODERATORS => self.moderators.contains(&value),
            _ => false,
        }
    }
}

/// A registry of compiled Sieve policies loaded from a directory of `*.sieve` files.
pub struct PolicyEngine {
    runtime: Runtime,
    policies: HashMap<String, Arc<Sieve>>,
}

impl PolicyEngine {
    /// An engine with only the built-in policies compiled.
    pub fn new() -> Result<Self> {
        let mut runtime = Runtime::new();
        runtime.set_valid_ext_list(LIST_SUBSCRIBERS);
        runtime.set_valid_ext_list(LIST_MEMBERS);
        runtime.set_valid_ext_list(LIST_MODERATORS);

        let compiler = Compiler::new();
        let mut policies = HashMap::new();
        for (name, script) in BUILTIN_SCRIPTS {
            let compiled = compiler
                .compile(script.as_bytes())
                .map_err(|e| Error::Config(format!("compiling built-in policy `{name}`: {e}")))?;
            policies.insert((*name).to_string(), Arc::new(compiled));
        }
        Ok(PolicyEngine { runtime, policies })
    }

    /// The built-in policies plus every custom `*.sieve` file in `dir` (the file stem is the
    /// policy name). Custom policies may not reuse a built-in name.
    pub fn load(dir: &Path) -> Result<Self> {
        let mut engine = Self::new()?;
        let compiler = Compiler::new();
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
                let script = compiler.compile(&text).map_err(|e| {
                    Error::Config(format!("compiling policy {}: {e}", path.display()))
                })?;
                engine.policies.insert(name, Arc::new(script));
            }
        }
        Ok(engine)
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

        let mut instance = self.runtime.filter(raw);
        if !mail_from.is_empty() {
            instance.set_envelope(Envelope::From, mail_from.to_string());
        }
        instance.set_env_variable("vnd.carriers.list", list_name.to_string());

        let mut decision: Option<PolicyDecision> = None;
        let mut input = Input::script(Script::Personal(name.to_string()), script.clone());
        while let Some(event) = instance.run(input) {
            let event =
                event.map_err(|e| Error::Auth(format!("policy `{name}` runtime error: {e:?}")))?;
            input = match event {
                Event::ListContains { lists, values, .. } => lists
                    .iter()
                    .any(|list| values.iter().any(|value| sets.contains(list, value)))
                    .into(),
                Event::MailboxExists { .. } | Event::DuplicateId { .. } => false.into(),
                Event::IncludeScript { optional, .. } => {
                    if optional {
                        Input::False
                    } else {
                        return Err(Error::Config(format!(
                            "policy `{name}` uses unsupported script includes"
                        )));
                    }
                }
                Event::Reject { .. } | Event::Discard => {
                    decision.get_or_insert(PolicyDecision::Reject);
                    true.into()
                }
                Event::FileInto { folder, .. } => {
                    decision.get_or_insert(classify_folder(&folder));
                    true.into()
                }
                // Keep and any other action: leave the (default) decision as-is.
                _ => true.into(),
            };
        }
        // No decisive action (implicit keep) means approve.
        Ok(decision.unwrap_or(PolicyDecision::Approve))
    }
}

fn classify_folder(folder: &str) -> PolicyDecision {
    match folder.to_ascii_lowercase().as_str() {
        "moderate" | "moderation" | "hold" => PolicyDecision::Moderate,
        "reject" | "discard" => PolicyDecision::Reject,
        // Any other destination is treated as a normal delivery: approve.
        _ => PolicyDecision::Approve,
    }
}
