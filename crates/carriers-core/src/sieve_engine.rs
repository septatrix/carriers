//! A thin, domain-agnostic wrapper around the `sieve` (sieve-rs) compiler and runtime:
//! compiling scripts and running one against a message, translating whatever Sieve action it
//! took into a small [`SieveOutcome`]. Nothing here knows about carriers' mailing-list concepts
//! (subscribers, posters, moderators, named policies) — see [`crate::policy`] for that.

use std::sync::Arc;

use async_trait::async_trait;
use sieve::{Compiler, Envelope, Event, Input, Runtime, Script, Sieve};

use crate::error::{Error, Result};

/// Resolves Sieve's `:list` external-list tests (e.g. `address :list "from" "subscribers"`)
/// against caller-specific data. Implemented by the caller — see `policy::MembershipSets`.
///
/// `Send + Sync` because a `&dyn ExternalLists` is held across the `await` in [`SieveEngine::run`].
pub trait ExternalLists: Send + Sync {
    fn contains(&self, list: &str, value: &str) -> bool;
}

/// Resolves Sieve's `duplicate` test (RFC 7352): tracks message identifiers that have been seen
/// so a repeat can be detected. Implemented by the caller against durable storage.
#[async_trait]
pub trait DuplicateStore: Send + Sync {
    /// Whether `id` has already been seen (within the last `expiry` seconds), recording it as
    /// seen now. Returns `true` for a repeat (the `duplicate` test then matches), `false` the
    /// first time an `id` is presented.
    async fn seen_before(&self, id: &str, expiry: u64) -> Result<bool>;
}

/// A [`DuplicateStore`] that records nothing and never reports a duplicate. Used for script tiers
/// that have no business tracking duplicates (everything except the built-in dedup check), so a
/// stray `duplicate` test there is simply inert rather than sharing — and corrupting — the
/// dedup state owned by that one check.
pub struct NoDuplicates;

#[async_trait]
impl DuplicateStore for NoDuplicates {
    async fn seen_before(&self, _id: &str, _expiry: u64) -> Result<bool> {
        Ok(false)
    }
}

/// The terminal action a Sieve script took, decoupled from what it means to the caller.
///
/// `discard` and `reject`/`ereject` are deliberately distinct: `discard` silently drops the
/// message with no indication to the sender (RFC 5228 §4.4), while `reject`/`ereject` refuses
/// it and carries a reason meant to be surfaced back to the sender (RFC 5429).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SieveOutcome {
    /// `keep;`, or the script ran to completion with no decisive action (implicit keep).
    Keep,
    /// `discard;` — silently drop; the sender is not told anything.
    Discard,
    /// `reject "reason";` / `ereject "reason";` — explicitly refuse, with a reason.
    Reject { reason: String },
    /// `fileinto "folder";`.
    FileInto { folder: String },
}

/// The result of running one Sieve script: its terminal [`SieveOutcome`], plus the rewritten
/// message bytes if the script edited headers (`addheader`/`deleteheader`, RFC 5293). `message`
/// is `None` when the script made no header changes, so the caller keeps the original bytes.
pub struct SieveRun {
    pub outcome: SieveOutcome,
    pub message: Option<Vec<u8>>,
}

/// A compiler and runtime for Sieve scripts, plus the external `:list` names scripts may
/// reference.
pub struct SieveEngine {
    compiler: Compiler,
    runtime: Runtime,
}

impl SieveEngine {
    /// `valid_lists` are the external list names (`:list "from" "<name>"`) scripts may use; any
    /// other name is simply never true.
    pub fn new(valid_lists: &[&'static str]) -> Self {
        let mut runtime = Runtime::new();
        for name in valid_lists {
            runtime.set_valid_ext_list(*name);
        }
        SieveEngine {
            compiler: Compiler::new(),
            runtime,
        }
    }

    /// Compile a script's source into a reusable, shareable [`Sieve`].
    pub fn compile(&self, source: &[u8]) -> Result<Arc<Sieve>> {
        self.compiler
            .compile(source)
            .map(Arc::new)
            .map_err(|e| Error::Config(format!("compiling Sieve script: {e}")))
    }

    /// Run `script` (named `name`, for error messages and script-cache keying) against `raw`
    /// and return its terminal action plus any header-edited message (see [`SieveRun`]).
    ///
    /// `mail_from` sets the envelope sender used by `address`/`envelope` tests; `env_vars` are
    /// exposed to the script via the "environment" extension; `lists` answers `:list` tests;
    /// `duplicates` answers the `duplicate` test.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        name: &str,
        script: &Arc<Sieve>,
        raw: &[u8],
        mail_from: &str,
        env_vars: &[(&str, &str)],
        lists: &dyn ExternalLists,
        duplicates: &dyn DuplicateStore,
    ) -> Result<SieveRun> {
        let mut instance = self.runtime.filter(raw);
        if !mail_from.is_empty() {
            instance.set_envelope(Envelope::From, mail_from.to_string());
        }
        for (key, value) in env_vars {
            instance.set_env_variable((*key).to_string(), (*value).to_string());
        }

        let mut outcome = None;
        let mut message = None;
        let mut input = Input::script(Script::Personal(name.to_string()), script.clone());
        while let Some(event) = instance.run(input) {
            let event = event
                .map_err(|e| Error::Auth(format!("Sieve script `{name}` runtime error: {e:?}")))?;
            input = match event {
                Event::ListContains {
                    lists: names,
                    values,
                    ..
                } => names
                    .iter()
                    .any(|list| values.iter().any(|value| lists.contains(list, value)))
                    .into(),
                Event::DuplicateId { id, expiry, .. } => {
                    duplicates.seen_before(&id, expiry).await?.into()
                }
                Event::MailboxExists { .. } => false.into(),
                Event::IncludeScript { optional, .. } => {
                    if optional {
                        Input::False
                    } else {
                        return Err(Error::Config(format!(
                            "Sieve script `{name}` uses unsupported script includes"
                        )));
                    }
                }
                // The message the script rebuilt after an `addheader`/`deleteheader` edit. The
                // original headers and body are copied verbatim, so a prepended header leaves the
                // author's DKIM signature intact.
                Event::CreatedMessage { message: bytes, .. } => {
                    message = Some(bytes);
                    true.into()
                }
                Event::Discard => {
                    outcome.get_or_insert(SieveOutcome::Discard);
                    true.into()
                }
                Event::Reject { reason, .. } => {
                    outcome.get_or_insert(SieveOutcome::Reject { reason });
                    true.into()
                }
                Event::FileInto { folder, .. } => {
                    outcome.get_or_insert(SieveOutcome::FileInto { folder });
                    true.into()
                }
                // Keep and any other action: leave the (default) outcome as-is.
                _ => true.into(),
            };
        }
        Ok(SieveRun {
            // No decisive action ran: implicit keep.
            outcome: outcome.unwrap_or(SieveOutcome::Keep),
            message,
        })
    }
}
