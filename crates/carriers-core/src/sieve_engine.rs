//! A thin, domain-agnostic wrapper around the `sieve` (sieve-rs) compiler and runtime:
//! compiling scripts and running one against a message, translating whatever Sieve action it
//! took into a small [`SieveOutcome`]. Nothing here knows about carriers' mailing-list concepts
//! (subscribers, posters, moderators, named policies) — see [`crate::policy`] for that.

use std::sync::Arc;

use async_trait::async_trait;
use sieve::{Compiler, Envelope, Event, Input, Recipient, Runtime, Script, Sieve};

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
/// it and carries a reason meant to be surfaced back to the sender (RFC 5429). A `fileinto` is
/// not a terminal action here — its destination is reported via [`SieveRun::filed_into`] and
/// interpreted by the caller (see `policy`), so the script continues past it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SieveOutcome {
    /// `keep;`, or the script ran to completion with no decisive action (implicit keep).
    Keep,
    /// `discard;` — silently drop; the sender is not told anything.
    Discard,
    /// `reject "reason";` / `ereject "reason";` — explicitly refuse, with a reason.
    Reject { reason: String },
}

/// One action a Sieve script performed, recorded in the order it happened for tracing/debugging
/// (see [`SieveEngine::run_traced`]). This is the raw Sieve-level action, *before* any
/// carriers-specific interpretation of `fileinto` pseudo-mailboxes or `discard`/`reject` (that
/// meaning is added in [`crate::policy`]); it lets a caller see everything a script did, including
/// actions the [`SieveOutcome`]/[`SieveRun`] summary deliberately drops (`redirect`, `notify`,
/// explicit `keep`, envelope edits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SieveAction {
    /// `keep;` — retain the message, optionally tagging it with the given IMAP flags.
    Keep { flags: Vec<String> },
    /// `discard;`
    Discard,
    /// `reject "reason";` — `extended` is true for the `ereject` form (RFC 5429).
    Reject { extended: bool, reason: String },
    /// `fileinto [:create] [:flags …] "folder";`
    FileInto {
        folder: String,
        flags: Vec<String>,
        create: bool,
    },
    /// `redirect "addr";` (RFC 5228) and its extensions — the message is (also) sent onward.
    Redirect { recipient: String },
    /// `notify "method";` (RFC 5435).
    Notify { method: String, message: String },
    /// A change to the message envelope (e.g. `setenvelope`), naming the field and its new value.
    SetEnvelope { field: String, value: String },
    /// `addheader`/`deleteheader` (RFC 5293) rebuilt the message. The resulting bytes are in
    /// [`SieveRun::message`]; compare them with the input to see exactly which headers changed.
    EditedMessage,
}

/// The result of running one Sieve script.
pub struct SieveRun {
    /// The terminal action the script took.
    pub outcome: SieveOutcome,
    /// The rewritten message bytes if the script edited headers (`addheader`/`deleteheader`,
    /// RFC 5293); `None` when it made no header changes, so the caller keeps the original bytes.
    pub message: Option<Vec<u8>>,
    /// Every `fileinto` destination the script named, in order. carriers reads these as
    /// pseudo-mailboxes (e.g. `moderate`, `archive`) rather than real folders.
    pub filed_into: Vec<String>,
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
        self.run_inner(
            name, script, raw, mail_from, env_vars, lists, duplicates, None,
        )
        .await
    }

    /// Like [`run`](Self::run), but additionally returns every action the script performed, in
    /// order (see [`SieveAction`]) — including ones the [`SieveRun`] summary drops (`redirect`,
    /// `notify`, explicit `keep`, envelope edits). For debugging/tracing a script's full behaviour;
    /// the daemon uses [`run`](Self::run).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_traced(
        &self,
        name: &str,
        script: &Arc<Sieve>,
        raw: &[u8],
        mail_from: &str,
        env_vars: &[(&str, &str)],
        lists: &dyn ExternalLists,
        duplicates: &dyn DuplicateStore,
    ) -> Result<(SieveRun, Vec<SieveAction>)> {
        let mut trace = Vec::new();
        let run = self
            .run_inner(
                name,
                script,
                raw,
                mail_from,
                env_vars,
                lists,
                duplicates,
                Some(&mut trace),
            )
            .await?;
        Ok((run, trace))
    }

    /// Shared driver for [`run`](Self::run)/[`run_traced`](Self::run_traced). When `trace` is
    /// `Some`, every action the script takes is appended to it in order; otherwise the event loop
    /// behaves exactly as before, so the daemon's path is unchanged.
    #[allow(clippy::too_many_arguments)]
    async fn run_inner(
        &self,
        name: &str,
        script: &Arc<Sieve>,
        raw: &[u8],
        mail_from: &str,
        env_vars: &[(&str, &str)],
        lists: &dyn ExternalLists,
        duplicates: &dyn DuplicateStore,
        mut trace: Option<&mut Vec<SieveAction>>,
    ) -> Result<SieveRun> {
        let mut instance = self.runtime.filter(raw);
        if !mail_from.is_empty() {
            instance.set_envelope(Envelope::From, mail_from.to_string());
        }
        for (key, value) in env_vars {
            instance.set_env_variable((*key).to_string(), (*value).to_string());
        }

        // Handle one action the script took: log it as it happens (a `debug`-level event, so it
        // costs nothing unless someone is listening — this is what lets the daemon surface a
        // script's actions under debug logging), then append it to the trace if one is being
        // collected. The action is the primitive; [`SieveRun`] is its fold (built inline below),
        // and [`run_traced`](Self::run_traced) hands the same list back for a caller to iterate.
        macro_rules! record {
            ($action:expr) => {{
                let action = $action;
                tracing::debug!(target: "carriers_core::sieve_engine", script = name, ?action, "sieve action");
                if let Some(t) = trace.as_deref_mut() {
                    t.push(action);
                }
            }};
        }

        let mut outcome = None;
        let mut message = None;
        let mut filed_into = Vec::new();
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
                    record!(SieveAction::EditedMessage);
                    true.into()
                }
                Event::Keep { flags, .. } => {
                    record!(SieveAction::Keep { flags });
                    true.into()
                }
                Event::Discard => {
                    outcome.get_or_insert(SieveOutcome::Discard);
                    record!(SieveAction::Discard);
                    true.into()
                }
                Event::Reject { reason, extended } => {
                    outcome.get_or_insert(SieveOutcome::Reject {
                        reason: reason.clone(),
                    });
                    record!(SieveAction::Reject { extended, reason });
                    true.into()
                }
                // `fileinto` is a side channel, not a terminal action: record the destination and
                // keep running, so the script can both file the message and reach a `keep`,
                // `discard`, or `reject` afterwards.
                Event::FileInto {
                    folder,
                    flags,
                    create,
                    ..
                } => {
                    record!(SieveAction::FileInto {
                        folder: folder.clone(),
                        flags,
                        create,
                    });
                    filed_into.push(folder);
                    true.into()
                }
                // `redirect` — the message is sent onward to another recipient.
                Event::SendMessage { recipient, .. } => {
                    record!(SieveAction::Redirect {
                        recipient: recipient_str(&recipient),
                    });
                    true.into()
                }
                Event::Notify {
                    method, message: m, ..
                } => {
                    record!(SieveAction::Notify { method, message: m });
                    true.into()
                }
                Event::SetEnvelope { envelope, value } => {
                    record!(SieveAction::SetEnvelope {
                        field: format!("{envelope:?}"),
                        value,
                    });
                    true.into()
                }
                // Anything else (e.g. an external `Function` call, which carriers never registers):
                // leave the outcome as-is and keep running.
                _ => true.into(),
            };
        }
        Ok(SieveRun {
            // No decisive action ran: implicit keep.
            outcome: outcome.unwrap_or(SieveOutcome::Keep),
            message,
            filed_into,
        })
    }
}

/// Render a redirect recipient for a trace line.
fn recipient_str(recipient: &Recipient) -> String {
    match recipient {
        Recipient::Address(addr) => addr.clone(),
        Recipient::List(list) => format!("list:{list}"),
        Recipient::Group(group) => group.join(", "),
    }
}
