//! A thin, domain-agnostic wrapper around the `sieve` (sieve-rs) compiler and runtime:
//! compiling scripts and running one against a message, translating whatever Sieve action it
//! took into a small [`SieveOutcome`]. Nothing here knows about carriers' mailing-list concepts
//! (subscribers, posters, moderators, named policies) — see [`crate::policy`] for that.

use std::sync::Arc;

use async_trait::async_trait;
use sieve::compiler::grammar::Capability;
use sieve::runtime::Variable;
use sieve::{Compiler, Envelope, Event, FunctionMap, Input, Runtime, Script, Sieve};

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

/// A host function exposed to scripts, as its script-visible name and the number of arguments it
/// takes. Both are fixed at compile time: [`SieveEngine::new`] registers the whole catalogue with
/// the compiler, which rejects a call to an unknown name or with the wrong argument count.
pub struct FunctionSpec {
    pub name: &'static str,
    pub args: u32,
}

/// The value a host function hands back to the script that called it.
pub enum FunctionValue {
    Bool(bool),
    Integer(i64),
    String(String),
}

impl From<FunctionValue> for Variable {
    fn from(value: FunctionValue) -> Self {
        match value {
            FunctionValue::Bool(v) => v.into(),
            FunctionValue::Integer(v) => v.into(),
            FunctionValue::String(v) => v.into(),
        }
    }
}

/// Implements the host functions declared to [`SieveEngine::new`]. A call is dispatched by the
/// function's index in that catalogue, with its arguments stringified in the order the script
/// wrote them.
///
/// Unlike this module's other traits, an implementation is expected to act on the world outside
/// the message — that is the whole point: these are how a script reaches a database or a remote
/// service (see `policy::BounceFunctions`). A call blocks the script, so an implementation owes
/// the caller a bounded running time.
#[async_trait]
pub trait SieveFunctions: Send + Sync {
    async fn call(&self, index: usize, args: Vec<String>) -> Result<FunctionValue>;
}

/// A [`SieveFunctions`] that implements nothing: any call fails the script. Used by the tiers
/// that expose no host functions at all, so calling one there fails loudly rather than quietly
/// returning a value that looks like it did something.
pub struct NoFunctions;

#[async_trait]
impl SieveFunctions for NoFunctions {
    async fn call(&self, _index: usize, _args: Vec<String>) -> Result<FunctionValue> {
        Err(Error::Config(
            "this script tier exposes no callable functions".to_string(),
        ))
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
    /// other name is simply never true. `functions` is the catalogue of host functions scripts
    /// may call; a call to one surfaces to the [`SieveFunctions`] given to [`SieveEngine::run`],
    /// identified by the function's index here.
    pub fn new(valid_lists: &[&'static str], functions: &[FunctionSpec]) -> Self {
        // `vnd.stalwart.expressions` is off by default but is the only way a script can call a
        // host function at all (there is no statement form — a call is an expression), so the
        // catalogue above would be unreachable without it.
        let mut runtime = Runtime::new().with_capability(Capability::Expressions);
        for name in valid_lists {
            runtime.set_valid_ext_list(*name);
        }

        // Registered as *external* functions — declared to the compiler (so a script can call
        // them, and is rejected at compile time if it gets the name or argument count wrong) but
        // deliberately left unimplemented in the runtime, which is what makes each call surface
        // as an `Event::Function` we can answer asynchronously. A natively registered function
        // would have to be a plain `fn`, with no way to await a database or a network round trip.
        let mut fnc_map = FunctionMap::new();
        for (index, spec) in functions.iter().enumerate() {
            fnc_map = fnc_map.with_external_function(spec.name, index as u32, spec.args);
        }

        SieveEngine {
            compiler: Compiler::new().register_functions(&mut fnc_map),
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
    /// `duplicates` answers the `duplicate` test; `functions` implements the host functions the
    /// script calls.
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
        functions: &dyn SieveFunctions,
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
                Event::Function { id, arguments } => {
                    let args = arguments
                        .iter()
                        .map(|arg| arg.to_string().into_owned())
                        .collect();
                    Input::FncResult(functions.call(id as usize, args).await?.into())
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
                // `fileinto` is a side channel, not a terminal action: record the destination and
                // keep running, so the script can both file the message and reach a `keep`,
                // `discard`, or `reject` afterwards.
                Event::FileInto { folder, .. } => {
                    filed_into.push(folder);
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
            filed_into,
        })
    }
}
