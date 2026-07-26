//! DKIM-safe `List-*` header injection, plus the From/Reply-To munging mechanism.
//!
//! The default transformation carriers performs is *adding* `List-*` headers (RFC 2369 + RFC
//! 8058); the body and existing headers are never touched, so the author's original DKIM
//! signature stays valid. The mechanical insertion is done by the built-in `list-headers.sieve`
//! script (via `addheader`, which prepends); this module only computes the header *values* from
//! the list config and exposes them to that script as environment variables.
//!
//! [`munge_from_env`] backs the separate, DKIM-*breaking* `munge-from.sieve` mechanism (mailman3's
//! `munge_from` DMARC mitigation): rewriting `From`/`Reply-To` to the list's own identity. This is
//! deliberately never applied by default — see `builtin_policies/munge-from.sieve`.

use mail_parser::MessageParser;

use crate::list::List;

/// Environment variable names carrying each `List-*` header value to `list-headers.sieve`. These
/// must match the `${env.…}` references in that script.
pub const HDR_LIST_ID: &str = "vnd.carriers.hdr_list_id";
pub const HDR_LIST_POST: &str = "vnd.carriers.hdr_list_post";
pub const HDR_LIST_HELP: &str = "vnd.carriers.hdr_list_help";
pub const HDR_LIST_SUBSCRIBE: &str = "vnd.carriers.hdr_list_subscribe";
pub const HDR_LIST_UNSUBSCRIBE: &str = "vnd.carriers.hdr_list_unsubscribe";
pub const HDR_LIST_UNSUBSCRIBE_POST: &str = "vnd.carriers.hdr_list_unsubscribe_post";
pub const HDR_LIST_ARCHIVE: &str = "vnd.carriers.hdr_list_archive";
pub const HDR_LIST_OWNER: &str = "vnd.carriers.hdr_list_owner";

/// Compute the `(env-var, value)` pairs for the `List-*` headers of `list`. Every variable is
/// present; a header the list has no value for maps to an empty string, which the script skips.
pub fn list_header_env(list: &List) -> Vec<(&'static str, String)> {
    let cfg = &list.cfg;

    let description = cfg
        .display_name
        .clone()
        .unwrap_or_else(|| list.name.clone());

    // List-Unsubscribe prefers the one-click target (RFC 8058), else a plain link. The
    // `List-Unsubscribe-Post` companion is only emitted for the one-click form.
    let (unsubscribe, unsubscribe_post) = match (&cfg.unsubscribe_oneclick, &cfg.unsubscribe_url) {
        (Some(target), _) => (
            format!("<{target}>"),
            "List-Unsubscribe=One-Click".to_string(),
        ),
        (None, Some(url)) => (format!("<{url}>"), String::new()),
        (None, None) => (String::new(), String::new()),
    };

    let angled = |v: &Option<String>| v.as_ref().map(|u| format!("<{u}>")).unwrap_or_default();

    vec![
        (HDR_LIST_ID, format!("{description} <{}>", list.list_id())),
        (HDR_LIST_POST, format!("<mailto:{}>", cfg.posting_address)),
        (HDR_LIST_HELP, angled(&cfg.help_url)),
        (HDR_LIST_SUBSCRIBE, angled(&cfg.subscribe_url)),
        (HDR_LIST_UNSUBSCRIBE, unsubscribe),
        (HDR_LIST_UNSUBSCRIBE_POST, unsubscribe_post),
        (HDR_LIST_ARCHIVE, angled(&cfg.archive_url)),
        (
            HDR_LIST_OWNER,
            cfg.owner
                .as_ref()
                .map(|o| format!("<mailto:{o}>"))
                .unwrap_or_default(),
        ),
    ]
}

/// Environment variable names carrying the munged `From`/`Reply-To` values to `munge-from.sieve`.
pub const MUNGE_FROM: &str = "vnd.carriers.munge_from";
pub const REPLY_TO: &str = "vnd.carriers.reply_to";

/// Compute the `(env-var, value)` pairs for [`crate::policy::PolicyEngine::apply_munge_from`]:
/// a `From` value naming the original sender under the list's own posting address (mailman3-style,
/// `"<original name or address> via <list display name>" <list posting address>`), and a
/// `Reply-To` pointing back at the original sender's address. If `raw`'s `From` can't be parsed,
/// both values fall back to the list's own posting address (munging still succeeds, just with
/// nothing to attribute to).
pub fn munge_from_env(list: &List, raw: &[u8]) -> Vec<(&'static str, String)> {
    let posting_address = &list.cfg.posting_address;
    let list_description = list
        .cfg
        .display_name
        .clone()
        .unwrap_or_else(|| list.name.clone());

    let (original_name, original_address) = MessageParser::default()
        .parse(raw)
        .and_then(|m| m.from().and_then(|addr| addr.first()).cloned())
        .map(|addr| {
            (
                addr.name().map(str::to_string),
                addr.address().map(str::to_string),
            )
        })
        .unwrap_or_default();

    let attribution = original_name
        .filter(|n| !n.is_empty())
        .or_else(|| original_address.clone())
        .unwrap_or_else(|| posting_address.clone());

    vec![
        (
            MUNGE_FROM,
            format!("\"{attribution} via {list_description}\" <{posting_address}>"),
        ),
        (
            REPLY_TO,
            original_address.unwrap_or_else(|| posting_address.clone()),
        ),
    ]
}
