//! DKIM-safe `List-*` header injection.
//!
//! The only transformation carriers performs is *adding* `List-*` headers (RFC 2369 + RFC 8058);
//! the body and existing headers are never touched, so the author's original DKIM signature
//! stays valid. The mechanical insertion is done by the built-in `list-headers.sieve` script
//! (via `addheader`, which prepends); this module only computes the header *values* from the
//! list config and exposes them to that script as environment variables.

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
