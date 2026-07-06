//! DKIM-safe message transformation.
//!
//! The only transformation we perform is *prepending* `List-*` headers. We never modify the
//! body or any existing header, so the author's original DKIM signature stays valid. New
//! headers placed above the originals do not affect an existing signature (its `h=` tag
//! enumerates exactly which headers it covers, and it never covers a header that was absent
//! when it was created).

use std::fmt::Write as _;

use crate::list::List;

/// Build the `List-*` header block (RFC 2369 + RFC 8058) as CRLF-terminated header lines.
pub fn list_headers(list: &List) -> String {
    let cfg = &list.cfg;
    let mut out = String::new();

    let description = cfg
        .display_name
        .clone()
        .unwrap_or_else(|| list.name.clone());
    let _ = write!(out, "List-Id: {description} <{}>\r\n", list.list_id());
    let _ = write!(out, "List-Post: <mailto:{}>\r\n", cfg.posting_address);

    if let Some(url) = &cfg.help_url {
        let _ = write!(out, "List-Help: <{url}>\r\n");
    }
    if let Some(url) = &cfg.subscribe_url {
        let _ = write!(out, "List-Subscribe: <{url}>\r\n");
    }
    // Prefer one-click unsubscribe (RFC 8058), otherwise fall back to a plain link.
    if let Some(target) = &cfg.unsubscribe_oneclick {
        let _ = write!(out, "List-Unsubscribe: <{target}>\r\n");
        out.push_str("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n");
    } else if let Some(url) = &cfg.unsubscribe_url {
        let _ = write!(out, "List-Unsubscribe: <{url}>\r\n");
    }
    if let Some(url) = &cfg.archive_url {
        let _ = write!(out, "List-Archive: <{url}>\r\n");
    }
    if let Some(owner) = &cfg.owner {
        let _ = write!(out, "List-Owner: <mailto:{owner}>\r\n");
    }
    out
}

/// Prepend the `List-*` headers to `raw`, leaving the original bytes untouched.
///
/// The result is `list_headers || raw`, which preserves the author's DKIM signature.
pub fn augment(list: &List, raw: &[u8]) -> Vec<u8> {
    let headers = list_headers(list);
    let mut out = Vec::with_capacity(headers.len() + raw.len());
    out.extend_from_slice(headers.as_bytes());
    out.extend_from_slice(raw);
    out
}
