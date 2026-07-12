//! Craft or replay an inbound message and inject it into the daemon's ingress listener.
//!
//! Two shapes of test message: one built from parts here (optionally signed as the author, the
//! way a real MUA/MTA would DKIM-sign before it ever reaches a list), or an existing `.eml`
//! replayed verbatim so real-world messages can be exercised. Injection is a plain SMTP
//! submission via `mail-send`, exactly like the front MTA a production deployment sits behind.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::DkimSigner;
use mail_auth::dkim2::{Dkim2Signer, Hop};
use mail_send::SmtpClientBuilder;
use mail_send::smtp::message::Message;

use carriers_core::crypto::load_dkim_key;
use carriers_core::list::{Algorithm, KeyConfig};

/// The author key used to DKIM-sign a crafted message, as it would be published in DNS.
pub struct AuthorKey {
    pub key_file: PathBuf,
    pub selector: String,
    pub domain: String,
    pub algorithm: Algorithm,
}

/// A message to craft from parts.
pub struct Draft {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    /// Extra header lines as `(name, value)`, inserted below the standard headers.
    pub extra_headers: Vec<(String, String)>,
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Build a raw RFC 5322 message (CRLF line endings) from `draft`, with a unique `Message-ID` so
/// repeated sends are not swallowed by the daemon's duplicate detection.
pub fn build(draft: &Draft) -> Vec<u8> {
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let from_domain = draft
        .from
        .rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('>'))
        .unwrap_or("example.com");

    let mut headers = format!(
        "From: {from}\r\n\
         To: {to}\r\n\
         Subject: {subject}\r\n\
         Date: Mon, 06 Jul 2026 10:00:00 +0000\r\n\
         Message-ID: <{nanos}.{seq}@{from_domain}>\r\n\
         MIME-Version: 1.0\r\n",
        from = draft.from,
        to = draft.to,
        subject = draft.subject,
    );
    for (name, value) in &draft.extra_headers {
        headers.push_str(&format!("{name}: {value}\r\n"));
    }

    let body = normalize_crlf(&draft.body);
    let mut out = headers.into_bytes();
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&body);
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// The header names an author signs over. Mirrors the set a typical MUA covers, and the set the
/// `roundtrip.rs` fixtures use.
const AUTHOR_SIGNED_HEADERS: &[&str] = &[
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
];

/// Prepend an author DKIM signature to `raw`, producing `DKIM-Signature || raw` with the original
/// bytes untouched — the same layering carriers relies on to keep the author signature valid.
pub fn sign_as_author(raw: &[u8], key: &AuthorKey) -> Result<Vec<u8>> {
    let dkim_key = load_dkim_key(&KeyConfig {
        selector: key.selector.clone(),
        key_file: key.key_file.clone(),
        algorithm: key.algorithm,
        domain: Some(key.domain.clone()),
    })
    .context("loading author DKIM key")?;

    let signer = DkimSigner::from_key(dkim_key)
        .domain(key.domain.clone())
        .selector(key.selector.clone())
        .headers(AUTHOR_SIGNED_HEADERS.iter().map(|s| s.to_string()));

    let signature = signer
        .sign(raw)
        .map_err(|e| anyhow::anyhow!("author DKIM signing failed: {e}"))?;

    let mut out = signature.to_header().into_bytes();
    out.extend_from_slice(raw);
    Ok(out)
}

/// Prepend an author DKIM2 chain link to `raw`, simulating a message that already participates
/// in a DKIM2 chain (draft-ietf-dkim-dkim2-spec) before it ever reaches the list — this is the
/// only case in which carriers itself will extend the chain further (see
/// `carriers_core::sign::should_sign_dkim2`). `mail_from`/`rcpt_to` are the envelope this
/// origination hop binds to (the author's own submission envelope, not the list's).
pub fn sign_as_author_dkim2(
    raw: &[u8],
    key: &AuthorKey,
    mail_from: &str,
    rcpt_to: &str,
) -> Result<Vec<u8>> {
    let dkim_key = load_dkim_key(&KeyConfig {
        selector: key.selector.clone(),
        key_file: key.key_file.clone(),
        algorithm: key.algorithm,
        domain: Some(key.domain.clone()),
    })
    .context("loading author DKIM2 key")?;

    let signer = Dkim2Signer::from_key(dkim_key)
        .domain(key.domain.clone())
        .selector(key.selector.clone());

    let signed = signer
        .sign(raw, Hop::real(mail_from, [rcpt_to]))
        .map_err(|e| anyhow::anyhow!("author DKIM2 signing failed: {e}"))?;

    let mut out = signed.to_header().into_bytes();
    out.extend_from_slice(raw);
    Ok(out)
}

/// Load an existing `.eml` file, normalizing line endings to CRLF for SMTP submission.
pub fn load_eml(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(normalize_crlf_bytes(&bytes))
}

/// Prepare in-memory message bytes (e.g. an embedded fixture) for replay: CRLF-normalized.
pub fn prepare(bytes: &[u8]) -> Vec<u8> {
    normalize_crlf_bytes(bytes)
}

/// Inject `raw` into the ingress listener at `host:port` via a plain SMTP submission.
pub async fn inject(host: &str, port: u16, mail_from: &str, rcpt: &str, raw: &[u8]) -> Result<()> {
    let mut client = SmtpClientBuilder::new(host.to_string(), port)
        .map_err(|e| anyhow::anyhow!("invalid ingress host {host}: {e}"))?
        .implicit_tls(false)
        .connect_plain()
        .await
        .with_context(|| format!("connecting to ingress {host}:{port}"))?;
    client
        .send(Message::new(
            mail_from.to_string(),
            vec![rcpt.to_string()],
            raw.to_vec(),
        ))
        .await
        .context("submitting message to ingress")?;
    let _ = client.quit().await;
    Ok(())
}

/// Normalize a `str` to CRLF line endings.
fn normalize_crlf(s: &str) -> Vec<u8> {
    normalize_crlf_bytes(s.as_bytes())
}

/// Normalize bytes to CRLF: every line terminator becomes exactly one `\r\n`, whether the input
/// used bare `\n` or `\r\n`. Idempotent for already-CRLF input, so an author signature computed
/// over CRLF survives replay.
fn normalize_crlf_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' if bytes.get(i + 1) == Some(&b'\n') => {
                out.extend_from_slice(b"\r\n");
                i += 2;
            }
            b'\r' | b'\n' => {
                out.extend_from_slice(b"\r\n");
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}
