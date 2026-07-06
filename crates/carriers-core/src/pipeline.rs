//! The message-processing pipeline: policy checks, transformation, signing and sealing.

use mail_auth::MessageAuthenticator;
use mail_parser::{HeaderName, MessageParser};

use crate::error::{Error, Result};
use crate::list::List;
use crate::member::MemberProvider;
use crate::sign::{sign_and_seal, Ingress};
use crate::store::Store;
use crate::transform::augment;

/// The outcome of preparing an inbound post for distribution.
pub struct Prepared {
    /// The final signed + sealed message, identical for every recipient.
    pub message: Vec<u8>,
    /// Subscriber addresses to deliver to.
    pub recipients: Vec<String>,
    /// Local part of the list's posting address, used to build the VERP return path.
    pub return_path_local: String,
    /// List domain, used to build the VERP return path.
    pub list_domain: String,
}

/// Build a VERP (Variable Envelope Return Path) bounce address encoding the recipient, so a
/// later bounce can be attributed to the subscriber that failed.
///
/// e.g. `verp("dev", "lists.example.org", "user@example.com")`
/// -> `dev+bounce=user=example.com@lists.example.org`.
pub fn verp(list_local: &str, list_domain: &str, recipient: &str) -> String {
    let encoded = recipient.replacen('@', "=", 1);
    format!("{list_local}+bounce={encoded}@{list_domain}")
}

/// Validate posting policy, then transform, sign and seal the message for distribution.
///
/// Returns [`Error::Rejected`] when the message must not be distributed (non-subscriber post,
/// loop, or duplicate) — callers should accept-and-drop these rather than bounce, to avoid
/// backscatter.
pub async fn prepare(
    authenticator: &MessageAuthenticator,
    store: &Store,
    members: &dyn MemberProvider,
    list: &List,
    hostname: &str,
    ingress: &Ingress,
    raw: &[u8],
) -> Result<Prepared> {
    let parsed = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| Error::Rejected("unparseable message".into()))?;

    // Loop guard: refuse a message that already carries our List-Id.
    if let Some(value) = parsed.header(HeaderName::ListId) {
        if value
            .as_text()
            .is_some_and(|text| text.contains(&list.list_id()))
        {
            return Err(Error::Rejected(
                "message already carries this List-Id (loop)".into(),
            ));
        }
    }

    // Posting policy: optionally restrict posting to subscribers.
    let from = parsed
        .from()
        .and_then(|addr| addr.first())
        .and_then(|addr| addr.address())
        .map(|s| s.to_ascii_lowercase());
    if list.cfg.policy.subscribers_only {
        let sender = from.as_deref().unwrap_or("");
        if !members.is_member(&list.name, sender).await? {
            return Err(Error::Rejected(format!(
                "sender `{sender}` is not a subscriber of `{}`",
                list.name
            )));
        }
    }

    // Duplicate suppression by Message-ID.
    if let Some(message_id) = parsed.message_id() {
        if !store.record_message(&list.name, message_id).await? {
            return Err(Error::Rejected(format!(
                "duplicate Message-ID `{message_id}`"
            )));
        }
    }

    let recipients = members.recipients(&list.name).await?;

    let augmented = augment(list, raw);
    let message = sign_and_seal(authenticator, list, hostname, &augmented, ingress).await?;

    let return_path_local = list
        .cfg
        .posting_address
        .split('@')
        .next()
        .unwrap_or("list")
        .to_string();

    Ok(Prepared {
        message,
        recipients,
        return_path_local,
        list_domain: list.domain.clone(),
    })
}
