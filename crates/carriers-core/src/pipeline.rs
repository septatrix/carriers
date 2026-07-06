//! The message-processing pipeline: policy checks, moderation, transformation, and signing.

use mail_auth::MessageAuthenticator;
use mail_parser::{HeaderName, Message, MessageParser};

use crate::error::{Error, Result};
use crate::list::{List, PostingPolicy};
use crate::member::MemberProvider;
use crate::sign::{sign_and_seal, Ingress};
use crate::store::Store;
use crate::transform::augment;

/// A message that is ready to be distributed to the list's subscribers.
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

/// What the pipeline decided to do with an inbound post.
pub enum Disposition {
    /// Distribute it now.
    Distribute(Prepared),
    /// Held for moderation (already stored in the queue); `id` is the queue entry.
    Held { id: i64 },
    /// Accepted but not distributed (loop or duplicate). Reply 2xx to avoid backscatter.
    Dropped { reason: String },
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

/// Ingest an inbound post: reject loops/duplicates, apply the posting policy (distributing,
/// holding for moderation, as appropriate), and prepare the message when it may go out now.
pub async fn intake(
    authenticator: &MessageAuthenticator,
    store: &Store,
    members: &dyn MemberProvider,
    list: &List,
    hostname: &str,
    ingress: &Ingress,
    raw: &[u8],
) -> Result<Disposition> {
    let parsed = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| Error::Rejected("unparseable message".into()))?;

    // Loop guard: refuse a message that already carries our List-Id.
    if let Some(value) = parsed.header(HeaderName::ListId) {
        if value
            .as_text()
            .is_some_and(|text| text.contains(&list.list_id()))
        {
            return Ok(Disposition::Dropped {
                reason: "message already carries this List-Id (loop)".into(),
            });
        }
    }

    // Duplicate suppression by Message-ID.
    if let Some(message_id) = parsed.message_id() {
        if !store.record_message(&list.name, message_id).await? {
            return Ok(Disposition::Dropped {
                reason: format!("duplicate Message-ID `{message_id}`"),
            });
        }
    }

    let sender = from_address(&parsed);

    // Decide whether this sender may post without moderation.
    let may_post = match list.cfg.policy.posting {
        PostingPolicy::Open => true,
        PostingPolicy::Subscribers => {
            members
                .is_subscriber(&list.name, sender.as_deref().unwrap_or(""))
                .await?
        }
        PostingPolicy::Members => {
            members
                .is_member(&list.name, sender.as_deref().unwrap_or(""))
                .await?
        }
        PostingPolicy::Moderated => false,
    };

    if may_post {
        let prepared = finalize(authenticator, members, list, hostname, ingress, raw).await?;
        Ok(Disposition::Distribute(prepared))
    } else {
        let subject = parsed.subject();
        let id = store
            .enqueue_held(
                &list.name,
                &ingress.mail_from,
                &ingress.helo,
                &ingress.remote_ip.to_string(),
                sender.as_deref(),
                subject,
                raw,
            )
            .await?;
        Ok(Disposition::Held { id })
    }
}

/// Transform, sign and seal a message and gather its recipients, without any policy check.
///
/// Used both for an immediately-distributable post and when a moderator approves a held one.
pub async fn finalize(
    authenticator: &MessageAuthenticator,
    members: &dyn MemberProvider,
    list: &List,
    hostname: &str,
    ingress: &Ingress,
    raw: &[u8],
) -> Result<Prepared> {
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

/// Lowercased `From` address of a parsed message, if present.
fn from_address(parsed: &Message) -> Option<String> {
    parsed
        .from()
        .and_then(|addr| addr.first())
        .and_then(|addr| addr.address())
        .map(|s| s.to_ascii_lowercase())
}
