//! The message-processing pipeline: policy checks, moderation, transformation, and signing.

use std::collections::HashSet;

use mail_auth::MessageAuthenticator;
use mail_parser::{HeaderName, Message, MessageParser};

use crate::error::{Error, Result};
use crate::list::List;
use crate::member::MemberProvider;
use crate::policy::{MembershipSets, PolicyDecision, PolicyEngine};
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
    /// Accepted but not distributed (loop or duplicate). The caller should still reply with a
    /// 2xx SMTP status (accept), rather than a 5xx rejection, to avoid backscatter — this is
    /// the three-digit basic SMTP reply code, distinct from the RFC 3463 enhanced status code
    /// (itself also written `2.x.x`) that accompanies it in the reply text.
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

/// Decode a VERP bounce address produced by [`verp`], returning
/// `(list posting address, original recipient)`.
///
/// e.g. `dev+bounce=user=example.com@lists.example.org`
/// -> `("dev@lists.example.org", "user@example.com")`.
pub fn decode_verp(address: &str) -> Option<(String, String)> {
    let (local, domain) = address.rsplit_once('@')?;
    let (base_local, encoded) = local.split_once("+bounce=")?;
    // The original recipient's `@` was encoded as the last `=` (its local part may itself
    // contain `=`), so split on the final one.
    let at = encoded.rfind('=')?;
    let recipient = format!("{}@{}", &encoded[..at], &encoded[at + 1..]);
    Some((format!("{base_local}@{domain}"), recipient))
}

/// Ingest an inbound post: reject loops/duplicates, apply the posting policy (distributing,
/// holding for moderation, as appropriate), and prepare the message when it may go out now.
#[allow(clippy::too_many_arguments)]
pub async fn intake(
    authenticator: &MessageAuthenticator,
    store: &Store,
    members: &dyn MemberProvider,
    policy: &PolicyEngine,
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

    // Every list is moderated by a Sieve policy: either the one named in its config, or the
    // built-in policy for its `posting` mode. Both run through the same engine.
    let policy_name = match &list.cfg.policy.sieve {
        Some(name) => name.as_str(),
        None => list.cfg.policy.posting.policy_name(),
    };
    let sets = membership_sets(members, &list.name).await?;
    let approved = match policy.evaluate(policy_name, &list.name, &ingress.mail_from, raw, &sets)? {
        PolicyDecision::Approve => true,
        PolicyDecision::Moderate => false,
        PolicyDecision::Reject => {
            return Ok(Disposition::Dropped {
                reason: format!("rejected by policy `{policy_name}`"),
            });
        }
    };

    if approved {
        let prepared = finalize(authenticator, members, list, hostname, ingress, raw).await?;
        Ok(Disposition::Distribute(prepared))
    } else {
        let id = store
            .enqueue_held(
                &list.name,
                &ingress.mail_from,
                &ingress.helo,
                &ingress.remote_ip.to_string(),
                sender.as_deref(),
                parsed.subject(),
                raw,
            )
            .await?;
        Ok(Disposition::Held { id })
    }
}

/// Build the membership sets exposed to Sieve policies for `list_name`.
async fn membership_sets(members: &dyn MemberProvider, list_name: &str) -> Result<MembershipSets> {
    let mut sets = MembershipSets {
        subscribers: HashSet::new(),
        members: HashSet::new(),
        moderators: HashSet::new(),
    };
    for member in members.members(list_name).await? {
        if member.subscribed {
            sets.subscribers.insert(member.address.clone());
        }
        if member.moderator {
            sets.moderators.insert(member.address.clone());
        }
        sets.members.insert(member.address);
    }
    Ok(sets)
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

#[cfg(test)]
mod tests {
    use super::{decode_verp, verp};

    #[test]
    fn verp_round_trips() {
        let bounce = verp("dev", "lists.example.org", "user@example.com");
        assert_eq!(bounce, "dev+bounce=user=example.com@lists.example.org");
        assert_eq!(
            decode_verp(&bounce),
            Some(("dev@lists.example.org".into(), "user@example.com".into()))
        );
    }

    #[test]
    fn decode_verp_handles_equals_in_local_part() {
        let bounce = verp("dev", "lists.example.org", "a=b@example.com");
        assert_eq!(
            decode_verp(&bounce),
            Some(("dev@lists.example.org".into(), "a=b@example.com".into()))
        );
    }

    #[test]
    fn decode_verp_rejects_plain_addresses() {
        assert_eq!(decode_verp("dev@lists.example.org"), None);
    }
}
