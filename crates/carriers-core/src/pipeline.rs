//! The message-processing pipeline: policy checks, moderation, transformation, and signing.

use std::collections::HashSet;
use std::path::Path;

use async_trait::async_trait;
use mail_auth::MessageAuthenticator;
use mail_parser::{Message, MessageParser};
use tracing::warn;

use crate::error::{Error, Result};
use crate::list::List;
use crate::member::MemberProvider;
use crate::policy::{MembershipSets, PolicyDecision, PolicyEngine};
use crate::sieve_engine::DuplicateStore;
use crate::sign::{self, Ingress, sign_and_seal};
use crate::store::Store;
use crate::transform;

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
    /// The pristine inbound message, present only when the list has a `[dkim2]` key configured
    /// and no policy tier withheld the list's own signature. DKIM2 binds the exact SMTP envelope,
    /// which — unlike ARC/classic DKIM — differs per recipient here (VERP), so the list's DKIM2
    /// chain link can't be added to the shared `message` above; the caller must add one per
    /// recipient at actual delivery time instead, via
    /// [`crate::sign::sign_dkim2_for_delivery`], using this as the diff baseline.
    pub dkim2_original: Option<Vec<u8>>,
}

/// What the pipeline decided to do with an inbound post.
pub enum Disposition {
    /// Distribute it now.
    Distribute(Prepared),
    /// Held for moderation (already stored in the queue); `id` is the queue entry.
    Held { id: i64 },
    /// Silently dropped: a loop, a duplicate, or a policy's Sieve `discard`. The sender is told
    /// nothing about this specific message; the caller should still reply with a 2xx SMTP
    /// status (accept) rather than a 5xx rejection, to avoid backscatter — this is the
    /// three-digit basic SMTP reply code, distinct from the RFC 3463 enhanced status code
    /// (itself also written `2.x.x`) that accompanies it in the reply text.
    Discarded { reason: String },
    /// Explicitly refused by a policy's Sieve `reject`/`ereject`, carrying its reason. The
    /// caller should reply with a permanent (5xx) SMTP status containing this reason — since
    /// this happens synchronously within the inbound SMTP transaction, it is a real-time
    /// protocol rejection (the sender's own MTA is responsible for notifying its user), not a
    /// bounce we generate ourselves, so it does not risk backscatter.
    Rejected { reason: String },
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

/// Ingest an inbound post: discard loops/duplicates, then run the "before" half of the policy
/// chain (the global/domain "before" scripts and the list's own posting policy — see
/// [`crate::policy::PolicyEngine::evaluate_before`]) to decide whether to distribute, hold for
/// moderation, discard, or reject it. An approved post goes straight to [`finalize`], which runs
/// the "after" half and prepares the outgoing message.
///
/// Loop and duplicate detection are themselves built-in Sieve scripts (see
/// [`crate::policy::PolicyEngine::check_loop`] / [`check_duplicate`](PolicyEngine::check_duplicate)),
/// run ahead of the policy chain.
#[allow(clippy::too_many_arguments)]
pub async fn intake(
    authenticator: &MessageAuthenticator,
    store: &Store,
    members: &dyn MemberProvider,
    policy: &PolicyEngine,
    list: &List,
    hostname: &str,
    archive_dir: Option<&Path>,
    ingress: &Ingress,
    raw: &[u8],
) -> Result<Disposition> {
    let parsed = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| Error::Unparseable("failed to parse RFC 5322 message".into()))?;

    let list_id = list.list_id();

    // Loop guard: a message already carrying our List-Id (built-in `loop.sieve` header check).
    if policy
        .check_loop(&list.name, &list_id, &ingress.mail_from, raw)
        .await?
    {
        return Ok(Disposition::Discarded {
            reason: "message already carries this List-Id (loop)".into(),
        });
    }

    // Duplicate suppression by Message-ID (built-in `duplicate.sieve`, RFC 7352).
    let duplicates = StoreDuplicates {
        store,
        list: &list.name,
    };
    if policy
        .check_duplicate(&list.name, &list_id, &ingress.mail_from, raw, &duplicates)
        .await?
    {
        return Ok(Disposition::Discarded {
            reason: "duplicate message (Message-ID already seen)".into(),
        });
    }

    let sender = from_address(&parsed);
    let sets = membership_sets(members, &list.name).await?;

    // DMARC/DKIM/SPF facts for this message, exposed to the "before" chain as `vnd.carriers.*`
    // environment variables — in particular the built-in `dmarc-before.sieve` gate, which rejects
    // outright a message failing DMARC against an enforcing domain policy (see
    // `sign::evaluate_dmarc`), before it can even reach moderation.
    let verdict = sign::evaluate_dmarc(authenticator, hostname, list, ingress, raw).await?;
    let auth_env = verdict.env_pairs();
    let auth_env: Vec<(&str, &str)> = auth_env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    // The "before" half of the policy chain decides moderation: the global/domain "before"
    // scripts and the list's own policy (`list.cfg.policy` — a built-in name or a custom
    // `<name>.sieve`). The "after" half runs later, in `finalize` (see `evaluate_after`).
    let policy_name = list.cfg.policy.as_str();
    let outcome = policy
        .evaluate_before(
            policy_name,
            &list.name,
            &list_id,
            &list.domain,
            &ingress.mail_from,
            raw,
            &sets,
            &auth_env,
        )
        .await?;

    // A "before" tier may file the message into the `archive` pseudo-mailbox — e.g. to capture
    // every inbound post, including ones about to be rejected, for debugging.
    if outcome.archive {
        archive_message(archive_dir, &list.name, raw).await;
    }

    match outcome.decision {
        PolicyDecision::Approve => {
            finalize(
                authenticator,
                store,
                members,
                policy,
                list,
                hostname,
                archive_dir,
                ingress,
                raw,
            )
            .await
        }
        PolicyDecision::Moderate => {
            hold(
                store,
                list,
                ingress,
                sender.as_deref(),
                parsed.subject(),
                raw,
            )
            .await
        }
        PolicyDecision::Discard => Ok(Disposition::Discarded {
            reason: "discarded by policy".into(),
        }),
        PolicyDecision::Reject { reason } => Ok(Disposition::Rejected { reason }),
    }
}

/// Backs the built-in `duplicate` check with the persistent per-list seen-message set. `expiry`
/// (the Sieve deduplication window) is ignored: carriers records seen `Message-ID`s indefinitely.
struct StoreDuplicates<'a> {
    store: &'a Store,
    list: &'a str,
}

#[async_trait]
impl DuplicateStore for StoreDuplicates<'_> {
    async fn seen_before(&self, id: &str, _expiry: u64) -> Result<bool> {
        // `record_message` returns true when newly recorded, i.e. not seen before.
        Ok(!self.store.record_message(self.list, id).await?)
    }
}

/// Enqueue a message in the moderation queue.
async fn hold(
    store: &Store,
    list: &List,
    ingress: &Ingress,
    sender: Option<&str>,
    subject: Option<&str>,
    raw: &[u8],
) -> Result<Disposition> {
    let id = store
        .enqueue_held(
            &list.name,
            &ingress.mail_from,
            &ingress.helo,
            &ingress.remote_ip.to_string(),
            sender,
            subject,
            raw,
        )
        .await?;
    Ok(Disposition::Held { id })
}

/// Build the membership sets exposed to Sieve policies for `list_name`.
///
/// Each role is populated only from its own flag — subscribers and posters are independent
/// sets, not a hierarchy, so an address is not implicitly a poster just for being a subscriber.
async fn membership_sets(members: &dyn MemberProvider, list_name: &str) -> Result<MembershipSets> {
    let mut sets = MembershipSets {
        subscribers: HashSet::new(),
        posters: HashSet::new(),
        moderators: HashSet::new(),
    };
    for member in members.members(list_name).await? {
        if member.subscribed {
            sets.subscribers.insert(member.address.clone());
        }
        if member.poster {
            sets.posters.insert(member.address.clone());
        }
        if member.moderator {
            sets.moderators.insert(member.address);
        }
    }
    Ok(sets)
}

/// Run the "after" half of the policy chain and, if it still approves, transform, sign and seal
/// the message and gather its recipients.
///
/// Used both for an immediately-approved post and when a moderator approves a held one — either
/// way this is the message's last stop before delivery, so the "after" scripts (see
/// [`crate::policy::PolicyEngine::evaluate_after`]) run here, after any moderation, and get the
/// final say: they may still hold, discard, or reject a message that was otherwise ready to go.
#[allow(clippy::too_many_arguments)]
pub async fn finalize(
    authenticator: &MessageAuthenticator,
    store: &Store,
    members: &dyn MemberProvider,
    policy: &PolicyEngine,
    list: &List,
    hostname: &str,
    archive_dir: Option<&Path>,
    ingress: &Ingress,
    raw: &[u8],
) -> Result<Disposition> {
    let list_id = list.list_id();
    let sets = membership_sets(members, &list.name).await?;

    // Recomputed independently of any earlier `intake` pass (a message may have sat held for
    // moderation, during which the author domain's DNS/policy state could have changed) — see
    // `sign::evaluate_dmarc`.
    let verdict = sign::evaluate_dmarc(authenticator, hostname, list, ingress, raw).await?;
    let auth_env = verdict.env_pairs();
    let auth_env: Vec<(&str, &str)> = auth_env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let outcome = policy
        .evaluate_after(
            &list.name,
            &list_id,
            &list.domain,
            &ingress.mail_from,
            raw,
            &sets,
            &auth_env,
        )
        .await?;

    // An "after" tier may file the message into the `archive` pseudo-mailbox — the usual place
    // for a plain archive, since it runs on messages that are actually about to go out.
    if outcome.archive {
        archive_message(archive_dir, &list.name, raw).await;
    }

    match outcome.decision {
        PolicyDecision::Approve => {
            let recipients = members.recipients(&list.name).await?;

            // The pristine inbound bytes, before any of carriers' own transforms — the diff
            // baseline for the list's own DKIM2 chain link (see `sign::sign_and_seal`), which
            // records exactly what carriers changed (munge-from, if any, plus List headers).
            let original_raw = raw;

            // An "after" tier may request From/Reply-To munging (`fileinto "munge-from"`) — an
            // available mechanism, not applied unless a script explicitly asks for it.
            let munged;
            let raw = if outcome.munge_from {
                let munge_env = transform::munge_from_env(list, raw);
                let munge_env: Vec<(&str, &str)> =
                    munge_env.iter().map(|(k, v)| (*k, v.as_str())).collect();
                munged = policy
                    .apply_munge_from(&list.name, &list_id, &munge_env, raw)
                    .await?;
                munged.as_slice()
            } else {
                raw
            };

            let owned = transform::list_header_env(list);
            let header_env: Vec<(&str, &str)> =
                owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let augmented = policy
                .apply_list_headers(&list.name, &list_id, &header_env, raw)
                .await?;
            let message = sign_and_seal(
                authenticator,
                list,
                hostname,
                &augmented,
                ingress,
                outcome.no_own_dkim,
            )
            .await?;

            // DKIM2's exact envelope-match requirement means its chain link can't be added here
            // (this `message` is shared, unsigned-per-recipient); the caller adds it per delivery
            // instead (see `Prepared::dkim2_original`'s docs).
            let dkim2_original = (!outcome.no_own_dkim && list.dkim2_signer().is_some())
                .then(|| original_raw.to_vec());

            let return_path_local = list
                .cfg
                .posting_address
                .split('@')
                .next()
                .unwrap_or("list")
                .to_string();

            Ok(Disposition::Distribute(Prepared {
                message,
                recipients,
                return_path_local,
                list_domain: list.domain.clone(),
                dkim2_original,
            }))
        }
        PolicyDecision::Moderate => {
            let parsed = MessageParser::default().parse(raw);
            let sender = parsed.as_ref().and_then(from_address);
            let subject = parsed.as_ref().and_then(|p| p.subject());
            hold(store, list, ingress, sender.as_deref(), subject, raw).await
        }
        PolicyDecision::Discard => Ok(Disposition::Discarded {
            reason: "discarded by after-policy".into(),
        }),
        PolicyDecision::Reject { reason } => Ok(Disposition::Rejected { reason }),
    }
}

/// Lowercased `From` address of a parsed message, if present.
fn from_address(parsed: &Message) -> Option<String> {
    parsed
        .from()
        .and_then(|addr| addr.first())
        .and_then(|addr| addr.address())
        .map(|s| s.to_ascii_lowercase())
}

/// Write `raw` to the message archive as `<archive_dir>/<list>/<nanos>-<message-id>.eml`, the
/// message exactly as received (the author's original DKIM intact). A no-op if `archive_dir` is
/// unset; a failure is logged rather than propagated, so an archive problem never blocks a post.
async fn archive_message(archive_dir: Option<&Path>, list_name: &str, raw: &[u8]) {
    let Some(dir) = archive_dir else {
        warn!(
            list = list_name,
            "policy filed a message into `archive`, but no archive_dir is configured"
        );
        return;
    };
    if let Err(err) = write_archive(dir, list_name, raw).await {
        warn!(list = list_name, %err, "failed to archive message");
    }
}

async fn write_archive(dir: &Path, list_name: &str, raw: &[u8]) -> Result<()> {
    let list_dir = dir.join(list_name);
    tokio::fs::create_dir_all(&list_dir).await?;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let id = MessageParser::default()
        .parse(raw)
        .and_then(|m| m.message_id().map(sanitize_message_id))
        .unwrap_or_else(|| "no-message-id".to_string());

    tokio::fs::write(list_dir.join(format!("{nanos}-{id}.eml")), raw).await?;
    Ok(())
}

/// Reduce a `Message-ID` to a safe, bounded filename component.
fn sanitize_message_id(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(120)
        .collect();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        "no-message-id".to_string()
    } else {
        trimmed.to_string()
    }
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
