//! Classification of delivery status notifications (bounces).
//!
//! Outbound copies carry a per-recipient VERP return path (see [`crate::pipeline::verp`]), so a
//! failed delivery produces a DSN addressed back to that VERP address. We classify the DSN by
//! its RFC 3464 `Status:` field, whose value is one of the enhanced mail system status codes
//! registered by RFC 3463 (`class.subject.detail`, e.g. `5.1.1`), to weigh permanent failures
//! more heavily than transient ones.

use mail_parser::{MessageParser, MessagePart, MimeHeaders, PartType};

/// The severity of a bounce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BounceKind {
    /// Permanent failure (RFC 3463 class `5.x.x`) — the address is very likely dead.
    Hard,
    /// Transient failure (RFC 3463 class `4.x.x`) — a temporary problem (full mailbox,
    /// greylisting, …).
    Soft,
    /// Not recognisable as a failure DSN: no `Status:` field, an auto-reply, or a success
    /// notification (RFC 3463 class `2.x.x`, e.g. a requested `NOTIFY=SUCCESS` receipt).
    /// Not penalised.
    Unknown,
}

impl BounceKind {
    /// The name this kind is exposed under to Sieve (`vnd.carriers.bounce_kind`).
    pub fn as_str(self) -> &'static str {
        match self {
            BounceKind::Hard => "hard",
            BounceKind::Soft => "soft",
            BounceKind::Unknown => "unknown",
        }
    }
}

/// A classified bounce: its severity plus the enhanced status code it was read from.
pub struct Bounce {
    pub kind: BounceKind,
    /// The RFC 3463 status the classification came from, e.g. `5.1.1` — `None` for
    /// [`BounceKind::Unknown`], which is by definition the case where no status was found.
    pub status: Option<String>,
}

/// Classify a bounce message by scanning for the DSN `Status:` field (`Status: 5.1.1`).
///
/// This looks at the whole message rather than only the `message/delivery-status` MIME part,
/// which is a pragmatic simplification: the DSN `Status` field is the only header whose value
/// is a `class.subject.detail` triple, so a line-oriented scan is reliable in practice.
pub fn classify(raw: &[u8]) -> Bounce {
    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        let line = line.trim_start();
        let Some(value) = line
            .get(..7)
            .filter(|p| p.eq_ignore_ascii_case("status:"))
            .map(|_| line[7..].trim())
        else {
            continue;
        };
        // A DSN status is `class.subject.detail`, e.g. `5.1.1`. Anything trailing it (some
        // reporters append a human-readable comment) is not part of the status.
        let status = value.split_whitespace().next().unwrap_or_default();
        let mut parts = status.splitn(3, '.');
        let class = parts.next();
        let has_subject = parts.next().is_some();
        if !has_subject {
            continue;
        }
        let kind = match class {
            Some("5") => BounceKind::Hard,
            Some("4") => BounceKind::Soft,
            _ => continue,
        };
        return Bounce {
            kind,
            status: Some(status.to_string()),
        };
    }
    Bounce {
        kind: BounceKind::Unknown,
        status: None,
    }
}

/// The `Message-ID` of the message this DSN is about, if it can be worked out.
///
/// A DSN returns the failed message in a part of its own (RFC 3464 §6.3): the whole message as
/// `message/rfc822`, or just its headers as `text/rfc822-headers`. Either way the original
/// `Message-ID` is in there. Not every reporter includes that part — and some truncate it — so
/// this falls back to the DSN's own `In-Reply-To`, which RFC 3464 §3 asks a reporting MTA to set
/// to the `Message-ID` of the message being reported on.
///
/// Returned as it appears in the header, without the surrounding angle brackets, matching what
/// carriers records elsewhere (see `pipeline::write_archive`).
pub fn original_message_id(raw: &[u8]) -> Option<String> {
    let dsn = MessageParser::default().parse(raw)?;

    for part in &dsn.parts {
        match &part.body {
            // `message/rfc822`: the returned message, already parsed as a message of its own.
            PartType::Message(original) => {
                if let Some(id) = original.message_id() {
                    return Some(id.to_string());
                }
            }
            // `text/rfc822-headers`: the returned headers as plain text, which have to be parsed
            // as a (body-less) message to read anything out of them.
            PartType::Text(text) if is_returned_headers(part) => {
                if let Some(id) = MessageParser::default()
                    .parse(text.as_bytes())
                    .and_then(|headers| headers.message_id().map(str::to_string))
                {
                    return Some(id);
                }
            }
            _ => {}
        }
    }

    dsn.in_reply_to().as_text().map(str::to_string)
}

/// Whether a part is the `text/rfc822-headers` form of a DSN's returned content.
fn is_returned_headers(part: &MessagePart<'_>) -> bool {
    part.content_type()
        .and_then(|content_type| content_type.subtype())
        .is_some_and(|subtype| subtype.eq_ignore_ascii_case("rfc822-headers"))
}

/// Environment variables carrying the facts about a bounce to the bounce script — see
/// [`BounceFacts::env_pairs`] and `builtin_policies/bounce.sieve`.
pub const ENV_ADDRESS: &str = "vnd.carriers.bounce_address";
pub const ENV_MESSAGE_ID: &str = "vnd.carriers.bounce_message_id";
pub const ENV_KIND: &str = "vnd.carriers.bounce_kind";
pub const ENV_STATUS: &str = "vnd.carriers.bounce_status";
pub const ENV_SCORE: &str = "vnd.carriers.bounce_score";
pub const ENV_WEIGHT: &str = "vnd.carriers.bounce_weight";
pub const ENV_THRESHOLD: &str = "vnd.carriers.bounce_threshold";
pub const ENV_OVER_THRESHOLD: &str = "vnd.carriers.bounce_over_threshold";
pub const ENV_DISABLED: &str = "vnd.carriers.bounce_disabled";

/// Everything known about one bounce when the bounce script runs, exposed to it as
/// `vnd.carriers.bounce_*` environment variables (see
/// [`crate::policy::PolicyEngine::evaluate_bounce`]).
///
/// The score is the member's *new* running score: the weight for this bounce has already been
/// added when the script runs, so the script sees the total it is deciding about.
pub struct BounceFacts {
    /// The subscriber this DSN is about, decoded from the VERP return path.
    pub address: String,
    /// The `Message-ID` of the post that bounced, if the DSN identified it (see
    /// [`original_message_id`]).
    pub message_id: Option<String>,
    pub kind: BounceKind,
    /// The DSN status this bounce was classified from (see [`Bounce::status`]).
    pub status: Option<String>,
    /// The member's running bounce score, including this bounce.
    pub score: f64,
    /// The weight this bounce added to the score.
    pub weight: f64,
    /// The configured score at which delivery is meant to stop (`[bounce] threshold`).
    pub threshold: f64,
    /// Whether delivery to this address was *already* disabled before this bounce — so a script
    /// can tell a member that has just crossed the threshold from one that crossed it long ago,
    /// and not repeat whatever it did then.
    pub disabled: bool,
}

impl BounceFacts {
    /// The `(env-var, value)` pairs exposed to Sieve, under the `vnd.carriers.*` namespace.
    ///
    /// Numbers are rendered as strings, like every other Sieve environment value. Comparing one
    /// against a *literal* number in an `eval` expression is still a numeric comparison
    /// (`eval "env.vnd.carriers.bounce_score >= 10"`), but comparing two environment variables
    /// against each other compares them as text — which is why the one comparison the built-in
    /// script needs, score against threshold, is precomputed here as
    /// [`ENV_OVER_THRESHOLD`] rather than left to the script.
    pub fn env_pairs(&self) -> Vec<(&'static str, String)> {
        vec![
            (ENV_ADDRESS, self.address.clone()),
            (ENV_MESSAGE_ID, self.message_id.clone().unwrap_or_default()),
            (ENV_KIND, self.kind.as_str().to_string()),
            (ENV_STATUS, self.status.clone().unwrap_or_default()),
            (ENV_SCORE, self.score.to_string()),
            (ENV_WEIGHT, self.weight.to_string()),
            (ENV_THRESHOLD, self.threshold.to_string()),
            (
                ENV_OVER_THRESHOLD,
                yes_no(self.score >= self.threshold).to_string(),
            ),
            (ENV_DISABLED, yes_no(self.disabled).to_string()),
        ]
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HARD_DSN: &[u8] = concat!(
        "Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n",
        "\r\n--b\r\n",
        "Content-Type: message/delivery-status\r\n\r\n",
        "Reporting-MTA: dns; mx.example.com\r\n\r\n",
        "Final-Recipient: rfc822; user@example.com\r\n",
        "Action: failed\r\n",
        "Status: 5.1.1\r\n",
        "Diagnostic-Code: smtp; 550 5.1.1 user unknown\r\n",
        "\r\n--b--\r\n",
    )
    .as_bytes();

    const SOFT_DSN: &[u8] = b"Action: delayed\r\nStatus: 4.2.2 (mailbox full)\r\n";

    #[test]
    fn classifies_hard_soft_and_unknown() {
        let hard = classify(HARD_DSN);
        assert_eq!(hard.kind, BounceKind::Hard);
        assert_eq!(hard.status.as_deref(), Some("5.1.1"));

        // The status is read without the trailing human-readable comment.
        let soft = classify(SOFT_DSN);
        assert_eq!(soft.kind, BounceKind::Soft);
        assert_eq!(soft.status.as_deref(), Some("4.2.2"));

        let unknown = classify(b"Subject: out of office\r\n\r\nI am away.");
        assert_eq!(unknown.kind, BounceKind::Unknown);
        assert_eq!(unknown.status, None);
    }

    /// A DSN whose third part returns the failed message itself, the common shape.
    const DSN_WITH_RETURNED_MESSAGE: &[u8] = concat!(
        "From: MAILER-DAEMON@mx.example.com\r\n",
        "Subject: Undelivered Mail Returned to Sender\r\n",
        "Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n",
        "\r\n--b\r\n",
        "Content-Type: message/delivery-status\r\n\r\n",
        "Final-Recipient: rfc822; bob@example.com\r\n",
        "Action: failed\r\n",
        "Status: 5.1.1\r\n",
        "\r\n--b\r\n",
        "Content-Type: message/rfc822\r\n\r\n",
        "From: alice@example.com\r\n",
        "To: dev@lists.example.org\r\n",
        "Message-ID: <post-42@example.com>\r\n",
        "Subject: the post that bounced\r\n",
        "\r\n",
        "body\r\n",
        "\r\n--b--\r\n",
    )
    .as_bytes();

    /// The other permitted shape: only the failed message's headers come back.
    const DSN_WITH_RETURNED_HEADERS: &[u8] = concat!(
        "From: MAILER-DAEMON@mx.example.com\r\n",
        "Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n",
        "\r\n--b\r\n",
        "Content-Type: message/delivery-status\r\n\r\n",
        "Status: 5.2.1\r\n",
        "\r\n--b\r\n",
        "Content-Type: text/rfc822-headers\r\n\r\n",
        "From: alice@example.com\r\n",
        "Message-ID: <post-43@example.com>\r\n",
        "Subject: the post that bounced\r\n",
        "\r\n--b--\r\n",
    )
    .as_bytes();

    #[test]
    fn original_message_id_reads_the_returned_message_or_headers() {
        // Either way, the id comes back without its angle brackets.
        assert_eq!(
            original_message_id(DSN_WITH_RETURNED_MESSAGE).as_deref(),
            Some("post-42@example.com")
        );
        assert_eq!(
            original_message_id(DSN_WITH_RETURNED_HEADERS).as_deref(),
            Some("post-43@example.com")
        );
    }

    #[test]
    fn original_message_id_falls_back_to_in_reply_to() {
        // A reporter that returns nothing of the original message, but does point at it the way
        // RFC 3464 asks.
        let dsn = concat!(
            "From: MAILER-DAEMON@mx.example.com\r\n",
            "In-Reply-To: <post-44@example.com>\r\n",
            "Content-Type: message/delivery-status\r\n\r\n",
            "Status: 5.1.1\r\n",
        )
        .as_bytes();
        assert_eq!(
            original_message_id(dsn).as_deref(),
            Some("post-44@example.com")
        );

        // Nothing to go on at all: the script is told nothing rather than something invented.
        assert_eq!(original_message_id(HARD_DSN), None);
    }
}
