//! Classification of delivery status notifications (bounces).
//!
//! Outbound copies carry a per-recipient VERP return path (see [`crate::pipeline::verp`]), so a
//! failed delivery produces a DSN addressed back to that VERP address. We classify the DSN by
//! its RFC 3464 `Status:` field, whose value is one of the enhanced mail system status codes
//! registered by RFC 3463 (`class.subject.detail`, e.g. `5.1.1`), to weigh permanent failures
//! more heavily than transient ones.

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

/// Classify a bounce message by scanning for the DSN `Status:` field (`Status: 5.1.1`).
///
/// This looks at the whole message rather than only the `message/delivery-status` MIME part,
/// which is a pragmatic simplification: the DSN `Status` field is the only header whose value
/// is a `class.subject.detail` triple, so a line-oriented scan is reliable in practice.
pub fn classify(raw: &[u8]) -> BounceKind {
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
        // A DSN status is `class.subject.detail`, e.g. `5.1.1`.
        let mut parts = value.splitn(3, '.');
        let class = parts.next();
        let has_subject = parts.next().is_some();
        if !has_subject {
            continue;
        }
        match class {
            Some("5") => return BounceKind::Hard,
            Some("4") => return BounceKind::Soft,
            _ => continue,
        }
    }
    BounceKind::Unknown
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
        assert_eq!(classify(HARD_DSN), BounceKind::Hard);
        assert_eq!(classify(SOFT_DSN), BounceKind::Soft);
        assert_eq!(
            classify(b"Subject: out of office\r\n\r\nI am away."),
            BounceKind::Unknown
        );
    }
}
