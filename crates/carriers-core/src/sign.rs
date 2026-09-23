//! Inbound authentication, plus DKIM signing and ARC sealing of the outbound message.

use std::net::IpAddr;

use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim2::{Envelope, Hop};
use mail_auth::dmarc::Policy;
use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{
    AuthenticatedMessage, AuthenticationResults, Dkim2Result, DkimOutput, DkimResult, DmarcResult,
    MessageAuthenticator,
};

use crate::error::{Error, Result};
use crate::list::List;

/// Envelope/connection metadata for the inbound message, used to evaluate inbound SPF and to
/// record what we observed in the `Authentication-Results` we seal into the ARC chain.
pub struct Ingress {
    pub remote_ip: IpAddr,
    pub helo: String,
    pub mail_from: String,
}

/// The DMARC-relevant authentication facts for an inbound message, exposed to Sieve policy
/// scripts as `vnd.carriers.*` environment variables (see [`AuthVerdict::env_pairs`]) so the
/// "don't sign unauthenticated mail with our own reputation" gate can live in Sieve rather than
/// hardcoded Rust — see `builtin_policies/dmarc-before.sieve` / `dmarc-after.sieve`.
///
/// Deliberately holds only owned primitives, not the borrowed `DkimOutput`/`ArcOutput`/
/// `SpfOutput` mail-auth returns: those are tied to the lifetime of the specific
/// `AuthenticatedMessage` they were computed from. This verdict is computed once, on the pristine
/// inbound message, for the Sieve policy tiers; [`sign_and_seal`] independently re-verifies that
/// same pristine message when it builds the `Authentication-Results` it seals into the ARC set
/// (see its doc comment). Keeping only owned primitives here avoids threading those borrows across
/// the transform/sign/seal step.
pub struct AuthVerdict {
    /// DMARC passed via an aligned, passing DKIM or SPF identity.
    pub dmarc_pass: bool,
    /// The author domain's requested enforcement: `"none"` (no DMARC record published, *or* a
    /// record with `p=none` — mail-auth already collapses both to `Policy::None`, exactly
    /// matching the TODO's "without DMARC/DKIM/SPF configured" case), `"quarantine"`, or
    /// `"reject"`.
    pub dmarc_policy: &'static str,
    /// DMARC's DKIM-alignment leg: `"pass"`/`"fail"`/`"none"`/`"temperror"`/`"permerror"`. A
    /// passing, aligned DKIM2 chain (see `dkim2_result`) counts here too — mail-auth folds DKIM2
    /// into the same DMARC DKIM-alignment leg as classic DKIM.
    pub dkim_result: &'static str,
    /// DMARC's SPF-alignment leg, same shape as `dkim_result`.
    pub spf_result: &'static str,
    /// The raw classic DKIM (RFC 6376) verification result across every signature on the
    /// message, independent of DMARC alignment: `"pass"` if any signature verifies, otherwise the
    /// most specific failure seen, or `"none"` if the message carries no DKIM signature at all.
    /// Mirrors `dkim2_result`'s raw, pre-alignment shape — `dkim_result` above is the
    /// alignment-checked leg DMARC actually decides on.
    pub dkim1_result: &'static str,
    /// The raw DKIM2 chain verification result (draft-ietf-dkim-dkim2-spec), independent of DMARC
    /// alignment: `"pass"`/`"fail"`/`"none"`/`"temperror"`/`"permerror"`. `"none"` when the
    /// message carries no DKIM2 signature at all.
    pub dkim2_result: &'static str,
}

impl AuthVerdict {
    /// The `(env-var, value)` pairs exposed to Sieve, under the `vnd.carriers.*` namespace.
    pub fn env_pairs(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "vnd.carriers.dmarc_pass",
                if self.dmarc_pass { "yes" } else { "no" }.to_string(),
            ),
            ("vnd.carriers.dmarc_policy", self.dmarc_policy.to_string()),
            ("vnd.carriers.dkim_result", self.dkim_result.to_string()),
            ("vnd.carriers.spf_result", self.spf_result.to_string()),
            ("vnd.carriers.dkim1_result", self.dkim1_result.to_string()),
            ("vnd.carriers.dkim2_result", self.dkim2_result.to_string()),
        ]
    }
}

/// Verify the inbound message's DKIM/DKIM2/SPF/DMARC, reduced to the facts Sieve policy scripts
/// need to decide whether it may be distributed, and whether it may carry the list's own DKIM
/// signature. See [`AuthVerdict`].
///
/// `list` supplies the envelope (`ingress.mail_from` / the list's own posting address) DKIM2
/// verification binds to — the same envelope carriers itself observed on ingress.
pub async fn evaluate_dmarc(
    authenticator: &MessageAuthenticator,
    hostname: &str,
    list: &List,
    ingress: &Ingress,
    raw: &[u8],
) -> Result<AuthVerdict> {
    let message = AuthenticatedMessage::parse(raw)
        .ok_or_else(|| Error::Auth("failed to parse inbound message".into()))?;

    let dkim = authenticator.verify_dkim(&message).await;
    let spf = authenticator
        .verify_spf(SpfParameters::verify_mail_from(
            ingress.remote_ip,
            &ingress.helo,
            hostname,
            &ingress.mail_from,
        ))
        .await;
    let dkim2 = authenticator
        .verify_dkim2(
            &message,
            Envelope::new(
                ingress.mail_from.as_str(),
                [list.cfg.posting_address.as_str()],
            ),
        )
        .await;
    let mail_from_domain = domain_of(&ingress.mail_from);
    let dmarc = authenticator
        .verify_dmarc(
            DmarcParameters::new(&message, &dkim, mail_from_domain, &spf).with_dkim2_output(&dkim2),
        )
        .await;

    let dkim_result = dmarc_result_str(dmarc.dkim_result());
    let spf_result = dmarc_result_str(dmarc.spf_result());
    Ok(AuthVerdict {
        dmarc_pass: dkim_result == "pass" || spf_result == "pass",
        dmarc_policy: match dmarc.policy() {
            Policy::None | Policy::Unspecified => "none",
            Policy::Quarantine => "quarantine",
            Policy::Reject => "reject",
        },
        dkim_result,
        spf_result,
        dkim1_result: dkim1_result_str(&dkim),
        dkim2_result: dkim2_result_str(dkim2.result()),
    })
}

fn dmarc_result_str(result: &DmarcResult) -> &'static str {
    match result {
        DmarcResult::Pass => "pass",
        DmarcResult::Fail(_) => "fail",
        DmarcResult::TempError(_) => "temperror",
        DmarcResult::PermError(_) => "permerror",
        DmarcResult::None => "none",
    }
}

/// Reduce every DKIM signature's raw verification result to one representative value: `"pass"`
/// if any signature verifies (mirroring how DMARC alignment itself accepts any passing,
/// aligned signature), otherwise the most specific failure across all of them, or `"none"` if the
/// message carries no DKIM signature at all.
fn dkim1_result_str(results: &[DkimOutput<'_>]) -> &'static str {
    if results.iter().any(|o| *o.result() == DkimResult::Pass) {
        "pass"
    } else if results
        .iter()
        .any(|o| matches!(o.result(), DkimResult::Fail(_)))
    {
        "fail"
    } else if results
        .iter()
        .any(|o| matches!(o.result(), DkimResult::TempError(_)))
    {
        "temperror"
    } else if results
        .iter()
        .any(|o| matches!(o.result(), DkimResult::PermError(_)))
    {
        "permerror"
    } else if results
        .iter()
        .any(|o| matches!(o.result(), DkimResult::Neutral(_)))
    {
        "neutral"
    } else {
        "none"
    }
}

fn dkim2_result_str(result: &Dkim2Result) -> &'static str {
    match result {
        Dkim2Result::Pass => "pass",
        Dkim2Result::Fail(_) => "fail",
        Dkim2Result::TempError(_) => "temperror",
        Dkim2Result::PermError(_) => "permerror",
        Dkim2Result::None => "none",
    }
}

/// The domain of an email address (the part after the last `@`), or the whole string if there
/// is none.
fn domain_of(address: &str) -> &str {
    address.rsplit_once('@').map_or(address, |(_, d)| d)
}

/// Verify the inbound authentication of `original`, then DKIM-sign (unless `skip_own_dkim`) and
/// ARC-seal `augmented`.
///
/// The returned message is `ARC-* || [DKIM-Signature ||] augmented`: fresh headers prepended to
/// the untouched `augmented` bytes (which are themselves `List-* || [transformed] original`).
/// `original` is the pristine inbound message as received; `augmented` is what actually goes out.
/// They differ by the List-* headers we prepend and, when a list opts in, a DKIM-breaking
/// transform (Subject prefix / munge-from).
///
/// **The authentication recorded in the ARC seal is taken from `original`, not `augmented`.** ARC
/// exists to carry forward the authentication observed at *ingress*, so a later hop that trusts
/// this sealer can still honour the author's original result even after an intermediary breaks it.
/// For a plain List-header prepend the two agree (the author's DKIM doesn't cover the headers we
/// add). But a Subject prefix / munge-from deliberately invalidates the author's signature on the
/// outbound copy — verifying *those* bytes would seal a self-inflicted `dkim=fail` and defeat the
/// whole point of the seal. So DKIM (and any inbound ARC chain, whose message signature such a
/// transform would likewise break) is verified against `original`, and the author `From` recorded
/// in the results is `original`'s (munge-from rewrites it in the outbound copy). The AMS we
/// generate still signs `augmented` — that is the message we are forwarding.
///
/// This does *not* add a DKIM2 chain link, even if the list has one configured: DKIM2 binds the
/// exact SMTP envelope (`mail_from`/`rcpt_to`), which — unlike ARC/DKIM — varies per recipient
/// here (VERP gives each subscriber a distinct return path), so a single shared signature computed
/// here could only ever exactly match one recipient's envelope. See [`sign_dkim2_for_delivery`],
/// called once per recipient at actual delivery time instead.
///
/// `skip_own_dkim` withholds the list's own `DKIM-Signature` — set when the Sieve "after" policy
/// chain decided this message must not be lent the list's reputation (see
/// `builtin_policies/dmarc-after.sieve` and [`AuthVerdict`]); [`sign_dkim2_for_delivery`] is not
/// called at all in that case either. The ARC seal is added either way: it is an honest record of
/// what was observed, not a reputation grant.
pub async fn sign_and_seal(
    authenticator: &MessageAuthenticator,
    list: &List,
    hostname: &str,
    original: &[u8],
    augmented: &[u8],
    ingress: &Ingress,
    skip_own_dkim: bool,
) -> Result<Vec<u8>> {
    // The message we are forwarding: what the list's own DKIM signature and the ARC message
    // signature (AMS) sign.
    let message = AuthenticatedMessage::parse(augmented)
        .ok_or_else(|| Error::Auth("failed to parse outbound message".into()))?;

    // The pristine inbound message, verified to record what we observed at ingress in the ARC seal
    // — see the doc comment above on why this must be `original`, not `augmented`. In production
    // these use live DNS via the shared resolver.
    let ingress_message = AuthenticatedMessage::parse(original)
        .ok_or_else(|| Error::Auth("failed to parse inbound message".into()))?;
    let dkim = authenticator.verify_dkim(&ingress_message).await;
    let arc = authenticator.verify_arc(&ingress_message).await;
    let from = ingress_message.from().to_string();

    // SPF is a connection/envelope fact, independent of the message bytes, so it reads the same
    // either way.
    let spf = authenticator
        .verify_spf(SpfParameters::verify_mail_from(
            ingress.remote_ip,
            &ingress.helo,
            hostname,
            &ingress.mail_from,
        ))
        .await;

    let auth_results = AuthenticationResults::new(hostname)
        .with_dkim_results(&dkim, &from)
        .with_spf_mailfrom_result(&spf, ingress.remote_ip, &ingress.mail_from, &ingress.helo)
        .with_arc_result(&arc, ingress.remote_ip);

    // Seal the chain over the outbound `message`, recording the ingress `auth_results` above,
    // regardless of `skip_own_dkim` — the seal is an honest record of what we observed, not a
    // grant of our own reputation.
    let arc_set = list
        .sealer()
        .seal(&message, &auth_results, &arc)
        .map_err(|e| Error::Auth(format!("ARC seal failed: {e}")))?;

    let mut out = Vec::with_capacity(augmented.len() + 1024);
    out.extend_from_slice(arc_set.to_header().as_bytes());
    if !skip_own_dkim {
        let signature = list
            .signer()
            .sign(augmented)
            .map_err(|e| Error::Auth(format!("DKIM signing failed: {e}")))?;
        out.extend_from_slice(signature.to_header().as_bytes());
    }
    out.extend_from_slice(augmented);
    Ok(out)
}

/// Whether the list should extend the message's DKIM2 chain at delivery. carriers never
/// originates a DKIM2 chain of its own — that only makes sense once the inbound message already
/// participates in one, i.e. `verdict.dkim2_result` is anything other than `"none"` (whether that
/// existing chain itself passed, failed, or errored is irrelevant here: extending it is still
/// meaningful, and `sign_dkim2_for_delivery` re-derives the next `i=` from what's actually there).
/// Also withheld whenever `no_own_dkim` is set, for the same reason the list's classic
/// `DKIM-Signature` is withheld — see [`AuthVerdict`].
pub fn should_sign_dkim2(verdict: &AuthVerdict, no_own_dkim: bool) -> bool {
    !no_own_dkim && verdict.dkim2_result != "none"
}

/// Add the list's own DKIM2 chain link for one specific outbound delivery, bound to the exact
/// SMTP envelope (`mail_from`/`rcpt_to`) that delivery will use. Unlike ARC/classic DKIM, DKIM2
/// verification requires an *exact* match against the real envelope — see [`sign_and_seal`]'s
/// docs for why that means this must run once per recipient rather than once per message.
///
/// `original` is the pristine inbound message, before any of carriers' own transforms (List
/// headers, munge-from) — the diff baseline for the chain link's recipe, so it records exactly
/// what carriers changed. `message` is the fully ARC-sealed/DKIM-signed message produced by
/// [`sign_and_seal`] (identical for every recipient — only the envelope differs here). Call this
/// only when [`should_sign_dkim2`] says so; there is no such thing as "no DKIM2 key configured"
/// to fall back on.
pub fn sign_dkim2_for_delivery(
    list: &List,
    original: &[u8],
    message: &[u8],
    mail_from: &str,
    rcpt_to: &str,
) -> Result<Vec<u8>> {
    let signed = list
        .dkim2_signer()
        .sign_revised(original, message, Hop::real(mail_from, [rcpt_to]))
        .map_err(|e| Error::Auth(format!("DKIM2 signing failed: {e}")))?;

    let mut out = Vec::with_capacity(message.len() + 256);
    out.extend_from_slice(signed.to_header().as_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use mail_auth::{DkimOutput, Error as MailAuthError};

    use super::{AuthVerdict, dkim1_result_str, should_sign_dkim2};

    fn verdict_with_dkim2_result(dkim2_result: &'static str) -> AuthVerdict {
        AuthVerdict {
            dmarc_pass: true,
            dmarc_policy: "none",
            dkim_result: "pass",
            spf_result: "pass",
            dkim1_result: "pass",
            dkim2_result,
        }
    }

    #[test]
    fn extends_the_chain_only_when_the_inbound_message_already_had_one() {
        assert!(should_sign_dkim2(&verdict_with_dkim2_result("pass"), false));
        assert!(should_sign_dkim2(&verdict_with_dkim2_result("fail"), false));
        assert!(!should_sign_dkim2(
            &verdict_with_dkim2_result("none"),
            false
        ));
    }

    #[test]
    fn never_signs_when_the_list_own_dkim_is_withheld() {
        assert!(!should_sign_dkim2(&verdict_with_dkim2_result("pass"), true));
    }

    #[test]
    fn pass_wins_even_alongside_a_failing_signature() {
        let results = vec![
            DkimOutput::fail(MailAuthError::NotAligned),
            DkimOutput::pass(),
        ];
        assert_eq!(dkim1_result_str(&results), "pass");
    }

    #[test]
    fn no_signature_at_all_is_none() {
        assert_eq!(dkim1_result_str(&[]), "none");
    }

    #[test]
    fn a_single_failing_signature_is_fail() {
        let results = vec![DkimOutput::fail(MailAuthError::NotAligned)];
        assert_eq!(dkim1_result_str(&results), "fail");
    }

    #[test]
    fn temporary_dns_errors_are_reported_as_temperror() {
        let results = vec![DkimOutput::temp_err(MailAuthError::NotAligned)];
        assert_eq!(dkim1_result_str(&results), "temperror");
    }
}
