//! Inbound authentication, plus DKIM signing and ARC sealing of the outbound message.

use std::net::IpAddr;

use mail_auth::common::headers::HeaderWriter;
use mail_auth::dmarc::Policy;
use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{AuthenticatedMessage, AuthenticationResults, DmarcResult, MessageAuthenticator};

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
/// `AuthenticatedMessage` they were computed from, and [`sign_and_seal`] verifies a *different*
/// (List-header-augmented) byte sequence for the actual seal/sign step. Prepending headers is
/// DKIM/ARC-safe (established elsewhere in this codebase), so the two verifications agree; this
/// struct just avoids fighting the borrow checker to prove it.
pub struct AuthVerdict {
    /// DMARC passed via an aligned, passing DKIM or SPF identity.
    pub dmarc_pass: bool,
    /// The author domain's requested enforcement: `"none"` (no DMARC record published, *or* a
    /// record with `p=none` — mail-auth already collapses both to `Policy::None`, exactly
    /// matching the TODO's "without DMARC/DKIM/SPF configured" case), `"quarantine"`, or
    /// `"reject"`.
    pub dmarc_policy: &'static str,
    /// DMARC's DKIM-alignment leg: `"pass"`/`"fail"`/`"none"`/`"temperror"`/`"permerror"`.
    pub dkim_result: &'static str,
    /// DMARC's SPF-alignment leg, same shape as `dkim_result`.
    pub spf_result: &'static str,
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
        ]
    }
}

/// Verify the inbound message's DKIM/SPF/DMARC, reduced to the facts Sieve policy scripts need
/// to decide whether it may be distributed, and whether it may carry the list's own DKIM
/// signature. See [`AuthVerdict`].
pub async fn evaluate_dmarc(
    authenticator: &MessageAuthenticator,
    hostname: &str,
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
    let mail_from_domain = domain_of(&ingress.mail_from);
    let dmarc = authenticator
        .verify_dmarc(DmarcParameters::new(
            &message,
            &dkim,
            mail_from_domain,
            &spf,
        ))
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

/// The domain of an email address (the part after the last `@`), or the whole string if there
/// is none.
fn domain_of(address: &str) -> &str {
    address.rsplit_once('@').map_or(address, |(_, d)| d)
}

/// Verify the inbound authentication of `augmented`, then DKIM-sign (unless `skip_own_dkim`) and
/// ARC-seal it.
///
/// The returned message is `ARC-* || [DKIM-Signature ||] augmented`: fresh headers prepended to
/// the untouched `augmented` bytes (which are themselves `List-* || original`). Because the
/// original bytes are never rewritten, the author's DKIM signature survives and DMARC passes
/// at the receiver via DKIM alignment; the ARC seal is the backstop for hops that break it.
///
/// `skip_own_dkim` withholds the list's own `DKIM-Signature` — set when the Sieve "after" policy
/// chain decided this message must not be lent the list's reputation (see
/// `builtin_policies/dmarc-after.sieve` and [`AuthVerdict`]). The ARC seal is added either way: it
/// is an honest record of what was observed, not a reputation grant.
pub async fn sign_and_seal(
    authenticator: &MessageAuthenticator,
    list: &List,
    hostname: &str,
    augmented: &[u8],
    ingress: &Ingress,
    skip_own_dkim: bool,
) -> Result<Vec<u8>> {
    let message = AuthenticatedMessage::parse(augmented)
        .ok_or_else(|| Error::Auth("failed to parse outbound message".into()))?;

    // Evaluate the authentication of the message as we received it. In production these use
    // live DNS via the shared resolver.
    let dkim = authenticator.verify_dkim(&message).await;
    let arc = authenticator.verify_arc(&message).await;
    let spf = authenticator
        .verify_spf(SpfParameters::verify_mail_from(
            ingress.remote_ip,
            &ingress.helo,
            hostname,
            &ingress.mail_from,
        ))
        .await;

    let from = message.from().to_string();
    let auth_results = AuthenticationResults::new(hostname)
        .with_dkim_results(&dkim, &from)
        .with_spf_mailfrom_result(&spf, ingress.remote_ip, &ingress.mail_from, &ingress.helo)
        .with_arc_result(&arc, ingress.remote_ip);

    // Seal the chain, recording the results above, regardless of `skip_own_dkim` — the seal is
    // an honest record of what we observed, not a grant of our own reputation.
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
