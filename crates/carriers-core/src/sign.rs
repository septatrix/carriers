//! Inbound authentication, plus DKIM signing and ARC sealing of the outbound message.

use std::net::IpAddr;

use mail_auth::common::headers::HeaderWriter;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{AuthenticatedMessage, AuthenticationResults, MessageAuthenticator};

use crate::error::{Error, Result};
use crate::list::List;

/// Envelope/connection metadata for the inbound message, used to evaluate inbound SPF and to
/// record what we observed in the `Authentication-Results` we seal into the ARC chain.
pub struct Ingress {
    pub remote_ip: IpAddr,
    pub helo: String,
    pub mail_from: String,
}

/// Verify the inbound authentication of `augmented`, then DKIM-sign and ARC-seal it.
///
/// The returned message is `ARC-* || DKIM-Signature || augmented`: fresh headers prepended to
/// the untouched `augmented` bytes (which are themselves `List-* || original`). Because the
/// original bytes are never rewritten, the author's DKIM signature survives and DMARC passes
/// at the receiver via DKIM alignment; the ARC seal is the backstop for hops that break it.
pub async fn sign_and_seal(
    authenticator: &MessageAuthenticator,
    list: &List,
    hostname: &str,
    augmented: &[u8],
    ingress: &Ingress,
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

    // Seal the chain, recording the results above, then add our own aligned DKIM signature.
    let arc_set = list
        .sealer()
        .seal(&message, &auth_results, &arc)
        .map_err(|e| Error::Auth(format!("ARC seal failed: {e}")))?;
    let signature = list
        .signer()
        .sign(augmented)
        .map_err(|e| Error::Auth(format!("DKIM signing failed: {e}")))?;

    let mut out = Vec::with_capacity(augmented.len() + 1024);
    out.extend_from_slice(arc_set.to_header().as_bytes());
    out.extend_from_slice(signature.to_header().as_bytes());
    out.extend_from_slice(augmented);
    Ok(out)
}
