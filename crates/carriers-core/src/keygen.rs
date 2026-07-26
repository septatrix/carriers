//! DKIM/ARC/DKIM2 key generation for the `carriers setup` command.
//!
//! Keys are generated with mail-auth's generator. For RSA, the public key is re-encoded as
//! X.509 `SubjectPublicKeyInfo` (SPKI) before base64 — that is the form Google, Microsoft and
//! Apple expect in the `p=` tag of a DKIM DNS record.

use base64::Engine;
use mail_auth::dkim::generate::DkimKeyPair;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::EncodePublicKey;

use crate::error::{Error, Result};
use crate::list::Algorithm;

pub struct GeneratedKey {
    /// DER-encoded private key (PKCS#8 for Ed25519, PKCS#1 for RSA), to be written as-is to
    /// the list's `key_file`.
    pub private_der: Vec<u8>,
    /// The DNS TXT record value to publish at `<selector>._domainkey.<domain>`.
    pub dns_txt: String,
}

pub fn generate(algorithm: Algorithm, rsa_bits: usize) -> Result<GeneratedKey> {
    match algorithm {
        Algorithm::Rsa => {
            let pair = DkimKeyPair::generate_rsa(rsa_bits)
                .map_err(|e| Error::Key(format!("RSA key generation failed: {e}")))?;
            // `public_key()` is PKCS#1 DER; convert to SPKI for the DNS record.
            let spki = rsa::RsaPublicKey::from_pkcs1_der(pair.public_key())
                .map_err(|e| Error::Key(format!("RSA public key decode: {e}")))?
                .to_public_key_der()
                .map_err(|e| Error::Key(format!("RSA public key SPKI encode: {e}")))?;
            let p = base64::engine::general_purpose::STANDARD.encode(spki.as_bytes());
            Ok(GeneratedKey {
                // `private_key()` is PKCS#1 DER.
                private_der: pair.private_key().to_vec(),
                dns_txt: format!("v=DKIM1; k=rsa; p={p}"),
            })
        }
        Algorithm::Ed25519 => {
            let pair = DkimKeyPair::generate_ed25519()
                .map_err(|e| Error::Key(format!("Ed25519 key generation failed: {e}")))?;
            Ok(GeneratedKey {
                // `private_key()` is PKCS#8 DER.
                private_der: pair.private_key().to_vec(),
                dns_txt: format!("v=DKIM1; k=ed25519; p={}", pair.encoded_public_key()),
            })
        }
    }
}
