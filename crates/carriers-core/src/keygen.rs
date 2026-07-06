//! DKIM/ARC key generation for the `carriers genkey` command.
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
    /// PEM-encoded private key, to be written to the list's `key_file`.
    pub private_pem: String,
    /// The DNS TXT record value to publish at `<selector>._domainkey.<domain>`.
    pub dns_txt: String,
}

pub fn generate(algorithm: Algorithm, rsa_bits: usize) -> Result<GeneratedKey> {
    match algorithm {
        Algorithm::Rsa => {
            let pair = DkimKeyPair::generate_rsa(rsa_bits)
                .map_err(|e| Error::Key(format!("RSA key generation failed: {e}")))?;
            // `private_key()` is PKCS#1 DER.
            let private_pem = der_to_pem(pair.private_key(), "RSA PRIVATE KEY");
            // `public_key()` is PKCS#1 DER; convert to SPKI for the DNS record.
            let spki = rsa::RsaPublicKey::from_pkcs1_der(pair.public_key())
                .map_err(|e| Error::Key(format!("RSA public key decode: {e}")))?
                .to_public_key_der()
                .map_err(|e| Error::Key(format!("RSA public key SPKI encode: {e}")))?;
            let p = base64::engine::general_purpose::STANDARD.encode(spki.as_bytes());
            Ok(GeneratedKey {
                private_pem,
                dns_txt: format!("v=DKIM1; k=rsa; p={p}"),
            })
        }
        Algorithm::Ed25519 => {
            let pair = DkimKeyPair::generate_ed25519()
                .map_err(|e| Error::Key(format!("Ed25519 key generation failed: {e}")))?;
            // `private_key()` is PKCS#8 DER; `encoded_public_key()` is the base64 raw key.
            let private_pem = der_to_pem(pair.private_key(), "PRIVATE KEY");
            Ok(GeneratedKey {
                private_pem,
                dns_txt: format!("v=DKIM1; k=ed25519; p={}", pair.encoded_public_key()),
            })
        }
    }
}

fn der_to_pem(der: &[u8], label: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // chunk is always valid ASCII base64.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
