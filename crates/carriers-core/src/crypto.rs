//! Loading of DKIM/ARC signing keys from PEM files.

use base64::Engine;
use mail_auth::common::crypto::{DkimKey, Ed25519Key, RsaKey, Sha256};

use crate::error::{Error, Result};
use crate::list::{Algorithm, KeyConfig};

/// Load a signing key described by `cfg` into a [`DkimKey`] usable by both the
/// [`mail_auth::dkim::DkimSigner`] and [`mail_auth::arc::ArcSealer`].
pub fn load_dkim_key(cfg: &KeyConfig) -> Result<DkimKey> {
    let pem = std::fs::read_to_string(&cfg.key_file)
        .map_err(|e| Error::Key(format!("reading {}: {e}", cfg.key_file.display())))?;
    match cfg.algorithm {
        Algorithm::Rsa => {
            // Accept both PKCS#8 (`BEGIN PRIVATE KEY`) and PKCS#1 (`BEGIN RSA PRIVATE KEY`).
            #[allow(deprecated)]
            let key = RsaKey::<Sha256>::from_pkcs8_pem(&pem)
                .or_else(|_| RsaKey::<Sha256>::from_rsa_pem(&pem))
                .map_err(|e| {
                    Error::Key(format!("parsing RSA key {}: {e}", cfg.key_file.display()))
                })?;
            Ok(DkimKey::Rsa(key))
        }
        Algorithm::Ed25519 => {
            let der = pem_to_der(&pem, "PRIVATE KEY")?;
            let key = Ed25519Key::from_pkcs8_der(&der).map_err(|e| {
                Error::Key(format!(
                    "parsing Ed25519 key {}: {e}",
                    cfg.key_file.display()
                ))
            })?;
            Ok(DkimKey::Ed25519(key))
        }
    }
}

/// Extract the DER payload of a single PEM block with the given `label`
/// (e.g. `"PRIVATE KEY"`).
pub fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .ok_or_else(|| Error::Key(format!("PEM missing `{begin}`")))?;
    let body = &pem[start + begin.len()..];
    let stop = body
        .find(&end)
        .ok_or_else(|| Error::Key(format!("PEM missing `{end}`")))?;
    let b64: String = body[..stop].split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| Error::Key(format!("PEM base64 decode: {e}")))
}
