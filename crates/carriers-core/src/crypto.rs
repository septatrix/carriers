//! Loading of DKIM/ARC signing keys from DER-encoded key files.

use mail_auth::common::crypto::{DkimKey, Ed25519Key, RsaKey, Sha256};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};

use crate::error::{Error, Result};
use crate::list::{Algorithm, KeyConfig};

/// Load a signing key described by `cfg` into a [`DkimKey`] usable by both the
/// [`mail_auth::dkim::DkimSigner`] and [`mail_auth::arc::ArcSealer`].
///
/// Keys are read as raw DER, not PEM: RSA keys as PKCS#8 or PKCS#1, Ed25519 keys as PKCS#8.
/// `carriers setup` writes keys in this format.
pub fn load_dkim_key(cfg: &KeyConfig) -> Result<DkimKey> {
    let der = std::fs::read(&cfg.key_file)
        .map_err(|e| Error::Key(format!("reading {}: {e}", cfg.key_file.display())))?;
    match cfg.algorithm {
        Algorithm::Rsa => {
            let key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs8(
                PrivatePkcs8KeyDer::from(der.clone()),
            ))
            .or_else(|_| {
                RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)))
            })
            .map_err(|e| Error::Key(format!("parsing RSA key {}: {e}", cfg.key_file.display())))?;
            Ok(DkimKey::Rsa(key))
        }
        Algorithm::Ed25519 => {
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
