//! End-to-end, offline verification of the carriers signing pipeline.
//!
//! These tests never touch the network: DKIM/ARC public keys are injected through a static
//! DNS TXT cache, so `verify_dkim`/`verify_arc` resolve against in-memory records.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::Instant;

use mail_auth::common::headers::HeaderWriter;
use mail_auth::common::parse::TxtRecordParser;
use mail_auth::common::resolver::ToFqdn;
use mail_auth::common::verify::DomainKey;
use mail_auth::dkim::DkimSigner;
use mail_auth::dkim2::Envelope;
use mail_auth::{
    AuthenticatedMessage, AuthenticationResults, Dkim2Result, DkimResult, MessageAuthenticator,
    Parameters, ResolverCache, Txt,
};

use carriers_core::crypto::load_dkim_key;
use carriers_core::keygen;
use carriers_core::list::{Algorithm, KeyConfig, List};
use carriers_core::policy::PolicyEngine;
use carriers_core::sign;
use carriers_core::transform;

/// Prepend the `List-*` headers via the built-in `list-headers.sieve` script — the same path
/// `pipeline::finalize` uses — returning `list-headers || raw`.
async fn augment(list: &List, raw: &[u8]) -> Vec<u8> {
    let engine = PolicyEngine::new().unwrap();
    let owned = transform::list_header_env(list);
    let env: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    engine
        .apply_list_headers("dev", &list.list_id(), &env, raw)
        .await
        .unwrap()
}

/// A read-only in-memory TXT cache. A cache hit prevents any real DNS query.
struct StaticCache {
    map: HashMap<Box<str>, Txt>,
}

impl ResolverCache<Box<str>, Txt> for StaticCache {
    fn get<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(name).cloned()
    }
    fn remove<Q>(&self, _name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        None
    }
    fn insert(&self, _key: Box<str>, _value: Txt, _valid_until: Instant) {}
}

/// Build a TXT cache from `(selector, domain, "v=DKIM1;...")` triples.
fn cache(entries: &[(&str, &str, &str)]) -> StaticCache {
    let mut map = HashMap::new();
    for (selector, domain, txt) in entries {
        let key = format!("{selector}._domainkey.{domain}").to_fqdn();
        let record = DomainKey::parse(txt.as_bytes()).expect("valid DKIM TXT record");
        map.insert(key, Txt::from(record));
    }
    StaticCache { map }
}

/// Generate an Ed25519 key, write the private DER into `dir`, and return
/// `(key_file, "v=DKIM1;..." record)`.
fn make_key(dir: &std::path::Path, name: &str) -> (std::path::PathBuf, String) {
    make_key_with(dir, name, Algorithm::Ed25519)
}

fn make_key_with(
    dir: &std::path::Path,
    name: &str,
    algorithm: Algorithm,
) -> (std::path::PathBuf, String) {
    let bits = match algorithm {
        Algorithm::Rsa => 2048,
        Algorithm::Ed25519 => 0,
    };
    let key = keygen::generate(algorithm, bits).expect("key generation");
    let path = dir.join(name);
    std::fs::write(&path, key.private_der).unwrap();
    (path, key.dns_txt)
}

const FIXTURE: &[u8] = concat!(
    "From: Alice <alice@example.com>\r\n",
    "To: dev@lists.example.org\r\n",
    "Subject: Hello list\r\n",
    "Date: Mon, 06 Jul 2026 10:00:00 +0000\r\n",
    "Message-ID: <original-1@example.com>\r\n",
    "MIME-Version: 1.0\r\n",
    "\r\n",
    "This is the original body and it must survive byte-for-byte.\r\n",
)
.as_bytes();

/// Sign `FIXTURE` as the author, producing an inbound message with a valid author DKIM
/// signature: `DKIM-Signature(author) || FIXTURE`.
fn authored_message(author_key_file: &std::path::Path) -> Vec<u8> {
    let key = load_dkim_key(&KeyConfig {
        selector: "auth".into(),
        key_file: author_key_file.to_path_buf(),
        algorithm: Algorithm::Ed25519,
        domain: Some("example.com".into()),
    })
    .unwrap();
    let signer = DkimSigner::from_key(key)
        .domain("example.com")
        .selector("auth")
        .headers(
            [
                "From",
                "To",
                "Subject",
                "Date",
                "Message-ID",
                "MIME-Version",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
    let signature = signer.sign(FIXTURE).unwrap();
    let mut out = signature.to_header().into_bytes();
    out.extend_from_slice(FIXTURE);
    out
}

fn build_list(
    dir: &std::path::Path,
    dkim_file: &std::path::Path,
    arc_file: &std::path::Path,
) -> List {
    let toml = format!(
        r#"
posting_address = "dev@lists.example.org"
display_name = "Dev List"
unsubscribe_oneclick = "https://lists.example.org/u/dev"

[dkim]
selector = "dkimtest"
key_file = "{dkim}"
algorithm = "ed25519"
domain = "lists.example.org"

[arc]
selector = "arctest"
key_file = "{arc}"
algorithm = "ed25519"
domain = "lists.example.org"
"#,
        dkim = dkim_file.display(),
        arc = arc_file.display(),
    );
    let path = dir.join("dev.toml");
    std::fs::write(&path, toml).unwrap();
    List::load("dev", &path).unwrap()
}

/// Like [`build_list`], but with an additional `[dkim2]` key configured (DKIM2 is opt-in).
fn build_list_with_dkim2(
    dir: &std::path::Path,
    dkim_file: &std::path::Path,
    arc_file: &std::path::Path,
    dkim2_file: &std::path::Path,
) -> List {
    let toml = format!(
        r#"
posting_address = "dev@lists.example.org"
display_name = "Dev List"
unsubscribe_oneclick = "https://lists.example.org/u/dev"

[dkim]
selector = "dkimtest"
key_file = "{dkim}"
algorithm = "ed25519"
domain = "lists.example.org"

[arc]
selector = "arctest"
key_file = "{arc}"
algorithm = "ed25519"
domain = "lists.example.org"

[dkim2]
selector = "dkim2test"
key_file = "{dkim2}"
algorithm = "ed25519"
domain = "lists.example.org"
"#,
        dkim = dkim_file.display(),
        arc = arc_file.display(),
        dkim2 = dkim2_file.display(),
    );
    let path = dir.join("dev.toml");
    std::fs::write(&path, toml).unwrap();
    List::load("dev", &path).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn augment_preserves_body_and_adds_list_headers() {
    let dir = tempfile::tempdir().unwrap();
    let (dkim_file, _) = make_key(dir.path(), "dkim.der");
    let (arc_file, _) = make_key(dir.path(), "arc.der");
    let list = build_list(dir.path(), &dkim_file, &arc_file);

    let augmented = augment(&list, FIXTURE).await;

    // The original bytes appear untouched, and the List-* headers were added. (mail-parser
    // canonicalises the field name `List-Id` to `List-ID`; both are equivalent per RFC 5322.)
    assert!(contains(&augmented, FIXTURE), "original bytes preserved");
    assert!(contains(
        &augmented,
        b"List-ID: Dev List <dev.lists.example.org>"
    ));
    assert!(contains(
        &augmented,
        b"List-Unsubscribe: <https://lists.example.org/u/dev>"
    ));
    assert!(contains(
        &augmented,
        b"List-Unsubscribe-Post: List-Unsubscribe=One-Click"
    ));
}

#[tokio::test]
async fn rsa_der_key_signs_and_verifies() {
    // RSA keys are read as raw PKCS#1 DER (constructed by hand into a `PrivateKeyDer::Pkcs1`),
    // unlike Ed25519's PKCS#8 — exercise that path specifically rather than relying only on
    // the Ed25519 coverage used elsewhere in this file.
    let dir = tempfile::tempdir().unwrap();
    let (key_file, dns_txt) = make_key_with(dir.path(), "rsa.der", Algorithm::Rsa);

    let key = load_dkim_key(&KeyConfig {
        selector: "rsatest".into(),
        key_file,
        algorithm: Algorithm::Rsa,
        domain: Some("example.com".into()),
    })
    .unwrap();
    let signer = DkimSigner::from_key(key)
        .domain("example.com")
        .selector("rsatest")
        .headers(["From", "To", "Subject"].iter().map(|s| s.to_string()));
    let signature = signer.sign(FIXTURE).unwrap();
    let mut signed = signature.to_header().into_bytes();
    signed.extend_from_slice(FIXTURE);

    let message = AuthenticatedMessage::parse(&signed).unwrap();
    let cache = cache(&[("rsatest", "example.com", &dns_txt)]);
    let authenticator = MessageAuthenticator::new_cloudflare().unwrap();
    let results = authenticator
        .verify_dkim(Parameters::new(&message).with_txt_cache(&cache))
        .await;
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].result(),
        &DkimResult::Pass,
        "RSA DER key must sign a message that verifies against its published SPKI record"
    );
}

#[tokio::test]
async fn author_dkim_survives_and_list_dkim_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let (author_file, author_txt) = make_key(dir.path(), "author.der");
    let (dkim_file, dkim_txt) = make_key(dir.path(), "dkim.der");
    let (arc_file, _arc_txt) = make_key(dir.path(), "arc.der");
    let list = build_list(dir.path(), &dkim_file, &arc_file);

    // Inbound message with the author's signature, then our List-* headers, then our signature.
    let authored = authored_message(&author_file);
    let augmented = augment(&list, &authored).await;
    let signature = list.signer().sign(&augmented).unwrap();
    let mut signed = signature.to_header().into_bytes();
    signed.extend_from_slice(&augmented);

    let message = AuthenticatedMessage::parse(&signed).unwrap();
    let cache = cache(&[
        ("auth", "example.com", &author_txt),
        ("dkimtest", "lists.example.org", &dkim_txt),
    ]);
    let authenticator = MessageAuthenticator::new_cloudflare().unwrap();
    let results = authenticator
        .verify_dkim(Parameters::new(&message).with_txt_cache(&cache))
        .await;

    let passes = results
        .iter()
        .filter(|o| matches!(o.result(), DkimResult::Pass))
        .count();
    assert_eq!(
        passes, 2,
        "both the author's original DKIM and our list DKIM must verify: {results:?}"
    );
}

#[tokio::test]
async fn arc_seal_produces_a_valid_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (dkim_file, _) = make_key(dir.path(), "dkim.der");
    let (arc_file, arc_txt) = make_key(dir.path(), "arc.der");
    let list = build_list(dir.path(), &dkim_file, &arc_file);
    let authenticator = MessageAuthenticator::new_cloudflare().unwrap();

    let augmented = augment(&list, FIXTURE).await;

    // No ARC headers present yet -> an empty chain that can be sealed.
    let pre = AuthenticatedMessage::parse(&augmented).unwrap();
    let arc_in = authenticator.verify_arc(&pre).await;
    let auth_results = AuthenticationResults::new("mx.lists.example.org")
        .with_arc_result(&arc_in, "127.0.0.1".parse().unwrap());
    let arc_set = list.sealer().seal(&pre, &auth_results, &arc_in).unwrap();

    let mut sealed = arc_set.to_header().into_bytes();
    sealed.extend_from_slice(&augmented);

    // Verify the sealed chain against the ARC public key.
    let message = AuthenticatedMessage::parse(&sealed).unwrap();
    let cache = cache(&[("arctest", "lists.example.org", &arc_txt)]);
    let arc_out = authenticator
        .verify_arc(Parameters::new(&message).with_txt_cache(&cache))
        .await;

    assert_eq!(
        arc_out.result(),
        &DkimResult::Pass,
        "the freshly sealed ARC chain must verify as cv=pass"
    );
}

#[tokio::test]
async fn dkim2_chain_link_is_valid_per_recipient_delivery() {
    // DKIM2 binds the exact SMTP envelope, which VERP makes different per recipient, so carriers
    // adds the list's DKIM2 chain link once per delivery (`sign::sign_dkim2_for_delivery`), not
    // once for the shared message — see that function's docs and `crates/carriers/src/deliver.rs`.
    let dir = tempfile::tempdir().unwrap();
    let (dkim_file, _) = make_key(dir.path(), "dkim.der");
    let (arc_file, _) = make_key(dir.path(), "arc.der");
    let (dkim2_file, dkim2_txt) = make_key(dir.path(), "dkim2.der");
    let list = build_list_with_dkim2(dir.path(), &dkim_file, &arc_file, &dkim2_file);
    let authenticator = MessageAuthenticator::new_cloudflare().unwrap();

    let augmented = augment(&list, FIXTURE).await;

    // The VERP return path this delivery uses, and the one subscriber it's addressed to — an
    // exact match between these and what's baked into the signature is required for DKIM2 to
    // verify (unlike ARC/DKIM), which is exactly why this must run per recipient.
    let return_path = "dev+bounce=bob=subscriber.example@lists.example.org";
    let recipient = "bob@subscriber.example";
    let out =
        sign::sign_dkim2_for_delivery(&list, FIXTURE, &augmented, return_path, recipient).unwrap();
    assert!(
        contains(&out, &augmented),
        "the shared message bytes are untouched, only prepended to"
    );

    let message = AuthenticatedMessage::parse(&out).unwrap();
    let cache = cache(&[("dkim2test", "lists.example.org", &dkim2_txt)]);
    let output = authenticator
        .verify_dkim2(
            Parameters::new(&message).with_txt_cache(&cache),
            Envelope::new(return_path, [recipient]),
        )
        .await;

    assert_eq!(
        output.result(),
        &Dkim2Result::Pass,
        "the list's own DKIM2 chain link must verify against the exact delivery envelope: {:?}",
        output.result()
    );
}

#[tokio::test]
async fn dkim2_for_delivery_is_a_noop_when_not_configured() {
    let dir = tempfile::tempdir().unwrap();
    let (dkim_file, _) = make_key(dir.path(), "dkim.der");
    let (arc_file, _) = make_key(dir.path(), "arc.der");
    let list = build_list(dir.path(), &dkim_file, &arc_file);
    let augmented = augment(&list, FIXTURE).await;

    let out = sign::sign_dkim2_for_delivery(
        &list,
        FIXTURE,
        &augmented,
        "dev+bounce=bob=subscriber.example@lists.example.org",
        "bob@subscriber.example",
    )
    .unwrap();
    assert_eq!(
        out, augmented,
        "no [dkim2] key means no chain link is added"
    );
}

#[tokio::test]
async fn dkim2_is_unset_when_not_configured() {
    let dir = tempfile::tempdir().unwrap();
    let (dkim_file, _) = make_key(dir.path(), "dkim.der");
    let (arc_file, _) = make_key(dir.path(), "arc.der");
    let list = build_list(dir.path(), &dkim_file, &arc_file);
    assert!(
        list.dkim2_signer().is_none(),
        "dkim2 must stay opt-in: no [dkim2] section means no signer"
    );
}
