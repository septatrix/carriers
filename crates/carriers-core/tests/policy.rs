//! Tests for Sieve-based moderation policies.

use std::collections::HashSet;

use carriers_core::policy::{MembershipSets, PolicyDecision, PolicyEngine};

const POLICY: &str = r#"
require ["envelope", "extlists", "fileinto"];
# Subscribers post freely; other members are moderated; strangers are rejected.
if address :list "from" "subscribers" {
    keep;
} elsif address :list "from" "members" {
    fileinto "moderate";
} else {
    discard;
}
"#;

fn write_policy(dir: &std::path::Path, name: &str, body: &str) {
    std::fs::write(dir.join(format!("{name}.sieve")), body).unwrap();
}

fn tempdir() -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "carriers-policy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn message(from: &str) -> Vec<u8> {
    format!("From: {from}\r\nTo: dev@lists.example.org\r\nSubject: hi\r\n\r\nbody\r\n").into_bytes()
}

fn sets() -> MembershipSets {
    MembershipSets {
        subscribers: HashSet::from(["alice@example.com".to_string()]),
        members: HashSet::from([
            "alice@example.com".to_string(),
            "bot@example.net".to_string(),
        ]),
        moderators: HashSet::new(),
    }
}

#[test]
fn sieve_policy_decides_approve_moderate_reject() {
    let dir = tempdir();
    write_policy(&dir, "corporate", POLICY);
    let engine = PolicyEngine::load(&dir).unwrap();
    assert!(engine.contains("corporate"));

    let sets = sets();
    let eval = |from: &str| {
        engine
            .evaluate("corporate", "dev", from, &message(from), &sets)
            .unwrap()
    };

    // Subscriber -> approve; posting-only member -> moderate; stranger -> reject.
    assert_eq!(eval("alice@example.com"), PolicyDecision::Approve);
    assert_eq!(eval("bot@example.net"), PolicyDecision::Moderate);
    assert_eq!(eval("mallory@evil.example"), PolicyDecision::Reject);
}

#[test]
fn empty_script_approves_by_default() {
    let dir = tempdir();
    write_policy(&dir, "allow", "# allow everything (implicit keep)\n");
    let engine = PolicyEngine::load(&dir).unwrap();
    assert_eq!(
        engine
            .evaluate(
                "allow",
                "dev",
                "anyone@example.com",
                &message("anyone@example.com"),
                &MembershipSets::default()
            )
            .unwrap(),
        PolicyDecision::Approve
    );
}

#[test]
fn compile_error_is_reported() {
    let dir = tempdir();
    write_policy(&dir, "broken", "if address :list \"from\" {\n"); // malformed
    assert!(PolicyEngine::load(&dir).is_err());
}

#[test]
fn builtin_policies_behave_like_the_posting_modes() {
    let engine = PolicyEngine::new().unwrap();
    let sets = sets(); // subscribers: alice; members: alice, bot
    let eval = |policy: &str, from: &str| {
        engine
            .evaluate(policy, "dev", from, &message(from), &sets)
            .unwrap()
    };

    // open: everyone approved.
    assert_eq!(
        eval("open", "mallory@evil.example"),
        PolicyDecision::Approve
    );

    // subscribers: subscriber approved, everyone else held.
    assert_eq!(
        eval("subscribers", "alice@example.com"),
        PolicyDecision::Approve
    );
    assert_eq!(
        eval("subscribers", "bot@example.net"),
        PolicyDecision::Moderate
    );

    // members: any member approved, others held.
    assert_eq!(eval("members", "bot@example.net"), PolicyDecision::Approve);
    assert_eq!(
        eval("members", "mallory@evil.example"),
        PolicyDecision::Moderate
    );

    // moderated: everyone held.
    assert_eq!(
        eval("moderated", "alice@example.com"),
        PolicyDecision::Moderate
    );
}

#[test]
fn custom_policy_may_not_reuse_a_builtin_name() {
    let dir = tempdir();
    write_policy(&dir, "subscribers", "# tries to shadow a built-in\n");
    assert!(PolicyEngine::load(&dir).is_err());
}
