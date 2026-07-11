//! Tests for Sieve-based moderation policies.

use std::collections::HashSet;

use carriers_core::policy::{MembershipSets, PolicyDecision, PolicyEngine};

const POLICY: &str = r#"
require ["envelope", "extlists", "fileinto", "reject"];
# Subscribers post freely; posters are moderated; a known spammer is silently discarded;
# everyone else is rejected with a reason.
if address :list "from" "subscribers" {
    keep;
} elsif address :list "from" "posters" {
    fileinto "moderate";
} elsif address :is "from" "spammer@evil.example" {
    discard;
} else {
    reject "Only subscribers and posters may write to this list.";
}
"#;

fn write_policy(dir: &std::path::Path, name: &str, body: &str) {
    std::fs::write(dir.join(format!("{name}.sieve")), body).unwrap();
}

fn message(from: &str) -> Vec<u8> {
    format!("From: {from}\r\nTo: dev@lists.example.org\r\nSubject: hi\r\n\r\nbody\r\n").into_bytes()
}

/// alice is a subscriber only; bot is a poster only — the two sets are disjoint here, not a
/// superset of one another, demonstrating that subscribing does not imply posting rights.
fn sets() -> MembershipSets {
    MembershipSets {
        subscribers: HashSet::from(["alice@example.com".to_string()]),
        posters: HashSet::from(["bot@example.net".to_string()]),
        moderators: HashSet::new(),
    }
}

#[test]
fn sieve_policy_decides_approve_moderate_discard_reject() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let engine = PolicyEngine::load(dir.path()).unwrap();
    assert!(engine.contains("corporate"));

    let sets = sets();
    let eval = |from: &str| {
        engine
            .evaluate("corporate", "dev", from, &message(from), &sets)
            .unwrap()
    };

    // Subscriber -> approve; poster (not a subscriber) -> moderate; known spammer -> silently
    // discarded; stranger -> rejected with a reason.
    assert_eq!(eval("alice@example.com"), PolicyDecision::Approve);
    assert_eq!(eval("bot@example.net"), PolicyDecision::Moderate);
    assert_eq!(eval("spammer@evil.example"), PolicyDecision::Discard);
    assert_eq!(
        eval("mallory@evil.example"),
        PolicyDecision::Reject {
            reason: "Only subscribers and posters may write to this list.".to_string()
        }
    );
}

#[test]
fn empty_script_approves_by_default() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "allow", "# allow everything (implicit keep)\n");
    let engine = PolicyEngine::load(dir.path()).unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "broken", "if address :list \"from\" {\n"); // malformed
    assert!(PolicyEngine::load(dir.path()).is_err());
}

#[test]
fn builtin_policies_behave_like_the_posting_modes() {
    let engine = PolicyEngine::new().unwrap();
    let sets = sets(); // subscribers: alice; posters: bot
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

    // subscribers: subscriber approved, everyone else (including a poster) held.
    assert_eq!(
        eval("subscribers", "alice@example.com"),
        PolicyDecision::Approve
    );
    assert_eq!(
        eval("subscribers", "bot@example.net"),
        PolicyDecision::Moderate
    );

    // posters: a poster is approved even without being a subscriber; a subscriber who is not
    // also a poster is held (the two roles are independent).
    assert_eq!(eval("posters", "bot@example.net"), PolicyDecision::Approve);
    assert_eq!(
        eval("posters", "alice@example.com"),
        PolicyDecision::Moderate
    );
    assert_eq!(
        eval("posters", "mallory@evil.example"),
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
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "subscribers", "# tries to shadow a built-in\n");
    assert!(PolicyEngine::load(dir.path()).is_err());
}
