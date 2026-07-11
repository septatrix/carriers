//! Tests for Sieve-based moderation policies.

use std::collections::HashSet;
use std::sync::Mutex;

use carriers_core::policy::{MembershipSets, PolicyDecision, PolicyEngine};
use carriers_core::sieve_engine::{DuplicateStore, NoDuplicates};

/// A stand-in `List-Id` for the tests; the built-in checks don't run through `evaluate*`, so its
/// exact value is irrelevant to these.
const LIST_ID: &str = "dev.lists.example.org";

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

/// An in-memory [`DuplicateStore`]: records ids and reports a repeat, like the real store.
#[derive(Default)]
struct MemDuplicates(Mutex<HashSet<String>>);

#[async_trait::async_trait]
impl DuplicateStore for MemDuplicates {
    async fn seen_before(&self, id: &str, _expiry: u64) -> carriers_core::Result<bool> {
        Ok(!self.0.lock().unwrap().insert(id.to_string()))
    }
}

#[tokio::test]
async fn sieve_policy_decides_approve_moderate_discard_reject() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let engine = PolicyEngine::load(dir.path()).unwrap();
    assert!(engine.contains("corporate"));

    let sets = sets();
    let eval = async |from: &str| {
        engine
            .evaluate("corporate", "dev", LIST_ID, from, &message(from), &sets)
            .await
            .unwrap()
    };

    // Subscriber -> approve; poster (not a subscriber) -> moderate; known spammer -> silently
    // discarded; stranger -> rejected with a reason.
    assert_eq!(eval("alice@example.com").await, PolicyDecision::Approve);
    assert_eq!(eval("bot@example.net").await, PolicyDecision::Moderate);
    assert_eq!(eval("spammer@evil.example").await, PolicyDecision::Discard);
    assert_eq!(
        eval("mallory@evil.example").await,
        PolicyDecision::Reject {
            reason: "Only subscribers and posters may write to this list.".to_string()
        }
    );
}

#[tokio::test]
async fn empty_script_approves_by_default() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "allow", "# allow everything (implicit keep)\n");
    let engine = PolicyEngine::load(dir.path()).unwrap();
    assert_eq!(
        engine
            .evaluate(
                "allow",
                "dev",
                LIST_ID,
                "anyone@example.com",
                &message("anyone@example.com"),
                &MembershipSets::default()
            )
            .await
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

#[tokio::test]
async fn builtin_policies_behave_like_the_posting_modes() {
    let engine = PolicyEngine::new().unwrap();
    let sets = sets(); // subscribers: alice; posters: bot
    let eval = async |policy: &str, from: &str| {
        engine
            .evaluate(policy, "dev", LIST_ID, from, &message(from), &sets)
            .await
            .unwrap()
    };

    // open: everyone approved.
    assert_eq!(
        eval("open", "mallory@evil.example").await,
        PolicyDecision::Approve
    );

    // subscribers: subscriber approved, everyone else (including a poster) held.
    assert_eq!(
        eval("subscribers", "alice@example.com").await,
        PolicyDecision::Approve
    );
    assert_eq!(
        eval("subscribers", "bot@example.net").await,
        PolicyDecision::Moderate
    );

    // posters: a poster is approved even without being a subscriber; a subscriber who is not
    // also a poster is held (the two roles are independent).
    assert_eq!(
        eval("posters", "bot@example.net").await,
        PolicyDecision::Approve
    );
    assert_eq!(
        eval("posters", "alice@example.com").await,
        PolicyDecision::Moderate
    );
    assert_eq!(
        eval("posters", "mallory@evil.example").await,
        PolicyDecision::Moderate
    );

    // moderated: everyone held.
    assert_eq!(
        eval("moderated", "alice@example.com").await,
        PolicyDecision::Moderate
    );
}

#[test]
fn custom_policy_may_not_reuse_a_builtin_name() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "subscribers", "# tries to shadow a built-in\n");
    assert!(PolicyEngine::load(dir.path()).is_err());
}

fn write_sieve(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

#[tokio::test]
async fn check_loop_matches_the_lists_own_list_id_via_a_header_check() {
    let engine = PolicyEngine::new().unwrap();

    let looped =
        b"From: a@example.com\r\nList-Id: <dev.lists.example.org>\r\nSubject: hi\r\n\r\nx\r\n";
    assert!(
        engine
            .check_loop("dev", "dev.lists.example.org", "a@example.com", looped)
            .await
            .unwrap()
    );

    // A different list's List-Id is not a loop for this list.
    let other =
        b"From: a@example.com\r\nList-Id: <ops.lists.example.org>\r\nSubject: hi\r\n\r\nx\r\n";
    assert!(
        !engine
            .check_loop("dev", "dev.lists.example.org", "a@example.com", other)
            .await
            .unwrap()
    );

    // No List-Id header at all: not a loop.
    let plain = b"From: a@example.com\r\nSubject: hi\r\n\r\nx\r\n";
    assert!(
        !engine
            .check_loop("dev", "dev.lists.example.org", "a@example.com", plain)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn check_duplicate_uses_the_duplicate_extension_on_message_id() {
    let engine = PolicyEngine::new().unwrap();
    let dups = MemDuplicates::default();
    let msg = b"From: a@example.com\r\nMessage-ID: <m1@example.com>\r\nSubject: hi\r\n\r\nx\r\n";

    // First sighting: not a duplicate. Second sighting of the same Message-ID: a duplicate.
    assert!(
        !engine
            .check_duplicate("dev", LIST_ID, "a@example.com", msg, &dups)
            .await
            .unwrap()
    );
    assert!(
        engine
            .check_duplicate("dev", LIST_ID, "a@example.com", msg, &dups)
            .await
            .unwrap()
    );

    // A message with no Message-ID never keys the duplicate test, so it is never a duplicate.
    let no_id = b"From: a@example.com\r\nSubject: hi\r\n\r\nx\r\n";
    assert!(
        !engine
            .check_duplicate("dev", LIST_ID, "a@example.com", no_id, &dups)
            .await
            .unwrap()
    );
    assert!(
        !engine
            .check_duplicate("dev", LIST_ID, "a@example.com", no_id, &dups)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn check_duplicate_is_never_a_duplicate_without_a_store() {
    // With a `NoDuplicates` store, even a repeat is never reported as a duplicate.
    let engine = PolicyEngine::new().unwrap();
    let msg = b"From: a@example.com\r\nMessage-ID: <m1@example.com>\r\nSubject: hi\r\n\r\nx\r\n";
    for _ in 0..2 {
        assert!(
            !engine
                .check_duplicate("dev", LIST_ID, "a@example.com", msg, &NoDuplicates)
                .await
                .unwrap()
        );
    }
}

/// Evaluate the full chain for a subscriber in `lists.example.org` (helper to keep the
/// tier-composition tests readable).
async fn eval_list(engine: &PolicyEngine, domain: &str, from: &str) -> PolicyDecision {
    engine
        .evaluate_for_list(
            "corporate",
            "dev",
            LIST_ID,
            domain,
            from,
            &message(from),
            &sets(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn evaluate_for_list_without_any_global_scripts_just_runs_the_named_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let engine = PolicyEngine::load(dir.path()).unwrap();

    assert_eq!(
        eval_list(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Approve
    );
}

#[tokio::test]
async fn global_before_short_circuits_ahead_of_the_list_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let before = write_sieve(
        dir.path(),
        "before.sieve",
        r#"require "envelope"; if address :is "from" "spammer@evil.example" { discard; }"#,
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&before)
        .unwrap();

    // spammer would otherwise hit POLICY's final `reject` branch, but the global before-script
    // discards first, so the list policy never runs.
    assert_eq!(
        eval_list(&engine, "lists.example.org", "spammer@evil.example").await,
        PolicyDecision::Discard
    );
}

#[tokio::test]
async fn global_before_no_opinion_falls_through_to_the_list_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let before = write_sieve(
        dir.path(),
        "before.sieve",
        r#"require "envelope"; if address :is "from" "nobody@evil.example" { discard; }"#,
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&before)
        .unwrap();

    // The before-script's condition never matches alice, so its implicit keep is not
    // authoritative and the list policy (which approves subscribers) still decides.
    assert_eq!(
        eval_list(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Approve
    );
}

#[tokio::test]
async fn domain_before_only_applies_to_its_own_domain() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let before = write_sieve(dir.path(), "before.sieve", "discard;\n");
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_domain_before("lists.example.com", &before)
        .unwrap();

    // The scoped domain's before-script discards unconditionally...
    assert_eq!(
        eval_list(&engine, "lists.example.com", "alice@example.com").await,
        PolicyDecision::Discard
    );
    // ...but a list in a different domain never sees it, so the list policy still approves.
    assert_eq!(
        eval_list(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Approve
    );
}

#[tokio::test]
async fn global_after_can_escalate_an_approval_from_the_list_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let after = write_sieve(
        dir.path(),
        "after.sieve",
        r#"require ["envelope", "reject"]; if address :is "from" "alice@example.com" { reject "blocked instance-wide"; }"#,
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_after(&after)
        .unwrap();

    // The list policy approves alice (a subscriber), but the global after-script tightens it.
    assert_eq!(
        eval_list(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Reject {
            reason: "blocked instance-wide".to_string()
        }
    );
}

#[tokio::test]
async fn a_before_hold_still_lets_the_after_tier_escalate_it() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let before = write_sieve(
        dir.path(),
        "before.sieve",
        "require \"fileinto\"; fileinto \"moderate\";\n",
    );
    let after = write_sieve(
        dir.path(),
        "after.sieve",
        r#"require ["envelope", "reject"]; reject "blocked instance-wide";"#,
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&before)
        .unwrap()
        .with_global_after(&after)
        .unwrap();

    // The before-script holds every message (skipping the list policy entirely, since a hold
    // has nothing left for it to add), but the after-script still runs and escalates the hold
    // all the way to a reject.
    assert_eq!(
        eval_list(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Reject {
            reason: "blocked instance-wide".to_string()
        }
    );
}

#[tokio::test]
async fn full_chain_runs_in_order_global_before_domain_before_list_domain_after_global_after() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", "keep;\n"); // always approves on its own
    let global_before = write_sieve(dir.path(), "gb.sieve", "# no opinion\n");
    let domain_before = write_sieve(dir.path(), "db.sieve", "# no opinion\n");
    let domain_after = write_sieve(
        dir.path(),
        "da.sieve",
        "require \"fileinto\"; fileinto \"moderate\";\n",
    );
    let global_after = write_sieve(
        dir.path(),
        "ga.sieve",
        r#"require ["envelope", "reject"]; reject "final word";"#,
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&global_before)
        .unwrap()
        .with_domain_before("lists.example.com", &domain_before)
        .unwrap()
        .with_domain_after("lists.example.com", &domain_after)
        .unwrap()
        .with_global_after(&global_after)
        .unwrap();

    // global-before/domain-before have no opinion, so the list policy approves; domain-after
    // then holds it, and global-after has the final word, escalating to a reject.
    assert_eq!(
        eval_list(&engine, "lists.example.com", "alice@example.com").await,
        PolicyDecision::Reject {
            reason: "final word".to_string()
        }
    );
}
