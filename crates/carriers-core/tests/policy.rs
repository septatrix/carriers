//! Tests for Sieve-based moderation policies.

use std::collections::HashSet;
use std::sync::Mutex;

use carriers_core::policy::{MembershipSets, PolicyDecision, PolicyEngine, PolicyOutcome};
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
            .evaluate(
                "corporate",
                "dev",
                LIST_ID,
                from,
                &message(from),
                &sets,
                &[],
            )
            .await
            .unwrap()
            .decision
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
async fn evaluate_source_runs_an_ad_hoc_script() {
    // `evaluate_source` compiles and runs a script that was never loaded as a named policy,
    // yielding the same decisions as a loaded one. This is what `carriers-sieve` builds on.
    let engine = PolicyEngine::new().unwrap();
    let sets = sets(); // subscribers: alice; posters: bot
    let eval = async |from: &str| {
        engine
            .evaluate_source("ad-hoc", POLICY.as_bytes(), "dev", LIST_ID, from, &message(from), &sets, &[])
            .await
            .unwrap()
            .decision
    };

    assert_eq!(eval("alice@example.com").await, PolicyDecision::Approve);
    assert_eq!(eval("bot@example.net").await, PolicyDecision::Moderate);
    assert_eq!(eval("spammer@evil.example").await, PolicyDecision::Discard);
    assert_eq!(
        eval("mallory@evil.example").await,
        PolicyDecision::Reject {
            reason: "Only subscribers and posters may write to this list.".to_string()
        }
    );

    // A malformed script surfaces a compile error rather than a decision.
    assert!(
        engine
            .evaluate_source(
                "broken",
                b"if address :list \"from\" {\n",
                "dev",
                LIST_ID,
                "anyone@example.com",
                &message("anyone@example.com"),
                &MembershipSets::default(),
                &[],
            )
            .await
            .is_err()
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
                &MembershipSets::default(),
                &[]
            )
            .await
            .unwrap()
            .decision,
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
            .evaluate(policy, "dev", LIST_ID, from, &message(from), &sets, &[])
            .await
            .unwrap()
            .decision
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

/// Create a `.d` drop-in directory named `name` under `dir`, holding a single script `body`,
/// and return its path (for the `with_global_before`/… builders, which take a directory).
fn dropin(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("10-x.sieve"), body).unwrap();
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

/// The "before" half of the chain (global-before -> domain-before -> the list policy), decided
/// at intake (helper to keep the tier-composition tests readable).
async fn eval_before(engine: &PolicyEngine, domain: &str, from: &str) -> PolicyDecision {
    eval_before_outcome(engine, domain, from, &[])
        .await
        .decision
}

/// Like [`eval_before`], but returns the full [`PolicyOutcome`] and accepts extra environment
/// variables (e.g. the `vnd.carriers.dmarc_*` facts) for tests of the built-in DMARC gate.
async fn eval_before_outcome(
    engine: &PolicyEngine,
    domain: &str,
    from: &str,
    extra_env: &[(&str, &str)],
) -> PolicyOutcome {
    engine
        .evaluate_before(
            "corporate",
            "dev",
            LIST_ID,
            domain,
            from,
            &message(from),
            &sets(),
            extra_env,
        )
        .await
        .unwrap()
}

/// The "after" half of the chain (domain-after -> global-after), decided at distribution time.
async fn eval_after(engine: &PolicyEngine, domain: &str, from: &str) -> PolicyDecision {
    eval_after_outcome(engine, domain, from, &[]).await.decision
}

/// Like [`eval_after`], but returns the full [`PolicyOutcome`] and accepts extra environment
/// variables.
async fn eval_after_outcome(
    engine: &PolicyEngine,
    domain: &str,
    from: &str,
    extra_env: &[(&str, &str)],
) -> PolicyOutcome {
    engine
        .evaluate_after(
            "dev",
            LIST_ID,
            domain,
            from,
            &message(from),
            &sets(),
            extra_env,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn evaluate_before_without_any_global_scripts_just_runs_the_named_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let engine = PolicyEngine::load(dir.path()).unwrap();

    assert_eq!(
        eval_before(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Approve
    );
    // With no after-scripts configured, the after half approves too.
    assert_eq!(
        eval_after(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Approve
    );
}

#[tokio::test]
async fn global_before_short_circuits_ahead_of_the_list_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let before = dropin(
        dir.path(),
        "before.d",
        r#"require "envelope"; if address :is "from" "spammer@evil.example" { discard; }"#,
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&before)
        .unwrap();

    // spammer would otherwise hit POLICY's final `reject` branch, but the global before-script
    // discards first, so the list policy never runs.
    assert_eq!(
        eval_before(&engine, "lists.example.org", "spammer@evil.example").await,
        PolicyDecision::Discard
    );
}

#[tokio::test]
async fn global_before_no_opinion_falls_through_to_the_list_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let before = dropin(
        dir.path(),
        "before.d",
        r#"require "envelope"; if address :is "from" "nobody@evil.example" { discard; }"#,
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&before)
        .unwrap();

    // The before-script's condition never matches alice, so its implicit keep is not
    // authoritative and the list policy (which approves subscribers) still decides.
    assert_eq!(
        eval_before(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Approve
    );
}

#[tokio::test]
async fn domain_before_only_applies_to_its_own_domain() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let before = dropin(dir.path(), "before.d", "discard;\n");
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_domain_before("lists.example.com", &before)
        .unwrap();

    // The scoped domain's before-script discards unconditionally...
    assert_eq!(
        eval_before(&engine, "lists.example.com", "alice@example.com").await,
        PolicyDecision::Discard
    );
    // ...but a list in a different domain never sees it, so the list policy still approves.
    assert_eq!(
        eval_before(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Approve
    );
}

#[tokio::test]
async fn global_after_can_escalate_an_approval() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let after = dropin(
        dir.path(),
        "after.d",
        r#"require ["envelope", "reject"]; if address :is "from" "alice@example.com" { reject "blocked instance-wide"; }"#,
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_after(&after)
        .unwrap();

    // The before half approves alice (a subscriber)...
    assert_eq!(
        eval_before(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Approve
    );
    // ...but at distribution time the after half tightens that approval to a reject.
    assert_eq!(
        eval_after(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Reject {
            reason: "blocked instance-wide".to_string()
        }
    );
}

#[tokio::test]
async fn a_before_hold_then_a_later_after_reject() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let before = dropin(
        dir.path(),
        "before.d",
        "require \"fileinto\"; fileinto \"moderate\";\n",
    );
    let after = dropin(
        dir.path(),
        "after.d",
        r#"require ["envelope", "reject"]; reject "blocked instance-wide";"#,
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&before)
        .unwrap()
        .with_global_after(&after)
        .unwrap();

    // The before-script holds every message (skipping the list policy, since a hold has nothing
    // left for it to add) — the message is queued for moderation...
    assert_eq!(
        eval_before(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Moderate
    );
    // ...then once a moderator approves it and it reaches `finalize`, the after-script still runs
    // and escalates it all the way to a reject.
    assert_eq!(
        eval_after(&engine, "lists.example.org", "alice@example.com").await,
        PolicyDecision::Reject {
            reason: "blocked instance-wide".to_string()
        }
    );
}

#[tokio::test]
async fn full_chain_runs_in_order_before_at_intake_after_at_finalize() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", "keep;\n"); // always approves on its own
    let global_before = dropin(dir.path(), "gb.d", "# no opinion\n");
    let domain_before = dropin(dir.path(), "db.d", "# no opinion\n");
    let domain_after = dropin(
        dir.path(),
        "da.d",
        "require \"fileinto\"; fileinto \"moderate\";\n",
    );
    let global_after = dropin(
        dir.path(),
        "ga.d",
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

    // before half: global-before/domain-before have no opinion, so the list policy approves.
    assert_eq!(
        eval_before(&engine, "lists.example.com", "alice@example.com").await,
        PolicyDecision::Approve
    );
    // after half: domain-after holds it, then global-after has the final word, a reject.
    assert_eq!(
        eval_after(&engine, "lists.example.com", "alice@example.com").await,
        PolicyDecision::Reject {
            reason: "final word".to_string()
        }
    );
}

/// `load_root` discovers the whole conventional layout — moderation policies plus the
/// global/domain drop-ins — from one root, feeding the same builders the tests above drive by
/// hand. This is the single knob `sieve_scripts` points at.
#[tokio::test]
async fn load_root_discovers_the_conventional_layout() {
    let root = tempfile::tempdir().unwrap();

    // moderation_policies/corporate.sieve — a named list policy that always approves.
    let moderation = root.path().join("moderation_policies");
    std::fs::create_dir_all(&moderation).unwrap();
    write_policy(&moderation, "corporate", "keep;\n");

    // before.d / after.d — global drop-ins. domains/<d>/after.d — a per-domain after script.
    dropin(root.path(), "before.d", "# no opinion\n");
    dropin(root.path(), "after.d", "# no opinion\n");
    let domain_after = root.path().join("domains").join("lists.example.com");
    std::fs::create_dir_all(&domain_after).unwrap();
    dropin(
        &domain_after,
        "after.d",
        "require \"fileinto\"; fileinto \"moderate\";\n",
    );

    let engine = PolicyEngine::load_root(root.path()).unwrap();

    // Everything was discovered from the one root.
    assert!(engine.contains("corporate"), "moderation policy discovered");
    assert_eq!(engine.global_before_count(), 1);
    assert_eq!(engine.global_after_count(), 1);
    assert_eq!(engine.domains().collect::<Vec<_>>(), ["lists.example.com"]);

    // And it behaves: the named policy approves at intake, and the discovered per-domain after
    // script holds the message at distribution — only for its own domain.
    assert_eq!(
        eval_before(&engine, "lists.example.com", "alice@example.com").await,
        PolicyDecision::Approve
    );
    assert_eq!(
        eval_after(&engine, "lists.example.com", "alice@example.com").await,
        PolicyDecision::Moderate
    );
    assert_eq!(
        eval_after(&engine, "other.example.org", "alice@example.com").await,
        PolicyDecision::Approve,
        "the per-domain after script must not apply to a different domain"
    );
}

/// An empty (or entirely absent) root is fine: `load_root` yields just the built-ins.
#[tokio::test]
async fn load_root_on_an_empty_root_is_just_the_builtins() {
    let root = tempfile::tempdir().unwrap();
    let engine = PolicyEngine::load_root(root.path()).unwrap();
    assert_eq!(engine.names().count(), 0);
    assert_eq!(engine.global_before_count(), 0);
    assert_eq!(engine.global_after_count(), 0);
    assert_eq!(engine.domains().count(), 0);
    assert!(engine.contains("open"), "built-ins are always present");
}

#[tokio::test]
async fn fileinto_copy_archive_requests_an_archive_but_keeps_the_decision() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    // A before-script archives every message but takes no decision of its own.
    let before = dropin(
        dir.path(),
        "before.d",
        "require [\"fileinto\", \"copy\"]; fileinto :copy \"archive\";\n",
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&before)
        .unwrap();

    // alice (a subscriber) is approved by the list policy, and archiving is requested alongside.
    let out = eval_before_outcome(&engine, "lists.example.org", "alice@example.com", &[]).await;
    assert_eq!(
        out,
        PolicyOutcome {
            decision: PolicyDecision::Approve,
            archive: true,
            no_own_dkim: false,
            munge_from: false,
        }
    );

    // The archive flag rides along with an authoritative decision too: mallory is rejected by the
    // list policy, but the before-script still asked to archive her post.
    let out = eval_before_outcome(&engine, "lists.example.org", "mallory@evil.example", &[]).await;
    assert_eq!(
        out.decision,
        PolicyDecision::Reject {
            reason: "Only subscribers and posters may write to this list.".to_string()
        }
    );
    assert!(out.archive);
}

#[tokio::test]
async fn no_archive_when_no_tier_files_into_archive() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let engine = PolicyEngine::load(dir.path()).unwrap();

    let out = eval_before_outcome(&engine, "lists.example.org", "alice@example.com", &[]).await;
    assert!(!out.archive);
}

#[tokio::test]
async fn archive_can_be_requested_by_the_after_tier() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let after = dropin(
        dir.path(),
        "after.d",
        "require [\"fileinto\", \"copy\"]; fileinto :copy \"archive\";\n",
    );
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_after(&after)
        .unwrap();

    let out = eval_after_outcome(&engine, "lists.example.org", "alice@example.com", &[]).await;
    assert_eq!(
        out,
        PolicyOutcome {
            decision: PolicyDecision::Approve,
            archive: true,
            no_own_dkim: false,
            munge_from: false,
        }
    );
}

#[tokio::test]
async fn before_dropins_run_in_filename_order_and_compose() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", "keep;\n"); // the list policy approves on its own
    // Two drop-ins in one directory: 10- archives, 20- holds. Both effects must apply.
    let before = dir.path().join("before.d");
    std::fs::create_dir_all(&before).unwrap();
    std::fs::write(
        before.join("10-archive.sieve"),
        "require [\"fileinto\", \"copy\"]; fileinto :copy \"archive\";\n",
    )
    .unwrap();
    std::fs::write(
        before.join("20-hold.sieve"),
        "require \"fileinto\"; fileinto \"moderate\";\n",
    )
    .unwrap();
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&before)
        .unwrap();

    let out = eval_before_outcome(&engine, "lists.example.org", "x@example.com", &[]).await;
    assert_eq!(
        out,
        PolicyOutcome {
            decision: PolicyDecision::Moderate,
            archive: true,
            no_own_dkim: false,
            munge_from: false,
        }
    );
}

#[tokio::test]
async fn an_earlier_dropin_reject_short_circuits_later_dropins() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", "keep;\n");
    let before = dir.path().join("before.d");
    std::fs::create_dir_all(&before).unwrap();
    // `10-` rejects; `20-` would discard, but must never run, since reject is terminal. The
    // result being a reject (not a discard) also proves `10-` ran before `20-`.
    std::fs::write(
        before.join("10-reject.sieve"),
        "require \"reject\"; reject \"first\";\n",
    )
    .unwrap();
    std::fs::write(before.join("20-discard.sieve"), "discard;\n").unwrap();
    let engine = PolicyEngine::load(dir.path())
        .unwrap()
        .with_global_before(&before)
        .unwrap();

    let out = eval_before_outcome(&engine, "lists.example.org", "x@example.com", &[]).await;
    assert_eq!(
        out.decision,
        PolicyDecision::Reject {
            reason: "first".to_string()
        }
    );
}

/// `(vnd.carriers.dmarc_pass, vnd.carriers.dmarc_policy)` env pairs, standing in for a computed
/// [`carriers_core::sign::AuthVerdict`] — these tests exercise the gate scripts and policy.rs
/// wiring directly, without a real `MessageAuthenticator`/DNS (that correctness is covered by
/// `sign.rs` and the end-to-end `carriers-testkit` scenarios).
fn dmarc_env(pass: bool, policy: &str) -> [(&str, &str); 2] {
    [
        ("vnd.carriers.dmarc_pass", if pass { "yes" } else { "no" }),
        ("vnd.carriers.dmarc_policy", policy),
    ]
}

#[tokio::test]
async fn dmarc_before_gate_rejects_an_enforced_failure_ahead_of_the_list_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let engine = PolicyEngine::load(dir.path()).unwrap();

    // alice is a subscriber — POLICY would approve her outright — but the built-in DMARC gate
    // runs first and rejects, so the list policy never gets a say.
    let env = dmarc_env(false, "reject");
    let out = eval_before_outcome(&engine, "lists.example.org", "alice@example.com", &env).await;
    assert_eq!(
        out.decision,
        PolicyDecision::Reject {
            reason: "This message failed DMARC and its domain requests enforcement on failure."
                .to_string()
        }
    );
}

#[tokio::test]
async fn dmarc_before_gate_lets_an_unenforced_failure_reach_the_list_policy() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(dir.path(), "corporate", POLICY);
    let engine = PolicyEngine::load(dir.path()).unwrap();

    // No DMARC record published (or an explicit p=none) collapses to "none": the gate has no
    // opinion, so the list policy (which approves alice, a subscriber) still decides.
    let env = dmarc_env(false, "none");
    let out = eval_before_outcome(&engine, "lists.example.org", "alice@example.com", &env).await;
    assert_eq!(out.decision, PolicyDecision::Approve);
}

#[tokio::test]
async fn dmarc_after_gate_withholds_the_list_dkim_signature_for_an_unenforced_failure() {
    let engine = PolicyEngine::new().unwrap();

    let env = dmarc_env(false, "none");
    let out = eval_after_outcome(&engine, "lists.example.org", "alice@example.com", &env).await;
    assert_eq!(out.decision, PolicyDecision::Approve);
    assert!(
        out.no_own_dkim,
        "an unenforced DMARC failure must withhold the list's own DKIM signature"
    );
}

#[tokio::test]
async fn dmarc_after_gate_rejects_an_enforced_failure_defensively() {
    // Even a message that made it past the "before" gate (e.g. the author domain's DNS/policy
    // changed while a message sat held for moderation) must not slip through at the last step.
    let engine = PolicyEngine::new().unwrap();

    let env = dmarc_env(false, "quarantine");
    let out = eval_after_outcome(&engine, "lists.example.org", "alice@example.com", &env).await;
    assert_eq!(
        out.decision,
        PolicyDecision::Reject {
            reason: "This message failed DMARC and its domain requests enforcement on failure."
                .to_string()
        }
    );
}

#[tokio::test]
async fn dmarc_pass_leaves_the_after_outcome_unaffected() {
    let engine = PolicyEngine::new().unwrap();

    // Passing DMARC keeps the list's own signature even against a domain that requests strict
    // enforcement — the gate only acts on a failure, never on a pass.
    let env = dmarc_env(true, "reject");
    let out = eval_after_outcome(&engine, "lists.example.org", "alice@example.com", &env).await;
    assert_eq!(out.decision, PolicyDecision::Approve);
    assert!(!out.no_own_dkim);
}

#[tokio::test]
async fn apply_munge_from_rewrites_from_and_reply_to() {
    let engine = PolicyEngine::new().unwrap();
    let raw = b"From: Alice <alice@example.com>\r\nTo: dev@lists.example.org\r\nSubject: hi\r\n\r\nbody\r\n";

    let munge_env = [
        (
            "vnd.carriers.munge_from",
            "\"Alice via Dev List\" <dev@lists.example.org>",
        ),
        ("vnd.carriers.reply_to", "alice@example.com"),
    ];
    let out = engine
        .apply_munge_from("dev", LIST_ID, &munge_env, raw)
        .await
        .unwrap();
    let out = String::from_utf8(out).unwrap();

    assert!(out.contains("From: \"Alice via Dev List\" <dev@lists.example.org>"));
    assert!(out.contains("Reply-To: alice@example.com"));
    assert!(!out.contains("Alice <alice@example.com>"));
    // The body and other headers survive untouched.
    assert!(out.contains("To: dev@lists.example.org"));
    assert!(out.contains("body"));
}
