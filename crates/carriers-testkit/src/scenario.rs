//! Built-in end-to-end scenarios. Each brings up a fresh harness, injects one message, and
//! asserts how the delivered copy scores at the sink — turning carriers' core DMARC-survival
//! claim into something you can actually run.

use anyhow::{Result, bail};

use crate::harness::{self, Harness, HarnessOpts};
use crate::sender::{self, Draft};
use crate::sink::Verdict;

/// Every built-in scenario name, in a natural running order.
pub const ALL: &[&str] = &[
    "author-signed-preject",
    "no-dkim",
    "replay-eml",
    "dmarc-reject-spoofed",
    "dmarc-none-no-signature",
    "dkim2-signing",
];

/// Run one scenario by name; returns whether every assertion held. Details are printed.
pub async fn run(name: &str) -> Result<bool> {
    match name {
        "author-signed-preject" => author_signed_preject().await,
        "no-dkim" => no_dkim().await,
        "replay-eml" => replay_eml().await,
        "dmarc-reject-spoofed" => dmarc_reject_spoofed().await,
        "dmarc-none-no-signature" => dmarc_none_no_signature().await,
        "dkim2-signing" => dkim2_signing().await,
        other => bail!("unknown scenario `{other}` (known: {})", ALL.join(", ")),
    }
}

/// An existing, validly author-signed message from a `p=reject` domain: the whole reason carriers
/// exists. The author's DKIM must survive, the list adds its own aligned DKIM and an ARC seal, and
/// the subscriber sees DMARC pass via DKIM alignment on the author domain.
async fn author_signed_preject() -> Result<bool> {
    let h = Harness::start(HarnessOpts {
        author_dmarc_policy: "reject".to_string(),
        print_verdicts: false,
        ..Default::default()
    })
    .await?;

    let raw = sender::build(&draft("Hello list (signed)"));
    let signed = sender::sign_as_author(&raw, &h.author)?;
    let verdict = send_and_score(&h, &signed).await?;

    report(
        "author-signed-preject",
        &verdict,
        &[
            check("author DKIM survives", verdict.author_dkim_pass(), true),
            check(
                "list DKIM valid",
                verdict.dkim_pass_for(harness::LIST_DOMAIN),
                true,
            ),
            check("ARC cv=pass", verdict.arc_pass, true),
            check("DMARC via DKIM alignment", verdict.dmarc_via_dkim, true),
            check("DMARC pass overall", verdict.dmarc_pass, true),
        ],
    )
}

/// The same post with no author signature. The list identity (its own DKIM + ARC) is still valid,
/// but the author domain cannot pass DMARC via DKIM — the delivered copy fails author-domain DMARC.
/// This is exactly why an unsigned original can't be laundered into alignment.
async fn no_dkim() -> Result<bool> {
    let h = Harness::start(HarnessOpts {
        author_dmarc_policy: "reject".to_string(),
        print_verdicts: false,
        ..Default::default()
    })
    .await?;

    let raw = sender::build(&draft("Hello list (unsigned)"));
    let verdict = send_and_score(&h, &raw).await?;

    report(
        "no-dkim",
        &verdict,
        &[
            check(
                "no surviving author DKIM",
                verdict.author_dkim_pass(),
                false,
            ),
            check(
                "list DKIM valid",
                verdict.dkim_pass_for(harness::LIST_DOMAIN),
                true,
            ),
            check("ARC cv=pass", verdict.arc_pass, true),
            check("author-domain DMARC fails", verdict.dmarc_pass, false),
        ],
    )
}

/// Replay an existing `.eml` verbatim (bundled fixture), proving real-world messages flow through
/// and get scored. The fixture is unsigned, so it behaves like `no-dkim` but exercises the replay
/// path rather than a crafted message.
async fn replay_eml() -> Result<bool> {
    let h = Harness::start(HarnessOpts {
        author_dmarc_policy: "none".to_string(),
        print_verdicts: false,
        ..Default::default()
    })
    .await?;

    let fixture = include_bytes!("../../../examples/testkit/messages/plain.eml");
    let raw = sender::prepare(fixture);
    let verdict = send_and_score(&h, &raw).await?;

    report(
        "replay-eml",
        &verdict,
        &[
            check(
                "list DKIM valid",
                verdict.dkim_pass_for(harness::LIST_DOMAIN),
                true,
            ),
            check("ARC cv=pass", verdict.arc_pass, true),
        ],
    )
}

/// A spoofed identity: `From:` claims a third-party domain that publishes a strict, enforcing
/// DMARC policy (`p=reject`) but authorizes no sender at all — no valid DKIM signature, no SPF
/// authorization for the injecting IP. This is exactly the "open relay" risk the DMARC gate
/// exists for: without it, carriers would happily add its own valid, aligned DKIM signature to
/// this message and relay it, laundering an unauthenticated, impersonated identity with the
/// list's own reputation. The `dmarc-before` gate must reject it outright, at the SMTP level,
/// before it ever reaches moderation or signing.
async fn dmarc_reject_spoofed() -> Result<bool> {
    let h = Harness::start(HarnessOpts::default()).await?;
    let before = h.sink.verdicts().await.len();

    let from = format!("mallory@{}", harness::SPOOFED_STRICT_DOMAIN);
    let draft = Draft {
        from: from.clone(),
        to: harness::POSTING_ADDRESS.to_string(),
        subject: "Urgent: impersonated identity".to_string(),
        body: "This message claims a strict domain's identity with no valid authentication.\n"
            .to_string(),
        extra_headers: Vec::new(),
    };
    let raw = sender::build(&draft);
    let result = sender::inject(&h.ingress_host, h.ingress_port, &from, &draft.to, &raw).await;
    let after = h.sink.verdicts().await.len();

    println!("\n=== scenario: dmarc-reject-spoofed ===");
    let rejected = result.is_err();
    let no_copy_delivered = after == before;
    println!(
        "  submission: {}",
        result.as_ref().err().map_or_else(
            || "accepted (unexpected)".to_string(),
            |e| format!("rejected ({e})")
        )
    );
    let mut all_ok = true;
    for (label, ok) in [
        ("SMTP submission rejected", rejected),
        ("no copy reached the sink", no_copy_delivered),
    ] {
        println!("  [{}] {label}", if ok { "OK  " } else { "FAIL" });
        all_ok &= ok;
    }
    println!("  result: {}", if all_ok { "PASS" } else { "FAIL" });
    Ok(all_ok)
}

/// A domain with no DMARC or SPF record configured at all (not even `p=none` — the record is
/// simply absent), and no author DKIM signature. carriers has nothing to authenticate here, so
/// per the "must never sign unauthenticated mail with our own reputation" invariant, the message
/// is still distributed (the domain isn't asking for enforcement), but must not carry the list's
/// own DKIM signature — only the honest ARC seal.
async fn dmarc_none_no_signature() -> Result<bool> {
    let h = Harness::start(HarnessOpts::default()).await?;

    let from = format!("casey@{}", harness::UNCONFIGURED_DOMAIN);
    let draft = Draft {
        from: from.clone(),
        to: harness::POSTING_ADDRESS.to_string(),
        subject: "No DMARC configured".to_string(),
        body: "This domain has no DMARC, DKIM or SPF record at all.\n".to_string(),
        extra_headers: Vec::new(),
    };
    let raw = sender::build(&draft);
    let verdict = send_and_score_from(&h, &from, &draft.to, &raw).await?;

    report(
        "dmarc-none-no-signature",
        &verdict,
        &[
            check(
                "list DKIM withheld",
                verdict.dkim_pass_for(harness::LIST_DOMAIN),
                false,
            ),
            check("ARC cv=pass", verdict.arc_pass, true),
        ],
    )
}

/// A list with an opt-in `[dkim2]` key configured (draft-ietf-dkim-dkim2-spec). DKIM2 binds the
/// exact SMTP envelope, so carriers adds the chain link once per delivery, matching each
/// subscriber's own VERP return path — the sink verifies it against the real envelope it received
/// the copy under.
async fn dkim2_signing() -> Result<bool> {
    let h = Harness::start(HarnessOpts {
        list_dkim2: true,
        ..Default::default()
    })
    .await?;

    let raw = sender::build(&draft("Hello list (DKIM2)"));
    let verdict = send_and_score(&h, &raw).await?;

    report(
        "dkim2-signing",
        &verdict,
        &[
            check(
                "list DKIM valid",
                verdict.dkim_pass_for(harness::LIST_DOMAIN),
                true,
            ),
            check("ARC cv=pass", verdict.arc_pass, true),
            check(
                "DKIM2 chain valid against the delivery envelope",
                verdict.dkim2_pass,
                true,
            ),
        ],
    )
}

fn draft(subject: &str) -> Draft {
    Draft {
        from: harness::AUTHOR_FROM.to_string(),
        to: harness::POSTING_ADDRESS.to_string(),
        subject: subject.to_string(),
        body: "Hello, list. This body must survive byte-for-byte.\n".to_string(),
        extra_headers: Vec::new(),
    }
}

/// Inject `raw` as the fixed harness author and return the verdict the sink scored for the
/// resulting delivered copy.
async fn send_and_score(h: &Harness, raw: &[u8]) -> Result<Verdict> {
    send_and_score_from(h, harness::AUTHOR_FROM, harness::POSTING_ADDRESS, raw).await
}

/// Inject `raw` with an arbitrary envelope `mail_from`/`to` and return the verdict the sink
/// scored for the resulting delivered copy.
async fn send_and_score_from(
    h: &Harness,
    mail_from: &str,
    to: &str,
    raw: &[u8],
) -> Result<Verdict> {
    let before = h.sink.verdicts().await.len();
    sender::inject(&h.ingress_host, h.ingress_port, mail_from, to, raw).await?;

    // The ingress only returns 2xx after delivery to the sink has completed, so a verdict is
    // already recorded; poll briefly to be robust against scheduling.
    for _ in 0..100 {
        let verdicts = h.sink.verdicts().await;
        if verdicts.len() > before {
            return Ok(verdicts[before].clone());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    bail!("no delivered copy reached the sink (was the message distributed?)")
}

struct Check {
    label: &'static str,
    ok: bool,
    got: bool,
    want: bool,
}

fn check(label: &'static str, got: bool, want: bool) -> Check {
    Check {
        label,
        ok: got == want,
        got,
        want,
    }
}

/// Print a scenario's verdict and per-assertion results; return whether all passed.
fn report(name: &str, verdict: &Verdict, checks: &[Check]) -> Result<bool> {
    println!("\n=== scenario: {name} ===");
    println!("  delivered: {}", verdict.summary());
    let mut all_ok = true;
    for c in checks {
        let mark = if c.ok { "OK  " } else { "FAIL" };
        println!(
            "  [{mark}] {} (want {}, got {})",
            c.label,
            yesno(c.want),
            yesno(c.got)
        );
        all_ok &= c.ok;
    }
    println!("  result: {}", if all_ok { "PASS" } else { "FAIL" });
    Ok(all_ok)
}

fn yesno(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}
