//! carriers-sieve — run a carriers Sieve policy against real messages, outside the daemon.
//!
//! Two ways to use it, sharing one argument layout (`<script> <inputs...>`):
//!
//! - **directly**: `carriers-sieve policy.sieve message.eml [--mail-from …] [--list subscribers=…]`
//! - **as a shebang** on a `.sieve` script, so the script becomes runnable against a message:
//!   ```sieve
//!   #!/usr/bin/env -S carriers-sieve --list-name announce
//!   require ["envelope", "extlists", "fileinto", "reject"];
//!   …
//!   ```
//!   invoked as `./policy.sieve message.eml` — the kernel passes the script path first and the
//!   message file(s) after it, which is exactly the layout above.
//!
//! Each message is evaluated as a single carriers policy tier (see
//! [`carriers_core::policy::PolicyEngine::evaluate_source`]) and its decision — approve / moderate
//! / discard / reject, plus the archive / no-dkim / munge-from side-effect flags — is printed. The
//! decision logic is the daemon's own, so what you see here is what a list would do.

mod input;

use anyhow::{Context, Result, bail};
use clap::Parser;

use carriers_core::policy::{
    LIST_MODERATORS, LIST_POSTERS, LIST_SUBSCRIBERS, MembershipSets, PolicyDecision, PolicyEngine,
    PolicyOutcome,
};

use input::Format;

#[derive(Parser)]
#[command(
    name = "carriers-sieve",
    version,
    about = "Run a carriers Sieve policy against .eml or mbox messages",
    long_about = "Run a carriers Sieve policy against one or more messages and print the decision \
                  it reaches (approve/moderate/discard/reject). Works from the command line or as \
                  a `#!/usr/bin/env -S carriers-sieve …` shebang on a .sieve script."
)]
struct Cli {
    /// The Sieve policy script to run. As a shebang, this is supplied automatically as the script
    /// being executed.
    script: std::path::PathBuf,

    /// Messages to evaluate: `.eml` files, mbox files, and/or directories of them.
    #[arg(value_name = "INPUT")]
    inputs: Vec<std::path::PathBuf>,

    /// Envelope MAIL FROM, used by `address`/`envelope` tests. Defaults to empty (no envelope
    /// sender).
    #[arg(long, value_name = "ADDR", default_value = "")]
    mail_from: String,

    /// Membership for a Sieve external `:list` test, as `NAME=addr[,addr…]`, repeatable. NAME is
    /// one of `subscribers`, `posters`, `moderators` (e.g. `--list subscribers=a@x.com,b@y.com`).
    #[arg(long = "list", value_name = "NAME=ADDRS")]
    lists: Vec<String>,

    /// Set a Sieve environment item, as `NAME=VALUE`, repeatable (e.g.
    /// `--env vnd.carriers.dmarc_pass=false`). Overrides any inherited OS variable of the same name.
    #[arg(long = "env", value_name = "NAME=VALUE")]
    env: Vec<String>,

    /// Do not import the process's OS environment variables into the Sieve environment (by default
    /// they are, so a shebang'd script sees the environment it was launched with).
    #[arg(long)]
    no_inherit_env: bool,

    /// The current list's short name, exposed to the script as `vnd.carriers.list`.
    #[arg(long, value_name = "NAME", default_value = "debug")]
    list_name: String,

    /// The current list's `List-Id`, exposed to the script as `vnd.carriers.list_id`.
    #[arg(long, value_name = "LIST-ID", default_value = "")]
    list_id: String,

    /// How to interpret file inputs.
    #[arg(long, value_enum, default_value_t = Format::Auto)]
    format: Format,

    /// Emit results as a JSON array instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Map the decision to the process exit status (approve=0, moderate=10, discard=11, reject=12).
    /// With several messages, the most severe decision wins. Off by default (always exit 0).
    #[arg(long)]
    exit_code: bool,
}

#[derive(serde::Serialize)]
struct JsonResult<'a> {
    label: &'a str,
    decision: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    archive: bool,
    no_dkim: bool,
    munge_from: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "carriers_sieve=info,carriers_core=warn".into()),
        )
        .init();

    let cli = Cli::parse();

    if cli.inputs.is_empty() {
        bail!(
            "no message given: run `carriers-sieve <script.sieve> <message.eml…>` (a directory or \
             mbox file works too)"
        );
    }

    let source = std::fs::read(&cli.script)
        .with_context(|| format!("reading script {}", cli.script.display()))?;
    let script_name = cli.script.display().to_string();

    let sets = parse_lists(&cli.lists)?;
    let env = build_env(cli.no_inherit_env, &cli.env)?;
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    let messages = input::expand(&cli.inputs, cli.format)?;
    if messages.is_empty() {
        bail!("the given inputs contained no messages");
    }

    let engine = PolicyEngine::new().context("initialising the Sieve policy engine")?;

    let mut results = Vec::with_capacity(messages.len());
    for msg in &messages {
        let outcome = engine
            .evaluate_source(
                &script_name,
                &source,
                &cli.list_name,
                &cli.list_id,
                &cli.mail_from,
                &msg.raw,
                &sets,
                &env_refs,
            )
            .await
            .with_context(|| format!("evaluating {}", msg.label))?;
        results.push((msg.label.as_str(), outcome));
    }

    if cli.json {
        print_json(&results)?;
    } else {
        print_human(&results);
    }

    if cli.exit_code {
        let code = results
            .iter()
            .map(|(_, o)| decision_code(&o.decision))
            .max()
            .unwrap_or(0);
        std::process::exit(code);
    }
    Ok(())
}

/// Parse `--list NAME=addr,addr…` arguments into a [`MembershipSets`]. Addresses are lowercased to
/// match how `MembershipSets` resolves `:list` tests.
fn parse_lists(specs: &[String]) -> Result<MembershipSets> {
    let mut sets = MembershipSets::default();
    for spec in specs {
        let (name, addrs) = spec
            .split_once('=')
            .with_context(|| format!("expected --list NAME=addr[,addr…], got `{spec}`"))?;
        let target = match name {
            LIST_SUBSCRIBERS => &mut sets.subscribers,
            LIST_POSTERS => &mut sets.posters,
            LIST_MODERATORS => &mut sets.moderators,
            other => bail!(
                "unknown list `{other}` in `--list {spec}` (expected `{LIST_SUBSCRIBERS}`, \
                 `{LIST_POSTERS}` or `{LIST_MODERATORS}`)"
            ),
        };
        for addr in addrs.split(',') {
            let addr = addr.trim();
            if !addr.is_empty() {
                target.insert(addr.to_ascii_lowercase());
            }
        }
    }
    Ok(sets)
}

/// Build the Sieve environment items: the process's OS environment (unless `no_inherit`) followed
/// by the explicit `--env` overrides. Later entries win via the runtime's set-then-overwrite
/// semantics, so `--env` takes precedence over an inherited variable of the same name.
fn build_env(no_inherit: bool, overrides: &[String]) -> Result<Vec<(String, String)>> {
    let mut env = Vec::new();
    if !no_inherit {
        for (k, v) in std::env::vars_os() {
            // Skip any variable that isn't valid UTF-8 rather than aborting the whole run.
            if let (Ok(k), Ok(v)) = (k.into_string(), v.into_string()) {
                env.push((k, v));
            }
        }
    }
    for spec in overrides {
        let (name, value) = spec
            .split_once('=')
            .with_context(|| format!("expected --env NAME=VALUE, got `{spec}`"))?;
        env.push((name.to_string(), value.to_string()));
    }
    Ok(env)
}

fn decision_code(decision: &PolicyDecision) -> i32 {
    match decision {
        PolicyDecision::Approve => 0,
        PolicyDecision::Moderate => 10,
        PolicyDecision::Discard => 11,
        PolicyDecision::Reject { .. } => 12,
    }
}

fn decision_word(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Approve => "approve",
        PolicyDecision::Moderate => "moderate",
        PolicyDecision::Discard => "discard",
        PolicyDecision::Reject { .. } => "reject",
    }
}

fn side_effects(outcome: &PolicyOutcome) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if outcome.archive {
        flags.push("archive");
    }
    if outcome.no_own_dkim {
        flags.push("no-dkim");
    }
    if outcome.munge_from {
        flags.push("munge-from");
    }
    flags
}

fn print_human(results: &[(&str, PolicyOutcome)]) {
    for (label, outcome) in results {
        let decision = match &outcome.decision {
            PolicyDecision::Reject { reason } => format!("reject: {reason}"),
            other => decision_word(other).to_string(),
        };
        let flags = side_effects(outcome);
        let suffix = if flags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", flags.join(", "))
        };
        println!("{label}: {decision}{suffix}");
    }

    if results.len() > 1 {
        let mut approve = 0;
        let mut moderate = 0;
        let mut discard = 0;
        let mut reject = 0;
        for (_, o) in results {
            match o.decision {
                PolicyDecision::Approve => approve += 1,
                PolicyDecision::Moderate => moderate += 1,
                PolicyDecision::Discard => discard += 1,
                PolicyDecision::Reject { .. } => reject += 1,
            }
        }
        println!(
            "\n{} message(s): {approve} approve, {moderate} moderate, {discard} discard, {reject} reject",
            results.len()
        );
    }
}

fn print_json(results: &[(&str, PolicyOutcome)]) -> Result<()> {
    let json: Vec<JsonResult> = results
        .iter()
        .map(|(label, outcome)| JsonResult {
            label,
            decision: decision_word(&outcome.decision),
            reason: match &outcome.decision {
                PolicyDecision::Reject { reason } => Some(reason.as_str()),
                _ => None,
            },
            archive: outcome.archive,
            no_dkim: outcome.no_own_dkim,
            munge_from: outcome.munge_from,
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}
