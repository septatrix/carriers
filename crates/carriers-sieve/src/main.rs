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
    PolicyOutcome, PolicyTrace,
};
use carriers_core::sieve_engine::SieveAction;

use input::{Format, Message};

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

    /// Show the full ordered list of actions each script performed (keep, fileinto, redirect,
    /// notify, envelope and header edits) and, when it edited headers, exactly which headers
    /// changed. Without it, only the final decision is printed.
    #[arg(long, short = 't')]
    trace: bool,

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
    /// The ordered action trace, present only with `--trace`.
    #[serde(skip_serializing_if = "Option::is_none")]
    actions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    added_headers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    removed_headers: Vec<String>,
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

    let mut traces = Vec::with_capacity(messages.len());
    for msg in &messages {
        let trace = engine
            .trace_source(
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
        traces.push(trace);
    }

    if cli.json {
        print_json(&messages, &traces, cli.trace)?;
    } else {
        print_human(&messages, &traces, cli.trace);
    }

    if cli.exit_code {
        let code = traces
            .iter()
            .map(|t| decision_code(&t.outcome.decision))
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

fn print_human(messages: &[Message], traces: &[PolicyTrace], show_trace: bool) {
    for (msg, trace) in messages.iter().zip(traces) {
        let outcome = &trace.outcome;
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
        println!("{}: {decision}{suffix}", msg.label);

        if show_trace {
            if trace.actions.is_empty() {
                println!("    actions: (none — implicit keep)");
            } else {
                println!("    actions:");
                for action in &trace.actions {
                    println!("      {}", action_line(action));
                }
            }
            if let Some(rewritten) = &trace.rewritten {
                let (added, removed) = header_diff(&msg.raw, rewritten);
                if !added.is_empty() || !removed.is_empty() {
                    println!("    header changes:");
                    for h in &added {
                        println!("      + {h}");
                    }
                    for h in &removed {
                        println!("      - {h}");
                    }
                }
            }
        }
    }

    if messages.len() > 1 {
        let mut approve = 0;
        let mut moderate = 0;
        let mut discard = 0;
        let mut reject = 0;
        for trace in traces {
            match trace.outcome.decision {
                PolicyDecision::Approve => approve += 1,
                PolicyDecision::Moderate => moderate += 1,
                PolicyDecision::Discard => discard += 1,
                PolicyDecision::Reject { .. } => reject += 1,
            }
        }
        println!(
            "\n{} message(s): {approve} approve, {moderate} moderate, {discard} discard, {reject} reject",
            messages.len()
        );
    }
}

fn print_json(messages: &[Message], traces: &[PolicyTrace], show_trace: bool) -> Result<()> {
    let json: Vec<JsonResult> = messages
        .iter()
        .zip(traces)
        .map(|(msg, trace)| {
            let outcome = &trace.outcome;
            let (added_headers, removed_headers) = match (show_trace, &trace.rewritten) {
                (true, Some(rewritten)) => header_diff(&msg.raw, rewritten),
                _ => (Vec::new(), Vec::new()),
            };
            JsonResult {
                label: &msg.label,
                decision: decision_word(&outcome.decision),
                reason: match &outcome.decision {
                    PolicyDecision::Reject { reason } => Some(reason.as_str()),
                    _ => None,
                },
                archive: outcome.archive,
                no_dkim: outcome.no_own_dkim,
                munge_from: outcome.munge_from,
                actions: show_trace.then(|| trace.actions.iter().map(action_line).collect()),
                added_headers,
                removed_headers,
            }
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

/// A one-line, human-readable rendering of a single traced Sieve action.
fn action_line(action: &SieveAction) -> String {
    match action {
        SieveAction::Keep { flags } if flags.is_empty() => "keep".to_string(),
        SieveAction::Keep { flags } => format!("keep [flags: {}]", flags.join(", ")),
        SieveAction::Discard => "discard".to_string(),
        SieveAction::Reject { extended, reason } => {
            let verb = if *extended { "ereject" } else { "reject" };
            format!("{verb} {reason:?}")
        }
        SieveAction::FileInto {
            folder,
            flags,
            create,
        } => {
            let mut s = format!("fileinto {folder:?}");
            if *create {
                s.push_str(" :create");
            }
            if !flags.is_empty() {
                s.push_str(&format!(" [flags: {}]", flags.join(", ")));
            }
            s
        }
        SieveAction::Redirect { recipient } => format!("redirect {recipient}"),
        SieveAction::Notify { method, message } if message.is_empty() => format!("notify {method}"),
        SieveAction::Notify { method, message } => format!("notify {method} — {message}"),
        SieveAction::SetEnvelope { field, value } => format!("setenvelope {field} = {value:?}"),
        SieveAction::EditedMessage => "edited message headers".to_string(),
    }
}

/// Header lines added / removed between the original message and the script-rewritten one, as a
/// multiset difference of their (unfolded) header blocks. Used to show exactly what
/// `addheader`/`deleteheader` did.
fn header_diff(original: &[u8], rewritten: &[u8]) -> (Vec<String>, Vec<String>) {
    let orig = header_lines(original);
    let new = header_lines(rewritten);

    // added = new − orig, removed = orig − new, each as a multiset so a duplicated header is
    // reported the right number of times.
    let mut remaining = new.clone();
    let mut removed = Vec::new();
    for line in &orig {
        if let Some(pos) = remaining.iter().position(|l| l == line) {
            remaining.remove(pos);
        } else {
            removed.push(line.clone());
        }
    }
    let mut remaining = orig.clone();
    let mut added = Vec::new();
    for line in &new {
        if let Some(pos) = remaining.iter().position(|l| l == line) {
            remaining.remove(pos);
        } else {
            added.push(line.clone());
        }
    }
    (added, removed)
}

/// The unfolded header lines of a raw RFC 5322 message: the header block (everything before the
/// first blank line), with folded continuation lines joined onto their parent so each entry is one
/// logical header.
fn header_lines(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let end = text
        .find("\r\n\r\n")
        .or_else(|| text.find("\n\n"))
        .unwrap_or(text.len());
    let mut lines: Vec<String> = Vec::new();
    for line in text[..end].split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if (line.starts_with(' ') || line.starts_with('\t')) && !lines.is_empty() {
            let last = lines.last_mut().unwrap();
            last.push(' ');
            last.push_str(line.trim_start());
        } else {
            lines.push(line.to_string());
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_diff_reports_added_and_removed_only() {
        let orig = b"From: a@example.com\r\nX-Spam-Flag: NO\r\nSubject: hi\r\n\r\nbody\r\n";
        // A header prepended, one removed, the rest (and the body) unchanged.
        let new = b"X-Carriers: seen\r\nFrom: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let (added, removed) = header_diff(orig, new);
        assert_eq!(added, vec!["X-Carriers: seen".to_string()]);
        assert_eq!(removed, vec!["X-Spam-Flag: NO".to_string()]);
    }

    #[test]
    fn header_lines_unfolds_continuations() {
        let raw = b"Subject: a very\r\n long subject\r\nTo: b@example.com\r\n\r\nbody\r\n";
        assert_eq!(
            header_lines(raw),
            vec![
                "Subject: a very long subject".to_string(),
                "To: b@example.com".to_string(),
            ]
        );
    }

    #[test]
    fn action_line_renders_each_action() {
        assert_eq!(action_line(&SieveAction::Discard), "discard");
        assert_eq!(
            action_line(&SieveAction::Reject {
                extended: true,
                reason: "no".to_string()
            }),
            "ereject \"no\""
        );
        assert_eq!(
            action_line(&SieveAction::FileInto {
                folder: "archive".to_string(),
                flags: vec![],
                create: true,
            }),
            "fileinto \"archive\" :create"
        );
        assert_eq!(
            action_line(&SieveAction::Redirect {
                recipient: "x@y.com".to_string()
            }),
            "redirect x@y.com"
        );
    }
}
