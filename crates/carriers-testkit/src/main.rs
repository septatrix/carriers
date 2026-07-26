//! carriers-testkit — a local, in-process end-to-end harness for carriers.
//!
//! Stands up a mock authoritative DNS server (driven by a zone file), a capturing+scoring SMTP
//! sink standing in for subscribers' servers, and the real carriers daemon run in-process, then
//! lets you inject real messages and see how the delivered copies score for DMARC/DKIM/ARC.

mod dns;
mod harness;
mod scenario;
mod sender;
mod sink;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use carriers_core::list::Algorithm;
use harness::{Harness, HarnessOpts};
use sender::{AuthorKey, Draft};

#[derive(Parser)]
#[command(
    name = "carriers-testkit",
    about = "Local end-to-end test harness for carriers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // clap arg structs; not worth boxing for a CLI dispatch enum
enum Command {
    /// Bring the full stack (mock DNS + sink + in-process daemon) online and stream verdicts.
    Up,
    /// Inject a single message into a running ingress listener.
    Send(SendArgs),
    /// Run a built-in scenario (or all of them) with assertions.
    Scenario(ScenarioArgs),
}

#[derive(Args)]
struct SendArgs {
    /// Ingress listener to submit to, `host:port`.
    #[arg(long)]
    ingress: String,
    /// `From` header address.
    #[arg(long, default_value = harness::AUTHOR_FROM)]
    from: String,
    /// Recipient (list posting address).
    #[arg(long, default_value = harness::POSTING_ADDRESS)]
    to: String,
    /// Envelope MAIL FROM (defaults to `--from`).
    #[arg(long)]
    mail_from: Option<String>,
    /// Subject header.
    #[arg(long, default_value = "Test post")]
    subject: String,
    /// Body text.
    #[arg(long, default_value = "Hello from carriers-testkit.\n")]
    body: String,
    /// Replay an existing `.eml` verbatim instead of crafting a message.
    #[arg(long)]
    eml: Option<PathBuf>,
    /// DKIM-sign the crafted message as the author (requires the author key flags).
    #[arg(long)]
    sign: bool,
    /// Author DKIM private key (raw DER), as printed by `up`.
    #[arg(long)]
    author_key: Option<PathBuf>,
    /// Author DKIM selector.
    #[arg(long, default_value = harness::AUTHOR_SELECTOR)]
    author_selector: String,
    /// Author DKIM domain.
    #[arg(long, default_value = harness::AUTHOR_DOMAIN)]
    author_domain: String,
}

#[derive(Args)]
struct ScenarioArgs {
    /// Scenario name; omit with --all.
    name: Option<String>,
    /// Run every built-in scenario.
    #[arg(long)]
    all: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "carriers_testkit=info,carriers=warn,carriers_core=warn".into()
            }),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Up => up().await,
        Command::Send(args) => send(args).await,
        Command::Scenario(args) => run_scenarios(args).await,
    }
}

async fn up() -> Result<()> {
    let h = Harness::start(HarnessOpts {
        print_verdicts: true,
        ..Default::default()
    })
    .await?;

    println!("carriers-testkit is up.");
    println!("  ingress (SMTP):   {}", h.ingress());
    println!("  mock DNS:         127.0.0.1:{}", h.dns.port());
    println!("  sink capture dir: {}", h.capture_dir.display());
    println!("  list:             {}", harness::POSTING_ADDRESS);
    println!("  subscriber:       {}", harness::SUBSCRIBER);
    println!();
    println!("Send a signed post (author DKIM valid) in another shell:");
    println!(
        "  cargo run -p carriers-testkit -- send --ingress {ingress} \\\n    \
         --from {from} --to {to} --sign --author-key {key} \\\n    \
         --author-selector {sel} --author-domain {dom}",
        ingress = h.ingress(),
        from = harness::AUTHOR_FROM,
        to = harness::POSTING_ADDRESS,
        key = h.author.key_file.display(),
        sel = harness::AUTHOR_SELECTOR,
        dom = harness::AUTHOR_DOMAIN,
    );
    println!("Or replay an existing message:");
    println!(
        "  cargo run -p carriers-testkit -- send --ingress {ingress} --eml some-message.eml",
        ingress = h.ingress(),
    );
    println!("\nDelivered copies are scored live below. Press Ctrl-C to stop.\n");

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    println!("\nshutting down.");
    Ok(())
}

async fn send(args: SendArgs) -> Result<()> {
    let (host, port) = split_hostport(&args.ingress)?;
    let mail_from = args.mail_from.clone().unwrap_or_else(|| args.from.clone());

    let raw = if let Some(eml) = &args.eml {
        sender::load_eml(eml)?
    } else {
        let draft = Draft {
            from: args.from.clone(),
            to: args.to.clone(),
            subject: args.subject.clone(),
            body: args.body.clone(),
            extra_headers: Vec::new(),
        };
        let base = sender::build(&draft);
        if args.sign {
            let key_file = args
                .author_key
                .clone()
                .context("--sign requires --author-key")?;
            sender::sign_as_author(
                &base,
                &AuthorKey {
                    key_file,
                    selector: args.author_selector.clone(),
                    domain: args.author_domain.clone(),
                    algorithm: Algorithm::Ed25519,
                },
            )?
        } else {
            base
        }
    };

    sender::inject(&host, port, &mail_from, &args.to, &raw).await?;
    println!(
        "submitted {} bytes to {} for {}",
        raw.len(),
        args.ingress,
        args.to
    );
    Ok(())
}

async fn run_scenarios(args: ScenarioArgs) -> Result<()> {
    let names: Vec<String> = if args.all {
        scenario::ALL.iter().map(|s| s.to_string()).collect()
    } else if let Some(name) = args.name {
        vec![name]
    } else {
        bail!(
            "give a scenario name or --all (known: {})",
            scenario::ALL.join(", ")
        );
    };

    let mut failures = 0;
    for name in &names {
        if !scenario::run(name).await? {
            failures += 1;
        }
    }

    println!(
        "\n{} scenario(s) run, {} passed, {} failed.",
        names.len(),
        names.len() - failures,
        failures
    );
    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn split_hostport(s: &str) -> Result<(String, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .with_context(|| format!("expected host:port, got `{s}`"))?;
    Ok((host.to_string(), port.parse().context("invalid port")?))
}
