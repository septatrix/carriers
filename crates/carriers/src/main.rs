//! carriers — a DMARC/ARC-compliant mailing list daemon and CLI.

mod deliver;
mod smtp;
mod state;

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use carriers_core::config::Config;
use carriers_core::keygen;
use carriers_core::list::{Algorithm, List};
use carriers_core::member::{MemberProvider, SqliteMemberProvider};
use carriers_core::policy::PolicyEngine;
use carriers_core::sign::Ingress;
use carriers_core::store::Store;

use crate::state::{load_lists, AppState};

#[derive(Parser)]
#[command(
    name = "carriers",
    version,
    about = "A DMARC/ARC-compliant mailing list"
)]
struct Cli {
    /// Path to the global configuration file.
    #[arg(
        short,
        long,
        default_value = "/etc/carriers/carriers.toml",
        global = true
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the ingress listener and distribute incoming posts.
    Run,
    /// Generate a DKIM/ARC key pair and print the DNS record to publish.
    Genkey(GenkeyArgs),
    /// Import the flat member seed file(s) into the database.
    Sync,
    /// Manage subscribers and members.
    #[command(subcommand)]
    Member(MemberCommand),
    /// Review and act on messages held for moderation.
    #[command(subcommand)]
    Moderate(ModerateCommand),
    /// List the loaded Sieve moderation policies.
    Policies,
}

#[derive(Args)]
struct GenkeyArgs {
    /// Key algorithm.
    #[arg(long, value_enum, default_value_t = KeyAlg::Rsa)]
    algorithm: KeyAlg,
    /// RSA key size in bits (ignored for ed25519).
    #[arg(long, default_value_t = 2048)]
    bits: usize,
    /// DNS selector the record will be published under (for the printed record name).
    #[arg(long, default_value = "carriers")]
    selector: String,
    /// Signing domain (for the printed record name).
    #[arg(long, default_value = "example.org")]
    domain: String,
    /// Write the raw DER-encoded private key here instead of stdout (recommended: printing
    /// binary DER to a terminal is not useful; redirect stdout to a file if `--out` is omitted).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum KeyAlg {
    Rsa,
    Ed25519,
}

impl From<KeyAlg> for Algorithm {
    fn from(a: KeyAlg) -> Self {
        match a {
            KeyAlg::Rsa => Algorithm::Rsa,
            KeyAlg::Ed25519 => Algorithm::Ed25519,
        }
    }
}

#[derive(Subcommand)]
enum MemberCommand {
    /// Add a member to a list (a subscriber by default). Roles are independent: a poster is
    /// not automatically subscribed, and a subscriber is not automatically a poster.
    Add {
        list: String,
        address: String,
        /// Do not subscribe this address (it will not receive the list). Combine with
        /// --poster for a posting-only address.
        #[arg(long)]
        no_subscribe: bool,
        /// Grant posting rights independent of subscription (exposed to Sieve policies as the
        /// `posters` list, and used by the `posters` built-in policy).
        #[arg(long)]
        poster: bool,
        /// Grant the moderator role (exposed to Sieve policies as the `moderators` list).
        #[arg(long)]
        moderator: bool,
    },
    /// Remove a member from a list.
    Remove { list: String, address: String },
    /// List members of a list and their roles.
    List { list: String },
    /// Clear a member's bounce state and re-enable delivery.
    Enable { list: String, address: String },
}

#[derive(Subcommand)]
enum ModerateCommand {
    /// List messages held for moderation (optionally for a single list).
    List { list: Option<String> },
    /// Print the raw held message to stdout.
    Show { id: i64 },
    /// Approve a held message and distribute it.
    Approve { id: i64 },
    /// Reject (discard) a held message.
    Reject { id: i64 },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "carriers=info,carriers_core=info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run => run(&cli.config).await,
        Command::Genkey(args) => genkey(args),
        Command::Sync => sync(&cli.config).await,
        Command::Member(cmd) => member(&cli.config, cmd).await,
        Command::Moderate(cmd) => moderate(&cli.config, cmd).await,
        Command::Policies => policies(&cli.config),
    }
}

async fn run(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    let state = Arc::new(AppState::load(config).await?);
    smtp::serve(state).await
}

fn genkey(args: GenkeyArgs) -> Result<()> {
    let key = keygen::generate(args.algorithm.into(), args.bits)?;
    match &args.out {
        Some(path) => {
            std::fs::write(path, &key.private_der)
                .with_context(|| format!("writing private key to {}", path.display()))?;
            eprintln!("Private key written to {}", path.display());
        }
        None => std::io::stdout().write_all(&key.private_der)?,
    }
    eprintln!();
    eprintln!("Publish this DNS TXT record:");
    eprintln!();
    eprintln!("  {}._domainkey.{}. IN TXT (", args.selector, args.domain);
    for chunk in split_txt(&key.dns_txt) {
        eprintln!("    \"{chunk}\"");
    }
    eprintln!("  )");
    Ok(())
}

/// DNS TXT strings are limited to 255 octets; split long records into quoted chunks.
fn split_txt(value: &str) -> Vec<String> {
    value
        .as_bytes()
        .chunks(255)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

async fn open_store(config: &Config) -> Result<Arc<Store>> {
    Ok(Arc::new(Store::open(&config.db_path).await.with_context(
        || format!("opening database {}", config.db_path.display()),
    )?))
}

async fn sync(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let store = open_store(&config).await?;
    let provider = SqliteMemberProvider::new(store);
    let lists = load_lists(&config)?;
    for list in lists.values() {
        if let Some(members_file) = &list.cfg.members_file {
            let n = seed_subscribers_from_file(&provider, &list.name, members_file).await?;
            println!(
                "{}: imported {n} members from {}",
                list.name,
                members_file.display()
            );
        }
    }
    Ok(())
}

/// Import subscriber addresses from a flat file (one per line, `#` comments and blanks
/// ignored). Returns the number of addresses imported.
async fn seed_subscribers_from_file(
    provider: &SqliteMemberProvider,
    list: &str,
    path: &Path,
) -> Result<usize> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading members file {}", path.display()))?;
    let mut n = 0;
    for line in text.lines() {
        let addr = line.trim();
        if addr.is_empty() || addr.starts_with('#') {
            continue;
        }
        provider.add(list, addr, true, false, false).await?;
        n += 1;
    }
    Ok(n)
}

async fn member(config_path: &Path, cmd: MemberCommand) -> Result<()> {
    let config = Config::load(config_path)?;
    let store = open_store(&config).await?;
    let provider = SqliteMemberProvider::new(store.clone());
    match cmd {
        MemberCommand::Add {
            list,
            address,
            no_subscribe,
            poster,
            moderator,
        } => {
            resolve_list_name(&config, &list)?;
            provider
                .add(&list, &address, !no_subscribe, poster, moderator)
                .await?;
            let mut roles = Vec::new();
            if !no_subscribe {
                roles.push("subscriber");
            }
            if poster {
                roles.push("poster");
            }
            if moderator {
                roles.push("moderator");
            }
            if roles.is_empty() {
                roles.push("no roles");
            }
            println!("added {address} to {list} ({})", roles.join(", "));
        }
        MemberCommand::Remove { list, address } => {
            provider.remove(&list, &address).await?;
            println!("removed {address} from {list}");
        }
        MemberCommand::List { list } => {
            for member in provider.members(&list).await? {
                let mut roles = Vec::new();
                if member.subscribed {
                    roles.push("subscriber");
                }
                if member.poster {
                    roles.push("poster");
                }
                if member.moderator {
                    roles.push("moderator");
                }
                if roles.is_empty() {
                    roles.push("no roles");
                }
                let role = roles.join(", ");
                let status = if member.bounce_disabled {
                    format!(" [bounce-disabled score={:.1}]", member.bounce_score)
                } else if member.bounce_score > 0.0 {
                    format!(" [bounces score={:.1}]", member.bounce_score)
                } else {
                    String::new()
                };
                println!("{}\t{role}{status}", member.address);
            }
        }
        MemberCommand::Enable { list, address } => {
            if store.enable_member(&list, &address).await? {
                println!("re-enabled {address} on {list}");
            } else {
                bail!("no member {address} on {list}");
            }
        }
    }
    Ok(())
}

async fn moderate(config_path: &Path, cmd: ModerateCommand) -> Result<()> {
    let config = Config::load(config_path)?;
    match cmd {
        ModerateCommand::List { list } => {
            let store = open_store(&config).await?;
            for held in store.held_messages(list.as_deref()).await? {
                println!(
                    "{}\t{}\t{}\t{}",
                    held.id,
                    held.list,
                    held.sender.as_deref().unwrap_or("-"),
                    held.subject.as_deref().unwrap_or("(no subject)"),
                );
            }
        }
        ModerateCommand::Show { id } => {
            let store = open_store(&config).await?;
            let held = store
                .get_held(id)
                .await?
                .with_context(|| format!("no held message with id {id}"))?;
            std::io::stdout().write_all(&held.raw)?;
        }
        ModerateCommand::Approve { id } => {
            let state = Arc::new(AppState::load(config).await?);
            let held = state
                .store
                .get_held(id)
                .await?
                .with_context(|| format!("no held message with id {id}"))?;
            let list = state
                .list_by_name(&held.list)
                .with_context(|| {
                    format!("list `{}` for held message {id} is not loaded", held.list)
                })?
                .clone();
            let ingress = Ingress {
                remote_ip: held
                    .remote_ip
                    .parse()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                helo: held.helo,
                mail_from: held.mail_from,
            };
            let count = smtp::distribute_approved(&state, &list, &ingress, &held.raw).await?;
            state.store.delete_held(id).await?;
            println!("approved {id}: distributed to {count} recipient(s)");
        }
        ModerateCommand::Reject { id } => {
            let store = open_store(&config).await?;
            if store.delete_held(id).await? {
                println!("rejected {id}");
            } else {
                bail!("no held message with id {id}");
            }
        }
    }
    Ok(())
}

fn policies(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let engine = match &config.policies_dir {
        Some(dir) => PolicyEngine::load(dir)
            .with_context(|| format!("loading Sieve policies from {}", dir.display()))?,
        None => PolicyEngine::new().context("compiling built-in policies")?,
    };

    println!(
        "built-in: {}, {}, {}, {}",
        carriers_core::policy::BUILTIN_OPEN,
        carriers_core::policy::BUILTIN_SUBSCRIBERS,
        carriers_core::policy::BUILTIN_POSTERS,
        carriers_core::policy::BUILTIN_MODERATED,
    );
    let mut names: Vec<&str> = engine.names().collect();
    names.sort_unstable();
    if names.is_empty() {
        println!("custom:   (none)");
    } else {
        println!("custom:   {}", names.join(", "));
    }
    Ok(())
}

/// Ensure a list with `name` exists, so we don't silently add members to a typo'd list.
fn resolve_list_name(config: &Config, name: &str) -> Result<()> {
    let path = config.lists_dir.join(format!("{name}.toml"));
    if !path.is_file() {
        anyhow::bail!("no such list `{name}` (expected {})", path.display());
    }
    List::load(name, &path)?;
    Ok(())
}
