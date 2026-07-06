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
    /// Write the private key here instead of stdout.
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
    /// Add a member to a list (a subscriber by default).
    Add {
        list: String,
        address: String,
        /// Add as a posting-only member (may post but does not receive the list).
        #[arg(long)]
        posting_only: bool,
    },
    /// Remove a member from a list.
    Remove { list: String, address: String },
    /// List members of a list and their roles.
    List { list: String },
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
            std::fs::write(path, &key.private_pem)
                .with_context(|| format!("writing private key to {}", path.display()))?;
            eprintln!("Private key written to {}", path.display());
        }
        None => print!("{}", key.private_pem),
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
            let n = provider.seed_from_file(&list.name, members_file).await?;
            println!(
                "{}: imported {n} members from {}",
                list.name,
                members_file.display()
            );
        }
    }
    Ok(())
}

async fn member(config_path: &Path, cmd: MemberCommand) -> Result<()> {
    let config = Config::load(config_path)?;
    let store = open_store(&config).await?;
    let provider = SqliteMemberProvider::new(store);
    match cmd {
        MemberCommand::Add {
            list,
            address,
            posting_only,
        } => {
            resolve_list_name(&config, &list)?;
            provider.add(&list, &address, !posting_only).await?;
            let role = if posting_only { "poster" } else { "subscriber" };
            println!("added {address} to {list} ({role})");
        }
        MemberCommand::Remove { list, address } => {
            provider.remove(&list, &address).await?;
            println!("removed {address} from {list}");
        }
        MemberCommand::List { list } => {
            for member in provider.members(&list).await? {
                let role = if member.subscribed {
                    "subscriber"
                } else {
                    "poster"
                };
                println!("{}\t{role}", member.address);
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

/// Ensure a list with `name` exists, so we don't silently add members to a typo'd list.
fn resolve_list_name(config: &Config, name: &str) -> Result<()> {
    let path = config.lists_dir.join(format!("{name}.toml"));
    if !path.is_file() {
        anyhow::bail!("no such list `{name}` (expected {})", path.display());
    }
    List::load(name, &path)?;
    Ok(())
}
