//! carriers — a DMARC/ARC-compliant mailing list daemon and CLI.

mod deliver;
mod smtp;
mod state;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use carriers_core::config::Config;
use carriers_core::keygen;
use carriers_core::list::{Algorithm, List};
use carriers_core::member::{MemberProvider, SqliteMemberProvider};
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
    /// Manage subscribers.
    #[command(subcommand)]
    Member(MemberCommand),
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
    /// Add a subscriber to a list.
    Add { list: String, address: String },
    /// Remove a subscriber from a list.
    Remove { list: String, address: String },
    /// List subscribers of a list.
    List { list: String },
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
        Command::Sync => sync(&cli.config),
        Command::Member(cmd) => member(&cli.config, cmd),
    }
}

async fn run(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    let state = Arc::new(AppState::load(config)?);
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

fn open_store(config: &Config) -> Result<Arc<Store>> {
    Ok(Arc::new(Store::open(&config.db_path).with_context(
        || format!("opening database {}", config.db_path.display()),
    )?))
}

fn sync(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let store = open_store(&config)?;
    let provider = SqliteMemberProvider::new(store);
    let lists = load_lists(&config)?;
    for list in lists.values() {
        if let Some(members_file) = &list.cfg.members_file {
            let n = provider.seed_from_file(&list.name, members_file)?;
            println!(
                "{}: imported {n} members from {}",
                list.name,
                members_file.display()
            );
        }
    }
    Ok(())
}

fn member(config_path: &Path, cmd: MemberCommand) -> Result<()> {
    let config = Config::load(config_path)?;
    let store = open_store(&config)?;
    let provider = SqliteMemberProvider::new(store);
    match cmd {
        MemberCommand::Add { list, address } => {
            resolve_list_name(&config, &list)?;
            provider.add(&list, &address)?;
            println!("added {address} to {list}");
        }
        MemberCommand::Remove { list, address } => {
            provider.remove(&list, &address)?;
            println!("removed {address} from {list}");
        }
        MemberCommand::List { list } => {
            for address in provider.recipients(&list)? {
                println!("{address}");
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
