//! carriers — a DMARC/ARC-compliant mailing list daemon and CLI.
//!
//! The daemon runtime (ingress listener, delivery, shared state) lives in the sibling library
//! crate `carriers`; this binary is the CLI wrapper around it.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use carriers::smtp;
use carriers::state::{AppState, load_lists, load_policy_engine};
use carriers_core::MessageAuthenticator;
use carriers_core::config::Config;
use carriers_core::keygen;
use carriers_core::list::{Algorithm, List};
use carriers_core::member::{MemberProvider, SqliteMemberProvider};
use carriers_core::sign::Ingress;
use carriers_core::store::Store;

/// Build the DNS resolver the daemon uses for inbound authentication, from the host's system
/// configuration (`/etc/resolv.conf`).
fn system_authenticator() -> Result<MessageAuthenticator> {
    MessageAuthenticator::new_system_conf()
        .context("initialising DNS resolver from system configuration")
}

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
    /// Generate DKIM/ARC/DKIM2 keys and one DNS zone file covering everything a list domain
    /// needs to publish (DKIM, DKIM2, SPF, ARC, DMARC, plus a PTR reminder).
    Setup(SetupArgs),
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
struct SetupArgs {
    /// The list domain, e.g. `lists.example.org`.
    domain: String,
    /// Key algorithm, applied to all generated keys.
    #[arg(long, value_enum, default_value_t = KeyAlg::Rsa)]
    algorithm: KeyAlg,
    /// RSA key size in bits (ignored for ed25519).
    #[arg(long, default_value_t = 2048)]
    bits: usize,
    /// DKIM selector.
    #[arg(long, default_value = "dkim")]
    selector_dkim: String,
    /// ARC selector.
    #[arg(long, default_value = "arc")]
    selector_arc: String,
    /// DKIM2 selector (draft-ietf-dkim-dkim2-spec). Every list needs one, like DKIM/ARC — whether
    /// it's ever used to sign depends on the inbound message, not on config.
    #[arg(long, default_value = "dkim2")]
    selector_dkim2: String,
    /// Smarthost IP address to authorize in the SPF record (repeatable for multiple
    /// smarthosts/IPv4+IPv6). Omit to leave a placeholder in the zone file instead.
    #[arg(long = "spf-ip")]
    spf_ip: Vec<String>,
    /// DMARC policy (`none`, `quarantine`, or `reject`).
    #[arg(long, default_value = "quarantine")]
    dmarc_policy: String,
    /// DMARC aggregate-report address, e.g. `dmarc@lists.example.org`.
    #[arg(long)]
    dmarc_rua: Option<String>,
    /// Directory to write the keys and zone file into.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,
    /// Overwrite output files if they already exist.
    #[arg(long)]
    force: bool,
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
        Command::Setup(args) => setup(args),
        Command::Sync => sync(&cli.config).await,
        Command::Member(cmd) => member(&cli.config, cmd).await,
        Command::Moderate(cmd) => moderate(&cli.config, cmd).await,
        Command::Policies => policies(&cli.config),
    }
}

async fn run(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    let state = Arc::new(AppState::load(config, system_authenticator()?).await?);
    smtp::serve(state).await
}

/// One generated key, remembered alongside the file it was written to and the label used in the
/// zone file's comments.
struct SetupKey {
    label: &'static str,
    selector: String,
    path: PathBuf,
    dns_txt: String,
}

fn setup(args: SetupArgs) -> Result<()> {
    if !["none", "quarantine", "reject"].contains(&args.dmarc_policy.as_str()) {
        bail!(
            "--dmarc-policy must be one of `none`, `quarantine`, `reject` (got `{}`)",
            args.dmarc_policy
        );
    }

    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("creating output directory {}", args.out_dir.display()))?;
    let zone_path = args.out_dir.join(format!("{}.zone", args.domain));

    let selectors: Vec<(&'static str, &str)> = vec![
        ("DKIM", &args.selector_dkim),
        ("ARC", &args.selector_arc),
        ("DKIM2", &args.selector_dkim2),
    ];
    let key_paths: Vec<PathBuf> = selectors
        .iter()
        .map(|(_, selector)| args.out_dir.join(format!("{selector}.der")))
        .collect();

    if !args.force {
        for path in key_paths.iter().chain([&zone_path]) {
            if path.exists() {
                bail!(
                    "{} already exists (pass --force to overwrite)",
                    path.display()
                );
            }
        }
    }

    let mut keys = Vec::with_capacity(selectors.len());
    for ((label, selector), path) in selectors.into_iter().zip(key_paths) {
        let generated = keygen::generate(args.algorithm.into(), args.bits)?;
        std::fs::write(&path, &generated.private_der)
            .with_context(|| format!("writing {label} private key to {}", path.display()))?;
        keys.push(SetupKey {
            label,
            selector: selector.to_string(),
            path,
            dns_txt: generated.dns_txt,
        });
    }

    let zone = setup_zone(&args, &keys);
    std::fs::write(&zone_path, zone)
        .with_context(|| format!("writing zone file to {}", zone_path.display()))?;

    println!("Generated keys for {}:", args.domain);
    for key in &keys {
        println!("  {:<6} {}", key.label, key.path.display());
    }
    println!("DNS zone file written to {}", zone_path.display());
    println!();
    println!(
        "Publish it: append {} to your zone (or a $INCLUDE), or paste its records into your DNS",
        zone_path.display()
    );
    println!("provider's UI. It also has a reminder about the PTR record your host controls.");
    println!();
    println!("List config ([dkim]/[arc]/[dkim2]):");
    for key in &keys {
        println!(
            "[{}]\nselector = \"{}\"\nkey_file = \"{}\"\nalgorithm = \"{}\"\n",
            key.label.to_lowercase(),
            key.selector,
            key.path.display(),
            match args.algorithm {
                KeyAlg::Rsa => "rsa",
                KeyAlg::Ed25519 => "ed25519",
            },
        );
    }
    Ok(())
}

/// The full DNS zone-file content for a list domain: DKIM/ARC/DKIM2 public keys, SPF, DMARC, and
/// an advisory PTR reminder. Not a complete zone (no SOA/NS) — records only, meant to be appended
/// to an existing zone or pasted into a DNS provider's UI.
fn setup_zone(args: &SetupArgs, keys: &[SetupKey]) -> String {
    let mut out = format!(
        "; DNS records for {domain}, generated by `carriers setup`.\n\
         ; Publish these via $INCLUDE, or paste them into your DNS provider's UI.\n\n",
        domain = args.domain
    );

    for key in keys {
        out.push_str(&format!("; {} public key\n", key.label));
        out.push_str(&txt_record(
            &format!("{}._domainkey.{}", key.selector, args.domain),
            &key.dns_txt,
        ));
        out.push('\n');
    }

    out.push_str("; SPF - authorize the IP address(es) your smarthost sends from\n");
    if args.spf_ip.is_empty() {
        out.push_str(&format!(
            "; no --spf-ip given; fill in your smarthost's address(es), e.g.:\n\
             ; {domain}. IN TXT \"v=spf1 ip4:203.0.113.1 -all\"\n\n",
            domain = args.domain
        ));
    } else {
        let mechanisms: Vec<String> = args
            .spf_ip
            .iter()
            .map(|ip| {
                let kind = if ip.contains(':') { "ip6" } else { "ip4" };
                format!("{kind}:{ip}")
            })
            .collect();
        out.push_str(&txt_record(
            &args.domain,
            &format!("v=spf1 {} -all", mechanisms.join(" ")),
        ));
        out.push('\n');
    }

    out.push_str("; DMARC\n");
    let rua_tag = args
        .dmarc_rua
        .as_ref()
        .map(|rua| format!("; rua=mailto:{rua}"))
        .unwrap_or_default();
    out.push_str(&txt_record(
        &format!("_dmarc.{}", args.domain),
        &format!("v=DMARC1; p={}{rua_tag}", args.dmarc_policy),
    ));
    out.push('\n');

    out.push_str(
        "; PTR - reverse DNS for your smarthost's IP address(es). This cannot be published\n\
         ; from this zone: a PTR record lives in the IP's own reverse-DNS zone\n\
         ; (in-addr.arpa/ip6.arpa), controlled by whoever assigns you that IP address (your\n\
         ; hosting provider or ISP), not by this domain's zone. Ask them to point it at your\n\
         ; smarthost's HELO/EHLO name, which most receivers expect to match.\n",
    );

    out
}

/// One DNS zone-file-syntax TXT record, `<name>. IN TXT ( "chunk" "chunk" )`, chunked to the
/// 255-octet limit for a single TXT string.
fn txt_record(name: &str, value: &str) -> String {
    let mut out = format!("{name}. IN TXT (\n");
    for chunk in split_txt(value) {
        out.push_str(&format!("    \"{chunk}\"\n"));
    }
    out.push_str(")\n");
    out
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
            let state = Arc::new(AppState::load(config, system_authenticator()?).await?);
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
            let outcome = smtp::distribute_approved(&state, &list, &ingress, &held.raw).await?;
            // The held entry is consumed either way — it was distributed, dropped, or re-queued
            // as a new entry by the "after" policy tier.
            state.store.delete_held(id).await?;
            match outcome {
                smtp::Outcome::Distributed(count) => {
                    println!("approved {id}: distributed to {count} recipient(s)")
                }
                smtp::Outcome::Held(new_id) => {
                    println!("approved {id}: re-held for moderation by after-policy as {new_id}")
                }
                smtp::Outcome::Discarded(reason) => {
                    println!("approved {id}: discarded by after-policy ({reason})")
                }
                smtp::Outcome::Rejected(reason) => {
                    println!("approved {id}: rejected by after-policy ({reason})")
                }
            }
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
    let engine = load_policy_engine(&config)?;

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

    let (before, after) = (engine.global_before_count(), engine.global_after_count());
    if before == 0 && after == 0 {
        println!("global:   (none)");
    } else {
        println!("global:   before={before} script(s), after={after} script(s)");
    }

    let mut domains: Vec<&str> = engine.domains().collect();
    domains.sort_unstable();
    if domains.is_empty() {
        println!("domains:  (none)");
    } else {
        println!("domains:  {}", domains.join(", "));
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
