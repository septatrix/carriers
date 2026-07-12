//! Bring the whole stack up in one process: mock DNS, the scoring sink, and the *real* carriers
//! daemon run in-process as a tokio task (via `AppState::load` + `carriers::smtp::serve`), all
//! pointed at the mock DNS. This is what makes end-to-end scenarios and interactive poking cheap:
//! no subprocess, no system DNS, no external smarthost.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tempfile::TempDir;
use tokio::net::TcpStream;

use carriers::state::AppState;
use carriers_core::config::Config;
use carriers_core::keygen;
use carriers_core::list::Algorithm;
use carriers_core::member::{MemberProvider, SqliteMemberProvider};
use carriers_core::store::Store;

use crate::dns::{self, MockDns};
use crate::sender::AuthorKey;
use crate::sink::{self, Sink};

/// Fixed identities the harness uses. Chosen so the interesting alignment cases show up:
/// the author (`example.com`) is a different org domain from the list (`lists.example.org`),
/// so DMARC can only pass via the author's own DKIM surviving, not via the list identity.
pub const HOSTNAME: &str = "mx.lists.example.org";
pub const LIST_NAME: &str = "dev";
pub const POSTING_ADDRESS: &str = "dev@lists.example.org";
pub const LIST_DOMAIN: &str = "lists.example.org";
pub const AUTHOR_FROM: &str = "alice@example.com";
pub const AUTHOR_DOMAIN: &str = "example.com";
pub const AUTHOR_SELECTOR: &str = "auth";
pub const SUBSCRIBER: &str = "bob@subscriber.example";

/// A third-party domain publishing a strict, enforcing DMARC policy but authorizing no sender —
/// standing in for an impersonated identity with no valid authentication of its own. Always
/// present in the zone (unconditionally on `author_dmarc_policy`), for the `dmarc-reject-spoofed`
/// scenario.
pub const SPOOFED_STRICT_DOMAIN: &str = "spoofed-strict.example";
/// A domain with no DMARC/SPF record at all (deliberately absent from the zone) — the "nothing
/// configured" case, for the `dmarc-none-no-signature` scenario.
pub const UNCONFIGURED_DOMAIN: &str = "unconfigured.example";

/// Options that vary between scenarios.
pub struct HarnessOpts {
    /// The author domain's published DMARC policy (`p=`), e.g. `reject` or `none`.
    pub author_dmarc_policy: String,
    /// Whether the sink prints a live verdict line per delivered copy.
    pub print_verdicts: bool,
}

impl Default for HarnessOpts {
    fn default() -> Self {
        Self {
            author_dmarc_policy: "reject".to_string(),
            print_verdicts: false,
        }
    }
}

/// A running harness. Keep it alive for the duration of testing — dropping it stops the DNS
/// server and sink and deletes the working directory.
pub struct Harness {
    _workdir: TempDir,
    pub ingress_host: String,
    pub ingress_port: u16,
    pub dns: MockDns,
    pub sink: Sink,
    pub author: AuthorKey,
    pub capture_dir: PathBuf,
}

impl Harness {
    pub async fn start(opts: HarnessOpts) -> Result<Self> {
        let workdir = tempfile::tempdir().context("creating harness working dir")?;
        let root = workdir.path().to_path_buf();
        let keys_dir = root.join("keys");
        let lists_dir = root.join("lists");
        let capture_dir = root.join("captured");
        std::fs::create_dir_all(&keys_dir)?;
        std::fs::create_dir_all(&lists_dir)?;

        // Generate the three keys and remember the DNS records they must be published under.
        let (author_key, author_txt) = make_key(&keys_dir, "author.der")?;
        let (list_dkim, list_dkim_txt) = make_key(&keys_dir, "list.dkim.der")?;
        let (list_arc, list_arc_txt) = make_key(&keys_dir, "list.arc.der")?;

        // Assemble the zone file: DKIM public keys, DMARC and SPF for both domains.
        let mut zone = dns::base_zone();
        zone.push_str(&zone_records(
            &author_txt,
            &list_dkim_txt,
            &list_arc_txt,
            &opts.author_dmarc_policy,
        ));
        let dns = dns::start(&zone).await.context("starting mock DNS")?;

        // The sink stands in for subscribers' servers; it scores against the mock DNS.
        let sink = sink::start(
            Arc::new(dns.authenticator()?),
            HOSTNAME.to_string(),
            capture_dir.clone(),
            opts.print_verdicts,
        )
        .await
        .context("starting sink")?;

        // Reserve an ingress port for the daemon.
        let ingress_port = reserve_port().await?;

        // Write the daemon config + list definition.
        let db_path = root.join("carriers.db");
        write_config(&root, ingress_port, sink.port(), &db_path, &lists_dir)?;
        write_list(&lists_dir, &list_dkim, &list_arc)?;

        // Seed one subscriber so distribution actually produces a delivered copy.
        seed_subscriber(&db_path).await?;

        // Load the real daemon state with a resolver aimed at the mock DNS, and serve in-process.
        let config = Config::load(&root.join("carriers.toml")).context("loading harness config")?;
        let daemon_auth = dns.authenticator()?;
        let state = Arc::new(
            AppState::load(config, daemon_auth)
                .await
                .context("loading daemon state")?,
        );
        tokio::spawn(async move {
            if let Err(err) = carriers::smtp::serve(state).await {
                tracing::error!(%err, "in-process daemon exited");
            }
        });

        let ingress_host = "127.0.0.1".to_string();
        wait_ready(&ingress_host, ingress_port).await?;

        Ok(Self {
            _workdir: workdir,
            ingress_host,
            ingress_port,
            dns,
            sink,
            author: AuthorKey {
                key_file: author_key,
                selector: AUTHOR_SELECTOR.to_string(),
                domain: AUTHOR_DOMAIN.to_string(),
                algorithm: Algorithm::Ed25519,
            },
            capture_dir,
        })
    }

    pub fn ingress(&self) -> String {
        format!("{}:{}", self.ingress_host, self.ingress_port)
    }
}

fn make_key(dir: &Path, name: &str) -> Result<(PathBuf, String)> {
    let key = keygen::generate(Algorithm::Ed25519, 0)
        .map_err(|e| anyhow::anyhow!("generating key {name}: {e}"))?;
    let path = dir.join(name);
    std::fs::write(&path, &key.private_der)
        .with_context(|| format!("writing key {}", path.display()))?;
    Ok((path, key.dns_txt))
}

/// The per-run records appended to [`dns::base_zone`]. All names are FQDNs so a single root-origin
/// authority serves them.
fn zone_records(
    author_dkim_txt: &str,
    list_dkim_txt: &str,
    list_arc_txt: &str,
    author_dmarc_policy: &str,
) -> String {
    format!(
        "{AUTHOR_SELECTOR}._domainkey.{AUTHOR_DOMAIN}. IN TXT \"{author_dkim_txt}\"\n\
         dkim._domainkey.{LIST_DOMAIN}. IN TXT \"{list_dkim_txt}\"\n\
         arc._domainkey.{LIST_DOMAIN}. IN TXT \"{list_arc_txt}\"\n\
         _dmarc.{AUTHOR_DOMAIN}. IN TXT \"v=DMARC1; p={author_dmarc_policy}; adkim=r; aspf=r\"\n\
         _dmarc.{LIST_DOMAIN}. IN TXT \"v=DMARC1; p=quarantine; adkim=r; aspf=r\"\n\
         {AUTHOR_DOMAIN}. IN TXT \"v=spf1 ip4:127.0.0.1 -all\"\n\
         {LIST_DOMAIN}. IN TXT \"v=spf1 ip4:127.0.0.1 -all\"\n\
         {AUTHOR_DOMAIN}. IN A 127.0.0.1\n\
         {LIST_DOMAIN}. IN A 127.0.0.1\n\
         _dmarc.{SPOOFED_STRICT_DOMAIN}. IN TXT \"v=DMARC1; p=reject; adkim=r; aspf=r\"\n\
         {SPOOFED_STRICT_DOMAIN}. IN TXT \"v=spf1 -all\"\n",
        // `UNCONFIGURED_DOMAIN` is deliberately absent from this zone: no DMARC or SPF record at
        // all, the "nothing configured" case.
    )
}

fn write_config(
    root: &Path,
    ingress_port: u16,
    sink_port: u16,
    db_path: &Path,
    lists_dir: &Path,
) -> Result<()> {
    let toml = format!(
        "hostname = \"{HOSTNAME}\"\n\
         listen = \"127.0.0.1:{ingress_port}\"\n\
         protocol = \"smtp\"\n\
         db_path = \"{db}\"\n\
         lists_dir = \"{lists}\"\n\
         \n\
         [smarthost]\n\
         host = \"127.0.0.1\"\n\
         port = {sink_port}\n\
         implicit_tls = false\n\
         allow_plaintext = true\n",
        db = db_path.display(),
        lists = lists_dir.display(),
    );
    std::fs::write(root.join("carriers.toml"), toml).context("writing carriers.toml")
}

fn write_list(lists_dir: &Path, dkim_key: &Path, arc_key: &Path) -> Result<()> {
    let toml = format!(
        "posting_address = \"{POSTING_ADDRESS}\"\n\
         display_name = \"Dev List\"\n\
         policy = \"open\"\n\
         \n\
         [dkim]\n\
         selector = \"dkim\"\n\
         key_file = \"{dkim}\"\n\
         algorithm = \"ed25519\"\n\
         domain = \"{LIST_DOMAIN}\"\n\
         \n\
         [arc]\n\
         selector = \"arc\"\n\
         key_file = \"{arc}\"\n\
         algorithm = \"ed25519\"\n\
         domain = \"{LIST_DOMAIN}\"\n",
        dkim = dkim_key.display(),
        arc = arc_key.display(),
    );
    std::fs::write(lists_dir.join(format!("{LIST_NAME}.toml")), toml).context("writing list toml")
}

async fn seed_subscriber(db_path: &Path) -> Result<()> {
    let store = Arc::new(
        Store::open(db_path)
            .await
            .context("opening db to seed subscriber")?,
    );
    let provider = SqliteMemberProvider::new(store);
    provider
        .add(LIST_NAME, SUBSCRIBER, true, false, false)
        .await
        .context("seeding subscriber")?;
    Ok(())
}

/// Grab a free loopback TCP port by binding to `:0` and immediately releasing it. There is a
/// small race before the daemon rebinds it, closed by [`wait_ready`].
async fn reserve_port() -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    Ok(listener.local_addr()?.port())
}

/// Wait until the ingress listener accepts connections (bounded retries, no blind sleep).
async fn wait_ready(host: &str, port: u16) -> Result<()> {
    for _ in 0..100 {
        if TcpStream::connect((host, port)).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("ingress {host}:{port} did not become ready")
}
