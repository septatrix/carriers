//! A mock authoritative DNS server driven by an RFC 1035 zone file.
//!
//! The zone file is the single source of truth: every record the carriers daemon and the scoring
//! sink resolve (author + list DKIM public keys, `_dmarc`, SPF, `A`) comes from it. All records
//! are loaded into one root-origin authority, so a single flat file can cover any number of
//! domains (`example.com`, `lists.example.org`, …) as long as the names are written as FQDNs.
//! The file must carry an SOA record for the root (`. IN SOA …`); [`base_zone`] provides one.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use hickory_proto::rr::{LowerName, Name};
use hickory_proto::serialize::txt::Parser;
use hickory_server::Server;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneHandler, ZoneType};
use mail_auth::MessageAuthenticator;
use mail_auth::hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts,
};
use tokio::net::{TcpListener, UdpSocket};

/// A running mock DNS server bound to a loopback port.
///
/// Keep this value alive for as long as queries should be answered: dropping it drops the
/// server's task set, which aborts the UDP/TCP listeners.
pub struct MockDns {
    port: u16,
    _server: Server<Catalog>,
}

impl MockDns {
    /// The loopback port the server is listening on (same number for UDP and TCP).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Build a resolver that queries this mock server, ready to hand to `AppState::load` (for the
    /// daemon) or to use directly for scoring delivered mail. Everything resolves against the
    /// zone file; there is no fallback to the host's real DNS.
    pub fn authenticator(&self) -> Result<MessageAuthenticator> {
        authenticator(self.port)
    }
}

/// Parse a zone file and serve it over UDP+TCP on `127.0.0.1` (ephemeral port).
pub async fn start(zone_text: &str) -> Result<MockDns> {
    let catalog = build_catalog(zone_text)?;

    // Bind UDP first to claim an ephemeral port, then bind TCP on the same number (TCP and UDP
    // port spaces are independent, so this does not clash).
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = udp.local_addr()?.port();
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;

    let mut server = Server::new(catalog);
    server.register_socket(udp);
    server.register_listener(tcp, Duration::from_secs(10), u16::MAX as usize);

    Ok(MockDns {
        port,
        _server: server,
    })
}

/// Parse `zone_text` (RFC 1035 master format) into a root-origin authority wrapped in a Catalog.
fn build_catalog(zone_text: &str) -> Result<Catalog> {
    let (_origin, records) = Parser::new(zone_text.to_string(), None, Some(Name::root()))
        .parse()
        .map_err(|e| anyhow!("parsing mock zone file: {e}"))?;

    let authority = InMemoryZoneHandler::<hickory_server::net::runtime::TokioRuntimeProvider>::new(
        Name::root(),
        records,
        ZoneType::Primary,
        AxfrPolicy::Deny,
    )
    .map_err(|e| anyhow!("building mock zone authority: {e}"))?;

    let mut catalog = Catalog::new();
    catalog.upsert(
        LowerName::from(Name::root()),
        vec![Arc::new(authority) as Arc<dyn ZoneHandler>],
    );
    Ok(catalog)
}

/// Build a [`MessageAuthenticator`] whose resolver targets the mock server on `127.0.0.1:port`.
pub fn authenticator(port: u16) -> Result<MessageAuthenticator> {
    let mut udp = ConnectionConfig::udp();
    udp.port = port;
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = port;

    let name_server = NameServerConfig::new(IpAddr::V4(Ipv4Addr::LOCALHOST), true, vec![udp, tcp]);
    let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);

    MessageAuthenticator::new(config, ResolverOpts::default())
        .map_err(|e| anyhow!("building mock DNS resolver: {e}"))
}

/// A minimal base zone: an SOA and NS for the root so the authority is valid. The harness appends
/// the per-run DKIM/ARC/`_dmarc`/SPF/`A` records to this before serving. `ns.mock.test` is never
/// resolved (the resolver talks to us directly), it only satisfies the zone's structural needs.
pub fn base_zone() -> String {
    "$TTL 60\n\
     . IN SOA ns.mock.test. hostmaster.mock.test. 1 3600 600 86400 60\n\
     . IN NS ns.mock.test.\n"
        .to_string()
}
