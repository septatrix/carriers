//! A capturing, scoring SMTP sink standing in for the subscribers' mail servers.
//!
//! carriers' outbound `deliver` relays each subscriber copy here (point `[smarthost]` at this
//! port). For every message the sink records the VERP envelope, writes the raw bytes to
//! `captured/<n>.eml`, and scores it exactly the way a receiving MTA would: DKIM, ARC, SPF and
//! DMARC via `mail-auth`, resolving against the mock DNS. The [`Verdict`] is what a subscriber's
//! server would conclude — the whole point of the harness.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use mail_auth::dkim2::Envelope;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{
    AuthenticatedMessage, Dkim2Result, DkimResult, DmarcResult, MessageAuthenticator, SpfResult,
    dmarc::verify::DmarcParameters,
};
use smtp_proto::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::warn;

/// The authentication verdict a receiving server would reach for one delivered copy.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub mail_from: String,
    pub rcpt: Vec<String>,
    pub from_domain: String,
    /// Signing domains (`d=`) of every DKIM signature that verified.
    pub dkim_pass_domains: Vec<String>,
    /// The ARC chain validated (`cv=pass`).
    pub arc_pass: bool,
    /// The DKIM2 chain (draft-ietf-dkim-dkim2-spec) validated against the exact delivery
    /// envelope (`mail_from`/`rcpt`) — `false` when the message carries no DKIM2 signature.
    pub dkim2_pass: bool,
    pub spf: SpfResult,
    /// DMARC passed overall (via an aligned, passing DKIM or SPF identity).
    pub dmarc_pass: bool,
    /// DMARC's DKIM-alignment leg passed (an aligned DKIM signature verified).
    pub dmarc_via_dkim: bool,
    /// DMARC's SPF-alignment leg passed.
    pub dmarc_via_spf: bool,
}

impl Verdict {
    /// Did an aligned DKIM signature for the author's `From` domain survive?
    pub fn author_dkim_pass(&self) -> bool {
        self.dkim_pass_domains
            .iter()
            .any(|d| aligned(d, &self.from_domain))
    }

    /// Did a DKIM signature for `domain` (e.g. the list domain) verify?
    pub fn dkim_pass_for(&self, domain: &str) -> bool {
        self.dkim_pass_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
    }

    /// A compact one-line rendering for interactive output and logs.
    pub fn summary(&self) -> String {
        let dkim = if self.dkim_pass_domains.is_empty() {
            "none".to_string()
        } else {
            self.dkim_pass_domains.join("+")
        };
        format!(
            "dmarc={} (dkim-align={}, spf-align={}) | dkim-pass=[{}] | arc={} | dkim2={} | spf={:?} | from={} envelope={} rcpt={}",
            pass(self.dmarc_pass),
            pass(self.dmarc_via_dkim),
            pass(self.dmarc_via_spf),
            dkim,
            pass(self.arc_pass),
            pass(self.dkim2_pass),
            self.spf,
            self.from_domain,
            self.mail_from,
            self.rcpt.join(","),
        )
    }
}

fn pass(b: bool) -> &'static str {
    if b { "pass" } else { "fail" }
}

/// Relaxed organizational-domain alignment: identical, or one is a subdomain of the other.
fn aligned(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

/// A running sink. Holds the scored verdicts; keep it alive while messages are expected.
pub struct Sink {
    port: u16,
    verdicts: Arc<Mutex<Vec<Verdict>>>,
}

impl Sink {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// All verdicts scored so far, in arrival order.
    pub async fn verdicts(&self) -> Vec<Verdict> {
        self.verdicts.lock().await.clone()
    }
}

/// Bind the sink on `127.0.0.1:0` and start accepting mail. Delivered copies are scored with
/// `authenticator` (aim it at the mock DNS), written under `capture_dir`, and — when `print` —
/// echoed live as one verdict line each.
pub async fn start(
    authenticator: Arc<MessageAuthenticator>,
    hostname: String,
    capture_dir: PathBuf,
    print: bool,
) -> Result<Sink> {
    tokio::fs::create_dir_all(&capture_dir).await?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let verdicts = Arc::new(Mutex::new(Vec::new()));

    let shared = SinkState {
        authenticator,
        hostname,
        capture_dir,
        print,
        verdicts: verdicts.clone(),
        counter: Arc::new(AtomicUsize::new(0)),
    };

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle(shared, stream, peer.ip()).await {
                            warn!(%peer, %err, "sink connection error");
                        }
                    });
                }
                Err(err) => {
                    warn!(%err, "sink accept error");
                    break;
                }
            }
        }
    });

    Ok(Sink { port, verdicts })
}

#[derive(Clone)]
struct SinkState {
    authenticator: Arc<MessageAuthenticator>,
    hostname: String,
    capture_dir: PathBuf,
    print: bool,
    verdicts: Arc<Mutex<Vec<Verdict>>>,
    counter: Arc<AtomicUsize>,
}

async fn handle(state: SinkState, stream: TcpStream, remote_ip: IpAddr) -> Result<()> {
    let (read_half, mut write) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write
        .write_all(format!("220 {} sink ready\r\n", state.hostname).as_bytes())
        .await?;

    let mut helo = String::new();
    let mut mail_from: Option<String> = None;
    let mut recipients: Vec<String> = Vec::new();
    let mut line: Vec<u8> = Vec::new();

    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            break;
        }
        match Request::parse(&mut line.iter()) {
            Ok(Request::Ehlo { host }) | Ok(Request::Lhlo { host }) => {
                helo = host.into_owned();
                mail_from = None;
                recipients.clear();
                write
                    .write_all(
                        format!("250-{} greets you\r\n250 PIPELINING\r\n", state.hostname)
                            .as_bytes(),
                    )
                    .await?;
            }
            Ok(Request::Helo { host }) => {
                helo = host.into_owned();
                write
                    .write_all(format!("250 {}\r\n", state.hostname).as_bytes())
                    .await?;
            }
            Ok(Request::Mail { from }) => {
                mail_from = Some(from.address.into_owned());
                recipients.clear();
                write.write_all(b"250 2.1.0 OK\r\n").await?;
            }
            Ok(Request::Rcpt { to }) => {
                recipients.push(to.address.into_owned());
                write.write_all(b"250 2.1.5 OK\r\n").await?;
            }
            Ok(Request::Data) => {
                if mail_from.is_none() || recipients.is_empty() {
                    write.write_all(b"503 5.5.1 Need MAIL and RCPT\r\n").await?;
                    continue;
                }
                write
                    .write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                    .await?;
                let raw = read_data(&mut reader).await?;
                let envelope_from = mail_from.clone().unwrap_or_default();

                let verdict = score(&state, remote_ip, &helo, &envelope_from, &recipients, &raw)
                    .await
                    .unwrap_or_else(|err| unparseable_verdict(&envelope_from, &recipients, err));

                let n = state.counter.fetch_add(1, Ordering::SeqCst);
                let path = state.capture_dir.join(format!("{n:03}.eml"));
                if let Err(err) = tokio::fs::write(&path, &raw).await {
                    warn!(?path, %err, "failed to write captured message");
                }
                if state.print {
                    println!(
                        "[sink] captured {} -> {}",
                        path.display(),
                        verdict.summary()
                    );
                }
                state.verdicts.lock().await.push(verdict);

                write.write_all(b"250 2.6.0 Message accepted\r\n").await?;
                mail_from = None;
                recipients.clear();
            }
            Ok(Request::Rset) => {
                mail_from = None;
                recipients.clear();
                write.write_all(b"250 2.0.0 OK\r\n").await?;
            }
            Ok(Request::Noop { .. }) => write.write_all(b"250 2.0.0 OK\r\n").await?,
            Ok(Request::Quit) => {
                write.write_all(b"221 2.0.0 Bye\r\n").await?;
                break;
            }
            Ok(_) => {
                write
                    .write_all(b"502 5.5.1 Command not implemented\r\n")
                    .await?;
            }
            Err(_) => write.write_all(b"500 5.5.2 Syntax error\r\n").await?,
        }
    }
    Ok(())
}

/// Score one captured message the way a receiving MTA would.
async fn score(
    state: &SinkState,
    remote_ip: IpAddr,
    helo: &str,
    mail_from: &str,
    rcpt: &[String],
    raw: &[u8],
) -> Result<Verdict> {
    let message = AuthenticatedMessage::parse(raw)
        .ok_or_else(|| anyhow::anyhow!("message failed to parse"))?;

    let dkim = state.authenticator.verify_dkim(&message).await;
    let arc = state.authenticator.verify_arc(&message).await;
    let dkim2 = state
        .authenticator
        .verify_dkim2(
            &message,
            Envelope::new(mail_from, rcpt.iter().map(String::as_str)),
        )
        .await;
    let mail_from_domain = domain_of(mail_from);
    let spf = state
        .authenticator
        .verify_spf(SpfParameters::verify_mail_from(
            remote_ip,
            helo,
            &state.hostname,
            mail_from,
        ))
        .await;
    let from = message.from().to_string();
    let from_domain = domain_of(&from);

    let dmarc = state
        .authenticator
        .verify_dmarc(DmarcParameters::new(
            &message,
            &dkim,
            &mail_from_domain,
            &spf,
        ))
        .await;

    let dkim_pass_domains = dkim
        .iter()
        .filter(|o| matches!(o.result(), DkimResult::Pass))
        .filter_map(|o| o.signature().map(|s| s.d.clone()))
        .collect();

    let dmarc_via_dkim = matches!(dmarc.dkim_result(), DmarcResult::Pass);
    let dmarc_via_spf = matches!(dmarc.spf_result(), DmarcResult::Pass);

    Ok(Verdict {
        mail_from: mail_from.to_string(),
        rcpt: rcpt.to_vec(),
        from_domain,
        dkim_pass_domains,
        arc_pass: matches!(arc.result(), DkimResult::Pass),
        dkim2_pass: matches!(dkim2.result(), Dkim2Result::Pass),
        spf: spf.result(),
        dmarc_pass: dmarc_via_dkim || dmarc_via_spf,
        dmarc_via_dkim,
        dmarc_via_spf,
    })
}

fn unparseable_verdict(mail_from: &str, rcpt: &[String], err: anyhow::Error) -> Verdict {
    warn!(%err, "scoring failed");
    Verdict {
        mail_from: mail_from.to_string(),
        rcpt: rcpt.to_vec(),
        from_domain: String::new(),
        dkim_pass_domains: Vec::new(),
        arc_pass: false,
        dkim2_pass: false,
        spf: SpfResult::None,
        dmarc_pass: false,
        dmarc_via_dkim: false,
        dmarc_via_spf: false,
    }
}

fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@')
        .map(|(_, d)| {
            d.trim_end_matches('>')
                .trim_matches(|c: char| c.is_whitespace() || c == '>' || c == '"')
                .to_ascii_lowercase()
        })
        .unwrap_or_default()
}

/// Read the DATA payload up to `<CRLF>.<CRLF>`, dot-unstuffing, preserving bytes exactly.
async fn read_data<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut message = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            break;
        }
        if line == b".\r\n" || line == b".\n" {
            break;
        }
        let start = usize::from(line.first() == Some(&b'.'));
        message.extend_from_slice(&line[start..]);
    }
    Ok(message)
}
