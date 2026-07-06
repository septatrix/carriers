//! A minimal LMTP/SMTP ingress listener.
//!
//! This speaks just enough ESMTP/LMTP to receive a message from a trusted front MTA: EHLO/LHLO,
//! MAIL FROM, RCPT TO (restricted to known list addresses), and DATA. STARTTLS and inbound
//! authentication of the connecting client are intentionally out of scope for the MVP — the
//! listener is meant to sit behind an MTA on a trusted interface.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use listenfd::ListenFd;
use smtp_proto::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use carriers_core::config::Protocol;
use carriers_core::list::List;
use carriers_core::pipeline::{self, Disposition};
use carriers_core::sign::Ingress;
use carriers_core::Error as CoreError;

use crate::deliver::deliver;
use crate::state::AppState;

pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let listener = bind_listener(&state).await?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(state, stream, peer.ip()).await {
                warn!(%peer, %err, "connection error");
            }
        });
    }
}

/// Obtain the ingress listener.
///
/// Under systemd socket activation the socket is passed to us as an inherited file descriptor
/// (`LISTEN_FDS`); we adopt it and the `listen` config value is ignored. Otherwise we bind the
/// configured address ourselves.
async fn bind_listener(state: &AppState) -> Result<TcpListener> {
    if let Some(std_listener) = ListenFd::from_env().take_tcp_listener(0)? {
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;
        info!(
            addr = ?listener.local_addr().ok(),
            protocol = ?state.config.protocol,
            "listening (systemd socket activation)"
        );
        Ok(listener)
    } else {
        let listener = TcpListener::bind(state.config.listen).await?;
        info!(addr = %state.config.listen, protocol = ?state.config.protocol, "listening");
        Ok(listener)
    }
}

/// Per-connection SMTP/LMTP session.
async fn handle_connection(
    state: Arc<AppState>,
    stream: tokio::net::TcpStream,
    remote_ip: IpAddr,
) -> Result<()> {
    let is_lmtp = state.config.protocol == Protocol::Lmtp;
    let (read_half, mut write) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let host = state.config.hostname.clone();

    write
        .write_all(format!("220 {host} carriers ready\r\n").as_bytes())
        .await?;

    let mut helo = String::new();
    let mut mail_from: Option<String> = None;
    let mut recipients: Vec<Arc<List>> = Vec::new();
    let mut line: Vec<u8> = Vec::new();

    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            break; // client disconnected
        }

        let request = Request::parse(&mut line.iter());
        match request {
            Ok(Request::Ehlo { host: h }) | Ok(Request::Lhlo { host: h }) => {
                helo = h.into_owned();
                mail_from = None;
                recipients.clear();
                write
                    .write_all(format!("250-{host} greets you\r\n250 PIPELINING\r\n").as_bytes())
                    .await?;
            }
            Ok(Request::Helo { host: h }) => {
                helo = h.into_owned();
                mail_from = None;
                recipients.clear();
                write
                    .write_all(format!("250 {host}\r\n").as_bytes())
                    .await?;
            }
            Ok(Request::Mail { from }) => {
                mail_from = Some(from.address.into_owned());
                recipients.clear();
                write.write_all(b"250 2.1.0 OK\r\n").await?;
            }
            Ok(Request::Rcpt { to }) => {
                if mail_from.is_none() {
                    write.write_all(b"503 5.5.1 MAIL first\r\n").await?;
                    continue;
                }
                match state.list_for_address(&to.address) {
                    Some(list) => {
                        recipients.push(list.clone());
                        write.write_all(b"250 2.1.5 OK\r\n").await?;
                    }
                    None => {
                        write
                            .write_all(b"550 5.1.1 No such mailing list\r\n")
                            .await?;
                    }
                }
            }
            Ok(Request::Data) => {
                if recipients.is_empty() {
                    write
                        .write_all(b"503 5.5.1 No valid recipients\r\n")
                        .await?;
                    continue;
                }
                write
                    .write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                    .await?;
                let raw = read_data(&mut reader).await?;

                let ingress = Ingress {
                    remote_ip,
                    helo: helo.clone(),
                    mail_from: mail_from.clone().unwrap_or_default(),
                };

                // Process each addressed list and reply.
                let replies = process(&state, &recipients, &ingress, &raw).await;
                if is_lmtp {
                    // LMTP: one reply per recipient (RFC 2033).
                    for reply in &replies {
                        write.write_all(reply.as_bytes()).await?;
                    }
                } else {
                    // SMTP: a single reply. Succeed unless every recipient failed.
                    let any_ok = replies.iter().any(|r| r.starts_with('2'));
                    if any_ok {
                        write.write_all(b"250 2.6.0 Message accepted\r\n").await?;
                    } else {
                        write
                            .write_all(b"451 4.3.0 Message could not be processed\r\n")
                            .await?;
                    }
                }

                mail_from = None;
                recipients.clear();
            }
            Ok(Request::Rset) => {
                mail_from = None;
                recipients.clear();
                write.write_all(b"250 2.0.0 OK\r\n").await?;
            }
            Ok(Request::Noop { .. }) => {
                write.write_all(b"250 2.0.0 OK\r\n").await?;
            }
            Ok(Request::Quit) => {
                write.write_all(b"221 2.0.0 Bye\r\n").await?;
                break;
            }
            Ok(_) => {
                write
                    .write_all(b"502 5.5.1 Command not implemented\r\n")
                    .await?;
            }
            Err(_) => {
                write.write_all(b"500 5.5.2 Syntax error\r\n").await?;
            }
        }
    }
    Ok(())
}

/// Process the message for each addressed list, returning one SMTP reply line per recipient.
async fn process(
    state: &Arc<AppState>,
    recipients: &[Arc<List>],
    ingress: &Ingress,
    raw: &[u8],
) -> Vec<String> {
    let mut replies = Vec::with_capacity(recipients.len());
    for list in recipients {
        let reply = match handle_one(state, list, ingress, raw).await {
            Ok(Outcome::Distributed(count)) => {
                info!(list = %list.name, recipients = count, "distributed message");
                "250 2.6.0 Message accepted\r\n".to_string()
            }
            Ok(Outcome::Held(id)) => {
                info!(list = %list.name, id, "message held for moderation");
                "250 2.6.0 Message accepted (held for moderation)\r\n".to_string()
            }
            Ok(Outcome::Dropped(reason)) => {
                // Accept-and-drop: replying 2xx avoids generating backscatter.
                info!(list = %list.name, reason, "message dropped");
                "250 2.6.0 Message accepted (not distributed)\r\n".to_string()
            }
            Err(err) => {
                error!(list = %list.name, %err, "processing failed");
                "451 4.3.0 Temporary processing failure\r\n".to_string()
            }
        };
        replies.push(reply);
    }
    replies
}

enum Outcome {
    Distributed(usize),
    Held(i64),
    Dropped(String),
}

async fn handle_one(
    state: &Arc<AppState>,
    list: &Arc<List>,
    ingress: &Ingress,
    raw: &[u8],
) -> anyhow::Result<Outcome> {
    let disposition = match pipeline::intake(
        &state.authenticator,
        &state.store,
        state.members.as_ref(),
        list,
        &state.config.hostname,
        ingress,
        raw,
    )
    .await
    {
        Ok(disposition) => disposition,
        // An unparseable message surfaces as Rejected; accept-and-drop it.
        Err(CoreError::Rejected(reason)) => return Ok(Outcome::Dropped(reason)),
        Err(other) => return Err(other.into()),
    };

    match disposition {
        Disposition::Distribute(prepared) => {
            let count = deliver(&state.config.smarthost, &prepared).await?;
            Ok(Outcome::Distributed(count))
        }
        Disposition::Held { id } => Ok(Outcome::Held(id)),
        Disposition::Dropped { reason } => Ok(Outcome::Dropped(reason)),
    }
}

/// Distribute a message a moderator has approved.
pub async fn distribute_approved(
    state: &Arc<AppState>,
    list: &Arc<List>,
    ingress: &Ingress,
    raw: &[u8],
) -> anyhow::Result<usize> {
    let prepared = pipeline::finalize(
        &state.authenticator,
        state.members.as_ref(),
        list,
        &state.config.hostname,
        ingress,
        raw,
    )
    .await?;
    let count = deliver(&state.config.smarthost, &prepared).await?;
    Ok(count)
}

/// Read the DATA payload, terminated by `<CRLF>.<CRLF>`, performing dot-unstuffing.
/// The message bytes are preserved exactly (CRLF line endings intact) so DKIM stays valid.
async fn read_data<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut message = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            break; // EOF before terminator
        }
        if line == b".\r\n" || line == b".\n" {
            break;
        }
        // Dot-unstuffing: a line beginning with '.' had one prepended by the sender.
        let start = usize::from(line.first() == Some(&b'.'));
        message.extend_from_slice(&line[start..]);
    }
    Ok(message)
}
