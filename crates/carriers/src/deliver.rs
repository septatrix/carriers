//! Outbound delivery of prepared messages to the configured smarthost.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::warn;

use carriers_core::config::Smarthost;
use carriers_core::list::List;
use carriers_core::pipeline::{Prepared, verp};
use carriers_core::sign;
use mail_send::smtp::message::Message;
use mail_send::{SmtpClient, SmtpClientBuilder};

/// Relay a prepared message to every recipient via the smarthost, one message per recipient so
/// each carries its own VERP return path. Returns the number of recipients accepted.
///
/// `list` supplies the DKIM2 signer (if configured): DKIM2 binds the exact envelope, which
/// differs per recipient here (VERP), so unlike ARC/DKIM its chain link is added per delivery —
/// see [`Prepared::dkim2_original`].
pub async fn deliver(smarthost: &Smarthost, list: &List, prepared: &Prepared) -> Result<usize> {
    if prepared.recipients.is_empty() {
        return Ok(0);
    }

    let builder = SmtpClientBuilder::new(smarthost.host.clone(), smarthost.port)
        .map_err(|e| anyhow::anyhow!("invalid smarthost hostname: {e}"))?
        .implicit_tls(smarthost.implicit_tls);

    // A trusted local relay may not speak TLS; everything else must.
    if smarthost.allow_plaintext && !smarthost.implicit_tls {
        let client = builder
            .connect_plain()
            .await
            .with_context(|| format!("connecting to smarthost {}", smarthost.host))?;
        send_all(client, list, prepared).await
    } else {
        let client = builder
            .connect()
            .await
            .with_context(|| format!("connecting to smarthost {}", smarthost.host))?;
        send_all(client, list, prepared).await
    }
}

async fn send_all<S>(mut client: SmtpClient<S>, list: &List, prepared: &Prepared) -> Result<usize>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut accepted = 0;
    for recipient in &prepared.recipients {
        let return_path = verp(
            &prepared.return_path_local,
            &prepared.list_domain,
            recipient,
        );
        let body = match &prepared.dkim2_original {
            Some(original) => sign::sign_dkim2_for_delivery(
                list,
                original,
                &prepared.message,
                &return_path,
                recipient,
            )
            .context("DKIM2-signing delivery to recipient")?,
            None => prepared.message.clone(),
        };
        let message = Message::new(return_path, vec![recipient.clone()], body);
        match client.send(message).await {
            Ok(()) => accepted += 1,
            Err(err) => warn!(recipient, %err, "delivery to recipient failed"),
        }
    }
    let _ = client.quit().await;
    Ok(accepted)
}
