//! The daemon's implementation of the primitives Sieve scripts call out through.
//!
//! carriers-core deliberately does no network I/O and holds no connections, so the primitives it
//! *declares* (see [`BounceFunctions`]) are implemented here, where the HTTP client and the store
//! live. A script's call blocks until one of these returns — for a bounce, that means holding the
//! DSN's SMTP transaction open — so both are bounded: the HTTP client carries a timeout, and the
//! store call is a single local statement.

use async_trait::async_trait;
use reqwest::Method;
use reqwest::header::CONTENT_TYPE;
use tracing::warn;

use carriers_core::policy::BounceFunctions;
use carriers_core::store::Store;
use carriers_core::{Error as CoreError, Result as CoreResult};

/// How long a script's HTTP request may take before it is abandoned and reported to the script as
/// unreachable. An external system that is down must not be able to stall ingress.
pub const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Implements the bounce script's primitives against one bounce: the member a DSN was attributed
/// to, on the list it was sent through.
pub struct BounceHooks<'a> {
    http: &'a reqwest::Client,
    store: &'a Store,
    list: &'a str,
    address: &'a str,
}

impl<'a> BounceHooks<'a> {
    pub fn new(
        http: &'a reqwest::Client,
        store: &'a Store,
        list: &'a str,
        address: &'a str,
    ) -> Self {
        BounceHooks {
            http,
            store,
            list,
            address,
        }
    }
}

#[async_trait]
impl BounceFunctions for BounceHooks<'_> {
    async fn http_request(&self, method: &str, url: &str, body: &str) -> CoreResult<i64> {
        let method = Method::from_bytes(method.trim().as_bytes()).map_err(|_| {
            CoreError::Config(format!(
                "Sieve script used an invalid HTTP method `{method}`"
            ))
        })?;

        let mut request = self.http.request(method, url);
        if !body.is_empty() {
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }

        match request.send().await {
            Ok(response) => Ok(i64::from(response.status().as_u16())),
            // Unreachable, untrusted TLS, timed out, or the URL never parsed: all of it is
            // reported to the script as "no status", for it to handle as it sees fit. Failing the
            // script instead would mean one unreachable service also skips whatever else it had
            // left to do.
            Err(err) => {
                warn!(url, %err, "Sieve script's HTTP request failed");
                Ok(0)
            }
        }
    }

    async fn disable_delivery(&self) -> CoreResult<bool> {
        let found = self.store.disable_delivery(self.list, self.address).await?;
        if found {
            warn!(
                list = self.list,
                address = self.address,
                "delivery disabled by the bounce policy"
            );
        }
        Ok(found)
    }
}
