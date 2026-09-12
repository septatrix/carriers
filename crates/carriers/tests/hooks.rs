//! Tests for the primitives Sieve scripts call out through — the daemon half of the bounce tier
//! (the script half lives in `carriers-core`'s policy tests).

use std::sync::Arc;

use carriers_core::policy::BounceFunctions;
use carriers_core::store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use carriers::hooks::BounceHooks;

/// A one-shot HTTP server: answers a single request with `status`, and hands back the raw request
/// it received. Hand-rolled rather than pulled in as a dependency — one request, one response.
async fn one_shot_server(status: &'static str) -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/bounces", listener.local_addr().unwrap());
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        // Read until the body is in hand: the client sends a Content-Length, so the request ends
        // once we have the headers plus that many bytes.
        loop {
            let read = stream.read(&mut buf).await.unwrap();
            request.extend_from_slice(&buf[..read]);
            let text = String::from_utf8_lossy(&request).to_string();
            let body_len = text
                .split("\r\n\r\n")
                .nth(1)
                .map(|body| body.len())
                .unwrap_or(0);
            let want = content_length(&text);
            if read == 0 || (text.contains("\r\n\r\n") && body_len >= want) {
                break;
            }
        }
        stream
            .write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let _ = tx.send(String::from_utf8_lossy(&request).to_string());
    });

    (url, rx)
}

fn content_length(request: &str) -> usize {
    request
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length: ")
                .or_else(|| line.strip_prefix("Content-Length: "))
        })
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

#[tokio::test]
async fn http_request_sends_the_body_as_json_and_reports_the_status() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let client = reqwest::Client::new();
    let hooks = BounceHooks::new(&client, &store, "dev", "bob@example.com");

    let (url, request) = one_shot_server("202 Accepted").await;
    let status = hooks
        .http_request("POST", &url, r#"{"address": "bob@example.com"}"#)
        .await
        .unwrap();

    assert_eq!(status, 202, "the script is told what the server answered");
    let request = request.await.unwrap();
    assert!(request.starts_with("POST /bounces HTTP/1.1"), "{request}");
    assert!(
        request
            .to_lowercase()
            .contains("content-type: application/json"),
        "{request}"
    );
    assert!(
        request.ends_with(r#"{"address": "bob@example.com"}"#),
        "{request}"
    );
}

#[tokio::test]
async fn http_request_reports_an_unreachable_service_as_status_zero() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let client = reqwest::Client::new();
    let hooks = BounceHooks::new(&client, &store, "dev", "bob@example.com");

    // Bind and drop, so the port is one nothing is listening on.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/bounces", dead.local_addr().unwrap());
    drop(dead);

    // A script sees this as a fact to act on, not as a failure that abandons the rest of it.
    assert_eq!(hooks.http_request("POST", &url, "{}").await.unwrap(), 0);

    // A method that is not a method at all is a script bug, and is reported as one.
    let err = hooks
        .http_request("POST /bounces", &url, "{}")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid HTTP method"), "{err}");
}

#[tokio::test]
async fn disable_delivery_stops_delivery_to_the_bouncing_member_only() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .add_member("dev", "bob@example.com", true, false, false)
        .await
        .unwrap();
    store
        .add_member("dev", "alice@example.com", true, false, false)
        .await
        .unwrap();
    let client = reqwest::Client::new();

    let hooks = BounceHooks::new(&client, &store, "dev", "bob@example.com");
    assert!(hooks.disable_delivery().await.unwrap());
    assert_eq!(
        store.subscribers("dev").await.unwrap(),
        vec!["alice@example.com".to_string()],
        "only the bouncing address stops receiving the list"
    );

    // Nothing to disable for an address that is not a member.
    let stranger = BounceHooks::new(&client, &store, "dev", "nobody@nowhere.example");
    assert!(!stranger.disable_delivery().await.unwrap());
}
