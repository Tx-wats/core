#![forbid(unsafe_code)]

//! txwatch-notifier delivers webhook payloads over HTTP with retry and backoff,
//! exposing `send_webhook` and `test_payload` helpers for webhook delivery.

use anyhow::{anyhow, Result};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Client;
use schemars::JsonSchema;
use serde::Serialize;
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tracing::{debug, error, info, span, warn, Level};
use txwatch_config::{WebhookDestination, WebhookHeaders};
use txwatch_rules::AlertPayload;

pub mod format;
pub mod kyc_auth;
pub use kyc_auth::verify_kyc_webhook;

const MAX_RETRIES: u32 = 3;

/// Structured result returned by a successful `send_webhook` call.
#[derive(Debug, PartialEq)]
pub struct DeliveryResult {
    /// Number of attempts made (1 = delivered on first try).
    pub attempts: u32,
    /// HTTP status code of the successful response.
    pub final_status: u16,
}

/// Build a shared HTTP client with sensible defaults.
pub fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| anyhow!("failed to build HTTP client: {}", e))
}

/// [`send_webhook`] for callers that have no shutdown signal to honour.
///
/// Holds the sender for the duration of the call so the receiver never fires
/// and retry behaviour is identical to the pre-shutdown implementation.
pub async fn send_webhook_simple(
    client: &Client,
    url: &str,
    payload: &AlertPayload,
    secret: Option<&str>,
) -> Result<DeliveryResult> {
    let (_tx, rx) = oneshot::channel();
    send_webhook(client, url, payload, secret, rx).await
}

/// POST `payload` to `url`, retrying up to `MAX_RETRIES` times with
/// exponential backoff (2 s → 4 s → 8 s). Logs each attempt.
/// If `secret` is Some, every request carries an
/// `X-TxWatch-Signature: sha256=<hex HMAC-SHA256 of the body>` header; see
/// `docs/verifying-webhooks.md`.
///
/// Delivery semantics: HTTP 2xx = success. The response body is logged at
/// debug level but is otherwise ignored — a 200 OK with an error body is
/// still treated as a successful delivery (#24).
///
/// Returns a [`DeliveryResult`] describing how many attempts were needed.
pub async fn send_webhook(
    client: &Client,
    url: &str,
    payload: &AlertPayload,
    secret: Option<&str>,
    shutdown: oneshot::Receiver<()>,
) -> Result<DeliveryResult> {
    let span = span!(Level::INFO, "send_webhook", contract = %payload.label, rule = %payload.rule_triggered);
    let _enter = span.enter();

    let body = serde_json::to_string(payload)?;
    deliver(
        client,
        url,
        body,
        secret,
        &WebhookHeaders::default(),
        payload,
        shutdown,
    )
    .await
}

/// The client to use for `destination`: `client` itself, or a dedicated client
/// carrying the destination's mTLS identity and extra CA certificate.
pub fn destination_client(client: &Client, destination: &WebhookDestination) -> Result<Client> {
    if !destination.has_tls_config() {
        return Ok(client.clone());
    }
    let read = |path: &str| {
        std::fs::read(path).map_err(|e| anyhow!("cannot read TLS file '{}': {}", path, e))
    };
    let mut builder = Client::builder().timeout(Duration::from_secs(15));
    if let (Some(cert), Some(key)) = (&destination.client_cert, &destination.client_key) {
        let mut pem = read(cert)?;
        pem.push(b'\n');
        pem.extend(read(key)?);
        builder = builder.identity(
            reqwest::Identity::from_pem(&pem)
                .map_err(|e| anyhow!("invalid client certificate or key: {}", e))?,
        );
    }
    if let Some(ca) = &destination.ca_cert {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&read(ca)?)
                .map_err(|e| anyhow!("invalid CA certificate '{}': {}", ca, e))?,
        );
    }
    builder
        .build()
        .map_err(|e| anyhow!("failed to build HTTP client: {}", e))
}

/// Deliver `payload` to one configured destination: the body is rendered in
/// the destination's [`format`](txwatch_config::WebhookFormat), and its
/// custom headers and secret are applied. Retries as [`send_webhook`] does.
/// Header values and secrets are never logged.
pub async fn send_to_destination(
    client: &Client,
    destination: &WebhookDestination,
    payload: &AlertPayload,
    shutdown: oneshot::Receiver<()>,
) -> Result<DeliveryResult> {
    let span = span!(
        Level::INFO,
        "send_webhook",
        contract = %payload.label,
        rule = %payload.rule_triggered,
        format = %destination.format
    );
    let _enter = span.enter();

    let body = format::render_body(
        destination.format,
        payload,
        destination.routing_key.as_deref(),
        destination.template.as_deref(),
    )?;
    let client = destination_client(client, destination)?;
    deliver(
        &client,
        &destination.url,
        body,
        destination.secret.as_deref(),
        &destination.headers,
        payload,
        shutdown,
    )
    .await
}

/// [`send_to_destination`] for callers that have no shutdown signal to honour.
pub async fn send_to_destination_simple(
    client: &Client,
    destination: &WebhookDestination,
    payload: &AlertPayload,
) -> Result<DeliveryResult> {
    let (_tx, rx) = oneshot::channel();
    send_to_destination(client, destination, payload, rx).await
}

/// Maximum number of alerts in one batched POST; larger sets are split.
pub const MAX_BATCH_SIZE: usize = 50;

/// Body of a batched webhook POST: `{"alerts": [<AlertPayload>, ...]}`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct AlertBatch<'a> {
    pub alerts: &'a [AlertPayload],
}

/// POST `payloads` as one `{"alerts": [...]}` request, with the same retries,
/// headers and signature as [`send_webhook`] (the signature covers the whole
/// batch body). At most [`MAX_BATCH_SIZE`] payloads are accepted; split
/// larger sets with `payloads.chunks(MAX_BATCH_SIZE)`.
pub async fn send_webhook_batch(
    client: &Client,
    url: &str,
    payloads: &[AlertPayload],
    secret: Option<&str>,
    shutdown: oneshot::Receiver<()>,
) -> Result<DeliveryResult> {
    if payloads.is_empty() {
        return Err(anyhow!("cannot send an empty alert batch"));
    }
    if payloads.len() > MAX_BATCH_SIZE {
        return Err(anyhow!(
            "alert batch of {} exceeds the maximum of {}",
            payloads.len(),
            MAX_BATCH_SIZE
        ));
    }
    let span = span!(Level::INFO, "send_webhook_batch", contract = %payloads[0].label, alerts = payloads.len());
    let _enter = span.enter();

    let body = serde_json::to_string(&AlertBatch { alerts: payloads })?;
    deliver(
        client,
        url,
        body,
        secret,
        &WebhookHeaders::default(),
        &payloads[0],
        shutdown,
    )
    .await
}

/// POSTs `body` with retries and exponential backoff. `payload` supplies the
/// rule and transaction identifiers that label the log lines.
async fn deliver(
    client: &Client,
    url: &str,
    body: String,
    secret: Option<&str>,
    headers: &WebhookHeaders,
    payload: &AlertPayload,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<DeliveryResult> {
    let mut shutdown_live = true;
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 1..=MAX_RETRIES {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        let mut req = client.post(url);
        // Custom headers first, so the TxWatch headers below always win
        // (validation already rejects reserved names).
        for (name, value) in headers.iter() {
            req = req.header(name, value);
        }
        req = req
            .header("Content-Type", "application/json")
            .header("X-TxWatch-Version", env!("CARGO_PKG_VERSION"))
            .header("X-TxWatch-Alert-Id", &payload.alert_id)
            .body(body.clone());
        if let Some(s) = secret {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(s.as_bytes()).expect("HMAC accepts any key length");
            mac.update(body.as_bytes());
            let sig = hex::encode(mac.finalize().into_bytes());
            req = req
                .header("X-TxWatch-Secret", s)
                .header("X-TxWatch-Signature", format!("sha256={}", sig));
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                let final_status = resp.status().as_u16();
                // Issue #24: log response body at debug level.
                // HTTP 2xx = delivery success regardless of body content.
                // Some receivers return 200 OK with an error body; we treat
                // any 2xx as a successful delivery (body is informational only).
                let body_text = resp.text().await.unwrap_or_default();
                debug!(
                    timestamp     = %ts,
                    url           = %url,
                    status        = final_status,
                    response_body = %body_text,
                    "webhook 2xx response body"
                );
                info!(
                    timestamp = %ts,
                    url       = %url,
                    rule      = %payload.rule_triggered,
                    tx        = %payload.transaction_hash,
                    attempts  = attempt,
                    "webhook delivered"
                );
                return Ok(DeliveryResult {
                    attempts: attempt,
                    final_status,
                });
            }
            Ok(resp) => {
                let status = resp.status();
                warn!(
                    timestamp = %ts,
                    attempt   = attempt,
                    url       = %url,
                    status    = %status,
                    "webhook attempt failed with HTTP error"
                );
                last_err = Some(anyhow!("HTTP {}", status));
            }
            Err(e) => {
                warn!(
                    timestamp = %ts,
                    attempt   = attempt,
                    url       = %url,
                    error     = %e,
                    "webhook attempt failed with network error"
                );
                last_err = Some(e.into());
            }
        }

        if attempt < MAX_RETRIES {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))) => {}
                res = &mut shutdown, if shutdown_live => {
                    match res {
                        // A real signal: stop retrying.
                        Ok(()) => return Err(anyhow!(
                            "webhook retry aborted: shutdown signal received"
                        )),
                        // Sender dropped: nobody can ever signal, so keep going
                        // and stop polling the receiver.
                        Err(_) => shutdown_live = false,
                    }
                }
            }
        }
    }

    let err = last_err.unwrap_or_else(|| anyhow!("webhook failed after {} retries", MAX_RETRIES));
    error!(
        url  = %url,
        rule = %payload.rule_triggered,
        tx   = %payload.transaction_hash,
        "webhook delivery failed permanently: {}",
        err
    );
    Err(err)
}

/// Contract ID used by test payloads: a valid contract StrKey (base32, contract
/// version byte, correct CRC16 checksum) that visibly reads as synthetic, so
/// receivers that validate or decode addresses accept it.
pub const TEST_CONTRACT_ID: &str = "CATXWATCHTESTCONTRACTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5UI";

/// Build a synthetic `AlertPayload` suitable for `test-webhook`.
pub fn test_payload(label: &str) -> AlertPayload {
    test_payload_with_network(
        label,
        "testnet",
        "https://horizon-testnet.stellar.org",
        Some("https://stellar.expert/explorer/testnet"),
    )
}

/// Build a synthetic `AlertPayload` for a network. Pass the network's own
/// `Network::as_str()`, `horizon_base_url()` and `explorer_base_url()`: the
/// explorer path is not the network name (mainnet is `/explorer/public`). A
/// network without an explorer links to the transaction on Horizon instead.
///
/// `label` is used as-is. The webhook URL is deliberately not part of the
/// payload: receivers often forward alerts to chat, and URLs can embed tokens.
/// Test payloads are marked with `rule_type = "TestWebhook"` and `"test": true`.
pub fn test_payload_with_network(
    label: &str,
    network: &str,
    horizon_base_url: &str,
    explorer_base_url: Option<&str>,
) -> AlertPayload {
    let now = Utc::now();
    let tx_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let rule_type = "TestWebhook";
    let rule_triggered = "TestWebhook";
    AlertPayload {
        schema_version: 1,
        // Unique per send, so repeated tests are not de-duplicated by receivers.
        alert_id: txwatch_rules::alert_id(
            network,
            TEST_CONTRACT_ID,
            tx_hash,
            rule_type,
            &format!(
                "TestWebhook@{}",
                now.timestamp_nanos_opt().unwrap_or_default()
            ),
            0,
        ),
        label: label.to_string(),
        contract_id: TEST_CONTRACT_ID.into(),
        network: network.to_string(),
        rule_type: rule_type.into(),
        rule_triggered: rule_triggered.into(),
        transaction_hash: tx_hash.into(),
        function_name: Some("test".into()),
        function_names: vec!["test".into()],
        amount_xlm: None,
        amount_stroops: None,
        amount_xlm_decimal: None,
        fee_charged_stroops: None,
        source_account: None,
        fee_account: None,
        severity: None,
        timestamp: now.timestamp(),
        timestamp_iso: now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        horizon_link: format!("{}/transactions/{}", horizon_base_url, tx_hash),
        explorer_link: match explorer_base_url {
            Some(explorer) => format!("{}/tx/{}", explorer, tx_hash),
            None => format!("{}/transactions/{}", horizon_base_url, tx_hash),
        },
        effective_webhook_url: None,
        effective_webhook_secret: None,
        ledger: None,
        memo: None,
        memo_type: None,
        operation_count: None,
        resolved: false,
        matched_events: vec![],
        suppressed_count: 0,
        test: true,
        old_wasm_hash: None,
        new_wasm_hash: None,
        enrichment_incomplete: false,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_payload() -> AlertPayload {
        AlertPayload {
            schema_version: 1,
            alert_id: "0123456789abcdef0123456789abcdef".into(),
            label: "Test Contract".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
            network: "testnet".into(),
            rule_type: "AnyTransaction".into(),
            rule_triggered: "AnyTransaction".into(),
            transaction_hash: "abc123".into(),
            function_name: None,
            function_names: vec![],
            amount_xlm: None,
            amount_stroops: None,
            amount_xlm_decimal: None,
            fee_charged_stroops: None,
            source_account: None,
            fee_account: None,
            severity: None,
            timestamp: 1_700_000_000,
            timestamp_iso: "2023-11-15T03:13:20Z".into(),
            horizon_link: "https://horizon-testnet.stellar.org/transactions/abc123".into(),
            explorer_link: "https://stellar.expert/explorer/testnet/tx/abc123".into(),
            effective_webhook_url: None,
            effective_webhook_secret: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
            resolved: false,
            matched_events: vec![],
            suppressed_count: 0,
            test: false,
            old_wasm_hash: None,
            new_wasm_hash: None,
            enrichment_incomplete: false,
        }
    }

    fn dummy_shutdown() -> oneshot::Receiver<()> {
        oneshot::channel().1
    }

    #[tokio::test]
    async fn delivers_on_first_attempt() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        let result = send_webhook(&client, &url, &sample_payload(), None, dummy_shutdown()).await;
        assert!(result.is_ok());
        let delivery = result.unwrap();
        assert_eq!(delivery.attempts, 1);
        assert_eq!(delivery.final_status, 200);
    }

    #[tokio::test]
    async fn retries_on_server_error_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        let result = send_webhook(&client, &url, &sample_payload(), None, dummy_shutdown()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn attempts_is_two_when_first_fails_and_second_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = Client::new();
        let url = format!("{}/hook", server.uri());
        let delivery = send_webhook(&client, &url, &sample_payload(), None, dummy_shutdown())
            .await
            .expect("should succeed on second attempt");
        assert_eq!(delivery.attempts, 2);
        assert_eq!(delivery.final_status, 200);
    }

    /// Issue #24: a 200 response with an error body must still be treated as success.
    /// The body is logged at debug level but does not affect delivery outcome.
    #[tokio::test]
    async fn success_with_error_body_is_still_treated_as_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"error":"something went wrong"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        let delivery = send_webhook(&client, &url, &sample_payload(), None, dummy_shutdown())
            .await
            .expect("200 with error body should be treated as success");
        assert_eq!(delivery.final_status, 200);
        assert_eq!(delivery.attempts, 1);
    }

    #[tokio::test]
    async fn signature_header_present_when_provided() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        send_webhook(
            &client,
            &url,
            &sample_payload(),
            Some("mysecret"),
            dummy_shutdown(),
        )
        .await
        .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].headers.contains_key("x-txwatch-secret"));
        assert_eq!(
            requests[0].headers.get("x-txwatch-secret").unwrap(),
            "mysecret"
        );
    }

    #[tokio::test]
    async fn signature_header_absent_when_not_provided() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        send_webhook(&client, &url, &sample_payload(), None, dummy_shutdown())
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].headers.contains_key("x-txwatch-secret"));
    }

    #[tokio::test]
    async fn signature_header_is_correct_hmac() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let payload = sample_payload();
        let body = serde_json::to_string(&payload).unwrap();
        let secret = "test-secret";

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body.as_bytes());
        let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        send_webhook(&client, &url, &payload, Some(secret), dummy_shutdown())
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let sig = requests[0].headers.get("x-txwatch-signature").unwrap();
        assert_eq!(sig, &expected);
    }

    /// Test vector published in `docs/verifying-webhooks.md`; keep both in sync.
    #[tokio::test]
    async fn signature_matches_documented_test_vector() {
        const BODY: &str = r#"{"alert_id":"test-vector","amount":"100.0000000"}"#;
        const SECRET: &str = "whsec_test_vector";
        const SIGNATURE: &str =
            "sha256=0330f633146e241611d9308f5c7d38cb97ad862c0a2a22895889208691a9d691";

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        deliver(
            &client,
            &url,
            BODY.to_owned(),
            Some(SECRET),
            &WebhookHeaders::default(),
            &sample_payload(),
            dummy_shutdown(),
        )
        .await
        .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests[0].body, BODY.as_bytes());
        assert_eq!(
            requests[0].headers.get("x-txwatch-signature").unwrap(),
            SIGNATURE
        );
    }

    #[tokio::test]
    async fn fails_after_max_retries() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        let result = send_webhook(&client, &url, &sample_payload(), None, dummy_shutdown()).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        // This asserted "shutdown" while dummy_shutdown() dropped its sender
        // immediately, so the retry loop aborted on the drop rather than
        // exhausting retries. With the drop no longer treated as a signal, the
        // error is the real HTTP failure this test is named for.
        assert!(
            msg.contains("500"),
            "error should report the HTTP failure, got: {}",
            msg
        );
    }

    /// A genuine shutdown signal aborts the retry loop.
    #[tokio::test]
    async fn shutdown_signal_aborts_retries() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        let (tx, rx) = oneshot::channel();
        tx.send(()).expect("receiver is alive");

        let err = send_webhook(&client, &url, &sample_payload(), None, rx)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("shutdown"),
            "error should mention shutdown, got: {}",
            err
        );
    }

    /// Issue #13: test_payload produces a structurally valid AlertPayload.
    #[test]
    fn test_payload_is_structurally_valid() {
        let p = test_payload("My Contract");
        assert_eq!(p.rule_type, "TestWebhook");
        assert_eq!(p.rule_triggered, "TestWebhook");
        assert!(p.test, "test payloads must be marked as such");
        assert!(
            p.horizon_link.contains("/transactions/"),
            "horizon_link must contain /transactions/"
        );
        assert!(
            p.explorer_link.contains("stellar.expert"),
            "explorer_link must point to stellar.expert"
        );
    }

    /// Issue #13: test_payload_with_network derives links from the supplied network config.
    #[test]
    fn test_payload_with_network_derives_links_from_config() {
        let network = txwatch_config::Network::Mainnet;
        let p = test_payload_with_network(
            "Label",
            network.as_str(),
            network.horizon_base_url(),
            network.explorer_base_url(),
        );
        assert!(p
            .horizon_link
            .starts_with("https://horizon.stellar.org/transactions/"));
        assert!(
            p.explorer_link
                .starts_with("https://stellar.expert/explorer/public/tx/"),
            "mainnet explorer path is /explorer/public/, got {}",
            p.explorer_link
        );
    }

    #[test]
    fn test_payload_with_network_uses_futurenet_explorer() {
        let network = txwatch_config::Network::Futurenet;
        let p = test_payload_with_network(
            "Label",
            network.as_str(),
            network.horizon_base_url(),
            network.explorer_base_url(),
        );
        assert_eq!(p.network, "futurenet");
        assert!(p
            .horizon_link
            .starts_with("https://horizon-futurenet.stellar.org/transactions/"));
        assert!(
            p.explorer_link
                .starts_with("https://stellar.expert/explorer/futurenet/tx/"),
            "got {}",
            p.explorer_link
        );
    }

    #[test]
    fn test_payload_without_explorer_links_to_horizon() {
        let p = test_payload_with_network("Label", "custom", "http://localhost:8000", None);
        assert_eq!(p.explorer_link, p.horizon_link);
        assert!(p
            .explorer_link
            .starts_with("http://localhost:8000/transactions/"));
    }

    /// The label is passed through unchanged; the webhook URL (which may embed
    /// a token) never appears anywhere in the payload.
    #[test]
    fn test_payload_keeps_label_and_never_includes_webhook_url() {
        let p = test_payload("My Contract");
        assert_eq!(p.label, "My Contract");

        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("test-webhook to"), "got: {}", json);
        assert!(!json.contains("example.com"), "got: {}", json);
        assert!(json.contains(r#""test":true"#), "got: {}", json);
    }

    /// The synthetic contract ID passes the same StrKey decoding (alphabet,
    /// version byte, CRC16 checksum) that txwatch-config provides.
    #[test]
    fn test_payload_contract_id_is_a_valid_strkey() {
        let p = test_payload("My Contract");
        assert_eq!(p.contract_id, TEST_CONTRACT_ID);
        txwatch_config::validate_contract_id(&p.contract_id)
            .unwrap_or_else(|e| panic!("{} is not a valid contract StrKey: {}", p.contract_id, e));
        assert!(p.contract_id.contains("TXWATCHTEST"));
    }

    #[tokio::test]
    async fn version_header_is_present_on_every_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("X-TxWatch-Version", env!("CARGO_PKG_VERSION")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        let result = send_webhook(&client, &url, &sample_payload(), None, dummy_shutdown()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn content_length_header_is_present_and_correct() {
        let server = MockServer::start().await;
        let body = serde_json::to_string(&sample_payload()).unwrap();

        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("content-length", body.len().to_string()))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let url = format!("{}/hook", server.uri());
        let result = send_webhook(&client, &url, &sample_payload(), None, dummy_shutdown()).await;
        assert!(result.is_ok());
    }

    // ── Destinations ─────────────────────────────────────────────────────────

    fn destination(url: String, format: txwatch_config::WebhookFormat) -> WebhookDestination {
        WebhookDestination {
            url,
            format,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn destination_sends_custom_headers_and_keeps_txwatch_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("Authorization", "Bearer t0ken"))
            .and(header("X-Api-Key", "k"))
            .and(header("Content-Type", "application/json"))
            .and(header("X-TxWatch-Version", env!("CARGO_PKG_VERSION")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let mut dest = destination(
            format!("{}/hook", server.uri()),
            txwatch_config::WebhookFormat::Txwatch,
        );
        dest.headers = WebhookHeaders(
            [
                ("Authorization".to_string(), "Bearer t0ken".to_string()),
                ("X-Api-Key".to_string(), "k".to_string()),
            ]
            .into_iter()
            .collect(),
        );

        let client = build_client().unwrap();
        let result = send_to_destination_simple(&client, &dest, &sample_payload())
            .await
            .unwrap();
        assert_eq!(result.final_status, 200);
    }

    // ── Batched delivery ─────────────────────────────────────────────────────

    fn payload_for(tx: &str) -> AlertPayload {
        let mut p = sample_payload();
        p.transaction_hash = tx.into();
        p
    }

    #[tokio::test]
    async fn destination_with_custom_headers_posts_once() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let mut dest = destination(
            format!("{}/hook", server.uri()),
            txwatch_config::WebhookFormat::Txwatch,
        );
        dest.headers
            .0
            .insert("Authorization".into(), "Bearer t0ken".into());
        dest.headers.0.insert("X-Api-Key".into(), "k".into());
        send_to_destination_simple(&build_client().unwrap(), &dest, &sample_payload())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn destination_renders_its_format_and_signs_the_rendered_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let mut dest = destination(server.uri(), txwatch_config::WebhookFormat::Pagerduty);
        dest.routing_key = Some("R0UT1NG".into());
        dest.secret = Some("s3".into());
        send_to_destination_simple(&build_client().unwrap(), &dest, &sample_payload())
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["routing_key"], "R0UT1NG");
        assert_eq!(body["event_action"], "trigger");
        assert_eq!(body["dedup_key"], sample_payload().alert_id);
    }

    #[tokio::test]
    async fn batch_signs_the_whole_alerts_array() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let payloads = vec![payload_for("tx1"), payload_for("tx2")];
        let client = build_client().unwrap();
        let url = format!("{}/hook", server.uri());
        let delivery = send_webhook_batch(&client, &url, &payloads, Some("s3"), dummy_shutdown())
            .await
            .unwrap();
        assert_eq!(delivery.attempts, 1);

        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let alerts = body["alerts"].as_array().expect("alerts array");
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0]["transaction_hash"], "tx1");
        assert_eq!(alerts[1]["transaction_hash"], "tx2");
        assert_eq!(body.as_object().unwrap().len(), 1, "only the alerts key");

        let mut mac = Hmac::<Sha256>::new_from_slice(b"s3").unwrap();
        mac.update(&requests[0].body);
        let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert_eq!(
            requests[0].headers.get("x-txwatch-signature").unwrap(),
            &expected
        );
    }

    #[tokio::test]
    async fn batch_rejects_empty_and_oversized_batches() {
        let client = build_client().unwrap();
        let url = "http://127.0.0.1:9/hook";
        assert!(
            send_webhook_batch(&client, url, &[], None, dummy_shutdown())
                .await
                .is_err()
        );
        let too_many: Vec<_> = (0..=MAX_BATCH_SIZE)
            .map(|i| payload_for(&i.to_string()))
            .collect();
        let err = send_webhook_batch(&client, url, &too_many, None, dummy_shutdown())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("exceeds the maximum of 50"),
            "got: {}",
            err
        );
    }
}
