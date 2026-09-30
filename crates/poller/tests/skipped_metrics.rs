//! A transaction skipped for an enrichment error is counted in the
//! `txwatch_transactions_skipped_total` Prometheus counter.
#![cfg(feature = "metrics")]

use std::path::Path;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use txwatch_config::AppConfig;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn record(hash: &str, token: &str, created_at: &str) -> serde_json::Value {
    json!({
        "hash": hash,
        "created_at": created_at,
        "successful": true,
        "paging_token": token,
        "fee_charged": "100",
        "envelope_xdr": null,
        "result_xdr": null,
        "operations": [{ "type": "payment", "amount": "1.0000000" }]
    })
}

#[tokio::test]
async fn skipped_transactions_are_counted_in_metrics() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_embedded": { "records": [
                record("badtx", "1", "not-a-timestamp"),
                record("goodtx", "2", "2024-06-01T10:00:00Z"),
            ] }
        })))
        .up_to_n_times(1)
        .mount(&horizon)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_embedded": { "records": [] }
        })))
        .mount(&horizon)
        .await;

    let mut cfg = AppConfig::parse(
        r#"
        [[contracts]]
        label = "Skip Test Contract"
        contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        network = "testnet"
        webhook_url = "https://hooks.example.com/x"
        [[contracts.rules]]
        type = "AnyTransaction"
        "#,
        Path::new("test.toml"),
    )
    .unwrap();
    cfg.contracts[0].horizon_base_url_override = Some(horizon.uri());

    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    // Signal shutdown up front: the poller runs one full cycle, then returns.
    let (poller_tx, poller_rx) = watch::channel(false);
    poller_tx.send(true).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        txwatch_poller::run_with_shutdown(cfg, true, poller_rx),
    )
    .await
    .expect("poll cycle should finish")
    .expect("poller should succeed");

    let body = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .expect("scrape /metrics")
        .text()
        .await
        .unwrap();
    let labels = r#"{contract="Skip Test Contract",network="testnet"}"#;
    assert!(
        body.contains(&format!("txwatch_transactions_skipped_total{labels} 1")),
        "{body}"
    );
}
