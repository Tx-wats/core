//! End-to-end check of the `metrics` feature: run a mocked poll, then scrape
//! the HTTP endpoint started by `serve_metrics` on port 0.
#![cfg(feature = "metrics")]

mod helpers;

use std::time::Duration;

use tokio::sync::watch;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use txwatch_config::{AlertRule, AppConfig};

#[tokio::test]
async fn mocked_poll_is_reflected_in_metrics_endpoint() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::tx_page(
            "metrics001",
            "700",
            true,
        )))
        .up_to_n_times(1)
        .mount(&horizon)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;
    Mock::given(method("GET"))
        .and(path("/transactions/metrics001/operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;

    let mut contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::AnyTransaction],
    );
    contract.label = "Metrics Test Contract".into();
    contract.horizon_base_url_override = Some(horizon.uri());
    let cfg = AppConfig {
        poll_interval_seconds: 5,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    // The endpoint keeps running for the scrape; only the poller is stopped.
    let (_server_tx, server_rx) = watch::channel(false);
    let addr = txwatch_poller::serve_metrics("127.0.0.1:0".parse().unwrap(), server_rx)
        .await
        .expect("start metrics endpoint");

    // Signal shutdown up front: the poller runs one full cycle, then returns.
    let (poller_tx, poller_rx) = watch::channel(false);
    poller_tx.send(true).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        txwatch_poller::run_with_shutdown(cfg, false, poller_rx),
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
    let labels = r#"{contract="Metrics Test Contract",network="testnet"}"#;
    assert!(
        body.contains(&format!("txwatch_transactions_total{labels} 1")),
        "{body}"
    );
    assert!(
        body.contains(&format!("txwatch_alerts_total{labels} 1")),
        "{body}"
    );
    assert!(
        body.contains(&format!("txwatch_consecutive_poll_failures{labels} 0")),
        "{body}"
    );
    assert!(
        body.contains("txwatch_horizon_request_duration_seconds_count"),
        "{body}"
    );

    let ready = reqwest::get(format!("http://{addr}/readyz")).await.unwrap();
    assert_eq!(ready.status(), 200);
    let missing = reqwest::get(format!("http://{addr}/nope")).await.unwrap();
    assert_eq!(missing.status(), 404);
}
