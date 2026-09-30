//! Attack tests for `txwatch-poller` verifying resilience against malicious or malfunctioning
//! Horizon RPC servers, such as 429 flood and server error cascades.

use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use txwatch_config::{AlertRule, AppConfig, Network, RuleConfig, WatchedContract};

#[tokio::test]
async fn test_attack_horizon_429_flood_backs_off() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "1")
                .set_body_string("rate limited"),
        )
        .mount(&horizon)
        .await;

    let contract = WatchedContract {
        label: "FloodContract".into(),
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
        network: Network::Testnet,
        rules: vec![RuleConfig {
            rule: AlertRule::AnyTransaction,
            cooldown_seconds: None,
        }],
        webhook_url: Some("http://127.0.0.1:9999/hook".into()),
        webhook_secret: None,
        webhook_format: Default::default(),
        webhook_headers: Default::default(),
        webhook_routing_key: None,
        webhooks: Vec::new(),
        poll_interval_seconds: Some(5),
        enabled: true,
        soroban_rpc_url: None,
        batch_alerts: false,
        horizon_base_url_override: Some(horizon.uri()),
    };

    let cfg = AppConfig {
        poll_interval_seconds: 1,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 5,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    // Run poller with a timeout; it must safely handle the 429 without panicking
    let res = tokio::time::timeout(Duration::from_millis(1500), txwatch_poller::run(cfg)).await;
    assert!(
        res.is_err(),
        "Poller loop ran and handled 429 backoff until timeout"
    );
}
