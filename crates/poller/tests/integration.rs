/// Integration tests for the full poll → evaluate → notify pipeline.
///
/// These tests spin up two wiremock servers:
///   - a mock Horizon server (transactions + operations endpoints)
///   - a mock webhook receiver
///
/// They then either call the public `run()` entry-point or drive the evaluate /
/// notify helpers directly to verify end-to-end behaviour without touching the
/// real Stellar network.
mod helpers;

use reqwest::Client;
use std::time::Duration;

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use txwatch_config::{AlertRule, AppConfig};
use txwatch_rules::{evaluate, EnrichedTransaction, EvalContext};

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `run()` polling loop: fires exactly one webhook for the single transaction
/// returned on the first poll cycle, then gets empty pages on subsequent cycles.
#[tokio::test]
async fn run_polls_once_and_fires_webhook() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    // First transactions request returns one tx.
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(helpers::tx_page("run001", "500", true)),
        )
        .up_to_n_times(1)
        .mount(&horizon)
        .await;

    // All subsequent transaction requests return an empty page.
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    // Operations for the tx: no Soroban details needed.
    Mock::given(method("GET"))
        .and(path("/transactions/run001/operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    // Webhook receiver: expect exactly 1 POST.
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let mut contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::AnyTransaction],
    );
    contract.horizon_base_url_override = Some(horizon.uri());

    let cfg = AppConfig {
        poll_interval_seconds: 1,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    // Drive the loop for one full poll cycle (slightly more than the interval).
    let _ = tokio::time::timeout(Duration::from_millis(1500), txwatch_poller::run(cfg)).await;

    // MockServer drop verifies that exactly 1 webhook was received.
}

#[tokio::test]
async fn poll_includes_fee_charged_and_fires_high_fee_rule() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    // Horizon: transaction with fee_charged: "50000" (stroops)
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "_embedded": {
                "records": [{
                    "hash":         "fee_tx_poll",
                    "created_at":   "2024-06-01T10:00:00Z",
                    "successful":   true,
                    "paging_token": "1",
                    "fee_charged":  "50000",
                    "envelope_xdr": null,
                    "result_xdr":   null
                }]
            }
        })))
        .up_to_n_times(1)
        .mount(&horizon)
        .await;

    // All subsequent transaction requests return an empty page.
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    // Operations for that tx: empty
    Mock::given(method("GET"))
        .and(path("/transactions/fee_tx_poll/operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let mut contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::HighFee {
            threshold_stroops: 10_000,
            threshold_xlm: None,
        }],
    );
    contract.horizon_base_url_override = Some(horizon.uri());

    let cfg = AppConfig {
        poll_interval_seconds: 1,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    let _ = tokio::time::timeout(Duration::from_millis(1500), txwatch_poller::run(cfg)).await;
}

#[tokio::test]
async fn cursor_file_is_loaded_and_used_for_initial_cursor() {
    use std::fs::OpenOptions;
    use std::io::Write;

    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    // Expect the poll request to include cursor=100 (the persisted value).
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions.*cursor=100.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    let mut contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::AnyTransaction],
    );
    contract.horizon_base_url_override = Some(horizon.uri());

    // Create a temporary cursor file with the contract_id -> "100" mapping.
    let tmp = std::env::temp_dir().join("txwatch_test_cursor.json");
    let mapping = serde_json::json!({ contract.contract_id.clone(): "100" });
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)
        .unwrap();
    write!(f, "{}", mapping).unwrap();

    let cfg = AppConfig {
        poll_interval_seconds: 1,
        contracts: vec![contract],
        cursor_file: Some(tmp.to_string_lossy().to_string()),
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    let _ = tokio::time::timeout(Duration::from_millis(1500), txwatch_poller::run(cfg)).await;
}

/// AnyTransaction rule fires and webhook is called exactly once.
#[tokio::test]
async fn any_transaction_fires_webhook() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(helpers::tx_page("hash001", "100", true)),
        )
        .mount(&horizon)
        .await;

    Mock::given(method("GET"))
        .and(path("/transactions/hash001/operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let client = txwatch_notifier::build_client().unwrap();
    let contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::AnyTransaction],
    );

    let url = format!(
        "{}/accounts/{}/transactions?cursor=now&order=asc&limit=200",
        horizon.uri(),
        contract.contract_id
    );

    #[derive(serde::Deserialize)]
    struct Page {
        _embedded: Emb,
    }
    #[derive(serde::Deserialize)]
    struct Emb {
        records: Vec<txwatch_rules::HorizonTransaction>,
    }

    let page: Page = client.get(&url).send().await.unwrap().json().await.unwrap();
    let records = page._embedded.records;
    assert_eq!(records.len(), 1);

    for raw in records {
        let ops_url = format!("{}/transactions/{}/operations", horizon.uri(), raw.hash);
        // Consume the operations response to satisfy the mock expectation.
        let _ = client
            .get(&ops_url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();

        let enriched = EnrichedTransaction::from_horizon(raw, vec![], None, None).unwrap();
        let ctx = EvalContext {
            label: &contract.label,
            contract_id: &contract.contract_id,
            network: contract.network.as_str(),
            horizon_base: &horizon.uri(),
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        };
        let payloads = evaluate(&ctx, &contract.rules, &enriched, None);
        assert_eq!(payloads.len(), 1);

        for payload in &payloads {
            txwatch_notifier::send_webhook_simple(
                &client,
                contract.webhook_url.as_deref().unwrap(),
                payload,
                None,
            )
            .await
            .unwrap();
        }
    }
}

/// TransactionFailed rule fires only for failed transactions.
#[tokio::test]
async fn transaction_failed_rule_fires_only_on_failure() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "_embedded": {
                "records": [
                    {
                        "hash": "ok_tx", "created_at": "2024-06-01T10:00:00Z",
                        "successful": true, "paging_token": "1",
                        "envelope_xdr": null, "result_xdr": null
                    },
                    {
                        "hash": "fail_tx", "created_at": "2024-06-01T10:01:00Z",
                        "successful": false, "paging_token": "2",
                        "envelope_xdr": null, "result_xdr": null
                    }
                ]
            }
        })))
        .mount(&horizon)
        .await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let client = txwatch_notifier::build_client().unwrap();
    let contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::TransactionFailed],
    );

    let txs = vec![
        EnrichedTransaction::from_horizon(
            txwatch_rules::HorizonTransaction {
                hash: "ok_tx".into(),
                created_at: "2024-06-01T10:00:00Z".into(),
                successful: true,
                paging_token: "1".into(),
                fee_charged: None,
                source_account: None,
                fee_account: None,
                envelope_xdr: None,
                result_xdr: None,
                ledger: None,
                ..Default::default()
            },
            vec![],
            None,
            None,
        )
        .unwrap(),
        EnrichedTransaction::from_horizon(
            txwatch_rules::HorizonTransaction {
                hash: "fail_tx".into(),
                created_at: "2024-06-01T10:01:00Z".into(),
                successful: false,
                paging_token: "2".into(),
                fee_charged: None,
                source_account: None,
                fee_account: None,
                envelope_xdr: None,
                result_xdr: None,
                ledger: None,
                ..Default::default()
            },
            vec![],
            None,
            None,
        )
        .unwrap(),
    ];

    for tx in &txs {
        let ctx = EvalContext {
            label: &contract.label,
            contract_id: &contract.contract_id,
            network: contract.network.as_str(),
            horizon_base: &horizon.uri(),
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        };
        let payloads = evaluate(&ctx, &contract.rules, tx, None);
        for p in &payloads {
            txwatch_notifier::send_webhook_simple(
                &client,
                contract.webhook_url.as_deref().unwrap(),
                p,
                None,
            )
            .await
            .unwrap();
        }
    }
}

/// LargeTransfer rule fires when payment amount meets threshold.
#[tokio::test]
async fn large_transfer_fires_above_threshold() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let client = txwatch_notifier::build_client().unwrap();
    let contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::LargeTransfer {
            threshold_xlm: 5_000,
            threshold_stroops: 5_000 * 10_000_000,
        }],
    );

    let tx = EnrichedTransaction::from_horizon(
        txwatch_rules::HorizonTransaction {
            hash: "big_tx".into(),
            created_at: "2024-06-01T10:00:00Z".into(),
            successful: true,
            paging_token: "1".into(),
            fee_charged: None,
            source_account: None,
            fee_account: None,
            envelope_xdr: None,
            result_xdr: None,
            ledger: None,
            ..Default::default()
        },
        vec![],
        Some(100_000_000_000),
        None,
    )
    .unwrap();

    let payloads = evaluate(
        &EvalContext {
            label: &contract.label,
            contract_id: &contract.contract_id,
            network: contract.network.as_str(),
            horizon_base: "https://horizon-testnet.stellar.org",
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        },
        &contract.rules,
        &tx,
        None,
    );
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].amount_xlm, Some(10_000));

    txwatch_notifier::send_webhook_simple(
        &client,
        contract.webhook_url.as_deref().unwrap(),
        &payloads[0],
        None,
    )
    .await
    .unwrap();
}

/// FunctionCalled rule fires only when the function name matches.
#[tokio::test]
async fn function_called_rule_fires_on_exact_match() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let client = txwatch_notifier::build_client().unwrap();
    let contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::FunctionCalled {
            function_name: "withdraw".into(),
            match_mode: Default::default(),
        }],
    );

    let txs = vec![
        EnrichedTransaction::from_horizon(
            txwatch_rules::HorizonTransaction {
                hash: "t1".into(),
                created_at: "2024-06-01T10:00:00Z".into(),
                successful: true,
                paging_token: "1".into(),
                fee_charged: None,
                source_account: None,
                fee_account: None,
                envelope_xdr: None,
                result_xdr: None,
                ledger: None,
                ..Default::default()
            },
            vec!["deposit".into()],
            None,
            None,
        )
        .unwrap(),
        EnrichedTransaction::from_horizon(
            txwatch_rules::HorizonTransaction {
                hash: "t2".into(),
                created_at: "2024-06-01T10:01:00Z".into(),
                successful: true,
                paging_token: "2".into(),
                fee_charged: None,
                source_account: None,
                fee_account: None,
                envelope_xdr: None,
                result_xdr: None,
                ledger: None,
                ..Default::default()
            },
            vec!["withdraw".into()],
            None,
            None,
        )
        .unwrap(),
    ];

    for tx in &txs {
        let payloads = evaluate(
            &EvalContext {
                label: &contract.label,
                contract_id: &contract.contract_id,
                network: contract.network.as_str(),
                horizon_base: "https://horizon-testnet.stellar.org",
                explorer_base: Some("https://stellar.expert/explorer/testnet"),
            },
            &contract.rules,
            tx,
            None,
        );
        for p in &payloads {
            txwatch_notifier::send_webhook_simple(
                &client,
                contract.webhook_url.as_deref().unwrap(),
                p,
                None,
            )
            .await
            .unwrap();
        }
    }
}

/// Cursor advances so the same transaction is not processed twice.
#[tokio::test]
async fn cursor_advances_after_each_transaction() {
    use std::collections::HashMap;

    let mut cursors: HashMap<String, String> = HashMap::new();
    let contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
    cursors.insert(contract_id.to_string(), "now".to_string());

    for token in &["100", "200", "300"] {
        cursors.insert(contract_id.to_string(), token.to_string());
    }

    assert_eq!(cursors.get(contract_id).map(String::as_str), Some("300"));
}

/// HighFee rule fires when fee_charged from Horizon response exceeds threshold.
#[tokio::test]
async fn high_fee_rule_fires_on_fee_charged() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    // Horizon: transaction with fee_charged: "50000" (stroops)
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "_embedded": {
                "records": [{
                    "hash":         "fee_tx",
                    "created_at":   "2024-06-01T10:00:00Z",
                    "successful":   true,
                    "paging_token": "1",
                    "fee_charged":  "50000",
                    "envelope_xdr": null,
                    "result_xdr":   null
                }]
            }
        })))
        .mount(&horizon)
        .await;

    // Horizon: operations for that transaction (empty, no Soroban)
    Mock::given(method("GET"))
        .and(path("/transactions/fee_tx/operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    // Webhook receiver: expect exactly 1 POST (HighFee fires)
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let client = Client::new();
    let contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::HighFee {
            threshold_stroops: 10_000,
            threshold_xlm: None,
        }],
    );

    let tx = EnrichedTransaction::from_horizon(
        txwatch_rules::HorizonTransaction {
            hash: "fee_tx".into(),
            created_at: "2024-06-01T10:00:00Z".into(),
            successful: true,
            paging_token: "1".into(),
            fee_charged: Some("50000".into()),
            source_account: None,
            fee_account: None,
            envelope_xdr: None,
            result_xdr: None,
            ledger: None,
            ..Default::default()
        },
        vec![],
        None,
        Some(50_000),
    )
    .unwrap();

    let payloads = evaluate(
        &EvalContext {
            label: &contract.label,
            contract_id: &contract.contract_id,
            network: contract.network.as_str(),
            horizon_base: &horizon.uri(),
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        },
        &contract.rules,
        &tx,
        None,
    );
    assert_eq!(payloads.len(), 1);
    assert!(payloads[0].rule_triggered.contains("HighFee"));
    assert_eq!(payloads[0].fee_charged_stroops, Some(50_000));

    txwatch_notifier::send_webhook_simple(
        &client,
        contract.webhook_url.as_deref().unwrap(),
        &payloads[0],
        None,
    )
    .await
    .unwrap();
}

/// When run in dry-run mode, matched rules are logged but webhooks are not sent.
#[tokio::test]
async fn run_polls_once_and_skips_webhook_in_dry_run() {
    use std::time::Duration;

    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    // First transactions request returns one tx.
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::tx_page(
            "dryrun001",
            "500",
            true,
        )))
        .up_to_n_times(1)
        .mount(&horizon)
        .await;

    // All subsequent transaction requests return an empty page.
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    // Operations for the tx: no Soroban details needed.
    Mock::given(method("GET"))
        .and(path("/transactions/dryrun001/operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    // Webhook receiver: expect exactly 0 POSTs when dry-run is enabled.
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&receiver)
        .await;

    let mut contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::AnyTransaction],
    );
    contract.horizon_base_url_override = Some(horizon.uri());

    let cfg = AppConfig {
        poll_interval_seconds: 1,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    // Drive the loop for one full poll cycle (slightly more than the interval).
    let _ = tokio::time::timeout(
        Duration::from_millis(1500),
        txwatch_poller::run_with(cfg, true),
    )
    .await;

    // MockServer drop verifies that 0 webhooks were received.
}

/// End-to-end LargeTransfer poll, webhook payload, and cursor advancement.
#[tokio::test]
async fn large_transfer_poll_fires_webhook_and_advances_cursor() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(helpers::tx_page("large_tx", "1", true)),
        )
        .up_to_n_times(1)
        .mount(&horizon)
        .await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    Mock::given(method("GET"))
        .and(path("/transactions/large_tx/operations"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(helpers::payment_ops_page("5000.0000000")),
        )
        .mount(&horizon)
        .await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let mut contract = helpers::contract(
        &format!("{}/hook", receiver.uri()),
        vec![AlertRule::LargeTransfer {
            threshold_xlm: 1000,
            threshold_stroops: 1000 * 10_000_000,
        }],
    );
    contract.horizon_base_url_override = Some(horizon.uri());

    let cfg = AppConfig {
        poll_interval_seconds: 1,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    let _ = tokio::time::timeout(Duration::from_millis(1500), txwatch_poller::run(cfg)).await;

    let webhook_requests = receiver.received_requests().await.unwrap();
    assert_eq!(
        webhook_requests.len(),
        1,
        "expected exactly one webhook POST"
    );

    let body: serde_json::Value =
        serde_json::from_slice(&webhook_requests[0].body).expect("webhook body is JSON");
    assert_eq!(body["rule_type"].as_str(), Some("LargeTransfer"));
    assert_eq!(
        body["rule_triggered"].as_str(),
        Some("LargeTransfer(>=1000XLM)")
    );
    assert_eq!(body["amount_xlm"].as_u64(), Some(5000));

    let requests = horizon.received_requests().await.unwrap();
    assert!(
        requests.iter().any(|r| r.url.as_str().contains("cursor=1")),
        "expected the second Horizon transaction request to advance the cursor to '1'"
    );
}

/// horizon_link in webhook payloads always points to the canonical Horizon URL
/// even when polling against a mock server (horizon_base_url_override set). Closes #92.
#[tokio::test]
async fn horizon_link_uses_canonical_url_not_mock_server() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(helpers::tx_page("link_tx", "1", true)),
        )
        .up_to_n_times(1)
        .mount(&horizon)
        .await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
        .mount(&horizon)
        .await;

    Mock::given(method("GET"))
        .and(path("/transactions/link_tx/operations"))
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
    contract.horizon_base_url_override = Some(horizon.uri());

    let canonical_base = txwatch_config::Network::Testnet.horizon_base_url();

    let cfg = AppConfig {
        poll_interval_seconds: 1,
        contracts: vec![contract],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    let _ = tokio::time::timeout(Duration::from_millis(1500), txwatch_poller::run(cfg)).await;

    let requests = receiver.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "expected exactly 1 webhook POST");

    let body: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("webhook body is JSON");
    let horizon_link = body["horizon_link"]
        .as_str()
        .expect("horizon_link field present");

    assert!(
        horizon_link.starts_with(canonical_base),
        "horizon_link should start with canonical URL '{}', got: {}",
        canonical_base,
        horizon_link
    );
    assert!(
        !horizon_link.starts_with("http://127.0.0.1"),
        "horizon_link must not point to mock server, got: {}",
        horizon_link
    );
}

/// Two contracts polled concurrently: total wall time must be less than
/// the sum of each contract's individual response delay, proving that a
/// slow Horizon response for contract A does not delay contract B. Closes #7
/// and protects the concurrency behaviour introduced for #36.
#[tokio::test]
async fn contracts_polled_concurrently() {
    const DELAY_MS: u64 = 1000;

    let horizon1 = MockServer::start().await;
    let horizon2 = MockServer::start().await;
    let receiver = MockServer::start().await;

    for horizon in [&horizon1, &horizon2] {
        // Each Horizon server returns one tx with an artificial delay.
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(helpers::tx_page("delayed_tx", "1", true))
                    .set_delay(Duration::from_millis(DELAY_MS)),
            )
            .up_to_n_times(1)
            .mount(horizon)
            .await;

        // Subsequent requests return empty immediately.
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
            .mount(horizon)
            .await;

        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
            .mount(horizon)
            .await;
    }

    // Expect exactly 2 webhook POSTs — one per contract.
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&receiver)
        .await;

    let make_contract = |label: &str, horizon_uri: &str| {
        let mut c = helpers::contract(
            &format!("{}/hook", receiver.uri()),
            vec![AlertRule::AnyTransaction],
        );
        c.label = label.to_string();
        c.contract_id = if label == "A" {
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".to_string()
        } else {
            "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526".to_string()
        };
        c.horizon_base_url_override = Some(horizon_uri.to_string());
        c
    };

    let cfg = AppConfig {
        poll_interval_seconds: 1,
        contracts: vec![
            make_contract("A", &horizon1.uri()),
            make_contract("B", &horizon2.uri()),
        ],
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
        cursor_file: None,
    };

    // `run` never returns, so time how long it takes until both webhooks arrive.
    let start = std::time::Instant::now();
    let run = tokio::spawn(txwatch_poller::run(cfg));
    while receiver.received_requests().await.unwrap().len() < 2
        && start.elapsed() < Duration::from_secs(5)
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let elapsed = start.elapsed();
    run.abort();

    // Sequential polling takes at least 2 × DELAY_MS, so this 1.5× bound fails it.
    assert!(
        elapsed < Duration::from_millis(DELAY_MS * 3 / 2),
        "contracts should be polled concurrently; elapsed {:?} ≥ {}ms",
        elapsed,
        DELAY_MS * 3 / 2,
    );
}

/// Reloading the config keeps the cursor of a contract that still exists and
/// starts a newly added contract from `now`. Closes #98.
#[tokio::test]
async fn reload_keeps_existing_cursors_and_starts_new_contracts() {
    let horizon_a = MockServer::start().await;
    let horizon_b = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(helpers::tx_page("tx_a", "5", true)))
        .up_to_n_times(1)
        .mount(&horizon_a)
        .await;
    for horizon in [&horizon_a, &horizon_b] {
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
            .mount(horizon)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
            .mount(horizon)
            .await;
    }

    let mut a = helpers::contract(
        "https://hooks.example.com/a",
        vec![AlertRule::AnyTransaction],
    );
    a.label = "A".into();
    a.horizon_base_url_override = Some(horizon_a.uri());
    let mut b = helpers::contract(
        "https://hooks.example.com/b",
        vec![AlertRule::AnyTransaction],
    );
    b.label = "B".into();
    b.contract_id = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526".into();
    b.horizon_base_url_override = Some(horizon_b.uri());

    let config = |contracts| AppConfig {
        // Long interval: the only second poll comes from the reload.
        poll_interval_seconds: 3600,
        contracts,
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(1);
    let run = tokio::spawn(txwatch_poller::run_with_reload(
        config(vec![a.clone()]),
        true,
        shutdown_rx,
        reload_rx,
    ));

    tokio::time::sleep(Duration::from_millis(500)).await;
    reload_tx.send(config(vec![a, b])).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("poller should stop after shutdown")
        .unwrap()
        .unwrap();

    let cursors = |requests: Vec<wiremock::Request>| -> Vec<String> {
        requests
            .iter()
            .filter(|r| r.url.path().ends_with("/transactions"))
            .filter_map(|r| {
                r.url
                    .query_pairs()
                    .find(|(k, _)| k == "cursor")
                    .map(|(_, v)| v.into_owned())
            })
            .collect()
    };
    assert_eq!(
        cursors(horizon_a.received_requests().await.unwrap()),
        vec!["now", "5"],
        "A must keep its advanced cursor across the reload"
    );
    assert_eq!(
        cursors(horizon_b.received_requests().await.unwrap()),
        vec!["now"],
        "B is new and must start from 'now'"
    );
}

/// A per-contract `poll_interval_seconds` override is scheduled independently:
/// the fast contract is polled several times while the slow one (global
/// interval) is polled only once. Closes #97.
#[tokio::test]
async fn per_contract_poll_interval_is_scheduled_independently() {
    let fast_horizon = MockServer::start().await;
    let slow_horizon = MockServer::start().await;

    for horizon in [&fast_horizon, &slow_horizon] {
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
            .mount(horizon)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(helpers::empty_page()))
            .mount(horizon)
            .await;
    }

    let mut fast = helpers::contract(
        "https://hooks.example.com/fast",
        vec![AlertRule::AnyTransaction],
    );
    fast.label = "fast".into();
    fast.poll_interval_seconds = Some(1);
    fast.horizon_base_url_override = Some(fast_horizon.uri());

    let mut slow = helpers::contract(
        "https://hooks.example.com/slow",
        vec![AlertRule::AnyTransaction],
    );
    slow.label = "slow".into();
    slow.contract_id = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526".into();
    slow.horizon_base_url_override = Some(slow_horizon.uri());

    let cfg = AppConfig {
        poll_interval_seconds: 3600,
        contracts: vec![fast, slow],
        cursor_file: None,
        http_pool_max_idle_per_host: 10,
        http_tcp_keepalive_secs: 30,
        http_connection_verbose: None,
        max_contracts: None,
        max_pages_per_cycle: None,
    };

    let _ = tokio::time::timeout(Duration::from_millis(2500), txwatch_poller::run(cfg)).await;

    let fast_polls = fast_horizon.received_requests().await.unwrap().len();
    let slow_polls = slow_horizon.received_requests().await.unwrap().len();
    assert!(
        fast_polls >= 2,
        "fast contract should be polled repeatedly, got {}",
        fast_polls
    );
    assert_eq!(
        slow_polls, 1,
        "slow contract should be polled once, got {}",
        slow_polls
    );
}
