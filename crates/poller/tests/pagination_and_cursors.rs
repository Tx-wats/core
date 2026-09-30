//! Per-cycle page cap (`max_pages_per_cycle`), per-network cursor keys and
//! migration of legacy cursor files, exercised through `run_once`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::json;
use txwatch_config::AppConfig;
use wiremock::matchers::{method, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

/// A Horizon page with one transaction per paging token in `range`.
fn tx_page(range: std::ops::RangeInclusive<u32>) -> serde_json::Value {
    let records: Vec<_> = range
        .map(|n| {
            json!({
                "hash": format!("tx{n}"),
                "created_at": "2024-06-01T10:00:00Z",
                "successful": true,
                "paging_token": n.to_string(),
                "fee_charged": "100",
                "envelope_xdr": null,
                "result_xdr": null,
                "operations": [{ "type": "payment", "amount": "1.0000000" }]
            })
        })
        .collect();
    json!({ "_embedded": { "records": records } })
}

fn empty_page() -> serde_json::Value {
    json!({ "_embedded": { "records": [] } })
}

async fn serve_page(server: &MockServer, cursor: &str, page: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .and(query_param("cursor", cursor))
        .respond_with(ResponseTemplate::new(200).set_body_json(page))
        .mount(server)
        .await;
}

/// The `cursor` query parameter of every transactions request the server saw.
async fn requested_cursors(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/transactions"))
        .filter_map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k == "cursor")
                .map(|(_, v)| v.into_owned())
        })
        .collect()
}

fn cursor_file(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("txwatch-{}-{}.json", std::process::id(), name));
    let _ = std::fs::remove_file(&path);
    path
}

fn read_cursors(path: &Path) -> HashMap<String, String> {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn contract_toml(label: &str, id: &str, network: &str) -> String {
    format!(
        r#"
        [[contracts]]
        label = "{label}"
        contract_id = "{id}"
        network = "{network}"
        webhook_url = "https://hooks.example.com/x"
        [[contracts.rules]]
        type = "AnyTransaction"
        "#
    )
}

/// Parses a config; `servers[i]` becomes contract `i`'s Horizon endpoint.
fn config(toml: &str, cursor_file: &Path, servers: &[&MockServer]) -> AppConfig {
    let raw = format!("cursor_file = {:?}\n{}", cursor_file.display().to_string(), toml);
    let mut cfg = AppConfig::parse(&raw, Path::new("test.toml")).unwrap();
    for (contract, server) in cfg.contracts.iter_mut().zip(servers) {
        contract.horizon_base_url_override = Some(server.uri());
    }
    cfg
}

#[tokio::test]
async fn page_cap_stops_the_cycle_and_the_next_cycle_resumes() {
    let server = MockServer::start().await;
    serve_page(&server, "now", tx_page(1..=200)).await;
    serve_page(&server, "200", tx_page(201..=201)).await;
    serve_page(&server, "201", empty_page()).await;
    let file = cursor_file("page-cap");
    let key = format!("testnet:{ID}");
    let toml = format!(
        "max_pages_per_cycle = 1\n{}",
        contract_toml("capped", ID, "testnet")
    );

    txwatch_poller::run_once(config(&toml, &file, &[&server]), true)
        .await
        .unwrap();
    assert_eq!(requested_cursors(&server).await, vec!["now"]);
    assert_eq!(read_cursors(&file).get(&key).map(String::as_str), Some("200"));

    txwatch_poller::run_once(config(&toml, &file, &[&server]), true)
        .await
        .unwrap();
    assert_eq!(requested_cursors(&server).await, vec!["now", "200"]);
    assert_eq!(read_cursors(&file).get(&key).map(String::as_str), Some("201"));
}

#[tokio::test]
async fn default_cap_reads_further_pages_in_one_cycle() {
    let server = MockServer::start().await;
    serve_page(&server, "now", tx_page(1..=200)).await;
    serve_page(&server, "200", tx_page(201..=201)).await;
    let file = cursor_file("default-cap");
    let toml = contract_toml("uncapped", ID, "testnet");

    txwatch_poller::run_once(config(&toml, &file, &[&server]), true)
        .await
        .unwrap();

    assert_eq!(requested_cursors(&server).await, vec!["now", "200"]);
    let key = format!("testnet:{ID}");
    assert_eq!(read_cursors(&file).get(&key).map(String::as_str), Some("201"));
}

#[tokio::test]
async fn cursors_are_kept_per_network_for_the_same_contract_id() {
    let testnet = MockServer::start().await;
    let futurenet = MockServer::start().await;
    serve_page(&testnet, "111", tx_page(112..=112)).await;
    serve_page(&futurenet, "222", tx_page(223..=223)).await;
    let file = cursor_file("per-network");
    std::fs::write(
        &file,
        json!({ format!("testnet:{ID}"): "111", format!("futurenet:{ID}"): "222" }).to_string(),
    )
    .unwrap();
    let toml = format!(
        "{}{}",
        contract_toml("on-testnet", ID, "testnet"),
        contract_toml("on-futurenet", ID, "futurenet")
    );

    txwatch_poller::run_once(config(&toml, &file, &[&testnet, &futurenet]), true)
        .await
        .unwrap();

    assert_eq!(requested_cursors(&testnet).await, vec!["111"]);
    assert_eq!(requested_cursors(&futurenet).await, vec!["222"]);
    let saved = read_cursors(&file);
    assert_eq!(saved.get(&format!("testnet:{ID}")).map(String::as_str), Some("112"));
    assert_eq!(saved.get(&format!("futurenet:{ID}")).map(String::as_str), Some("223"));
}

#[tokio::test]
async fn legacy_cursor_file_is_migrated_to_network_keys() {
    let server = MockServer::start().await;
    serve_page(&server, "500", tx_page(501..=501)).await;
    let file = cursor_file("legacy");
    std::fs::write(&file, json!({ ID: "500" }).to_string()).unwrap();

    txwatch_poller::run_once(
        config(&contract_toml("legacy", ID, "testnet"), &file, &[&server]),
        true,
    )
    .await
    .unwrap();

    assert_eq!(requested_cursors(&server).await, vec!["500"]);
    let saved = read_cursors(&file);
    assert_eq!(saved.get(&format!("testnet:{ID}")).map(String::as_str), Some("501"));
    assert!(!saved.contains_key(ID), "legacy key must not be written back");
}

#[tokio::test]
async fn ambiguous_legacy_cursor_starts_from_now_on_every_network() {
    let testnet = MockServer::start().await;
    let futurenet = MockServer::start().await;
    serve_page(&testnet, "now", empty_page()).await;
    serve_page(&futurenet, "now", empty_page()).await;
    let file = cursor_file("ambiguous");
    std::fs::write(&file, json!({ ID: "500" }).to_string()).unwrap();
    let toml = format!(
        "{}{}",
        contract_toml("on-testnet", ID, "testnet"),
        contract_toml("on-futurenet", ID, "futurenet")
    );

    txwatch_poller::run_once(config(&toml, &file, &[&testnet, &futurenet]), true)
        .await
        .unwrap();

    assert_eq!(requested_cursors(&testnet).await, vec!["now"]);
    assert_eq!(requested_cursors(&futurenet).await, vec!["now"]);
}
