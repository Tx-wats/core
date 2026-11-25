//! Per-cycle page cap (`max_pages_per_cycle`), per-network cursor keys and
//! migration of legacy cursor files, exercised through `run_once`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use txwatch_config::AppConfig;
use wiremock::matchers::{method, path, path_regex, query_param};
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
    let _ = std::fs::remove_file(lock_path(&path));
    path
}

fn lock_path(cursor_file: &Path) -> PathBuf {
    let mut name = cursor_file.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// Reads the persisted state document, returning its cursor map.
fn read_cursors(path: &Path) -> HashMap<String, String> {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cursors = doc
        .get("cursors")
        .cloned()
        .unwrap_or_else(|| json!({}));
    serde_json::from_value(cursors).unwrap()
}

/// Reads the whole persisted state document.
fn read_state(path: &Path) -> Value {
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
    let raw = format!(
        "cursor_file = {:?}\n{}",
        cursor_file.display().to_string(),
        toml
    );
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
    assert_eq!(
        read_cursors(&file).get(&key).map(String::as_str),
        Some("200")
    );

    txwatch_poller::run_once(config(&toml, &file, &[&server]), true)
        .await
        .unwrap();
    assert_eq!(requested_cursors(&server).await, vec!["now", "200"]);
    assert_eq!(
        read_cursors(&file).get(&key).map(String::as_str),
        Some("201")
    );
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
    assert_eq!(
        read_cursors(&file).get(&key).map(String::as_str),
        Some("201")
    );
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
    assert_eq!(
        saved.get(&format!("testnet:{ID}")).map(String::as_str),
        Some("112")
    );
    assert_eq!(
        saved.get(&format!("futurenet:{ID}")).map(String::as_str),
        Some("223")
    );
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
    assert_eq!(
        saved.get(&format!("testnet:{ID}")).map(String::as_str),
        Some("501")
    );
    assert!(
        !saved.contains_key(ID),
        "legacy key must not be written back"
    );
}

#[tokio::test]
async fn reload_keeps_cursors_of_temporarily_removed_contracts() {
    let first = MockServer::start().await;
    let second = MockServer::start().await;
    serve_page(&first, "100", tx_page(101..=101)).await;
    serve_page(&second, "200", tx_page(201..=201)).await;
    let file = cursor_file("reload-preserve");
    let both = format!(
        "{}{}",
        contract_toml("first", ID, "testnet"),
        contract_toml("second", ID, "futurenet")
    );

    txwatch_poller::run_once(config(&both, &file, &[&first, &second]), true)
        .await
        .unwrap();
    let saved = read_cursors(&file);
    assert_eq!(
        saved.get(&format!("testnet:{ID}")).map(String::as_str),
        Some("101")
    );
    assert_eq!(
        saved.get(&format!("futurenet:{ID}")).map(String::as_str),
        Some("201")
    );

    // Reload with only the first contract configured.
    txwatch_poller::run_once(
        config(&contract_toml("first", ID, "testnet"), &file, &[&first]),
        true,
    )
    .await
    .unwrap();
    let saved = read_cursors(&file);
    assert_eq!(
        saved.get(&format!("futurenet:{ID}")).map(String::as_str),
        Some("201"),
        "cursor of a removed contract must be preserved"
    );

    // Re-add the second contract: it must resume from its saved cursor.
    let second_again = MockServer::start().await;
    serve_page(&second_again, "201", empty_page()).await;
    txwatch_poller::run_once(
        config(&both, &file, &[&first, &second_again]),
        true,
    )
    .await
    .unwrap();
    assert_eq!(requested_cursors(&second_again).await, vec!["201"]);
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

/// A Horizon operations page with `count` records and a `next` link.
fn operations_page(count: usize, next: &str) -> serde_json::Value {
    let records: Vec<_> = (0..count)
        .map(|n| json!({ "id": n.to_string(), "type": "invoke_host_function" }))
        .collect();
    json!({
        "_embedded": { "records": records },
        "_links": { "next": { "href": next } }
    })
}

/// The `cursor` query parameter of every operations request the server saw.
async fn requested_operation_cursors(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/operations"))
        .filter_map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k == "cursor")
                .map(|(_, v)| v.into_owned())
        })
        .collect()
}

#[tokio::test]
async fn legacy_cursor_file_is_migrated_to_a_versioned_state_document() {
    let server = MockServer::start().await;
    serve_page(&server, "500", tx_page(501..=501)).await;
    let file = cursor_file("legacy-versioned");
    std::fs::write(&file, json!({ ID: "500" }).to_string()).unwrap();

    txwatch_poller::run_once(
        config(&contract_toml("legacy", ID, "testnet"), &file, &[&server]),
        true,
    )
    .await
    .unwrap();

    let state = read_state(&file);
    assert_eq!(state.get("version").and_then(Value::as_u64), Some(1));
    assert_eq!(
        state
            .get("cursors")
            .and_then(|c| c.get(format!("testnet:{ID}")))
            .and_then(Value::as_str),
        Some("501")
    );
}

// --- Soroban event stream pagination (issue #289) -------------------------
//
// `SorobanEventStreamer` must never send `startLedger` together with a
// `pagination.cursor` (Soroban RPC rejects that combination), and it must only
// advance its ledger watermark past the last event actually returned so that
// unread events between a page and the tip are not skipped.

/// A Soroban `getEvents` page with one event per ledger in `range`.
fn soroban_page(range: std::ops::RangeInclusive<u32>, cursor: &str) -> serde_json::Value {
    let events: Vec<_> = range
        .map(|ledger| {
            json!({
                "type": "contract",
                "ledger": ledger,
                "ledgerClosedAt": "2024-06-01T10:00:00Z",
                "contractId": ID,
                "id": format!("{ledger}-1"),
                "pagingToken": format!("{ledger}-1"),
                "topic": [],
                "value": { "xdr": "AAAAAA==" }
            })
        })
        .collect();
    json!({
        "events": events,
        "latestLedger": 1000,
        "cursor": cursor
    })
}

fn empty_soroban_page(cursor: &str) -> serde_json::Value {
    json!({ "events": [], "latestLedger": 1000, "cursor": cursor })
}

/// The `startLedger` query parameter of every `getEvents` request, if present.
async fn requested_start_ledgers(server: &MockServer) -> Vec<Option<String>> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/operations"))
        .filter_map(|r| {
        .filter(|r| r.url.path().ends_with("/events"))
        .map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k == "startLedger")
                .map(|(_, v)| v.into_owned())
        })
        .collect()
}

/// The `cursor` query parameter of every `getEvents` request, if present.
async fn requested_event_cursors(server: &MockServer) -> Vec<Option<String>> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/events"))
        .map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k == "cursor")
                .map(|(_, v)| v.into_owned())
        })
        .collect()
}

#[tokio::test]
async fn fetch_soroban_details_follows_next_link() {
    let server = MockServer::start().await;
    let limit = txwatch_poller::OPERATIONS_PAGE_LIMIT;
    let tx_hash = "abc123";
    let ops_path = format!("/transactions/{tx_hash}/operations");

    // First page is full, so `next` must be followed.
    Mock::given(method("GET"))
        .and(path(ops_path.clone()))
        .and(query_param("cursor", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(operations_page(
            limit,
            &format!("{}/operations?cursor=page2", server.uri()),
        )))
        .mount(&server)
        .await;
    // Second page is full too, so `next` must be followed again.
    Mock::given(method("GET"))
        .and(path(ops_path.clone()))
        .and(query_param("cursor", "page2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(operations_page(
            limit,
            &format!("{}/operations?cursor=page3", server.uri()),
        )))
        .mount(&server)
        .await;
    // Third page is short: stop here even though Horizon still sends `next`.
    Mock::given(method("GET"))
        .and(path(ops_path.clone()))
        .and(query_param("cursor", "page3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(operations_page(
            1,
            &format!("{}/operations?cursor=page4", server.uri()),
        )))
        .mount(&server)
        .await;

    let details = txwatch_poller::fetch_soroban_details(&server.uri(), tx_hash)
        .await
        .unwrap();

    assert_eq!(details.operations.len(), limit * 2 + 1);
    assert_eq!(
        requested_operation_cursors(&server).await,
        vec!["0", "page2", "page3"],
        "must stop after the short page instead of following `next` to the cap"
    );

    let requests = server.received_requests().await.unwrap();
    let ops_requests: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().ends_with("/operations"))
        .collect();
    assert_eq!(ops_requests.len(), 3, "exactly one request per page");
    for request in ops_requests {
        assert!(
            !request.url.query_pairs().any(|(k, _)| k == "join"),
            "join=operations is ignored by Horizon and must not be sent"
        );
    }
async fn serve_event_page(server: &MockServer, cursor: &str, page: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path_regex("/events"))
        .and(query_param("cursor", cursor))
        .respond_with(ResponseTemplate::new(200).set_body_json(page))
        .mount(server)
        .await;
}

#[tokio::test]
async fn soroban_stream_omits_start_ledger_once_a_cursor_is_known() {
    let server = MockServer::start().await;
    serve_event_page(&server, "10-1", soroban_page(11..=11, "11-1")).await;
    serve_event_page(&server, "11-1", empty_soroban_page("11-1")).await;
    let file = cursor_file("soroban-cursor");
    std::fs::write(
        &file,
        json!({ format!("testnet:{ID}"): "10-1" }).to_string(),
    )
    .unwrap();

    txwatch_poller::run_once(
        config(&contract_toml("soroban", ID, "testnet"), &file, &[&server]),
        true,
    )
    .await
    .unwrap();

    let state = read_state(&file);
    assert_eq!(state.get("version").and_then(Value::as_u64), Some(1));
    assert_eq!(
        state
            .get("cursors")
            .and_then(|c| c.get(format!("testnet:{ID}")))
            .and_then(Value::as_str),
        Some("501")
    // Every request carried a cursor and none carried `startLedger`.
    let cursors = requested_event_cursors(&server).await;
    assert!(!cursors.is_empty(), "expected at least one getEvents call");
    assert!(cursors.iter().all(|c| c.is_some()));
    assert!(
        requested_start_ledgers(&server)
            .await
            .iter()
            .all(Option::is_none),
        "startLedger must be omitted when a cursor is present"
    );
}

#[tokio::test]
async fn runtime_state_round_trips_across_runs() {
    let server = MockServer::start().await;
    serve_page(&server, "now", empty_page()).await;
    let file = cursor_file("state-roundtrip");
    let key = format!("testnet:{ID}");
    std::fs::write(
        &file,
        json!({
            "version": 1,
            "cursors": { key.clone(): "777" },
            "cooldowns": { "capped": 1_700_000_000u64 },
            "no_activity": { "capped": { "alerting": true } }
        })
        .to_string(),
    )
    .unwrap();

    txwatch_poller::run_once(
        config(&contract_toml("capped", ID, "testnet"), &file, &[&server]),
async fn soroban_stream_advances_only_past_the_last_returned_event() {
    let server = MockServer::start().await;
    // First page returns events up to ledger 11 while the tip is 1000; the
    // watermark must land on 11, not 1000, so ledgers 12..=1000 stay unread.
    serve_event_page(&server, "10-1", soroban_page(11..=11, "11-1")).await;
    serve_event_page(&server, "11-1", empty_soroban_page("11-1")).await;
    let file = cursor_file("soroban-watermark");
    std::fs::write(
        &file,
        json!({ format!("testnet:{ID}"): "10-1" }).to_string(),
    )
    .unwrap();

    txwatch_poller::run_once(
        config(&contract_toml("soroban", ID, "testnet"), &file, &[&server]),
        true,
    )
    .await
    .unwrap();

    let state = read_state(&file);
    assert_eq!(state.get("version").and_then(Value::as_u64), Some(1));
    assert_eq!(
        state
            .get("cooldowns")
            .and_then(|c| c.get("capped"))
            .and_then(Value::as_u64),
        Some(1_700_000_000)
    );
    assert_eq!(
        state
            .get("no_activity")
            .and_then(|n| n.get("capped"))
            .and_then(|n| n.get("alerting"))
            .and_then(Value::as_bool),
        Some(true)
    let saved = read_cursors(&file);
    assert_eq!(
        saved.get(&format!("testnet:{ID}")).map(String::as_str),
        Some("11-1"),
        "watermark must stop at the last returned event, not the tip"
    );
}

#[tokio::test]
async fn cursor_file_ending_in_tmp_does_not_clobber_itself() {
    let server = MockServer::start().await;
    serve_page(&server, "now", empty_page()).await;
    let file = std::env::temp_dir().join(format!(
        "txwatch-{}-ends-in-tmp.tmp",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(lock_path(&file));

    txwatch_poller::run_once(
        config(&contract_toml("tmp", ID, "testnet"), &file, &[&server]),
async fn soroban_stream_paginates_across_multiple_pages() {
    let server = MockServer::start().await;
    serve_event_page(&server, "10-1", soroban_page(11..=11, "11-1")).await;
    serve_event_page(&server, "11-1", soroban_page(12..=12, "12-1")).await;
    serve_event_page(&server, "12-1", empty_soroban_page("12-1")).await;
    let file = cursor_file("soroban-multi-page");
    std::fs::write(
        &file,
        json!({ format!("testnet:{ID}"): "10-1" }).to_string(),
    )
    .unwrap();

    txwatch_poller::run_once(
        config(&contract_toml("soroban", ID, "testnet"), &file, &[&server]),
        true,
    )
    .await
    .unwrap();

    assert!(file.exists(), "cursor file must survive the write");
    let state = read_state(&file);
    assert_eq!(state.get("version").and_then(Value::as_u64), Some(1));
}

#[tokio::test]
async fn held_lock_makes_a_second_instance_fail_fast() {
    let server = MockServer::start().await;
    serve_page(&server, "now", empty_page()).await;
    let file = cursor_file("lock-contention");
    let lock = lock_path(&file);
    std::fs::write(&lock, b"").unwrap();
    let held = std::fs::OpenOptions::new()
        .write(true)
        .open(&lock)
        .unwrap();
    fs2::FileExt::lock_exclusive(&held).unwrap();

    let result = txwatch_poller::run_once(
        config(&contract_toml("locked", ID, "testnet"), &file, &[&server]),
        true,
    )
    .await;

    assert!(result.is_err(), "second instance must fail while lock is held");
    assert!(requested_cursors(&server).await.is_empty());

    fs2::FileExt::unlock(&held).unwrap();
    drop(held);
    let _ = std::fs::remove_file(&lock);
    let cursors: Vec<_> = requested_event_cursors(&server)
        .await
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(cursors, vec!["10-1", "11-1", "12-1"]);
    assert!(
        requested_start_ledgers(&server)
            .await
            .iter()
            .all(Option::is_none),
        "startLedger must be omitted on every cursor-based page"
    );
    let saved = read_cursors(&file);
    assert_eq!(
        saved.get(&format!("testnet:{ID}")).map(String::as_str),
        Some("12-1")
    );
}
