//! `txwatch watch --once` against mock Horizon and webhook servers.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use tokio::process::Command;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn txwatch_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_txwatch"))
}

fn tx_page(hash: &str, paging_token: &str) -> serde_json::Value {
    serde_json::json!({
        "_embedded": {
            "records": [{
                "hash":         hash,
                "created_at":   "2024-06-01T10:00:00Z",
                "successful":   true,
                "paging_token": paging_token,
                "fee_charged":  "100",
                "envelope_xdr": null,
                "result_xdr":   null
            }]
        }
    })
}

fn empty_page() -> serde_json::Value {
    serde_json::json!({ "_embedded": { "records": [] } })
}

/// Write a single-contract config with a per-test cursor file and return
/// `(config_path, cursor_path)`.
fn write_config(name: &str, webhook_url: &str) -> (PathBuf, PathBuf) {
    let dir = env::temp_dir();
    let config_path = dir.join(format!("txwatch_once_{name}.toml"));
    let cursor_path = dir.join(format!("txwatch_once_{name}_cursors.json"));
    let _ = fs::remove_file(&cursor_path);
    let config = format!(
        r#"
poll_interval_seconds = 10
cursor_file = '{cursor}'

[[contracts]]
label       = "Once Contract"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = "testnet"
webhook_url = "{webhook_url}"

  [[contracts.rules]]
  type = "AnyTransaction"
"#,
        cursor = cursor_path.display()
    );
    fs::write(&config_path, config).unwrap();
    (config_path, cursor_path)
}

async fn mount_one_transaction(horizon: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(tx_page("once001", "700")))
        .mount(horizon)
        .await;
    Mock::given(method("GET"))
        .and(path("/transactions/once001/operations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_page()))
        .mount(horizon)
        .await;
}

async fn run_once(config_path: &Path, horizon: &MockServer) -> std::process::Output {
    txwatch_bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--horizon-url",
            &horizon.uri(),
            "watch",
            "--once",
        ])
        .output()
        .await
        .expect("failed to run txwatch")
}

#[tokio::test]
async fn once_delivers_alert_saves_cursor_and_exits_zero() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;
    mount_one_transaction(&horizon).await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let (config_path, cursor_path) = write_config("success", &format!("{}/hook", receiver.uri()));
    let output = run_once(&config_path, &horizon).await;

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cursors: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cursor_path).expect("cursor file written"))
            .unwrap();
    assert_eq!(
        cursors["testnet:CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"],
        "700"
    );
}

#[tokio::test]
async fn once_exits_non_zero_when_poll_fails() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&horizon)
        .await;

    let (config_path, _) = write_config("poll_failure", "https://hooks.example.com/unused");
    let output = run_once(&config_path, &horizon).await;

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit 1 on poll failure"
    );
}

#[tokio::test]
async fn once_exits_non_zero_when_webhook_fails() {
    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;
    mount_one_transaction(&horizon).await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&receiver)
        .await;

    let (config_path, cursor_path) =
        write_config("webhook_failure", &format!("{}/hook", receiver.uri()));
    let output = run_once(&config_path, &horizon).await;

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit 1 on webhook failure"
    );
    assert!(
        cursor_path.exists(),
        "cursors must be saved even when delivery fails"
    );
}
