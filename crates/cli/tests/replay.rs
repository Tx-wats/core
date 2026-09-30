//! `txwatch replay` against mocked Horizon responses.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use tokio::process::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TX_HASH: &str = "replay001";

fn write_config(name: &str, webhook_url: &str) -> PathBuf {
    let path = env::temp_dir().join(format!("txwatch_replay_{name}.toml"));
    let config = format!(
        r#"
poll_interval_seconds = 10

[[contracts]]
label       = "Replay Contract"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = "testnet"
webhook_url = "{webhook_url}"

  [[contracts.rules]]
  type           = "AdminFunctionCalled"
  function_names = ["set_admin"]

  [[contracts.rules]]
  type = "TransactionFailed"
"#
    );
    fs::write(&path, config).unwrap();
    path
}

/// Mock Horizon with one successful transaction that invokes `set_admin`.
async fn horizon_with_admin_call() -> MockServer {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/transactions/{TX_HASH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "hash":         TX_HASH,
            "created_at":   "2024-06-01T10:00:00Z",
            "successful":   true,
            "paging_token": "900",
            "fee_charged":  "100"
        })))
        .mount(&horizon)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/transactions/{TX_HASH}/operations")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "_embedded": { "records": [{
                "type":     "invoke_host_function",
                "function": "HostFunctionTypeHostFunctionTypeInvokeContract",
                "parameters": [{
                    "type": "Sym",
                    "value": "AAAADwAAAAlzZXRfYWRtaW4="
                }]
            }] }
        })))
        .mount(&horizon)
        .await;
    horizon
}

async fn replay(config: &Path, horizon: &MockServer, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "--horizon-url",
            &horizon.uri(),
            "replay",
            "--contract",
            "Replay Contract",
            "--tx",
            TX_HASH,
        ])
        .args(extra)
        .output()
        .await
        .expect("failed to run txwatch")
}

#[tokio::test]
async fn replay_prints_matched_rules_without_sending() {
    let horizon = horizon_with_admin_call().await;
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&receiver)
        .await;

    let config = write_config("no_send", &format!("{}/hook", receiver.uri()));
    let output = replay(&config, &horizon, &[]).await;

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 rule(s) matched transaction replay001"),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"rule_type\": \"AdminFunctionCalled\""),
        "{stdout}"
    );
    assert!(
        !stdout.contains("TransactionFailed"),
        "a successful tx must not match TransactionFailed: {stdout}"
    );
}

#[tokio::test]
async fn replay_with_send_delivers_webhooks() {
    let horizon = horizon_with_admin_call().await;
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let config = write_config("send", &format!("{}/hook", receiver.uri()));
    let output = replay(&config, &horizon, &["--send"]).await;

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn replay_unknown_transaction_exits_one() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&horizon)
        .await;

    let config = write_config("not_found", "https://hooks.example.com/unused");
    let output = replay(&config, &horizon, &[]).await;

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not found"));
}
