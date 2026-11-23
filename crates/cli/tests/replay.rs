//! `txwatch replay` against mocked Horizon responses.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use tokio::process::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// A valid 64-character hex transaction hash used by the happy-path tests.
const TX_HASH: &str = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";
const CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

fn write_config(name: &str, webhook_url: &str) -> PathBuf {
    let path = env::temp_dir().join(format!("txwatch_replay_{name}.toml"));
    let config = format!(
        r#"
poll_interval_seconds = 10

[[contracts]]
label       = "Replay Contract"
contract_id = "{CONTRACT_ID}"
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

/// Config with a per-rule webhook URL override for testing #223.
fn write_config_with_rule_override(
    name: &str,
    default_url: &str,
    rule_override_url: &str,
) -> PathBuf {
    let path = env::temp_dir().join(format!("txwatch_replay_{name}.toml"));
    let config = format!(
        r#"
poll_interval_seconds = 10

[[contracts]]
label       = "Replay Contract"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = "testnet"
webhook_url = "{default_url}"

  [[contracts.rules]]
  type           = "AdminFunctionCalled"
  function_names = ["set_admin"]
  webhook_url    = "{rule_override_url}"
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
                "parameters": [
                    {
                        "type": "Address",
                        "value": "AAAAEgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                    },
                    {
                        "type": "Sym",
                        "value": "AAAADwAAAAlzZXRfYWRtaW4="
                    }
                ]
            }] }
        })))
        .mount(&horizon)
        .await;
    horizon
}

async fn horizon_with_unrelated_transaction() -> MockServer {
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
                "type": "payment",
                "from": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "to": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "asset_type": "native",
                "amount": "1.0000000"
            }] }
        })))
        .mount(&horizon)
        .await;
    horizon
}

async fn replay(config: &Path, horizon: &MockServer, extra: &[&str]) -> std::process::Output {
    replay_with_contract(config, horizon, "Replay Contract", extra).await
}

async fn replay_with_contract(
    config: &Path,
    horizon: &MockServer,
    contract: &str,
    extra: &[&str],
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "--horizon-url",
            &horizon.uri(),
            "replay",
            "--contract",
            contract,
            "--tx",
            TX_HASH,
        ])
        .args(extra)
        .output()
        .await
        .expect("failed to run txwatch")
}

async fn replay_with_rules(
    horizon: &MockServer,
    rules: &str,
    extra: &[&str],
) -> std::process::Output {
    let path = env::temp_dir().join("txwatch_replay_unrelated.toml");
    let config = format!(
        r#"
poll_interval_seconds = 10

[[contracts]]
label       = "Replay Contract"
contract_id = "{CONTRACT_ID}"
network     = "testnet"
webhook_url = "https://hooks.example.com/unused"

  [[contracts.rules]]
  type = "{rules}"
"#
    );
    fs::write(&path, config).unwrap();
    replay(&path, horizon, extra).await
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
        stdout.contains(&format!("1 rule(s) matched transaction {}", TX_HASH)),
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
async fn replay_contract_lookup_is_case_insensitive() {
    let horizon = horizon_with_admin_call().await;
    let config = write_config("case_insensitive", "https://hooks.example.com/unused");
    let output = replay_with_contract(&config, &horizon, "replay contract", &[]).await;

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("1 rule(s) matched transaction {TX_HASH}")),
        "{stdout}"
    );
}

#[tokio::test]
async fn replay_unknown_contract_lists_configured_labels() {
    let horizon = horizon_with_admin_call().await;
    let config = write_config("unknown_contract", "https://hooks.example.com/unused");
    let output = replay_with_contract(&config, &horizon, "does-not-exist", &[]).await;

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not found"), "{stderr}");
    assert!(stderr.contains("Replay Contract"), "{stderr}");
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

// ── #222: hash validation tests ───────────────────────────────────────────────

/// Helper: run replay with a custom --tx value and no horizon override.
async fn replay_with_hash(hash: &str) -> std::process::Output {
    // No real Horizon needed — validation happens before the HTTP call.
    let config_path = env::temp_dir().join("txwatch_replay_hashtest.toml");
    fs::write(
        &config_path,
        r#"
poll_interval_seconds = 10

[[contracts]]
label       = "Hash Test"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = "testnet"
webhook_url = "https://hooks.example.com/unused"

  [[contracts.rules]]
  type = "AnyTransaction"
"#,
    )
    .unwrap();

    Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "replay",
            "--contract",
            "Hash Test",
            "--tx",
            hash,
        ])
        .output()
        .await
        .expect("failed to run txwatch")
}

#[tokio::test]
async fn replay_rejects_hash_too_short() {
    let output = replay_with_hash("abc123").await;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid transaction hash"),
        "expected hash validation error, got: {stderr}"
    );
}

#[tokio::test]
async fn replay_rejects_hash_too_long() {
    // 65 hex characters — one too many
    let output = replay_with_hash("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdde").await;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid transaction hash"),
        "expected hash validation error, got: {stderr}"
    );
}

#[tokio::test]
async fn replay_rejects_hash_with_whitespace() {
    let output = replay_with_hash("aabbccdd aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd").await;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid transaction hash"),
        "expected hash validation error, got: {stderr}"
    );
}

#[tokio::test]
async fn replay_rejects_hash_with_slash() {
    let output = replay_with_hash("aabbccddaabbccddaabbccddaabbccdd/aabbccddaabbccddaabbccddaabbccdd").await;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid transaction hash"),
        "expected hash validation error, got: {stderr}"
    );
}

#[tokio::test]
async fn replay_accepts_hash_with_0x_prefix() {
    // The 0x prefix should be stripped before use; the test just checks that
    // validation passes (Horizon 404 → exit 1 with "not found", not "invalid hash").
    let hash_with_prefix = format!("0x{}", TX_HASH);
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&horizon)
        .await;

    let config = write_config("0x_prefix", "https://hooks.example.com/unused");
    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "--horizon-url",
            &horizon.uri(),
            "replay",
            "--contract",
            "Replay Contract",
            "--tx",
            &hash_with_prefix,
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    // Should fail with "not found" (Horizon 404), not "invalid transaction hash"
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("not found"),
        "expected 'not found', got: {stderr}"
    );
    assert!(
        !stderr.contains("invalid transaction hash"),
        "0x prefix should be accepted: {stderr}"
    );
}

// ── #223: per-rule URL routing test ──────────────────────────────────────────

#[tokio::test]
async fn replay_send_routes_to_per_rule_webhook_url() {
    // Verify that replay --send honours a rule-level `webhook_url` override,
    // matching the live watch path's deliver_alert routing.
    let horizon = horizon_with_admin_call().await;

    let default_receiver = MockServer::start().await;
    let rule_receiver = MockServer::start().await;

    // The default webhook must NOT receive anything — the rule overrides it.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&default_receiver)
        .await;

    // The rule-level webhook must receive exactly one POST.
    Mock::given(method("POST"))
        .and(path("/rule-hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&rule_receiver)
        .await;

    let config = write_config_with_rule_override(
        "rule_routing",
        &format!("{}/default-hook", default_receiver.uri()),
        &format!("{}/rule-hook", rule_receiver.uri()),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
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
            "--send",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains(&format!("1 rule(s) matched transaction {TX_HASH}")));
}

#[tokio::test]
async fn replay_rejects_unrelated_transaction_unless_forced() {
    let horizon = horizon_with_unrelated_transaction().await;

    let output = replay_with_rules(&horizon, "AnyTransaction", &[]).await;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not appear to involve contract"), "{stderr}");
    assert!(stderr.contains("--force"), "{stderr}");

    let output = replay_with_rules(&horizon, "AnyTransaction", &["--force"]).await;
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── #379: replay --force must hit Horizon exactly once ───────────────────────

/// Regression test for #379: `txwatch replay --force` previously called
/// `replay_transaction` twice — once without `force` (a stale call that no
/// longer compiled) and once with `force`. If the stale call were "fixed" by
/// adding the missing argument, Horizon would be hit twice per replay.
///
/// This test mounts the transaction-fetch mock with `expect(1)`, so any
/// regression that re-introduces the double call fails with a clear
/// "received 2 requests" error rather than silently doubling the load.
#[tokio::test]
async fn replay_force_hits_horizon_exactly_once() {
    let horizon = MockServer::start().await;

    // Exactly one GET for the transaction itself.
    Mock::given(method("GET"))
        .and(path(format!("/transactions/{TX_HASH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "hash":         TX_HASH,
            "created_at":   "2024-06-01T10:00:00Z",
            "successful":   true,
            "paging_token": "900",
            "fee_charged":  "100"
        })))
        .expect(1)
        .mount(&horizon)
        .await;

    // Operations are fetched once per replay_transaction call as well.
    Mock::given(method("GET"))
        .and(path(format!("/transactions/{TX_HASH}/operations")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "_embedded": { "records": [{ "type": "payment" }] }
        })))
        .expect(1)
        .mount(&horizon)
        .await;

    let config = write_config("force_once", "https://hooks.example.com/unused");
    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
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
            "--force",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // `MockServer::verify()` (implicit on drop) enforces the `expect(1)` on
    // both mocks, so a second Horizon call fails this test.
}