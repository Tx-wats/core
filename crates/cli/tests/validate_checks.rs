//! Integration tests for `validate --check-webhooks` (#224) and
//! `validate --check-horizon` (#225).

use std::{env, fs, path::PathBuf};

use tokio::process::Command;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ──────────────────────────────────────────────────────────────────

fn write_config_custom_network(name: &str, webhook_url: &str, horizon_url: &str) -> PathBuf {
    let cfg = env::temp_dir().join(format!("txwatch_valcheck_{name}.toml"));
    fs::write(
        &cfg,
        format!(
            r#"
poll_interval_seconds = 10

[[contracts]]
label       = "Check Contract"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = {{ horizon_url = "{horizon_url}" }}
webhook_url = "{webhook_url}"

  [[contracts.rules]]
  type = "AnyTransaction"
"#
        ),
    )
    .unwrap();
    cfg
}

fn write_config_custom_with_passphrase(
    name: &str,
    horizon_url: &str,
    passphrase: &str,
) -> PathBuf {
    let cfg = env::temp_dir().join(format!("txwatch_valcheck_{name}.toml"));
    fs::write(
        &cfg,
        format!(
            r#"
poll_interval_seconds = 10

[[contracts]]
label       = "PhraseCheck"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = {{ horizon_url = "{horizon_url}", passphrase = "{passphrase}" }}
webhook_url = "https://hooks.example.com/unused"

  [[contracts.rules]]
  type = "AnyTransaction"
"#
        ),
    )
    .unwrap();
    cfg
}

// ── #224: --check-webhooks status reporting ───────────────────────────────────

#[tokio::test]
async fn check_webhooks_reports_401_as_reachable_auth_required() {
    let receiver = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&receiver)
        .await;

    let config = write_config_custom_network(
        "webhook_401",
        &format!("{}/hook", receiver.uri()),
        "http://127.0.0.1:1",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    // 401 means reachable (auth required) — not a failure.
    assert!(
        output.status.success(),
        "401 should not be a failure; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("reachable (auth required)"),
        "expected 'reachable (auth required)' in: {stdout}"
    );
}

#[tokio::test]
async fn check_webhooks_reports_403_as_reachable_auth_required() {
    let receiver = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&receiver)
        .await;

    let config = write_config_custom_network(
        "webhook_403",
        &format!("{}/hook", receiver.uri()),
        "http://127.0.0.1:1",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert!(
        output.status.success(),
        "403 should not be a failure; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("reachable (auth required)"),
        "expected 'reachable (auth required)' in: {stdout}"
    );
}

#[tokio::test]
async fn check_webhooks_reports_actual_status_code_for_500() {
    let receiver = MockServer::start().await;
    // HEAD → 500, then OPTIONS fallback → also 500.
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&receiver)
        .await;
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&receiver)
        .await;

    let config = write_config_custom_network(
        "webhook_500",
        &format!("{}/hook", receiver.uri()),
        "http://127.0.0.1:1",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Must report actual status, not the old generic "method not allowed".
    assert!(
        stdout.contains("HTTP 500"),
        "expected 'HTTP 500' in: {stdout}"
    );
    assert!(
        !stdout.contains("method not allowed"),
        "must not say 'method not allowed': {stdout}"
    );
}

#[tokio::test]
async fn check_webhooks_method_not_allowed_falls_back_to_options() {
    let receiver = MockServer::start().await;
    // HEAD → 405, OPTIONS → 200 → "reachable (OPTIONS)"
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&receiver)
        .await;
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;

    let config = write_config_custom_network(
        "webhook_options",
        &format!("{}/hook", receiver.uri()),
        "http://127.0.0.1:1",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert!(
        output.status.success(),
        "OPTIONS 200 fallback should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("reachable (OPTIONS)"),
        "expected 'reachable (OPTIONS)' in: {stdout}"
    );
}

// ── #475: JSON mode must agree with text mode on failures ────────────────────

async fn run_validate_json_webhooks(config: &PathBuf) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--format",
            "json",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

#[tokio::test]
async fn check_webhooks_json_404_is_failure() {
    let receiver = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&receiver)
        .await;
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&receiver)
        .await;

    let config = write_config_custom_network(
        "webhook_json_404",
        &format!("{}/hook", receiver.uri()),
        "http://127.0.0.1:1",
    );

    let (success, stdout) = run_validate_json_webhooks(&config).await;
    assert!(!success, "404 must fail in JSON mode; stdout: {stdout}");
    assert!(
        stdout.contains("\"ok\": false") || stdout.contains("\"ok\":false"),
        "expected \"ok\": false in JSON output: {stdout}"
    );
    assert!(
        stdout.contains("404"),
        "expected status 404 in JSON output: {stdout}"
    );
}

#[tokio::test]
async fn check_webhooks_json_500_is_failure() {
    let receiver = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&receiver)
        .await;
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&receiver)
        .await;

    let config = write_config_custom_network(
        "webhook_json_500",
        &format!("{}/hook", receiver.uri()),
        "http://127.0.0.1:1",
    );

    let (success, stdout) = run_validate_json_webhooks(&config).await;
    assert!(!success, "500 must fail in JSON mode; stdout: {stdout}");
    assert!(
        stdout.contains("\"ok\": false") || stdout.contains("\"ok\":false"),
        "expected \"ok\": false in JSON output: {stdout}"
    );
    assert!(
        stdout.contains("500"),
        "expected status 500 in JSON output: {stdout}"
    );
}

// ── #477: configured headers and POST probe ──────────────────────────────────

fn write_config_custom_with_headers(
    name: &str,
    webhook_url: &str,
    headers: &str,
) -> PathBuf {
    let cfg = env::temp_dir().join(format!("txwatch_valcheck_{name}.toml"));
    fs::write(
        &cfg,
        format!(
            r#"
poll_interval_seconds = 10

[[contracts]]
label       = "HeaderCheck"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = {{ horizon_url = "http://127.0.0.1:1" }}
webhook_url = "{webhook_url}"
webhook_headers = {{ {headers} }}

  [[contracts.rules]]
  type = "AnyTransaction"
"#
        ),
    )
    .unwrap();
    cfg
}

#[tokio::test]
async fn check_webhooks_sends_configured_headers() {
    let receiver = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(wiremock::matchers::header("authorization", "Bearer secret-token"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;

    let config = write_config_custom_with_headers(
        "webhook_headers",
        &format!("{}/hook", receiver.uri()),
        r#"Authorization = "Bearer secret-token""#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert!(
        output.status.success(),
        "configured header should be accepted; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The mock only matches when the Authorization header is present, so a
    // successful run proves the header was sent.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("reachable"),
        "expected 'reachable' in: {stdout}"
    );
}

#[tokio::test]
async fn check_webhooks_post_sends_test_payload() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .and(wiremock::matchers::body_string_contains("\"test\":true"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;

    let config = write_config_custom_network(
        "webhook_post",
        &format!("{}/hook", receiver.uri()),
        "http://127.0.0.1:1",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks=post",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert!(
        output.status.success(),
        "POST probe should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("reachable"),
        "expected 'reachable' in: {stdout}"
    );
}

// ── #225: --check-horizon passphrase verification ────────────────────────────

fn horizon_root_json(passphrase: &str) -> serde_json::Value {
    serde_json::json!({
        "network_passphrase": passphrase,
        "core_latest_ledger": 100u64,
    })
}

fn horizon_found_json() -> serde_json::Value {
    serde_json::json!({ "_embedded": { "records": [] } })
}

/// Horizon's real 400 body when a `C…` contract address is used on an
/// `/accounts/{id}` route (see #4 / #472).
fn horizon_c_address_400_json() -> serde_json::Value {
    serde_json::json!({
        "type": "https://stellar.org/horizon-errors/not_found",
        "title": "Resource Missing",
        "status": 404,
        "detail": "The resource at the url requested was not found.  This usually occurs for one of two reasons:  The url requested is not valid, or no data in our database could be found with the parameters provided."
    })
}

/// Soroban RPC `getLedgerEntries` response containing one contract instance.
fn soroban_entry_found_json() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "entries": [
                {
                    "key": "AAAABgAAAAH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                    "xdr": "AAAABgAAAAH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                    "lastModifiedLedgerSeq": 100u64,
                    "liveUntilLedgerSeq": 200u64
                }
            ],
            "latestLedger": 100u64
        }
    })
}

/// Soroban RPC `getLedgerEntries` response with no matching entry.
fn soroban_entry_missing_json() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "entries": [],
            "latestLedger": 100u64
        }
    })
}

#[tokio::test]
async fn check_horizon_passes_when_passphrase_matches() {
    let horizon = MockServer::start().await;
    // Root (GET /) returns the correct testnet passphrase.
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(horizon_root_json(
                "Test SDF Network ; September 2015",
            )),
        )
        .mount(&horizon)
        .await;
    // Contract account query — returns contract found.
    Mock::given(method("GET"))
        .and(path_regex(r"^/accounts/.*/transactions$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(horizon_found_json()))
        .mount(&horizon)
        .await;

    let config = write_config_custom_with_passphrase(
        "passphrase_ok",
        &horizon.uri(),
        "Test SDF Network ; September 2015",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-horizon",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert!(
        output.status.success(),
        "matching passphrase should pass; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn check_horizon_fails_when_passphrase_mismatches() {
    let horizon = MockServer::start().await;
    // Horizon reports mainnet passphrase, but config expects testnet.
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(horizon_root_json(
                "Public Global Stellar Network ; September 2015",
            )),
        )
        .mount(&horizon)
        .await;

    let config = write_config_custom_with_passphrase(
        "passphrase_mismatch",
        &horizon.uri(),
        "Test SDF Network ; September 2015",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-horizon",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "passphrase mismatch must fail; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("passphrase mismatch"),
        "expected passphrase mismatch message in: {stdout}"
    );
}

// ── #472: contract existence via Soroban RPC / Horizon 400 handling ──────────

#[tokio::test]
async fn check_horizon_reports_endpoint_does_not_support_contracts_on_400() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(horizon_root_json(
                "Test SDF Network ; September 2015",
            )),
        )
        .mount(&horizon)
        .await;
    // Horizon rejects `C…` addresses on /accounts/{id}/transactions with 400.
    Mock::given(method("GET"))
        .and(path_regex(r"^/accounts/.*/transactions$"))
        .respond_with(ResponseTemplate::new(400).set_body_json(horizon_c_address_400_json()))
        .mount(&horizon)
        .await;

    let config = write_config_custom_with_passphrase(
        "horizon_c_400",
        &horizon.uri(),
        "Test SDF Network ; September 2015",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-horizon",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("endpoint does not support contracts"),
        "expected 'endpoint does not support contracts' in: {stdout}"
    );
    assert!(
        !stdout.to_lowercase().contains("not found"),
        "must not report 'not found' for a 400: {stdout}"
    );
}

#[tokio::test]
async fn check_horizon_contract_found_via_soroban_rpc() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(horizon_root_json(
                "Test SDF Network ; September 2015",
            )),
        )
        .mount(&horizon)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(soroban_entry_found_json()))
        .mount(&horizon)
        .await;

    let config = write_config_custom_with_passphrase(
        "soroban_found",
        &horizon.uri(),
        "Test SDF Network ; September 2015",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-horizon",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert!(
        output.status.success(),
        "contract found via getLedgerEntries should pass; stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn check_horizon_contract_not_found_via_soroban_rpc() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(horizon_root_json(
                "Test SDF Network ; September 2015",
            )),
        )
        .mount(&horizon)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(soroban_entry_missing_json()))
        .mount(&horizon)
        .await;

    let config = write_config_custom_with_passphrase(
        "soroban_missing",
        &horizon.uri(),
        "Test SDF Network ; September 2015",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-horizon",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "missing contract must fail; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("not found"),
        "expected 'not found' in: {stdout}"
    );
}

// ── #473: JSON output includes passphrase_ok ─────────────────────────────────

#[tokio::test]
async fn check_horizon_json_includes_passphrase_ok_and_fails_on_mismatch() {
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(horizon_root_json(
                "Public Global Stellar Network ; September 2015",
            )),
        )
        .mount(&horizon)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(soroban_entry_found_json()))
        .mount(&horizon)
        .await;

    let config = write_config_custom_with_passphrase(
        "json_passphrase_mismatch",
        &horizon.uri(),
        "Test SDF Network ; September 2015",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-horizon",
            "--format",
            "json",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "passphrase mismatch must fail in JSON mode; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    let checks = json
        .get("horizon_checks")
        .and_then(|v| v.as_array())
        .expect("horizon_checks array present");
    let first = checks.first().expect("at least one horizon check");
    assert_eq!(
        first.get("passphrase_ok").and_then(|v| v.as_bool()),
        Some(false),
        "passphrase_ok should be false: {first}"
    );
}

// ── #474: JSON runs all checks before exiting ────────────────────────────────

#[tokio::test]
async fn json_with_failing_webhook_still_reports_horizon_checks() {
    let receiver = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&receiver)
        .await;
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&receiver)
        .await;

    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(horizon_root_json(
                "Test SDF Network ; September 2015",
            )),
        )
        .mount(&horizon)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(soroban_entry_found_json()))
        .mount(&horizon)
        .await;

    let config = write_config_custom_with_passphrase(
        "json_webhook_and_horizon",
        &horizon.uri(),
        "Test SDF Network ; September 2015",
    );
    // Point the webhook at the failing receiver.
    let cfg_text = fs::read_to_string(&config).unwrap().replace(
        "https://hooks.example.com/unused",
        &format!("{}/hook", receiver.uri()),
    );
    fs::write(&config, cfg_text).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
            "--check-horizon",
            "--format",
            "json",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "failing webhook must exit 1; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert!(
        json.get("horizon_checks").is_some(),
        "horizon_checks must be present even when webhook fails: {json}"
    );
}

#[tokio::test]
async fn check_horizon_skips_passphrase_check_when_not_configured() {
    // Custom network without `passphrase` — the check is skipped entirely.
    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(horizon_root_json("Some Random Network")),
        )
        .mount(&horizon)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/accounts/.*/transactions$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(horizon_found_json()))
        .mount(&horizon)
        .await;

    let config = write_config_custom_network(
        "passphrase_skip",
        "https://hooks.example.com/unused",
        &horizon.uri(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-horizon",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    // No passphrase configured → check skipped → pass.
    assert!(
        output.status.success(),
        "no passphrase configured: check should be skipped; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── #457: mTLS certificate path validation ───────────────────────────────────

/// Writes a config with a webhook that has mTLS client cert/key paths.
fn write_config_with_mtls(
    name: &str,
    webhook_url: &str,
    client_cert: &str,
    client_key: &str,
) -> PathBuf {
    let cfg = env::temp_dir().join(format!("txwatch_valcheck_{name}.toml"));
    fs::write(
        &cfg,
        format!(
            r#"
poll_interval_seconds = 10

[[contracts]]
label       = "MtlsCheck"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = {{ horizon_url = "http://127.0.0.1:1" }}
webhook_url = "{webhook_url}"

  [[contracts.rules]]
  type = "AnyTransaction"

[webhooks]
client_cert = "{client_cert}"
client_key  = "{client_key}"
"#
        ),
    )
    .unwrap();
    cfg
}

/// A minimal, syntactically valid self-signed cert/key pair is not required for
/// these tests — we only need to exercise the file-reading and PEM-parsing
/// paths. We use well-known PEM markers so the parser can distinguish
/// "malformed" from "missing".
const VALID_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const VALID_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n";

fn write_temp_file(name: &str, contents: &str) -> PathBuf {
    let p = env::temp_dir().join(format!("txwatch_valcheck_{name}"));
    fs::write(&p, contents).unwrap();
    p
}

#[tokio::test]
async fn check_webhooks_fails_on_typo_client_cert_path() {
    let key = write_temp_file("mtls_typo_key.pem", VALID_KEY_PEM);
    let missing_cert = env::temp_dir().join("txwatch_valcheck_does_not_exist_cert.pem");
    let _ = fs::remove_file(&missing_cert);

    let config = write_config_with_mtls(
        "mtls_typo_cert",
        "https://hooks.example.com/unused",
        missing_cert.to_str().unwrap(),
        key.to_str().unwrap(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "missing client_cert must fail; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("webhooks[0].client_cert"),
        "expected indexed field path 'webhooks[0].client_cert' in: {combined}"
    );
    // Must not leak file contents.
    assert!(
        !combined.contains("BEGIN PRIVATE KEY"),
        "must not print file contents: {combined}"
    );
}

#[tokio::test]
async fn check_webhooks_fails_on_unreadable_client_key() {
    let cert = write_temp_file("mtls_unreadable_cert.pem", VALID_CERT_PEM);
    // Create a key file then remove read permissions.
    let key = write_temp_file("mtls_unreadable_key.pem", VALID_KEY_PEM);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&key, perms).unwrap();
    }

    let config = write_config_with_mtls(
        "mtls_unreadable_key",
        "https://hooks.example.com/unused",
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    // Restore permissions so cleanup works.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key).unwrap().permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(&key, perms);
    }

    assert_eq!(
        output.status.code(),
        Some(1),
        "unreadable client_key must fail; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("webhooks[0].client_key"),
        "expected indexed field path 'webhooks[0].client_key' in: {combined}"
    );
    assert!(
        !combined.contains("BEGIN PRIVATE KEY"),
        "must not print file contents: {combined}"
    );
}

#[tokio::test]
async fn check_webhooks_fails_on_malformed_pem() {
    let cert = write_temp_file("mtls_malformed_cert.pem", "not a pem file\n");
    let key = write_temp_file("mtls_malformed_key.pem", VALID_KEY_PEM);

    let config = write_config_with_mtls(
        "mtls_malformed_pem",
        "https://hooks.example.com/unused",
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "malformed client_cert PEM must fail; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("webhooks[0].client_cert"),
        "expected indexed field path 'webhooks[0].client_cert' in: {combined}"
    );
    assert!(
        !combined.contains("not a pem file"),
        "must not print file contents: {combined}"
    );
}

#[tokio::test]
async fn check_webhooks_warns_on_group_or_world_readable_key() {
    let cert = write_temp_file("mtls_perm_cert.pem", VALID_CERT_PEM);
    let key = write_temp_file("mtls_perm_key.pem", VALID_KEY_PEM);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&key, perms).unwrap();
    }

    let config = write_config_with_mtls(
        "mtls_perm_warn",
        "https://hooks.example.com/unused",
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_txwatch"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "validate",
            "--check-webhooks",
        ])
        .output()
        .await
        .expect("failed to run txwatch");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("webhooks[0].client_key"),
        "expected indexed field path 'webhooks[0].client_key' in: {combined}"
    );
    assert!(
        combined.to_lowercase().contains("warn")
            || combined.to_lowercase().contains("readable")
            || combined.to_lowercase().contains("permission"),
        "expected a permission warning in: {combined}"
    );
    assert!(
        !combined.contains("BEGIN PRIVATE KEY"),
        "must not print file contents: {combined}"
    );
}