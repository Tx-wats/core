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

/// Write a multi-contract config with a per-test cursor file and return
/// `(config_path, cursor_path)`.
fn write_multi_config(name: &str, contracts: usize) -> (PathBuf, PathBuf) {
    let dir = env::temp_dir();
    let config_path = dir.join(format!("txwatch_once_{name}.toml"));
    let cursor_path = dir.join(format!("txwatch_once_{name}_cursors.json"));
    let _ = fs::remove_file(&cursor_path);
    let mut config = String::from("poll_interval_seconds = 10\n");
    config.push_str(&format!("cursor_file = '{}'\n", cursor_path.display()));
    for i in 0..contracts {
        config.push_str(&format!(
            r#"
[[contracts]]
label       = "Contract {i}"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = "testnet"
webhook_url = "https://hooks.example.com/unused"

  [[contracts.rules]]
  type = "AnyTransaction"
"#
        ));
    }
    fs::write(&config_path, config).unwrap();
    (config_path, cursor_path)
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

/// SIGTERM must route into the graceful shutdown path: the process exits and
/// the cursor file is flushed.
#[cfg(unix)]
#[tokio::test]
async fn sigterm_flushes_cursor_and_exits() {
    use std::time::Duration;

    let horizon = MockServer::start().await;
    let receiver = MockServer::start().await;
    mount_one_transaction(&horizon).await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;

    let (config_path, cursor_path) = write_config("sigterm", &format!("{}/hook", receiver.uri()));

    let mut child = txwatch_bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--horizon-url",
            &horizon.uri(),
            "watch",
        ])
        .spawn()
        .expect("failed to spawn txwatch");

    // Wait for the first cycle to persist the cursor before signalling.
    let mut flushed = false;
    for _ in 0..100 {
        if cursor_path.exists() {
            flushed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(flushed, "cursor file was never written before SIGTERM");

    let pid = child.id().expect("child pid");
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .await
        .expect("failed to send SIGTERM");
    assert!(status.success(), "kill -TERM failed");

    let exit = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("txwatch did not exit after SIGTERM")
        .expect("failed to wait for txwatch");
    assert!(
        exit.success(),
        "expected clean exit after SIGTERM, got {exit:?}"
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
async fn once_polls_contracts_concurrently() {
    const CONTRACTS: usize = 5;
    const DELAY_MS: u64 = 300;

    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(DELAY_MS))
                .set_body_json(empty_page()),
        )
        .mount(&horizon)
        .await;

    let (config_path, _) = write_multi_config("concurrent", CONTRACTS);

    let started = std::time::Instant::now();
    let output = run_once(&config_path, &horizon).await;
    let elapsed = started.elapsed();

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Sequential polling would take at least CONTRACTS * DELAY_MS.
    let sequential = std::time::Duration::from_millis(DELAY_MS * CONTRACTS as u64);
    assert!(
        elapsed < sequential,
        "expected concurrent polling, took {elapsed:?} (sequential would be {sequential:?})"
    );
}

#[tokio::test]
async fn once_honors_explicit_concurrency_flag() {
    const CONTRACTS: usize = 4;
    const DELAY_MS: u64 = 300;
    const CONCURRENCY: usize = 1;

    let horizon = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/accounts/.*/transactions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(DELAY_MS))
                .set_body_json(empty_page()),
        )
        .mount(&horizon)
        .await;

    let (config_path, _) = write_multi_config("explicit_concurrency", CONTRACTS);

    let started = std::time::Instant::now();
    let output = txwatch_bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--horizon-url",
            &horizon.uri(),
            "watch",
            "--once",
            "--concurrency",
            &CONCURRENCY.to_string(),
        ])
        .output()
        .await
        .expect("failed to run txwatch");
    let elapsed = started.elapsed();

    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // With concurrency 1 the polls must be sequential: at least
    // CONTRACTS * DELAY_MS. The default (8) would finish in ~DELAY_MS.
    let sequential = std::time::Duration::from_millis(DELAY_MS * CONTRACTS as u64);
    assert!(
        elapsed >= sequential,
        "expected --concurrency {CONCURRENCY} to serialize polls, took {elapsed:?} \
         (sequential would be {sequential:?})"
    );
}

#[tokio::test]
async fn once_fails_fast_when_cursor_lock_is_held() {
    let horizon = MockServer::start().await;
    mount_one_transaction(&horizon).await;

    let (config_path, cursor_path) = write_config("lock_held", "https://hooks.example.com/unused");
    let lock_path = PathBuf::from(format!("{}.lock", cursor_path.display()));

    // Hold the advisory lock from this process for the duration of the run.
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .expect("create lock file");
    lock_file.lock().expect("acquire advisory lock");

    let output = run_once(&config_path, &horizon).await;

    assert!(
        !output.status.success(),
        "expected non-zero exit when cursor lock is held"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lock"),
        "expected lock error on stderr, got: {stderr}"
    );

    lock_file.unlock().expect("release advisory lock");
}
