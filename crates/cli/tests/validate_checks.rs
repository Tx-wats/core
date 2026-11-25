use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;
use txwatch_config::{encode_account_id, encode_contract_id};

fn txwatch_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_txwatch"))
}

fn write_temp_config(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("temp file");
    file.write_all(contents.as_bytes()).expect("write config");
    file.flush().expect("flush config");
    file
}

#[test]
fn validate_succeeds_for_well_formed_config() {
    let cid = encode_contract_id(&[1u8; 32]);
    let acct = encode_account_id(&[2u8; 32]);
    let cfg = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "vault"
webhook_url = "https://hooks.example.com/vault"

[[contracts.rules]]
type = "FunctionCall"
function = "deposit"

[[contracts.rules]]
type = "SourceAccount"
account = "{acct}"
"#
    );
    let file = write_temp_config(&cfg);
    let output = txwatch_bin()
        .args(["validate", "--config"])
        .arg(file.path())
        .output()
        .expect("run txwatch validate");

    assert!(
        output.status.success(),
        "expected success, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Configuration valid"));
    assert!(stdout.contains("vault"));
}

#[test]
fn validate_fails_for_invalid_contract_id_checksum() {
    let cfg = r#"
[network]
kind = "testnet"

[[contracts]]
id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC5"
label = "bad-checksum"
webhook_url = "https://hooks.example.com/vault"

[[contracts.rules]]
type = "AnyTransaction"
"#;
    let file = write_temp_config(cfg);
    let output = txwatch_bin()
        .args(["validate", "--config"])
        .arg(file.path())
        .output()
        .expect("run txwatch validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("CRC16"));
}

#[test]
fn validate_fails_for_ssrf_private_webhook_by_default() {
    let cid = encode_contract_id(&[3u8; 32]);
    let cfg = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "local-hook"
webhook_url = "http://127.0.0.1:9000/hook"

[[contracts.rules]]
type = "AnyTransaction"
"#
    );
    let file = write_temp_config(&cfg);
    let output = txwatch_bin()
        .args(["validate", "--config"])
        .arg(file.path())
        .output()
        .expect("run txwatch validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("allow_private_ips"));
}

#[test]
fn validate_suggests_typo_for_unknown_rule_type() {
    let cid = encode_contract_id(&[4u8; 32]);
    let cfg = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "typo-contract"
webhook_url = "https://hooks.example.com/hook"

[[contracts.rules]]
type = "FunctonCall"
function = "transfer"
"#
    );
    let file = write_temp_config(&cfg);
    let output = txwatch_bin()
        .args(["validate", "--config"])
        .arg(file.path())
        .output()
        .expect("run txwatch validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("did you mean 'FunctionCall'"));
}

#[test]
fn validate_accepts_high_fee_in_xlm_and_reports_stroops() {
    let cid = encode_contract_id(&[5u8; 32]);
    let cfg = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "fee-monitor"
webhook_url = "https://hooks.example.com/fee"

[[contracts.rules]]
type = "HighFee"
threshold_xlm = 0.25
"#
    );
    let file = write_temp_config(&cfg);
    let output = txwatch_bin()
        .args(["validate", "--config"])
        .arg(file.path())
        .output()
        .expect("run txwatch validate");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("HighFee>=2500000"));
}

#[test]
fn validate_rejects_high_fee_with_both_stroops_and_xlm() {
    let cid = encode_contract_id(&[6u8; 32]);
    let cfg = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "ambiguous-fee"
webhook_url = "https://hooks.example.com/fee"

[[contracts.rules]]
type = "HighFee"
threshold_stroops = 100000
threshold_xlm = 0.5
"#
    );
    let file = write_temp_config(&cfg);
    let output = txwatch_bin()
        .args(["validate", "--config"])
        .arg(file.path())
        .output()
        .expect("run txwatch validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("specify only one of threshold_stroops or threshold_xlm"));
}

#[test]
fn validate_accepts_multi_webhook_headers_and_template_format() {
    let cid = encode_contract_id(&[7u8; 32]);
    let cfg = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "multi-dest"

[[contracts.webhooks]]
url = "https://hooks.example.com/custom"
format = "template"
template = "tx={{{{tx_hash}}}}"
content_type = "text/plain"

[contracts.webhooks.headers]
Authorization = "Bearer secret-token"

[[contracts.rules]]
type = "AnyTransaction"
"#
    );
    let file = write_temp_config(&cfg);
    let output = txwatch_bin()
        .args(["validate", "--config"])
        .arg(file.path())
        .output()
        .expect("run txwatch validate");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}