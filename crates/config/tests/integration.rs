use std::path::PathBuf;
use txwatch_config::AppConfig;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate parent missing")
        .parent()
        .expect("workspace root missing")
        .to_path_buf()
}

fn crate_fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn example_toml_parses_and_validates_successfully() {
    let path = project_root().join("config").join("example.toml");
    let cfg =
        AppConfig::from_file(&path).expect("example.toml should parse and validate successfully");

    assert_eq!(cfg.poll_interval_seconds, 10);
    assert!(
        !cfg.contracts.is_empty(),
        "example config should define contracts"
    );
}

#[test]
fn local_toml_parses_and_validates_successfully() {
    let path = project_root().join("config").join("local.toml");
    let cfg =
        AppConfig::from_file(&path).expect("local.toml should parse and validate successfully");

    assert_eq!(cfg.contracts[0].network.as_str(), "custom");
    assert_eq!(
        cfg.contracts[0].network.horizon_base_url(),
        "http://stellar:8000"
    );
}

#[test]
fn broken_toml_fixture_fails_with_meaningful_error() {
    let path = crate_fixture_path("broken-example.toml");
    let err = AppConfig::from_file(&path).expect_err("broken TOML fixture should fail");
    let msg = err.to_string();

    assert!(
        msg.contains("threshold_xlm must be > 0"),
        "expected a validation failure, got: {}",
        msg
    );
}

#[test]
fn multi_file_include_with_deterministic_ordering() {
    let dir = std::env::temp_dir().join(format!("txwatch-test-multi-{}", std::process::id()));
    let contracts_d = dir.join("contracts.d");
    std::fs::create_dir_all(&contracts_d).unwrap();

    let root_toml = dir.join("txwatch.toml");
    std::fs::write(
        &root_toml,
        r#"
poll_interval_seconds = 10
include = ["contracts.d/*.toml"]
"#,
    )
    .unwrap();

    let contract_b = contracts_d.join("02_token.toml");
    std::fs::write(
        &contract_b,
        r#"
[[contracts]]
label = "Token"
contract_id = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526"
network = "testnet"
webhook_url = "https://example.com/b"
[[contracts.rules]]
type = "AnyTransaction"
"#,
    )
    .unwrap();

    let contract_a = contracts_d.join("01_vault.toml");
    std::fs::write(
        &contract_a,
        r#"
[[contracts]]
label = "Vault"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network = "testnet"
webhook_url = "https://example.com/a"
[[contracts.rules]]
type = "AnyTransaction"
"#,
    )
    .unwrap();

    let cfg =
        AppConfig::from_file(&root_toml).expect("multi-file config should parse and validate");
    assert_eq!(cfg.contracts.len(), 2);
    // Deterministic order: 01_vault.toml before 02_token.toml
    assert_eq!(cfg.contracts[0].label, "Vault");
    assert_eq!(cfg.contracts[1].label, "Token");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn multi_file_reports_errors_with_originating_file_name() {
    let dir = std::env::temp_dir().join(format!("txwatch-test-err-{}", std::process::id()));
    let contracts_d = dir.join("contracts.d");
    std::fs::create_dir_all(&contracts_d).unwrap();

    let root_toml = dir.join("txwatch.toml");
    std::fs::write(
        &root_toml,
        r#"
poll_interval_seconds = 10
include = ["contracts.d/*.toml"]
"#,
    )
    .unwrap();

    let broken_file = contracts_d.join("invalid_contract.toml");
    std::fs::write(
        &broken_file,
        r#"
[[contracts]]
label = "Bad"
contract_id = "CSHORT"
network = "testnet"
webhook_url = "https://example.com/hook"
[[contracts.rules]]
type = "AnyTransaction"
"#,
    )
    .unwrap();

    let err = AppConfig::from_file(&root_toml).expect_err("should fail on invalid contract");
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("invalid_contract.toml"),
        "error must report originating file name, got: {}",
        err_msg
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn circular_include_is_detected_and_rejected() {
    let dir = std::env::temp_dir().join(format!("txwatch-test-circular-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let file_a = dir.join("a.toml");
    let file_b = dir.join("b.toml");

    std::fs::write(
        &file_a,
        r#"
poll_interval_seconds = 10
include = ["b.toml"]
"#,
    )
    .unwrap();

    std::fs::write(
        &file_b,
        r#"
include = ["a.toml"]
"#,
    )
    .unwrap();

    let err = AppConfig::from_file(&file_a).expect_err("circular include should fail");
    assert!(err.to_string().contains("circular include detected"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diamond_include_loads_shared_file_once() {
    let dir = std::env::temp_dir().join(format!("txwatch-test-diamond-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let file_a = dir.join("a.toml");
    let file_b = dir.join("b.toml");
    let file_c = dir.join("c.toml");
    let shared = dir.join("shared.toml");

    std::fs::write(
        &file_a,
        r#"
poll_interval_seconds = 10
include = ["b.toml", "c.toml"]
"#,
    )
    .unwrap();

    std::fs::write(
        &file_b,
        r#"
include = ["shared.toml"]
"#,
    )
    .unwrap();

    std::fs::write(
        &file_c,
        r#"
include = ["shared.toml"]
"#,
    )
    .unwrap();

    std::fs::write(
        &shared,
        r#"
[[contracts]]
label = "Shared"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network = "testnet"
webhook_url = "https://example.com/shared"
[[contracts.rules]]
type = "AnyTransaction"
"#,
    )
    .unwrap();

    let cfg = AppConfig::from_file(&file_a)
        .expect("diamond include should not be reported as circular");
    assert_eq!(
        cfg.contracts.len(),
        1,
        "shared file should be loaded exactly once"
    );
    assert_eq!(cfg.contracts[0].label, "Shared");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compute_config_hash_detects_changes_in_included_files() {
    let dir = std::env::temp_dir().join(format!("txwatch-test-hash-{}", std::process::id()));
    let contracts_d = dir.join("contracts.d");
    std::fs::create_dir_all(&contracts_d).unwrap();

    let root_toml = dir.join("txwatch.toml");
    std::fs::write(
        &root_toml,
        r#"
poll_interval_seconds = 10
include = ["contracts.d/*.toml"]
"#,
    )
    .unwrap();

    let inc_toml = contracts_d.join("token.toml");
    std::fs::write(&inc_toml, "# version 1\n").unwrap();

    let hash1 = txwatch_config::compute_config_hash(&root_toml).expect("hash1");

    // Modify the included file
    std::fs::write(&inc_toml, "# version 2\n").unwrap();
    let hash2 = txwatch_config::compute_config_hash(&root_toml).expect("hash2");

    assert_ne!(hash1, hash2, "hash must change when included file changes");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_syntax_toml_fixture_reports_file_path() {
    let path = crate_fixture_path("invalid-syntax.toml");
    let err = AppConfig::from_file(&path).expect_err("invalid TOML fixture should fail");
    let msg = err.to_string();

    assert!(
        msg.contains("invalid-syntax.toml"),
        "expected the error to include the file path, got: {}",
        msg
    );
}

fn write_temp_config(name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "txwatch-config-it-{}-{}",
        std::process::id(),
        name
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("config.toml");
    std::fs::write(&path, contents).expect("write temp config");
    path
}

const CONTRACT_HEADER: &str = r#"
poll_interval_seconds = 10

[[contracts]]
name = "token"
network = "testnet"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
"#;

#[test]
fn event_emitted_data_matchers_parse_and_validate() {
    let toml = format!(
        r#"{header}
[[contracts.rules]]
type = "event_emitted"
topic = ["transfer"]
data = [
  {{ pointer = "/amount", gte = "1000" }},
  {{ pointer = "/to", eq = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF" }},
]
"#,
        header = CONTRACT_HEADER
    );
    let path = write_temp_config("data-matchers-ok", &toml);
    AppConfig::from_file(&path).expect("data matchers should parse and validate");
}

#[test]
fn event_emitted_typed_topic_patterns_parse() {
    let toml = format!(
        r#"{header}
[[contracts.rules]]
type = "event_emitted"
topic = ["address:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", "u32:5"]
"#,
        header = CONTRACT_HEADER
    );
    let path = write_temp_config("typed-topics-ok", &toml);
    AppConfig::from_file(&path).expect("typed topic patterns should parse");
}

#[test]
fn event_emitted_rejects_invalid_json_pointer() {
    let toml = format!(
        r#"{header}
[[contracts.rules]]
type = "event_emitted"
topic = ["transfer"]
data = [{{ pointer = "amount", eq = "1" }}]
"#,
        header = CONTRACT_HEADER
    );
    let path = write_temp_config("bad-pointer", &toml);
    let err = AppConfig::from_file(&path).expect_err("invalid pointer should be rejected");
    assert!(
        err.to_string().to_lowercase().contains("pointer"),
        "expected pointer validation error, got: {}",
        err
    );
}

#[test]
fn event_emitted_rejects_incompatible_comparison_type() {
    let toml = format!(
        r#"{header}
[[contracts.rules]]
type = "event_emitted"
topic = ["transfer"]
data = [{{ pointer = "/amount", gte = "not-a-number" }}]
"#,
        header = CONTRACT_HEADER
    );
    let path = write_temp_config("bad-comparison", &toml);
    let err = AppConfig::from_file(&path).expect_err("bad comparison should be rejected");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("gte") || msg.contains("comparison") || msg.contains("number"),
        "expected comparison type validation error, got: {}",
        err
    );
}

#[test]
fn large_transfer_direction_parses_and_validates() {
    for direction in ["in", "out", "any"] {
        let toml = format!(
            r#"{header}
[[contracts.rules]]
type = "large_transfer"
threshold_xlm = 100.0
direction = "{direction}"
"#,
            header = CONTRACT_HEADER,
            direction = direction
        );
        let path = write_temp_config(&format!("direction-{}", direction), &toml);
        AppConfig::from_file(&path).expect("valid direction should parse and validate");
    }

    let toml = format!(
        r#"{header}
[[contracts.rules]]
type = "large_transfer"
threshold_xlm = 100.0
direction = "sideways"
"#,
        header = CONTRACT_HEADER
    );
    let path = write_temp_config("direction-bad", &toml);
    AppConfig::from_file(&path).expect_err("invalid direction should be rejected");
}

#[test]
fn contract_upgraded_rule_parses() {
    let toml = format!(
        r#"{header}
[[contracts.rules]]
type = "contract_upgraded"
"#,
        header = CONTRACT_HEADER
    );
    let path = write_temp_config("contract-upgraded", &toml);
    AppConfig::from_file(&path).expect("contract_upgraded rule should parse");
}

#[test]
fn high_fee_validate_is_idempotent() {
    let toml = format!(
        r#"{header}
[[contracts.rules]]
type = "high_fee"
threshold_xlm = 1
"#,
        header = CONTRACT_HEADER
    );
    let path = write_temp_config("high-fee-idempotent", &toml);
    let mut cfg = AppConfig::from_file(&path).expect("high_fee config should parse and validate");

    // Validating an already-validated rule must succeed.
    cfg.validate()
        .expect("re-validating a validated high_fee rule should succeed");
    cfg.validate()
        .expect("validating a high_fee rule twice should succeed");
}

#[test]
fn high_fee_survives_serialise_and_reparse() {
    let toml = format!(
        r#"{header}
[[contracts.rules]]
type = "high_fee"
threshold_xlm = 1
"#,
        header = CONTRACT_HEADER
    );
    let path = write_temp_config("high-fee-roundtrip", &toml);
    let cfg = AppConfig::from_file(&path).expect("high_fee config should parse and validate");

    let serialised = toml::to_string(&cfg).expect("serialising a validated config should succeed");
    let reparsed: AppConfig =
        toml::from_str(&serialised).expect("re-parsing a serialised config should succeed");
    reparsed
        .validate()
        .expect("re-parsed config should validate successfully");
}

#[test]
fn muxed_addresses_from_stellar_docs_are_accepted() {
    // Real muxed (M...) addresses from the Stellar documentation.
    let valid = [
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
    ];
    for addr in valid {
        assert_eq!(addr.len(), 69, "muxed address should be 69 chars: {}", addr);
        txwatch_config::validate_stellar_address(addr)
            .unwrap_or_else(|e| panic!("valid muxed address {} rejected: {}", addr, e));
    }
}

#[test]
fn muxed_address_wrong_length_is_rejected() {
    // A valid 69-char muxed address padded to 72 chars must be rejected.
    let padded = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKAAA";
    assert_eq!(padded.len(), 72);
    txwatch_config::validate_stellar_address(padded)
        .expect_err("wrong-length muxed address should be rejected");

    let short = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJL";
    assert_eq!(short.len(), 68);
    txwatch_config::validate_stellar_address(short)
        .expect_err("short muxed address should be rejected");
}

#[test]
fn muxed_address_bad_checksum_is_rejected() {
    // Flip the final character of a valid muxed address to break the CRC16 checksum.
    let bad = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLL";
    assert_eq!(bad.len(), 69);
    txwatch_config::validate_stellar_address(bad)
        .expect_err("muxed address with bad checksum should be rejected");
}
