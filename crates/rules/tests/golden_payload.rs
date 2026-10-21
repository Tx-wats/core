//! Golden-file test for `AlertPayload` JSON serialization (issue #58).
//!
//! The committed file `fixtures/alert_payload_golden.json` captures the
//! canonical shape of an `AlertPayload` at `schema_version = 1`.  This test
//! will fail — intentionally — whenever a field is added, removed, renamed, or
//! its serialised representation changes, forcing contributors to either update
//! the golden file (for additive/compatible changes) or bump `schema_version`
//! (for breaking changes) before merging.
//!
//! ## How to update the golden file
//!
//! If your change is **additive** (a new optional field) and backward-compatible,
//! run the test once with `UPDATE_GOLDEN=1` to regenerate it:
//!
//! ```sh
//! UPDATE_GOLDEN=1 cargo test -p txwatch-rules golden_payload
//! ```
//!
//! If your change is **breaking** (removing or renaming a field), bump
//! `schema_version` in `AlertPayload` and `evaluate()` before regenerating.

use std::collections::BTreeMap;

use serde_json::Value;
use txwatch_rules::AlertPayload;

/// The path to the golden fixture, relative to the workspace root.
const GOLDEN_PATH: &str = "crates/rules/tests/fixtures/alert_payload_golden.json";

/// A deterministic `AlertPayload` with every always-present field filled in.
/// Optional fields (`ledger`, `source_account`, `memo`, `memo_type`,
/// `operation_count`) are intentionally left as `None` so they are omitted from
/// the serialised output — the golden file documents the minimal required shape.
fn golden_payload() -> AlertPayload {
    AlertPayload {
        schema_version: 1,
        alert_id: "a3f1bc20e94d77c1a3f1bc20e94d77c1".into(),
        label: "My Escrow Contract".into(),
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        network: "testnet".into(),
        rule_type: "LargeTransfer".into(),
        rule_triggered: "LargeTransfer(>=10000XLM)".into(),
        transaction_hash: "abc123deadbeef".into(),
        function_name: Some("transfer".into()),
        function_names: vec!["transfer".into()],
        amount_xlm: Some(15000),
        amount_stroops: None,
        amount_xlm_decimal: None,
        fee_charged_stroops: Some(50000),
        timestamp: 1_705_316_096,
        timestamp_iso: "2024-01-15T12:00:00Z".into(),
        horizon_link: "https://horizon-testnet.stellar.org/transactions/abc123deadbeef".into(),
        explorer_link: "https://stellar.expert/explorer/testnet/tx/abc123deadbeef".into(),
        effective_webhook_url: None,
        effective_webhook_secret: None,
        severity: None,
        ledger: None,
        source_account: None,
        fee_account: None,
        memo: None,
        memo_type: None,
        operation_count: None,
        old_wasm_hash: None,
        new_wasm_hash: None,
        resolved: false,
        matched_events: vec![],
        suppressed_count: 0,
        test: false,
        enrichment_incomplete: false,
    }
}

#[test]
fn alert_payload_golden_file_matches_serialization() {
    let payload = golden_payload();
    let serialized: Value =
        serde_json::to_value(&payload).expect("AlertPayload should serialize to JSON");

    // Normalise both sides to BTreeMap for stable key ordering in diffs.
    let actual: BTreeMap<String, Value> =
        serde_json::from_value(serialized.clone()).expect("serialized value should be an object");

    // Allow regenerating the golden file in CI-friendly mode.
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        let pretty = serde_json::to_string_pretty(&actual).expect("pretty-print actual payload");
        // Resolve path from workspace root (the directory containing Cargo.toml).
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent() // crates/rules → crates
            .and_then(|p| p.parent()) // crates → workspace root
            .expect("workspace root not found");
        let golden_path = workspace_root.join(GOLDEN_PATH);
        std::fs::write(&golden_path, format!("{}\n", pretty)).unwrap_or_else(|e| {
            panic!(
                "failed to write golden file {}: {}",
                golden_path.display(),
                e
            )
        });
        eprintln!("Updated golden file: {}", golden_path.display());
        return;
    }

    let golden_str = include_str!("fixtures/alert_payload_golden.json");
    let expected: BTreeMap<String, Value> =
        serde_json::from_str(golden_str).expect("golden file should be valid JSON");

    assert_eq!(
        actual, expected,
        "\nAlertPayload serialization differs from golden file '{GOLDEN_PATH}'.\n\
         If this change is intentional:\n\
         - For additive/backward-compatible changes: run `UPDATE_GOLDEN=1 cargo test -p txwatch-rules golden_payload` to regenerate.\n\
         - For breaking changes (field removals or renames): bump `schema_version` in AlertPayload first, then regenerate.\n"
    );
}

/// Verify that the golden payload round-trips through deserialization without loss.
#[test]
fn alert_payload_golden_round_trips() {
    let golden_str = include_str!("fixtures/alert_payload_golden.json");
    let from_file: AlertPayload =
        serde_json::from_str(golden_str).expect("golden file should deserialize as AlertPayload");
    assert_eq!(
        from_file,
        golden_payload(),
        "round-trip deserialization must be lossless"
    );
}
