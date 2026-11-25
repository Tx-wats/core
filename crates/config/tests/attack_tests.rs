//! Attack tests for `txwatch-config` verifying defenses against malicious configurations,
//! integer overflow attempts, injection attacks, and invalid contract parameters.

use txwatch_config::{
    AlertRule, ArgMatcher, RuleConfig, RuleEntry, WatchedContract, MAX_ARG_VALUE_LEN,
    MAX_FUNCTION_ARGS,
};

#[test]
fn test_attack_oversized_transfer_threshold_rejected() {
    let mut rule = AlertRule::LargeTransfer {
        threshold_xlm: 2_000_000_000, // Exceeds MAX_LARGE_TRANSFER_THRESHOLD_XLM (1_000_000_000)
        threshold_stroops: 0,         // Filled in by `validate`
        direction: "any".into(),
    };
    let result = rule.validate("attack-target");
    assert!(
        result.is_err(),
        "Validator must reject absurdly large threshold exceeding bound"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("LargeTransfer threshold_xlm must be <="));
}

#[test]
fn test_attack_zero_threshold_rejected() {
    let mut rule = AlertRule::LargeTransfer {
        threshold_xlm: 0,
        threshold_stroops: 0,
        direction: "any".into(),
    };
    let result = rule.validate("attack-target");
    assert!(result.is_err(), "Validator must reject zero threshold");
}

#[test]
fn test_attack_symbol_injection_rejected() {
    let mut rule = AlertRule::FunctionCalled {
        function_name: "drop table users;--".into(),
        match_mode: Default::default(),
        args: vec![],
    };
    let result = rule.validate("attack-target");
    assert!(
        result.is_err(),
        "Validator must reject SQL/command-like special characters in Soroban symbol"
    );

    let mut rule_long = AlertRule::FunctionCalled {
        function_name: "a".repeat(33), // Max 32 chars
        match_mode: Default::default(),
        args: vec![],
    };
    let result_long = rule_long.validate("attack-target");
    assert!(
        result_long.is_err(),
        "Validator must reject symbols longer than 32 characters"
    );
}

#[test]
fn test_attack_contract_address_forgery_rejected() {
    let mut contract = WatchedContract {
        label: "Malicious Contract".into(),
        contract_id: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(), // Starts with 'G' (account), not 'C' (contract)
        network: txwatch_config::Network::Testnet,
        rules: vec![RuleConfig {
            rule: AlertRule::AnyTransaction,
            cooldown_seconds: None,
            cooldown_summary: false,
        }],
        webhook_url: Some("https://example.com/webhook".into()),
        webhook_secret: None,
        webhook_format: Default::default(),
        webhook_headers: Default::default(),
        webhook_routing_key: None,
        webhooks: vec![],
        poll_interval_seconds: None,
        enabled: true,
        soroban_rpc_url: None,
        batch_alerts: false,
        horizon_base_url_override: None,
    };
    let result = contract.validate();
    assert!(
        result.is_err(),
        "Validator must reject non-C contract address prefixes"
    );
}

#[test]
fn test_attack_control_character_injection_rejected() {
    let mut contract = WatchedContract {
        label: "Exploit\r\nHeader-Injection: true".into(),
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        network: txwatch_config::Network::Testnet,
        rules: vec![RuleConfig {
            rule: AlertRule::AnyTransaction,
            cooldown_seconds: None,
            cooldown_summary: false,
        }],
        webhook_url: Some("https://example.com/webhook".into()),
        webhook_secret: None,
        webhook_format: Default::default(),
        webhook_headers: Default::default(),
        webhook_routing_key: None,
        webhooks: vec![],
        poll_interval_seconds: None,
        enabled: true,
        soroban_rpc_url: None,
        batch_alerts: false,
        horizon_base_url_override: None,
    };
    let result = contract.validate();
    assert!(
        result.is_err(),
        "Validator must reject control character injection in label"
    );
}

fn function_called_with_args(args: Vec<ArgMatcher>) -> AlertRule {
    AlertRule::FunctionCalled {
        function_name: "transfer".into(),
        match_mode: Default::default(),
        args,
    }
}

fn arg(index: u32, eq: &str) -> ArgMatcher {
    ArgMatcher {
        index,
        eq: eq.into(),
    }
}

#[test]
fn test_attack_function_args_duplicate_or_excess_rejected() {
    let mut rule_dup = function_called_with_args(vec![arg(1, "GABC"), arg(1, "GDEF")]);
    assert!(
        rule_dup.validate("attack-target").is_err(),
        "Validator must reject duplicate argument indices"
    );

    let too_many = (0..=MAX_FUNCTION_ARGS as u32).map(|i| arg(i, "x")).collect();
    let mut rule_many = function_called_with_args(too_many);
    assert!(
        rule_many.validate("attack-target").is_err(),
        "Validator must reject more than MAX_FUNCTION_ARGS matchers"
    );
}

#[test]
fn test_attack_function_args_empty_or_oversized_value_rejected() {
    let mut rule_empty = function_called_with_args(vec![arg(0, "   ")]);
    assert!(
        rule_empty.validate("attack-target").is_err(),
        "Validator must reject an empty expected value"
    );

    let mut rule_long =
        function_called_with_args(vec![arg(0, &"a".repeat(MAX_ARG_VALUE_LEN + 1))]);
    assert!(
        rule_long.validate("attack-target").is_err(),
        "Validator must reject an oversized expected value"
    );

    let mut rule_ok = function_called_with_args(vec![arg(0, " GABC ")]);
    rule_ok.validate("attack-target").unwrap();
    let AlertRule::FunctionCalled { args, .. } = &rule_ok else {
        unreachable!()
    };
    assert_eq!(args[0].eq, "GABC", "expected values are trimmed");
}

fn any_transaction_entry() -> Box<RuleEntry> {
    Box::new(RuleEntry {
        enabled: true,
        webhook_url: None,
        webhook_secret: None,
        severity: None,
        rule: AlertRule::AnyTransaction,
    })
}

#[test]
fn test_attack_rate_rule_invalid_parameters_rejected() {
    let mut rule_zero_count = AlertRule::Rate {
        rule: any_transaction_entry(),
        count: 0,
        window_seconds: 300,
    };
    let result_zero_count = rule_zero_count.validate("attack-target");
    assert!(
        result_zero_count.is_err(),
        "Validator must reject a Rate rule with zero count"
    );

    let mut rule_zero_window = AlertRule::Rate {
        rule: any_transaction_entry(),
        count: 10,
        window_seconds: 0,
    };
    let result_zero_window = rule_zero_window.validate("attack-target");
    assert!(
        result_zero_window.is_err(),
        "Validator must reject a Rate rule with zero window"
    );

    let mut rule_huge_window = AlertRule::Rate {
        rule: any_transaction_entry(),
        count: 10,
        window_seconds: u64::MAX,
    };
    let result_huge_window = rule_huge_window.validate("attack-target");
    assert!(
        result_huge_window.is_err(),
        "Validator must reject a Rate rule with an out-of-range window"
    );
}

#[test]
fn test_attack_memo_rule_invalid_parameters_rejected() {
    let mut rule_both = AlertRule::Memo {
        memo_type: None,
        equals: Some("12345".into()),
        prefix: Some("12".into()),
    };
    let result_both = rule_both.validate("attack-target");
    assert!(
        result_both.is_err(),
        "Validator must reject a Memo rule with both equals and prefix"
    );

    let mut rule_neither = AlertRule::Memo {
        memo_type: None,
        equals: None,
        prefix: None,
    };
    let result_neither = rule_neither.validate("attack-target");
    assert!(
        result_neither.is_err(),
        "Validator must reject a Memo rule with neither equals nor prefix"
    );

    let mut rule_bad_type = AlertRule::Memo {
        memo_type: Some("bogus".into()),
        equals: Some("12345".into()),
        prefix: None,
    };
    let result_bad_type = rule_bad_type.validate("attack-target");
    assert!(
        result_bad_type.is_err(),
        "Validator must reject an unknown memo_type"
    );
    // ── Issue #390: DataMatcher rejects unknown / typo'd keys ───────────────────

#[test]
fn data_matcher_rejects_typo_pointer_key() {
    // `path` is a typo for `pointer`; before #390 this silently deserialised
    // with `pointer = ""` (whole-body match) and the rule matched every event.
    let cid = encode_contract_id(&[70u8; 32]);
    let bad = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "typo-pointer"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "EventEmitted"
topic = "transfer"
data = [{{ path = "/amount", op = "gte", value = "100" }}]
"#
    );
    let err = parse_toml_str(&bad).unwrap_err().to_string();
    assert!(
        err.contains("unknown field") || err.contains("path"),
        "expected an unknown-field error mentioning 'path', got: {err}"
    );
    assert!(
        err.contains("pointer"),
        "error should suggest 'pointer' as the valid key, got: {err}"
    );
}

#[test]
fn data_matcher_rejects_typo_op_key() {
    let cid = encode_contract_id(&[71u8; 32]);
    let bad = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "typo-op"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "EventEmitted"
topic = "transfer"
data = [{{ pointer = "/amount", oper = "gte", value = "100" }}]
"#
    );
    let err = parse_toml_str(&bad).unwrap_err().to_string();
    assert!(
        err.contains("unknown field") || err.contains("oper"),
        "expected an unknown-field error mentioning 'oper', got: {err}"
    );
}

#[test]
fn data_matcher_rejects_typo_value_key() {
    let cid = encode_contract_id(&[72u8; 32]);
    let bad = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "typo-value"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "EventEmitted"
topic = "transfer"
data = [{{ pointer = "/amount", op = "gte", valu = "100" }}]
"#
    );
    let err = parse_toml_str(&bad).unwrap_err().to_string();
    assert!(
        err.contains("unknown field") || err.contains("valu"),
        "expected an unknown-field error mentioning 'valu', got: {err}"
    );
}

#[test]
fn data_matcher_requires_op() {
    let cid = encode_contract_id(&[73u8; 32]);
    let bad = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "missing-op"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "EventEmitted"
topic = "transfer"
data = [{{ pointer = "/amount", value = "100" }}]
"#
    );
    let err = parse_toml_str(&bad).unwrap_err().to_string();
    assert!(
        err.contains("missing field") && err.contains("op"),
        "expected a missing-field error for 'op', got: {err}"
    );
}

#[test]
fn data_matcher_requires_value_for_comparison_operators() {
    // `value` is optional at the type level (Exists needs no value) but
    // validation rejects a comparison operator without it.
    let cid = encode_contract_id(&[74u8; 32]);
    let bad = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "missing-value"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "EventEmitted"
topic = "transfer"
data = [{{ pointer = "/amount", op = "gte" }}]
"#
    );
    let err = parse_toml_str(&bad).unwrap_err().to_string();
    assert!(
        err.contains("value is required"),
        "expected 'value is required', got: {err}"
    );
}

#[test]
fn data_matcher_exists_operator_still_needs_no_value() {
    // Regression guard: deny_unknown_fields / removing serde(default) on `op`
    // must not break the legitimate `Exists` matcher with no value.
    let cid = encode_contract_id(&[75u8; 32]);
    let ok = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "exists"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "EventEmitted"
topic = "transfer"
data = [{{ pointer = "/amount", op = "exists" }}]
"#
    );
    parse_toml_str(&ok).expect("Exists matcher without a value must validate");
}

#[test]
fn data_matcher_rejects_unknown_field_even_with_valid_others() {
    // A stray extra key alongside otherwise-valid fields must fail.
    let cid = encode_contract_id(&[76u8; 32]);
    let bad = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "extra-key"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "EventEmitted"
topic = "transfer"
data = [{{ pointer = "/amount", op = "gte", value = "100", note = "x" }}]
"#
    );
    let err = parse_toml_str(&bad).unwrap_err().to_string();
    assert!(
        err.contains("unknown field") || err.contains("note"),
        "expected an unknown-field error mentioning 'note', got: {err}"
    );
}
}
