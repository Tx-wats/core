use std::io::Write;
use tempfile::NamedTempFile;
use txwatch_config::{
    encode_account_id, encode_contract_id, load_from_path, parse_toml_str, validate_contract_id,
    validate_stellar_address, AlertFormat, AlertRule, AlertSeverity, DataMatcher, MatchOperator,
    RuleCombineMode, TransferDirection,
};

const CONTRACT_HEADER: &str = r#"
[network]
kind = "testnet"

[[contracts]]
id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
label = "token"
webhook_url = "https://example.com/hook"
"#;

#[test]
fn parses_valid_config_with_all_rule_variants() {
    let cid = encode_contract_id(&[42u8; 32]);
    let acct = encode_account_id(&[7u8; 32]);
    let toml = format!(
        r#"
[network]
kind = "testnet"
poll_interval_ms = 2000
page_limit = 50

[server]
bind = "127.0.0.1:9090"
metrics_path = "/metrics"
admin_token = "tok_test"

[storage]
sqlite_path = "./test.db"
alert_retention_days = 14

[webhook]
timeout_ms = 5000
max_attempts = 3
initial_backoff_ms = 200
max_backoff_ms = 2000
allow_private_ips = true

[[contracts]]
id = "{cid}"
label = "soroswap-router"
webhook_url = "http://127.0.0.1:8888/alerts"
webhook_secret = "whsec_123"
webhook_format = "slack"
start_ledger = 12345

[contracts.tags]
env = "staging"
team = "defi"

[[contracts.rules]]
type = "AnyTransaction"
cooldown_seconds = 10
severity = "info"

[[contracts.rules]]
type = "FailedTransaction"
severity = "critical"

[[contracts.rules]]
type = "FunctionCall"
function = "swap_exact_tokens_for_tokens"
arg_contains = "USDC"

[[contracts.rules]]
type = "EventEmitted"
topic_contains = "swap"
data_contains = "1000000"

[[contracts.rules]]
type = "HighFee"
threshold_stroops = 500000

[[contracts.rules]]
type = "LargeTransfer"
threshold_xlm = 250
asset = "XLM"

[[contracts.rules]]
type = "SourceAccount"
account = "{acct}"
"#
    );

    let cfg = parse_toml_str(&toml).expect("valid config should parse");
    assert_eq!(
        cfg.network.resolved_horizon_url(),
        Some("https://horizon-testnet.stellar.org")
    );
    assert_eq!(cfg.contracts.len(), 1);
    let c = &cfg.contracts[0];
    assert_eq!(c.rules.len(), 7);
    assert_eq!(c.webhook_format, AlertFormat::Slack);
    assert_eq!(c.tags.get("env").map(String::as_str), Some("staging"));
    assert_eq!(c.rules[1].severity, AlertSeverity::Critical);
    assert_eq!(
        c.rules[5].rule.effective_threshold_stroops(),
        Some(2_500_000_000)
    );
}

#[test]
fn rejects_duplicate_contract_ids_and_labels() {
    let cid = encode_contract_id(&[5u8; 32]);
    let toml = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "dup"
webhook_url = "https://example.com/a"

[[contracts.rules]]
type = "AnyTransaction"

[[contracts]]
id = "{cid}"
label = "dup"
webhook_url = "https://example.com/b"

[[contracts.rules]]
type = "AnyTransaction"
"#
    );
    let err = parse_toml_str(&toml).unwrap_err().to_string();
    assert!(err.contains("duplicates contracts[0]"));
    assert!(err.contains("labels must be unique"));
}

#[test]
fn custom_network_requires_url_and_passphrase() {
    let cid = encode_contract_id(&[3u8; 32]);
    let toml = format!(
        r#"
[network]
kind = "custom"

[[contracts]]
id = "{cid}"
label = "c"
webhook_url = "https://example.com/a"

[[contracts.rules]]
type = "AnyTransaction"
"#
    );
    let err = parse_toml_str(&toml).unwrap_err().to_string();
    assert!(err.contains("network.horizon_url is required"));
    assert!(err.contains("network.network_passphrase is required"));
}

#[test]
fn template_format_requires_template_body() {
    let cid = encode_contract_id(&[8u8; 32]);
    let toml = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "c"
webhook_url = "https://example.com/a"
webhook_format = "template"

[[contracts.rules]]
type = "AnyTransaction"
"#
    );
    let err = parse_toml_str(&toml).unwrap_err().to_string();
    assert!(err.contains("no template string was provided"));
}

#[test]
fn loads_from_disk_file() {
    let cid = encode_contract_id(&[12u8; 32]);
    let mut tmp = NamedTempFile::new().unwrap();
    write!(
        tmp,
        r#"
[network]
kind = "mainnet"

[[contracts]]
id = "{cid}"
label = "mainnet-pool"
webhook_url = "https://hooks.example.org/pool"

[[contracts.rules]]
type = "FailedTransaction"
"#
    )
    .unwrap();

    let cfg = load_from_path(tmp.path()).expect("file should load");
    assert_eq!(
        cfg.network.resolved_horizon_url(),
        Some("https://horizon.stellar.org")
    );
}

#[test]
fn composite_and_not_rules_parse_and_validate() {
    let cid = encode_contract_id(&[19u8; 32]);
    let toml = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "amm-router"
webhook_url = "https://hooks.example.org/amm"

[[contracts.rules]]
type = "Composite"
mode = "all"
severity = "critical"

  [[contracts.rules.rules]]
  type = "FunctionCall"
  function = "swap"

  [[contracts.rules.rules]]
  type = "Not"

    [contracts.rules.rules.rule]
    type = "FailedTransaction"

[[contracts.rules]]
type = "RateSpike"
max_transactions = 25
window_seconds = 60

[[contracts.rules]]
type = "Inactivity"
silence_seconds = 3600
repeat_interval_seconds = 900
"#
    );

    let cfg = parse_toml_str(&toml).expect("composite/rate_spike/inactivity config should parse");
    let rules = &cfg.contracts[0].rules;
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].severity, AlertSeverity::Critical);
    match &rules[0].rule {
        AlertRule::Composite { mode, rules } => {
            assert_eq!(*mode, RuleCombineMode::All);
            assert_eq!(rules.len(), 2);
            assert!(matches!(rules[1], AlertRule::Not { .. }));
        }
        other => panic!("expected Composite rule, got {other:?}"),
    }
    assert!(rules[0].rule.label().contains("FunctionCall:swap"));
    assert!(rules[0].rule.label().contains("!(FailedTransaction)"));

    let empty_composite = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "bad"
webhook_url = "https://hooks.example.org/amm"

[[contracts.rules]]
type = "Composite"
rules = [{{ type = "AnyTransaction" }}]
"#
    );
    let err = parse_toml_str(&empty_composite).unwrap_err().to_string();
    assert!(err.contains("at least 2 child rules"));
}

#[test]
fn multi_webhook_fanout_and_mute_until_validate() {
    let cid = encode_contract_id(&[27u8; 32]);
    let toml = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "treasury"
mute_until = "2099-01-01T00:00:00Z"

[contracts.rate_limit]
max_alerts = 10
window_seconds = 60

[[contracts.webhooks]]
url = "https://hooks.slack.com/services/T000/B000/XXXX"
format = "slack"
min_severity = "warning"

[[contracts.webhooks]]
url = "https://pager.example.org/events"
format = "json"
secret = "shhh"
min_severity = "critical"

[contracts.webhooks.headers]
X-Routing-Key = "rk_live_123"

[[contracts.rules]]
type = "AnyTransaction"
"#
    );

    let cfg = parse_toml_str(&toml).expect("multi-webhook config should parse");
    let c = &cfg.contracts[0];
    assert!(c.is_muted());
    let endpoints = c.resolved_webhooks();
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0].min_severity, Some(AlertSeverity::Warning));
    assert_eq!(endpoints[1].min_severity, Some(AlertSeverity::Critical));
    assert_eq!(
        endpoints[1]
            .headers
            .get("X-Routing-Key")
            .map(String::as_str),
        Some("rk_live_123")
    );
    assert_eq!(c.rate_limit.as_ref().unwrap().max_alerts, 10);

    let bad_mute = format!(
        r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "bad-mute"
webhook_url = "https://example.com/hook"
mute_until = "not-a-timestamp"

[[contracts.rules]]
type = "AnyTransaction"
"#
    );
    let err = parse_toml_str(&bad_mute).unwrap_err().to_string();
    assert!(err.contains("RFC-3339"));
}

#[test]
fn large_transfer_direction_parses_and_validates() {
    let toml = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "LargeTransfer"
threshold_xlm = 100
direction = "in"
"#
    );
    let cfg = parse_toml_str(&toml).expect("valid config");
    match &cfg.contracts[0].rules[0].rule {
        AlertRule::LargeTransfer {
            direction,
            threshold_xlm,
            ..
        } => {
            assert_eq!(*direction, TransferDirection::In);
            assert_eq!(*threshold_xlm, Some(100));
        }
        other => panic!("unexpected rule: {other:?}"),
    }
}

#[test]
fn large_transfer_rejects_unknown_direction() {
    let toml = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "LargeTransfer"
threshold_stroops = 1000
direction = "sideways"
"#
    );
    assert!(parse_toml_str(&toml).is_err());
}

#[test]
fn event_emitted_data_matchers_parse_and_validate() {
    let toml = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "EventEmitted"
topics = ["transfer", "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"]
data_match = [
  {{ pointer = "/amount", op = "gte", value = "1000" }},
  {{ pointer = "/memo", op = "regex", value = "^inv-[0-9]+$" }},
  {{ pointer = "/flag", op = "exists" }},
]
"#
    );
    let cfg = parse_toml_str(&toml).expect("valid config");
    match &cfg.contracts[0].rules[0].rule {
        AlertRule::EventEmitted {
            topics, data_match, ..
        } => {
            assert_eq!(topics.len(), 2);
            assert_eq!(data_match.len(), 3);
            assert_eq!(
                data_match[0],
                DataMatcher {
                    pointer: "/amount".to_string(),
                    op: MatchOperator::Gte,
                    value: Some("1000".to_string()),
                }
            );
            assert_eq!(data_match[1].op, MatchOperator::Regex);
            assert_eq!(data_match[2].op, MatchOperator::Exists);
        }
        other => panic!("unexpected rule: {other:?}"),
    }
}

#[test]
fn event_emitted_rejects_invalid_data_matcher_regex_and_pointer() {
    let bad_regex = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "EventEmitted"
data_match = [{{ pointer = "/memo", op = "regex", value = "[unclosed" }}]
"#
    );
    assert!(parse_toml_str(&bad_regex).is_err());

    let bad_pointer = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "EventEmitted"
data_match = [{{ pointer = "missing_leading_slash", op = "eq", value = "1" }}]
"#
    );
    assert!(parse_toml_str(&bad_pointer).is_err());

    let bad_numeric = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "EventEmitted"
data_match = [{{ pointer = "/amount", op = "gt", value = "not-a-number" }}]
"#
    );
    assert!(parse_toml_str(&bad_numeric).is_err());
}

#[test]
fn source_account_supports_multiple_accounts_and_muxed_flag() {
    let toml = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "SourceAccount"
accounts = [
  "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7",
  "MAAAAAAAAAAAAAB7BQ2L7E5NBWMXDUCMZSIPOBKRDSBYVLMXGSSKF6YNPIB7Y77ITLVL6",
]
match_muxed_base = true
"#
    );
    let cfg = parse_toml_str(&toml).expect("valid config");
    match &cfg.contracts[0].rules[0].rule {
        AlertRule::SourceAccount {
            accounts,
            match_muxed_base,
            ..
        } => {
            assert_eq!(accounts.len(), 2);
            assert!(*match_muxed_base);
        }
        other => panic!("unexpected rule: {other:?}"),
    }
}

#[test]
fn strkey_validators_accept_valid_and_reject_corrupt() {
    assert!(validate_contract_id(
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
    )
    .is_ok());
    assert!(validate_contract_id(
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC5"
    )
    .is_err());

    assert!(validate_stellar_address(
        "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"
    )
    .is_ok());
    assert!(validate_stellar_address(
        "MAAAAAAAAAAAAAB7BQ2L7E5NBWMXDUCMZSIPOBKRDSBYVLMXGSSKF6YNPIB7Y77ITLVL6"
    )
    .is_ok());
    assert!(validate_stellar_address(
        "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN8"
    )
    .is_err());
}

#[test]
fn high_fee_rule_parses_both_threshold_units_and_rejects_invalid() {
    let stroops_toml = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "HighFee"
threshold_stroops = 250000
"#
    );
    let cfg = parse_toml_str(&stroops_toml).expect("stroops config");
    assert_eq!(
        cfg.contracts[0].rules[0]
            .rule
            .effective_threshold_stroops(),
        Some(250_000)
    );

    let xlm_toml = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "HighFee"
threshold_xlm = 0.5
"#
    );
    let cfg = parse_toml_str(&xlm_toml).expect("xlm config");
    assert_eq!(
        cfg.contracts[0].rules[0]
            .rule
            .effective_threshold_stroops(),
        Some(5_000_000)
    );

    let both_toml = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "HighFee"
threshold_stroops = 100
threshold_xlm = 0.5
"#
    );
    assert!(parse_toml_str(&both_toml).is_err());

    let neither_toml = format!(
        r#"{CONTRACT_HEADER}
[[contracts.rules]]
type = "HighFee"
"#
    );
    assert!(parse_toml_str(&neither_toml).is_err());
}