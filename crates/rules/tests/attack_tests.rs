//! Attack tests for `txwatch-rules` verifying defenses against numeric overflow,
//! symbol spoofing, and evasion attacks.

use chrono::{DateTime, Duration, Utc};
use txwatch_config::{AlertRule, ArgMatcher, DataMatcher, RuleConfig, RuleEntry};
use txwatch_rules::{
    evaluate, EnrichedTransaction, EvalContext, FunctionInvocation, HorizonTransaction,
    RateTracker,
};

fn dummy_tx(hash: &str, successful: bool, fee_charged: Option<&str>) -> HorizonTransaction {
    HorizonTransaction {
        hash: hash.into(),
        created_at: "2024-06-01T12:00:00Z".into(),
        successful,
        paging_token: "1000".into(),
        fee_charged: fee_charged.map(|s| s.into()),
        envelope_xdr: None,
        result_xdr: None,
        source_account: None,
        source_account_muxed: None,
        source_account_muxed_id: None,
        fee_account: None,
        fee_account_muxed: None,
        ledger: None,
        memo: None,
        memo_type: None,
        operation_count: None,
    }
}

fn test_ctx() -> EvalContext<'static> {
    EvalContext {
        label: "Escrow",
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        network: "testnet",
        network_id: "testnet".into(),
        horizon_base: "https://horizon-testnet.stellar.org",
        explorer_base: Some("https://stellar.expert/explorer/testnet"),
    }
}

#[test]
fn test_attack_overflow_amount_handled_safely() {
    // An amount above the total XLM supply is not representable, so
    // `from_horizon` discards it rather than letting it drive an alert.
    let raw = dummy_tx("overflow_tx", true, None);
    let enriched =
        EnrichedTransaction::from_horizon(raw, vec!["transfer".into()], Some(u64::MAX), None)
            .unwrap();
    assert_eq!(
        enriched.amount_stroops, None,
        "an impossible amount must be discarded"
    );

    let rules = vec![RuleConfig { enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::LargeTransfer {
            threshold_xlm: 10_000,
            threshold_stroops: 100_000_000_000,
            direction: "any".into(),
        },
        cooldown_seconds: None,
        cooldown_summary: false,
    }];
    let payloads = evaluate(&test_ctx(), &rules, &enriched, None);

    assert!(
        payloads.is_empty(),
        "LargeTransfer must not fire on a discarded amount"
    );
}

#[test]
fn test_attack_case_spoofing_admin_function() {
    // Attack trying to bypass AdminFunctionCalled rule using mixed-case invocation
    let raw = dummy_tx("admin_tx", true, None);
    let enriched =
        EnrichedTransaction::from_horizon(raw, vec!["Set_Admin".into()], None, None).unwrap();

    let rules = vec![RuleConfig { enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::AdminFunctionCalled {
            function_names: vec!["set_admin".into(), "upgrade".into()],
        },
        cooldown_seconds: None,
        cooldown_summary: false,
    }];
    let payloads = evaluate(&test_ctx(), &rules, &enriched, None);

    assert_eq!(
        payloads.len(),
        1,
        "AdminFunctionCalled must catch case variations of sensitive functions"
    );
}

#[test]
fn test_admin_function_called_label_preserves_configured_case() {
    // Issue #396: the alert label must show the configured function name with
    // its original casing, even though matching is case-insensitive.
    let raw = dummy_tx("admin_label_tx", true, None);
    let enriched =
        EnrichedTransaction::from_horizon(raw, vec!["setAdmin".into()], None, None).unwrap();

    let rules = vec![RuleConfig { enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::AdminFunctionCalled {
            function_names: vec!["setAdmin".into()],
        },
        cooldown_seconds: None,
        cooldown_summary: false,
    }];
    let payloads = evaluate(&test_ctx(), &rules, &enriched, None);
    assert_eq!(payloads.len(), 1, "mixed-case function must still match");

    let label = &payloads[0].rule_triggered;
    assert!(
        label.contains("setAdmin"),
        "label must preserve configured casing, got {label:?}"
    );
    assert!(
        !label.contains("setadmin"),
        "label must not lowercase the configured name, got {label:?}"
    );
}

#[test]
fn test_source_account_muxed_matches_muxed_entry() {
    // Issue #398: an `M…` entry must match the muxed source account, while
    // Horizon reports the base `G…` account in `source_account`.
    let muxed = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";
    let base = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

    let mut raw = dummy_tx("muxed_tx", true, None);
    raw.source_account = Some(base.into());
    raw.source_account_muxed = Some(muxed.into());
    raw.source_account_muxed_id = Some("1234".into());
    let enriched = EnrichedTransaction::from_horizon(raw, vec![], None, None).unwrap();

    let muxed_rules = vec![RuleConfig { enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::SourceAccount { mode: txwatch_config::SourceAccountMode::In, field: txwatch_config::SourceAccountField::Source, alert_unless: vec![], allow: vec![], deny: vec![],
            accounts: vec![muxed.into()],
        },
        cooldown_seconds: None,
        cooldown_summary: false,
    }];
    assert_eq!(
        evaluate(&test_ctx(), &muxed_rules, &enriched, None).len(),
        1,
        "M… entry must match the muxed source account"
    );

    let base_rules = vec![RuleConfig { enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::SourceAccount { mode: txwatch_config::SourceAccountMode::In, field: txwatch_config::SourceAccountField::Source, alert_unless: vec![], allow: vec![], deny: vec![],
            accounts: vec![base.into()],
        },
        cooldown_seconds: None,
        cooldown_summary: false,
    }];
    assert_eq!(
        evaluate(&test_ctx(), &base_rules, &enriched, None).len(),
        1,
        "G… entry must match the base source account"
    );

    let other_rules = vec![RuleConfig { enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::SourceAccount { mode: txwatch_config::SourceAccountMode::In, field: txwatch_config::SourceAccountField::Source, alert_unless: vec![], allow: vec![], deny: vec![],
            accounts: vec![
                "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"
                    .replace("MA7Q", "MB7Q"),
            ],
        },
        cooldown_seconds: None,
        cooldown_summary: false,
    }];
    assert!(
        evaluate(&test_ctx(), &other_rules, &enriched, None).is_empty(),
        "a different muxed address must not match"
    );
}

#[test]
fn test_attack_status_spoofing_transaction_failed() {
    // Ensure successful transaction cannot trick TransactionFailed rule into firing
    let raw = dummy_tx("success_tx", true, None);
    let enriched = EnrichedTransaction::from_horizon(raw, vec![], None, None).unwrap();

    let rules = vec![RuleConfig { enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::TransactionFailed,
        cooldown_seconds: None,
        cooldown_summary: false,
    }];
    let payloads = evaluate(&test_ctx(), &rules, &enriched, None);

    assert!(
        payloads.is_empty(),
        "TransactionFailed must never trigger on successful transactions"
    );
}

#[test]
fn test_attack_contract_upgraded_reports_wasm_hashes() {
    // An executable change must fire ContractUpgraded with old/new hashes.
    let raw = dummy_tx("upgrade_tx", true, None);
    let mut enriched = EnrichedTransaction::from_horizon(raw, vec![], None, None).unwrap();
    enriched.watched_contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    enriched.wasm_upgrade = Some(txwatch_rules::WasmUpgrade {
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        old_wasm_hash: Some(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        ),
        new_wasm_hash: Some(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        ),
    });

    let rules = vec![RuleConfig { enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::ContractUpgraded,
        cooldown_seconds: None,
        cooldown_summary: false,
    }];
    let payloads = evaluate(&test_ctx(), &rules, &enriched, None);
    assert_eq!(payloads.len(), 1, "ContractUpgraded must fire on upgrade");
    let payload = &payloads[0];
    assert_eq!(
        payload.old_wasm_hash.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        payload.new_wasm_hash.as_deref(),
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );

    // No upgrade recorded: rule must stay silent.
    enriched.wasm_upgrade = None;
    let payloads = evaluate(&test_ctx(), &rules, &enriched, None);
    assert!(
        payloads.is_empty(),
        "ContractUpgraded must not fire without an executable change"
    );
}

#[test]
fn test_attack_rule_level_webhook_secret_only_override() {
    // A rule that sets only `webhook_secret` (no `webhook_url`) must still have
    // its secret applied to the relevant destination(s) rather than being
    // silently discarded by the `(None, _)` match arm.
    let raw = dummy_tx("secret_only_tx", false, None);
    let enriched = EnrichedTransaction::from_horizon(raw, vec![], None, None).unwrap();

    let rule_secret = "rule-level-signing-key";
    let rules = vec![RuleEntry {
        rule: AlertRule::TransactionFailed,
        webhook_url: None,
        webhook_secret: Some(rule_secret.to_string()),
        severity: None,
        enabled: true,
    }];
    let ctx = EvalContext { network_id: "testnet".to_string(),      
        label: "Escrow",
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        network: "testnet",
        horizon_base: "https://horizon-testnet.stellar.org",
        explorer_base: Some("https://stellar.expert/explorer/testnet"),
    };

    let payloads = evaluate(&ctx, &rules, &enriched, None);
    assert_eq!(
        payloads.len(),
        1,
        "TransactionFailed must fire on failed tx"
    );

    let payload = &payloads[0];
    assert_eq!(
        payload.effective_webhook_secret.as_deref(),
        Some(rule_secret),
        "rule-level webhook_secret must be applied to payload even without webhook_url"
    );
}

// ── Issue #266: FunctionCalled argument matchers ─────────────────────────────

fn function_called(args: Vec<ArgMatcher>) -> RuleConfig {
    RuleConfig { cooldown_summary: false, enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::FunctionCalled {
            function_name: "transfer".into(),
            match_mode: Default::default(),
            args,
        },
        cooldown_seconds: None,
    }
}

fn enriched_with_args(hash: &str, function: &str, args: Vec<serde_json::Value>) -> EnrichedTransaction {
    let raw = dummy_tx(hash, true, None);
    EnrichedTransaction::from_horizon(raw, vec![function.into()], None, None)
        .unwrap()
        .with_invocations(vec![FunctionInvocation::from_parameters(
            function.into(),
            &args,
        )])
}

#[test]
fn test_function_called_arg_address_match() {
    let ctx = test_ctx();
    let to = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let rules = vec![function_called(vec![ArgMatcher {
        index: 1,
        eq: to.into(),
    }])];

    let matching = enriched_with_args(
        "addr_match",
        "transfer",
        vec![
            serde_json::json!({ "i128": "100" }),
            serde_json::json!({ "address": to }),
        ],
    );
    let payloads = evaluate(&ctx, &rules, &matching, None);
    assert_eq!(payloads.len(), 1, "address argument must match");
    assert_eq!(
        payloads[0].function_args[0].arg(1),
        Some(to),
        "decoded argument values must be included in the payload"
    );

    let non_matching = enriched_with_args(
        "addr_miss",
        "transfer",
        vec![
            serde_json::json!({ "i128": "100" }),
            serde_json::json!({ "address": "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" }),
        ],
    );
    assert!(
        evaluate(&ctx, &rules, &non_matching, None).is_empty(),
        "different address must not match"
    );
}

#[test]
fn test_function_called_arg_scalar_types_match() {
    let ctx = test_ctx();
    let rules = vec![function_called(vec![ArgMatcher {
        index: 0,
        eq: "42".into(),
    }])];

    for value in [
        serde_json::json!({ "u32": 42 }),
        serde_json::json!({ "i128": "42" }),
        serde_json::json!({ "symbol": "42" }),
        serde_json::json!({ "string": "42" }),
    ] {
        let tx = enriched_with_args("scalar_match", "transfer", vec![value.clone()]);
        assert_eq!(
            evaluate(&ctx, &rules, &tx, None).len(),
            1,
            "{value} must match"
        );
    }

    let miss = enriched_with_args("scalar_miss", "transfer", vec![serde_json::json!({ "u32": 43 })]);
    assert!(evaluate(&ctx, &rules, &miss, None).is_empty());
}

#[test]
fn test_function_called_arg_requires_decoded_invocation() {
    // Without decoded parameters an argument constraint cannot be proven, so
    // the rule must not fire on the function name alone.
    let ctx = test_ctx();
    let rules = vec![function_called(vec![ArgMatcher {
        index: 0,
        eq: "admin".into(),
    }])];
    let raw = dummy_tx("no_params", true, None);
    let tx = EnrichedTransaction::from_horizon(raw, vec!["transfer".into()], None, None).unwrap();
    assert!(evaluate(&ctx, &rules, &tx, None).is_empty());

    let missing_index = enriched_with_args("short_args", "transfer", vec![]);
    assert!(evaluate(&ctx, &rules, &missing_index, None).is_empty());
}

// ── Issue #267: Rate rules ───────────────────────────────────────────────────

fn rate_rule(count: u64, window_seconds: u64) -> Vec<RuleConfig> {
    vec![RuleConfig { cooldown_summary: false, enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::Rate {
            rule: Box::new(RuleEntry {
                enabled: true,
                webhook_url: None,
                webhook_secret: None,
                severity: None,
                rule: AlertRule::TransactionFailed,
            }),
            count,
            window_seconds,
        },
        cooldown_seconds: None,
    }]
}

fn failed(hash: &str) -> EnrichedTransaction {
    EnrichedTransaction::from_horizon(dummy_tx(hash, false, None), vec![], None, None).unwrap()
}

fn t0() -> DateTime<Utc> {
    "2024-06-01T12:00:00Z".parse().unwrap()
}

#[test]
fn test_rate_rule_threshold_and_window_expiry() {
    let ctx = test_ctx();
    let rules = rate_rule(3, 300);
    let mut rates = RateTracker::new();
    let now = t0();

    // Rate rules never fire through the stateless evaluator.
    assert!(evaluate(&ctx, &rules, &failed("f0"), None).is_empty());

    // Two failures: below threshold.
    assert!(rates.evaluate(&ctx, &rules, &failed("f1"), now).is_empty());
    assert!(rates.evaluate(&ctx, &rules, &failed("f2"), now).is_empty());

    // Third failure within the window breaches the threshold.
    let payloads = rates.evaluate(&ctx, &rules, &failed("f3"), now);
    assert_eq!(payloads.len(), 1, "one alert per breach");
    assert_eq!(payloads[0].observed_count, Some(3));
    assert_eq!(payloads[0].rule_type, "Rate");

    // A successful transaction does not count toward the rate.
    let ok = EnrichedTransaction::from_horizon(dummy_tx("ok1", true, None), vec![], None, None)
        .unwrap();
    assert!(rates
        .evaluate(&ctx, &rules, &ok, now + Duration::seconds(10))
        .is_empty());

    // The breach cleared the window; old failures also expire with time.
    let later = now + Duration::seconds(301);
    assert!(rates.evaluate(&ctx, &rules, &failed("f4"), later).is_empty());
    assert!(rates.evaluate(&ctx, &rules, &failed("f5"), later).is_empty());
    assert!(
        rates
            .evaluate(&ctx, &rules, &failed("f6"), later + Duration::seconds(300))
            .is_empty(),
        "failures outside the window must not count"
    );
}

#[test]
fn test_rate_rule_per_contract_isolation() {
    let rules = rate_rule(2, 60);
    let mut rates = RateTracker::new();
    let now = t0();

    let ctx_a = test_ctx();
    let mut ctx_b = test_ctx();
    ctx_b.contract_id = "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    assert!(rates.evaluate(&ctx_a, &rules, &failed("a1"), now).is_empty());
    // Contract B's first failure must not be influenced by contract A's state.
    assert!(rates.evaluate(&ctx_b, &rules, &failed("b1"), now).is_empty());
    // Contract A's second failure breaches its own window.
    assert_eq!(rates.evaluate(&ctx_a, &rules, &failed("a2"), now).len(), 1);
    // Contract B breaches only on its own second failure.
    assert_eq!(rates.evaluate(&ctx_b, &rules, &failed("b2"), now).len(), 1);
}

// ── Issue #268: Memo rules ───────────────────────────────────────────────────

fn memo_rule(memo_type: Option<&str>, equals: Option<&str>, prefix: Option<&str>) -> Vec<RuleConfig> {
    vec![RuleConfig { cooldown_summary: false, enabled: true, webhook_url: None, webhook_secret: None, severity: None,
        rule: AlertRule::Memo {
            memo_type: memo_type.map(Into::into),
            equals: equals.map(Into::into),
            prefix: prefix.map(Into::into),
        },
        cooldown_seconds: None,
    }]
}

#[test]
fn test_memo_rule_exact_and_prefix() {
    let ctx = test_ctx();
    let mut matching =
        EnrichedTransaction::from_horizon(dummy_tx("memo_exact", true, None), vec![], None, None)
            .unwrap();
    matching.memo = Some("EXCHANGE-123".into());
    matching.memo_type = Some("text".into());

    let exact = memo_rule(Some("text"), Some("EXCHANGE-123"), None);
    assert_eq!(evaluate(&ctx, &exact, &matching, None).len(), 1);

    let mut wrong_type = matching.clone();
    wrong_type.memo_type = Some("id".into());
    assert!(
        evaluate(&ctx, &exact, &wrong_type, None).is_empty(),
        "memo_type must match"
    );

    let prefix = memo_rule(None, None, Some("EXCHANGE-"));
    assert_eq!(evaluate(&ctx, &prefix, &matching, None).len(), 1);

    let mut non_matching = matching.clone();
    non_matching.memo = Some("OTHER-1".into());
    assert!(evaluate(&ctx, &prefix, &non_matching, None).is_empty());

    let mut no_memo = matching.clone();
    no_memo.memo = None;
    assert!(evaluate(&ctx, &prefix, &no_memo, None).is_empty());
}
