//! Throughput benchmark for [`txwatch_rules::evaluate`]: the poller runs it once
//! per transaction, so the per-call cost matters more than anything else in the
//! rules crate.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use txwatch_config::{AlertRule, RuleEntry};
use txwatch_rules::{evaluate, EnrichedTransaction, EvalContext, RateTracker};

fn tx() -> EnrichedTransaction {
    EnrichedTransaction::from_horizon(
        txwatch_rules::HorizonTransaction {
            hash: "a".repeat(64),
            created_at: "2024-01-01T00:00:00Z".into(),
            successful: true,
            paging_token: "1".into(),
            envelope_xdr: None,
            result_xdr: None,
            ledger: Some(1),
            source_account: Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()),
            fee_account: None,
            source_account_muxed: None,
            source_account_muxed_id: None,
            fee_account_muxed: None,
            fee_charged: Some("100".into()),
            memo: None,
            memo_type: None,
            operation_count: Some(1),
        },
        vec!["transfer".into()],
        Some(1_000_000),
        Some(100),
    )
    .expect("fixture is well formed")
}

fn rules() -> Vec<RuleEntry> {
    vec![RuleEntry {
        enabled: true,
        webhook_url: None,
        webhook_secret: None,
        severity: None,
        rule: AlertRule::AnyTransaction,
    }]
}

fn rate_rules() -> Vec<RuleEntry> {
    vec![RuleEntry {
        enabled: true,
        webhook_url: None,
        webhook_secret: None,
        severity: None,
        rule: AlertRule::Rate {
            rule: Box::new(RuleEntry {
                enabled: true,
                webhook_url: None,
                webhook_secret: None,
                severity: None,
                rule: AlertRule::AnyTransaction,
            }),
            count: 10,
            window_seconds: 300,
        },
    }]
}

fn bench_evaluate(c: &mut Criterion) {
    let ctx = EvalContext {
        label: "bench",
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        network: "testnet",
        network_id: "testnet".into(),
        horizon_base: "https://horizon-testnet.stellar.org",
        explorer_base: Some("https://stellar.expert/explorer/testnet"),
    };
    let tx = tx();

    c.bench_function("evaluate/any_transaction", |b| {
        b.iter(|| black_box(evaluate(&ctx, &black_box(rules()), &tx, None)));
    });

    c.bench_function("evaluate/rate_any_transaction", |b| {
        let mut rates = RateTracker::new();
        let now = chrono::Utc::now();
        b.iter(|| black_box(rates.evaluate(&ctx, &black_box(rate_rules()), &tx, now)));
    });
}

criterion_group!(benches, bench_evaluate);
criterion_main!(benches);
