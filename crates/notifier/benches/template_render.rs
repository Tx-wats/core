//! Renders a template destination body through the compiled-template cache,
//! as every delivery to a `format = "template"` webhook does.
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use txwatch_config::WebhookFormat;
use txwatch_notifier::format::{render_body_with_content_type, TemplateCache};

const TEMPLATE_BODY: &str = r#"{
  "text": "[{{ severity }}] {{ rule_triggered }} on {{ label }}",
  "contract": {{ contract_id }},
  "tx": {{ transaction_hash }},
  "ledger": {{ ledger }},
  "functions": {{ function_names }}
}"#;

fn bench_render_template(c: &mut Criterion) {
    let payload = txwatch_notifier::test_payload("bench");
    let cache = TemplateCache::new();

    let mut group = c.benchmark_group("template_render");
    group.bench_function("cached_destination_body", |b| {
        b.iter(|| {
            let rendered = render_body_with_content_type(
                WebhookFormat::Template,
                black_box(&payload),
                None,
                Some(black_box(TEMPLATE_BODY)),
                None,
                Some(&cache),
            )
            .expect("template should render");
            black_box(rendered);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_render_template);
criterion_main!(benches);
