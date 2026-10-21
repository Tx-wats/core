//! Maps an [`AlertPayload`] to the body each supported receiver expects.
//!
//! - `txwatch`: the payload itself.
//! - `slack`: a Slack incoming-webhook message (`text` fallback plus Block Kit
//!   `blocks`).
//! - `discord`: a Discord webhook message (`content` plus one embed), with
//!   mentions disabled so a label can never ping `@everyone`.
//! - `pagerduty`: a PagerDuty Events API v2 `trigger` event whose `dedup_key`
//!   is the alert's `alert_id`.
//!
//! Batched delivery (`batch_alerts = true`) renders a digest per destination
//! via [`render_batch_body`]: chat formats get a single digest message and
//! PagerDuty gets one `trigger` event per alert (Events API v2 has no batch
//! envelope), so no format silently drops alerts.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use txwatch_config::WebhookFormat;
use txwatch_rules::AlertPayload;

/// Renders the request body for `format`. `routing_key` is required for
/// PagerDuty and ignored otherwise.
pub fn render_body(
    format: WebhookFormat,
    payload: &AlertPayload,
    routing_key: Option<&str>,
    template: Option<&str>,
) -> Result<String> {
    let body = match format {
        WebhookFormat::Template => {
            return render_template(
                template.ok_or_else(|| anyhow!("template destinations need a template"))?,
                payload,
            )
        }
        WebhookFormat::Txwatch => serde_json::to_value(payload)?,
        WebhookFormat::Slack => slack(payload),
        WebhookFormat::Discord => discord(payload),
        WebhookFormat::Pagerduty => pagerduty(
            payload,
            routing_key.ok_or_else(|| anyhow!("PagerDuty destinations need a routing_key"))?,
        ),
    };
    Ok(serde_json::to_string(&body)?)
}

/// Renders the request body for a batch of alerts destined for one
/// destination. `routing_key` is required for PagerDuty and ignored otherwise.
///
/// - `txwatch`: a JSON array of payloads.
/// - `slack` / `discord`: a single digest message summarising every alert.
/// - `pagerduty`: a JSON array of `trigger` events (one per alert).
pub fn render_batch_body(
    format: WebhookFormat,
    payloads: &[AlertPayload],
    routing_key: Option<&str>,
) -> Result<String> {
    let body = match format {
        WebhookFormat::Txwatch | WebhookFormat::Template => serde_json::to_value(payloads)?,
        WebhookFormat::Slack => slack_digest(payloads),
        WebhookFormat::Discord => discord_digest(payloads),
        WebhookFormat::Pagerduty => {
            let key =
                routing_key.ok_or_else(|| anyhow!("PagerDuty destinations need a routing_key"))?;
            Value::Array(payloads.iter().map(|p| pagerduty(p, key)).collect())
        }
        WebhookFormat::Template => serde_json::to_value(payloads)?,
    };
    Ok(serde_json::to_string(&body)?)
}

/// Renders a user-defined body template. Every [`AlertPayload`] field is a
/// variable, and values are JSON-escaped, so `{"text": {{ label }}}` yields
/// `{"text": "My Contract"}`. The engine is sandboxed: no file or network access.
fn render_template(template: &str, payload: &AlertPayload) -> Result<String> {
    let mut env = minijinja::Environment::new();
    env.set_auto_escape_callback(|_| minijinja::AutoEscape::Json);
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.add_template("body", template)?;
    Ok(env
        .get_template("body")?
        .render(minijinja::Value::from_serialize(payload))?)
}

/// One-line summary shared by the chat formats.
fn headline(p: &AlertPayload) -> String {
    format!(
        "TxWatch alert: {} on {} ({})",
        p.rule_triggered, p.label, p.network
    )
}

/// Renders a decimal XLM amount with trailing zeros (and a dangling decimal
/// point) trimmed, e.g. `0.9` stays `0.9` and `9999.99` stays `9999.99`.
fn trim_decimal(amount: &str) -> String {
    if !amount.contains('.') {
        return amount.to_owned();
    }
    let trimmed = amount.trim_end_matches('0');
    trimmed.trim_end_matches('.').to_owned()
}

/// Optional detail lines as (name, value) pairs, in display order.
pub fn details(p: &AlertPayload) -> Vec<(&'static str, String)> {
    let mut details = Vec::new();
    if let Some(xlm) = p.amount_xlm_decimal.as_deref() {
        details.push(("Amount", format!("{} XLM", trim_decimal(xlm))));
    }
    if let Some(fee) = p.fee_charged_stroops {
        details.push(("Fee", format!("{} stroops", fee)));
    }
    if !p.function_names.is_empty() {
        details.push(("Functions", p.function_names.join(", ")));
    }
    details
}

/// Truncates to at most `max` characters, marking the cut with `…`.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// Normalises the configured rule severity to one of `info`, `warning`,
/// `critical`. Returns `None` when the payload carries no severity so callers
/// can fall back to the rule-type heuristic.
fn configured_severity(p: &AlertPayload) -> Option<&'static str> {
    let raw = p.severity.as_deref()?.trim();
    if raw.is_empty() {
        return None;
    }
    match raw.to_ascii_lowercase().as_str() {
        "info" => Some("info"),
        "warning" | "warn" => Some("warning"),
        "critical" | "error" => Some("critical"),
        _ => None,
    }
}

// ── Slack ─────────────────────────────────────────────────────────────────────

/// Escapes the three characters Slack mrkdwn treats as control characters.
fn slack_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Severity emoji for the Slack headline: configured severity wins, falling
/// back to the rule-type heuristic when unset.
fn slack_emoji(p: &AlertPayload) -> &'static str {
    match configured_severity(p) {
        Some("info") => ":information_source:",
        Some("warning") => ":warning:",
        Some("critical") => ":rotating_light:",
        _ => match p.rule_type.as_str() {
            "TransactionFailed" | "AdminFunctionCalled" => ":rotating_light:",
            "TestWebhook" => ":information_source:",
            _ => ":warning:",
        },
    }
}

/// Slack incoming-webhook message.
pub fn slack(p: &AlertPayload) -> Value {
    let mut fields = vec![
        json!({ "type": "mrkdwn", "text": format!("*Contract*\n`{}`", p.contract_id) }),
        json!({
            "type": "mrkdwn",
            "text": format!("*Transaction*\n<{}|{}>", p.explorer_link, p.transaction_hash),
        }),
    ];
    for (name, value) in details(p) {
        fields.push(json!({
            "type": "mrkdwn",
            "text": format!("*{}*\n{}", name, slack_escape(&value)),
        }));
    }
    fields.push(json!({ "type": "mrkdwn", "text": format!("*Time*\n{}", p.timestamp_iso) }));

    json!({
        "text": slack_escape(&headline(p)),
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(
                        "{} *{}* on *{}* ({})",
                        slack_emoji(p),
                        slack_escape(&p.rule_triggered),
                        slack_escape(&p.label),
                        slack_escape(&p.network)
                    ),
                },
            },
            { "type": "section", "fields": fields },
            {
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": format!(
                        "<{}|Explorer> · <{}|Horizon> · alert `{}`",
                        p.explorer_link, p.horizon_link, p.alert_id
                    ),
                }],
            },
        ],
    })
}

/// Slack digest message summarising a batch of alerts.
pub fn slack_digest(payloads: &[AlertPayload]) -> Value {
    let mut lines = Vec::with_capacity(payloads.len());
    for p in payloads {
        lines.push(format!(
            "• *{}* on *{}* ({}) — <{}|{}>",
            slack_escape(&p.rule_triggered),
            slack_escape(&p.label),
            slack_escape(&p.network),
            p.explorer_link,
            p.transaction_hash
        ));
    }
    let summary = format!("TxWatch: {} alert(s)", payloads.len());
    json!({
        "text": summary,
        "blocks": [
            {
                "type": "section",
                "text": { "type": "mrkdwn", "text": format!("*{}*", summary) },
            },
            {
                "type": "section",
                "text": { "type": "mrkdwn", "text": lines.join("\n") },
            },
        ],
    })
}

// ── Discord ───────────────────────────────────────────────────────────────────

/// Embed colour: configured severity wins (info→blue, warning→amber,
/// critical→red), falling back to the rule-type heuristic when unset.
fn discord_color(p: &AlertPayload) -> u32 {
    match configured_severity(p) {
        Some("info") => 0x34_98_DB,
        Some("warning") => 0xF1_C4_0F,
        Some("critical") => 0xE7_4C_3C,
        _ => match p.rule_type.as_str() {
            "TransactionFailed" | "AdminFunctionCalled" => 0xE7_4C_3C,
            _ => 0x34_98_DB,
        },
    }
}

/// Discord webhook message.
pub fn discord(p: &AlertPayload) -> Value {
    let mut fields = vec![
        json!({ "name": "Contract", "value": format!("`{}`", p.contract_id), "inline": false }),
        json!({
            "name": "Transaction",
            "value": truncate(&format!("[{}]({})", p.transaction_hash, p.explorer_link), 1024),
            "inline": false,
        }),
    ];
    for (name, value) in details(p) {
        fields.push(json!({ "name": name, "value": truncate(&value, 1024), "inline": true }));
    }
    fields.push(json!({
        "name": "Horizon",
        "value": truncate(&format!("[transaction]({})", p.horizon_link), 1024),
        "inline": true,
    }));

    json!({
        "username": "TxWatch",
        "content": truncate(&headline(p), 2000),
        "allowed_mentions": { "parse": [] },
        "embeds": [{
            "title": truncate(&p.rule_triggered, 256),
            "url": p.explorer_link,
            "description": truncate(&format!("{} ({})", p.label, p.network), 4096),
            "color": discord_color(p),
            "timestamp": p.timestamp_iso,
            "fields": fields,
            "footer": { "text": format!("TxWatch · alert {}", p.alert_id) },
        }],
    })
}

/// Discord digest message summarising a batch of alerts.
pub fn discord_digest(payloads: &[AlertPayload]) -> Value {
    let mut lines = Vec::with_capacity(payloads.len());
    for p in payloads {
        lines.push(format!(
            "• {} on {} ({}) — [{}]({})",
            p.rule_triggered, p.label, p.network, p.transaction_hash, p.explorer_link
        ));
    }
    json!({
        "username": "TxWatch",
        "content": truncate(&format!("TxWatch: {} alert(s)", payloads.len()), 2000),
        "allowed_mentions": { "parse": [] },
        "embeds": [{
            "title": "Batched alerts",
            "description": truncate(&lines.join("\n"), 4096),
            "color": 0x34_98_DB,
            "footer": { "text": "TxWatch" },
        }],
    })
}

// ── PagerDuty ─────────────────────────────────────────────────────────────────

/// PagerDuty severity: the configured rule severity wins (info→info,
/// warning→warning, critical→critical); otherwise fall back to the rule-type
/// heuristic (failed transactions `error`, admin calls `critical`, test
/// webhooks `info`, everything else `warning`).
fn pagerduty_severity(p: &AlertPayload) -> &'static str {
    if let Some(severity) = configured_severity(p) {
        return severity;
    }
    match p.rule_type.as_str() {
        "TransactionFailed" => "error",
        "AdminFunctionCalled" => "critical",
        "TestWebhook" => "info",
        _ => "warning",
    }
}

/// PagerDuty Events API v2 `trigger` event. The full alert is attached as
/// `payload.custom_details`.
pub fn pagerduty(p: &AlertPayload, routing_key: &str) -> Value {
    json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": p.alert_id,
        "payload": {
            "summary": headline(p),
            "source": p.contract_id,
            "severity": pagerduty_severity(p),
            "timestamp": p.timestamp_iso,
            "custom_details": {
                "rule_triggered": p.rule_triggered,
                "label": p.label,
                "network": p.network,
                "transaction_hash": p.transaction_hash,
                "explorer_link": p.explorer_link,
                "horizon_link": p.horizon_link,
                "amount_xlm_decimal": p.amount_xlm_decimal,
                "fee_charged_stroops": p.fee_charged_stroops,
                "function_names": p.function_names,
            },
        },
    })
}

// ── Snapshot tests ────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A LargeTransfer alert whose label needs escaping in Slack mrkdwn.
    fn fixture() -> AlertPayload {
        AlertPayload {
            schema_version: 1,
            alert_id: "3f2b9c1d8e7a6b5c4d3e2f1a0b9c8d7e".into(),
            label: "Escrow <main> & co".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            network: "testnet".into(),
            rule_type: "LargeTransfer".into(),
            rule_triggered: "LargeTransfer(>=10000XLM)".into(),
            transaction_hash: "abc123".into(),
            function_name: Some("transfer".into()),
            function_names: vec!["transfer".into()],
            amount_xlm: Some(15000),
            amount_stroops: Some(150_000_000_000),
            amount_xlm_decimal: None,
            fee_charged_stroops: Some(50000),
            source_account: None,
            fee_account: None,
            severity: None,
            timestamp: 1705320000,
            timestamp_iso: "2024-01-15T12:00:00Z".into(),
            explorer_link: "https://stellar.expert/explorer/testnet/tx/abc123".into(),
            horizon_link: "https://horizon-testnet.stellar.org/transactions/abc123".into(),
            amount_stroops: None,
            amount_xlm_decimal: None,
            effective_webhook_url: None,
            effective_webhook_secret: None,
            severity: None,
            ledger: None,
            source_account: None,
            effective_webhook_url: None,
            effective_webhook_secret: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
            resolved: false,
            matched_events: vec![],
            suppressed_count: 0,
            test: false,
            old_wasm_hash: None,
            new_wasm_hash: None,
            enrichment_incomplete: false,
        }
    }

    fn render(format: WebhookFormat, payload: &AlertPayload) -> Value {
        serde_json::from_str(&render_body(format, payload, Some("R0UT1NGKEY"), None).unwrap())
            .unwrap()
    }

    #[allow(dead_code)]
    fn snapshot(expected: &str) -> Value {
        serde_json::from_str(expected).expect("snapshot is valid JSON")
    }

    #[test]
    fn txwatch_batch_is_array_of_payloads() {
        let payloads = vec![fixture(), fixture()];
        let body = render_batch_body(WebhookFormat::Txwatch, &payloads, None).unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 2);
    }

    #[test]
    fn slack_batch_is_single_digest() {
        let payloads = vec![fixture(), fixture()];
        let body = render_batch_body(WebhookFormat::Slack, &payloads, None).unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        assert!(value["text"].as_str().unwrap().contains("2 alert(s)"));
        assert!(value["blocks"].is_array());
    }

    #[test]
    fn discord_batch_is_single_digest() {
        let payloads = vec![fixture()];
        let body = render_batch_body(WebhookFormat::Discord, &payloads, None).unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        assert!(value["content"].as_str().unwrap().contains("1 alert(s)"));
        assert_eq!(value["allowed_mentions"]["parse"], json!([]));
    }

    #[test]
    fn pagerduty_batch_is_array_of_events() {
        let payloads = vec![fixture(), fixture()];
        let body = render_batch_body(WebhookFormat::Pagerduty, &payloads, Some("rk")).unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        let events = value.as_array().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["routing_key"], "rk");
        assert_eq!(events[0]["event_action"], "trigger");
    }

    #[test]
    fn pagerduty_batch_requires_routing_key() {
        let payloads = vec![fixture()];
        assert!(render_batch_body(WebhookFormat::Pagerduty, &payloads, None).is_err());
    }

    #[test]
    fn optional_details_are_omitted_when_absent() {
        let mut p = fixture();
        p.amount_xlm = None;
        p.fee_charged_stroops = None;
        p.function_name = None;
        p.function_names.clear();

        let slack = render(WebhookFormat::Slack, &p);
        let names: Vec<&str> = slack["blocks"][1]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["text"].as_str().unwrap().split('\n').next().unwrap())
            .collect();
        assert_eq!(names, ["*Contract*", "*Transaction*", "*Time*"]);

        let discord = render(WebhookFormat::Discord, &p);
        let names: Vec<&str> = discord["embeds"][0]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Contract", "Transaction", "Horizon"]);
    }

    #[test]
    fn severity_and_colour_follow_the_rule_type() {
        let mut p = fixture();
        for (rule_type, severity, colour) in [
            ("TransactionFailed", "error", 0xE7_4C_3C),
            ("AdminFunctionCalled", "critical", 0xE7_4C_3C),
            ("TestWebhook", "info", 0x34_98_DB),
            ("AnyTransaction", "warning", 0x34_98_DB),
        ] {
            p.rule_type = rule_type.into();
            assert_eq!(
                render(WebhookFormat::Pagerduty, &p)["payload"]["severity"],
                severity
            );
            assert_eq!(
                render(WebhookFormat::Discord, &p)["embeds"][0]["color"],
                colour
            );
        }
    }

    #[test]
    fn template_renders_payload_variables_with_json_escaping() {
        let mut p = fixture();
        p.label = "Quote \" and \\ backslash".into();
        let body = render_body(
            WebhookFormat::Template,
            &p,
            None,
            Some(r#"{"text": {{ label }}, "tx": {{ transaction_hash }}}"#),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["text"], p.label);
        assert_eq!(v["tx"], p.transaction_hash);
    }

    #[test]
    fn template_rejects_unknown_variables() {
        let err = render_body(
            WebhookFormat::Template,
            &fixture(),
            None,
            Some("{{ nope }}"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("undefined"), "got: {}", err);
    }

    #[test]
    fn pagerduty_requires_a_routing_key() {
        let err = render_body(WebhookFormat::Pagerduty, &fixture(), None, None).unwrap_err();
        assert!(err.to_string().contains("routing_key"), "got: {}", err);
    }

    #[test]
    fn long_text_is_truncated_to_provider_limits() {
        let mut p = fixture();
        p.rule_triggered = "x".repeat(300);
        let discord = render(WebhookFormat::Discord, &p);
        let title = discord["embeds"][0]["title"].as_str().unwrap();
        assert_eq!(title.chars().count(), 256);
        assert!(title.ends_with('\u{2026}'));

        p.label = "y".repeat(2000);
        let pd = render(WebhookFormat::Pagerduty, &p);
        assert_eq!(
            pd["payload"]["summary"].as_str().unwrap().chars().count(),
            1024
        );
    }
}
