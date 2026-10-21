//! Maps an [`AlertPayload`] to the body each supported receiver expects.
//!
//! - `txwatch`: the payload itself.
//! - `slack`: a Slack incoming-webhook message (`text` fallback plus Block Kit
//!   `blocks`).
//! - `discord`: a Discord webhook message (`content` plus one embed), with
//!   mentions disabled so a label can never ping `@everyone`.
//! - `pagerduty`: a PagerDuty Events API v2 `trigger` event whose `dedup_key`
//!   is the alert's `alert_id`.
//! - `teams`: a Microsoft Teams Incoming Webhook / Workflows message carrying
//!   one Adaptive Card.
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
        WebhookFormat::Teams => teams(payload),
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
        WebhookFormat::Teams => teams_digest(payloads),
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

/// One-line summary shared by the chat formats. A recovery notification
/// (`resolved = true`) gets the "✅ Resolved" variant so it is never mistaken
/// for the incident itself.
fn headline(p: &AlertPayload) -> String {
    let kind = if p.resolved {
        "✅ Resolved"
    } else {
        "TxWatch alert"
    };
    format!(
        "{}: {} on {} ({})",
        kind, p.rule_triggered, p.label, p.network
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
    if let Some(source) = p.source_account.as_deref() {
        details.push(("Source", source.to_owned()));
    }
    if let Some(ledger) = p.ledger {
        details.push(("Ledger", ledger.to_string()));
    }
    if let Some(memo) = p.memo.as_deref() {
        let value = match p.memo_type.as_deref() {
            Some(kind) => format!("{} ({})", memo, kind),
            None => memo.to_owned(),
        };
        details.push(("Memo", value));
    }
    if let Some(severity) = p.severity.as_deref() {
        details.push(("Severity", severity.to_owned()));
    }
    if p.suppressed_count > 0 {
        details.push((
            "Suppressed",
            format!("{} similar alert(s)", p.suppressed_count),
        ));
    }
    if !p.matched_events.is_empty() {
        let names: Vec<String> = p
            .matched_events
            .iter()
            .map(|e| match e.topics.first() {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Object(o)) if o.len() == 1 => match o.values().next() {
                    Some(Value::String(s)) => s.clone(),
                    _ => Value::Object(o.clone()).to_string(),
                },
                Some(other) => other.to_string(),
                None => "(no topics)".to_owned(),
            })
            .collect();
        details.push(("Events", names.join(", ")));
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

/// Makes a URL safe inside Slack `<url|text>` link markup: `&` is
/// entity-escaped and `<`, `>`, `|` are percent-encoded so they can never end
/// the link early.
fn slack_url(url: &str) -> String {
    url.replace('&', "&amp;")
        .replace('<', "%3C")
        .replace('>', "%3E")
        .replace('|', "%7C")
}

/// Slack Block Kit limits; exceeding any of them makes Slack answer HTTP 400.
const SLACK_TEXT_MAX: usize = 3000;
const SLACK_FIELD_MAX: usize = 2000;
const SLACK_FIELDS_MAX: usize = 10;

/// Severity emoji for the Slack headline: resolved alerts get a check mark,
/// otherwise configured severity wins, falling back to the rule-type heuristic
/// when unset.
fn slack_emoji(p: &AlertPayload) -> &'static str {
    if p.resolved {
        return ":white_check_mark:";
    }
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
            "text": truncate(
                &format!(
                    "*Transaction*\n<{}|{}>",
                    slack_url(&p.explorer_link),
                    slack_escape(&p.transaction_hash)
                ),
                SLACK_FIELD_MAX,
            ),
        }),
    ];
    for (name, value) in details(p) {
        fields.push(json!({
            "type": "mrkdwn",
            "text": truncate(&format!("*{}*\n{}", name, slack_escape(&value)), SLACK_FIELD_MAX),
        }));
    }
    // Keep room for the timestamp when the details overflow the field cap.
    fields.truncate(SLACK_FIELDS_MAX - 1);
    fields.push(json!({ "type": "mrkdwn", "text": format!("*Time*\n{}", p.timestamp_iso) }));

    let resolved = if p.resolved { "Resolved: " } else { "" };
    json!({
        "text": truncate(&slack_escape(&headline(p)), SLACK_TEXT_MAX),
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": truncate(
                        &format!(
                            "{} {}*{}* on *{}* ({})",
                            slack_emoji(p),
                            resolved,
                            slack_escape(&p.rule_triggered),
                            slack_escape(&p.label),
                            slack_escape(&p.network)
                        ),
                        SLACK_TEXT_MAX,
                    ),
                },
            },
            { "type": "section", "fields": fields },
            {
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": truncate(
                        &format!(
                            "<{}|Explorer> · <{}|Horizon> · alert `{}`",
                            slack_url(&p.explorer_link),
                            slack_url(&p.horizon_link),
                            p.alert_id
                        ),
                        SLACK_TEXT_MAX,
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
            slack_url(&p.explorer_link),
            slack_escape(&p.transaction_hash)
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
                "text": { "type": "mrkdwn", "text": truncate(&lines.join("\n"), SLACK_TEXT_MAX) },
            },
        ],
    })
}

// ── Discord ───────────────────────────────────────────────────────────────────

/// Embed colour: configured severity wins (info→blue, warning→amber,
/// critical→red), falling back to the rule-type heuristic when unset.
fn discord_color(p: &AlertPayload) -> u32 {
    if p.resolved {
        return 0x2E_CC_71;
    }
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
            "title": truncate(
                &if p.resolved {
                    format!("✅ Resolved: {}", p.rule_triggered)
                } else {
                    p.rule_triggered.clone()
                },
                256,
            ),
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

// ── Microsoft Teams ───────────────────────────────────────────────────────────

/// Wraps an Adaptive Card body in the message envelope accepted by Teams
/// Incoming Webhooks and Workflows ("Post to a channel when a webhook request
/// is received").
fn teams_message(body: Vec<Value>, actions: Vec<Value>) -> Value {
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "msteams": { "width": "Full" },
                "body": body,
                "actions": actions,
            },
        }],
    })
}

/// Headline colour: resolved → good, otherwise by severity.
fn teams_color(p: &AlertPayload) -> &'static str {
    if p.resolved {
        return "Good";
    }
    match discord_color(p) {
        0xE7_4C_3C => "Attention",
        0xF1_C4_0F => "Warning",
        _ => "Accent",
    }
}

/// Microsoft Teams message with one Adaptive Card.
pub fn teams(p: &AlertPayload) -> Value {
    let mut facts = vec![
        json!({ "title": "Contract", "value": p.contract_id }),
        json!({ "title": "Transaction", "value": p.transaction_hash }),
    ];
    for (name, value) in details(p) {
        facts.push(json!({ "title": name, "value": value }));
    }
    facts.push(json!({ "title": "Time", "value": p.timestamp_iso }));

    teams_message(
        vec![
            json!({
                "type": "TextBlock",
                "text": headline(p),
                "weight": "Bolder",
                "size": "Medium",
                "color": teams_color(p),
                "wrap": true,
            }),
            json!({ "type": "FactSet", "facts": facts }),
            json!({
                "type": "TextBlock",
                "text": format!("alert {}", p.alert_id),
                "isSubtle": true,
                "size": "Small",
                "wrap": true,
            }),
        ],
        vec![
            json!({ "type": "Action.OpenUrl", "title": "Explorer", "url": p.explorer_link }),
            json!({ "type": "Action.OpenUrl", "title": "Horizon", "url": p.horizon_link }),
        ],
    )
}

/// Microsoft Teams digest message summarising a batch of alerts.
pub fn teams_digest(payloads: &[AlertPayload]) -> Value {
    let facts: Vec<Value> = payloads
        .iter()
        .map(|p| {
            json!({
                "title": format!("{} on {} ({})", p.rule_triggered, p.label, p.network),
                "value": format!("[{}]({})", p.transaction_hash, p.explorer_link),
            })
        })
        .collect();
    teams_message(
        vec![
            json!({
                "type": "TextBlock",
                "text": format!("TxWatch: {} alert(s)", payloads.len()),
                "weight": "Bolder",
                "size": "Medium",
                "wrap": true,
            }),
            json!({ "type": "FactSet", "facts": facts }),
        ],
        vec![],
    )
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
    fn slack_enforces_block_kit_limits() {
        let mut p = fixture();
        p.rule_triggered = "x".repeat(5000);
        p.function_names = vec!["f".repeat(3000)];
        p.source_account = Some("G".into());
        p.ledger = Some(1);
        p.memo = Some("m".into());
        p.severity = Some("critical".into());
        p.suppressed_count = 2;
        p.amount_xlm_decimal = Some("1.5".into());
        let slack = render(WebhookFormat::Slack, &p);
        let blocks = &slack["blocks"];
        assert!(blocks[0]["text"]["text"].as_str().unwrap().chars().count() <= 3000);
        let fields = blocks[1]["fields"].as_array().unwrap();
        assert!(fields.len() <= 10);
        assert!(fields
            .iter()
            .all(|f| f["text"].as_str().unwrap().chars().count() <= 2000));
        assert!(fields.last().unwrap()["text"]
            .as_str()
            .unwrap()
            .starts_with("*Time*"));

        let digest = render_batch_body(WebhookFormat::Slack, &vec![p; 50], None).unwrap();
        let digest: Value = serde_json::from_str(&digest).unwrap();
        assert!(
            digest["blocks"][1]["text"]["text"]
                .as_str()
                .unwrap()
                .chars()
                .count()
                <= 3000
        );
    }

    #[test]
    fn slack_link_urls_are_escaped() {
        let mut p = fixture();
        p.explorer_link = "https://x.example/tx?a=1&b=<2>|3".into();
        let slack = render(WebhookFormat::Slack, &p);
        let tx = slack["blocks"][1]["fields"][1]["text"].as_str().unwrap();
        assert_eq!(
            tx,
            "*Transaction*\n<https://x.example/tx?a=1&amp;b=%3C2%3E%7C3|abc123>"
        );
        let context = slack["blocks"][2]["elements"][0]["text"].as_str().unwrap();
        assert!(context.starts_with("<https://x.example/tx?a=1&amp;b=%3C2%3E%7C3|Explorer>"));
    }

    #[test]
    fn resolved_alerts_use_the_resolved_headline_and_extra_details() {
        let mut p = fixture();
        p.resolved = true;
        p.source_account = Some("GSOURCE".into());
        p.ledger = Some(42);
        p.memo = Some("invoice-7".into());
        p.memo_type = Some("text".into());
        p.severity = Some("warning".into());
        p.suppressed_count = 3;

        let slack = render(WebhookFormat::Slack, &p);
        assert!(slack["text"].as_str().unwrap().starts_with("✅ Resolved"));
        assert!(slack["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap()
            .starts_with(":white_check_mark: Resolved:"));

        let discord = render(WebhookFormat::Discord, &p);
        assert_eq!(discord["embeds"][0]["color"], 0x2E_CC_71);
        let names: Vec<&str> = discord["embeds"][0]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "Contract",
                "Transaction",
                "Fee",
                "Functions",
                "Source",
                "Ledger",
                "Memo",
                "Severity",
                "Suppressed",
                "Horizon"
            ]
        );
    }

    #[test]
    fn teams_renders_an_adaptive_card() {
        let mut p = fixture();
        p.function_names.clear();
        p.fee_charged_stroops = None;
        let expected = snapshot(
            r#"{
              "type": "message",
              "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": null,
                "content": {
                  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                  "type": "AdaptiveCard",
                  "version": "1.4",
                  "msteams": { "width": "Full" },
                  "body": [
                    {
                      "type": "TextBlock",
                      "text": "TxWatch alert: LargeTransfer(>=10000XLM) on Escrow <main> & co (testnet)",
                      "weight": "Bolder",
                      "size": "Medium",
                      "color": "Accent",
                      "wrap": true
                    },
                    {
                      "type": "FactSet",
                      "facts": [
                        { "title": "Contract", "value": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
                        { "title": "Transaction", "value": "abc123" },
                        { "title": "Time", "value": "2024-01-15T12:00:00Z" }
                      ]
                    },
                    {
                      "type": "TextBlock",
                      "text": "alert 3f2b9c1d8e7a6b5c4d3e2f1a0b9c8d7e",
                      "isSubtle": true,
                      "size": "Small",
                      "wrap": true
                    }
                  ],
                  "actions": [
                    { "type": "Action.OpenUrl", "title": "Explorer", "url": "https://stellar.expert/explorer/testnet/tx/abc123" },
                    { "type": "Action.OpenUrl", "title": "Horizon", "url": "https://horizon-testnet.stellar.org/transactions/abc123" }
                  ]
                }
              }]
            }"#,
        );
        assert_eq!(render(WebhookFormat::Teams, &p), expected);

        let digest =
            render_batch_body(WebhookFormat::Teams, &[fixture(), fixture()], None).unwrap();
        let digest: Value = serde_json::from_str(&digest).unwrap();
        let card = &digest["attachments"][0]["content"];
        assert_eq!(card["body"][0]["text"], "TxWatch: 2 alert(s)");
        assert_eq!(card["body"][1]["facts"].as_array().unwrap().len(), 2);
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
