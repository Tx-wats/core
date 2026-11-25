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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use txwatch_config::{Severity, WebhookFormat};
use txwatch_rules::AlertPayload;

/// Content type used when a template destination does not set one.
pub const DEFAULT_CONTENT_TYPE: &str = "application/json";

/// A rendered request body together with the `Content-Type` the receiver
/// expects. Callers set the header from `content_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedBody {
    pub body: String,
    pub content_type: String,
}

/// Compiled templates, keyed by template source and escape mode, built once
/// per config generation. Cloning is cheap (the environments are shared).
#[derive(Debug, Clone, Default)]
pub struct TemplateCache {
    compiled: Arc<Mutex<HashMap<(String, bool), Arc<minijinja::Environment<'static>>>>>,
}

impl TemplateCache {
    /// Creates an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compiles `template` with JSON auto-escaping (if not already cached) and
    /// returns the shared environment.
    pub fn get(&self, template: &str) -> Result<Arc<minijinja::Environment<'static>>> {
        self.get_with_escape(template, true)
    }

    /// Compiles `template` (if not already cached) and returns the shared
    /// environment. Undefined variables are errors; `json_escape` selects JSON
    /// auto-escaping, otherwise values are rendered verbatim.
    pub fn get_with_escape(
        &self,
        template: &str,
        json_escape: bool,
    ) -> Result<Arc<minijinja::Environment<'static>>> {
        let key = (template.to_owned(), json_escape);
        if let Some(env) = self
            .compiled
            .lock()
            .map_err(|_| anyhow!("template cache poisoned"))?
            .get(&key)
            .cloned()
        {
            return Ok(env);
        }
        let mut env = minijinja::Environment::new();
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
        env.set_auto_escape_callback(move |_| {
            if json_escape {
                minijinja::AutoEscape::Json
            } else {
                minijinja::AutoEscape::None
            }
        });
        env.add_template_owned("body", template.to_owned())?;
        let env = Arc::new(env);
        self.compiled
            .lock()
            .map_err(|_| anyhow!("template cache poisoned"))?
            .insert(key, env.clone());
        Ok(env)
    }
}

/// Process-wide fallback cache for callers that do not thread a
/// [`TemplateCache`] through (e.g. ad-hoc rendering).
fn fallback_cache() -> &'static TemplateCache {
    static CACHE: OnceLock<TemplateCache> = OnceLock::new();
    CACHE.get_or_init(TemplateCache::new)
}

/// Renders the request body for `format`. `routing_key` is required for
/// PagerDuty and ignored otherwise.
pub fn render_body(
    format: WebhookFormat,
    payload: &AlertPayload,
    routing_key: Option<&str>,
    template: Option<&str>,
) -> Result<String> {
    Ok(render_body_with_content_type(
        format,
        payload,
        routing_key,
        template,
        None,
        None,
    )?
    .body)
}

/// Renders the request body for `format` and returns the content type the
/// receiver expects. `content_type` only applies to `format = "template"` and
/// defaults to [`DEFAULT_CONTENT_TYPE`]. `cache` is used to reuse compiled
/// templates; when `None` a process-wide fallback cache is used.
pub fn render_body_with_content_type(
    format: WebhookFormat,
    payload: &AlertPayload,
    routing_key: Option<&str>,
    template: Option<&str>,
    content_type: Option<&str>,
    cache: Option<&TemplateCache>,
) -> Result<RenderedBody> {
    if format == WebhookFormat::Template {
        let template =
            template.ok_or_else(|| anyhow!("template destinations need a template"))?;
        let content_type = content_type.unwrap_or(DEFAULT_CONTENT_TYPE);
        let cache = cache.unwrap_or_else(|| fallback_cache());
        let body = render_template(template, payload, content_type, cache)?;
        return Ok(RenderedBody {
            body,
            content_type: content_type.to_owned(),
        });
    }
    let body = match format {
        WebhookFormat::Template => unreachable!("handled above"),
        WebhookFormat::Txwatch => serde_json::to_value(payload)?,
        WebhookFormat::Slack => slack(payload),
        WebhookFormat::Discord => discord(payload),
        WebhookFormat::Teams => teams(payload),
        WebhookFormat::Pagerduty => pagerduty(
            payload,
            routing_key.ok_or_else(|| anyhow!("PagerDuty destinations need a routing_key"))?,
        ),
    };
    Ok(RenderedBody {
        body: serde_json::to_string(&body)?,
        content_type: DEFAULT_CONTENT_TYPE.to_owned(),
    })
}

/// Renders a user-defined body template. Every [`AlertPayload`] field is a
/// variable. When `content_type` is JSON, values are JSON-escaped, so
/// `{"text": {{ label }}}` yields `{"text": "My Contract"}`; for any other
/// content type values are rendered verbatim. The engine is sandboxed: no file
/// or network access. The compiled template is looked up in `cache`.
///
/// Optional fields are always present in the render context (as `null` when
/// the payload omits them), so a template referencing e.g. `{{ source_account }}`
/// renders for every alert type instead of failing at delivery time for alerts
/// such as `NoActivity` or cooldown summaries. Unknown variables still fail
/// (strict undefined behaviour).
fn render_template(
    template: &str,
    payload: &AlertPayload,
    content_type: &str,
    cache: &TemplateCache,
) -> Result<String> {
    let env = cache.get_with_escape(template, is_json_content_type(content_type))?;
    Ok(env
        .get_template("body")?
        .render(minijinja::Value::from(minijinja::value::Serde(
            template_context(payload),
        )))?)
}

/// Builds the render context for `payload`: the serialized payload with every
/// optional field filled in as `null` when absent, so templates can reference
/// them unconditionally.
fn template_context(payload: &AlertPayload) -> Value {
    let mut value = serde_json::to_value(payload).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        for field in OPTIONAL_TEMPLATE_FIELDS {
            map.entry((*field).to_owned()).or_insert(Value::Null);
        }
    }
    value
}

/// Optional [`AlertPayload`] fields that may be absent from the serialized
/// payload (`skip_serializing_if`) but must still be addressable from a
/// template.
const OPTIONAL_TEMPLATE_FIELDS: &[&str] = &[
    "function_name",
    "amount_xlm",
    "amount_stroops",
    "amount_xlm_decimal",
    "fee_charged_stroops",
    "source_account",
    "fee_account",
    "severity",
    "ledger",
    "memo",
    "memo_type",
    "operation_count",
    "old_wasm_hash",
    "new_wasm_hash",
    "effective_webhook_url",
    "effective_webhook_secret",
];

/// Validates a user-defined template at load time by rendering it against a
/// synthetic payload for every rule type (including `NoActivity` and
/// cooldown summaries). Returns an error naming the offending template when
/// rendering fails, so misconfiguration surfaces at config load rather than at
/// delivery time.
pub fn validate_template(template: &str) -> Result<()> {
    for payload in synthetic_payloads() {
        render_template(template, &payload, DEFAULT_CONTENT_TYPE, fallback_cache()).map_err(|err| {
            anyhow!(
                "template failed to render for rule type {}: {}",
                payload.rule_type,
                err
            )
        })?;
    }
    Ok(())
}

/// Synthetic payloads covering every rule type, including ones that omit
/// optional fields (`NoActivity`, cooldown summaries).
fn synthetic_payloads() -> Vec<AlertPayload> {
    let rule_types = [
        "LargeTransfer",
        "TransactionFailed",
        "AdminFunctionCalled",
        "AnyTransaction",
        "NoActivity",
        "CooldownSummary",
        "TestWebhook",
    ];
    rule_types
        .iter()
        .map(|rule_type| AlertPayload {
            schema_version: 1,
            alert_id: "0000000000000000000000000000000000000000".into(),
            label: "synthetic".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            network: "testnet".into(),
            rule_type: (*rule_type).into(),
            rule_triggered: format!("{}(synthetic)", rule_type),
            transaction_hash: "0".repeat(64),
            function_name: None,
            function_names: vec![],
            function_args: vec![],
            observed_count: None,
            amount_xlm: None,
            amount_stroops: None,
            amount_in_stroops: None,
            amount_out_stroops: None,
            amount_xlm_decimal: None,
            fee_charged_stroops: None,
            source_account: None,
            fee_account: None,
            severity: None,
            timestamp: 0,
            timestamp_iso: "1970-01-01T00:00:00Z".into(),
            explorer_link: "https://stellar.expert/explorer/testnet".into(),
            horizon_link: "https://horizon-testnet.stellar.org".into(),
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
        })
        .collect()
}

/// Whether `content_type` denotes JSON (ignoring parameters like `charset`).
fn is_json_content_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
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
    if let Some(severity) = &p.severity {
        details.push(("Severity", severity.to_string()));
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

/// Truncates a multi-line block on a line boundary, appending
/// `… and N more` for the dropped lines. Never cuts inside `<…>` markup: if
/// the last kept line would end mid-markup it is dropped too.
fn truncate_lines(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let mut kept: Vec<&str> = Vec::new();
    let mut used = 0usize;
    for line in &lines {
        let extra = if kept.is_empty() { 0 } else { 1 };
        if used + extra + line.chars().count() > max {
            break;
        }
        used += extra + line.chars().count();
        kept.push(line);
    }
    // Drop a trailing line whose `<…>` markup is unterminated.
    while let Some(last) = kept.last() {
        let opens = last.matches('<').count();
        let closes = last.matches('>').count();
        if opens > closes {
            kept.pop();
        } else {
            break;
        }
    }
    let dropped = lines.len() - kept.len();
    let suffix = format!("… and {} more", dropped);
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&suffix);
    truncate(&out, max)
}

/// Normalises the configured rule severity to one of `info`, `warning`,
/// `critical`. Returns `None` when the payload carries no severity so callers
/// can fall back to the rule-type heuristic.
fn configured_severity(p: &AlertPayload) -> Option<&'static str> {
    match p.severity.as_ref()? {
        Severity::Info => Some("info"),
        Severity::Warning => Some("warning"),
        Severity::Critical => Some("critical"),
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
                "text": { "type": "mrkdwn", "text": truncate_lines(&lines.join("\n"), SLACK_TEXT_MAX) },
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

/// Escapes the characters Discord treats as markdown so untrusted values
/// (labels, rule text, memos) can never inject masked links, spoilers or
/// formatting.
fn discord_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(
            c,
            '\\' | '*' | '_' | '~' | '|' | '>' | '[' | ']' | '(' | ')' | '`'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Discord embed limits; exceeding any of them makes Discord answer HTTP 400.
const DISCORD_FIELD_MAX: usize = 1024;
const DISCORD_FIELDS_MAX: usize = 25;
const DISCORD_EMBED_TOTAL_MAX: usize = 6000;

/// Discord webhook message.
pub fn discord(p: &AlertPayload) -> Value {
    let title = truncate(
        &if p.resolved {
            format!("✅ Resolved: {}", discord_escape(&p.rule_triggered))
        } else {
            discord_escape(&p.rule_triggered)
        },
        256,
    );
    let description = truncate(
        &format!(
            "{} ({})",
            discord_escape(&p.label),
            discord_escape(&p.network)
        ),
        4096,
    );

    // Running total of embed text: title, description, field names and values.
    let mut used = title.chars().count() + description.chars().count();

    let mut fields: Vec<Value> = Vec::new();
    let mut push_field = |name: &str, value: String, inline: bool, used: &mut usize| {
        if fields.len() >= DISCORD_FIELDS_MAX {
            return;
        }
        let value = truncate(&value, DISCORD_FIELD_MAX);
        let cost = name.chars().count() + value.chars().count();
        if *used + cost > DISCORD_EMBED_TOTAL_MAX {
            return;
        }
        *used += cost;
        fields.push(json!({ "name": name, "value": value, "inline": inline }));
    };

    push_field(
        "Contract",
        format!("`{}`", discord_escape(&p.contract_id)),
        false,
        &mut used,
    );
    push_field(
        "Transaction",
        format!(
            "[{}]({})",
            discord_escape(&p.transaction_hash),
            p.explorer_link
        ),
        false,
        &mut used,
    );
    for (name, value) in details(p) {
        push_field(name, discord_escape(&value), true, &mut used);
    }
    push_field(
        "Horizon",
        format!("[transaction]({})", p.horizon_link),
        true,
        &mut used,
    );

    json!({
        "username": "TxWatch",
        "content": truncate(&discord_escape(&headline(p)), 2000),
        "allowed_mentions": { "parse": [] },
        "embeds": [{
            "title": title,
            "url": p.explorer_link,
            "description": description,
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
            discord_escape(&p.rule_triggered),
            discord_escape(&p.label),
            discord_escape(&p.network),
            discord_escape(&p.transaction_hash),
            p.explorer_link
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

/// Teams Incoming Webhooks and Workflows reject payloads over roughly 28 KB,
/// so fact titles and values are truncated and the digest's fact count is
/// capped to keep the rendered body well under that limit.
const TEAMS_FACT_TITLE_MAX: usize = 120;
const TEAMS_FACT_VALUE_MAX: usize = 300;
const TEAMS_DIGEST_FACTS_MAX: usize = 40;

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
        json!({ "title": "Contract", "value": truncate(&p.contract_id, TEAMS_FACT_VALUE_MAX) }),
        json!({ "title": "Transaction", "value": truncate(&p.transaction_hash, TEAMS_FACT_VALUE_MAX) }),
    ];
    for (name, value) in details(p) {
        facts.push(json!({
            "title": truncate(name, TEAMS_FACT_TITLE_MAX),
            "value": truncate(&value, TEAMS_FACT_VALUE_MAX),
        }));
    }
    facts.push(json!({ "title": "Time", "value": truncate(&p.timestamp_iso, TEAMS_FACT_VALUE_MAX) }));

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

/// Microsoft Teams digest message summarising a batch of alerts. Fact titles
/// and values are truncated and the fact count is capped so the body stays
/// under the Teams payload limit.
pub fn teams_digest(payloads: &[AlertPayload]) -> Value {
    let facts: Vec<Value> = payloads
        .iter()
        .take(TEAMS_DIGEST_FACTS_MAX)
        .map(|p| {
            json!({
                "title": truncate(
                    &format!("{} on {} ({})", p.rule_triggered, p.label, p.network),
                    TEAMS_FACT_TITLE_MAX,
                ),
                "value": truncate(
                    &format!("[{}]({})", p.transaction_hash, p.explorer_link),
                    TEAMS_FACT_VALUE_MAX,
                ),
            })
        })
        .collect();
    let mut body = vec![json!({
        "type": "TextBlock",
        "text": format!("TxWatch: {} alert(s)", payloads.len()),
        "weight": "Bolder",
        "size": "Medium",
        "wrap": true,
    })];
    if payloads.len() > TEAMS_DIGEST_FACTS_MAX {
        body.push(json!({
            "type": "TextBlock",
            "text": format!(
                "…and {} more alert(s)",
                payloads.len() - TEAMS_DIGEST_FACTS_MAX
            ),
            "isSubtle": true,
            "size": "Small",
            "wrap": true,
        }));
    }
    body.push(json!({ "type": "FactSet", "facts": facts }));
    teams_message(body, vec![])
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

/// PagerDuty Events API v2 caps `payload.summary` at 1024 characters.
const PAGERDUTY_SUMMARY_MAX: usize = 1024;
/// PagerDuty Events API v2 caps `payload.source` at 1024 characters.
const PAGERDUTY_SOURCE_MAX: usize = 1024;
/// PagerDuty Events API v2 caps the serialised `custom_details` at 32 KiB.
const PAGERDUTY_CUSTOM_DETAILS_MAX: usize = 32 * 1024;

/// PagerDuty Events API v2 `trigger` event. The full alert is attached as
/// `payload.custom_details`.
pub fn pagerduty(p: &AlertPayload, routing_key: &str) -> Value {
    let mut custom_details = serde_json::Map::new();
    let mut insert = |key: &str, value: Value| {
        if !value.is_null() {
            custom_details.insert(key.to_owned(), value);
        }
    };
    insert("alert_id", json!(p.alert_id));
    insert("rule_type", json!(p.rule_type));
    insert("rule_triggered", json!(p.rule_triggered));
    insert("label", json!(p.label));
    insert("network", json!(p.network));
    insert("severity", json!(p.severity));
    insert("transaction_hash", json!(p.transaction_hash));
    insert("explorer_link", json!(p.explorer_link));
    insert("horizon_link", json!(p.horizon_link));
    insert("source_account", json!(p.source_account));
    insert("fee_account", json!(p.fee_account));
    insert("memo", json!(p.memo));
    insert("memo_type", json!(p.memo_type));
    insert("ledger", json!(p.ledger));
    insert("amount_xlm_decimal", json!(p.amount_xlm_decimal));
    insert("fee_charged_stroops", json!(p.fee_charged_stroops));
    insert("function_names", json!(p.function_names));
    insert("matched_events", json!(p.matched_events));
    insert("suppressed_count", json!(p.suppressed_count));
    insert("observed_count", json!(p.observed_count));
    insert("resolved", json!(p.resolved));
    insert("enrichment_incomplete", json!(p.enrichment_incomplete));

    // Keep the serialised details under the API's size cap by dropping the
    // largest values (matched_events first) until it fits.
    let mut custom_details = Value::Object(custom_details);
    while serde_json::to_string(&custom_details)
        .map(|s| s.len())
        .unwrap_or(0)
        > PAGERDUTY_CUSTOM_DETAILS_MAX
    {
        let Some(obj) = custom_details.as_object_mut() else {
            break;
        };
        let largest = obj
            .iter()
            .max_by_key(|(_, v)| serde_json::to_string(v).map(|s| s.len()).unwrap_or(0))
            .map(|(k, _)| k.clone());
        match largest {
            Some(key) => {
                obj.remove(&key);
            }
            None => break,
        }
    }

    json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": p.alert_id,
        "payload": {
            "summary": truncate(&headline(p), PAGERDUTY_SUMMARY_MAX),
            "source": truncate(&p.contract_id, PAGERDUTY_SOURCE_MAX),
            "severity": pagerduty_severity(p),
            "timestamp": p.timestamp_iso,
            "custom_details": custom_details,
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
    fn slack_digest_is_single_message() {
        let payloads = vec![fixture(), fixture()];
        let value = slack_digest(&payloads);
        assert!(value["text"].as_str().unwrap().contains("2 alert(s)"));
        assert!(value["blocks"].is_array());
    }

    #[test]
    fn discord_digest_is_single_message() {
        let payloads = vec![fixture()];
        let value = discord_digest(&payloads);
        assert!(value["content"].as_str().unwrap().contains("1 alert(s)"));
        assert_eq!(value["allowed_mentions"]["parse"], json!([]));
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
    fn template_content_type_defaults_to_json() {
        let rendered = render_body_with_content_type(
            WebhookFormat::Template,
            &fixture(),
            None,
            Some(r#"{"text": {{ label }}}"#),
            None,
            None,
        )
        .unwrap();
        assert_eq!(rendered.content_type, "application/json");
    }

    #[test]
    fn template_content_type_disables_json_escaping() {
        let mut p = fixture();
        p.label = "Quote \" and \\ backslash".into();
        let rendered = render_body_with_content_type(
            WebhookFormat::Template,
            &p,
            None,
            Some("label={{ label }}"),
            Some("text/plain"),
            None,
        )
        .unwrap();
        assert_eq!(rendered.content_type, "text/plain");
        assert_eq!(rendered.body, format!("label={}", p.label));
    }

    #[test]
    fn template_cache_reuses_compiled_environment() {
        let cache = TemplateCache::new();
        let first = cache.get("{{ label }}").unwrap();
        let second = cache.get("{{ label }}").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
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
    fn template_renders_optional_fields_as_null() {
        let body = render_body(
            WebhookFormat::Template,
            &fixture(),
            None,
            Some(r#"{"source": {{ source_account }}, "severity": {{ severity }}, "ledger": {{ ledger }}}"#),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["source"], Value::Null);
        assert_eq!(v["severity"], Value::Null);
        assert_eq!(v["ledger"], Value::Null);
    }

    #[test]
    fn template_requires_a_body() {
        let err = render_body(WebhookFormat::Template, &fixture(), None, None).unwrap_err();
        assert!(err.to_string().contains("template"), "got: {}", err);
    }

    #[test]
    fn template_body_from_file_like_string_renders() {
        // Mirrors the CLI flow: the body is read from `--template-file` (or
        // `--template`) and handed to `render_body` unchanged.
        let file_contents = "{\n  \"content\": \"{{ rule_triggered }} on {{ label }}\",\n  \"tx\": \"{{ transaction_hash }}\"\n}\n";
        let body = render_body(
            WebhookFormat::Template,
            &fixture(),
            None,
            Some(file_contents),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["content"], "LargeTransfer(>=10000XLM) on Escrow <main> & co");
        assert_eq!(v["tx"], "abc123");
    }

    #[test]
    fn validate_template_accepts_optional_field_references() {
        validate_template(r#"{"text": {{ source_account }}, "memo": {{ memo }}}"#).unwrap();
    }

    #[test]
    fn validate_template_rejects_unknown_variables() {
        let err = validate_template("{{ nope }}").unwrap_err();
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
        p.severity = Some(Severity::Critical);
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

        let digest = slack_digest(&vec![p; 50]);
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
        p.severity = Some(Severity::Warning);
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

        let digest = teams_digest(&[fixture(), fixture()]);
        let card = &digest["attachments"][0]["content"];
        assert_eq!(card["body"][0]["text"], "TxWatch: 2 alert(s)");
        assert_eq!(card["body"][1]["facts"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn teams_digest_stays_under_the_payload_limit() {
        let mut p = fixture();
        p.rule_triggered = "r".repeat(500);
        p.label = "l".repeat(500);
        p.network = "n".repeat(500);
        p.transaction_hash = "t".repeat(500);
        p.explorer_link = format!("https://x.example/{}", "u".repeat(500));
        let payloads = vec![p; 50];
        let digest = teams_digest(&payloads);
        let body = serde_json::to_string(&digest).unwrap();
        assert!(body.len() < 28 * 1024, "body was {} bytes", body.len());
        let card = &digest["attachments"][0]["content"];
        let facts = card["body"][2]["facts"].as_array().unwrap();
        assert_eq!(facts.len(), TEAMS_DIGEST_FACTS_MAX);
        assert!(facts.iter().all(|f| f["title"]
            .as_str()
            .unwrap()
            .chars()
            .count()
            <= TEAMS_FACT_TITLE_MAX));
        assert!(facts.iter().all(|f| f["value"]
            .as_str()
            .unwrap()
            .chars()
            .count()
            <= TEAMS_FACT_VALUE_MAX));
        assert!(card["body"][1]["text"]
            .as_str()
            .unwrap()
            .contains("10 more alert(s)"));
    }

    #[test]
    fn discord_enforces_embed_limits() {
        let mut p = fixture();
        p.rule_triggered = "x".repeat(5000);
        p.label = "y".repeat(4000);
        p.function_names = vec!["f".repeat(3000)];
        p.source_account = Some("G".repeat(2000));
        p.ledger = Some(1);
        p.memo = Some("m".repeat(2000));
        p.severity = Some("critical".into());
        p.suppressed_count = 2;
        p.amount_xlm_decimal = Some("1.5".into());
        p.matched_events = (0..10)
            .map(|i| txwatch_rules::MatchedEvent {
                topics: vec![json!(format!("event-{}-{}", i, "z".repeat(200)))],
                data: Value::Null,
            })
            .collect();
        let discord = render(WebhookFormat::Discord, &p);
        let embed = &discord["embeds"][0];
        let fields = embed["fields"].as_array().unwrap();
        assert!(fields.len() <= 25);
        let mut total = embed["title"].as_str().unwrap().chars().count()
            + embed["description"].as_str().unwrap().chars().count();
        for f in fields {
            let name = f["name"].as_str().unwrap();
            let value = f["value"].as_str().unwrap();
            assert!(value.chars().count() <= 1024);
            total += name.chars().count() + value.chars().count();
        }
        assert!(total <= 6000, "embed total was {}", total);
    }

    #[test]
    fn discord_escapes_markdown_in_untrusted_values() {
        let mut p = fixture();
        p.label = "[click here](https://evil.example)".into();
        p.rule_triggered = "||spoiler|| `fence`".into();
        p.memo = Some("*bold* _it_ ~strike~ > quote \\".into());
        let discord = render(WebhookFormat::Discord, &p);
        let description = discord["embeds"][0]["description"].as_str().unwrap();
        assert!(description.contains("\\[click here\\]\\(https://evil.example\\)"));
        let title = discord["embeds"][0]["title"].as_str().unwrap();
        assert!(title.contains("\\|\\|spoiler\\|\\|"));
        assert!(title.contains("\\`fence\\`"));
        let memo = discord["embeds"][0]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "Memo")
            .unwrap()["value"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(memo.contains("\\*bold\\*"));
        assert!(memo.contains("\\_it\\_"));
        assert!(memo.contains("\\~strike\\~"));
        assert!(memo.contains("\\> quote"));
        assert!(memo.contains("\\\\"));

        let digest = render_batch_body(WebhookFormat::Discord, &[p], None).unwrap();
        let digest: Value = serde_json::from_str(&digest).unwrap();
        let desc = digest["embeds"][0]["description"].as_str().unwrap();
        assert!(desc.contains("\\[click here\\]"));
    }

    #[test]
    fn slack_digest_truncates_on_line_boundaries() {
        let payloads: Vec<AlertPayload> = (0..100)
            .map(|i| {
                let mut p = fixture();
                p.transaction_hash = format!("hash{}", i);
                p
            })
            .collect();
        let body = render_batch_body(WebhookFormat::Slack, &payloads, None).unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        let text = value["blocks"][1]["text"]["text"].as_str().unwrap();
        assert!(text.chars().count() <= 3000);
        assert!(text.contains("… and "));
        assert!(text.ends_with(" more"));
        // Every kept line is a complete alert line with balanced link markup.
        for line in text.lines().filter(|l| l.starts_with('•')) {
            assert_eq!(line.matches('<').count(), line.matches('>').count());
            assert!(line.ends_with('>'));
        }
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

    #[test]
    fn pagerduty_truncates_oversized_summary() {
        let mut p = fixture();
        p.label = "G".repeat(5000);
        let pd = render(WebhookFormat::Pagerduty, &p);
        let summary = pd["payload"]["summary"].as_str().unwrap();
        assert_eq!(summary.chars().count(), 1024);
        assert!(summary.ends_with('\u{2026}'));
    }

    #[test]
    fn pagerduty_custom_details_include_all_non_null_fields() {
        let mut p = fixture();
        p.severity = Some("critical".into());
        p.source_account = Some("GSOURCE".into());
        p.fee_account = Some("GFEE".into());
        p.memo = Some("invoice-7".into());
        p.ledger = Some(42);
        p.suppressed_count = 3;
        p.resolved = true;
        p.enrichment_incomplete = true;
        let pd = render(WebhookFormat::Pagerduty, &p);
        let details = &pd["payload"]["custom_details"];
        assert_eq!(details["alert_id"], p.alert_id);
        assert_eq!(details["rule_type"], "LargeTransfer");
        assert_eq!(details["severity"], "critical");
        assert_eq!(details["source_account"], "GSOURCE");
        assert_eq!(details["fee_account"], "GFEE");
        assert_eq!(details["memo"], "invoice-7");
        assert_eq!(details["ledger"], 42);
        assert_eq!(details["suppressed_count"], 3);
        assert_eq!(details["resolved"], true);
        assert_eq!(details["enrichment_incomplete"], true);
        assert!(details.get("observed_count").is_none());
    }
}
