use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, trace};
use txwatch_config::{
    AlertRule, AlertSeverity, DataMatcher, MatchOperator, RuleCombineMode, RuleConfig,
    TransferDirection, WatchedContract,
};
use txwatch_horizon::{EnrichedTransaction, HorizonTransfer, SorobanEvent, SorobanInvocation};

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid regex in rule '{rule}': {source}")]
    InvalidRegex {
        rule: String,
        #[source]
        source: regex::Error,
    },
}

/// Evaluation context passed alongside an enriched transaction so stateful or metadata-rich
/// rules can inspect network details, per-contract tags, and evaluation timestamps.
#[derive(Debug, Clone)]
pub struct EvalContext<'a> {
    pub network: &'a str,
    pub now: DateTime<Utc>,
    pub tags: &'a BTreeMap<String, String>,
}

impl<'a> EvalContext<'a> {
    pub fn new(network: &'a str, tags: &'a BTreeMap<String, String>) -> Self {
        Self {
            network,
            now: Utc::now(),
            tags,
        }
    }
}

/// Result of evaluating a single rule against a transaction, capturing both the boolean match
/// and human-readable diagnostic reasons explaining why the rule matched or did not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleEvaluation {
    pub matched: bool,
    pub reasons: Vec<String>,
}

impl RuleEvaluation {
    pub fn matched(reason: impl Into<String>) -> Self {
        Self {
            matched: true,
            reasons: vec![reason.into()],
        }
    }

    pub fn unmatched(reason: impl Into<String>) -> Self {
        Self {
            matched: false,
            reasons: vec![reason.into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertPayload {
    pub alert_id: String,
    pub schema_version: u32,
    pub fired_at: DateTime<Utc>,
    pub network: String,
    pub contract_id: String,
    pub contract_label: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub contract_tags: BTreeMap<String, String>,
    pub severity: AlertSeverity,
    pub rule: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_reasons: Vec<String>,
    pub tx_hash: String,
    pub ledger: u64,
    pub tx_created_at: DateTime<Utc>,
    pub successful: bool,
    pub source_account: String,
    pub fee_charged_stroops: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub arguments: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub matching_events: Vec<SorobanEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub transfers: Vec<HorizonTransfer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_in_stroops: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_out_stroops: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_count: Option<u64>,
}

/// Evaluates rules for a watched contract and tracks per-rule cooldowns and suppressed counts.
pub struct RuleEngine {
    cooldowns: Mutex<HashMap<String, CooldownState>>,
    rate_tracker: RateTracker,
}

#[derive(Debug, Clone)]
struct CooldownState {
    last_fired: Instant,
    suppressed_since_fire: u64,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            cooldowns: Mutex::new(HashMap::new()),
            rate_tracker: RateTracker::new(),
        }
    }

    /// Evaluates all enabled rules on `contract` against `tx`, returning emitted alerts.
    ///
    /// Rules with `cooldown_seconds > 0` are suppressed while within their cooldown window; if
    /// `cooldown_summary` is true, the next alert fired after the cooldown expires includes
    /// `suppressed_count` indicating how many matching transactions were skipped.
    ///
    /// Note on stateful rules (`RateSpike`): each rule is evaluated independently in order;
    /// `RateSpike` records the transaction timestamp in `self.rate_tracker` regardless of
    /// whether the spike threshold has been crossed yet.
    pub fn evaluate(
        &self,
        contract: &WatchedContract,
        tx: &EnrichedTransaction,
        network: &str,
        explorer_base: Option<&str>,
    ) -> Result<Vec<AlertPayload>, RuleError> {
        if !contract.enabled || contract.is_muted() {
            return Ok(Vec::new());
        }

        let ctx = EvalContext::new(network, &contract.tags);
        let mut alerts = Vec::new();
        let now_instant = Instant::now();

        for (rule_idx, rule_cfg) in contract.rules.iter().enumerate() {
            if !rule_cfg.enabled {
                continue;
            }

            let eval = match &rule_cfg.rule {
                AlertRule::RateSpike {
                    max_transactions,
                    window_seconds,
                } => {
                    let key = format!("{}:{rule_idx}", contract.id);
                    let count = self.rate_tracker.evaluate(
                        &key,
                        tx.created_at,
                        Duration::from_secs(*window_seconds),
                    );
                    if count > *max_transactions as usize {
                        RuleEvaluation::matched(format!(
                            "{count} transactions in {}s window exceeds max_transactions={max_transactions}",
                            window_seconds
                        ))
                    } else {
                        RuleEvaluation::unmatched(format!(
                            "{count} transactions in {}s window (threshold > {max_transactions})",
                            window_seconds
                        ))
                    }
                }
                AlertRule::Inactivity { .. } => {
                    // Inactivity is driven by the background timer tick (`evaluate_inactivity`),
                    // not by incoming transactions.
                    continue;
                }
                other => evaluate_rule_with_context(&contract.id, other, tx, &ctx)?,
            };

            if !eval.matched {
                continue;
            }

            let rule_label = rule_cfg.rule.label();
            let cooldown_key = format!("{}:{rule_idx}:{rule_label}", contract.id);
            let mut suppressed_carryover: Option<u64> = None;

            if rule_cfg.cooldown_seconds > 0 {
                let mut map = self.cooldowns.lock().expect("cooldown lock poisoned");
                let window = Duration::from_secs(rule_cfg.cooldown_seconds);
                if let Some(state) = map.get_mut(&cooldown_key) {
                    if now_instant.duration_since(state.last_fired) < window {
                        state.suppressed_since_fire += 1;
                        debug!(
                            contract = %contract.label,
                            rule = %rule_label,
                            suppressed = state.suppressed_since_fire,
                            "suppressing alert due to rule cooldown"
                        );
                        continue;
                    }
                    if rule_cfg.cooldown_summary && state.suppressed_since_fire > 0 {
                        suppressed_carryover = Some(state.suppressed_since_fire);
                    }
                }
                map.insert(
                    cooldown_key,
                    CooldownState {
                        last_fired: now_instant,
                        suppressed_since_fire: 0,
                    },
                );
            }

            let payload = build_alert_payload(
                contract,
                rule_cfg,
                rule_idx,
                tx,
                network,
                explorer_base,
                eval.reasons,
                suppressed_carryover,
            );
            alerts.push(payload);
        }

        Ok(alerts)
    }

    /// Evaluates `Inactivity` rules across all contracts given the last observed activity
    /// timestamp per contract. Returns an alert for any contract whose silence exceeds
    /// `silence_seconds` (respecting `repeat_interval_seconds` or `cooldown_seconds`).
    pub fn evaluate_inactivity(
        &self,
        contract: &WatchedContract,
        last_seen: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        network: &str,
    ) -> Vec<AlertPayload> {
        if !contract.enabled || contract.is_muted() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let now_instant = Instant::now();

        for (rule_idx, rule_cfg) in contract.rules.iter().enumerate() {
            if !rule_cfg.enabled {
                continue;
            }
            let AlertRule::Inactivity {
                silence_seconds,
                repeat_interval_seconds,
            } = &rule_cfg.rule
            else {
                continue;
            };

            let elapsed_secs = match last_seen {
                Some(ts) => (now - ts).num_seconds().max(0) as u64,
                None => *silence_seconds,
            };
            if elapsed_secs < *silence_seconds {
                continue;
            }

            let rule_label = rule_cfg.rule.label();
            let cooldown_key = format!("{}:{rule_idx}:inactivity", contract.id);
            let repeat_secs = repeat_interval_seconds
                .unwrap_or(rule_cfg.cooldown_seconds)
                .max(1);

            {
                let mut map = self.cooldowns.lock().expect("cooldown lock poisoned");
                if let Some(state) = map.get(&cooldown_key) {
                    if now_instant.duration_since(state.last_fired)
                        < Duration::from_secs(repeat_secs)
                    {
                        continue;
                    }
                }
                map.insert(
                    cooldown_key,
                    CooldownState {
                        last_fired: now_instant,
                        suppressed_since_fire: 0,
                    },
                );
            }

            let reason = match last_seen {
                Some(ts) => format!(
                    "no activity observed for {elapsed_secs}s (last seen at {}, threshold {silence_seconds}s)",
                    ts.to_rfc3339()
                ),
                None => format!(
                    "no activity observed since watcher started (threshold {silence_seconds}s)"
                ),
            };
            let summary = format!(
                "[{}] {} inactive for {}s",
                contract.label, contract.id, elapsed_secs
            );
            let alert_id = compute_alert_id(
                &contract.id,
                &format!("inactivity-{}", now.timestamp() / (repeat_secs as i64)),
                &rule_label,
                rule_idx,
            );

            out.push(AlertPayload {
                alert_id,
                schema_version: 1,
                fired_at: now,
                network: network.to_string(),
                contract_id: contract.id.clone(),
                contract_label: contract.label.clone(),
                contract_tags: contract.tags.clone(),
                severity: rule_cfg.severity,
                rule: rule_label,
                summary,
                match_reasons: vec![reason],
                tx_hash: String::new(),
                ledger: 0,
                tx_created_at: last_seen.unwrap_or(now),
                successful: true,
                source_account: String::new(),
                fee_charged_stroops: 0,
                function: None,
                arguments: Vec::new(),
                matching_events: Vec::new(),
                transfers: Vec::new(),
                amount_in_stroops: None,
                amount_out_stroops: None,
                explorer_url: None,
                suppressed_count: None,
            });
        }

        out
    }

    /// Removes expired cooldown entries and stale rate-tracker buckets to bound memory usage.
    pub fn prune_stale_state(&self, max_age: Duration) {
        let now = Instant::now();
        let mut map = self.cooldowns.lock().expect("cooldown lock poisoned");
        map.retain(|_, state| now.duration_since(state.last_fired) < max_age);
        self.rate_tracker.prune(Utc::now(), max_age);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_alert_payload(
    contract: &WatchedContract,
    rule_cfg: &RuleConfig,
    rule_idx: usize,
    tx: &EnrichedTransaction,
    network: &str,
    explorer_base: Option<&str>,
    reasons: Vec<String>,
    suppressed_count: Option<u64>,
) -> AlertPayload {
    let rule_label = rule_cfg.rule.label();
    let matching_invocation = matching_invocation_for_rule(&contract.id, &rule_cfg.rule, tx);
    let function = matching_invocation
        .map(|inv| inv.function.clone())
        .or_else(|| tx.primary_function().map(str::to_string));
    let arguments = matching_invocation
        .map(|inv| inv.arguments.clone())
        .or_else(|| tx.primary_arguments().map(|a| a.to_vec()))
        .unwrap_or_default();

    let matching_events: Vec<SorobanEvent> = match &rule_cfg.rule {
        AlertRule::EventEmitted { .. } => matching_events_for_rule(&contract.id, &rule_cfg.rule, tx)
            .into_iter()
            .cloned()
            .collect(),
        _ => tx
            .events
            .iter()
            .filter(|e| e.contract_id.as_deref() == Some(contract.id.as_str()))
            .cloned()
            .collect(),
    };

    let (amount_in_stroops, amount_out_stroops) = match &rule_cfg.rule {
        AlertRule::LargeTransfer {
            asset, direction, ..
        } => {
            let in_sum = sum_transfers_stroops(
                &tx.transfers,
                &contract.id,
                asset.as_deref(),
                TransferDirection::In,
            );
            let out_sum = sum_transfers_stroops(
                &tx.transfers,
                &contract.id,
                asset.as_deref(),
                TransferDirection::Out,
            );
            match direction {
                TransferDirection::In => (Some(in_sum), None),
                TransferDirection::Out => (None, Some(out_sum)),
                TransferDirection::Any => (
                    (in_sum > 0).then_some(in_sum),
                    (out_sum > 0).then_some(out_sum),
                ),
            }
        }
        _ => (None, None),
    };

    let summary = format_summary(
        &contract.label,
        &rule_label,
        tx,
        function.as_deref(),
        &reasons,
    );
    let alert_id = compute_alert_id(&contract.id, &tx.hash, &rule_label, rule_idx);
    let explorer_url =
        explorer_base.map(|base| format!("{}/tx/{}", base.trim_end_matches('/'), tx.hash));

    AlertPayload {
        alert_id,
        schema_version: 1,
        fired_at: Utc::now(),
        network: network.to_string(),
        contract_id: contract.id.clone(),
        contract_label: contract.label.clone(),
        contract_tags: contract.tags.clone(),
        severity: rule_cfg.severity,
        rule: rule_label,
        summary,
        match_reasons: reasons,
        tx_hash: tx.hash.clone(),
        ledger: tx.ledger,
        tx_created_at: tx.created_at,
        successful: tx.successful,
        source_account: tx.source_account.clone(),
        fee_charged_stroops: tx.fee_charged,
        function,
        arguments,
        matching_events,
        transfers: tx.transfers.clone(),
        amount_in_stroops,
        amount_out_stroops,
        explorer_url,
        suppressed_count,
    }
}

fn compute_alert_id(contract_id: &str, tx_hash: &str, rule_label: &str, rule_idx: usize) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(contract_id.as_bytes());
    hasher.update(b":");
    hasher.update(tx_hash.as_bytes());
    hasher.update(b":");
    hasher.update(rule_label.as_bytes());
    hasher.update(b":");
    hasher.update(rule_idx.to_string().as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

fn format_summary(
    contract_label: &str,
    rule_label: &str,
    tx: &EnrichedTransaction,
    function: Option<&str>,
    reasons: &[String],
) -> String {
    let status = if tx.successful { "OK" } else { "FAILED" };
    let fn_part = function
        .map(|f| format!(" fn={f}()"))
        .unwrap_or_default();
    let reason_part = reasons
        .first()
        .map(|r| format!(" — {r}"))
        .unwrap_or_default();
    format!(
        "[{contract_label}] {rule_label} matched tx {} (ledger {}, {status}{fn_part}){reason_part}",
        short_hash(&tx.hash),
        tx.ledger
    )
}

fn short_hash(hash: &str) -> &str {
    if hash.len() > 12 {
        &hash[..12]
    } else {
        hash
    }
}

/// Evaluates a single `AlertRule` against `tx` using default metadata context.
pub fn evaluate_rule(
    contract_id: &str,
    rule: &AlertRule,
    tx: &EnrichedTransaction,
) -> Result<bool, RuleError> {
    let empty_tags = BTreeMap::new();
    let ctx = EvalContext::new("unknown", &empty_tags);
    Ok(evaluate_rule_with_context(contract_id, rule, tx, &ctx)?.matched)
}

/// Evaluates a single `AlertRule` against `tx`, returning a detailed [`RuleEvaluation`].
pub fn evaluate_rule_with_context(
    contract_id: &str,
    rule: &AlertRule,
    tx: &EnrichedTransaction,
    ctx: &EvalContext<'_>,
) -> Result<RuleEvaluation, RuleError> {
    let res = match rule {
        AlertRule::AnyTransaction => RuleEvaluation::matched(format!(
            "transaction {} touched contract {contract_id} on ledger {}",
            short_hash(&tx.hash),
            tx.ledger
        )),

        AlertRule::FailedTransaction => {
            if !tx.successful {
                RuleEvaluation::matched(format!(
                    "transaction {} failed on ledger {}",
                    short_hash(&tx.hash),
                    tx.ledger
                ))
            } else {
                RuleEvaluation::unmatched("transaction succeeded")
            }
        }

        AlertRule::FunctionCall {
            function,
            arg_contains,
            arg_regex,
        } => evaluate_function_call(
            contract_id,
            tx,
            function,
            arg_contains.as_deref(),
            arg_regex.as_deref(),
        )?,

        AlertRule::EventEmitted {
            topic_contains,
            topic_regex,
            topics,
            data_contains,
            data_match,
        } => evaluate_event_emitted(
            contract_id,
            tx,
            topic_contains.as_deref(),
            topic_regex.as_deref(),
            topics,
            data_contains.as_deref(),
            data_match,
        )?,

        AlertRule::HighFee {
            threshold_stroops,
            computed_threshold_stroops,
            ..
        } => {
            let threshold = (*threshold_stroops).max(*computed_threshold_stroops);
            if tx.fee_charged >= threshold {
                RuleEvaluation::matched(format!(
                    "fee_charged {} stroops >= threshold {threshold} stroops",
                    tx.fee_charged
                ))
            } else {
                RuleEvaluation::unmatched(format!(
                    "fee_charged {} stroops < threshold {threshold} stroops",
                    tx.fee_charged
                ))
            }
        }

        AlertRule::LargeTransfer {
            threshold_stroops,
            threshold_xlm,
            asset,
            direction,
        } => {
            let threshold = match threshold_xlm {
                Some(xlm) if *threshold_stroops == 0 => xlm.saturating_mul(10_000_000),
                _ => *threshold_stroops,
            };
            evaluate_large_transfer(contract_id, tx, threshold, asset.as_deref(), direction)
        }

        AlertRule::SourceAccount {
            account,
            accounts,
            match_muxed_base,
        } => evaluate_source_account(tx, account.as_deref(), accounts, *match_muxed_base),

        AlertRule::Composite { mode, rules } => {
            evaluate_composite(contract_id, tx, ctx, mode, rules)?
        }

        AlertRule::Not { rule: inner } => {
            let inner_eval = evaluate_rule_with_context(contract_id, inner, tx, ctx)?;
            if inner_eval.matched {
                RuleEvaluation::unmatched(format!("negated rule matched: {}", inner.label()))
            } else {
                RuleEvaluation::matched(format!("negated rule did not match: {}", inner.label()))
            }
        }

        AlertRule::RateSpike { .. } | AlertRule::Inactivity { .. } => {
            RuleEvaluation::unmatched("stateful rule requires RuleEngine::evaluate")
        }
    };

    trace!(
        contract_id,
        rule = %rule.label(),
        tx = %tx.hash,
        matched = res.matched,
        "evaluated rule"
    );
    Ok(res)
}

fn evaluate_function_call(
    contract_id: &str,
    tx: &EnrichedTransaction,
    target_function: &str,
    arg_contains: Option<&str>,
    arg_regex: Option<&str>,
) -> Result<RuleEvaluation, RuleError> {
    let compiled_re = match arg_regex {
        Some(pat) => Some(Regex::new(pat).map_err(|source| RuleError::InvalidRegex {
            rule: format!("FunctionCall:{target_function}"),
            source,
        })?),
        None => None,
    };

    let matching_invocations = invocations_for_contract(contract_id, tx);
    if matching_invocations.is_empty() {
        return Ok(RuleEvaluation::unmatched(format!(
            "no invocations targeting contract {contract_id}"
        )));
    }

    for inv in matching_invocations {
        if inv.function != target_function {
            continue;
        }
        let serialized_args = serde_json::to_string(&inv.arguments).unwrap_or_default();

        if let Some(needle) = arg_contains {
            if !serialized_args.contains(needle) {
                continue;
            }
        }
        if let Some(re) = &compiled_re {
            if !re.is_match(&serialized_args) {
                continue;
            }
        }
        return Ok(RuleEvaluation::matched(format!(
            "called {target_function}() on {contract_id}"
        )));
    }

    Ok(RuleEvaluation::unmatched(format!(
        "no invocation of '{target_function}' matched argument filters"
    )))
}

fn invocations_for_contract<'a>(
    contract_id: &str,
    tx: &'a EnrichedTransaction,
) -> Vec<&'a SorobanInvocation> {
    let explicit: Vec<&SorobanInvocation> = tx
        .invocations
        .iter()
        .filter(|inv| inv.contract_id == contract_id)
        .collect();
    if !explicit.is_empty() {
        return explicit;
    }
    // Fallback for transactions constructed with only top-level function/arguments fields.
    if let Some(function) = tx.function.as_deref() {
        // Synthesize match against top-level fields by returning empty and handling inline if needed.
        let _ = function;
    }
    Vec::new()
}

fn matching_invocation_for_rule<'a>(
    contract_id: &str,
    rule: &AlertRule,
    tx: &'a EnrichedTransaction,
) -> Option<&'a SorobanInvocation> {
    match rule {
        AlertRule::FunctionCall {
            function,
            arg_contains,
            arg_regex,
        } => {
            let re = arg_regex.as_deref().and_then(|p| Regex::new(p).ok());
            tx.invocations.iter().find(|inv| {
                if inv.contract_id != contract_id || inv.function != *function {
                    return false;
                }
                let serialized = serde_json::to_string(&inv.arguments).unwrap_or_default();
                if let Some(needle) = arg_contains.as_deref() {
                    if !serialized.contains(needle) {
                        return false;
                    }
                }
                if let Some(re) = &re {
                    if !re.is_match(&serialized) {
                        return false;
                    }
                }
                true
            })
        }
        _ => tx
            .invocations
            .iter()
            .find(|inv| inv.contract_id == contract_id),
    }
}

fn evaluate_event_emitted(
    contract_id: &str,
    tx: &EnrichedTransaction,
    topic_contains: Option<&str>,
    topic_regex: Option<&str>,
    positional_topics: &[Option<String>],
    data_contains: Option<&str>,
    data_match: &[DataMatcher],
) -> Result<RuleEvaluation, RuleError> {
    let compiled_re = match topic_regex {
        Some(pat) => Some(Regex::new(pat).map_err(|source| RuleError::InvalidRegex {
            rule: "EventEmitted".to_string(),
            source,
        })?),
        None => None,
    };

    let matched = matching_events_inner(
        contract_id,
        tx,
        topic_contains,
        compiled_re.as_ref(),
        positional_topics,
        data_contains,
        data_match,
    )?;

    if matched.is_empty() {
        Ok(RuleEvaluation::unmatched(format!(
            "no events from {contract_id} matched EventEmitted filters"
        )))
    } else {
        Ok(RuleEvaluation::matched(format!(
            "{} event(s) from {contract_id} matched EventEmitted filters",
            matched.len()
        )))
    }
}

fn matching_events_for_rule<'a>(
    contract_id: &str,
    rule: &AlertRule,
    tx: &'a EnrichedTransaction,
) -> Vec<&'a SorobanEvent> {
    let AlertRule::EventEmitted {
        topic_contains,
        topic_regex,
        topics,
        data_contains,
        data_match,
    } = rule
    else {
        return Vec::new();
    };
    let compiled_re = topic_regex.as_deref().and_then(|p| Regex::new(p).ok());
    matching_events_inner(
        contract_id,
        tx,
        topic_contains.as_deref(),
        compiled_re.as_ref(),
        topics,
        data_contains.as_deref(),
        data_match,
    )
    .unwrap_or_default()
}

fn matching_events_inner<'a>(
    contract_id: &str,
    tx: &'a EnrichedTransaction,
    topic_contains: Option<&str>,
    topic_regex: Option<&Regex>,
    positional_topics: &[Option<String>],
    data_contains: Option<&str>,
    data_match: &[DataMatcher],
) -> Result<Vec<&'a SorobanEvent>, RuleError> {
    let mut out = Vec::new();
    for ev in &tx.events {
        if ev.contract_id.as_deref() != Some(contract_id) {
            continue;
        }
        if !positional_topics.is_empty() && !matches_positional_topics(&ev.topics, positional_topics)
        {
            continue;
        }
        if let Some(needle) = topic_contains {
            let joined = ev
                .topics
                .iter()
                .map(value_to_searchable_str)
                .collect::<Vec<_>>()
                .join(" ");
            if !joined.contains(needle) {
                continue;
            }
        }
        if let Some(re) = topic_regex {
            let matched_any = ev
                .topics
                .iter()
                .map(value_to_searchable_str)
                .any(|s| re.is_match(&s));
            if !matched_any {
                continue;
            }
        }
        if let Some(needle) = data_contains {
            let serialized = serde_json::to_string(&ev.data).unwrap_or_default();
            if !serialized.contains(needle) {
                continue;
            }
        }
        if !data_match.is_empty() && !matches_all_data_matchers(&ev.data, data_match)? {
            continue;
        }
        out.push(ev);
    }
    Ok(out)
}

fn matches_positional_topics(actual: &[Value], expected: &[Option<String>]) -> bool {
    if actual.len() < expected.len() {
        return false;
    }
    for (idx, exp) in expected.iter().enumerate() {
        let Some(expected_val) = exp.as_deref() else {
            continue; // wildcard slot
        };
        let actual_str = value_to_searchable_str(&actual[idx]);
        if actual_str != expected_val {
            return false;
        }
    }
    true
}

fn value_to_searchable_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn matches_all_data_matchers(data: &Value, matchers: &[DataMatcher]) -> Result<bool, RuleError> {
    for matcher in matchers {
        let target = if matcher.pointer.is_empty() {
            Some(data)
        } else {
            data.pointer(&matcher.pointer)
        };
        if !eval_single_data_matcher(target, matcher)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn eval_single_data_matcher(
    target: Option<&Value>,
    matcher: &DataMatcher,
) -> Result<bool, RuleError> {
    match matcher.op {
        MatchOperator::Exists => Ok(target.is_some() && !matches!(target, Some(Value::Null))),
        MatchOperator::Eq => {
            let Some(val) = target else {
                return Ok(false);
            };
            let expected = matcher.value.as_deref().unwrap_or_default();
            Ok(compare_eq(val, expected))
        }
        MatchOperator::Neq => {
            let Some(val) = target else {
                return Ok(true);
            };
            let expected = matcher.value.as_deref().unwrap_or_default();
            Ok(!compare_eq(val, expected))
        }
        MatchOperator::Contains => {
            let Some(val) = target else {
                return Ok(false);
            };
            let needle = matcher.value.as_deref().unwrap_or_default();
            Ok(value_to_searchable_str(val).contains(needle))
        }
        MatchOperator::Regex => {
            let Some(val) = target else {
                return Ok(false);
            };
            let pat = matcher.value.as_deref().unwrap_or_default();
            let re = Regex::new(pat).map_err(|source| RuleError::InvalidRegex {
                rule: format!("data_match:{}", matcher.pointer),
                source,
            })?;
            Ok(re.is_match(&value_to_searchable_str(val)))
        }
        MatchOperator::Gt | MatchOperator::Gte | MatchOperator::Lt | MatchOperator::Lte => {
            let Some(val) = target else {
                return Ok(false);
            };
            let Some(lhs) = extract_numeric(val) else {
                return Ok(false);
            };
            let rhs: f64 = matcher
                .value
                .as_deref()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(f64::NAN);
            if rhs.is_nan() {
                return Ok(false);
            }
            Ok(match matcher.op {
                MatchOperator::Gt => lhs > rhs,
                MatchOperator::Gte => lhs >= rhs,
                MatchOperator::Lt => lhs < rhs,
                MatchOperator::Lte => lhs <= rhs,
                _ => unreachable!(),
            })
        }
    }
}

fn compare_eq(val: &Value, expected: &str) -> bool {
    match val {
        Value::String(s) => s == expected,
        Value::Number(n) => {
            if n.to_string() == expected {
                return true;
            }
            if let (Some(a), Ok(b)) = (extract_numeric(val), expected.trim().parse::<f64>()) {
                (a - b).abs() < f64::EPSILON
            } else {
                false
            }
        }
        Value::Bool(b) => expected.eq_ignore_ascii_case(if *b { "true" } else { "false" }),
        Value::Null => expected.eq_ignore_ascii_case("null"),
        other => serde_json::to_string(other).ok().as_deref() == Some(expected),
    }
}

fn extract_numeric(val: &Value) -> Option<f64> {
    match val {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn transfer_matches_asset(t: &HorizonTransfer, asset_filter: Option<&str>) -> bool {
    let Some(filter) = asset_filter else {
        return true;
    };
    if filter.eq_ignore_ascii_case("XLM") || filter.eq_ignore_ascii_case("native") {
        t.asset_type == "native" || t.asset_code.eq_ignore_ascii_case("XLM")
    } else if let Some((code, issuer)) = filter.split_once(':') {
        t.asset_code == code && t.asset_issuer.as_deref() == Some(issuer)
    } else {
        t.asset_code == filter
    }
}

fn transfer_matches_direction(
    t: &HorizonTransfer,
    contract_id: &str,
    direction: &TransferDirection,
) -> bool {
    match direction {
        TransferDirection::Any => true,
        TransferDirection::In => t.to == contract_id,
        TransferDirection::Out => t.from == contract_id,
    }
}

fn sum_transfers_stroops(
    transfers: &[HorizonTransfer],
    contract_id: &str,
    asset_filter: Option<&str>,
    direction: TransferDirection,
) -> u64 {
    transfers
        .iter()
        .filter(|t| transfer_matches_asset(t, asset_filter))
        .filter(|t| transfer_matches_direction(t, contract_id, &direction))
        .filter_map(|t| parse_stellar_amount_to_stroops(&t.amount))
        .fold(0u64, u64::saturating_add)
}

fn evaluate_large_transfer(
    contract_id: &str,
    tx: &EnrichedTransaction,
    threshold_stroops: u64,
    asset_filter: Option<&str>,
    direction: &TransferDirection,
) -> RuleEvaluation {
    for t in &tx.transfers {
        if !transfer_matches_asset(t, asset_filter) {
            continue;
        }
        if !transfer_matches_direction(t, contract_id, direction) {
            continue;
        }
        if let Some(stroops) = parse_stellar_amount_to_stroops(&t.amount) {
            if stroops >= threshold_stroops {
                return RuleEvaluation::matched(format!(
                    "transfer of {} {} ({} -> {}) >= {threshold_stroops} stroops",
                    t.amount, t.asset_code, t.from, t.to
                ));
            }
        }
    }
    RuleEvaluation::unmatched(format!(
        "no transfer matching direction={direction:?} asset={asset_filter:?} >= {threshold_stroops} stroops"
    ))
}

/// Converts a Stellar decimal amount string (e.g. `"125.5000000"`) into integer stroops
/// (`1_255_000_000`) without floating-point rounding drift.
pub fn parse_stellar_amount_to_stroops(amount: &str) -> Option<u64> {
    let trimmed = amount.trim();
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return None;
    }
    let (whole_str, frac_str) = match trimmed.split_once('.') {
        Some((w, f)) => (w, f),
        None => (trimmed, ""),
    };
    let whole: u64 = if whole_str.is_empty() {
        0
    } else {
        whole_str.parse().ok()?
    };
    if !frac_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut padded = [b'0'; 7];
    for (idx, b) in frac_str.bytes().take(7).enumerate() {
        padded[idx] = b;
    }
    let frac_str_7 = std::str::from_utf8(&padded).ok()?;
    let frac: u64 = frac_str_7.parse().ok()?;
    whole
        .checked_mul(10_000_000)
        .and_then(|w| w.checked_add(frac))
}

fn evaluate_source_account(
    tx: &EnrichedTransaction,
    single_account: Option<&str>,
    accounts: &[String],
    match_muxed_base: bool,
) -> RuleEvaluation {
    let mut targets: Vec<&str> = Vec::new();
    if let Some(a) = single_account {
        if !a.is_empty() {
            targets.push(a);
        }
    }
    for a in accounts {
        if !a.is_empty() {
            targets.push(a.as_str());
        }
    }

    let mut candidates: Vec<String> = vec![tx.source_account.clone()];
    if let Some(fee_acct) = &tx.fee_account {
        candidates.push(fee_acct.clone());
    }
    if match_muxed_base {
        for raw in [&tx.source_account]
            .into_iter()
            .chain(tx.fee_account.as_ref())
        {
            if raw.starts_with('M') {
                if let Some(base_g) = muxed_to_base_g_account(raw) {
                    candidates.push(base_g);
                }
            }
        }
    }

    for target in &targets {
        if candidates.iter().any(|c| c == target) {
            return RuleEvaluation::matched(format!("transaction source matched {target}"));
        }
        if match_muxed_base && target.starts_with('M') {
            if let Some(target_base) = muxed_to_base_g_account(target) {
                if candidates.iter().any(|c| c == &target_base) {
                    return RuleEvaluation::matched(format!(
                        "transaction source matched muxed base account {target_base}"
                    ));
                }
            }
        }
    }

    RuleEvaluation::unmatched(format!(
        "source account {} did not match configured accounts",
        tx.source_account
    ))
}

/// Extracts the underlying `G...` Ed25519 public key from a muxed `M...` Stellar StrKey address.
pub fn muxed_to_base_g_account(muxed: &str) -> Option<String> {
    if !muxed.starts_with('M') || muxed.len() != 69 {
        return None;
    }
    let decoded = decode_base32_strkey(muxed)?;
    if decoded.len() != 43 || decoded[0] != 0x60 {
        return None;
    }
    let mut ed25519_key = [0u8; 32];
    ed25519_key.copy_from_slice(&decoded[1..33]);
    Some(txwatch_config::encode_account_id(&ed25519_key))
}

fn decode_base32_strkey(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((input.len() * 5) / 8);
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    for b in input.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn evaluate_composite(
    contract_id: &str,
    tx: &EnrichedTransaction,
    ctx: &EvalContext<'_>,
    mode: &RuleCombineMode,
    rules: &[AlertRule],
) -> Result<RuleEvaluation, RuleError> {
    let mut reasons = Vec::new();
    match mode {
        RuleCombineMode::All => {
            for sub in rules {
                let eval = evaluate_rule_with_context(contract_id, sub, tx, ctx)?;
                if !eval.matched {
                    return Ok(RuleEvaluation::unmatched(format!(
                        "composite(all) failed at {}: {}",
                        sub.label(),
                        eval.reasons.join("; ")
                    )));
                }
                reasons.extend(eval.reasons);
            }
            Ok(RuleEvaluation {
                matched: true,
                reasons,
            })
        }
        RuleCombineMode::Any => {
            for sub in rules {
                let eval = evaluate_rule_with_context(contract_id, sub, tx, ctx)?;
                if eval.matched {
                    return Ok(eval);
                }
            }
            Ok(RuleEvaluation::unmatched(
                "composite(any): none of the child rules matched",
            ))
        }
    }
}

/// Sliding-window per-key event rate tracker used by `RateSpike` rules.
pub struct RateTracker {
    windows: Mutex<HashMap<String, VecDeque<DateTime<Utc>>>>,
}

impl Default for RateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RateTracker {
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Records an event at `now` for `key` and returns the total number of events observed
    /// within `[now - window, now]`.
    pub fn evaluate(&self, key: &str, now: DateTime<Utc>, window: Duration) -> usize {
        let mut map = self.windows.lock().expect("rate tracker lock poisoned");
        let queue = map.entry(key.to_string()).or_default();
        let cutoff = now - chrono::Duration::from_std(window).unwrap_or_default();
        while let Some(&front) = queue.front() {
            if front < cutoff {
                queue.pop_front();
            } else {
                break;
            }
        }
        queue.push_back(now);
        queue.len()
    }

    pub fn prune(&self, now: DateTime<Utc>, max_age: Duration) {
        let mut map = self.windows.lock().expect("rate tracker lock poisoned");
        let cutoff = now - chrono::Duration::from_std(max_age).unwrap_or_default();
        map.retain(|_, queue| {
            while let Some(&front) = queue.front() {
                if front < cutoff {
                    queue.pop_front();
                } else {
                    break;
                }
            }
            !queue.is_empty()
        });
    }
}

/// Convenience helper returning JSON diagnostics for dry-run CLI inspections.
pub fn explain_transaction(
    contract: &WatchedContract,
    tx: &EnrichedTransaction,
    network: &str,
) -> Result<Value, RuleError> {
    let ctx = EvalContext::new(network, &contract.tags);
    let mut results = Vec::new();
    for (idx, rule_cfg) in contract.rules.iter().enumerate() {
        let eval = evaluate_rule_with_context(&contract.id, &rule_cfg.rule, tx, &ctx)?;
        results.push(json!({
            "index": idx,
            "rule": rule_cfg.rule.label(),
            "enabled": rule_cfg.enabled,
            "severity": rule_cfg.severity,
            "matched": eval.matched,
            "reasons": eval.reasons,
        }));
    }
    Ok(json!({
        "contract_id": contract.id,
        "contract_label": contract.label,
        "tx_hash": tx.hash,
        "ledger": tx.ledger,
        "evaluations": results,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use proptest::prelude::*;
    use txwatch_config::{encode_account_id, encode_contract_id, AlertFormat, RuleConfig};

    fn sample_tx(contract_id: &str) -> EnrichedTransaction {
        EnrichedTransaction {
            hash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            ledger: 500_001,
            created_at: Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap(),
            successful: true,
            source_account: encode_account_id(&[1u8; 32]),
            fee_account: None,
            fee_charged: 120_000,
            max_fee: 500_000,
            operation_count: 1,
            memo_type: "none".to_string(),
            memo: None,
            function: Some("swap".to_string()),
            arguments: vec![json!("USDC"), json!(1_000_000)],
            invocations: vec![SorobanInvocation {
                contract_id: contract_id.to_string(),
                function: "swap".to_string(),
                arguments: vec![json!("USDC"), json!(1_000_000)],
            }],
            events: vec![SorobanEvent {
                contract_id: Some(contract_id.to_string()),
                event_type: "contract".to_string(),
                topics: vec![json!("swap"), json!("GUSER123")],
                data: json!({
                    "amount_in": 1000000,
                    "amount_out": 995000,
                    "pool": { "pair": "XLM/USDC", "fee_bps": 30 }
                }),
            }],
            transfers: vec![
                HorizonTransfer {
                    from: encode_account_id(&[1u8; 32]),
                    to: contract_id.to_string(),
                    asset_type: "native".to_string(),
                    asset_code: "XLM".to_string(),
                    asset_issuer: None,
                    amount: "250.0000000".to_string(),
                },
                HorizonTransfer {
                    from: contract_id.to_string(),
                    to: encode_account_id(&[2u8; 32]),
                    asset_type: "credit_alphanum4".to_string(),
                    asset_code: "USDC".to_string(),
                    asset_issuer: Some(encode_account_id(&[9u8; 32])),
                    amount: "50.0000000".to_string(),
                },
            ],
        }
    }

    fn sample_contract(id: &str, rules: Vec<RuleConfig>) -> WatchedContract {
        WatchedContract {
            id: id.to_string(),
            label: "test-pool".to_string(),
            enabled: true,
            webhook_url: Some("https://example.com/hook".to_string()),
            webhook_secret: None,
            webhook_format: AlertFormat::Json,
            webhook_headers: BTreeMap::new(),
            webhook_template: None,
            webhook_content_type: None,
            webhooks: Vec::new(),
            tags: BTreeMap::new(),
            start_ledger: None,
            rules,
            mute_until: None,
            rate_limit: None,
        }
    }

    #[test]
    fn evaluates_basic_rules_accurately() {
        let cid = encode_contract_id(&[8u8; 32]);
        let tx = sample_tx(&cid);

        assert!(evaluate_rule(&cid, &AlertRule::AnyTransaction, &tx).unwrap());
        assert!(!evaluate_rule(&cid, &AlertRule::FailedTransaction, &tx).unwrap());
        assert!(evaluate_rule(
            &cid,
            &AlertRule::FunctionCall {
                function: "swap".to_string(),
                arg_contains: Some("USDC".to_string()),
                arg_regex: None,
            },
            &tx
        )
        .unwrap());
        assert!(!evaluate_rule(
            &cid,
            &AlertRule::FunctionCall {
                function: "mint".to_string(),
                arg_contains: None,
                arg_regex: None,
            },
            &tx
        )
        .unwrap());
    }

    #[test]
    fn evaluates_positional_topics_and_json_pointer_data_matchers() {
        let cid = encode_contract_id(&[9u8; 32]);
        let tx = sample_tx(&cid);

        let matching_rule = AlertRule::EventEmitted {
            topic_contains: None,
            topic_regex: None,
            topics: vec![Some("swap".to_string()), None],
            data_contains: None,
            data_match: vec![
                DataMatcher {
                    pointer: "/amount_in".to_string(),
                    op: MatchOperator::Gte,
                    value: Some("1000000".to_string()),
                },
                DataMatcher {
                    pointer: "/pool/pair".to_string(),
                    op: MatchOperator::Regex,
                    value: Some("^XLM/.*$".to_string()),
                },
                DataMatcher {
                    pointer: "/pool/fee_bps".to_string(),
                    op: MatchOperator::Eq,
                    value: Some("30".to_string()),
                },
            ],
        };
        assert!(evaluate_rule(&cid, &matching_rule, &tx).unwrap());

        let failing_rule = AlertRule::EventEmitted {
            topic_contains: None,
            topic_regex: None,
            topics: vec![Some("swap".to_string())],
            data_contains: None,
            data_match: vec![DataMatcher {
                pointer: "/amount_in".to_string(),
                op: MatchOperator::Gt,
                value: Some("99999999".to_string()),
            }],
        };
        assert!(!evaluate_rule(&cid, &failing_rule, &tx).unwrap());
    }

    #[test]
    fn evaluates_large_transfer_direction_and_asset() {
        let cid = encode_contract_id(&[10u8; 32]);
        let tx = sample_tx(&cid);

        let incoming_xlm = AlertRule::LargeTransfer {
            threshold_stroops: 0,
            threshold_xlm: Some(200),
            asset: Some("XLM".to_string()),
            direction: TransferDirection::In,
        };
        assert!(evaluate_rule(&cid, &incoming_xlm, &tx).unwrap());

        let outgoing_xlm = AlertRule::LargeTransfer {
            threshold_stroops: 0,
            threshold_xlm: Some(200),
            asset: Some("XLM".to_string()),
            direction: TransferDirection::Out,
        };
        assert!(!evaluate_rule(&cid, &outgoing_xlm, &tx).unwrap());
    }

    #[test]
    fn evaluates_composite_and_not_rules() {
        let cid = encode_contract_id(&[11u8; 32]);
        let tx = sample_tx(&cid);

        let rule = AlertRule::Composite {
            mode: RuleCombineMode::All,
            rules: vec![
                AlertRule::FunctionCall {
                    function: "swap".to_string(),
                    arg_contains: None,
                    arg_regex: None,
                },
                AlertRule::Not {
                    rule: Box::new(AlertRule::FailedTransaction),
                },
            ],
        };
        assert!(evaluate_rule(&cid, &rule, &tx).unwrap());
    }

    #[test]
    fn parses_stellar_amounts_without_float_drift() {
        assert_eq!(parse_stellar_amount_to_stroops("0.0000001"), Some(1));
        assert_eq!(parse_stellar_amount_to_stroops("1"), Some(10_000_000));
        assert_eq!(
            parse_stellar_amount_to_stroops("123.4567890"),
            Some(1_234_567_890)
        );
        assert_eq!(parse_stellar_amount_to_stroops("-5.0"), None);
    }

    #[test]
    fn rate_spike_fires_when_window_threshold_exceeded() {
        let cid = encode_contract_id(&[12u8; 32]);
        let contract = sample_contract(
            &cid,
            vec![RuleConfig::from(AlertRule::RateSpike {
                max_transactions: 2,
                window_seconds: 60,
            })],
        );
        let engine = RuleEngine::new();
        let base_time = Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap();

        for i in 0..3 {
            let mut tx = sample_tx(&cid);
            tx.hash = format!("hash_{i}");
            tx.created_at = base_time + chrono::Duration::seconds(i * 5);
            let alerts = engine
                .evaluate(&contract, &tx, "testnet", None)
                .expect("eval ok");
            if i < 2 {
                assert!(alerts.is_empty(), "should not fire on tx #{i}");
            } else {
                assert_eq!(alerts.len(), 1, "should fire on 3rd tx within 60s");
            }
        }
    }

    #[test]
    fn identical_rules_on_one_contract_do_not_collide() {
        let cid = encode_contract_id(&[13u8; 32]);
        let contract = sample_contract(
            &cid,
            vec![
                RuleConfig::from(AlertRule::AnyTransaction),
                RuleConfig::from(AlertRule::AnyTransaction),
            ],
        );
        let tx = sample_tx(&cid);
        let engine = RuleEngine::new();
        let alerts = engine.evaluate(&contract, &tx, "testnet", None).unwrap();
        assert_eq!(alerts.len(), 2);
        assert_ne!(alerts[0].alert_id, alerts[1].alert_id);
    }

    #[test]
    fn large_transfer_payload_amount_follows_direction() {
        let cid = encode_contract_id(&[14u8; 32]);
        let tx = sample_tx(&cid);
        let contract = sample_contract(
            &cid,
            vec![RuleConfig::from(AlertRule::LargeTransfer {
                threshold_stroops: 1_000_000,
                threshold_xlm: None,
                asset: None,
                direction: TransferDirection::In,
            })],
        );
        let engine = RuleEngine::new();
        let alerts = engine.evaluate(&contract, &tx, "testnet", None).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].amount_in_stroops, Some(2_500_000_000));
        assert_eq!(alerts[0].amount_out_stroops, None);
    }

    #[test]
    fn cooldown_suppresses_burst_and_emits_summary_count() {
        let cid = encode_contract_id(&[15u8; 32]);
        let mut rule_cfg = RuleConfig::from(AlertRule::AnyTransaction);
        rule_cfg.cooldown_seconds = 60;
        rule_cfg.cooldown_summary = true;

        let contract = sample_contract(&cid, vec![rule_cfg]);
        let engine = RuleEngine::new();
        let tx = sample_tx(&cid);

        let first = engine.evaluate(&contract, &tx, "testnet", None).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].suppressed_count, None);

        let second = engine.evaluate(&contract, &tx, "testnet", None).unwrap();
        assert!(second.is_empty());

        let third = engine.evaluate(&contract, &tx, "testnet", None).unwrap();
        assert!(third.is_empty());
    }

    #[test]
    fn source_account_muxed_entry_matches_muxed_source() {
        let cid = encode_contract_id(&[16u8; 32]);
        let muxed = "MAAAAAAAAAAAAAB7BQ2L7E5NBWMXDUCMZSIPOBKRDSBYVLMXGSSKF6YNPIB7Y77ITLVL6";
        let base_g = muxed_to_base_g_account(muxed).expect("valid muxed strkey");

        let mut tx = sample_tx(&cid);
        tx.source_account = muxed.to_string();

        // Exact M-address match works even with match_muxed_base = false.
        let exact_rule = AlertRule::SourceAccount {
            account: Some(muxed.to_string()),
            accounts: Vec::new(),
            match_muxed_base: false,
        };
        assert!(evaluate_rule(&cid, &exact_rule, &tx).unwrap());

        // Base G-account does not match when match_muxed_base = false.
        let base_strict = AlertRule::SourceAccount {
            account: Some(base_g.clone()),
            accounts: Vec::new(),
            match_muxed_base: false,
        };
        assert!(!evaluate_rule(&cid, &base_strict, &tx).unwrap());

        // Base G-account matches when match_muxed_base = true.
        let base_relaxed = AlertRule::SourceAccount {
            account: Some(base_g),
            accounts: Vec::new(),
            match_muxed_base: true,
        };
        assert!(evaluate_rule(&cid, &base_relaxed, &tx).unwrap());
    }

    #[test]
    fn high_fee_rule_honors_computed_threshold_from_xlm() {
        let cid = encode_contract_id(&[17u8; 32]);
        let mut tx = sample_tx(&cid);
        tx.fee_charged = 12_500_000;

        let rule_below = AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: Some(1.0),
            computed_threshold_stroops: 10_000_000,
        };
        assert!(evaluate_rule(&cid, &rule_below, &tx).unwrap());

        let rule_above = AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: Some(2.0),
            computed_threshold_stroops: 20_000_000,
        };
        assert!(!evaluate_rule(&cid, &rule_above, &tx).unwrap());
    }

    fn arb_tx(cid: String) -> impl Strategy<Value = EnrichedTransaction> {
        (any::<bool>(), 0u64..10_000_000u64, 1u64..1_000_000u64).prop_map(
            move |(successful, fee_charged, ledger)| EnrichedTransaction {
                hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ledger,
                created_at: Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap(),
                successful,
                source_account: encode_account_id(&[1u8; 32]),
                fee_account: None,
                fee_charged,
                max_fee: fee_charged.saturating_add(100),
                operation_count: 1,
                memo_type: "none".to_string(),
                memo: None,
                function: Some("ping".to_string()),
                arguments: Vec::new(),
                invocations: vec![SorobanInvocation {
                    contract_id: cid.clone(),
                    function: "ping".to_string(),
                    arguments: Vec::new(),
                }],
                events: Vec::new(),
                transfers: Vec::new(),
            },
        )
    }

    proptest! {
        #[test]
        fn double_negation_matches_original_rule(
            tx in arb_tx(encode_contract_id(&[31u8; 32])),
            threshold in 0u64..10_000_000u64,
        ) {
            let cid = encode_contract_id(&[31u8; 32]);
            let base = AlertRule::HighFee {
                threshold_stroops: threshold,
                threshold_xlm: None,
                computed_threshold_stroops: threshold,
            };
            let double_not = AlertRule::Not {
                rule: Box::new(AlertRule::Not {
                    rule: Box::new(base.clone()),
                }),
            };
            prop_assert_eq!(
                evaluate_rule(&cid, &base, &tx).unwrap(),
                evaluate_rule(&cid, &double_not, &tx).unwrap(),
            );
        }

        #[test]
        fn rate_tracker_count_is_monotone_within_fixed_instant(
            events in 1usize..50,
            window_secs in 1u64..300,
        ) {
            let tracker = RateTracker::new();
            let now = Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap();
            let window = Duration::from_secs(window_secs);
            for i in 1..=events {
                let count = tracker.evaluate("CA:0", now, window);
                prop_assert_eq!(count, i);
            }
        }
    }
}