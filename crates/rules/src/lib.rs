#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

//! txwatch-rules evaluates `AlertRule` conditions against enriched Stellar transactions
//! and constructs structured `AlertPayload` webhook bodies.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use txwatch_config::{AlertRule, FunctionMatchMode, RuleConfig, EVENT_TOPIC_WILDCARD};

// ── Constants ──────────────────────────────────────────────────────────────────

/// Maximum XLM supply in stroops: 50 billion XLM × 10^7 stroops/XLM
/// = 5 × 10^17 (500 quadrillion) stroops, well below u64::MAX (~1.8 × 10^19).
/// Parsed amounts and fees above this value cannot exist on the network, so
/// [`EnrichedTransaction::from_horizon`] discards them as malformed.
pub const MAX_XLM_SUPPLY_STROOPS: u64 = 500_000_000_000_000_000;

/// Returns `value` if it is a possible on-chain stroop amount, logging and
/// discarding anything above [`MAX_XLM_SUPPLY_STROOPS`].
fn sanitize_stroops(value: Option<u64>, field: &str, tx_hash: &str) -> Option<u64> {
    match value {
        Some(v) if v > MAX_XLM_SUPPLY_STROOPS => {
            tracing::warn!(
                tx = %tx_hash,
                field,
                value = v,
                max = MAX_XLM_SUPPLY_STROOPS,
                "parsed amount exceeds the total XLM supply — ignoring it"
            );
            None
        }
        other => other,
    }
}

// ── Horizon transaction shape ─────────────────────────────────────────────────

/// Raw Horizon transaction record as returned by the REST API.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HorizonTransaction {
    /// Transaction hash.
    pub hash: String,
    /// Ledger close time as an RFC 3339 string.
    pub created_at: String, // RFC 3339
    /// Whether the transaction succeeded.
    pub successful: bool,
    /// Horizon paging token for this record.
    pub paging_token: String,
    /// Fee charged in stroops (Horizon returns this as a string).
    pub fee_charged: Option<String>,
    /// The account that signed the inner transaction. For fee-bump
    /// transactions this is the inner source account; the account that
    /// paid the fee is `fee_account`.
    pub source_account: Option<String>,
    /// The account that paid the transaction's fee. Equals
    /// `source_account` for regular transactions; for fee-bump
    /// transactions it is the fee-bump (outer) source account.
    pub fee_account: Option<String>,
    /// Base64-encoded XDR transaction envelope.
    pub envelope_xdr: Option<String>,
    /// Base64-encoded XDR transaction result.
    pub result_xdr: Option<String>,
    // ── Issue #56: additional Horizon fields ──────────────────────────────────
    /// Ledger sequence number in which this transaction was included.
    pub ledger: Option<u32>,
    /// Memo content as a string (may be absent for `MemoNone`).
    pub memo: Option<String>,
    /// Memo type: `"none"`, `"text"`, `"id"`, `"hash"`, `"return"`.
    pub memo_type: Option<String>,
    /// Total number of operations in the transaction.
    pub operation_count: Option<u32>,
}

// ── Contract events ───────────────────────────────────────────────────────────

/// A Soroban contract event emitted by a transaction, as returned by Soroban
/// RPC `getEvents` with `xdrFormat: "json"`. Topics and data are `ScVal`s in
/// their JSON form, e.g. `{"symbol": "transfer"}` or `{"address": "G…"}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
pub struct ContractEvent {
    /// Contract that emitted the event.
    pub contract_id: String,
    /// Event topics as JSON-encoded `ScVal`s; topic 0 is conventionally the
    /// event name symbol.
    pub topics: Vec<Value>,
    /// Event body as a JSON-encoded `ScVal`.
    pub data: Value,
}

/// A single `data` matcher for an `EventEmitted` rule (issue #262).
///
/// `pointer` is an RFC 6901 JSON pointer into the event's decoded `data`
/// (e.g. `"/amount"` or `""` for the whole value). `op` selects the
/// comparison and `value` is the expected value as a string.
pub use txwatch_config::DataMatcher;

pub trait DataMatcherExt {
    fn matches(&self, data: &Value) -> bool;
}

impl DataMatcherExt for DataMatcher {
    /// Does `data` satisfy this matcher?
    fn matches(&self, data: &Value) -> bool {
        let Some(target) = resolve_pointer(data, &self.pointer) else {
            return false;
        };
        compare_scval(target, &self.op, &self.value)
    }
}

/// Resolve an RFC 6901 JSON pointer against `value`. An empty pointer returns
/// the whole value. Returns `None` when any segment is missing.
fn resolve_pointer<'v>(value: &'v Value, pointer: &str) -> Option<&'v Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    let mut current = value;
    for raw in pointer.trim_start_matches('/').split('/') {
        // Unescape RFC 6901: `~1` → `/`, `~0` → `~`.
        let segment = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(map) => map.get(&segment)?,
            Value::Array(arr) => arr.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Extract the inner scalar text of an `ScVal` JSON value, if it is one.
fn scval_inner_text(value: &Value) -> Option<String> {
    let scalar = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    };
    match value {
        Value::Object(map) if map.len() == 1 => map.values().next().and_then(scalar),
        other => scalar(other),
    }
}

/// Compare an `ScVal` JSON value against `expected` using `op`.
///
/// i128/u128 values (either bare numeric strings or `{"i128": "…"}` /
/// `{"u128": "…"}` wrappers) are compared as 128-bit integers; everything
/// else falls back to string comparison.
fn compare_scval(value: &Value, op: &str, expected: &str) -> bool {
    // Detect a 128-bit integer ScVal and compare numerically.
    let int_text = match value {
        Value::Object(map) if map.len() == 1 => {
            if let Some((k, v)) = map.iter().next() {
                if (k == "i128" || k == "u128") && v.is_string() {
                    v.as_str().map(str::to_owned)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    };
    if let Some(text) = int_text {
        if let (Ok(lhs), Ok(rhs)) = (text.parse::<i128>(), expected.parse::<i128>()) {
            return match op {
                "eq" => lhs == rhs,
                "gte" => lhs >= rhs,
                "lte" => lhs <= rhs,
                _ => false,
            };
        }
        // Fall through to string comparison if parsing fails.
    }

    let Some(actual) = scval_inner_text(value) else {
        // Non-scalar: compare compact JSON for `eq` only.
        return op == "eq" && value.to_string() == expected;
    };
    match op {
        "eq" => actual == expected,
        "gte" => compare_ordered(&actual, expected) != Ordering::Less,
        "lte" => compare_ordered(&actual, expected) != Ordering::Greater,
        _ => false,
    }
}

/// Order two strings numerically when both parse as integers, else lexically.
fn compare_ordered(a: &str, b: &str) -> Ordering {
    if let (Ok(x), Ok(y)) = (a.parse::<i128>(), b.parse::<i128>()) {
        x.cmp(&y)
    } else {
        a.cmp(b)
    }
}

impl ContractEvent {
    /// Does this event match an `EventEmitted { topic, topics, data }` rule?
    ///
    /// `topic` is compared against topic 0 (any scalar `ScVal`, optionally
    /// typed with a `type:` prefix such as `address:G…` or `u32:5`). Each
    /// entry of `topics` is compared positionally against topics 1..
    /// (`"*"` matches anything). Every `data` matcher must also match.
    pub fn matches(&self, topic: &str, topics: &[String], data: &[DataMatcher]) -> bool {
        let Some(first) = self.topics.first() else {
            return false;
        };
        if !topic_value_matches(first, topic) {
            return false;
        }
        let topics_ok = topics.iter().enumerate().all(|(i, pattern)| {
            pattern == EVENT_TOPIC_WILDCARD
                || self
                    .topics
                    .get(i + 1)
                    .is_some_and(|value| topic_value_matches(value, pattern))
        });
        topics_ok && data.iter().all(|m| m.matches(&self.data))
    }
}

/// Compare a topic's compact JSON rendering against `pattern`. A topic is
/// compared once per event, so the allocation is not worth avoiding.
#[allow(clippy::cmp_owned)]
fn cmp_rendered(value: &Value, pattern: &str) -> bool {
    value.to_string() == pattern
}

// Compare one `ScVal` topic against a config pattern (issue #263).
//
// A pattern may be typed with a `type:` prefix (`address:`, `u32:`, `i128:`,
// `symbol:`, `string:`, `bytes:`, `bool:`, …) to constrain the ScVal variant,
// or bare to match any scalar's inner text. Non-scalar topics match their
// compact JSON rendering.
fn topic_value_matches(value: &Value, pattern: &str) -> bool {
    // Typed pattern: `type:rest`.
    if let Some((ty, rest)) = pattern.split_once(':') {
        if let Value::Object(map) = value {
            if map.len() == 1 {
                if let Some((k, v)) = map.iter().next() {
                    if k == ty {
                        return scval_inner_text(v).is_some_and(|text| text == rest);
                    }
                }
                return false;
            }
        }
        // Typed pattern against a bare scalar: compare inner text.
        return scval_inner_text(value).is_some_and(|text| text == rest);
    }
    match scval_inner_text(value) {
        Some(text) => text == pattern,
        // A non-scalar topic matches its own compact JSON rendering.
        None => cmp_rendered(value, pattern),
    }
}

// ── ScVal decoding (issue #266) ───────────────────────────────────────────────

/// Decode a Soroban `ScVal` (in its JSON form) into a plain string for
/// argument matching. Handles the common scalar types: `address`, `symbol`,
/// `string`, `u32`, `i32`, `u64`, `i64`, `u128`, `i128`, `bool`. Anything else
/// falls back to its compact JSON rendering.
pub fn decode_scval(value: &Value) -> String {
    match value {
        Value::Object(map) if map.len() == 1 => {
            let (key, inner) = map.iter().next().expect("map has one entry");
            match (key.as_str(), inner) {
                ("address", Value::String(s))
                | ("symbol", Value::String(s))
                | ("string", Value::String(s)) => s.clone(),
                ("u32", _)
                | ("i32", _)
                | ("u64", _)
                | ("i64", _)
                | ("u128", _)
                | ("i128", _)
                | ("bool", _) => match inner {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    other => other.to_string(),
                },
                _ => value.to_string(),
            }
        }
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// A single decoded invocation argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedArg {
    /// Zero-based position in the invocation's argument list.
    pub index: usize,
    /// Decoded textual value.
    pub value: String,
}

/// A Soroban contract function invocation with its decoded arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionInvocation {
    pub function_name: String,
    /// Decoded arguments in order.
    pub args: Vec<DecodedArg>,
}

impl FunctionInvocation {
    /// Build from a function name and the raw `parameters` array (each element
    /// is an `ScVal` in JSON form).
    pub fn from_parameters(function_name: String, parameters: &[Value]) -> Self {
        let args = parameters
            .iter()
            .enumerate()
            .map(|(index, value)| DecodedArg {
                index,
                value: decode_scval(value),
            })
            .collect();
        Self {
            function_name,
            args,
        }
    }

    /// The decoded value at `index`, if present.
    pub fn arg(&self, index: usize) -> Option<&str> {
        self.args
            .iter()
            .find(|a| a.index == index)
            .map(|a| a.value.as_str())
    }
}

// ── Enriched transaction ──────────────────────────────────────────────────────

/// A transaction enriched with Soroban-specific fields extracted from the
/// Horizon `operations` sub-resource JSON (returned inline via `join=operations`
/// or fetched separately). We keep this as a plain struct so rule evaluation
/// stays pure and testable without network calls.
#[derive(Debug, Clone)]
pub struct EnrichedTransaction {
    /// Transaction hash.
    pub hash: String,
    /// Ledger close time of the transaction.
    pub timestamp: DateTime<Utc>,
    /// Whether the transaction succeeded.
    pub successful: bool,
    /// Horizon paging token for this record.
    pub paging_token: String,
    /// All Soroban contract functions invoked in this transaction (may be multiple).
    pub function_names: Vec<String>,
    /// Decoded invocations (function name + arguments) for this transaction.
    /// Populated from the operation `parameters` array (issue #266).
    pub invocations: Vec<FunctionInvocation>,
    /// Transfer amount in stroops (1 XLM = 10_000_000 stroops), if detected.
    /// Uses u64 because the total XLM supply is ~50 billion XLM = 5 × 10^17
    /// (500 quadrillion) stroops ([`MAX_XLM_SUPPLY_STROOPS`]), well within
    /// u64::MAX (~1.8 × 10^19).
    pub amount_stroops: Option<u64>,
    /// Fee charged for this transaction in stroops.
    pub fee_charged_stroops: Option<u64>,
    /// The Stellar account that submitted the transaction (G-address).
    pub source_account: Option<String>,
    /// For fee-bump transactions, the inner source account.
    pub fee_account: Option<String>,
    // ── Issue #56: additional metadata fields ─────────────────────────────────
    /// Ledger sequence number in which this transaction was included.
    pub ledger: Option<u32>,
    /// Memo content (absent for `MemoNone`).
    pub memo: Option<String>,
    /// Memo type: `"none"`, `"text"`, `"id"`, `"hash"`, `"return"`.
    pub memo_type: Option<String>,
    /// Total number of operations in the transaction.
    pub operation_count: Option<u32>,
    /// The contract this transaction is being evaluated for. Used by
    /// `LargeTransfer` (issue #264) and `ContractUpgraded` (issue #265).
    pub watched_contract_id: String,
    /// Contract events emitted by this transaction. Only populated when the
    /// contract has an `EventEmitted` rule (fetched from Soroban RPC).
    pub events: Vec<ContractEvent>,
    /// Per-contract native balance changes observed in this transaction
    /// (issue #264). Used by `LargeTransfer` so unrelated transfers in the
    /// same transaction do not count toward the watched contract.
    pub contract_transfers: Vec<ContractTransfer>,
    /// Executable (WASM) change for the watched contract, if any (issue #265).
    pub wasm_upgrade: Option<WasmUpgrade>,
    /// `true` when the operations fetch failed, so `function_names` and
    /// `amount_stroops` may be incomplete. Alerts that still fire carry this
    /// flag so receivers know the evaluation was degraded.
    pub enrichment_incomplete: bool,
}

/// A native (XLM) balance movement between two addresses in a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractTransfer {
    /// Address the funds moved from (may be empty for mints).
    pub from: String,
    /// Address the funds moved to (may be empty for burns).
    pub to: String,
    /// Amount moved, in stroops.
    pub amount_stroops: u64,
}

/// A change to a contract's executable (WASM) code (issue #265).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmUpgrade {
    /// Contract whose code changed.
    pub contract_id: String,
    /// Previous WASM hash (hex), if known.
    pub old_wasm_hash: Option<String>,
    /// New WASM hash (hex).
    pub new_wasm_hash: Option<String>,
}

impl EnrichedTransaction {
    /// Build from a raw Horizon record plus optional Soroban operation details.
    pub fn from_horizon(
        tx: HorizonTransaction,
        function_names: Vec<String>,
        amount_stroops: Option<u64>,
        fee_charged_stroops: Option<u64>,
    ) -> Result<Self> {
        let timestamp = tx.created_at.parse::<DateTime<Utc>>().with_context(|| {
            format!(
                "cannot parse timestamp '{}' for tx {}",
                tx.created_at, tx.hash
            )
        })?;

        let fee_charged_stroops = fee_charged_stroops.or_else(|| {
            tx.fee_charged
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
        });

        Ok(Self {
            amount_stroops: sanitize_stroops(amount_stroops, "amount_stroops", &tx.hash),
            fee_charged_stroops: sanitize_stroops(
                fee_charged_stroops,
                "fee_charged_stroops",
                &tx.hash,
            ),
            hash: tx.hash,
            timestamp,
            successful: tx.successful,
            paging_token: tx.paging_token,
            function_names,
            invocations: Vec::new(),
            // The sanitized values set above are authoritative; the raw ones
            // are deliberately not repeated here.
            source_account: tx.source_account,
            fee_account: tx.fee_account,
            ledger: tx.ledger,
            memo: tx.memo,
            memo_type: tx.memo_type,
            operation_count: tx.operation_count,
            watched_contract_id: String::new(),
            events: Vec::new(),
            contract_transfers: Vec::new(),
            wasm_upgrade: None,
            enrichment_incomplete: false,
        })
    }

    /// Set the contract this transaction is being evaluated for.
    pub fn with_watched_contract(mut self, contract_id: impl Into<String>) -> Self {
        self.watched_contract_id = contract_id.into();
        self
    }

    /// Attach per-contract balance changes observed in this transaction.
    pub fn with_contract_transfers(mut self, transfers: Vec<ContractTransfer>) -> Self {
        self.contract_transfers = transfers;
        self
    }

    /// Attach an executable (WASM) change for the watched contract.
    pub fn with_wasm_upgrade(mut self, upgrade: Option<WasmUpgrade>) -> Self {
        self.wasm_upgrade = upgrade;
        self
    }

    /// Sum the stroops moved into or out of `contract_id` in this transaction,
    /// filtered by `direction` (`"in"`, `"out"` or `"any"`). Returns `None`
    /// when no matching transfer exists (issue #264).
    pub fn contract_amount_stroops(&self, contract_id: &str, direction: &str) -> Option<u64> {
        let mut total: u64 = 0;
        let mut matched = false;
        for t in &self.contract_transfers {
            let counts = match direction {
                "in" => t.to == contract_id,
                "out" => t.from == contract_id,
                _ => t.from == contract_id || t.to == contract_id,
            };
            if counts {
                matched = true;
                total = total.saturating_add(t.amount_stroops);
            }
        }
        matched.then_some(total)
    }

    /// Mark this transaction as evaluated with incomplete enrichment (the
    /// operations fetch failed after retries).
    pub fn with_enrichment_incomplete(mut self, incomplete: bool) -> Self {
        self.enrichment_incomplete = incomplete;
        self
    }

    /// Attach the contract events emitted by this transaction.
    pub fn with_events(mut self, events: Vec<ContractEvent>) -> Self {
        self.events = events;
        self
    }

    /// Attach decoded function invocations (with arguments).
    pub fn with_invocations(mut self, invocations: Vec<FunctionInvocation>) -> Self {
        self.invocations = invocations;
        self
    }
}

// ── AlertPayload ──────────────────────────────────────────────────────────────

/// The JSON body POSTed to the webhook URL when a rule fires.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
pub struct AlertPayload {
    /// Schema version for this payload shape (issue #58).
    /// Receivers should use this to detect breaking changes.
    /// Additive changes (new optional fields) keep the same version;
    /// breaking changes (field removals or renames) bump it.
    pub schema_version: u32,
    /// Stable, deterministic alert identifier derived from
    /// (network cursor ID, contract_id, tx hash, rule_type, rule_triggered,
    /// rule index) via SHA-256 (issues #57, #252). Receivers should
    /// deduplicate on this value.
    /// Used as the PagerDuty `dedup_key`.
    #[serde(default)]
    pub alert_id: String,
    /// Human-readable label of the watched contract.
    pub label: String,
    /// Contract ID the alert is about.
    pub contract_id: String,
    /// Network the contract lives on (`"mainnet"`, `"testnet"`, …).
    pub network: String,
    /// Stable machine-readable rule variant (e.g. `"LargeTransfer"`).
    pub rule_type: String,
    /// Human-readable description of the rule that fired.
    pub rule_triggered: String,
    /// Transaction hash (empty string `""` for synthetic alerts such as `NoActivity`).
    pub transaction_hash: String,
    /// First invoked function name (backward-compat singular field).
    pub function_name: Option<String>,
    /// All invoked function names in this transaction.
    pub function_names: Vec<String>,
    /// Decoded function invocations (name + arguments) for this transaction.
    /// Empty when the operation parameters were not available (issue #266).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub function_args: Vec<FunctionInvocation>,
    /// Amount in whole XLM (truncated, stroops / 10_000_000), present for
    /// LargeTransfer. Kept for backward compatibility — use `amount_xlm_decimal`
    /// for precise accounting (e.g. 9,999.99 XLM appears here as `9999`).
    #[serde(rename = "amount_xlm")]
    pub amount_xlm: Option<u64>,
    /// Transfer amount in stroops (1 XLM = 10_000_000 stroops).
    pub amount_stroops: Option<u64>,
    /// Transfer amount as a decimal string with 7 fractional digits
    /// (e.g. `"9999.9900000"`), or `null` when no amount is present.
    pub amount_xlm_decimal: Option<String>,
    /// Fee charged in stroops.
    pub fee_charged_stroops: Option<u64>,
    /// The account that signed the inner transaction (G-address).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_account: Option<String>,
    /// The account that paid the transaction's fee (G-address). Only
    /// included when it differs from `source_account` — i.e. for
    /// fee-bump transactions, where this is the fee-bump source account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_account: Option<String>,
    /// Optional severity level from the rule definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// ISO 8601 timestamp string.
    pub timestamp_iso: String,
    /// Horizon link to the transaction (or account for synthetic alerts).
    pub horizon_link: String,
    /// Stellar Expert explorer link for the transaction.
    pub explorer_link: String,
    /// Effective webhook URL for this alert (may be rule-level override).
    #[serde(skip)]
    pub effective_webhook_url: Option<String>,
    /// Effective webhook secret for this alert (may be rule-level override).
    #[serde(skip)]
    pub effective_webhook_secret: Option<String>,
    // ── Issue #56: additional metadata fields ─────────────────────────────────
    /// Ledger sequence number in which this transaction was included.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,
    /// Memo content (absent for `MemoNone`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// Memo type: `"none"`, `"text"`, `"id"`, `"hash"`, `"return"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo_type: Option<String>,
    /// Total number of operations in the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_count: Option<u32>,
    /// `true` for a recovery alert (e.g. activity resumed after `NoActivity`).
    /// `false` (the default) for an incident alert.
    #[serde(default)]
    pub resolved: bool,
    /// Contract events that matched an `EventEmitted` rule (topics and data);
    /// empty for every other rule type.
    #[serde(default)]
    pub matched_events: Vec<ContractEvent>,
    /// Number of matches of this rule that were suppressed by its
    /// `cooldown_seconds` since the previous alert was sent. 0 when the rule
    /// has no cooldown or nothing was suppressed.
    #[serde(default)]
    pub suppressed_count: u64,
    /// Observed match count for a `Rate` rule breach (issue #267). `None` for
    /// every other rule type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_count: Option<u64>,
    /// `true` only for synthetic payloads sent by `txwatch test-webhook`;
    /// omitted from the JSON otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub test: bool,
    /// Previous WASM hash for a `ContractUpgraded` alert (issue #265).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_wasm_hash: Option<String>,
    /// New WASM hash for a `ContractUpgraded` alert (issue #265).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_wasm_hash: Option<String>,
    /// `true` when the transaction's operations could not be fetched, so
    /// `function_names` / `amount_stroops` may be incomplete and rules such as
    /// `FunctionCalled`, `AdminFunctionCalled` and `LargeTransfer` may have
    /// missed this transaction. Omitted from the JSON when `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enrichment_incomplete: bool,
}

/// Deterministic alert ID: the first 32 hex characters (128 bits) of
/// SHA-256 over the network cursor ID, `contract_id`, `transaction_hash`,
/// `rule_type`, `rule_triggered` and the rule's index within its contract's
/// rule list.
///
/// Both the network and the rule identity are hashed (#252): two rules with
/// identical labels on one contract (e.g. two `LargeTransfer(>=100XLM)` rules
/// routed to different webhooks) must produce different IDs, otherwise
/// receivers deduplicate one of them away. `rule_index` is the position of the
/// rule in its contract's `rules` list, so it stays stable for a given config.
pub fn alert_id(
    network: &str,
    contract_id: &str,
    transaction_hash: &str,
    rule_type: &str,
    rule_triggered: &str,
    rule_index: usize,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in [
        network,
        contract_id,
        transaction_hash,
        rule_type,
        rule_triggered,
    ] {
        hasher.update(part.as_bytes());
        // Separator so ("ab", "c") and ("a", "bc") differ.
        hasher.update([0u8]);
    }
    hasher.update(rule_index.to_le_bytes());
    let mut id = hex::encode(hasher.finalize());
    id.truncate(32);
    id
}

// ── Rule evaluation ───────────────────────────────────────────────────────────

/// Context passed to [`evaluate`] to identify the contract being evaluated
/// and provide the link base URLs needed to build webhook payloads.
///
/// Using a struct instead of five positional `&str` parameters prevents
/// argument-order bugs (e.g. swapping `horizon_base` and `explorer_base`).
///
/// # Example
/// ```
/// use txwatch_rules::EvalContext;
/// use txwatch_config::{AlertRule, Network, RuleConfig, WatchedContract};
///
/// let contract = WatchedContract {
///     label: "My Oracle".into(),
///     contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
///     network: Network::Testnet,
///     rules: vec![RuleConfig {
///         rule: AlertRule::AnyTransaction,
///         cooldown_seconds: None,
///     }],
///     webhook_url: Some("https://hooks.example.com/hook".into()),
///     webhook_secret: None,
///     webhook_format: Default::default(),
///     webhook_headers: Default::default(),
///     webhook_routing_key: None,
///     webhooks: Vec::new(),
///     poll_interval_seconds: None,
///     enabled: true,
///     soroban_rpc_url: None,
///     batch_alerts: false,
///     horizon_base_url_override: None,
/// };
/// let ctx = EvalContext::from_contract(&contract);
/// assert_eq!(ctx.network, "testnet");
/// ```
#[derive(Debug, Clone)]
pub struct EvalContext<'a> {
    /// Human-readable label of the watched contract.
    pub label: &'a str,
    /// Contract ID being evaluated.
    pub contract_id: &'a str,
    /// Network the contract lives on (`"mainnet"`, `"testnet"`, …).
    pub network: &'a str,
    /// Network cursor ID ([`txwatch_config::Network::cursor_id`]): the stable
    /// per-network identity used in `alert_id` (#252). Unlike `network`, this
    /// tells two custom networks apart (`"custom@https://…"`, see issue #252).
    pub network_id: String,
    /// Horizon base URL used to build transaction links.
    pub horizon_base: &'a str,
    /// Explorer base URL for the network; `None` for custom networks that
    /// have no configured explorer (links will fall back to `horizon_link`).
    pub explorer_base: Option<&'a str>,
}

impl<'a> EvalContext<'a> {
    /// Convenience constructor: derive all fields from a [`WatchedContract`].
    /// Callers that need to override the Horizon base URL (e.g. tests using a
    /// mock server) should fill in the fields manually instead.
    pub fn from_contract(contract: &'a txwatch_config::WatchedContract) -> Self {
        let horizon_base = contract
            .horizon_base_url_override
            .as_deref()
            .unwrap_or_else(|| contract.network.horizon_base_url());
        Self {
            label: &contract.label,
            contract_id: &contract.contract_id,
            network: contract.network.as_str(),
            network_id: contract.network.cursor_id(),
            horizon_base,
            explorer_base: contract.network.explorer_base_url(),
        }
    }
}

/// Shared, thread-safe counter map used to rate-limit repeated evaluation
/// warnings. Keyed by `"<contract_id>:<rule_label>"`.
#[derive(Debug, Default, Clone)]
pub struct WarningSuppressor(Arc<Mutex<HashMap<String, u64>>>);

impl WarningSuppressor {
    /// Returns `true` if the warning for this key should be emitted (i.e. the
    /// first occurrence or every 100th recurrence).
    pub fn should_warn(&self, key: &str) -> bool {
        if let Ok(mut map) = self.0.lock() {
            let count = map.entry(key.to_owned()).or_insert(0);
            *count += 1;
            *count == 1 || *count % 100 == 0
        } else {
            true // lock poisoned — always warn rather than silently drop
        }
    }

    /// Returns how many times a warning has been suppressed for the given key.
    #[cfg(test)]
    pub fn suppressed_count(&self, key: &str) -> u64 {
        self.0
            .lock()
            .ok()
            .and_then(|m| m.get(key).copied())
            .unwrap_or(0)
    }
}

/// Evaluate all per-transaction rules for one contract against one transaction.
/// Returns one `AlertPayload` per matching rule.
/// Never panics — errors in individual rule evaluation are logged and skipped.
/// Repeated errors for the same rule are suppressed after the first occurrence
/// (see [`WarningSuppressor`]).
///
/// Pass `suppressor` as `None` to use a one-shot suppressor (appropriate for
/// replay and tests). The poller keeps a per-contract suppressor to
/// deduplicate repeated warnings across poll cycles.
pub fn evaluate<R: AsRef<AlertRule> + RuleOverrides>(
    ctx: &EvalContext<'_>,
    rules: &[R],
    tx: &EnrichedTransaction,
    suppressor: Option<&WarningSuppressor>,
) -> Vec<AlertPayload> {
    let label = ctx.label;
    let contract_id = ctx.contract_id;
    let network = ctx.network;
    // #45: Trim trailing slashes so callers that pass "https://host/" do not
    // produce double slashes in the generated links.
    let horizon_base = ctx.horizon_base.trim_end_matches('/');
    let horizon_link = format!("{}/transactions/{}", horizon_base, tx.hash);
    let explorer_link = match ctx.explorer_base {
        Some(base) => format!("{}/tx/{}", base.trim_end_matches('/'), tx.hash),
        None => horizon_link.clone(),
    };
    let timestamp = tx.timestamp.timestamp();
    let timestamp_iso = tx.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let _local_suppressor;
    let suppressor = match suppressor {
        Some(s) => s,
        None => {
            _local_suppressor = WarningSuppressor::default();
            &_local_suppressor
        }
    };

    // #46: Compute both forms of the amount once per transaction.
    let amount_xlm = tx.amount_stroops.map(|s| s / 10_000_000);
    let amount_xlm_decimal = tx.amount_stroops.map(|s| {
        let whole = s / 10_000_000;
        let frac = s % 10_000_000;
        format!("{}.{:07}", whole, frac)
    });

    rules
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.enabled())
        .filter_map(|(rule_index, entry)| {
            let rule: &AlertRule = entry.as_ref();
            match eval_rule(rule, tx) {
                Ok(true) => Some(AlertPayload {
                    schema_version: 1,
                    alert_id: alert_id(contract_id, &tx.hash, &rule.label()),
                    label: label.to_string(),
                    contract_id: contract_id.to_string(),
                    network: network.to_string(),
                    // #44: Use the single canonical implementations from txwatch-config.
                    rule_type: rule.rule_type().to_string(),
                    rule_triggered: rule.label(),
                    transaction_hash: tx.hash.clone(),
                    function_name: tx.function_names.first().cloned(),
                    function_names: tx.function_names.clone(),
                    function_args: tx.invocations.clone(),
                    amount_xlm,
                    amount_stroops: tx.amount_stroops,
                    amount_xlm_decimal: amount_xlm_decimal.clone(),
                    fee_charged_stroops: tx.fee_charged_stroops,
                    source_account: tx.source_account.clone(),
                    // Only surface the fee payer when it differs from the
                    // source account (fee-bump transactions, issue #251).
                    fee_account: tx
                        .fee_account
                        .clone()
                        .filter(|f| tx.source_account.as_deref() != Some(f.as_str())),
                    // Per-rule delivery overrides, absent unless the rule sets them.
                    severity: entry.severity().map(|s| s.to_string()),
                    effective_webhook_url: entry.webhook_url().map(str::to_owned),
                    effective_webhook_secret: entry.webhook_secret().map(str::to_owned),
                    timestamp,
                    timestamp_iso: timestamp_iso.clone(),
                    horizon_link: horizon_link.clone(),
                    explorer_link: explorer_link.clone(),
                    ledger: tx.ledger,
                    memo: tx.memo.clone(),
                    memo_type: tx.memo_type.clone(),
                    operation_count: tx.operation_count,
                    resolved: false,
                    matched_events: matched_events(rule, tx),
                    suppressed_count: 0,
                    observed_count: None,
                    test: false,
                    old_wasm_hash: upgrade_hashes(rule, tx).and_then(|(o, _)| o),
                    new_wasm_hash: upgrade_hashes(rule, tx).and_then(|(_, n)| n),
                    enrichment_incomplete: tx.enrichment_incomplete,
                }),
                Ok(true) => {
                    let rule_type = rule.rule_type().to_string();
                    let rule_triggered = rule.label();
                    Some(AlertPayload {
                        schema_version: 1,
                        alert_id: alert_id(
                            &ctx.network_id,
                            contract_id,
                            &tx.hash,
                            &rule_type,
                            &rule_triggered,
                            rule_index,
                        ),
                        label: label.to_string(),
                        contract_id: contract_id.to_string(),
                        network: network.to_string(),
                        // #44: Use the single canonical implementations from txwatch-config.
                        rule_type,
                        rule_triggered,
                        transaction_hash: tx.hash.clone(),
                        function_name: tx.function_names.first().cloned(),
                        function_names: tx.function_names.clone(),
                        function_args: tx.invocations.clone(),
                        amount_xlm,
                        amount_stroops: tx.amount_stroops,
                        amount_xlm_decimal: amount_xlm_decimal.clone(),
                        fee_charged_stroops: tx.fee_charged_stroops,
                        source_account: tx.source_account.clone(),
                        // Per-rule delivery overrides, absent unless the rule sets them.
                        severity: entry.severity().map(|s| s.to_string()),
                        effective_webhook_url: entry.webhook_url().map(str::to_owned),
                        effective_webhook_secret: entry.webhook_secret().map(str::to_owned),
                        timestamp,
                        timestamp_iso: timestamp_iso.clone(),
                        horizon_link: horizon_link.clone(),
                        explorer_link: explorer_link.clone(),
                        ledger: tx.ledger,
                        memo: tx.memo.clone(),
                        memo_type: tx.memo_type.clone(),
                        operation_count: tx.operation_count,
                        resolved: false,
                        matched_events: matched_events(rule, tx),
                        suppressed_count: 0,
                        observed_count: None,
                        test: false,
                        old_wasm_hash: upgrade_hashes(rule, tx).and_then(|(o, _)| o),
                        new_wasm_hash: upgrade_hashes(rule, tx).and_then(|(_, n)| n),
                        enrichment_incomplete: tx.enrichment_incomplete,
                    })
                }
                Ok(false) => None,
                Err(e) => {
                    // A broken rule would otherwise warn on every poll cycle.
                    let key = format!("{}:{}", ctx.contract_id, rule.label());
                    if suppressor.should_warn(&key) {
                        tracing::warn!(
                            tx = %tx.hash,
                            rule = %rule.label(),
                            error = %e,
                            "rule evaluation error — skipping"
                        );
                    }
                    None
                }
            }
        })
        .collect()
}

/// Per-rule delivery settings that ride alongside the rule itself. A bare
/// [`AlertRule`] and a `RuleConfig` have none; a `RuleEntry` (used for the
/// nested rules of a composite) carries the enable flag, the webhook overrides
/// and the severity.
pub trait RuleOverrides {
    /// `false` skips the rule entirely.
    fn enabled(&self) -> bool {
        true
    }
    /// Webhook URL this rule overrides the contract's with.
    fn webhook_url(&self) -> Option<&str> {
        None
    }
    /// Webhook secret this rule overrides the contract's with.
    fn webhook_secret(&self) -> Option<&str> {
        None
    }
    /// Severity carried on the alert payload.
    fn severity(&self) -> Option<&txwatch_config::Severity> {
        None
    }
}

impl<T: RuleOverrides + ?Sized> RuleOverrides for &T {
    fn enabled(&self) -> bool {
        (**self).enabled()
    }
    fn webhook_url(&self) -> Option<&str> {
        (**self).webhook_url()
    }
    fn webhook_secret(&self) -> Option<&str> {
        (**self).webhook_secret()
    }
    fn severity(&self) -> Option<&txwatch_config::Severity> {
        (**self).severity()
    }
}

impl RuleOverrides for AlertRule {}
impl RuleOverrides for txwatch_config::RuleConfig {
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn webhook_url(&self) -> Option<&str> {
        self.webhook_url.as_deref()
    }
    fn webhook_secret(&self) -> Option<&str> {
        self.webhook_secret.as_deref()
    }
    fn severity(&self) -> Option<&txwatch_config::Severity> {
        self.severity.as_ref()
    }
}

impl RuleOverrides for txwatch_config::RuleEntry {
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn webhook_url(&self) -> Option<&str> {
        self.webhook_url.as_deref()
    }
    fn webhook_secret(&self) -> Option<&str> {
        self.webhook_secret.as_deref()
    }
    fn severity(&self) -> Option<&txwatch_config::Severity> {
        self.severity.as_ref()
    }
}

// NOTE: When adding a new AlertRule variant, update both `eval_rule()` in this
// file and `AlertRule::label()` / `AlertRule::rule_type()` in txwatch-config together.
// Rust's exhaustive matching catches missing arms in eval_rule automatically.
fn eval_rule(rule: &AlertRule, tx: &EnrichedTransaction) -> Result<bool> {
    Ok(match rule {
        AlertRule::AnyTransaction => true,

        AlertRule::TransactionFailed => !tx.successful,

        // #43: threshold_stroops is pre-computed once during validation; no
        // per-evaluation multiplication or overflow path needed.
        // #264: only count balance changes involving the watched contract,
        // filtered by direction, rather than every transfer in the transaction.
        AlertRule::LargeTransfer {
            threshold_stroops,
            direction,
            ..
        } => tx
            .contract_amount_stroops(&tx.watched_contract_id, direction)
            .map(|s| s >= *threshold_stroops)
            .unwrap_or(false),

        AlertRule::FunctionCalled {
            function_name,
            match_mode,
            args,
        } => {
            // #266: A function matches when its name matches the mode AND every
            // configured argument constraint holds. When `args` is empty this
            // reduces to the original name-only behaviour.
            let name_matches = |f: &str| match match_mode {
                FunctionMatchMode::Exact => f == function_name.as_str(),
                FunctionMatchMode::Prefix => f.starts_with(function_name.as_str()),
                FunctionMatchMode::Glob => glob_match(function_name, f),
            };
            if args.is_empty() {
                tx.function_names.iter().any(|f| name_matches(f))
            } else {
                // Argument constraints require decoded invocations.
                tx.invocations.iter().any(|inv| {
                    name_matches(&inv.function_name)
                        && args.iter().all(|constraint| {
                            inv.arg(constraint.index as usize)
                                .is_some_and(|v| v == constraint.eq.as_str())
                        })
                })
            }
        }

        AlertRule::AdminFunctionCalled { function_names } => tx.function_names.iter().any(|f| {
            let f_lower = f.to_lowercase();
            function_names.iter().any(|n| n.to_lowercase() == f_lower)
        }),

        AlertRule::HighFee {
            threshold_stroops, ..
        } => tx
            .fee_charged_stroops
            .map(|f| f >= *threshold_stroops)
            .unwrap_or(false),

        AlertRule::SourceAccount {
            mode,
            accounts,
            alert_unless,
            allow,
            deny,
        } => {
            // `source_account` holds the inner source; `fee_account` holds the
            // fee payer (the fee-bump source for fee-bump transactions).
            let matched_account = match field {
                txwatch_config::SourceAccountField::Source => tx.source_account.as_deref(),
                txwatch_config::SourceAccountField::FeeAccount => {
                    tx.fee_account.as_deref().or(tx.source_account.as_deref())
                }
            };
            match matched_account {
                None => false,
                Some(src) => {
                    let list = if !accounts.is_empty() {
                        accounts
                    } else if !alert_unless.is_empty() {
                        alert_unless
                    } else {
                        &Vec::new()
                    };
                    if !list.is_empty() {
                        let is_member = list.iter().any(|a| a == src);
                        match mode {
                            txwatch_config::SourceAccountMode::In => is_member,
                            txwatch_config::SourceAccountMode::NotIn => !is_member,
                        }
                    } else {
                        let in_allow = allow.iter().any(|a| a == src);
                        let in_deny = deny.iter().any(|d| d == src);
                        if !allow.is_empty() {
                            // `allow` gates the rule; an address on the `deny`
                            // fire-list still fires, so it can carve out exceptions.
                            in_allow || in_deny
                        } else if !deny.is_empty() {
                            // With no gate, `deny` alone decides.
                            in_deny
                        } else {
                            true
                        }
                    }
                }
            }
        }

        // #268: Memo rule. `memo_type` (when set) must match the transaction's
        // memo type; `equals` / `prefix` constrain the memo text.
        AlertRule::Memo {
            memo_type,
            equals,
            prefix,
        } => {
            if let Some(required_type) = memo_type {
                if tx.memo_type.as_deref() != Some(required_type.as_str()) {
                    return Ok(false);
                }
            }
            let Some(memo) = tx.memo.as_deref() else {
                return Ok(false);
            };
            equals.as_deref().is_none_or(|eq| memo == eq)
                && prefix.as_deref().is_none_or(|p| memo.starts_with(p))
        }

        AlertRule::All { rules } => {
            let mut has_enabled_rule = false;
            for entry in rules {
                if !entry.enabled {
                    continue;
                }
                has_enabled_rule = true;
                if !eval_rule(&entry.rule, tx)? {
                    return Ok(false);
                }
            }
            has_enabled_rule
        }

        AlertRule::Any { rules } => {
            for entry in rules {
                if !entry.enabled {
                    continue;
                }
                if eval_rule(&entry.rule, tx)? {
                    return Ok(true);
                }
            }
            false
        }

        AlertRule::Not { rule: inner } => !eval_rule(&inner.rule, tx)?,
        // NoActivity is a poll-cycle-level rule evaluated by `check_no_activity`,
        // not a per-transaction rule.  It never fires here.
        AlertRule::NoActivity { .. } => false,
        AlertRule::EventEmitted {
            topic,
            topics,
            data,
        } => tx
            .events
            .iter()
            .any(|e| e.matches(topic, topics, data.as_slice())),

        // #265: fire when the watched contract's executable changed.
        AlertRule::ContractUpgraded => tx
            .wasm_upgrade
            .as_ref()
            .is_some_and(|u| u.contract_id == tx.watched_contract_id),

        // #267: Rate is a stateful, windowed rule evaluated by `RateTracker`,
        // not a per-transaction rule. It never fires here.
        AlertRule::Rate { .. } => false,
    })
}

/// The (old, new) WASM hashes for a `ContractUpgraded` rule that fired.
fn upgrade_hashes(
    rule: &AlertRule,
    tx: &EnrichedTransaction,
) -> Option<(Option<String>, Option<String>)> {
    match rule {
        AlertRule::ContractUpgraded => tx
            .wasm_upgrade
            .as_ref()
            .filter(|u| u.contract_id == tx.watched_contract_id)
            .map(|u| (u.old_wasm_hash.clone(), u.new_wasm_hash.clone())),
        _ => None,
    }
}

/// The events an `EventEmitted` rule matched; empty for other rules.
fn matched_events(rule: &AlertRule, tx: &EnrichedTransaction) -> Vec<ContractEvent> {
    match rule {
        AlertRule::EventEmitted {
            topic,
            topics,
            data,
        } => tx
            .events
            .iter()
            .filter(|e| e.matches(topic, topics, data.as_slice()))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

// NOTE: When adding a new AlertRule variant, update both `eval_rule()` and
// `rule_label()` together. Rust's exhaustive matching catches missing arms,
// but this convention should be preserved for new rule variants.
fn rule_label(rule: &AlertRule) -> String {
    match rule {
        AlertRule::AnyTransaction => "AnyTransaction".into(),
        AlertRule::TransactionFailed => "TransactionFailed".into(),
        AlertRule::LargeTransfer { threshold_xlm, .. } => {
            format!("LargeTransfer(>={}XLM)", threshold_xlm)
        }
        // #266: argument matchers are part of the label (see AlertRule::label).
        AlertRule::FunctionCalled { args, .. } if !args.is_empty() => rule.label(),
        AlertRule::FunctionCalled {
            function_name,
            match_mode,
            ..
        } => match match_mode {
            FunctionMatchMode::Exact => format!("FunctionCalled({})", function_name),
            FunctionMatchMode::Prefix => format!("FunctionCalled(prefix:{})", function_name),
            FunctionMatchMode::Glob => format!("FunctionCalled(glob:{})", function_name),
        },
        AlertRule::AdminFunctionCalled { function_names } => {
            format!("AdminFunctionCalled([{}])", function_names.join(", "))
        }
        AlertRule::HighFee {
            threshold_stroops,
            threshold_xlm,
        } => {
            if let Some(xlm) = threshold_xlm {
                format!("HighFee(>={} XLM)", xlm)
            } else {
                format!("HighFee(>={} stroops)", threshold_stroops)
            }
        }
        AlertRule::SourceAccount {
            mode,
            accounts,
            alert_unless,
            allow,
            deny,
        } => {
            // Only mention `field` when it is non-default so existing alert
            // IDs (derived from the label) stay stable.
            let field_str = match field {
                txwatch_config::SourceAccountField::Source => "",
                txwatch_config::SourceAccountField::FeeAccount => "field=fee_account, ",
            };
            let list = if !accounts.is_empty() {
                accounts
            } else if !alert_unless.is_empty() {
                alert_unless
            } else {
                &Vec::new()
            };
            if !list.is_empty() {
                let mode_str = match mode {
                    txwatch_config::SourceAccountMode::In => "in",
                    txwatch_config::SourceAccountMode::NotIn => "not_in",
                };
                format!("SourceAccount({}: [{}])", mode_str, list.join(", "))
            } else {
                let mut parts = Vec::new();
                if !allow.is_empty() {
                    parts.push(format!("allow=[{}]", allow.join(", ")));
                }
                if !deny.is_empty() {
                    parts.push(format!("deny=[{}]", deny.join(", ")));
                }
                format!("SourceAccount({})", parts.join(", "))
            }
        }
        AlertRule::All { rules } => {
            let inner: Vec<String> = rules.iter().map(|e| rule_label(&e.rule)).collect();
            format!("All({})", inner.join(", "))
        }
        AlertRule::Any { rules } => {
            let inner: Vec<String> = rules.iter().map(|e| rule_label(&e.rule)).collect();
            format!("Any({})", inner.join(", "))
        }
        AlertRule::Not { rule: inner } => format!("Not({})", rule_label(&inner.rule)),
        AlertRule::NoActivity { minutes } => format!("NoActivity({}min)", minutes),
        AlertRule::EventEmitted { topic, topics, .. } => {
            txwatch_config::event_emitted_label(topic, topics)
        }
        AlertRule::ContractUpgraded => "ContractUpgraded".into(),
        AlertRule::Rate { .. } | AlertRule::Memo { .. } => rule.label(),
    }
}

// ── NoActivity poll-cycle evaluation ─────────────────────────────────────────

/// State machine for a single `NoActivity` rule instance on one contract.
///
/// The poller keeps one `NoActivityState` per `(contract_id, rule_index)` pair
/// and calls [`check_no_activity`] once per poll cycle — even when there are no
/// new transactions.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NoActivityState {
    /// The contract is active (or we haven't yet exceeded the threshold).
    #[default]
    Active,
    /// The threshold was exceeded and an alert was fired.  We're in the quiet
    /// window; we will fire a recovery alert the next time a transaction arrives.
    Alerting {
        #[serde(default)]
        incident_alert_id: String,
    },
}

/// Check the `NoActivity` rule for a single contract after one poll cycle.
///
/// * `rule`              — must be `AlertRule::NoActivity { minutes }`.
/// * `rule_index`        — position of this rule in the contract's `rules`
///   list, hashed into `alert_id` so two identical `NoActivity` rules on one
///   contract get distinct IDs (#252).
/// * `last_seen`         — the timestamp of the most recent transaction seen,
///   or `None` if we have never seen any transaction.
/// * `now`               — current time (injectable for testing).
/// * `state`             — mutable state carried across poll cycles.
/// * `ctx`               — context used to build the `AlertPayload`.
///
/// Returns `Some(payload)` when the rule fires (either an incident or a
/// recovery); returns `None` when nothing changed.
///
/// Behaviour:
/// - First breach → returns an incident payload and transitions to `Alerting`.
/// - Still quiet (consecutive breaches) → returns `None` (already alerting).
/// - Activity resumes after breach → returns a recovery payload
///   (`resolved = true`) and transitions back to `Active`.
/// - Activity present and never breached → returns `None`.
pub fn check_no_activity(
    rule: &AlertRule,
    rule_index: usize,
    last_seen: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    state: &mut NoActivityState,
    ctx: &EvalContext<'_>,
) -> Option<AlertPayload> {
    let AlertRule::NoActivity { minutes } = rule else {
        return None;
    };

    let horizon_base = ctx.horizon_base.trim_end_matches('/');
    let explorer_base = ctx.explorer_base.map(|b| b.trim_end_matches('/'));

    let threshold = chrono::Duration::minutes(*minutes as i64);
    let quiet_since = last_seen
        .map(|t| now - t)
        .unwrap_or_else(|| chrono::Duration::MAX);
    let is_quiet = quiet_since >= threshold;

    let ts = now.timestamp();
    let ts_iso = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Synthetic payloads have no transaction — use empty hash and link to Horizon
    // account page rather than a specific transaction.
    let synthetic_hash = String::new();
    let synthetic_horizon_link = format!("{}/accounts/{}", horizon_base, ctx.contract_id);
    let synthetic_explorer_link = match explorer_base {
        Some(base) => format!("{}/contract/{}", base, ctx.contract_id),
        None => synthetic_horizon_link.clone(),
    };

    match (&*state, is_quiet) {
        // Threshold just exceeded for the first time → fire incident.
        (NoActivityState::Active, true) => {
            let rule_triggered = format!("NoActivity({}min)", minutes);
            let incident_id = alert_id(
                &ctx.network_id,
                ctx.contract_id,
                &ts.to_string(),
                "NoActivity",
                &rule_triggered,
                rule_index,
            );
            *state = NoActivityState::Alerting {
                incident_alert_id: incident_id.clone(),
            };
            Some(AlertPayload {
                label: ctx.label.to_string(),
                contract_id: ctx.contract_id.to_string(),
                network: ctx.network.to_string(),
                rule_type: "NoActivity".into(),
                rule_triggered,
                alert_id: incident_id,
                schema_version: 1,
                amount_stroops: None,
                amount_xlm_decimal: None,
                source_account: None,
                fee_account: None,
                severity: None,
                effective_webhook_url: None,
                effective_webhook_secret: None,
                ledger: None,
                memo: None,
                memo_type: None,
                operation_count: None,
                matched_events: vec![],
                suppressed_count: 0,
                observed_count: None,
                test: false,
                old_wasm_hash: None,
                new_wasm_hash: None,
                enrichment_incomplete: false,

                transaction_hash: synthetic_hash,
                function_name: None,
                function_names: vec![],
                function_args: vec![],
                amount_xlm: None,
                fee_charged_stroops: None,
                timestamp: ts,
                timestamp_iso: ts_iso,
                horizon_link: synthetic_horizon_link,
                explorer_link: synthetic_explorer_link,
                resolved: false,
            })
        }
        // Already alerting and activity has resumed → fire recovery.
        (NoActivityState::Alerting { incident_alert_id }, false) => {
            let recovery_alert_id = if incident_alert_id.is_empty() {
                alert_id(
                    &ctx.network_id,
                    ctx.contract_id,
                    &ts.to_string(),
                    "NoActivity",
                    &format!("NoActivity({}min) resolved", minutes),
                    rule_index,
                )
            } else {
                incident_alert_id.clone()
            };
            *state = NoActivityState::Active;
            let last_horizon_link = match last_seen {
                Some(_) => format!("{}/accounts/{}", horizon_base, ctx.contract_id),
                None => synthetic_horizon_link,
            };
            let last_explorer_link = match (explorer_base, last_seen) {
                (Some(base), _) => format!("{}/contract/{}", base, ctx.contract_id),
                _ => last_horizon_link.clone(),
            };
            let rule_triggered = format!("NoActivity({}min) resolved", minutes);
            Some(AlertPayload {
                label: ctx.label.to_string(),
                contract_id: ctx.contract_id.to_string(),
                network: ctx.network.to_string(),
                rule_type: "NoActivity".into(),
                rule_triggered,
                alert_id: recovery_alert_id,
                schema_version: 1,
                amount_stroops: None,
                amount_xlm_decimal: None,
                source_account: None,
                fee_account: None,
                severity: None,
                effective_webhook_url: None,
                effective_webhook_secret: None,
                ledger: None,
                memo: None,
                memo_type: None,
                operation_count: None,
                matched_events: vec![],
                suppressed_count: 0,
                observed_count: None,
                test: false,
                old_wasm_hash: None,
                new_wasm_hash: None,
                enrichment_incomplete: false,

                transaction_hash: synthetic_hash,
                function_name: None,
                function_names: vec![],
                function_args: vec![],
                amount_xlm: None,
                fee_charged_stroops: None,
                timestamp: ts,
                timestamp_iso: ts_iso,
                horizon_link: last_horizon_link,
                explorer_link: last_explorer_link,
                resolved: true,
            })
        }
        _ => None,
    }
}

// ── Cooldowns ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct CooldownState {
    last_fired: DateTime<Utc>,
    suppressed: u64,
}

/// Enforces per-rule `cooldown_seconds`: after a rule fires for a contract,
/// further matches of the same (contract, rule) within the window are dropped
/// and counted, and the next alert that goes out carries that count in
/// `suppressed_count`.
///
/// The current time is passed in by the caller, so tests control the clock.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(
    from = "Vec<((String, String), CooldownState)>",
    into = "Vec<((String, String), CooldownState)>"
)]
pub struct CooldownTracker {
    state: HashMap<(String, String), CooldownState>,
}

impl From<Vec<((String, String), CooldownState)>> for CooldownTracker {
    fn from(entries: Vec<((String, String), CooldownState)>) -> Self {
        Self {
            state: entries.into_iter().collect(),
        }
    }
}

impl From<CooldownTracker> for Vec<((String, String), CooldownState)> {
    fn from(tracker: CooldownTracker) -> Self {
        tracker.state.into_iter().collect()
    }
}

impl CooldownTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter `payloads` (as returned by [`evaluate`] for `rules`) through each
    /// rule's cooldown at time `now`. Payloads whose rule has no cooldown pass
    /// through unchanged.
    pub fn apply(
        &mut self,
        rules: &[RuleConfig],
        payloads: Vec<AlertPayload>,
        now: DateTime<Utc>,
    ) -> Vec<AlertPayload> {
        payloads
            .into_iter()
            .filter_map(|mut payload| {
                let cooldown = rules
                    .iter()
                    .find(|r| rule_label(&r.rule) == payload.rule_triggered)
                    .and_then(|r| r.cooldown_seconds)
                    .unwrap_or(0);
                match self.check(&payload.contract_id, &payload.rule_triggered, cooldown, now) {
                    Some(suppressed) => {
                        payload.suppressed_count = suppressed;
                        Some(payload)
                    }
                    None => {
                        tracing::debug!(
                            contract = %payload.label,
                            rule = %payload.rule_triggered,
                            tx = %payload.transaction_hash,
                            cooldown_seconds = cooldown,
                            "rule matched within its cooldown — alert suppressed"
                        );
                        None
                    }
                }
            })
            .collect()
    }

    /// Record a match of `rule` on `contract_id` at `now`. Returns
    /// `Some(suppressed_count)` when the alert should fire (resetting the
    /// window and the count), or `None` when it falls inside the cooldown.
    pub fn check(
        &mut self,
        contract_id: &str,
        rule: &str,
        cooldown_seconds: u64,
        now: DateTime<Utc>,
    ) -> Option<u64> {
        if cooldown_seconds == 0 {
            return Some(0);
        }
        let key = (contract_id.to_owned(), rule.to_owned());
        let window = i64::try_from(cooldown_seconds)
            .ok()
            .and_then(chrono::TimeDelta::try_seconds)
            .unwrap_or(chrono::TimeDelta::MAX);
        match self.state.get_mut(&key) {
            Some(state) if now.signed_duration_since(state.last_fired) < window => {
                state.suppressed = state.suppressed.saturating_add(1);
                None
            }
            Some(state) => {
                let suppressed = state.suppressed;
                *state = CooldownState {
                    last_fired: now,
                    suppressed: 0,
                };
                Some(suppressed)
            }
            None => {
                self.state.insert(
                    key,
                    CooldownState {
                        last_fired: now,
                        suppressed: 0,
                    },
                );
                Some(0)
            }
        }
    }

    /// Check for any rules where the cooldown window has expired and
    /// `suppressed > 0` with `cooldown_summary = true`.
    /// Emits a summary alert payload for each such rule and resets `suppressed` to 0.
    pub fn check_summaries(
        &mut self,
        rules: &[RuleConfig],
        ctx: &EvalContext<'_>,
        now: DateTime<Utc>,
    ) -> Vec<AlertPayload> {
        let horizon_base = ctx.horizon_base.trim_end_matches('/');
        let explorer_base = ctx.explorer_base.map(|b| b.trim_end_matches('/'));
        let synthetic_horizon_link = format!("{}/accounts/{}", horizon_base, ctx.contract_id);
        let synthetic_explorer_link = match explorer_base {
            Some(base) => format!("{}/contract/{}", base, ctx.contract_id),
            None => synthetic_horizon_link.clone(),
        };

        let mut summaries = Vec::new();

        for (rule_index, rule_cfg) in rules.iter().enumerate() {
            if !rule_cfg.cooldown_summary {
                continue;
            }
            let cooldown = rule_cfg.cooldown_seconds.unwrap_or(0);
            if cooldown == 0 {
                continue;
            }
            let window = match i64::try_from(cooldown)
                .ok()
                .and_then(chrono::TimeDelta::try_seconds)
            {
                Some(w) => w,
                None => continue,
            };
            let rule_trig = rule_label(&rule_cfg.rule);
            let key = (ctx.contract_id.to_owned(), rule_trig.clone());

            if let Some(state) = self.state.get_mut(&key) {
                if state.suppressed > 0 && now.signed_duration_since(state.last_fired) >= window {
                    let suppressed_count = state.suppressed;
                    state.suppressed = 0;
                    state.last_fired = now;

                    let ts = now.timestamp();
                    let ts_iso = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
                    let alert_id = alert_id(
                        &ctx.network_id,
                        ctx.contract_id,
                        &ts.to_string(),
                        rule_cfg.rule.rule_type(),
                        &rule_trig,
                        rule_index,
                    );

                    summaries.push(AlertPayload {
                        label: ctx.label.to_string(),
                        contract_id: ctx.contract_id.to_string(),
                        network: ctx.network.to_string(),
                        rule_type: rule_cfg.rule.rule_type().to_string(),
                        rule_triggered: rule_trig,
                        alert_id,
                        schema_version: 1,
                        amount_stroops: None,
                        amount_xlm_decimal: None,
                        source_account: None,
                        fee_account: None,
                        severity: None,
                        effective_webhook_url: None,
                        effective_webhook_secret: None,
                        ledger: None,
                        memo: None,
                        memo_type: None,
                        operation_count: None,
                        matched_events: vec![],
                        suppressed_count,
                        test: false,
                        old_wasm_hash: None,
                        new_wasm_hash: None,
                        enrichment_incomplete: false,
                        transaction_hash: String::new(),
                        function_name: None,
                        function_names: vec![],
                        amount_xlm: None,
                        fee_charged_stroops: None,
                        timestamp: ts,
                        timestamp_iso: ts_iso,
                        horizon_link: synthetic_horizon_link.clone(),
                        explorer_link: synthetic_explorer_link.clone(),
                        resolved: false,
                    });
                }
            }
        }

        summaries
    }
}

// ── Rate rules (issue #267) ───────────────────────────────────────────────────

/// Evaluates `Rate` rules, which fire when their nested rule matches at least
/// `count` times within a sliding `window_seconds` window.
///
/// Matches are tracked per (contract, rule). A breach emits one alert carrying
/// `observed_count` and clears the window, so the next alert needs another
/// `count` matches. The current time is passed in by the caller, so tests
/// control the clock.
#[derive(Debug, Default)]
pub struct RateTracker {
    hits: HashMap<(String, String), VecDeque<DateTime<Utc>>>,
}

impl RateTracker {
    /// An empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `tx` against every `Rate` rule in `rules` at time `now` and
    /// return one payload per rule whose threshold was breached. Non-`Rate`
    /// rules are ignored; they are handled by [`evaluate`].
    pub fn evaluate<R: AsRef<AlertRule> + RuleOverrides>(
        &mut self,
        ctx: &EvalContext<'_>,
        rules: &[R],
        tx: &EnrichedTransaction,
        now: DateTime<Utc>,
    ) -> Vec<AlertPayload> {
        let mut out = Vec::new();
        for entry in rules.iter().filter(|e| e.enabled()) {
            let rule: &AlertRule = entry.as_ref();
            let AlertRule::Rate {
                rule: inner,
                count,
                window_seconds,
            } = rule
            else {
                continue;
            };
            if !inner.enabled {
                continue;
            }
            match eval_rule(&inner.rule, tx) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!(
                        tx = %tx.hash,
                        rule = %rule.label(),
                        error = %e,
                        "rate rule evaluation error — skipping"
                    );
                    continue;
                }
            }

            let label = rule.label();
            let window = i64::try_from(*window_seconds)
                .ok()
                .and_then(chrono::TimeDelta::try_seconds)
                .unwrap_or(chrono::TimeDelta::MAX);
            let hits = self
                .hits
                .entry((ctx.contract_id.to_owned(), label.clone()))
                .or_default();
            hits.push_back(now);
            while hits
                .front()
                .is_some_and(|t| now.signed_duration_since(*t) >= window)
            {
                hits.pop_front();
            }
            let observed = hits.len() as u64;
            if observed < *count {
                continue;
            }
            hits.clear();

            // Build the payload from the nested rule so every transaction
            // field is filled the same way, then relabel it as the rate rule.
            let mut payloads = evaluate(ctx, std::slice::from_ref(&inner.rule), tx, None);
            if let Some(mut payload) = payloads.pop() {
                payload.rule_type = rule.rule_type().to_string();
                payload.alert_id = alert_id(ctx.contract_id, &tx.hash, &label);
                payload.rule_triggered = label;
                payload.observed_count = Some(observed);
                payload.severity = entry.severity().map(|s| s.to_string());
                payload.effective_webhook_url = entry.webhook_url().map(str::to_owned);
                payload.effective_webhook_secret = entry.webhook_secret().map(str::to_owned);
                out.push(payload);
            }
        }
        out
    }
}

// ── Glob matching (issue #55) ─────────────────────────────────────────────────

/// Internal parsers exposed for the fuzz targets in `fuzz/`. Not a public API.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    pub fn glob_match(pattern: &str, text: &str) -> bool {
        super::glob_match(pattern, text)
    }
}

/// Match `text` against a `pattern` that may contain `*` (any sequence of
/// characters) and `?` (exactly one character). All other characters are
/// matched literally, case-sensitively.
///
/// This is a lightweight recursive implementation with no external dependencies.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_inner(&p, &t)
}

fn glob_match_inner(p: &[char], t: &[char]) -> bool {
    match (p.first(), t.first()) {
        // Both exhausted → match.
        (None, None) => true,
        // Pattern consumed but text remains → no match.
        (None, Some(_)) => false,
        // `*` → try consuming zero characters (advance pattern only) or one
        // character from text (advance text only).
        (Some('*'), _) => {
            glob_match_inner(&p[1..], t) || (!t.is_empty() && glob_match_inner(p, &t[1..]))
        }
        // Text consumed but pattern has non-`*` characters remaining → no match.
        (Some(_), None) => false,
        // `?` → match any single character.
        (Some('?'), Some(_)) => glob_match_inner(&p[1..], &t[1..]),
        // Literal character match.
        (Some(pc), Some(tc)) if pc == tc => glob_match_inner(&p[1..], &t[1..]),
        // Literal mismatch.
        _ => false,
    }
}

impl AlertPayload {
    /// Builder helper to override the label (used by test-webhook).
    pub fn with_label(mut self, label: String) -> Self {
        self.label = label;
        self
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::Datelike;
    use txwatch_config::{AlertRule, RuleEntry, Severity};

    fn make_tx(
        successful: bool,
        function_names: &[&str],
        amount_stroops: Option<u64>,
    ) -> EnrichedTransaction {
        let function_names: Vec<String> = function_names.iter().map(|s| s.to_string()).collect();

        EnrichedTransaction {
            hash: "abc123".into(),
            timestamp: "2024-01-15T12:00:00Z".parse().unwrap(),
            successful,
            paging_token: "100".into(),
            function_names: function_names.iter().map(|s| s.to_string()).collect(),
            invocations: Vec::new(),
            amount_stroops,
            fee_charged_stroops: None,
            source_account: None,
            fee_account: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
            watched_contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
            events: vec![],
            contract_transfers: vec![],
            wasm_upgrade: None,
            enrichment_incomplete: false,
        }
    }

    fn entry(r: AlertRule) -> RuleEntry {
        RuleEntry {
            enabled: true,
            webhook_url: None,
            webhook_secret: None,
            severity: None,
            rule: r,
        }
    }

    fn run<R: AsRef<AlertRule> + RuleOverrides>(
        rules: &[R],
        tx: &EnrichedTransaction,
    ) -> Vec<AlertPayload> {
        let ctx = EvalContext {
            label: "Label",
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            network: "testnet",
            network_id: "testnet".into(),
            horizon_base: "https://horizon-testnet.stellar.org",
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        };
        evaluate(&ctx, rules, tx, None)
    }

    #[test]
    fn any_transaction_always_fires() {
        let tx = make_tx(true, &[], None);
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].rule_triggered, "AnyTransaction");
    }

    #[test]
    fn any_transaction_fires_on_failed_transaction() {
        let tx = make_tx(false, &[], None);
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].rule_triggered, "AnyTransaction");
    }

    /// #44: rule_triggered in the payload and rule.label() must agree for every variant.
    /// This guards against CLI validate and webhook payloads drifting from each other.
    #[test]
    fn rule_label_formats_are_stable() {
        assert_eq!(AlertRule::AnyTransaction.label(), "AnyTransaction");
        assert_eq!(AlertRule::TransactionFailed.label(), "TransactionFailed");
        assert_eq!(
            AlertRule::LargeTransfer {
                threshold_xlm: 10_000,
                threshold_stroops: 10_000 * 10_000_000,
                direction: "any".into(),
            }
            .label(),
            "LargeTransfer(>=10000XLM)"
        );
        assert_eq!(
            rule_label(&AlertRule::FunctionCalled {
                function_name: "withdraw".into(),
                match_mode: Default::default(),
                args: vec![],
            }),
            AlertRule::FunctionCalled {
                function_name: "withdraw".into(),
                match_mode: FunctionMatchMode::default(),
                args: vec![],
            }
            .label(),
            "FunctionCalled(withdraw)"
        );
        assert_eq!(
            AlertRule::AdminFunctionCalled {
                function_names: vec!["set_admin".into(), "upgrade".into()]
            }
            .label(),
            "AdminFunctionCalled([set_admin, upgrade])"
        );
        assert_eq!(
            AlertRule::HighFee {
                threshold_stroops: 10_000,
                threshold_xlm: None
            }
            .label(),
            "HighFee(>=10000 stroops)"
        );
    }

    /// #44: rule_type() must agree with the rule_type field in the webhook payload.
    #[test]
    fn rule_type_formats_are_stable() {
        assert_eq!(AlertRule::AnyTransaction.rule_type(), "AnyTransaction");
        assert_eq!(
            AlertRule::TransactionFailed.rule_type(),
            "TransactionFailed"
        );
        assert_eq!(
            AlertRule::LargeTransfer {
                threshold_xlm: 1,
                threshold_stroops: 10_000_000,
                direction: "any".into(),
            }
            .rule_type(),
            "LargeTransfer"
        );
        assert_eq!(
            AlertRule::FunctionCalled {
                function_name: "f".into(),
                match_mode: FunctionMatchMode::default(),
                args: vec![],
            }
            .rule_type(),
            "FunctionCalled"
        );
        assert_eq!(
            AlertRule::AdminFunctionCalled {
                function_names: vec!["f".into()]
            }
            .rule_type(),
            "AdminFunctionCalled"
        );
        assert_eq!(
            AlertRule::HighFee {
                threshold_stroops: 1,
                threshold_xlm: None
            }
            .rule_type(),
            "HighFee"
        );
    }

    /// #44: payload rule_triggered must equal AlertRule::label() for every variant.
    #[test]
    fn payload_rule_triggered_matches_alert_rule_label_for_every_variant() {
        let rules: &[AlertRule] = &[
            AlertRule::AnyTransaction,
            AlertRule::TransactionFailed,
            AlertRule::LargeTransfer {
                threshold_xlm: 10_000,
                threshold_stroops: 10_000 * 10_000_000,
                direction: "any".into(),
            },
            AlertRule::FunctionCalled {
                function_name: "withdraw".into(),
                match_mode: FunctionMatchMode::default(),
                args: vec![],
            },
            AlertRule::AdminFunctionCalled {
                function_names: vec!["set_admin".into(), "upgrade".into()],
            },
            AlertRule::HighFee {
                threshold_stroops: 50_000,
                threshold_xlm: None,
            },
        ];
        // A transaction that will satisfy every rule.
        let mut tx = EnrichedTransaction {
            hash: "abc123".into(),
            timestamp: "2024-01-15T12:00:00Z".parse().unwrap(),
            successful: false,
            paging_token: "1".into(),
            function_names: vec!["withdraw".into(), "set_admin".into()],
            invocations: Vec::new(),
            amount_stroops: Some(100_000_000_000_000),
            fee_charged_stroops: Some(50_000),
            source_account: None,
            fee_account: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
            watched_contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            events: vec![],
            contract_transfers: vec![],
            wasm_upgrade: None,
            enrichment_incomplete: false,
        };
        tx.successful = false; // satisfies TransactionFailed

        let ctx = EvalContext {
            label: "L",
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            network: "testnet",
            network_id: "testnet".into(),
            horizon_base: "https://horizon-testnet.stellar.org",
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        };
        for rule in rules {
            let payloads = evaluate(&ctx, std::slice::from_ref(&rule), &tx, None);
            assert_eq!(
                payloads.len(),
                1,
                "rule {:?} should fire on the test transaction",
                rule.rule_type()
            );
            assert_eq!(
                payloads[0].rule_triggered,
                rule.label(),
                "payload rule_triggered must equal AlertRule::label() for {:?}",
                rule.rule_type()
            );
            assert_eq!(
                payloads[0].rule_type,
                rule.rule_type(),
                "payload rule_type must equal AlertRule::rule_type() for {:?}",
                rule.rule_type()
            );
        }
    }

    #[test]
    fn transaction_failed_fires_on_failure() {
        let tx = make_tx(false, &[], None);
        let payloads = run(&[entry(AlertRule::TransactionFailed)], &tx);
        assert_eq!(payloads.len(), 1);
    }

    #[test]
    fn transaction_failed_does_not_fire_on_success() {
        let tx = make_tx(true, &[], None);
        let payloads = run(&[entry(AlertRule::TransactionFailed)], &tx);
        assert!(payloads.is_empty());
    }

    #[test]
    fn large_transfer_fires_at_threshold() {
        // exactly 10_000 XLM = 100_000_000_000 stroops
        let tx = make_tx(true, &[], Some(100_000_000_000));
        let payloads = run(
            &[entry(AlertRule::LargeTransfer {
                threshold_xlm: 10_000,
                threshold_stroops: 100_000_000_000,
                direction: "any".into(),
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].amount_xlm, Some(10_000));
    }

    #[test]
    fn large_transfer_does_not_fire_below_threshold() {
        let tx = make_tx(true, &[], Some(9_999 * 10_000_000));
        let payloads = run(
            &[entry(AlertRule::LargeTransfer {
                threshold_xlm: 10_000,
                threshold_stroops: 100_000_000_000,
                direction: "any".into(),
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn large_transfer_no_amount_does_not_fire() {
        let tx = make_tx(true, &[], None);
        let payloads = run(
            &[entry(AlertRule::LargeTransfer {
                threshold_xlm: 1,
                threshold_stroops: 0,
                direction: "any".into(),
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn large_transfer_overflow_is_handled_gracefully() {
        let tx = make_tx(true, &[], Some(1_000_000_000_000_000));
        // A validated rule never carries this pair, but if one did the
        // comparison must not multiply and overflow.
        let payloads = run(
            &[entry(AlertRule::LargeTransfer {
                threshold_xlm: u64::MAX,
                threshold_stroops: u64::MAX,
                direction: "any".into(),
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn large_transfer_fires_at_exact_threshold() {
        let tx = make_tx(true, &[], Some(10_000 * 10_000_000));
        let payloads = run(
            &[entry(AlertRule::LargeTransfer {
                threshold_xlm: 10_000,
                threshold_stroops: 100_000_000_000,
                direction: "any".into(),
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].amount_xlm, Some(10_000));
    }

    #[test]
    fn large_transfer_does_not_fire_one_stroop_below_threshold() {
        let tx = make_tx(true, &[], Some(10_000 * 10_000_000 - 1));
        let payloads = run(
            &[entry(AlertRule::LargeTransfer {
                threshold_xlm: 10_000,
                threshold_stroops: 100_000_000_000,
                direction: "any".into(),
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn function_called_fires_on_match() {
        let tx = make_tx(true, &["withdraw"], None);
        let payloads = run(
            &[entry(AlertRule::FunctionCalled {
                function_name: "withdraw".into(),
                match_mode: FunctionMatchMode::default(),
                args: vec![],
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].function_name.as_deref(), Some("withdraw"));
    }

    #[test]
    fn function_called_does_not_fire_on_mismatch() {
        let tx = make_tx(true, &["deposit"], None);
        let payloads = run(
            &[entry(AlertRule::FunctionCalled {
                function_name: "withdraw".into(),
                match_mode: FunctionMatchMode::default(),
                args: vec![],
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn admin_function_called_fires_on_any_match() {
        let tx = make_tx(true, &["upgrade"], None);
        let payloads = run(
            &[entry(AlertRule::AdminFunctionCalled {
                function_names: vec!["set_admin".into(), "upgrade".into()],
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
        assert!(payloads[0].rule_triggered.contains("upgrade"));
    }

    #[test]
    fn function_called_does_not_fire_when_function_name_is_none() {
        let tx = make_tx(true, &[], None);
        let payloads = run(
            &[entry(AlertRule::FunctionCalled {
                function_name: "withdraw".into(),
                match_mode: FunctionMatchMode::default(),
                args: vec![],
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn admin_function_called_does_not_fire_when_function_name_is_none() {
        let tx = make_tx(true, &[], None);
        let payloads = run(
            &[entry(AlertRule::AdminFunctionCalled {
                function_names: vec!["set_admin".into(), "upgrade".into()],
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn multiple_rules_can_fire_on_same_tx() {
        let tx = make_tx(false, &["set_admin"], Some(200_000_000_000));
        let rules = vec![
            entry(AlertRule::AnyTransaction),
            entry(AlertRule::TransactionFailed),
            entry(AlertRule::LargeTransfer {
                threshold_xlm: 10_000,
                threshold_stroops: 100_000_000_000,
                direction: "any".into(),
            }),
            entry(AlertRule::AdminFunctionCalled {
                function_names: vec!["set_admin".into()],
            }),
        ];
        let payloads = run(&rules, &tx);
        assert_eq!(payloads.len(), 4);
    }

    #[test]
    fn horizon_link_is_correct() {
        let tx = make_tx(true, &[], None);
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        assert_eq!(
            payloads[0].horizon_link,
            "https://horizon-testnet.stellar.org/transactions/abc123"
        );
    }

    #[test]
    fn url_fields_have_no_trailing_slash_and_exact_format() {
        // Verify both link fields are normalised even when base URLs have trailing slashes.
        fn run_with_bases(horizon_base: &str, explorer_base: Option<&str>) -> AlertPayload {
            let tx = EnrichedTransaction {
                hash: "deadbeef".into(),
                timestamp: "2024-01-15T12:00:00Z".parse().unwrap(),
                successful: true,
                paging_token: "1".into(),
                function_names: vec![],
                invocations: Vec::new(),
                amount_stroops: None,
                fee_charged_stroops: None,
                source_account: None,
                fee_account: None,
                ledger: None,
                memo: None,
                memo_type: None,
                operation_count: None,
                watched_contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
                    .into(),
                events: vec![],
                contract_transfers: vec![],
                wasm_upgrade: None,
                enrichment_incomplete: false,
            };
            let rules = vec![entry(AlertRule::AnyTransaction)];
            let ctx = EvalContext {
                label: "L",
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
                network: "testnet",
                network_id: "testnet".into(),
                horizon_base,
                explorer_base,
            };
            let mut payloads = evaluate(&ctx, &rules, &tx, None);
            payloads.remove(0)
        }

        // Without trailing slash — baseline
        let p = run_with_bases(
            "https://horizon-testnet.stellar.org",
            Some("https://stellar.expert/explorer/testnet"),
        );
        assert_eq!(
            p.horizon_link,
            "https://horizon-testnet.stellar.org/transactions/deadbeef"
        );
        assert_eq!(
            p.explorer_link,
            "https://stellar.expert/explorer/testnet/tx/deadbeef"
        );

        // With trailing slash — must produce identical output
        let p2 = run_with_bases(
            "https://horizon-testnet.stellar.org/",
            Some("https://stellar.expert/explorer/testnet/"),
        );
        assert_eq!(p.horizon_link, p2.horizon_link);
        assert_eq!(p.explorer_link, p2.explorer_link);
    }

    #[test]
    fn high_fee_fires_at_threshold() {
        let mut tx = make_tx(true, &[], None);
        tx.fee_charged_stroops = Some(10_000);
        let payloads = run(
            &[entry(AlertRule::HighFee {
                threshold_stroops: 10_000,
                threshold_xlm: None,
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
        assert!(payloads[0].rule_triggered.contains("HighFee"));
    }

    #[test]
    fn high_fee_does_not_fire_below_threshold() {
        let mut tx = make_tx(true, &[], None);
        tx.fee_charged_stroops = Some(9_999);
        let payloads = run(
            &[entry(AlertRule::HighFee {
                threshold_stroops: 10_000,
                threshold_xlm: None,
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn high_fee_no_fee_does_not_fire() {
        let tx = make_tx(true, &[], None);
        let payloads = run(
            &[entry(AlertRule::HighFee {
                threshold_stroops: 1,
                threshold_xlm: None,
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn enriched_transaction_parses_timestamp() {
        let raw = HorizonTransaction {
            hash: "h1".into(),
            created_at: "2024-06-01T00:00:00Z".into(),
            successful: true,
            paging_token: "1".into(),
            fee_charged: Some("100".into()),
            source_account: Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()),
            fee_account: None,
            envelope_xdr: None,
            result_xdr: None,
            ledger: None,
            ..Default::default()
        };
        let enriched = EnrichedTransaction::from_horizon(raw, vec![], None, None).unwrap();
        assert_eq!(enriched.timestamp.year(), 2024);
        assert!(enriched.source_account.is_some());
    }

    /// Issue #65: from_horizon must return Err when created_at is not a valid RFC 3339 timestamp.
    #[test]
    fn from_horizon_rejects_invalid_timestamp() {
        let raw = HorizonTransaction {
            hash: "badhash".into(),
            created_at: "not-a-timestamp".into(),
            successful: true,
            paging_token: "1".into(),
            fee_charged: None,
            source_account: None,
            fee_account: None,
            envelope_xdr: None,
            result_xdr: None,
            ledger: None,
            ..Default::default()
        };
        let result = EnrichedTransaction::from_horizon(raw, vec![], None, None);
        assert!(result.is_err(), "expected Err for invalid timestamp");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("cannot parse timestamp"),
            "error message should mention 'cannot parse timestamp', got: {}",
            msg
        );
    }

    // ── Issue #77: multiple invoke_host_function ops ──────────────────────────

    #[test]
    fn function_called_fires_when_matching_name_is_second_in_list() {
        // Transaction has two Soroban invocations; rule should match the second
        let tx = make_tx(true, &["deposit", "withdraw"], None);
        let payloads = run(
            &[entry(AlertRule::FunctionCalled {
                function_name: "withdraw".into(),
                match_mode: FunctionMatchMode::default(),
                args: vec![],
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].function_names, vec!["deposit", "withdraw"]);
    }

    #[test]
    fn function_called_does_not_fire_when_no_names_match() {
        let tx = make_tx(true, &["deposit", "transfer"], None);
        let payloads = run(
            &[entry(AlertRule::FunctionCalled {
                function_name: "withdraw".into(),
                match_mode: FunctionMatchMode::default(),
                args: vec![],
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn admin_function_called_fires_on_any_of_multiple_invocations() {
        // Two invocations; only the second is an admin function
        let tx = make_tx(true, &["transfer", "set_admin"], None);
        let payloads = run(
            &[entry(AlertRule::AdminFunctionCalled {
                function_names: vec!["set_admin".into(), "upgrade".into()],
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
    }

    #[test]
    fn payload_function_names_contains_all_invocations() {
        let tx = make_tx(true, &["foo", "bar", "baz"], None);
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        assert_eq!(payloads[0].function_names, vec!["foo", "bar", "baz"]);
        // function_name (singular) is the first for backward compat
        assert_eq!(payloads[0].function_name.as_deref(), Some("foo"));
    }

    // ── Issue #46: amount_xlm_decimal and amount_stroops fields ──────────────

    #[test]
    fn amount_xlm_decimal_is_formatted_with_7_decimal_places() {
        // 9,999 XLM + 9,900,000 stroops = 9999.9900000
        let tx = make_tx(true, &[], Some(99_999_900_000));
        let payloads = run(
            &[AlertRule::LargeTransfer {
                threshold_xlm: 1,
                threshold_stroops: 10_000_000,
                direction: "any".into(),
            }],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
        // amount_xlm truncates the fractional part
        assert_eq!(payloads[0].amount_xlm, Some(9_999));
        // amount_xlm_decimal is precise
        assert_eq!(
            payloads[0].amount_xlm_decimal.as_deref(),
            Some("9999.9900000")
        );
        // amount_stroops is the raw value
        assert_eq!(payloads[0].amount_stroops, Some(99_999_900_000));
    }

    #[test]
    fn amount_xlm_decimal_is_none_when_no_amount() {
        let tx = make_tx(true, &[], None);
        let payloads = run(&[AlertRule::AnyTransaction], &tx);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].amount_xlm, None);
        assert_eq!(payloads[0].amount_xlm_decimal, None);
        assert_eq!(payloads[0].amount_stroops, None);
    }

    #[test]
    fn sub_xlm_amount_is_not_zero_in_decimal_field() {
        // Less than 1 XLM — amount_xlm truncates to 0 but decimal is correct
        let tx = make_tx(true, &[], Some(5_000_000)); // 0.5 XLM
        let payloads = run(&[AlertRule::AnyTransaction], &tx);
        assert_eq!(payloads[0].amount_xlm, Some(0));
        assert_eq!(payloads[0].amount_xlm_decimal.as_deref(), Some("0.5000000"));
    }

    #[test]
    fn alert_payload_serialises_to_valid_json_with_all_fields_present() {
        let payload = AlertPayload {
            schema_version: 1,
            alert_id: "0123456789abcdef0123456789abcdef".into(),
            label: "My Contract".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
            network: "testnet".into(),
            rule_type: "LargeTransfer".into(),
            rule_triggered: "LargeTransfer(>=10000XLM)".into(),
            transaction_hash: "abc123".into(),
            function_name: Some("transfer".into()),
            function_names: vec!["transfer".into()],
            function_args: vec![],
            amount_xlm: Some(15000),
            amount_stroops: Some(150_000_000_000_000),
            amount_xlm_decimal: Some("15000.0000000".into()),
            fee_charged_stroops: Some(50000),
            source_account: Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()),
            fee_account: None,
            severity: None,
            timestamp: 1705316096,
            timestamp_iso: "2024-01-15T12:00:00Z".into(),
            horizon_link: "https://horizon-testnet.stellar.org/transactions/abc123".into(),
            explorer_link: "https://stellar.expert/explorer/testnet/tx/abc123".into(),
            effective_webhook_url: None,
            effective_webhook_secret: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
            resolved: false,
            matched_events: vec![],
            suppressed_count: 0,
            observed_count: None,
            test: false,
            old_wasm_hash: None,
            new_wasm_hash: None,
            enrichment_incomplete: false,
        };

        let json = serde_json::to_value(payload).expect("serialize AlertPayload to JSON");
        let obj = json
            .as_object()
            .expect("AlertPayload should serialize to a JSON object");

        assert_eq!(obj["schema_version"].as_u64(), Some(1));
        assert!(
            obj["alert_id"].as_str().is_some(),
            "alert_id must be present"
        );
        assert_eq!(obj["label"].as_str(), Some("My Contract"));
        assert_eq!(
            obj["contract_id"].as_str(),
            Some("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4")
        );
        assert_eq!(obj["network"].as_str(), Some("testnet"));
        assert_eq!(obj["rule_type"].as_str(), Some("LargeTransfer"));
        assert_eq!(
            obj["rule_triggered"].as_str(),
            Some("LargeTransfer(>=10000XLM)")
        );
        assert_eq!(obj["transaction_hash"].as_str(), Some("abc123"));
        assert_eq!(obj["function_name"].as_str(), Some("transfer"));
        assert_eq!(obj["function_names"].as_array().map(|a| a.len()), Some(1));
        assert_eq!(obj["amount_xlm"].as_u64(), Some(15000));
        assert_eq!(obj["amount_stroops"].as_u64(), Some(150_000_000_000_000));
        assert_eq!(obj["amount_xlm_decimal"].as_str(), Some("15000.0000000"));
        assert_eq!(obj["fee_charged_stroops"].as_u64(), Some(50000));
        assert_eq!(obj["timestamp"].as_i64(), Some(1705316096));
        assert_eq!(obj["timestamp_iso"].as_str(), Some("2024-01-15T12:00:00Z"));
        assert_eq!(
            obj["horizon_link"].as_str(),
            Some("https://horizon-testnet.stellar.org/transactions/abc123")
        );
        assert_eq!(
            obj["explorer_link"].as_str(),
            Some("https://stellar.expert/explorer/testnet/tx/abc123")
        );
        // source_account should be present when set
        assert_eq!(
            obj["source_account"].as_str(),
            Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN")
        );
        // effective_webhook_url/secret are skipped in serialization
        assert!(!obj.contains_key("effective_webhook_url"));
        assert!(!obj.contains_key("effective_webhook_secret"));
    }

    // ── Issue #54: disabled rules are skipped ────────────────────────────────

    #[test]
    fn disabled_rule_is_skipped() {
        let tx = make_tx(true, &[], None);
        let rules = vec![RuleEntry {
            enabled: false,
            webhook_url: None,
            webhook_secret: None,
            severity: None,
            rule: AlertRule::AnyTransaction,
        }];
        let payloads = run(&rules, &tx);
        assert!(payloads.is_empty(), "disabled rule must not fire");
    }

    #[test]
    fn enabled_rule_fires() {
        let tx = make_tx(true, &[], None);
        let rules = vec![RuleEntry {
            enabled: true,
            webhook_url: None,
            webhook_secret: None,
            severity: None,
            rule: AlertRule::AnyTransaction,
        }];
        let payloads = run(&rules, &tx);
        assert_eq!(payloads.len(), 1);
    }

    // ── Issue #53: per-rule webhook overrides and severity ───────────────────

    #[test]
    fn per_rule_webhook_url_override_is_propagated() {
        let tx = make_tx(true, &[], None);
        let rules = vec![RuleEntry {
            enabled: true,
            webhook_url: Some("https://override.example.com/hook".into()),
            webhook_secret: Some("mysecret".into()),
            severity: Some(Severity::Critical),
            rule: AlertRule::AnyTransaction,
        }];
        let payloads = run(&rules, &tx);
        assert_eq!(payloads.len(), 1);
        assert_eq!(
            payloads[0].effective_webhook_url.as_deref(),
            Some("https://override.example.com/hook")
        );
        assert_eq!(
            payloads[0].effective_webhook_secret.as_deref(),
            Some("mysecret")
        );
        assert_eq!(payloads[0].severity.as_deref(), Some("critical"));
    }

    #[test]
    fn severity_is_serialized_in_payload() {
        let tx = make_tx(true, &[], None);
        let rules = vec![RuleEntry {
            enabled: true,
            webhook_url: None,
            webhook_secret: None,
            severity: Some(Severity::Warning),
            rule: AlertRule::AnyTransaction,
        }];
        let payloads = run(&rules, &tx);
        let json = serde_json::to_value(&payloads[0]).unwrap();
        assert_eq!(json["severity"].as_str(), Some("warning"));
    }

    // ── Issue #52: composite rules ─────────────────────────────────────────

    #[test]
    fn all_rule_fires_when_all_conditions_match() {
        let tx = make_tx(false, &["withdraw"], Some(200_000_000_000));
        let all_rule = AlertRule::All {
            rules: vec![
                RuleEntry {
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::FunctionCalled {
                        function_name: "withdraw".into(),
                        match_mode: FunctionMatchMode::default(),
                        args: vec![],
                    },
                },
                RuleEntry {
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::LargeTransfer {
                        threshold_xlm: 10_000,
                        threshold_stroops: 100000000000,
                        direction: "any".into(),
                    },
                },
            ],
        };
        let payloads = run(&[entry(all_rule)], &tx);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].rule_type, "All");
        assert_eq!(
            payloads[0].rule_triggered,
            "All(FunctionCalled(withdraw), LargeTransfer(>=10000XLM))"
        );
    }

    #[test]
    fn all_rule_does_not_fire_when_one_condition_fails() {
        let tx = make_tx(false, &["withdraw"], Some(50_000_000)); // 5 XLM, below threshold
        let all_rule = AlertRule::All {
            rules: vec![
                RuleEntry {
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::FunctionCalled {
                        function_name: "withdraw".into(),
                        match_mode: FunctionMatchMode::default(),
                        args: vec![],
                    },
                },
                RuleEntry {
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::LargeTransfer {
                        threshold_xlm: 10_000,
                        threshold_stroops: 100000000000,
                        direction: "any".into(),
                    },
                },
            ],
        };
        let payloads = run(&[entry(all_rule)], &tx);
        assert!(
            payloads.is_empty(),
            "All rule must not fire unless all sub-rules match"
        );
    }

    #[test]
    fn all_rule_does_not_fire_when_all_subrules_are_disabled() {
        let tx = make_tx(true, &[], None);
        let all_rule = AlertRule::All {
            rules: vec![RuleEntry {
                enabled: false,
                webhook_url: None,
                webhook_secret: None,
                severity: None,
                rule: AlertRule::AnyTransaction,
            }],
        };

        let payloads = run(&[entry(all_rule)], &tx);
        assert!(
            payloads.is_empty(),
            "All must not match when it has no enabled sub-rules"
        );
    }

    #[test]
    fn any_rule_fires_when_one_condition_matches() {
        let tx = make_tx(true, &["upgrade"], None);
        let any_rule = AlertRule::Any {
            rules: vec![
                RuleEntry {
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::FunctionCalled {
                        function_name: "withdraw".into(),
                        match_mode: FunctionMatchMode::default(),
                        args: vec![],
                    },
                },
                RuleEntry {
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::FunctionCalled {
                        function_name: "upgrade".into(),
                        match_mode: FunctionMatchMode::default(),
                        args: vec![],
                    },
                },
            ],
        };
        let payloads = run(&[entry(any_rule)], &tx);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].rule_type, "Any");
    }

    #[test]
    fn any_rule_does_not_fire_when_all_subrules_are_disabled() {
        let tx = make_tx(true, &[], None);
        let any_rule = AlertRule::Any {
            rules: vec![RuleEntry {
                enabled: false,
                webhook_url: None,
                webhook_secret: None,
                severity: None,
                rule: AlertRule::AnyTransaction,
            }],
        };

        let payloads = run(&[entry(any_rule)], &tx);
        assert!(
            payloads.is_empty(),
            "Any must not match when it has no enabled sub-rules"
        );
    }

    #[test]
    fn not_rule_inverts_match() {
        let tx_success = make_tx(true, &[], None);
        let tx_failed = make_tx(false, &[], None);
        let not_rule = AlertRule::Not {
            rule: Box::new(RuleEntry {
                enabled: true,
                webhook_url: None,
                webhook_secret: None,
                severity: None,
                rule: AlertRule::TransactionFailed,
            }),
        };
        // Successful tx should match Not(TransactionFailed)
        let payloads = run(&[entry(not_rule.clone())], &tx_success);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].rule_type, "Not");

        // Failed tx should not match Not(TransactionFailed)
        let payloads = run(&[entry(not_rule)], &tx_failed);
        assert!(payloads.is_empty());
    }

    #[test]
    fn composite_disabled_subrule_is_skipped_in_all() {
        // All with one enabled passing and one disabled sub-rule; should still fire
        // because the disabled sub-rule is skipped (treated as trivially true for All).
        let tx = make_tx(true, &["withdraw"], None);
        let all_rule = AlertRule::All {
            rules: vec![
                RuleEntry {
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::FunctionCalled {
                        function_name: "withdraw".into(),
                        match_mode: FunctionMatchMode::default(),
                        args: vec![],
                    },
                },
                RuleEntry {
                    enabled: false, // disabled — skip this sub-rule
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::TransactionFailed, // would fail if evaluated
                },
            ],
        };
        let payloads = run(&[entry(all_rule)], &tx);
        assert_eq!(
            payloads.len(),
            1,
            "disabled sub-rules in All should be skipped"
        );
    }

    // ── Issue #51: SourceAccount rule ─────────────────────────────────────────

    #[test]
    fn source_account_allow_fires_on_match() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::In,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec![],
                alert_unless: vec![],
                allow: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                deny: vec![],
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].rule_type, "SourceAccount");
    }

    #[test]
    fn source_account_allow_does_not_fire_on_mismatch() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::In,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec![],
                alert_unless: vec![],
                allow: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                deny: vec![],
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn source_account_deny_fires_on_blocked_address() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::In,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec![],
                alert_unless: vec![],
                allow: vec![],
                deny: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
    }

    #[test]
    fn source_account_deny_does_not_fire_on_allowed_address() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::In,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec![],
                alert_unless: vec![],
                allow: vec![],
                deny: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn source_account_does_not_fire_when_source_is_missing() {
        let tx = make_tx(true, &[], None); // source_account = None
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::In,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec![],
                alert_unless: vec![],
                allow: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                deny: vec![],
            })],
            &tx,
        );
        assert!(
            payloads.is_empty(),
            "SourceAccount must not fire when source_account is None"
        );
    }

    // ── Issue #250: SourceAccount mode="not_in" and alert_unless ─────────────

    #[test]
    fn source_account_mode_not_in_fires_on_unknown_caller() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::NotIn,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                alert_unless: vec![],
                allow: vec![],
                deny: vec![],
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].rule_type, "SourceAccount");
    }

    #[test]
    fn source_account_mode_not_in_does_not_fire_on_known_caller() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::NotIn,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                alert_unless: vec![],
                allow: vec![],
                deny: vec![],
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn source_account_mode_not_in_does_not_fire_when_source_is_missing() {
        let tx = make_tx(true, &[], None); // source_account = None
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::NotIn,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                alert_unless: vec![],
                allow: vec![],
                deny: vec![],
            })],
            &tx,
        );
        assert!(
            payloads.is_empty(),
            "SourceAccount with mode=not_in must not fire when source_account is None"
        );
    }

    #[test]
    fn source_account_alert_unless_fires_on_unknown_caller() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::NotIn,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec![],
                alert_unless: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                allow: vec![],
                deny: vec![],
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
    }

    #[test]
    fn source_account_alert_unless_does_not_fire_on_known_caller() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::NotIn,
                field: txwatch_config::SourceAccountField::Source,
                accounts: vec![],
                alert_unless: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                allow: vec![],
                deny: vec![],
            })],
            &tx,
        );
        assert!(payloads.is_empty());
    }

    #[test]
    fn source_account_included_in_payload() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into());
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        assert_eq!(
            payloads[0].source_account.as_deref(),
            Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN")
        );
    }

    #[test]
    fn real_alerts_do_not_carry_the_test_marker() {
        let tx = make_tx(true, &[], None);
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        let obj = serde_json::to_value(&payloads[0]).unwrap();
        let obj = obj.as_object().unwrap();
        assert!(
            !obj.contains_key("test"),
            "real alerts must not carry the test marker"
        );
    }

    // ── Issue #251: SourceAccount field="fee_account" and fee-bump payload ────

    #[test]
    fn source_account_field_fee_account_fires_on_fee_payer() {
        let mut tx = make_tx(true, &[], None);
        // Horizon fee-bump shape: inner source differs from the fee payer.
        tx.source_account = Some("GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into());
        tx.fee_account = Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::In,
                field: txwatch_config::SourceAccountField::FeeAccount,
                accounts: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                alert_unless: vec![],
                allow: vec![],
                deny: vec![],
            })],
            &tx,
        );
        assert_eq!(
            payloads.len(),
            1,
            "field=fee_account must match the fee payer of a fee-bump"
        );
    }

    #[test]
    fn source_account_field_fee_account_falls_back_to_source() {
        let mut tx = make_tx(true, &[], None);
        // Non-fee-bump: no fee_account, so fall back to source_account.
        tx.source_account = Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into());
        let payloads = run(
            &[entry(AlertRule::SourceAccount {
                mode: txwatch_config::SourceAccountMode::In,
                field: txwatch_config::SourceAccountField::FeeAccount,
                accounts: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
                alert_unless: vec![],
                allow: vec![],
                deny: vec![],
            })],
            &tx,
        );
        assert_eq!(payloads.len(), 1);
    }

    #[test]
    fn fee_account_included_in_payload_when_different_from_source() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into());
        tx.fee_account = Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into());
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        assert_eq!(
            payloads[0].fee_account.as_deref(),
            Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"),
            "fee_account must ride along when it differs from source_account"
        );
        let obj = serde_json::to_value(&payloads[0]).unwrap();
        let obj = obj.as_object().unwrap();
        assert!(
            obj.contains_key("fee_account"),
            "fee_account present in JSON when it differs"
        );
    }

    #[test]
    fn fee_account_omitted_from_payload_when_same_as_source() {
        let mut tx = make_tx(true, &[], None);
        tx.source_account = Some("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into());
        tx.fee_account = tx.source_account.clone();
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        assert_eq!(
            payloads[0].fee_account, None,
            "fee_account must be omitted when it equals source_account"
        );
        let obj = serde_json::to_value(&payloads[0]).unwrap();
        let obj = obj.as_object().unwrap();
        assert!(
            !obj.contains_key("fee_account"),
            "fee_account absent in JSON when it equals source_account"
        );
    }

    #[test]
    fn source_account_field_fee_account_label_mentions_field() {
        use txwatch_config::{SourceAccountField, SourceAccountMode};
        let label = rule_label(&AlertRule::SourceAccount {
            mode: SourceAccountMode::In,
            field: SourceAccountField::FeeAccount,
            accounts: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN".into()],
            alert_unless: vec![],
            allow: vec![],
            deny: vec![],
        });
        assert!(
            label.contains("field=fee_account"),
            "label must distinguish fee_account rules, got: {}",
            label
        );
    }

    #[test]
    fn optional_fields_are_omitted_when_none() {
        let tx = make_tx(true, &[], None);
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        let value = serde_json::to_value(&payloads[0]).unwrap();
        let obj = value.as_object().unwrap();
        assert!(!obj.contains_key("ledger"), "ledger absent when None");
        assert!(
            !obj.contains_key("source_account"),
            "source_account absent when None"
        );
        assert_eq!(obj["resolved"].as_bool(), Some(false));
    }

    // ── Issue #274: enrichment_incomplete flag ───────────────────────────────

    #[test]
    fn enrichment_incomplete_is_omitted_when_false() {
        let tx = make_tx(true, &[], None);
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        let value = serde_json::to_value(&payloads[0]).unwrap();
        assert!(
            !value
                .as_object()
                .unwrap()
                .contains_key("enrichment_incomplete"),
            "enrichment_incomplete must be omitted when false"
        );
    }

    #[test]
    fn enrichment_incomplete_is_propagated_to_payload() {
        let tx = make_tx(true, &[], None).with_enrichment_incomplete(true);
        let payloads = run(&[entry(AlertRule::AnyTransaction)], &tx);
        assert_eq!(payloads.len(), 1);
        assert!(payloads[0].enrichment_incomplete);
        let value = serde_json::to_value(&payloads[0]).unwrap();
        assert_eq!(value["enrichment_incomplete"].as_bool(), Some(true));
    }

    #[test]
    fn from_horizon_defaults_enrichment_incomplete_to_false() {
        let raw = HorizonTransaction {
            hash: "h1".into(),
            created_at: "2024-06-01T00:00:00Z".into(),
            successful: true,
            paging_token: "1".into(),
            ..Default::default()
        };
        let enriched = EnrichedTransaction::from_horizon(raw, vec![], None, None).unwrap();
        assert!(!enriched.enrichment_incomplete);
    }
}

// ── Property-based tests (#61) ────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;
    use txwatch_config::AlertRule;

    /// Minimal valid `EnrichedTransaction` for property tests.
    fn arb_tx(
        amount_stroops: Option<u64>,
        fee_stroops: Option<u64>,
        function_names: Vec<String>,
        successful: bool,
    ) -> EnrichedTransaction {
        EnrichedTransaction {
            hash: "proptesthash".into(),
            timestamp: "2024-01-01T00:00:00Z".parse().unwrap(),
            successful,
            paging_token: "1".into(),
            function_names,
            amount_stroops,
            fee_charged_stroops: fee_stroops,
            source_account: None,
            fee_account: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
            watched_contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            events: vec![],
            contract_transfers: vec![],
            wasm_upgrade: None,
            enrichment_incomplete: false,
        }
    }

    fn eval_one(rule: AlertRule, tx: &EnrichedTransaction) -> Vec<AlertPayload> {
        let ctx = EvalContext {
            label: "PropTest",
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            network: "testnet",
            network_id: "testnet".into(),
            horizon_base: "https://horizon-testnet.stellar.org",
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        };
        evaluate(&ctx, &[rule], tx, None)
    }

    proptest! {
        /// LargeTransfer fires iff amount_stroops >= threshold_xlm × 10^7,
        /// for all valid (non-zero, non-overflowing) threshold values.
        #[test]
        fn large_transfer_fires_iff_at_or_above_threshold(
            amount_stroops in 0u64..=u64::MAX / 2,
            threshold_xlm in 1u64..=1_000_000_000u64,
        ) {
            let tx = arb_tx(Some(amount_stroops), None, vec![], true);
            let rule = AlertRule::LargeTransfer {
                threshold_xlm,
                threshold_stroops: threshold_xlm.saturating_mul(10_000_000),
                direction: "any".into(),
            };
            let payloads = eval_one(rule, &tx);
            let threshold_stroops = threshold_xlm.saturating_mul(10_000_000);
            let should_fire = amount_stroops >= threshold_stroops;
            prop_assert_eq!(payloads.len() == 1, should_fire,
                "amount={} threshold_xlm={} threshold_stroops={} should_fire={}",
                amount_stroops, threshold_xlm, threshold_stroops, should_fire);
        }

        /// LargeTransfer never panics for any u64 threshold and amount combination.
        #[test]
        fn large_transfer_never_panics(
            amount_stroops in 0u64..=u64::MAX,
            threshold_xlm in 0u64..=u64::MAX,
        ) {
            let tx = arb_tx(Some(amount_stroops), None, vec![], true);
            // Use u64::MAX as threshold to exercise checked_mul overflow path.
            // validate() rejects threshold_xlm=0 so we can pass any value here
            // directly — eval_rule returns Ok(false) on overflow.
            let rule = AlertRule::LargeTransfer {
                threshold_xlm,
                threshold_stroops: threshold_xlm.saturating_mul(10_000_000),
                direction: "any".into(),
            };
            // Must not panic regardless of inputs.
            let _ = eval_one(rule, &tx);
        }

        /// HighFee fires iff fee_charged_stroops >= threshold_stroops, for all u64 values.
        #[test]
        fn high_fee_fires_iff_at_or_above_threshold(
            fee in 0u64..=u64::MAX,
            threshold in 1u64..=u64::MAX,
        ) {
            let tx = arb_tx(None, Some(fee), vec![], true);
            let rule = AlertRule::HighFee { threshold_stroops: threshold, threshold_xlm: None };
            let payloads = eval_one(rule, &tx);
            let should_fire = fee >= threshold;
            prop_assert_eq!(payloads.len() == 1, should_fire,
                "fee={} threshold={} should_fire={}", fee, threshold, should_fire);
        }

        /// evaluate never panics for arbitrary EnrichedTransaction inputs.
        #[test]
        fn evaluate_never_panics(
            amount_stroops in proptest::option::of(0u64..=u64::MAX),
            fee_stroops in proptest::option::of(0u64..=u64::MAX),
            successful in proptest::bool::ANY,
        ) {
            let tx = arb_tx(amount_stroops, fee_stroops, vec![], successful);
            let rules = vec![
                AlertRule::AnyTransaction,
                AlertRule::TransactionFailed,
                AlertRule::LargeTransfer { threshold_xlm: 1, threshold_stroops: 0, direction: "any".into() },
                AlertRule::HighFee { threshold_stroops: 1, threshold_xlm: None },
            ];
            let ctx = EvalContext {
                label: "PropTest",
                contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                network: "testnet",
                network_id: "testnet".into(),
                horizon_base: "https://horizon-testnet.stellar.org",
                explorer_base: Some("https://stellar.expert/explorer/testnet"),
            };
            // Must not panic.
            let _ = evaluate(&ctx, &rules, &tx, None);
        }
    }
}

// ── NoActivity tests (#62) ────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod no_activity_tests {
    use super::*;
    use chrono::TimeZone;
    use txwatch_config::AlertRule;

    fn ctx() -> EvalContext<'static> {
        EvalContext {
            label: "Oracle",
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            network: "testnet",
            network_id: "testnet".into(),
            horizon_base: "https://horizon-testnet.stellar.org",
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        }
    }

    fn ts(h: i32, m: i32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .with_ymd_and_hms(2024, 1, 15, h as u32, m as u32, 0)
            .unwrap()
    }

    #[test]
    fn no_activity_fires_when_threshold_exceeded() {
        let contract = ctx();
        let eval_ctx = contract;
        let rule = AlertRule::NoActivity { minutes: 5 };
        let mut state = NoActivityState::default();

        // Last seen 6 minutes ago — threshold is 5 min, so this should fire.
        let last_seen = ts(12, 0);
        let now = ts(12, 6);
        let payload = check_no_activity(&rule, 0, Some(last_seen), now, &mut state, &eval_ctx);

        assert!(payload.is_some(), "should fire when quiet for > threshold");
        let p = payload.unwrap();
        assert_eq!(p.rule_type, "NoActivity");
        assert!(!p.resolved, "incident payload must have resolved=false");
        assert!(
            p.transaction_hash.is_empty(),
            "synthetic payload has empty hash"
        );
        match &state {
            NoActivityState::Alerting { incident_alert_id } => {
                assert_eq!(incident_alert_id, &p.alert_id);
            }
            _ => panic!("expected Alerting state"),
        }
    }

    #[test]
    fn no_activity_does_not_fire_below_threshold() {
        let contract = ctx();
        let eval_ctx = contract;
        let rule = AlertRule::NoActivity { minutes: 5 };
        let mut state = NoActivityState::default();

        // Last seen 4 minutes ago — below threshold.
        let last_seen = ts(12, 0);
        let now = ts(12, 4);
        let payload = check_no_activity(&rule, 0, Some(last_seen), now, &mut state, &eval_ctx);

        assert!(payload.is_none());
        assert_eq!(state, NoActivityState::Active);
    }

    #[test]
    fn no_activity_fires_exactly_at_threshold() {
        let contract = ctx();
        let eval_ctx = contract;
        let rule = AlertRule::NoActivity { minutes: 5 };
        let mut state = NoActivityState::default();

        // Exactly 5 minutes gap — should fire.
        let last_seen = ts(12, 0);
        let now = ts(12, 5);
        let payload = check_no_activity(&rule, 0, Some(last_seen), now, &mut state, &eval_ctx);

        assert!(payload.is_some(), "should fire at exactly threshold");
    }

    #[test]
    fn no_activity_does_not_repeat_while_alerting() {
        let contract = ctx();
        let eval_ctx = contract;
        let rule = AlertRule::NoActivity { minutes: 5 };
        let mut state = NoActivityState::Alerting {
            incident_alert_id: "prev_incident".into(),
        };

        // Still quiet — already alerting, so no second payload.
        let last_seen = ts(12, 0);
        let now = ts(12, 20);
        let payload = check_no_activity(&rule, 0, Some(last_seen), now, &mut state, &eval_ctx);

        assert!(
            payload.is_none(),
            "should not re-fire while already alerting"
        );
        assert_eq!(
            state,
            NoActivityState::Alerting {
                incident_alert_id: "prev_incident".into()
            }
        );
    }

    #[test]
    fn no_activity_fires_recovery_when_activity_resumes() {
        let contract = ctx();
        let eval_ctx = contract;
        let rule = AlertRule::NoActivity { minutes: 5 };
        let incident_id = alert_id(
            &eval_ctx.network_id,
            eval_ctx.contract_id,
            &ts(12, 0).timestamp().to_string(),
            "NoActivity",
            "NoActivity(5min)",
            0,
        );
        let mut state = NoActivityState::Alerting {
            incident_alert_id: incident_id.clone(),
        };

        // Activity just happened (1 minute ago) while we were in Alerting state.
        let last_seen = ts(12, 10);
        let now = ts(12, 11);
        let payload = check_no_activity(&rule, 0, Some(last_seen), now, &mut state, &eval_ctx);

        assert!(
            payload.is_some(),
            "should fire recovery when activity resumes"
        );
        let p = payload.unwrap();
        assert!(p.resolved, "recovery payload must have resolved=true");
        assert_eq!(p.rule_type, "NoActivity");
        assert_eq!(
            p.alert_id, incident_id,
            "recovery alert_id must match incident alert_id"
        );
        assert_eq!(state, NoActivityState::Active);
    }

    #[test]
    fn no_activity_consecutive_incidents_have_different_alert_ids() {
        let contract = ctx();
        let eval_ctx = contract;
        let rule = AlertRule::NoActivity { minutes: 5 };
        let mut state = NoActivityState::default();

        // 1. Incident 1: quiet at 12:06
        let last_seen_1 = ts(12, 0);
        let now_1 = ts(12, 6);
        let payload_1 =
            check_no_activity(&rule, 0, Some(last_seen_1), now_1, &mut state, &eval_ctx).unwrap();
        assert!(!payload_1.resolved);
        let incident_id_1 = payload_1.alert_id.clone();
        assert_eq!(
            state,
            NoActivityState::Alerting {
                incident_alert_id: incident_id_1.clone(),
            }
        );

        // 2. Recovery 1: activity resumes at 12:10, polled at 12:11
        let last_seen_2 = ts(12, 10);
        let now_2 = ts(12, 11);
        let recovery_1 =
            check_no_activity(&rule, 0, Some(last_seen_2), now_2, &mut state, &eval_ctx).unwrap();
        assert!(recovery_1.resolved);
        assert_eq!(
            recovery_1.alert_id, incident_id_1,
            "recovery alert_id matches incident alert_id"
        );
        assert_eq!(state, NoActivityState::Active);

        // 3. Incident 2: quiet again at 12:20
        let now_3 = ts(12, 20);
        let payload_2 =
            check_no_activity(&rule, 0, Some(last_seen_2), now_3, &mut state, &eval_ctx).unwrap();
        assert!(!payload_2.resolved);
        let incident_id_2 = payload_2.alert_id.clone();
        assert_eq!(
            state,
            NoActivityState::Alerting {
                incident_alert_id: incident_id_2.clone(),
            }
        );

        // Consecutive incidents have distinct IDs
        assert_ne!(
            incident_id_1, incident_id_2,
            "consecutive incidents must have different alert IDs"
        );

        // 4. Recovery 2: activity resumes at 12:25, polled at 12:26
        let last_seen_3 = ts(12, 25);
        let now_4 = ts(12, 26);
        let recovery_2 =
            check_no_activity(&rule, 0, Some(last_seen_3), now_4, &mut state, &eval_ctx).unwrap();
        assert!(recovery_2.resolved);
        assert_eq!(
            recovery_2.alert_id, incident_id_2,
            "recovery 2 alert_id matches incident 2 alert_id"
        );
        assert_eq!(state, NoActivityState::Active);
    }

    #[test]
    fn no_activity_no_last_seen_fires_immediately() {
        let contract = ctx();
        let eval_ctx = contract;
        let rule = AlertRule::NoActivity { minutes: 5 };
        let mut state = NoActivityState::default();

        // No transactions ever seen — treated as infinite quiet period.
        let now = ts(12, 0);
        let payload = check_no_activity(&rule, 0, None, now, &mut state, &eval_ctx);

        assert!(
            payload.is_some(),
            "should fire when no transactions ever seen"
        );
        assert!(!payload.unwrap().resolved);
    }
}

// ── WarningSuppressor tests (#60) ─────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod suppressor_tests {
    use super::*;
    use txwatch_config::RuleEntry;

    #[test]
    fn first_warning_is_always_emitted() {
        let s = WarningSuppressor::default();
        assert!(s.should_warn("contract:rule"), "first occurrence must warn");
    }

    #[test]
    fn second_through_99th_are_suppressed() {
        let s = WarningSuppressor::default();
        s.should_warn("k"); // first — emitted
        for _ in 2..100 {
            assert!(!s.should_warn("k"), "occurrences 2-99 must be suppressed");
        }
    }

    #[test]
    fn hundredth_occurrence_is_emitted() {
        let s = WarningSuppressor::default();
        for _ in 0..99 {
            s.should_warn("k");
        }
        assert!(s.should_warn("k"), "100th occurrence must be emitted");
    }

    #[test]
    fn different_keys_are_independent() {
        let s = WarningSuppressor::default();
        assert!(s.should_warn("a"));
        assert!(s.should_warn("b"));
    }

    #[test]
    fn suppressed_count_tracks_calls() {
        let s = WarningSuppressor::default();
        s.should_warn("x");
        s.should_warn("x");
        s.should_warn("x");
        assert_eq!(s.suppressed_count("x"), 3);
    }

    #[test]
    fn alert_id_is_deterministic_and_distinguishes_inputs() {
        let id = alert_id("testnet", "CA", "tx1", "AnyTransaction", "AnyTransaction", 0);
        assert_eq!(
            id,
            alert_id("testnet", "CA", "tx1", "AnyTransaction", "AnyTransaction", 0)
        );
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(id, alert_id("testnet", "CA", "tx2", "AnyTransaction", "AnyTransaction", 0));
        assert_ne!(id, alert_id("testnet", "CA", "tx1", "TransactionFailed", "TransactionFailed", 0));
        assert_ne!(id, alert_id("mainnet", "CA", "tx1", "AnyTransaction", "AnyTransaction", 0));
        assert_ne!(id, alert_id("testnet", "CA", "tx1", "LargeTransfer", "AnyTransaction", 0));
        assert_ne!(id, alert_id("testnet", "CA", "tx1", "AnyTransaction", "AnyTransaction", 1));
        assert_ne!(
            alert_id("testnet", "ab", "c", "r", "r", 0),
            alert_id("testnet", "a", "bc", "r", "r", 0)
        );
    }

    /// Two rules with identical labels on one contract (e.g. two
    /// `LargeTransfer(>=100XLM)` rules routed to different webhooks) must get
    /// distinct `alert_id`s, otherwise receivers deduplicate one of them away
    /// (#252).
    #[test]
    fn identical_rules_on_one_contract_do_not_collide() {
        let tx = EnrichedTransaction {
            hash: "deadbeef".into(),
            timestamp: "2024-01-15T12:00:00Z".parse().unwrap(),
            successful: true,
            paging_token: "1".into(),
            function_names: vec![],
            amount_stroops: Some(500_000_000_000),
            fee_charged_stroops: None,
            source_account: None,
            fee_account: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
            watched_contract_id: "CAAA".into(),
            events: vec![],
            contract_transfers: vec![ContractTransfer {
                from: "CAAA".into(),
                to: "GBUYER".into(),
                amount_stroops: 500_000_000_000,
            }],
            wasm_upgrade: None,
            enrichment_incomplete: false,
        };
        let ctx = EvalContext {
            label: "L",
            contract_id: "CAAA",
            network: "testnet",
            network_id: "testnet".into(),
            horizon_base: "https://h",
            explorer_base: Some("https://e"),
        };
        let same_rule = || AlertRule::LargeTransfer {
            threshold_xlm: 100,
            direction: "any".into(),
            threshold_stroops: 1_000_000_000,
        };
        let payloads = evaluate(&ctx, &[same_rule(), same_rule()], &tx, None);
        assert_eq!(payloads.len(), 2, "both duplicate rules must fire");
        assert_eq!(payloads[0].rule_triggered, payloads[1].rule_triggered);
        assert_eq!(payloads[0].alert_id, alert_id(
            "testnet", "CAAA", "deadbeef", "LargeTransfer",
            &payloads[0].rule_triggered, 0,
        ));
        assert_ne!(
            payloads[0].alert_id, payloads[1].alert_id,
            "identical rules at different indexes must not share an alert_id"
        );

        // The same rule on a different network must not collide either.
        let mut other = ctx.clone();
        other.network_id = "mainnet".into();
        let other_payloads = evaluate(&other, &[same_rule()], &tx, None);
        assert_ne!(payloads[0].alert_id, other_payloads[0].alert_id);
    }

    #[test]
    fn evaluate_sets_alert_id_per_rule() {
        let tx = EnrichedTransaction {
            hash: "deadbeef".into(),
            timestamp: "2024-01-15T12:00:00Z".parse().unwrap(),
            successful: false,
            paging_token: "1".into(),
            function_names: vec![],
            invocations: Vec::new(),
            amount_stroops: None,
            fee_charged_stroops: None,
            source_account: None,
            fee_account: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
            watched_contract_id: "CAAA".into(),
            events: vec![],
            contract_transfers: vec![],
            wasm_upgrade: None,
            enrichment_incomplete: false,
        };
        let ctx = EvalContext {
            label: "L",
            contract_id: "CAAA",
            network: "testnet",
            network_id: "testnet".into(),
            horizon_base: "https://h",
            explorer_base: Some("https://e"),
        };
        let payloads = evaluate(
            &ctx,
            &[AlertRule::AnyTransaction, AlertRule::TransactionFailed],
            &tx,
            None,
        );
        assert_eq!(payloads.len(), 2);
        assert_eq!(
            payloads[0].alert_id,
            alert_id(
                "testnet",
                "CAAA",
                "deadbeef",
                "AnyTransaction",
                "AnyTransaction",
                0,
            )
        );
        assert_ne!(payloads[0].alert_id, payloads[1].alert_id);
    }

    // ── Issue #48: MAX_XLM_SUPPLY_STROOPS sanity check ────────────────────────

    fn raw_tx(fee_charged: Option<&str>) -> HorizonTransaction {
        HorizonTransaction {
            hash: "h1".into(),
            created_at: "2024-06-01T00:00:00Z".into(),
            successful: true,
            paging_token: "1".into(),
            fee_charged: fee_charged.map(Into::into),
            envelope_xdr: None,
            result_xdr: None,
            source_account: None,
            fee_account: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
        }
    }

    #[test]
    fn from_horizon_discards_amount_above_total_supply() {
        let enriched = EnrichedTransaction::from_horizon(
            raw_tx(None),
            vec![],
            Some(MAX_XLM_SUPPLY_STROOPS + 1),
            None,
        )
        .unwrap();
        assert_eq!(enriched.amount_stroops, None);
    }

    #[test]
    fn from_horizon_keeps_amount_at_total_supply() {
        let enriched = EnrichedTransaction::from_horizon(
            raw_tx(None),
            vec![],
            Some(MAX_XLM_SUPPLY_STROOPS),
            None,
        )
        .unwrap();
        assert_eq!(enriched.amount_stroops, Some(MAX_XLM_SUPPLY_STROOPS));
    }

    #[test]
    fn from_horizon_discards_fee_above_total_supply() {
        let fee = (MAX_XLM_SUPPLY_STROOPS + 1).to_string();
        let enriched =
            EnrichedTransaction::from_horizon(raw_tx(Some(&fee)), vec![], None, None).unwrap();
        assert_eq!(enriched.fee_charged_stroops, None);
    }

    // ── Issue #50: EventEmitted ───────────────────────────────────────────────

    fn make_tx(
        successful: bool,
        function_names: &[&str],
        amount: Option<u64>,
    ) -> EnrichedTransaction {
        let function_names: Vec<String> = function_names.iter().map(|s| s.to_string()).collect();
        EnrichedTransaction {
            hash: "abc123".into(),
            timestamp: "2024-01-15T12:00:00Z".parse().unwrap(),
            successful,
            paging_token: "100".into(),
            function_names: function_names.iter().map(|s| s.to_string()).collect(),
            invocations: Vec::new(),
            amount_stroops: amount,
            fee_charged_stroops: None,
            source_account: None,
            fee_account: None,
            ledger: None,
            memo: None,
            memo_type: None,
            operation_count: None,
            watched_contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
            events: vec![],
            contract_transfers: vec![],
            wasm_upgrade: None,
            enrichment_incomplete: false,
        }
    }

    fn event(topics: Vec<Value>, data: Value) -> ContractEvent {
        ContractEvent {
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            topics,
            data,
        }
    }

    fn transfer_event() -> ContractEvent {
        event(
            vec![
                serde_json::json!({"symbol": "transfer"}),
                serde_json::json!({"address": "GFROM"}),
                serde_json::json!({"address": "GTO"}),
            ],
            serde_json::json!({"i128": "1000"}),
        )
    }

    fn event_rule(topic: &str, topics: &[&str]) -> AlertRule {
        AlertRule::EventEmitted {
            topic: topic.into(),
            topics: topics.iter().map(|t| t.to_string()).collect(),
            data: vec![],
        }
    }

    fn entry(r: AlertRule) -> RuleEntry {
        RuleEntry {
            enabled: true,
            webhook_url: None,
            webhook_secret: None,
            severity: None,
            rule: r,
        }
    }

    fn run<R: AsRef<AlertRule> + RuleOverrides>(
        rules: &[R],
        tx: &EnrichedTransaction,
    ) -> Vec<AlertPayload> {
        let ctx = EvalContext {
            label: "Label",
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            network: "testnet",
            network_id: "testnet".into(),
            horizon_base: "https://horizon-testnet.stellar.org",
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        };
        evaluate(&ctx, rules, tx, None)
    }

    #[test]
    fn event_emitted_fires_on_first_topic_symbol() {
        let tx = make_tx(true, &[], None).with_events(vec![transfer_event()]);
        let payloads = run(&[event_rule("transfer", &[])], &tx);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].rule_type, "EventEmitted");
        assert_eq!(payloads[0].rule_triggered, "EventEmitted(transfer)");
        assert_eq!(payloads[0].matched_events, vec![transfer_event()]);
    }

    #[test]
    fn event_emitted_does_not_fire_on_other_symbol() {
        let tx = make_tx(true, &[], None).with_events(vec![transfer_event()]);
        assert!(run(&[event_rule("mint", &[])], &tx).is_empty());
    }

    #[test]
    fn event_emitted_does_not_fire_without_events() {
        let tx = make_tx(true, &["transfer"], None);
        assert!(run(&[event_rule("transfer", &[])], &tx).is_empty());
    }

    #[test]
    fn event_emitted_first_topic_matches_any_scalar() {
        // #263: a string topic 0 is now matchable.
        let ev = event(vec![serde_json::json!({"string": "transfer"})], Value::Null);
        let tx = make_tx(true, &[], None).with_events(vec![ev]);
        assert_eq!(run(&[event_rule("transfer", &[])], &tx).len(), 1);
    }

    #[test]
    fn event_emitted_typed_topic_patterns() {
        let tx = make_tx(true, &[], None).with_events(vec![transfer_event()]);
        // Typed address pattern matches the address ScVal.
        assert_eq!(
            run(&[event_rule("transfer", &["address:GFROM"])], &tx).len(),
            1
        );
        // Wrong type does not match.
        assert!(run(&[event_rule("transfer", &["u32:GFROM"])], &tx).is_empty());
        // Typed symbol pattern for topic 0.
        assert_eq!(run(&[event_rule("symbol:transfer", &[])], &tx).len(), 1);
        assert!(run(&[event_rule("string:transfer", &[])], &tx).is_empty());
    }

    #[test]
    fn event_emitted_data_matchers() {
        let tx = make_tx(true, &[], None).with_events(vec![transfer_event()]);
        let rule = |m: DataMatcher| AlertRule::EventEmitted {
            topic: "transfer".into(),
            topics: vec![],
            data: vec![m],
        };
        // i128 data compared as an integer.
        assert_eq!(
            run(
                &[rule(DataMatcher {
                    pointer: String::new(),
                    op: "gte".into(),
                    value: "1000".into(),
                })],
                &tx
            )
            .len(),
            1
        );
        assert!(run(
            &[rule(DataMatcher {
                pointer: String::new(),
                op: "gte".into(),
                value: "1001".into(),
            })],
            &tx
        )
        .is_empty());
        assert_eq!(
            run(
                &[rule(DataMatcher {
                    pointer: String::new(),
                    op: "eq".into(),
                    value: "1000".into(),
                })],
                &tx
            )
            .len(),
            1
        );
    }

    #[test]
    fn data_matcher_pointer_and_integer_compare() {
        let data = serde_json::json!({"amount": {"i128": "10000000000"}});
        assert!(DataMatcher {
            pointer: "/amount".into(),
            op: "gte".into(),
            value: "9999999999".into(),
        }
        .matches(&data));
        assert!(!DataMatcher {
            pointer: "/amount".into(),
            op: "lte".into(),
            value: "9999999999".into(),
        }
        .matches(&data));
        assert!(!DataMatcher {
            pointer: "/missing".into(),
            op: "eq".into(),
            value: "1".into(),
        }
        .matches(&data));
    }

    #[test]
    fn large_transfer_filters_by_contract_and_direction() {
        let mut tx = make_tx(true, &[], None);
        tx.watched_contract_id = "CWATCHED".into();
        tx.contract_transfers = vec![
            ContractTransfer {
                from: "GUNRELATED".into(),
                to: "GOTHER".into(),
                amount_stroops: 1_000_000_000_000,
            },
            ContractTransfer {
                from: "GUSER".into(),
                to: "CWATCHED".into(),
                amount_stroops: 50_000_000,
            },
        ];
        let rule = |direction: &str| {
            entry(AlertRule::LargeTransfer {
                threshold_xlm: 1,
                threshold_stroops: 10_000_000,
                direction: direction.into(),
            })
        };
        // The unrelated 100k XLM transfer must not count.
        assert_eq!(run(&[rule("any")], &tx).len(), 1);
        assert_eq!(run(&[rule("in")], &tx).len(), 1);
        assert!(run(&[rule("out")], &tx).is_empty());
    }

    #[test]
    fn contract_upgraded_fires_and_reports_hashes() {
        let mut tx = make_tx(true, &[], None);
        tx.watched_contract_id = "CWATCHED".into();
        tx.wasm_upgrade = Some(WasmUpgrade {
            contract_id: "CWATCHED".into(),
            old_wasm_hash: Some("aa".into()),
            new_wasm_hash: Some("bb".into()),
        });
        let payloads = run(&[entry(AlertRule::ContractUpgraded)], &tx);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].rule_type, "ContractUpgraded");
        assert_eq!(payloads[0].old_wasm_hash.as_deref(), Some("aa"));
        assert_eq!(payloads[0].new_wasm_hash.as_deref(), Some("bb"));
    }

    #[test]
    fn contract_upgraded_ignores_other_contracts() {
        let mut tx = make_tx(true, &[], None);
        tx.watched_contract_id = "CWATCHED".into();
        tx.wasm_upgrade = Some(WasmUpgrade {
            contract_id: "COTHER".into(),
            old_wasm_hash: None,
            new_wasm_hash: Some("bb".into()),
        });
        assert!(run(&[entry(AlertRule::ContractUpgraded)], &tx).is_empty());
    }

    #[test]
    fn event_emitted_matches_further_topics_positionally() {
        let tx = make_tx(true, &[], None).with_events(vec![transfer_event()]);
        assert_eq!(run(&[event_rule("transfer", &["GFROM"])], &tx).len(), 1);
        assert_eq!(run(&[event_rule("transfer", &["*", "GTO"])], &tx).len(), 1);
        assert!(run(&[event_rule("transfer", &["GTO"])], &tx).is_empty());
        assert!(run(&[event_rule("transfer", &["*", "*", "GX"])], &tx).is_empty());
    }

    #[test]
    fn event_emitted_wildcard_matches_missing_topic() {
        let tx = make_tx(true, &[], None).with_events(vec![transfer_event()]);
        assert_eq!(
            run(&[event_rule("transfer", &["*", "*", "*"])], &tx).len(),
            1
        );
    }

    #[test]
    fn event_emitted_payload_contains_only_matching_events() {
        let mint = event(
            vec![serde_json::json!({"symbol": "mint"})],
            serde_json::json!({"i128": "5"}),
        );
        let tx = make_tx(true, &[], None).with_events(vec![mint, transfer_event()]);
        let payloads = run(&[event_rule("transfer", &[])], &tx);
        assert_eq!(payloads[0].matched_events, vec![transfer_event()]);
    }

    #[test]
    fn non_event_rules_have_empty_matched_events() {
        let tx = make_tx(true, &[], None).with_events(vec![transfer_event()]);
        let payloads = run(&[AlertRule::AnyTransaction], &tx);
        assert!(payloads[0].matched_events.is_empty());
    }

    #[test]
    fn topic_value_matches_scalars_and_json() {
        assert!(topic_value_matches(&serde_json::json!({"u32": 5}), "5"));
        assert!(topic_value_matches(
            &serde_json::json!({"bool": true}),
            "true"
        ));
        assert!(topic_value_matches(&serde_json::json!("plain"), "plain"));
        let vec_val = serde_json::json!({"vec": [{"u32": 1}]});
        assert!(topic_value_matches(&vec_val, &vec_val.to_string()));
        assert!(!topic_value_matches(&vec_val, "1"));
        // Typed patterns (#263).
        assert!(topic_value_matches(&serde_json::json!({"u32": 5}), "u32:5"));
        assert!(!topic_value_matches(
            &serde_json::json!({"u32": 5}),
            "i32:5"
        ));
        assert!(topic_value_matches(
            &serde_json::json!({"address": "GABC"}),
            "address:GABC"
        ));
    }

    #[test]
    fn event_emitted_label_includes_extra_topics() {
        assert_eq!(
            rule_label(&event_rule("transfer", &["*", "GTO"])),
            "EventEmitted(transfer, *, GTO)"
        );
    }

    // ── Issue #244: EventEmitted nested inside composite rules ─────────────────

    #[test]
    fn event_emitted_nested_in_composite_all_fires_when_both_match() {
        let all_rule = AlertRule::All {
            rules: vec![
                RuleEntry {
                    rule: AlertRule::FunctionCalled {
                        function_name: "deposit".into(),
                        match_mode: FunctionMatchMode::Exact,
                        args: vec![],
                    },
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                },
                RuleEntry {
                    rule: event_rule("transfer", &[]),
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                },
            ],
        };

        // Tx with both function and event: fires
        let matching_tx = make_tx(true, &["deposit"], None).with_events(vec![transfer_event()]);
        let payloads = run(std::slice::from_ref(&all_rule), &matching_tx);
        assert_eq!(
            payloads.len(),
            1,
            "composite All with nested EventEmitted must fire when both match"
        );
        assert_eq!(payloads[0].matched_events.len(), 1);

        // Tx with function only (no event): does not fire
        let no_event_tx = make_tx(true, &["deposit"], None);
        let payloads = run(std::slice::from_ref(&all_rule), &no_event_tx);
        assert!(
            payloads.is_empty(),
            "composite All must not fire when nested EventEmitted has no events"
        );

        // Tx with event only (no matching function): does not fire
        let no_fn_tx = make_tx(true, &["withdraw"], None).with_events(vec![transfer_event()]);
        let payloads = run(&[all_rule], &no_fn_tx);
        assert!(
            payloads.is_empty(),
            "composite All must not fire when function does not match"
        );
    }

    #[test]
    fn event_emitted_nested_in_composite_any_and_not() {
        let any_rule = AlertRule::Any {
            rules: vec![
                RuleEntry {
                    rule: AlertRule::TransactionFailed,
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                },
                RuleEntry {
                    rule: event_rule("transfer", &[]),
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                },
            ],
        };

        // Successful tx with transfer event fires Any
        let tx = make_tx(true, &[], None).with_events(vec![transfer_event()]);
        let payloads = run(&[any_rule], &tx);
        assert_eq!(payloads.len(), 1);

        let not_rule = AlertRule::Not {
            rule: Box::new(RuleEntry {
                rule: event_rule("transfer", &[]),
                enabled: true,
                webhook_url: None,
                webhook_secret: None,
                severity: None,
            }),
        };

        // Tx without transfer event fires Not
        let no_event_tx = make_tx(true, &[], None);
        let payloads = run(std::slice::from_ref(&not_rule), &no_event_tx);
        assert_eq!(payloads.len(), 1);

        // Tx with transfer event does not fire Not
        let payloads = run(&[not_rule], &tx);
        assert!(payloads.is_empty());
    }

    #[test]
    fn contract_upgraded_label_is_stable() {
        assert_eq!(rule_label(&AlertRule::ContractUpgraded), "ContractUpgraded");
    }

    // ── Issue #49: cooldowns ──────────────────────────────────────────────────

    /// A clock the test advances by hand.
    struct TestClock(DateTime<Utc>);

    impl TestClock {
        fn start() -> Self {
            Self("2024-01-15T12:00:00Z".parse().unwrap())
        }
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
        fn advance(&mut self, secs: i64) {
            self.0 += chrono::TimeDelta::seconds(secs);
        }
    }

    fn with_cooldown(rule: AlertRule, cooldown: u64) -> RuleConfig {
        RuleConfig {
            rule,
            cooldown_seconds: Some(cooldown),
            cooldown_summary: false,
        }
    }

    fn fire(
        tracker: &mut CooldownTracker,
        rules: &[RuleConfig],
        clock: &TestClock,
    ) -> Vec<AlertPayload> {
        let tx = make_tx(false, &[], None);
        let plain: Vec<AlertRule> = rules.iter().map(|r| r.rule.clone()).collect();
        tracker.apply(rules, run(&plain, &tx), clock.now())
    }

    #[test]
    fn cooldown_suppresses_within_window_and_reports_count() {
        let rules = vec![with_cooldown(AlertRule::AnyTransaction, 60)];
        let mut tracker = CooldownTracker::new();
        let mut clock = TestClock::start();

        let first = fire(&mut tracker, &rules, &clock);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].suppressed_count, 0);

        for _ in 0..3 {
            clock.advance(10);
            assert!(fire(&mut tracker, &rules, &clock).is_empty());
        }

        clock.advance(30); // 60s after the first alert
        let next = fire(&mut tracker, &rules, &clock);
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].suppressed_count, 3);

        clock.advance(60);
        let after = fire(&mut tracker, &rules, &clock);
        assert_eq!(after[0].suppressed_count, 0, "count resets after firing");
    }

    #[test]
    fn no_cooldown_passes_everything_through() {
        let rules: Vec<RuleConfig> = vec![AlertRule::AnyTransaction.into()];
        let mut tracker = CooldownTracker::new();
        let clock = TestClock::start();
        for _ in 0..5 {
            let out = fire(&mut tracker, &rules, &clock);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].suppressed_count, 0);
        }
    }

    #[test]
    fn zero_cooldown_is_disabled() {
        let rules = vec![with_cooldown(AlertRule::AnyTransaction, 0)];
        let mut tracker = CooldownTracker::new();
        let clock = TestClock::start();
        assert_eq!(fire(&mut tracker, &rules, &clock).len(), 1);
        assert_eq!(fire(&mut tracker, &rules, &clock).len(), 1);
    }

    #[test]
    fn cooldown_is_tracked_per_rule() {
        let rules = vec![
            with_cooldown(AlertRule::AnyTransaction, 60),
            AlertRule::TransactionFailed.into(),
        ];
        let mut tracker = CooldownTracker::new();
        let mut clock = TestClock::start();
        assert_eq!(fire(&mut tracker, &rules, &clock).len(), 2);
        clock.advance(1);
        let second = fire(&mut tracker, &rules, &clock);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].rule_type, "TransactionFailed");
    }

    #[test]
    fn cooldown_is_tracked_per_contract() {
        let mut tracker = CooldownTracker::new();
        let now = TestClock::start().now();
        assert_eq!(tracker.check("CA", "AnyTransaction", 60, now), Some(0));
        assert_eq!(tracker.check("CB", "AnyTransaction", 60, now), Some(0));
        assert_eq!(tracker.check("CA", "AnyTransaction", 60, now), None);
    }

    fn ctx() -> EvalContext<'static> {
        EvalContext {
            label: "Oracle",
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            network: "testnet",
            network_id: "testnet".into(),
            horizon_base: "https://horizon-testnet.stellar.org",
            explorer_base: Some("https://stellar.expert/explorer/testnet"),
        }
    }

    #[test]
    fn cooldown_summary_emitted_when_window_expires_with_suppressed_matches() {
        let rule_cfg = RuleConfig {
            rule: AlertRule::AnyTransaction,
            cooldown_seconds: Some(60),
            cooldown_summary: true,
        };
        let rules = vec![rule_cfg];
        let mut tracker = CooldownTracker::new();
        let mut clock = TestClock::start();
        let contract = ctx();
        let eval_ctx = contract;

        // 1. Initial fire
        let first = fire(&mut tracker, &rules, &clock);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].suppressed_count, 0);

        // 2. Burst of 5 suppressed matches inside the window
        for _ in 0..5 {
            clock.advance(5);
            assert!(fire(&mut tracker, &rules, &clock).is_empty());
        }

        // Before window expires, check_summaries returns empty
        assert!(tracker
            .check_summaries(&rules, &eval_ctx, clock.now())
            .is_empty());

        // 3. Advance clock past the cooldown window (total 65s > 60s)
        clock.advance(40);

        // Burst ended, no new transactions. check_summaries should emit a summary alert!
        let summaries = tracker.check_summaries(&rules, &eval_ctx, clock.now());
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s.rule_type, "AnyTransaction");
        assert_eq!(s.suppressed_count, 5);
        assert!(
            s.transaction_hash.is_empty(),
            "summary alert has no transaction"
        );
        assert!(!s.resolved);

        // Calling check_summaries again without new suppressed matches should return empty
        assert!(tracker
            .check_summaries(&rules, &eval_ctx, clock.now())
            .is_empty());
    }

    #[test]
    fn cooldown_summary_not_emitted_when_opted_out() {
        let rule_cfg = RuleConfig {
            rule: AlertRule::AnyTransaction,
            cooldown_seconds: Some(60),
            cooldown_summary: false,
        };
        let rules = vec![rule_cfg];
        let mut tracker = CooldownTracker::new();
        let mut clock = TestClock::start();
        let contract = ctx();
        let eval_ctx = contract;

        let first = fire(&mut tracker, &rules, &clock);
        assert_eq!(first.len(), 1);

        clock.advance(10);
        assert!(fire(&mut tracker, &rules, &clock).is_empty());

        clock.advance(60);
        assert!(tracker
            .check_summaries(&rules, &eval_ctx, clock.now())
            .is_empty());
    }
}
