#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use anyhow::{anyhow, bail, Context, Result};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, fmt, fs, path::Path};
use url::Url;

const MAX_LARGE_TRANSFER_THRESHOLD_XLM: u64 = 1_000_000_000;

/// Upper bound for a rule's `cooldown_seconds` (one week).
const MAX_COOLDOWN_SECONDS: u64 = 7 * 24 * 3600;

/// Wildcard accepted in `EventEmitted.topics` to match any value at that position.
pub const EVENT_TOPIC_WILDCARD: &str = "*";

/// Soroban function names are symbols: at most 32 characters from `[a-zA-Z0-9_]`.
const MAX_SOROBAN_SYMBOL_LEN: usize = 32;

/// Maximum length of a contract label, in characters.
pub const MAX_LABEL_LEN: usize = 128;

pub const DEFAULT_POLL_INTERVAL_SECONDS: u64 = 10;
const MIN_POLL_INTERVAL_SECONDS: u64 = 5;
const MAX_POLL_INTERVAL_SECONDS: u64 = 3600;

pub const DEFAULT_HTTP_POOL_MAX_IDLE_PER_HOST: usize = 10;
const MAX_HTTP_POOL_MAX_IDLE_PER_HOST: usize = 100;
pub const DEFAULT_HTTP_TCP_KEEPALIVE_SECS: u64 = 30;
const MAX_HTTP_TCP_KEEPALIVE_SECS: u64 = 7200;

/// Rejects names that can never match a Soroban function: blank, longer than
/// 32 characters, or containing anything outside `[a-zA-Z0-9_]`.
fn validate_function_name(name: &str, rule: &str, contract_label: &str) -> Result<()> {
    if !is_soroban_symbol(name) {
        bail!(
            "contract '{}': {} function name {:?} is not a valid Soroban symbol \
             (at most {} characters from [a-zA-Z0-9_])",
            contract_label,
            rule,
            name,
            MAX_SOROBAN_SYMBOL_LEN
        );
    }
    Ok(())
}

/// At most 32 characters from `[a-zA-Z0-9_]`.
fn is_soroban_symbol(name: &str) -> bool {
    name.len() <= MAX_SOROBAN_SYMBOL_LEN
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_poll_interval(value: u64, field: &str) -> Result<()> {
    if value < MIN_POLL_INTERVAL_SECONDS {
        bail!("{} must be >= {}", field, MIN_POLL_INTERVAL_SECONDS);
    }
    if value > MAX_POLL_INTERVAL_SECONDS {
        bail!(
            "{} must be <= {} (1 hour)",
            field,
            MAX_POLL_INTERVAL_SECONDS
        );
    }
    Ok(())
}

// ── Network ───────────────────────────────────────────────────────────────────

/// The Stellar network a contract lives on: one of the public networks by name
/// (`network = "testnet"`), or a custom / local network such as
/// `stellar/quickstart --local` given as an inline table
/// (`network = { horizon_url = "http://localhost:8000" }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Futurenet,
    Custom(CustomNetwork),
}

/// A standalone or private network reached through its own Horizon instance.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustomNetwork {
    /// Horizon base URL, e.g. `http://localhost:8000` for stellar/quickstart.
    pub horizon_url: String,
    /// Optional block-explorer base URL; transaction links are `<explorer_url>/tx/<hash>`.
    #[serde(default)]
    pub explorer_url: Option<String>,
    /// Optional network passphrase, e.g. `Standalone Network ; February 2017`.
    #[serde(default)]
    pub passphrase: Option<String>,
    /// Optional Soroban RPC URL, e.g. `http://localhost:8000/rpc` for stellar/quickstart.
    /// Used to fetch contract events for `EventEmitted` rules.
    #[serde(default)]
    pub rpc_url: Option<String>,
}

const NAMED_NETWORKS: &[&str] = &["mainnet", "testnet", "futurenet"];

impl<'de> Deserialize<'de> for Network {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NetworkVisitor;

        impl<'de> serde::de::Visitor<'de> for NetworkVisitor {
            type Value = Network;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("`mainnet`, `testnet`, `futurenet` or a { horizon_url = \"…\" } table")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Network, E> {
                match value {
                    "mainnet" => Ok(Network::Mainnet),
                    "testnet" => Ok(Network::Testnet),
                    "futurenet" => Ok(Network::Futurenet),
                    other => Err(E::unknown_variant(other, NAMED_NETWORKS)),
                }
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Network, A::Error> {
                CustomNetwork::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(Network::Custom)
            }
        }

        deserializer.deserialize_any(NetworkVisitor)
    }
}

impl Serialize for Network {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Network::Custom(custom) => custom.serialize(serializer),
            named => serializer.serialize_str(named.as_str()),
        }
    }
}

/// A public Stellar network name, or a custom network table with `horizon_url`.
#[derive(JsonSchema)]
#[serde(untagged)]
#[allow(dead_code)]
enum NetworkSchema {
    Named(NamedNetworkSchema),
    Custom(CustomNetwork),
}

#[derive(JsonSchema)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
enum NamedNetworkSchema {
    Mainnet,
    Testnet,
    Futurenet,
}

impl JsonSchema for Network {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Network".into()
    }

    fn json_schema(gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        NetworkSchema::json_schema(gen)
    }
}

impl Network {
    pub fn horizon_base_url(&self) -> &str {
        match self {
            Network::Mainnet => "https://horizon.stellar.org",
            Network::Testnet => "https://horizon-testnet.stellar.org",
            Network::Futurenet => "https://horizon-futurenet.stellar.org",
            Network::Custom(custom) => &custom.horizon_url,
        }
    }

    /// Default Soroban RPC URL for this network. SDF runs public endpoints for
    /// testnet and futurenet only, so mainnet (and a custom network without
    /// `rpc_url`) returns `None` and needs an explicit `soroban_rpc_url`.
    pub fn soroban_rpc_url(&self) -> Option<&str> {
        match self {
            Network::Mainnet => None,
            Network::Testnet => Some("https://soroban-testnet.stellar.org"),
            Network::Futurenet => Some("https://rpc-futurenet.stellar.org"),
            Network::Custom(custom) => custom.rpc_url.as_deref(),
        }
    }

    /// Network name used in logs and the `network` field of alert payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Futurenet => "futurenet",
            Network::Custom(_) => "custom",
        }
    }

    /// Identity of this network for keying per-network state such as poll
    /// cursors. Named networks use their name; custom networks are told apart
    /// by their Horizon URL, so two different private networks never collide.
    pub fn cursor_id(&self) -> String {
        match self {
            Network::Custom(custom) => {
                format!("custom@{}", custom.horizon_url.trim_end_matches('/'))
            }
            named => named.as_str().to_owned(),
        }
    }

    /// Human-readable display name shown in logs and CLI output.
    pub fn display_name(&self) -> &'static str {
        match self {
            Network::Mainnet => "Stellar Mainnet",
            Network::Testnet => "Stellar Testnet",
            Network::Futurenet => "Stellar Futurenet",
            Network::Custom(_) => "Custom Network",
        }
    }

    /// Explorer base URL for this network (Stellar Expert for the public
    /// networks); `None` for a custom network without `explorer_url`.
    pub fn explorer_base_url(&self) -> Option<&str> {
        match self {
            Network::Mainnet => Some("https://stellar.expert/explorer/public"),
            Network::Testnet => Some("https://stellar.expert/explorer/testnet"),
            Network::Futurenet => Some("https://stellar.expert/explorer/futurenet"),
            Network::Custom(custom) => custom.explorer_url.as_deref(),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── AlertRule ─────────────────────────────────────────────────────────────────

/// Maximum nesting depth for composite rules (All / Any / Not).
pub const MAX_COMPOSITE_DEPTH: usize = 5;

/// Allowed severity levels for alert rules.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => f.write_str("info"),
            Severity::Warning => f.write_str("warning"),
            Severity::Critical => f.write_str("critical"),
        }
    }
}

/// A validated Stellar G-address (56 chars, starts with 'G').
fn validate_stellar_address(addr: &str, field: &str, contract_label: &str) -> Result<()> {
    if addr.len() != 56
        || !addr.starts_with('G')
        || !addr.chars().all(|c| c.is_ascii_alphanumeric())
    {
        bail!(
            "contract '{}': {} '{}' is not a valid Stellar account address \
             (must start with 'G' and be 56 alphanumeric characters)",
            contract_label,
            field,
            addr
        );
    }
    Ok(())
}

/// Match mode for the `FunctionCalled` rule (issue #55).
///
/// - `Exact`  — the invoked name must equal `function_name` exactly (default, pre-existing behaviour).
/// - `Prefix` — the invoked name must start with `function_name`.
/// - `Glob`   — the invoked name must match the glob pattern in `function_name`
///   (`*` matches any sequence of characters, `?` matches exactly one character).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FunctionMatchMode {
    #[default]
    Exact,
    Prefix,
    Glob,
}

/// Unknown keys in a rule table are rejected (e.g. `threshold_xml` on a
/// `HighFee` rule, or `function_name` on an `AnyTransaction` rule).
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum AlertRule {
    AnyTransaction,
    TransactionFailed,
    LargeTransfer {
        threshold_xlm: u64,
        /// Pre-computed stroops value set during validation (`threshold_xlm * 10_000_000`).
        /// Skipped in serialisation so it does not appear in TOML or JSON config output.
        #[serde(skip)]
        #[schemars(skip)]
        threshold_stroops: u64,
    },
    FunctionCalled {
        function_name: String,
        /// How `function_name` is matched against the invoked Soroban function.
        /// Defaults to `"exact"` for backward compatibility.
        #[serde(default)]
        #[schemars(default)]
        match_mode: FunctionMatchMode,
    },
    AdminFunctionCalled {
        function_names: Vec<String>,
    },
    /// Fires when the transaction's fee is greater than or equal to the threshold.
    /// Specify either `threshold_stroops` (raw stroops) or `threshold_xlm` (whole XLM,
    /// converted to stroops during validation); the two are mutually exclusive.
    HighFee {
        #[serde(default)]
        threshold_stroops: u64,
        #[serde(default)]
        threshold_xlm: Option<u64>,
    },
    /// Fires when the transaction source account is in (or not in) a list of G-addresses.
    SourceAccount {
        /// If set, only fire when `source_account` is one of these addresses.
        #[serde(default)]
        allow: Vec<String>,
        /// If set, fire when `source_account` is one of these addresses.
        #[serde(default)]
        deny: Vec<String>,
    },
    /// Fires when **all** nested rules match.
    All {
        rules: Vec<RuleEntry>,
    },
    /// Fires when **any** nested rule matches.
    Any {
        rules: Vec<RuleEntry>,
    },
    /// Fires when the nested rule does **not** match.
    Not {
        rule: Box<RuleEntry>,
    },
    /// Fires once when a contract has produced no transactions for longer than
    /// `minutes` minutes, and again (with `resolved = true`) when activity
    /// resumes.  Evaluated per poll cycle, not per transaction.
    NoActivity {
        minutes: u32,
    },
    /// Fires when the transaction emitted a Soroban contract event whose first
    /// topic is the symbol `topic` (e.g. `transfer`, `mint`, `admin_changed`).
    /// `topics` optionally constrains the following topics positionally
    /// (`topics[0]` matches event topic 1, and so on); `"*"` matches anything.
    EventEmitted {
        topic: String,
        #[serde(default)]
        topics: Vec<String>,
    },
}

/// A rule entry with optional per-rule overrides.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RuleEntry {
    /// Set `enabled = false` to silence a rule without removing it.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Override the webhook URL for this rule (falls back to the contract's URL).
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Override the webhook secret for this rule.
    #[serde(default)]
    pub webhook_secret: Option<String>,
    /// Optional severity level included in the alert payload.
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(flatten)]
    pub rule: AlertRule,
}

/// Deserialization mirror of [`AlertRule`]. serde ignores extra keys on unit
/// variants of an internally tagged enum even with `deny_unknown_fields`, so
/// every variant here is a struct variant and unknown keys are rejected.
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum AlertRuleRepr {
    AnyTransaction {},
    TransactionFailed {},
    LargeTransfer {
        threshold_xlm: u64,
    },
    FunctionCalled {
        function_name: String,
    },
    AdminFunctionCalled {
        function_names: Vec<String>,
    },
    HighFee {
        #[serde(default)]
        threshold_stroops: u64,
        #[serde(default)]
        threshold_xlm: Option<u64>,
    },
    SourceAccount {
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        deny: Vec<String>,
    },
    All {
        rules: Vec<RuleEntry>,
    },
    Any {
        rules: Vec<RuleEntry>,
    },
    Not {
        rule: Box<RuleEntry>,
    },
    NoActivity {
        minutes: u32,
    },
    EventEmitted {
        topic: String,
        #[serde(default)]
        topics: Vec<String>,
    },
}

impl<'de> Deserialize<'de> for AlertRule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match AlertRuleRepr::deserialize(deserializer)? {
            AlertRuleRepr::AnyTransaction {} => AlertRule::AnyTransaction,
            AlertRuleRepr::TransactionFailed {} => AlertRule::TransactionFailed,
            AlertRuleRepr::LargeTransfer { threshold_xlm } => AlertRule::LargeTransfer {
                threshold_xlm,
                // Filled in by `validate`.
                threshold_stroops: 0,
            },
            AlertRuleRepr::FunctionCalled { function_name } => AlertRule::FunctionCalled {
                function_name,
                match_mode: FunctionMatchMode::default(),
            },
            AlertRuleRepr::AdminFunctionCalled { function_names } => {
                AlertRule::AdminFunctionCalled { function_names }
            }
            AlertRuleRepr::HighFee {
                threshold_stroops,
                threshold_xlm,
            } => AlertRule::HighFee {
                threshold_stroops,
                threshold_xlm,
            },
            AlertRuleRepr::SourceAccount { allow, deny } => {
                AlertRule::SourceAccount { allow, deny }
            }
            AlertRuleRepr::All { rules } => AlertRule::All { rules },
            AlertRuleRepr::Any { rules } => AlertRule::Any { rules },
            AlertRuleRepr::Not { rule } => AlertRule::Not { rule },
            AlertRuleRepr::NoActivity { minutes } => AlertRule::NoActivity { minutes },
            AlertRuleRepr::EventEmitted { topic, topics } => {
                AlertRule::EventEmitted { topic, topics }
            }
        })
    }
}

impl AlertRule {
    pub fn validate(&mut self, contract_label: &str) -> Result<()> {
        self.validate_at_depth(contract_label, 0)
    }

    fn validate_at_depth(&mut self, contract_label: &str, depth: usize) -> Result<()> {
        if depth > MAX_COMPOSITE_DEPTH {
            bail!(
                "contract '{}': composite rule nesting exceeds maximum depth ({})",
                contract_label,
                MAX_COMPOSITE_DEPTH
            );
        }
        match self {
            AlertRule::LargeTransfer {
                threshold_xlm,
                threshold_stroops,
            } => {
                if *threshold_xlm == 0 {
                    bail!(
                        "contract '{}': LargeTransfer threshold_xlm must be > 0",
                        contract_label
                    );
                }
                if *threshold_xlm > MAX_LARGE_TRANSFER_THRESHOLD_XLM {
                    bail!(
                        "contract '{}': LargeTransfer threshold_xlm must be <= {}",
                        contract_label,
                        MAX_LARGE_TRANSFER_THRESHOLD_XLM
                    );
                }
                // Pre-compute once here; the cap above ensures this cannot overflow
                // (1_000_000_000 * 10_000_000 = 10^16, well within u64::MAX).
                *threshold_stroops = threshold_xlm
                    .checked_mul(10_000_000)
                    .expect("LargeTransfer stroop conversion overflow — should have been caught by the cap above");
            }
            AlertRule::FunctionCalled {
                function_name,
                match_mode,
            } => {
                if function_name.trim().is_empty() {
                    bail!(
                        "contract '{}': FunctionCalled function_name must not be empty",
                        contract_label
                    );
                }
                match match_mode {
                    FunctionMatchMode::Exact | FunctionMatchMode::Prefix => {
                        // Exact and prefix must be valid Soroban symbols.
                        validate_function_name(function_name, "FunctionCalled", contract_label)?;
                    }
                    FunctionMatchMode::Glob => {
                        // Glob patterns may contain `*` and `?`; everything else must be a
                        // valid Soroban symbol character.
                        for ch in function_name.chars() {
                            if ch != '*' && ch != '?' && !(ch.is_ascii_alphanumeric() || ch == '_')
                            {
                                bail!(
                                    "contract '{}': FunctionCalled glob pattern {:?} contains \
                                     invalid character {:?} — only [a-zA-Z0-9_*?] are allowed",
                                    contract_label,
                                    function_name,
                                    ch
                                );
                            }
                        }
                        if function_name.len() > 64 {
                            bail!(
                                "contract '{}': FunctionCalled glob pattern must be \
                                 at most 64 characters",
                                contract_label
                            );
                        }
                    }
                }
            }
            AlertRule::AdminFunctionCalled { function_names } => {
                if function_names.is_empty() {
                    bail!(
                        "contract '{}': AdminFunctionCalled function_names must not be empty",
                        contract_label
                    );
                }
                for name in function_names.iter_mut() {
                    if name.trim().is_empty() {
                        bail!(
                            "contract '{}': AdminFunctionCalled contains a blank function name",
                            contract_label
                        );
                    }
                    validate_function_name(name, "AdminFunctionCalled", contract_label)?;
                    *name = name.to_lowercase();
                }
            }
            AlertRule::AnyTransaction | AlertRule::TransactionFailed => {}
            AlertRule::HighFee {
                threshold_stroops,
                threshold_xlm,
            } => match (*threshold_xlm, *threshold_stroops) {
                (Some(_), s) if s > 0 => bail!(
                    "contract '{}': HighFee: specify either threshold_stroops or \
                         threshold_xlm, not both",
                    contract_label
                ),
                (None, 0) => bail!(
                    "contract '{}': HighFee threshold_stroops must be > 0",
                    contract_label
                ),
                (Some(0), _) => bail!(
                    "contract '{}': HighFee threshold_xlm must be > 0",
                    contract_label
                ),
                (Some(xlm), 0) => {
                    *threshold_stroops = xlm.checked_mul(10_000_000).with_context(|| {
                        format!(
                            "contract '{}': HighFee threshold_xlm overflow",
                            contract_label
                        )
                    })?;
                }
                _ => {}
            },
            AlertRule::SourceAccount { allow, deny } => {
                if allow.is_empty() && deny.is_empty() {
                    bail!(
                        "contract '{}': SourceAccount: at least one of 'allow' or 'deny' must be non-empty",
                        contract_label
                    );
                }
                for addr in allow.iter() {
                    validate_stellar_address(addr, "SourceAccount allow entry", contract_label)?;
                }
                for addr in deny.iter() {
                    validate_stellar_address(addr, "SourceAccount deny entry", contract_label)?;
                }
            }
            AlertRule::All { rules } => {
                if rules.is_empty() {
                    bail!(
                        "contract '{}': All: rules list must not be empty",
                        contract_label
                    );
                }
                for entry in rules.iter_mut() {
                    entry.validate_at_depth(contract_label, depth + 1)?;
                }
            }
            AlertRule::Any { rules } => {
                if rules.is_empty() {
                    bail!(
                        "contract '{}': Any: rules list must not be empty",
                        contract_label
                    );
                }
                for entry in rules.iter_mut() {
                    entry.validate_at_depth(contract_label, depth + 1)?;
                }
            }
            AlertRule::Not { rule } => {
                rule.validate_at_depth(contract_label, depth + 1)?;
            }
            AlertRule::NoActivity { minutes } => {
                if *minutes == 0 {
                    bail!(
                        "contract '{}': NoActivity minutes must be > 0",
                        contract_label
                    );
                }
            }
            AlertRule::EventEmitted { topic, topics } => {
                *topic = topic.trim().to_owned();
                if topic.is_empty() {
                    bail!(
                        "contract '{}': EventEmitted topic must not be empty",
                        contract_label
                    );
                }
                if !is_soroban_symbol(topic) {
                    bail!(
                        "contract '{}': EventEmitted topic {:?} is not a valid Soroban symbol \
                         (at most {} characters from [a-zA-Z0-9_])",
                        contract_label,
                        topic,
                        MAX_SOROBAN_SYMBOL_LEN
                    );
                }
                for t in topics.iter_mut() {
                    *t = t.trim().to_owned();
                    if t.is_empty() {
                        bail!(
                            "contract '{}': EventEmitted topics must not contain blank entries \
                             (use \"{}\" to match any value)",
                            contract_label,
                            EVENT_TOPIC_WILDCARD
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Human-readable rule label, e.g. `"LargeTransfer(>=10000XLM)"`.
    /// Used in CLI `validate` output and in the `rule_triggered` webhook field.
    /// True for rules that need the transaction's contract events (fetched from Soroban RPC).
    pub fn needs_events(&self) -> bool {
        matches!(self, AlertRule::EventEmitted { .. })
    }

    pub fn label(&self) -> String {
        match self {
            AlertRule::AnyTransaction => "AnyTransaction".into(),
            AlertRule::TransactionFailed => "TransactionFailed".into(),
            AlertRule::LargeTransfer { threshold_xlm, .. } => {
                format!("LargeTransfer(>={}XLM)", threshold_xlm)
            }
            AlertRule::FunctionCalled {
                function_name,
                match_mode,
            } => match match_mode {
                FunctionMatchMode::Exact => format!("FunctionCalled({})", function_name),
                FunctionMatchMode::Prefix => {
                    format!("FunctionCalled(prefix:{})", function_name)
                }
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
            AlertRule::SourceAccount { allow, deny } => {
                let mut parts = Vec::new();
                if !allow.is_empty() {
                    parts.push(format!("allow=[{}]", allow.join(", ")));
                }
                if !deny.is_empty() {
                    parts.push(format!("deny=[{}]", deny.join(", ")));
                }
                format!("SourceAccount({})", parts.join(", "))
            }
            AlertRule::All { rules } => {
                let inner: Vec<String> = rules.iter().map(|e| e.rule.label()).collect();
                format!("All({})", inner.join(", "))
            }
            AlertRule::Any { rules } => {
                let inner: Vec<String> = rules.iter().map(|e| e.rule.label()).collect();
                format!("Any({})", inner.join(", "))
            }
            AlertRule::Not { rule } => {
                format!("Not({})", rule.rule.label())
            }
            AlertRule::NoActivity { minutes } => format!("NoActivity({}min)", minutes),
            AlertRule::EventEmitted { topic, topics } => event_emitted_label(topic, topics),
        }
    }

    /// Stable machine-readable rule variant name, e.g. `"LargeTransfer"`.
    /// Used in the `rule_type` webhook field for programmatic routing.
    pub fn rule_type(&self) -> &'static str {
        match self {
            AlertRule::AnyTransaction => "AnyTransaction",
            AlertRule::TransactionFailed => "TransactionFailed",
            AlertRule::LargeTransfer { .. } => "LargeTransfer",
            AlertRule::FunctionCalled { .. } => "FunctionCalled",
            AlertRule::AdminFunctionCalled { .. } => "AdminFunctionCalled",
            AlertRule::HighFee { .. } => "HighFee",
            AlertRule::SourceAccount { .. } => "SourceAccount",
            AlertRule::All { .. } => "All",
            AlertRule::Any { .. } => "Any",
            AlertRule::Not { .. } => "Not",
            AlertRule::NoActivity { .. } => "NoActivity",
            AlertRule::EventEmitted { .. } => "EventEmitted",
        }
    }
}

fn default_true() -> bool {
    true
}

impl RuleEntry {
    pub fn validate(&mut self, contract_label: &str) -> Result<()> {
        self.validate_at_depth(contract_label, 0)
    }

    fn validate_at_depth(&mut self, contract_label: &str, depth: usize) -> Result<()> {
        if let Some(url) = &self.webhook_url {
            if let Some(problem) = check_http_url(url) {
                bail!(
                    "contract '{}': rule webhook_url {}",
                    contract_label,
                    problem
                );
            }
        }
        if let Some(secret) = &self.webhook_secret {
            if secret.is_empty() {
                bail!(
                    "contract '{}': rule webhook_secret must not be blank",
                    contract_label
                );
            }
        }
        if self.enabled {
            self.rule.validate_at_depth(contract_label, depth)?;
        }
        Ok(())
    }
}

/// Label for an `EventEmitted` rule, e.g. `EventEmitted(transfer)` or
/// `EventEmitted(transfer, *, GABC…)`.
pub fn event_emitted_label(topic: &str, topics: &[String]) -> String {
    if topics.is_empty() {
        format!("EventEmitted({})", topic)
    } else {
        format!("EventEmitted({}, {})", topic, topics.join(", "))
    }
}

// ── RuleConfig ────────────────────────────────────────────────────────────────

/// One `[[contracts.rules]]` entry: the rule itself plus per-rule delivery
/// settings that apply to every rule type.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RuleConfig {
    #[serde(flatten)]
    pub rule: AlertRule,
    /// Minimum number of seconds between two alerts for this rule on this
    /// contract. Matches inside the window are suppressed and counted; the next
    /// alert that fires reports them in `suppressed_count`. Unset or 0 disables
    /// the cooldown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<u64>,
}

impl RuleConfig {
    pub fn validate(&mut self, contract_label: &str) -> Result<()> {
        self.rule.validate(contract_label)?;
        if let Some(cooldown) = self.cooldown_seconds {
            if cooldown > MAX_COOLDOWN_SECONDS {
                bail!(
                    "contract '{}': {} cooldown_seconds must be <= {}",
                    contract_label,
                    self.rule.label(),
                    MAX_COOLDOWN_SECONDS
                );
            }
        }
        Ok(())
    }

    pub fn label(&self) -> String {
        self.rule.label()
    }
}

impl From<AlertRule> for RuleConfig {
    fn from(rule: AlertRule) -> Self {
        Self {
            rule,
            cooldown_seconds: None,
        }
    }
}

impl AsRef<AlertRule> for AlertRule {
    fn as_ref(&self) -> &AlertRule {
        self
    }
}

impl AsRef<AlertRule> for RuleConfig {
    fn as_ref(&self) -> &AlertRule {
        &self.rule
    }
}

impl AsRef<AlertRule> for RuleEntry {
    fn as_ref(&self) -> &AlertRule {
        &self.rule
    }
}

// ── Webhook destinations ──────────────────────────────────────────────────────

/// Printed in place of secret values (header values, secrets, routing keys).
pub const REDACTED: &str = "<redacted>";

/// Body shape sent to a webhook destination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    /// TxWatch's own alert JSON.
    #[default]
    Txwatch,
    /// Slack incoming webhook (`text` plus Block Kit `blocks`).
    Slack,
    /// Discord webhook (`content` plus one embed).
    Discord,
    /// PagerDuty Events API v2 `trigger` event; requires `routing_key`.
    Pagerduty,
}

impl WebhookFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            WebhookFormat::Txwatch => "txwatch",
            WebhookFormat::Slack => "slack",
            WebhookFormat::Discord => "discord",
            WebhookFormat::Pagerduty => "pagerduty",
        }
    }
}

impl fmt::Display for WebhookFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Extra HTTP headers sent with every POST to a destination, e.g.
/// `{ "Authorization" = "Bearer ${TOKEN}" }`. Values often hold credentials,
/// so `Debug` prints only the header names.
#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct WebhookHeaders(pub BTreeMap<String, String>);

impl WebhookHeaders {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// `Name: <redacted>` pairs, safe to print.
    pub fn redacted(&self) -> Vec<String> {
        self.0
            .keys()
            .map(|k| format!("{}: {}", k, REDACTED))
            .collect()
    }
}

impl fmt::Debug for WebhookHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|k| (k, REDACTED)))
            .finish()
    }
}

/// Headers TxWatch sets itself; a destination may not override them.
fn is_reserved_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "content-type" || name == "content-length" || name.starts_with("x-txwatch-")
}

/// RFC 9110 token: the characters allowed in a header name.
fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Header values may not contain control characters (CR/LF would allow header
/// injection); tabs are allowed.
fn is_header_value(value: &str) -> bool {
    value.chars().all(|c| c == '\t' || !c.is_control())
}

/// One place alerts are delivered to: a `[[contracts.webhooks]]` entry, or
/// the contract's `webhook_*` shorthand.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookDestination {
    /// http(s) URL the alert is POSTed to.
    pub url: String,
    /// Optional secret: sent as `X-TxWatch-Secret` and used for the
    /// `X-TxWatch-Signature` HMAC. Supports `${ENV_VAR}` interpolation.
    #[serde(default)]
    pub secret: Option<String>,
    /// Body shape: `txwatch` (default), `slack`, `discord` or `pagerduty`.
    #[serde(default)]
    pub format: WebhookFormat,
    /// Extra HTTP headers. Values support `${ENV_VAR}` interpolation.
    #[serde(default, skip_serializing_if = "WebhookHeaders::is_empty")]
    pub headers: WebhookHeaders,
    /// PagerDuty integration (routing) key; required for `format = "pagerduty"`.
    /// Supports `${ENV_VAR}` interpolation.
    #[serde(default)]
    pub routing_key: Option<String>,
}

impl fmt::Debug for WebhookDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookDestination")
            .field("url", &self.url)
            .field("secret", &self.secret.as_ref().map(|_| REDACTED))
            .field("format", &self.format)
            .field("headers", &self.headers)
            .field("routing_key", &self.routing_key.as_ref().map(|_| REDACTED))
            .finish()
    }
}

impl WebhookDestination {
    /// Validates a stand-alone destination (e.g. one built from CLI flags).
    pub fn validate(&self) -> Result<()> {
        ValidationErrors::into_result(self.problems(&|name| name.to_owned()))
    }

    /// Every problem with this destination. `field(name)` renders a field's
    /// config path, e.g. `webhook_url` or `webhooks[1].url`. Header values and
    /// secrets never appear in the messages.
    fn problems(&self, field: &dyn Fn(&str) -> String) -> Vec<String> {
        let mut problems = Vec::new();
        if let Some(problem) = check_http_url(&self.url) {
            problems.push(format!("{} {}", field("url"), problem));
        }
        for (name, value) in self.headers.iter() {
            if !is_header_name(name) {
                problems.push(format!(
                    "{} {:?} is not a valid HTTP header name",
                    field("headers"),
                    name
                ));
            } else if is_reserved_header(name) {
                problems.push(format!(
                    "{} {:?} is reserved: Content-Type, Content-Length and X-TxWatch-* \
                     are set by TxWatch",
                    field("headers"),
                    name
                ));
            }
            if !is_header_value(value) {
                problems.push(format!(
                    "{} value of {:?} contains control characters",
                    field("headers"),
                    name
                ));
            }
        }
        let has_routing_key = self
            .routing_key
            .as_deref()
            .is_some_and(|k| !k.trim().is_empty());
        match (self.format, has_routing_key) {
            (WebhookFormat::Pagerduty, false) => problems.push(format!(
                "{} is required when format is \"pagerduty\"",
                field("routing_key")
            )),
            (format, true) if format != WebhookFormat::Pagerduty => problems.push(format!(
                "{} is only used when format is \"pagerduty\"",
                field("routing_key")
            )),
            _ => {}
        }
        problems
    }
}

// ── WatchedContract ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchedContract {
    pub label: String,
    pub contract_id: String,
    pub network: Network,
    pub rules: Vec<RuleConfig>,
    /// Shorthand for a single destination; the `webhook_*` fields below
    /// describe it. Use `webhooks` for more than one destination. Optional when
    /// `webhooks` is non-empty.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Optional secret sent as X-TxWatch-Secret header on every webhook POST.
    ///
    /// `webhook_url`, `webhook_secret`, the custom network fields and
    /// `cursor_file` support `${ENV_VAR}` interpolation anywhere in the value
    /// (e.g. `webhook_url = "https://hooks.example.com/${TOKEN}"`), with
    /// `${VAR:-default}` for a fallback and `$${` for a literal `${`.
    pub webhook_secret: Option<String>,
    /// Body shape for `webhook_url` (default `txwatch`).
    #[serde(default)]
    pub webhook_format: WebhookFormat,
    /// Extra HTTP headers for `webhook_url`, with `${ENV_VAR}` interpolation.
    #[serde(default, skip_serializing_if = "WebhookHeaders::is_empty")]
    pub webhook_headers: WebhookHeaders,
    /// PagerDuty routing key for `webhook_url` when `webhook_format = "pagerduty"`.
    #[serde(default)]
    pub webhook_routing_key: Option<String>,
    /// Additional destinations (`[[contracts.webhooks]]`). Every alert is
    /// delivered to each destination independently.
    #[serde(default)]
    pub webhooks: Vec<WebhookDestination>,
    /// Per-contract polling interval in seconds, overriding the top-level
    /// `poll_interval_seconds`. Same bounds (5–3600).
    #[serde(default)]
    pub poll_interval_seconds: Option<u64>,
    /// Set `enabled = false` to pause monitoring this contract without removing it.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Soroban RPC endpoint used to fetch contract events for `EventEmitted`
    /// rules. Defaults to the network's RPC URL (see [`Network::soroban_rpc_url`]);
    /// required for mainnet, which has no default.
    #[serde(default)]
    pub soroban_rpc_url: Option<String>,
    /// Deliver all alerts from one poll cycle as a single `{"alerts": [...]}`
    /// POST (split into batches of at most 50) instead of one POST per alert.
    /// Default: false.
    #[serde(default)]
    pub batch_alerts: bool,
    /// Override the Horizon base URL; never read from TOML — set programmatically in tests.
    #[serde(skip, default)]
    #[schemars(skip)]
    pub horizon_base_url_override: Option<String>,
}

/// Every problem found while validating a config. Each entry keeps the
/// `contract '<label>': <message>` format; `Display` prints one per line.
#[derive(Debug)]
pub struct ValidationErrors(pub Vec<String>);

impl ValidationErrors {
    fn into_result(errors: Vec<String>) -> Result<()> {
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors).into())
        }
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let [only] = self.0.as_slice() {
            return f.write_str(only);
        }
        write!(f, "{} configuration errors:", self.0.len())?;
        for error in &self.0 {
            write!(f, "\n  - {}", error)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

/// Checks that `value` is an http(s) URL with a host; returns a description
/// of the problem otherwise.
fn check_http_url(value: &str) -> Option<String> {
    match Url::parse(value) {
        Err(e) => Some(format!("'{}' is not a valid URL: {}", value, e)),
        Ok(url) if url.scheme() != "http" && url.scheme() != "https" => {
            Some(format!("'{}' must use http or https scheme", value))
        }
        Ok(url) if url.host().is_none() => Some(format!("'{}' has no host", value)),
        Ok(_) => None,
    }
}

// ── Contract StrKey ───────────────────────────────────────────────────────────

/// Length of a contract StrKey: base32 of 1 version byte + 32 payload bytes +
/// 2 checksum bytes (35 bytes = 280 bits = 56 base32 characters, no padding).
const CONTRACT_STRKEY_LEN: usize = 56;

/// StrKey version byte for contract addresses (`2 << 3`), which encodes to a
/// leading 'C'.
const CONTRACT_STRKEY_VERSION: u8 = 2 << 3;

/// Why a string is not a valid Stellar contract StrKey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractIdError {
    /// Not exactly 56 characters long.
    Length(usize),
    /// Contains a character outside the base32 alphabet `A–Z2–7`
    /// (lowercase letters, `0`, `1`, `8` and `9` are the usual culprits).
    Alphabet { position: usize, found: char },
    /// Decodes, but the version byte is not the contract version ('C…').
    VersionByte(u8),
    /// Decodes, but the CRC16-XModem checksum does not match — usually a
    /// copy-paste or typing error.
    Checksum { expected: u16, found: u16 },
}

impl fmt::Display for ContractIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractIdError::Length(len) => {
                write!(f, "must be {} characters, got {}", CONTRACT_STRKEY_LEN, len)
            }
            ContractIdError::Alphabet { position, found } => write!(
                f,
                "invalid character {:?} at position {} (only A-Z and 2-7 are allowed)",
                found, position
            ),
            ContractIdError::VersionByte(byte) => write!(
                f,
                "wrong version byte 0x{:02x} (contract addresses start with 'C')",
                byte
            ),
            ContractIdError::Checksum { expected, found } => write!(
                f,
                "checksum mismatch (expected 0x{:04x}, found 0x{:04x}); \
                 the address is probably mistyped",
                expected, found
            ),
        }
    }
}

impl std::error::Error for ContractIdError {}

/// CRC16-XModem (poly 0x1021, init 0), as used by StrKey.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Decodes and checks a contract StrKey (`C…`): length, base32 alphabet,
/// version byte and CRC16-XModem checksum. Returns the 32-byte contract hash.
pub fn validate_contract_id(id: &str) -> std::result::Result<[u8; 32], ContractIdError> {
    let len = id.chars().count();
    if len != CONTRACT_STRKEY_LEN {
        return Err(ContractIdError::Length(len));
    }

    let mut bytes = [0u8; 35];
    let mut buffer: u32 = 0;
    let mut bits = 0;
    let mut out = 0;
    for (position, c) in id.chars().enumerate() {
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            found => return Err(ContractIdError::Alphabet { position, found }),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes[out] = (buffer >> bits) as u8;
            out += 1;
        }
    }

    let (body, checksum) = bytes.split_at(33);
    if body[0] != CONTRACT_STRKEY_VERSION {
        return Err(ContractIdError::VersionByte(body[0]));
    }
    let expected = crc16_xmodem(body);
    let found = u16::from_le_bytes([checksum[0], checksum[1]]);
    if expected != found {
        return Err(ContractIdError::Checksum { expected, found });
    }

    let mut payload = [0u8; 32];
    payload.copy_from_slice(&body[1..]);
    Ok(payload)
}

impl WatchedContract {
    /// This contract's poll-cursor key (see [`cursor_key`]).
    pub fn cursor_key(&self) -> String {
        cursor_key(&self.network, &self.contract_id)
    }

    /// Every webhook destination: the `webhook_*` shorthand (when `webhook_url`
    /// is set) followed by the `[[contracts.webhooks]]` entries.
    pub fn destinations(&self) -> Vec<WebhookDestination> {
        let mut destinations = Vec::with_capacity(self.webhooks.len() + 1);
        if let Some(url) = &self.webhook_url {
            destinations.push(WebhookDestination {
                url: url.clone(),
                secret: self.webhook_secret.clone(),
                format: self.webhook_format,
                headers: self.webhook_headers.clone(),
                routing_key: self.webhook_routing_key.clone(),
            });
        }
        destinations.extend(self.webhooks.iter().cloned());
        destinations
    }

    /// The interval this contract is polled at: its own override, or `default`
    /// (the top-level `poll_interval_seconds`).
    pub fn effective_poll_interval(&self, default: u64) -> u64 {
        self.poll_interval_seconds.unwrap_or(default)
    }

    /// The Soroban RPC endpoint for this contract: its own `soroban_rpc_url`,
    /// else the network default.
    pub fn effective_soroban_rpc_url(&self) -> Option<&str> {
        self.soroban_rpc_url
            .as_deref()
            .or_else(|| self.network.soroban_rpc_url())
    }

    /// True when any configured rule needs contract events.
    pub fn needs_events(&self) -> bool {
        self.rules.iter().any(|r| r.rule.needs_events())
    }

    pub fn validate(&mut self) -> Result<()> {
        ValidationErrors::into_result(self.collect_errors())
    }

    /// Runs every contract check and returns all failures instead of stopping
    /// at the first one.
    fn collect_errors(&mut self) -> Vec<String> {
        let mut errors = Vec::new();

        self.label = self.label.trim().to_owned();
        if self.label.is_empty() {
            errors.push("a contract has an empty label".to_owned());
        } else if self.label.chars().any(char::is_control) {
            // Labels end up in log lines and CLI output; `{:?}` escapes the
            // offending characters so the error itself cannot inject them.
            errors.push(format!(
                "contract label {:?} must not contain control characters",
                self.label
            ));
        } else if self.label.chars().count() > MAX_LABEL_LEN {
            errors.push(format!(
                "contract label '{}…' is longer than {} characters",
                self.label.chars().take(32).collect::<String>(),
                MAX_LABEL_LEN
            ));
        }

        if let Some(interval) = self.poll_interval_seconds {
            if let Err(e) = validate_poll_interval(
                interval,
                &format!("contract '{}': poll_interval_seconds", self.label),
            ) {
                errors.push(e.to_string());
            }
        }

        if let Err(e) = validate_contract_id(&self.contract_id) {
            errors.push(format!(
                "contract '{}': contract_id '{}' is not a valid Stellar contract address: {}",
                self.label, self.contract_id, e
            ));
        }

        if self.webhook_url.is_none() {
            let stray: Vec<&str> = [
                ("webhook_secret", self.webhook_secret.is_some()),
                (
                    "webhook_format",
                    self.webhook_format != WebhookFormat::default(),
                ),
                ("webhook_headers", !self.webhook_headers.is_empty()),
                ("webhook_routing_key", self.webhook_routing_key.is_some()),
            ]
            .into_iter()
            .filter_map(|(name, set)| set.then_some(name))
            .collect();
            if !stray.is_empty() {
                errors.push(format!(
                    "contract '{}': {} set without webhook_url (put them in a \
                     [[contracts.webhooks]] entry instead)",
                    self.label,
                    stray.join(", ")
                ));
            }
        }
        let shorthand = usize::from(self.webhook_url.is_some());
        let destinations = self.destinations();
        if destinations.is_empty() {
            errors.push(format!(
                "contract '{}': no webhook destination; set webhook_url or add a \
                 [[contracts.webhooks]] entry",
                self.label
            ));
        }
        for (i, destination) in destinations.iter().enumerate() {
            let field = |name: &str| {
                if i < shorthand {
                    format!("webhook_{}", name)
                } else {
                    format!("webhooks[{}].{}", i - shorthand, name)
                }
            };
            for problem in destination.problems(&field) {
                errors.push(format!("contract '{}': {}", self.label, problem));
            }
        }

        if let Network::Custom(custom) = &mut self.network {
            // Links and request URLs are built as "<base>/...".
            custom.horizon_url = custom.horizon_url.trim_end_matches('/').to_owned();
            if let Some(problem) = check_http_url(&custom.horizon_url) {
                errors.push(format!(
                    "contract '{}': network horizon_url {}",
                    self.label, problem
                ));
            }
            if let Some(explorer_url) = &mut custom.explorer_url {
                *explorer_url = explorer_url.trim_end_matches('/').to_owned();
                if let Some(problem) = check_http_url(explorer_url) {
                    errors.push(format!(
                        "contract '{}': network explorer_url {}",
                        self.label, problem
                    ));
                }
            }
            if let Some(rpc_url) = &mut custom.rpc_url {
                *rpc_url = rpc_url.trim_end_matches('/').to_owned();
                if let Some(problem) = check_http_url(rpc_url) {
                    errors.push(format!(
                        "contract '{}': network rpc_url {}",
                        self.label, problem
                    ));
                }
            }
        }

        if self.rules.is_empty() {
            errors.push(format!(
                "contract '{}': at least one rule is required",
                self.label
            ));
        }

        let label = self.label.clone();
        for rule in &mut self.rules {
            if let Err(e) = rule.validate(&label) {
                errors.push(e.to_string());
            }
        }

        if let Some(rpc_url) = &mut self.soroban_rpc_url {
            *rpc_url = rpc_url.trim_end_matches('/').to_owned();
            if let Some(problem) = check_http_url(rpc_url) {
                errors.push(format!(
                    "contract '{}': soroban_rpc_url {}",
                    self.label, problem
                ));
            }
        }
        if self.needs_events() && self.effective_soroban_rpc_url().is_none() {
            errors.push(format!(
                "contract '{}': EventEmitted rules need a Soroban RPC endpoint; \
                 set soroban_rpc_url (network '{}' has no default)",
                self.label,
                self.network.as_str()
            ));
        }

        errors
    }
}

// ── AppConfig ─────────────────────────────────────────────────────────────────

/// Default maximum number of watched contracts in a single configuration.
/// Every contract is polled by its own task, so an unbounded list could
/// exhaust memory, file descriptors or the Horizon rate limit. Raise it with
/// the top-level `max_contracts` setting.
pub const MAX_CONTRACTS: usize = 100;

/// Upper bound for the `max_contracts` override, for operators running their
/// own Horizon instance.
pub const MAX_CONTRACTS_CEILING: usize = 10_000;

/// Default for `max_pages_per_cycle`: the most Horizon pages (200 transactions
/// each) one poll cycle fetches per contract before yielding. The rest is
/// picked up from the saved cursor on the next cycle.
pub const DEFAULT_MAX_PAGES_PER_CYCLE: usize = 10;

/// Upper bound for the `max_pages_per_cycle` override.
pub const MAX_PAGES_PER_CYCLE_CEILING: usize = 1_000;

/// Key under which a contract's poll cursor is stored, in memory and in
/// `cursor_file`: `<network>:<contract_id>`. Keying by network as well as
/// contract ID keeps a contract deployed at the same address on several
/// networks from sharing one cursor. Keys written before this format existed
/// are the bare contract ID and contain no `:`.
pub fn cursor_key(network: &Network, contract_id: &str) -> String {
    format!("{}:{}", network.cursor_id(), contract_id)
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Default polling interval in seconds for every contract (5–3600).
    /// Default: 10.
    #[serde(default = "default_poll_interval_seconds")]
    pub poll_interval_seconds: u64,
    pub contracts: Vec<WatchedContract>,
    /// Optional path to a JSON file used to persist the cursor map across restarts.
    /// When set, the poller will load cursors from this file on startup and write
    /// the updated cursor map after each poll cycle. If absent, cursors default
    /// to the Horizon keyword `now` and are not persisted.
    #[serde(default)]
    pub cursor_file: Option<String>,
    /// Maximum number of idle connections per host in the HTTP connection pool.
    /// Lower values reduce memory usage; higher values improve throughput for many contracts.
    /// Must be 1–100. Default: 10.
    #[serde(default = "default_http_pool_max_idle_per_host")]
    pub http_pool_max_idle_per_host: usize,
    /// TCP keepalive interval in seconds for idle HTTP connections.
    /// Helps detect stalled connections quickly; 0 disables keepalive.
    /// Must be <= 7200. Default: 30 seconds.
    #[serde(default = "default_http_tcp_keepalive_secs")]
    pub http_tcp_keepalive_secs: u64,
    /// Enable verbose output for HTTP connection pool debug information.
    /// Only useful for troubleshooting connection issues.
    /// Default: false.
    #[serde(default)]
    pub http_connection_verbose: Option<bool>,
    /// Maximum number of `[[contracts]]` entries (1–10000). Default: 100.
    /// Raise it only when the Horizon instance (typically your own) can take
    /// the extra polling load.
    #[serde(default)]
    pub max_contracts: Option<usize>,
    /// Maximum Horizon pages (200 transactions each) fetched per contract in one
    /// poll cycle (1–1000). When the cap is hit the poller logs a warning and
    /// continues from the saved cursor on the next cycle. Default: 10.
    #[serde(default)]
    pub max_pages_per_cycle: Option<usize>,
}

fn default_poll_interval_seconds() -> u64 {
    DEFAULT_POLL_INTERVAL_SECONDS
}

fn default_http_pool_max_idle_per_host() -> usize {
    DEFAULT_HTTP_POOL_MAX_IDLE_PER_HOST
}

fn default_http_tcp_keepalive_secs() -> u64 {
    DEFAULT_HTTP_TCP_KEEPALIVE_SECS
}

fn deserialize_toml_with_field_context<T>(raw: &str, path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    // serde_path_to_error::deserialize owns the Track that Deserializer::new
    // otherwise requires, so the field path survives into the error message.
    let deserializer = toml::Deserializer::new(raw);
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let field_path = error.path().to_string();
        let inner = error.into_inner();
        if field_path.is_empty() {
            anyhow!("{} (in {})", inner, path.display())
        } else {
            anyhow!("{} (field: {} in {})", inner, field_path, path.display())
        }
    })
}

// ── Env-var interpolation ─────────────────────────────────────────────────────

fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Expands environment-variable references anywhere in `value`:
///
/// - `${VAR}` is replaced by the value of `VAR`; an unset variable is an error.
/// - `${VAR:-default}` uses `default` when `VAR` is unset or empty.
/// - `$${` is an escape for a literal `${`.
/// - Any other `$` is kept as is.
///
/// `lookup` resolves a variable name; errors never include resolved values.
fn interpolate(value: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(dollar) = rest.find('$') {
        out.push_str(&rest[..dollar]);
        let after = &rest[dollar..];
        if let Some(tail) = after.strip_prefix("$${") {
            out.push_str("${");
            rest = tail;
        } else if let Some(tail) = after.strip_prefix("${") {
            let end = tail
                .find('}')
                .with_context(|| format!("unterminated '${{' in {:?}", value))?;
            let expr = &tail[..end];
            let (name, default) = match expr.split_once(":-") {
                Some((name, default)) => (name, Some(default)),
                None => (expr, None),
            };
            if name.is_empty() {
                bail!("empty variable name in '${{{}}}'", expr);
            }
            if !is_env_var_name(name) {
                bail!(
                    "invalid variable name {:?} (use letters, digits and '_', \
                     not starting with a digit)",
                    name
                );
            }
            match (lookup(name), default) {
                (Some(resolved), Some(default)) if resolved.is_empty() => out.push_str(default),
                (Some(resolved), _) => out.push_str(&resolved),
                (None, Some(default)) => out.push_str(default),
                (None, None) => bail!("env var '{}' referenced in config is not set", name),
            }
            rest = &tail[end + 1..];
        } else {
            out.push('$');
            rest = &after[1..];
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// [`interpolate`] against the process environment.
fn resolve_env_interpolation(value: &str) -> Result<String> {
    interpolate(value, &|name| env::var(name).ok())
}

/// Interpolates `value` in place, naming `field` (never the value) in errors.
fn resolve_field(value: &mut String, field: &str) -> Result<()> {
    *value = resolve_env_interpolation(value).with_context(|| field.to_owned())?;
    Ok(())
}

/// Interpolates a destination's secret-bearing fields.
fn resolve_destination(
    secret: &mut Option<String>,
    headers: &mut WebhookHeaders,
    routing_key: &mut Option<String>,
    field: &dyn Fn(&str) -> String,
) -> Result<()> {
    if let Some(secret) = secret {
        resolve_field(secret, &field("secret"))?;
    }
    for (name, value) in headers.0.iter_mut() {
        resolve_field(value, &format!("{}.{}", field("headers"), name))?;
    }
    if let Some(key) = routing_key {
        resolve_field(key, &field("routing_key"))?;
    }
    Ok(())
}

impl AppConfig {
    /// Expands `${VAR}` references in every string field that may carry a
    /// secret or a deployment-specific value.
    fn resolve_env_vars(&mut self) -> Result<()> {
        if let Some(cursor_file) = &mut self.cursor_file {
            resolve_field(cursor_file, "cursor_file")?;
        }
        for (i, contract) in self.contracts.iter_mut().enumerate() {
            let field = |name: &str| format!("contracts[{}].{}", i, name);
            if let Some(url) = &mut contract.webhook_url {
                resolve_field(url, &field("webhook_url"))?;
            }
            // The shorthand destination's secret, header values and routing key.
            resolve_destination(
                &mut contract.webhook_secret,
                &mut contract.webhook_headers,
                &mut contract.webhook_routing_key,
                &|name| field(&format!("webhook_{name}")),
            )?;
            // Each entry of the `webhooks` array is a destination in its own right.
            for (j, destination) in contract.webhooks.iter_mut().enumerate() {
                resolve_destination(
                    &mut destination.secret,
                    &mut destination.headers,
                    &mut destination.routing_key,
                    &|name| format!("contracts[{}].webhooks[{}].{}", i, j, name),
                )?;
            }
            if let Network::Custom(custom) = &mut contract.network {
                resolve_field(&mut custom.horizon_url, &field("network.horizon_url"))?;
                if let Some(explorer_url) = &mut custom.explorer_url {
                    resolve_field(explorer_url, &field("network.explorer_url"))?;
                }
                if let Some(passphrase) = &mut custom.passphrase {
                    resolve_field(passphrase, &field("network.passphrase"))?;
                }
            }
        }
        Ok(())
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("cannot read config file '{}'", path.display()))?;
        Self::parse(&raw, path)
    }

    /// Parse and validate TOML exactly as [`AppConfig::from_file`] does;
    /// `source` only labels error messages.
    pub fn parse(raw: &str, source: &Path) -> Result<Self> {
        let mut cfg: AppConfig = deserialize_toml_with_field_context(raw, source)
            .with_context(|| format!("failed to parse config file '{}'", source.display()))?;
        cfg.resolve_env_vars()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// The contract limit in force: `max_contracts`, else [`MAX_CONTRACTS`].
    pub fn effective_max_contracts(&self) -> usize {
        self.max_contracts.unwrap_or(MAX_CONTRACTS)
    }

    /// The per-cycle page cap in force: `max_pages_per_cycle`, else
    /// [`DEFAULT_MAX_PAGES_PER_CYCLE`].
    pub fn effective_max_pages_per_cycle(&self) -> usize {
        self.max_pages_per_cycle
            .unwrap_or(DEFAULT_MAX_PAGES_PER_CYCLE)
    }

    /// Validates the whole config and reports every error found, not just the first.
    pub fn validate(&mut self) -> Result<()> {
        let mut errors = Vec::new();

        if let Err(e) = validate_poll_interval(self.poll_interval_seconds, "poll_interval_seconds")
        {
            errors.push(e.to_string());
        }

        if self.http_pool_max_idle_per_host == 0
            || self.http_pool_max_idle_per_host > MAX_HTTP_POOL_MAX_IDLE_PER_HOST
        {
            errors.push(format!(
                "http_pool_max_idle_per_host must be between 1 and {}",
                MAX_HTTP_POOL_MAX_IDLE_PER_HOST
            ));
        }

        if self.http_tcp_keepalive_secs > MAX_HTTP_TCP_KEEPALIVE_SECS {
            errors.push(format!(
                "http_tcp_keepalive_secs must be <= {} (0 disables keepalive)",
                MAX_HTTP_TCP_KEEPALIVE_SECS
            ));
        }

        if let Some(pages) = self.max_pages_per_cycle {
            if pages == 0 || pages > MAX_PAGES_PER_CYCLE_CEILING {
                errors.push(format!(
                    "max_pages_per_cycle must be between 1 and {}",
                    MAX_PAGES_PER_CYCLE_CEILING
                ));
            }
        }

        if self.contracts.is_empty() {
            errors.push("at least one [[contracts]] entry is required".to_owned());
        }

        for contract in &mut self.contracts {
            errors.extend(contract.collect_errors());
        }

        match self.max_contracts {
            Some(max) if max == 0 || max > MAX_CONTRACTS_CEILING => errors.push(format!(
                "max_contracts must be between 1 and {}",
                MAX_CONTRACTS_CEILING
            )),
            _ => {
                let max = self.effective_max_contracts();
                if self.contracts.len() > max {
                    errors.push(format!(
                        "{} contracts configured, more than the limit of {}; each contract is \
                         polled by its own task. Split the config across several TxWatch \
                         instances, or raise max_contracts (up to {}) if your Horizon can \
                         handle the load",
                        self.contracts.len(),
                        max,
                        MAX_CONTRACTS_CEILING
                    ));
                }
            }
        }

        // Labels are already trimmed by `WatchedContract::collect_errors`; compare
        // case-insensitively so "Vault" and "vault" count as duplicates.
        let mut seen_labels = std::collections::HashSet::new();
        let mut reported_labels = std::collections::HashSet::new();
        for contract in &self.contracts {
            let key = contract.label.to_lowercase();
            if !seen_labels.insert(key.clone()) && reported_labels.insert(key) {
        // Labels are already trimmed by `WatchedContract::collect_errors`; compare
        // case-insensitively so "Vault" and "vault" count as duplicates. Report each
        // offending label once even when it appears more than twice.
        let mut seen = std::collections::HashSet::new();
        let mut reported = std::collections::HashSet::new();
        for contract in &self.contracts {
            let key = contract.label.to_lowercase();
            if !seen.insert(key) && reported.insert(contract.label.clone()) {
                errors.push(format!("duplicate contract label '{}'", contract.label));
            }
        }

        // Cursors are keyed by (network, contract_id), so the same contract may
        // be watched on several networks but only once per network.
        let mut seen_keys: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for contract in &self.contracts {
            let key = contract.cursor_key();
            if let Some(first_label) = seen_keys.get(&key).cloned() {
                errors.push(format!(
                    "duplicate contract_id '{}' on network '{}' (labels '{}' and '{}'); each \
                     (network, contract_id) pair can be watched only once",
                    contract.contract_id,
                    contract.network.as_str(),
                    first_label,
                    contract.label
                ));
            } else {
                seen_keys.insert(key, contract.label.clone());
            }
        }

        ValidationErrors::into_result(errors)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn rule(r: AlertRule) -> RuleConfig {
        RuleConfig {
            rule: r,
            cooldown_seconds: None,
        }
    }

    fn valid_contract() -> WatchedContract {
        WatchedContract {
            label: "Test".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
            network: Network::Testnet,
            rules: vec![rule(AlertRule::AnyTransaction)],
            webhook_url: Some("https://example.com/hook".into()),
            webhook_secret: None,
            poll_interval_seconds: None,
            enabled: true,
            soroban_rpc_url: None,
            horizon_base_url_override: None,
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: Vec::new(),
            batch_alerts: false,
        }
    }

    #[test]
    fn valid_config_passes() {
        let mut c = valid_contract();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_short_contract_id() {
        let mut c = valid_contract();
        c.contract_id = "CSHORT".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_non_c_contract_id() {
        let mut c = valid_contract();
        c.contract_id = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_bad_webhook_url() {
        let mut c = valid_contract();
        c.webhook_url = Some("ftp://bad".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_webhook_url_with_no_host() {
        let mut c = valid_contract();
        c.webhook_url = Some("https://".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_webhook_url_with_spaces() {
        let mut c = valid_contract();
        c.webhook_url = Some("https://example .com/hook".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_webhook_url_that_is_not_a_url() {
        let mut c = valid_contract();
        c.webhook_url = Some("not-a-url-at-all".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_webhook_url_with_ftp_scheme() {
        let mut c = valid_contract();
        c.webhook_url = Some("ftp://files.example.com/hook".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_valid_http_webhook_url() {
        let mut c = valid_contract();
        c.webhook_url = Some("http://hooks.example.com/my-webhook".into());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn accepts_valid_https_webhook_url_with_path_and_query() {
        let mut c = valid_contract();
        c.webhook_url = Some("https://hooks.example.com/alerts?token=abc123".into());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_empty_rules() {
        let mut c = valid_contract();
        c.rules = vec![];
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_zero_threshold() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::LargeTransfer {
            threshold_xlm: 0,
            threshold_stroops: 0,
        })];
        assert!(c.validate().is_err());
    }

    /// #43: LargeTransfer::threshold_stroops is pre-computed once during validation.
    #[test]
    fn large_transfer_threshold_normalises_to_stroops() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::LargeTransfer {
            threshold_xlm: 10_000,
            threshold_stroops: 0,
        })];
        c.validate().unwrap();
        if let AlertRule::LargeTransfer {
            threshold_stroops, ..
        } = &c.rules[0].rule
        {
            assert_eq!(
                *threshold_stroops, 100_000_000_000,
                "10_000 XLM should become 100_000_000_000 stroops"
            );
        } else {
            panic!("expected LargeTransfer");
        }
    }

    #[test]
    fn rejects_too_large_large_transfer_threshold() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::LargeTransfer {
            threshold_xlm: MAX_LARGE_TRANSFER_THRESHOLD_XLM + 1,
            threshold_stroops: 0,
        })];
        let err = c.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("LargeTransfer threshold_xlm must be <="));
    }

    #[test]
    fn rejects_empty_function_name() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::FunctionCalled {
            function_name: "  ".into(),
            match_mode: Default::default(),
        })];
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_empty_admin_function_names() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::AdminFunctionCalled {
            function_names: vec![],
        })];
        assert!(c.validate().is_err());
    }

    /// Issue #18: blank entry in function_names should fail validation.
    #[test]
    fn rejects_blank_entry_in_admin_function_names() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::AdminFunctionCalled {
            function_names: vec!["set_admin".into(), " ".into()],
        })];
        let err = c.validate().unwrap_err();
        assert!(
            err.to_string().contains("blank"),
            "expected 'blank' in error, got: {}",
            err
        );
    }

    /// Issue #18: single valid entry in function_names should pass validation.
    #[test]
    fn accepts_single_valid_admin_function_name() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::AdminFunctionCalled {
            function_names: vec!["set_admin".into()],
        })];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn admin_function_names_normalised_to_lowercase() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::AdminFunctionCalled {
            function_names: vec!["Set_Admin".into(), "UPGRADE".into()],
        })];
        c.validate().unwrap();
        if let AlertRule::AdminFunctionCalled { function_names } = &c.rules[0].rule {
            assert_eq!(function_names, &["set_admin", "upgrade"]);
        } else {
            panic!("expected AdminFunctionCalled");
        }
    }

    #[test]
    fn network_urls() {
        assert!(Network::Mainnet
            .horizon_base_url()
            .contains("horizon.stellar.org"));
        assert!(Network::Testnet.horizon_base_url().contains("testnet"));
        assert!(Network::Futurenet.horizon_base_url().contains("futurenet"));
    }

    #[test]
    fn network_display_names() {
        assert_eq!(Network::Mainnet.display_name(), "Stellar Mainnet");
        assert_eq!(Network::Testnet.display_name(), "Stellar Testnet");
        assert_eq!(Network::Futurenet.display_name(), "Stellar Futurenet");
    }

    #[test]
    fn network_explorer_urls() {
        assert!(Network::Mainnet
            .explorer_base_url()
            .unwrap()
            .contains("public"));
        assert!(Network::Testnet
            .explorer_base_url()
            .unwrap()
            .contains("testnet"));
    }

    // ── #99: custom / local network ──────────────────────────────────────────

    const CUSTOM_NETWORK_TOML: &str = r#"
        [[contracts]]
        label = "local"
        contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        network = { horizon_url = "http://localhost:8000/", passphrase = "Standalone Network ; February 2017" }
        webhook_url = "https://example.com/hook"
        [[contracts.rules]]
        type = "AnyTransaction"
    "#;

    fn parse_with_interval(contracts_toml: &str) -> AppConfig {
        toml::from_str(&format!("poll_interval_seconds = 10\n{}", contracts_toml)).unwrap()
    }

    #[test]
    fn custom_network_parses_and_validates() {
        let mut cfg = parse_with_interval(CUSTOM_NETWORK_TOML);
        cfg.validate().unwrap();
        let network = &cfg.contracts[0].network;
        assert_eq!(
            network,
            &Network::Custom(CustomNetwork {
                horizon_url: "http://localhost:8000".into(),
                explorer_url: None,
                passphrase: Some("Standalone Network ; February 2017".into()),
                rpc_url: None,
            })
        );
        assert_eq!(network.horizon_base_url(), "http://localhost:8000");
        assert_eq!(network.explorer_base_url(), None);
        assert_eq!(network.as_str(), "custom");
        assert_eq!(network.display_name(), "Custom Network");
    }

    #[test]
    fn custom_network_requires_horizon_url() {
        let raw = CUSTOM_NETWORK_TOML.replace(
            r#"{ horizon_url = "http://localhost:8000/", passphrase"#,
            r#"{ passphrase"#,
        );
        let err = toml::from_str::<AppConfig>(&format!("poll_interval_seconds = 10\n{}", raw))
            .unwrap_err();
        assert!(err.to_string().contains("horizon_url"), "got: {}", err);
    }

    #[test]
    fn custom_network_rejects_invalid_urls() {
        let raw = CUSTOM_NETWORK_TOML.replace(
            r#"horizon_url = "http://localhost:8000/""#,
            r#"horizon_url = "ftp://localhost", explorer_url = "not a url""#,
        );
        let err = parse_with_interval(&raw)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("contract 'local': network horizon_url"),
            "got: {}",
            err
        );
        assert!(
            err.contains("contract 'local': network explorer_url"),
            "got: {}",
            err
        );
    }

    #[test]
    fn unknown_network_name_is_still_rejected_with_variant_list() {
        let raw = CUSTOM_NETWORK_TOML.replace(
            r#"{ horizon_url = "http://localhost:8000/", passphrase = "Standalone Network ; February 2017" }"#,
            r#""main""#,
        );
        let err = toml::from_str::<AppConfig>(&format!("poll_interval_seconds = 10\n{}", raw))
            .unwrap_err();
        assert!(
            err.to_string().contains(
                "unknown variant `main`, expected one of `mainnet`, `testnet`, `futurenet`"
            ),
            "got: {}",
            err
        );
    }

    // ── #101: all validation errors reported together ────────────────────────

    #[test]
    fn validate_reports_all_errors_together() {
        let mut bad_id = valid_contract();
        bad_id.label = "A".into();
        bad_id.contract_id = "CSHORT".into();
        bad_id.webhook_url = Some("ftp://bad".into());
        let mut bad_rule = valid_contract();
        bad_rule.label = "B".into();
        bad_rule.rules = vec![rule(AlertRule::LargeTransfer {
            threshold_xlm: 0,
            threshold_stroops: 0,
        })];
        let mut cfg = AppConfig {
            poll_interval_seconds: 1,
            contracts: vec![bad_id, bad_rule, valid_contract(), valid_contract()],
            http_pool_max_idle_per_host: DEFAULT_HTTP_POOL_MAX_IDLE_PER_HOST,
            http_tcp_keepalive_secs: DEFAULT_HTTP_TCP_KEEPALIVE_SECS,
            http_connection_verbose: None,
            max_contracts: None,
            max_pages_per_cycle: None,
            cursor_file: None,
        };
        let err = cfg.validate().unwrap_err();
        let errors = &err.downcast_ref::<ValidationErrors>().unwrap().0;
        assert_eq!(
            errors,
            &[
                "poll_interval_seconds must be >= 5".to_owned(),
                "contract 'A': contract_id 'CSHORT' is not a valid Stellar contract address: \
                 must be 56 characters, got 6"
                    .to_owned(),
                "contract 'A': webhook_url 'ftp://bad' must use http or https scheme".to_owned(),
                "contract 'B': LargeTransfer threshold_xlm must be > 0".to_owned(),
                "duplicate contract label 'Test'".to_owned(),
            ]
        );
        let text = err.to_string();
        assert!(
            text.starts_with("5 configuration errors:\n  - "),
            "got: {}",
            text
        );
    }

    #[test]
    fn rejects_duplicate_labels() {
        let c = valid_contract();
        let mut cfg = AppConfig {
            poll_interval_seconds: 10,
            contracts: vec![c.clone(), c],
            http_pool_max_idle_per_host: DEFAULT_HTTP_POOL_MAX_IDLE_PER_HOST,
            http_tcp_keepalive_secs: DEFAULT_HTTP_TCP_KEEPALIVE_SECS,
            http_connection_verbose: None,
            max_contracts: None,
            max_pages_per_cycle: None,
            cursor_file: None,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate contract label"));
    }

    #[test]
    fn appconfig_validate_rejects_empty_contracts() {
        let mut cfg = AppConfig {
            poll_interval_seconds: 10,
            contracts: vec![],
            http_pool_max_idle_per_host: DEFAULT_HTTP_POOL_MAX_IDLE_PER_HOST,
            http_tcp_keepalive_secs: DEFAULT_HTTP_TCP_KEEPALIVE_SECS,
            http_connection_verbose: None,
            max_contracts: None,
            max_pages_per_cycle: None,
            cursor_file: None,
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("at least one"),
            "error should mention 'at least one', got: {}",
            err
        );
    }

    #[test]
    fn high_fee_threshold_xlm_normalises_to_stroops() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: Some(1),
        })];
        c.validate().unwrap();
        if let AlertRule::HighFee {
            threshold_stroops, ..
        } = &c.rules[0].rule
        {
            assert_eq!(
                *threshold_stroops, 10_000_000,
                "1 XLM should become 10_000_000 stroops"
            );
        } else {
            panic!("expected HighFee");
        }
    }

    #[test]
    fn high_fee_threshold_xlm_zero_is_rejected() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: Some(0),
        })];
        assert!(c.validate().is_err());
    }

    #[test]
    fn high_fee_both_thresholds_is_rejected() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::HighFee {
            threshold_stroops: 100,
            threshold_xlm: Some(1),
        })];
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("not both"));
    }

    #[test]
    fn high_fee_neither_threshold_is_rejected() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: None,
        })];
        assert!(c.validate().is_err());
    }

    #[test]
    fn no_activity_zero_minutes_is_rejected() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::NoActivity { minutes: 0 })];
        let err = c.validate().unwrap_err().to_string();
        assert!(
            err.contains("NoActivity minutes must be > 0"),
            "got: {}",
            err
        );
    }

    #[test]
    fn no_activity_nonzero_minutes_is_valid() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::NoActivity { minutes: 30 })];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_poll_interval_too_low() {
        for val in 0u64..5 {
            let mut cfg = AppConfig {
                poll_interval_seconds: val,
                contracts: vec![valid_contract()],
                http_pool_max_idle_per_host: DEFAULT_HTTP_POOL_MAX_IDLE_PER_HOST,
                http_tcp_keepalive_secs: DEFAULT_HTTP_TCP_KEEPALIVE_SECS,
                http_connection_verbose: None,
                max_contracts: None,
                max_pages_per_cycle: None,
                cursor_file: None,
            };
            let err = cfg.validate().unwrap_err();
            assert!(
                err.to_string()
                    .contains("poll_interval_seconds must be >= 5"),
                "val={} should be rejected: {}",
                val,
                err
            );
        }
    }

    #[test]
    fn rejects_poll_interval_over_max() {
        let raw = r#"
            poll_interval_seconds = 9999
            [[contracts]]
            label = "x"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "AnyTransaction"
        "#;
        let mut cfg: AppConfig = toml::from_str(raw).unwrap();
        assert!(cfg.validate().is_err());
    }

    fn config_with(contracts: Vec<WatchedContract>) -> AppConfig {
        AppConfig {
            poll_interval_seconds: DEFAULT_POLL_INTERVAL_SECONDS,
            contracts,
            http_pool_max_idle_per_host: DEFAULT_HTTP_POOL_MAX_IDLE_PER_HOST,
            http_tcp_keepalive_secs: DEFAULT_HTTP_TCP_KEEPALIVE_SECS,
            http_connection_verbose: None,
            max_contracts: None,
            max_pages_per_cycle: None,
            cursor_file: None,
        }
    }

    const MINIMAL_TOML: &str = r#"
        [[contracts]]
        label = "x"
        contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        network = "testnet"
        webhook_url = "https://example.com/hook"
        [[contracts.rules]]
        type = "AnyTransaction"
    "#;

    // ── cursor keys and duplicate (network, contract_id) entries ─────────────

    fn two_contracts_toml(network_a: &str, network_b: &str) -> String {
        format!(
            r#"
            [[contracts]]
            label = "first"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network = "{network_a}"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "AnyTransaction"
            [[contracts]]
            label = "second"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network = "{network_b}"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "AnyTransaction"
        "#
        )
    }

    #[test]
    fn rejects_same_contract_id_twice_on_one_network() {
        let mut cfg: AppConfig = toml::from_str(&two_contracts_toml("testnet", "testnet")).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("duplicate contract_id")
                && err.contains("'testnet'")
                && err.contains("'first' and 'second'"),
            "got: {}",
            err
        );
    }

    #[test]
    fn allows_same_contract_id_on_different_networks() {
        let mut cfg: AppConfig =
            toml::from_str(&two_contracts_toml("testnet", "mainnet")).unwrap();
        cfg.validate().unwrap();
        assert_ne!(cfg.contracts[0].cursor_key(), cfg.contracts[1].cursor_key());
    }

    #[test]
    fn cursor_key_is_network_then_contract_id() {
        let mut cfg: AppConfig = toml::from_str(MINIMAL_TOML).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.contracts[0].cursor_key(),
            "testnet:CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        );
    }

    #[test]
    fn custom_networks_are_told_apart_by_horizon_url() {
        let a = Network::Custom(CustomNetwork {
            horizon_url: "http://localhost:8000/".to_owned(),
            explorer_url: None,
            passphrase: None,
            rpc_url: None,
        });
        let same_as_a = Network::Custom(CustomNetwork {
            horizon_url: "http://localhost:8000".to_owned(),
            explorer_url: None,
            passphrase: None,
            rpc_url: None,
        });
        let b = Network::Custom(CustomNetwork {
            horizon_url: "http://localhost:9000".to_owned(),
            explorer_url: None,
            passphrase: None,
            rpc_url: None,
        });
        assert_eq!(a.cursor_id(), same_as_a.cursor_id());
        assert_ne!(a.cursor_id(), b.cursor_id());
        assert_ne!(cursor_key(&a, "CX"), cursor_key(&Network::Testnet, "CX"));
    }

    // ── max_pages_per_cycle ───────────────────────────────────────────────────

    #[test]
    fn max_pages_per_cycle_defaults_to_ten() {
        let mut cfg: AppConfig = toml::from_str(MINIMAL_TOML).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.max_pages_per_cycle, None);
        assert_eq!(cfg.effective_max_pages_per_cycle(), 10);
    }

    #[test]
    fn max_pages_per_cycle_can_be_overridden_within_bounds() {
        let mut cfg: AppConfig =
            toml::from_str(&format!("max_pages_per_cycle = 3\n{}", MINIMAL_TOML)).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.effective_max_pages_per_cycle(), 3);

        for bad in [0, MAX_PAGES_PER_CYCLE_CEILING + 1] {
            let mut cfg: AppConfig =
                toml::from_str(&format!("max_pages_per_cycle = {}\n{}", bad, MINIMAL_TOML))
                    .unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("max_pages_per_cycle must be between 1 and"), "got: {}", err);
        }
    }

    // ── #97: poll interval default and per-contract override ─────────────────

    #[test]
    fn poll_interval_and_http_settings_default_when_omitted() {
        let mut cfg: AppConfig = toml::from_str(MINIMAL_TOML).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.poll_interval_seconds, 10);
        assert_eq!(cfg.http_pool_max_idle_per_host, 10);
        assert_eq!(cfg.http_tcp_keepalive_secs, 30);
        assert_eq!(cfg.contracts[0].poll_interval_seconds, None);
        assert_eq!(
            cfg.contracts[0].effective_poll_interval(cfg.poll_interval_seconds),
            10
        );
    }

    #[test]
    fn per_contract_poll_interval_overrides_global() {
        let raw = r#"
            poll_interval_seconds = 60
            [[contracts]]
            label = "fast"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network = "testnet"
            webhook_url = "https://example.com/hook"
            poll_interval_seconds = 5
            [[contracts.rules]]
            type = "AnyTransaction"
            [[contracts]]
            label = "slow"
            contract_id = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526"
            network = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "AnyTransaction"
        "#;
        let mut cfg: AppConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.contracts[0].effective_poll_interval(cfg.poll_interval_seconds),
            5
        );
        assert_eq!(
            cfg.contracts[1].effective_poll_interval(cfg.poll_interval_seconds),
            60
        );
    }

    #[test]
    fn rejects_per_contract_poll_interval_out_of_bounds() {
        for val in [0, 4, 3601] {
            let mut c = valid_contract();
            c.poll_interval_seconds = Some(val);
            let err = config_with(vec![c]).validate().unwrap_err().to_string();
            assert!(
                err.contains("contract 'Test': poll_interval_seconds must be"),
                "val={} should be rejected, got: {}",
                val,
                err
            );
        }
    }

    // ── #96: HTTP pool settings ──────────────────────────────────────────────

    #[test]
    fn rejects_zero_http_pool_max_idle_per_host() {
        let mut cfg = config_with(vec![valid_contract()]);
        cfg.http_pool_max_idle_per_host = 0;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("http_pool_max_idle_per_host"));
    }

    #[test]
    fn rejects_too_large_http_pool_max_idle_per_host() {
        let mut cfg = config_with(vec![valid_contract()]);
        cfg.http_pool_max_idle_per_host = MAX_HTTP_POOL_MAX_IDLE_PER_HOST + 1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_too_large_http_tcp_keepalive_secs() {
        let mut cfg = config_with(vec![valid_contract()]);
        cfg.http_tcp_keepalive_secs = MAX_HTTP_TCP_KEEPALIVE_SECS + 1;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("http_tcp_keepalive_secs"));
    }

    #[test]
    fn accepts_zero_http_tcp_keepalive_secs() {
        let mut cfg = config_with(vec![valid_contract()]);
        cfg.http_tcp_keepalive_secs = 0;
        assert!(cfg.validate().is_ok());
    }

    // ── #95: contract labels ─────────────────────────────────────────────────

    #[test]
    fn rejects_label_with_newline() {
        let mut c = valid_contract();
        c.label = "Vault\nINFO forged log line".into();
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("control characters"), "got: {}", err);
        assert!(
            !err.contains('\n'),
            "error must not echo the raw newline: {}",
            err
        );
    }

    #[test]
    fn rejects_label_with_ansi_escape() {
        let mut c = valid_contract();
        c.label = "\u{1b}[31mVault\u{1b}[0m".into();
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("control characters"), "got: {}", err);
        assert!(
            !err.contains('\u{1b}'),
            "error must not echo the raw escape: {}",
            err
        );
    }

    #[test]
    fn rejects_label_longer_than_max() {
        let mut c = valid_contract();
        c.label = "a".repeat(MAX_LABEL_LEN + 1);
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("longer than 128 characters"), "got: {}", err);
    }

    #[test]
    fn accepts_label_of_max_length() {
        let mut c = valid_contract();
        c.label = "é".repeat(MAX_LABEL_LEN);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn label_is_trimmed() {
        let mut c = valid_contract();
        c.label = "  Vault \t".into();
        c.validate().unwrap();
        assert_eq!(c.label, "Vault");
    }

    #[test]
    fn rejects_duplicate_labels_differing_in_case_and_whitespace() {
        let mut a = valid_contract();
        a.label = "Vault".into();
        let mut b = valid_contract();
        b.label = "vault ".into();
        let err = config_with(vec![a, b]).validate().unwrap_err();
        assert!(err.to_string().contains("duplicate contract label"));
    }

    // ── #94: Soroban function names ──────────────────────────────────────────

    #[test]
    fn rejects_function_name_longer_than_32_chars() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::FunctionCalled {
            function_name: "a".repeat(33),
            match_mode: Default::default(),
        })];
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("contract 'Test'"), "got: {}", err);
        assert!(err.contains("FunctionCalled"), "got: {}", err);
        assert!(
            err.contains("at most 32 characters from [a-zA-Z0-9_]"),
            "got: {}",
            err
        );
    }

    #[test]
    fn accepts_function_name_of_32_chars() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::FunctionCalled {
            function_name: "a".repeat(32),
            match_mode: Default::default(),
        })];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_function_name_with_invalid_characters() {
        for name in ["with-draw", "with draw", "withdraw()", "wïthdraw"] {
            let mut c = valid_contract();
            c.rules = vec![rule(AlertRule::FunctionCalled {
                function_name: name.into(),
                match_mode: Default::default(),
            })];
            let err = c.validate().unwrap_err().to_string();
            assert!(
                err.contains("not a valid Soroban symbol"),
                "{}: {}",
                name,
                err
            );
        }
    }

    #[test]
    fn rejects_function_name_with_surrounding_whitespace() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::FunctionCalled {
            function_name: "withdraw ".into(),
            match_mode: Default::default(),
        })];
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("\"withdraw \""), "got: {}", err);
    }

    #[test]
    fn rejects_invalid_admin_function_name() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::AdminFunctionCalled {
            function_names: vec!["set_admin".into(), " upgrade".into()],
        })];
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("AdminFunctionCalled"), "got: {}", err);
        assert!(err.contains("not a valid Soroban symbol"), "got: {}", err);
    }

    #[test]
    fn from_file_returns_err_for_missing_file() {
        let nonexistent_path = std::path::Path::new("/tmp/txwatch_nonexistent_test_config.toml");
        let result = AppConfig::from_file(nonexistent_path);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("txwatch_nonexistent_test_config.toml"));
    }

    #[test]
    fn from_file_returns_err_for_wrong_type_field() {
        let path = std::env::temp_dir().join("txwatch_wrong_type_field_test_config.toml");
        let raw = r#"
            poll_interval_seconds = "ten"
            [[contracts]]
            label = "x"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "AnyTransaction"
        "#;

        std::fs::write(&path, raw).unwrap();
        let result = AppConfig::from_file(&path);
        let _ = std::fs::remove_file(&path);

        assert!(result.is_err());
        // `{:#}` renders the whole anyhow chain; the field path lives on the
        // source error, not on the outer context.
        let error_msg = format!("{:#}", result.unwrap_err());
        assert!(error_msg.contains("failed to parse config file"));
        assert!(
            error_msg.contains("field: poll_interval_seconds"),
            "error should name the offending field, got: {}",
            error_msg
        );
    }

    // ── #54: enabled flag ────────────────────────────────────────────────────

    #[test]
    fn disabled_contract_parses() {
        let raw = r#"
            poll_interval_seconds = 10
            [[contracts]]
            label       = "Off"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network     = "testnet"
            webhook_url = "https://example.com/hook"
            enabled     = false
            [[contracts.rules]]
            type = "AnyTransaction"
        "#;
        let mut cfg: AppConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        assert!(!cfg.contracts[0].enabled);
    }

    #[test]
    fn disabled_rule_parses() {
        let raw = r#"
            poll_interval_seconds = 10
            [[contracts]]
            label       = "C"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network     = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "All"
            [[contracts.rules.rules]]
            type    = "AnyTransaction"
            enabled = false
        "#;
        let mut cfg: AppConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        let AlertRule::All { rules } = &cfg.contracts[0].rules[0].rule else {
            panic!("expected All");
        };
        assert!(
            !rules[0].enabled,
            "nested rule defaults to enabled=false when set"
        );
    }

    #[test]
    fn enabled_defaults_to_true() {
        let mut c = valid_contract();
        c.validate().unwrap();
        assert!(c.enabled);
        assert!(matches!(c.rules[0].rule, AlertRule::AnyTransaction));
    }

    // ── #53: per-rule webhook_url, webhook_secret, severity ─────────────────

    #[test]
    fn per_rule_webhook_url_accepted() {
        let raw = r#"
            poll_interval_seconds = 10
            [[contracts]]
            label       = "C"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network     = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "All"
            [[contracts.rules.rules]]
            type        = "AnyTransaction"
            webhook_url = "https://pagerduty.example.com/alert"
            severity    = "critical"
        "#;
        let mut cfg: AppConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        let AlertRule::All { rules } = &cfg.contracts[0].rules[0].rule else {
            panic!("expected All");
        };
        assert_eq!(
            rules[0].webhook_url.as_deref(),
            Some("https://pagerduty.example.com/alert")
        );
        assert_eq!(rules[0].severity, Some(Severity::Critical));
    }

    #[test]
    fn per_rule_webhook_url_invalid_is_rejected() {
        let raw = r#"
            poll_interval_seconds = 10
            [[contracts]]
            label       = "C"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network     = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "All"
            [[contracts.rules.rules]]
            type        = "AnyTransaction"
            webhook_url = "ftp://bad"
        "#;
        let mut cfg: AppConfig = toml::from_str(raw).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("rule webhook_url"), "got: {}", err);
    }

    // ── #52: composite rules ─────────────────────────────────────────────────

    #[test]
    fn all_rule_parses_and_validates() {
        let raw = r#"
            poll_interval_seconds = 10
            [[contracts]]
            label       = "C"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network     = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "All"
            [[contracts.rules.rules]]
            type          = "LargeTransfer"
            threshold_xlm = 1000
            [[contracts.rules.rules]]
            type = "TransactionFailed"
        "#;
        let mut cfg: AppConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        if let AlertRule::All { rules } = &cfg.contracts[0].rules[0].rule {
            assert_eq!(rules.len(), 2);
        } else {
            panic!("expected All rule");
        }
    }

    // ── Issue #50: EventEmitted ───────────────────────────────────────────────

    fn event_rule(topic: &str, topics: &[&str]) -> RuleConfig {
        RuleConfig {
            rule: AlertRule::EventEmitted {
                topic: topic.into(),
                topics: topics.iter().map(|t| t.to_string()).collect(),
            },
            cooldown_seconds: None,
        }
    }

    #[test]
    fn event_emitted_accepts_symbol_topic_on_testnet() {
        let mut c = valid_contract();
        c.rules = vec![event_rule(" transfer ", &["*", "GABC"])];
        c.validate().unwrap();
        if let AlertRule::EventEmitted { topic, .. } = &c.rules[0].rule {
            assert_eq!(topic, "transfer");
        }
        assert_eq!(c.rules[0].label(), "EventEmitted(transfer, *, GABC)");
    }

    #[test]
    fn event_emitted_rejects_invalid_topic() {
        let too_long = "a".repeat(33);
        for bad in ["", "not-a-symbol", too_long.as_str()] {
            let mut c = valid_contract();
            c.rules = vec![event_rule(bad, &[])];
            assert!(c.validate().is_err(), "topic {:?} should be rejected", bad);
        }
    }

    #[test]
    fn event_emitted_rejects_blank_extra_topic() {
        let mut c = valid_contract();
        c.rules = vec![event_rule("transfer", &["  "])];
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("blank"), "got: {}", err);
    }

    #[test]
    fn event_emitted_on_mainnet_requires_rpc_url() {
        let mut c = valid_contract();
        c.network = Network::Mainnet;
        c.rules = vec![event_rule("transfer", &[])];
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("soroban_rpc_url"), "got: {}", err);

        let mut c = valid_contract();
        c.network = Network::Mainnet;
        c.rules = vec![event_rule("transfer", &[])];
        c.soroban_rpc_url = Some("https://rpc.example.com/".into());
        c.validate().unwrap();
        assert_eq!(
            c.effective_soroban_rpc_url(),
            Some("https://rpc.example.com")
        );
    }

    #[test]
    fn event_emitted_parses_from_toml() {
        let mut cfg = parse_with_interval(
            r#"
            [[contracts]]
            label = "x"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "EventEmitted"
            topic = "mint"
            topics = ["*"]
            "#,
        );
        cfg.validate().unwrap();
        assert!(cfg.contracts[0].needs_events());
        assert_eq!(
            cfg.contracts[0].effective_soroban_rpc_url(),
            Some("https://soroban-testnet.stellar.org")
        );
    }

    // ── Issue #49: cooldown_seconds ───────────────────────────────────────────

    #[test]
    fn cooldown_seconds_parses_on_any_rule() {
        let mut cfg = parse_with_interval(
            r#"
            [[contracts]]
            label = "x"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "AnyTransaction"
            cooldown_seconds = 300
            [[contracts.rules]]
            type = "HighFee"
            threshold_stroops = 100
            "#,
        );
        cfg.validate().unwrap();
        let rules = &cfg.contracts[0].rules;
        assert_eq!(rules[0].cooldown_seconds, Some(300));
        assert!(matches!(rules[0].rule, AlertRule::AnyTransaction));
        assert_eq!(rules[1].cooldown_seconds, None);
    }

    #[test]
    fn cooldown_seconds_above_max_is_rejected() {
        let mut c = valid_contract();
        c.rules = vec![RuleConfig {
            rule: AlertRule::AnyTransaction,
            cooldown_seconds: Some(MAX_COOLDOWN_SECONDS + 1),
        }];
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("cooldown_seconds"), "got: {}", err);
    }
    // ── Webhook destinations, formats and headers ────────────────────────────

    /// Parses and validates `contract_body` as the only `[[contracts]]` entry
    /// (label "x", one AnyTransaction rule).
    fn parse_contract(contract_body: &str) -> Result<AppConfig> {
        let raw = format!(
            r#"
            [[contracts]]
            label = "x"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network = "testnet"
            {}
            [[contracts.rules]]
            type = "AnyTransaction"
            "#,
            contract_body
        );
        AppConfig::parse(&raw, Path::new("webhooks.toml"))
    }

    fn parse_err(contract_body: &str) -> String {
        format!("{:#}", parse_contract(contract_body).unwrap_err())
    }

    #[test]
    fn webhook_url_shorthand_is_one_txwatch_destination() {
        let cfg = parse_contract(r#"webhook_url = "https://example.com/hook""#).unwrap();
        let destinations = cfg.contracts[0].destinations();
        assert_eq!(destinations.len(), 1);
        assert_eq!(destinations[0].url, "https://example.com/hook");
        assert_eq!(destinations[0].format, WebhookFormat::Txwatch);
        assert!(destinations[0].headers.is_empty());
    }

    #[test]
    fn webhooks_array_combines_with_the_shorthand() {
        let cfg = parse_contract(
            r#"
            webhook_url = "https://internal.example.com/hook"
            [[contracts.webhooks]]
            url = "https://hooks.slack.com/services/T/B/X"
            format = "slack"
            [[contracts.webhooks]]
            url = "https://events.pagerduty.com/v2/enqueue"
            format = "pagerduty"
            routing_key = "R0UT1NG"
            "#,
        )
        .unwrap();
        let destinations = cfg.contracts[0].destinations();
        let summary: Vec<(&str, WebhookFormat)> = destinations
            .iter()
            .map(|d| (d.url.as_str(), d.format))
            .collect();
        assert_eq!(
            summary,
            [
                ("https://internal.example.com/hook", WebhookFormat::Txwatch),
                (
                    "https://hooks.slack.com/services/T/B/X",
                    WebhookFormat::Slack
                ),
                (
                    "https://events.pagerduty.com/v2/enqueue",
                    WebhookFormat::Pagerduty
                ),
            ]
        );
    }

    #[test]
    fn webhooks_array_alone_is_enough() {
        let cfg = parse_contract(
            r#"
            [[contracts.webhooks]]
            url = "https://discord.com/api/webhooks/1/abc"
            format = "discord"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.contracts[0].webhook_url, None);
        assert_eq!(cfg.contracts[0].destinations().len(), 1);
    }

    #[test]
    fn a_contract_needs_at_least_one_destination() {
        let err = parse_err("");
        assert!(err.contains("no webhook destination"), "got: {}", err);
    }

    #[test]
    fn shorthand_fields_without_webhook_url_are_rejected() {
        let err = parse_err(
            r#"
            webhook_format = "slack"
            [[contracts.webhooks]]
            url = "https://example.com/hook"
            "#,
        );
        assert!(
            err.contains("webhook_format set without webhook_url"),
            "got: {}",
            err
        );
    }

    #[test]
    fn unknown_format_and_unknown_destination_fields_are_rejected() {
        let err = parse_err(
            r#"webhook_url = "https://example.com/hook"
            webhook_format = "teams""#,
        );
        assert!(err.contains("unknown variant `teams`"), "got: {}", err);

        let err = parse_err(
            r#"
            [[contracts.webhooks]]
            url = "https://example.com/hook"
            secrett = "x"
            "#,
        );
        assert!(err.contains("unknown field `secrett`"), "got: {}", err);
    }

    #[test]
    fn destination_errors_name_the_field() {
        let err = parse_err(
            r#"
            [[contracts.webhooks]]
            url = "https://example.com/ok"
            [[contracts.webhooks]]
            url = "ftp://example.com/bad"
            "#,
        );
        assert!(
            err.contains(
                "contract 'x': webhooks[1].url 'ftp://example.com/bad' must use http or https"
            ),
            "got: {}",
            err
        );
    }

    // ── Contract limit ───────────────────────────────────────────────────────

    /// `n` contracts with unique labels.
    fn contracts(n: usize) -> Vec<WatchedContract> {
        (0..n)
            .map(|i| {
                let mut c = valid_contract();
                c.label = format!("c{}", i);
                c
            })
            .collect()
    }

    #[test]
    fn accepts_exactly_max_contracts() {
        let mut cfg = config_with(contracts(MAX_CONTRACTS));
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_more_than_max_contracts() {
        let mut cfg = config_with(contracts(MAX_CONTRACTS + 1));
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("101 contracts configured, more than the limit of 100"),
            "got: {}",
            err
        );
        assert!(err.contains("max_contracts"), "got: {}", err);
    }

    #[test]
    fn max_contracts_override_raises_and_lowers_the_limit() {
        let mut cfg = config_with(contracts(150));
        cfg.max_contracts = Some(150);
        cfg.validate().unwrap();

        let mut cfg = config_with(contracts(3));
        cfg.max_contracts = Some(2);
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("more than the limit of 2"), "got: {}", err);
    }

    #[test]
    fn max_contracts_override_must_be_in_range() {
        for max in [0, MAX_CONTRACTS_CEILING + 1] {
            let mut cfg = config_with(contracts(1));
            cfg.max_contracts = Some(max);
            let err = cfg.validate().unwrap_err().to_string();
            assert!(
                err.contains("max_contracts must be between 1 and 10000"),
                "max={}: {}",
                max,
                err
            );
        }
    }

    #[test]
    fn not_rule_parses_and_validates() {
        let raw = r#"
            poll_interval_seconds = 10
            [[contracts]]
            label       = "C"
            contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
            network     = "testnet"
            webhook_url = "https://example.com/hook"
            [[contracts.rules]]
            type = "Not"
            [contracts.rules.rule]
            type = "TransactionFailed"
        "#;
        let mut cfg: AppConfig = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        assert!(matches!(
            cfg.contracts[0].rules[0].rule,
            AlertRule::Not { .. }
        ));
    }

    #[test]
    fn all_rule_empty_is_rejected() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::All { rules: vec![] })];
        let err = c.validate().unwrap_err().to_string();
        assert!(
            err.contains("All: rules list must not be empty"),
            "got: {}",
            err
        );
    }

    #[test]
    fn composite_rule_label_is_readable() {
        let r = AlertRule::All {
            rules: vec![
                RuleEntry {
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::FunctionCalled {
                        function_name: "withdraw".into(),
                        match_mode: FunctionMatchMode::default(),
                    },
                },
                RuleEntry {
                    enabled: true,
                    webhook_url: None,
                    webhook_secret: None,
                    severity: None,
                    rule: AlertRule::LargeTransfer {
                        threshold_xlm: 10_000,
                        threshold_stroops: 0,
                    },
                },
            ],
        };
        assert_eq!(
            r.label(),
            "All(FunctionCalled(withdraw), LargeTransfer(>=10000XLM))"
        );
    }

    // ── #51: SourceAccount rule ───────────────────────────────────────────────

    #[test]
    fn source_account_allow_validates() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::SourceAccount {
            allow: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNA".into()],
            deny: vec![],
        })];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn source_account_deny_validates() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::SourceAccount {
            allow: vec![],
            deny: vec!["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNA".into()],
        })];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn source_account_empty_both_is_rejected() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::SourceAccount {
            allow: vec![],
            deny: vec![],
        })];
        let err = c.validate().unwrap_err().to_string();
        assert!(
            err.contains("at least one of 'allow' or 'deny'"),
            "got: {}",
            err
        );
    }

    #[test]
    fn source_account_invalid_address_is_rejected() {
        let mut c = valid_contract();
        c.rules = vec![rule(AlertRule::SourceAccount {
            allow: vec!["NOT_A_STELLAR_ADDR".into()],
            deny: vec![],
        })];
        let err = c.validate().unwrap_err().to_string();
        assert!(
            err.contains("not a valid Stellar account address"),
            "got: {}",
            err
        );
    }

    #[test]
    fn max_contracts_parses_from_toml() {
        let mut cfg: AppConfig =
            toml::from_str(&format!("max_contracts = 500\n{}", MINIMAL_TOML)).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.effective_max_contracts(), 500);
        let default: AppConfig = toml::from_str(MINIMAL_TOML).unwrap();
        assert_eq!(default.effective_max_contracts(), MAX_CONTRACTS);
    }
    // ── Unknown fields in rules ──────────────────────────────────────────────

    fn parse_rule(rule_toml: &str) -> Result<AppConfig> {
        let raw = format!(
            "{}\n{}",
            MINIMAL_TOML.replace("type = \"AnyTransaction\"", ""),
            rule_toml
        );
        AppConfig::parse(&raw, Path::new("rules.toml"))
    }

    fn assert_unknown_field(rule_toml: &str, field: &str) {
        let err = format!("{:#}", parse_rule(rule_toml).unwrap_err());
        assert!(
            err.contains(&format!("unknown field `{}`", field)),
            "expected unknown field `{}`, got: {}",
            field,
            err
        );
        assert!(
            err.contains("field: contracts[0].rules[0]"),
            "error should name the rule's path, got: {}",
            err
        );
    }

    #[test]
    fn pagerduty_requires_a_routing_key_and_others_reject_one() {
        let err = parse_err(
            r#"webhook_url = "https://events.pagerduty.com/v2/enqueue"
            webhook_format = "pagerduty""#,
        );
        assert!(
            err.contains("webhook_routing_key is required when format is \"pagerduty\""),
            "got: {}",
            err
        );

        let err = parse_err(
            r#"
            [[contracts.webhooks]]
            url = "https://example.com/hook"
            routing_key = "R0UT1NG"
            "#,
        );
        assert!(
            err.contains("webhooks[0].routing_key is only used when format is \"pagerduty\""),
            "got: {}",
            err
        );
    }

    #[test]
    fn custom_headers_are_accepted() {
        let cfg = parse_contract(
            r#"webhook_url = "https://example.com/hook"
            webhook_headers = { "Authorization" = "Bearer abc", "X-Api-Key" = "k" }"#,
        )
        .unwrap();
        let headers: Vec<(&str, &str)> = cfg.contracts[0].webhook_headers.iter().collect();
        assert_eq!(
            headers,
            [("Authorization", "Bearer abc"), ("X-Api-Key", "k")]
        );
    }

    #[test]
    fn reserved_headers_are_rejected() {
        for name in [
            "Content-Type",
            "content-length",
            "X-TxWatch-Secret",
            "x-txwatch-anything",
        ] {
            let err = parse_err(&format!(
                r#"webhook_url = "https://example.com/hook"
                webhook_headers = {{ "{}" = "v" }}"#,
                name
            ));
            assert!(err.contains("is reserved"), "{}: {}", name, err);
            assert!(err.contains("webhook_headers"), "{}: {}", name, err);
        }
    }

    #[test]
    fn rejects_misspelled_field_on_every_rule_type() {
        let cases = [
            (
                "type = \"AnyTransaction\"\nfunction_name = \"x\"",
                "function_name",
            ),
            (
                "type = \"TransactionFailed\"\nthreshold_xlm = 5",
                "threshold_xlm",
            ),
            (
                "type = \"LargeTransfer\"\nthreshold_xlm = 5\nthreshhold = 1",
                "threshhold",
            ),
            (
                "type = \"FunctionCalled\"\nfunction_name = \"x\"\nextra = true",
                "extra",
            ),
            (
                "type = \"AdminFunctionCalled\"\nfunction_names = [\"x\"]\nfunction_name = \"y\"",
                "function_name",
            ),
            ("type = \"HighFee\"\nthreshold_xml = 5", "threshold_xml"),
        ];
        for (rule, field) in cases {
            assert_unknown_field(rule, field);
        }
    }

    #[test]
    fn high_fee_typo_is_not_reported_as_missing_threshold() {
        let err = format!(
            "{:#}",
            parse_rule("type = \"HighFee\"\nthreshold_xml = 5").unwrap_err()
        );
        assert!(
            !err.contains("threshold_stroops must be > 0"),
            "got: {}",
            err
        );
    }

    #[test]
    fn every_rule_type_still_parses_without_extra_fields() {
        for rule in [
            "type = \"AnyTransaction\"",
            "type = \"TransactionFailed\"",
            "type = \"LargeTransfer\"\nthreshold_xlm = 5",
            "type = \"FunctionCalled\"\nfunction_name = \"x\"",
            "type = \"AdminFunctionCalled\"\nfunction_names = [\"x\"]",
            "type = \"HighFee\"\nthreshold_xlm = 5",
        ] {
            parse_rule(rule).unwrap_or_else(|e| panic!("{}: {:#}", rule, e));
        }
    }

    // ── Contract StrKey ──────────────────────────────────────────────────────

    const VALID_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    #[test]
    fn validate_contract_id_accepts_real_contract_ids() {
        assert!(validate_contract_id(VALID_ID).is_ok());
    }

    #[test]
    fn accepts_real_contract_ids() {
        // Native XLM Stellar Asset Contract on testnet and mainnet.
        for id in [
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
            "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA",
        ] {
            assert!(validate_contract_id(id).is_ok(), "{}", id);
        }
    }

    #[test]
    fn invalid_header_names_and_values_are_rejected_without_echoing_values() {
        let err = parse_err(
            r#"
            [[contracts.webhooks]]
            url = "https://example.com/hook"
            headers = { "Bad Header" = "v", "X-Ok" = "line1\r\nInjected: secret-value" }
            "#,
        );
        assert!(
            err.contains("webhooks[0].headers \"Bad Header\" is not a valid HTTP header name"),
            "got: {}",
            err
        );
        assert!(
            err.contains("webhooks[0].headers value of \"X-Ok\" contains control characters"),
            "got: {}",
            err
        );
        assert!(
            !err.contains("secret-value"),
            "header value leaked: {}",
            err
        );
    }

    #[test]
    fn debug_output_redacts_header_values_secrets_and_routing_keys() {
        let destination = WebhookDestination {
            url: "https://example.com/hook".into(),
            secret: Some("s3cret".into()),
            format: WebhookFormat::Pagerduty,
            headers: WebhookHeaders(BTreeMap::from([(
                "Authorization".to_owned(),
                "Bearer t0ken".to_owned(),
            )])),
            routing_key: Some("R0UT1NG".into()),
        };
        let debug = format!("{:?}", destination);
        for secret in ["s3cret", "t0ken", "R0UT1NG"] {
            assert!(!debug.contains(secret), "{} leaked: {}", secret, debug);
        }
        assert!(debug.contains("Authorization"), "{}", debug);
        assert_eq!(
            destination.headers.redacted(),
            ["Authorization: <redacted>"]
        );
    }

    #[test]
    fn validate_contract_id_reports_each_failure_distinctly() {
        let valid = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
        assert_eq!(
            validate_contract_id(&valid[..55]),
            Err(ContractIdError::Length(55))
        );
        assert_eq!(
            validate_contract_id("CTEST000000000000000000000000000000000000000000000000000"),
            Err(ContractIdError::Alphabet {
                position: 5,
                found: '0'
            })
        );
        assert_eq!(
            validate_contract_id("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"),
            Err(ContractIdError::VersionByte(6 << 3))
        );
        let mistyped = valid.replacen("LZ", "LY", 1);
        assert!(matches!(
            validate_contract_id(&mistyped),
            Err(ContractIdError::Checksum { .. })
        ));
    }

    #[test]
    fn batch_alerts_defaults_to_false_and_parses() {
        let cfg: AppConfig = toml::from_str(MINIMAL_TOML).unwrap();
        assert!(!cfg.contracts[0].batch_alerts);
        let raw = MINIMAL_TOML.replace(
            "network = \"testnet\"",
            "network = \"testnet\"\n        batch_alerts = true",
        );
        let cfg: AppConfig = toml::from_str(&raw).unwrap();
        assert!(cfg.contracts[0].batch_alerts);
    }

    #[test]
    fn rejects_contract_id_outside_base32_alphabet() {
        for bad in ['a', '0', '1', '8', '9'] {
            let id = format!("C{}{}", bad, &VALID_ID[2..]);
            assert_eq!(
                validate_contract_id(&id),
                Err(ContractIdError::Alphabet {
                    position: 1,
                    found: bad
                }),
                "{}",
                id
            );
        }
        let mut c = valid_contract();
        c.contract_id = VALID_ID.to_lowercase();
        let err = c.validate().unwrap_err().to_string();
        assert!(
            err.contains("invalid character 'c' at position 0"),
            "got: {}",
            err
        );
    }

    #[test]
    fn rejects_contract_id_with_wrong_version_byte() {
        // A valid account (G…) StrKey: right length and alphabet, wrong version.
        let err = validate_contract_id("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
            .unwrap_err();
        assert_eq!(err, ContractIdError::VersionByte(6 << 3));
        assert!(err.to_string().contains("wrong version byte"));
    }

    #[test]
    fn rejects_contract_id_with_bad_checksum() {
        // One mistyped character in the payload.
        let id = VALID_ID.replacen("AAAA", "AABA", 1);
        let err = validate_contract_id(&id).unwrap_err();
        assert!(matches!(err, ContractIdError::Checksum { .. }), "{:?}", err);

        let mut c = valid_contract();
        c.contract_id = id;
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("checksum mismatch"), "got: {}", err);
    }

    #[test]
    fn rejects_contract_id_of_wrong_length() {
        assert_eq!(
            validate_contract_id(&VALID_ID[..55]),
            Err(ContractIdError::Length(55))
        );
    }

    // ── Env-var interpolation ────────────────────────────────────────────────

    fn lookup(name: &str) -> Option<String> {
        match name {
            "TOKEN" => Some("s3cr3t".into()),
            "HOST" => Some("hooks.example.com".into()),
            "EMPTY" => Some(String::new()),
            _ => None,
        }
    }

    #[test]
    fn interpolation_supports_embedded_defaults_and_escapes() {
        let interp = |v: &str| interpolate(v, &lookup);
        assert_eq!(interp("${TOKEN}").unwrap(), "s3cr3t");
        assert_eq!(interp("Bearer ${TOKEN}").unwrap(), "Bearer s3cr3t");
        assert_eq!(interp("${MISSING:-fallback}").unwrap(), "fallback");
        assert_eq!(interp("${EMPTY:-fallback}").unwrap(), "fallback");
        assert_eq!(interp("$${TOKEN}").unwrap(), "${TOKEN}");
        assert_eq!(interp("cost: $5").unwrap(), "cost: $5");
        assert!(interp("${MISSING}")
            .unwrap_err()
            .to_string()
            .contains("'MISSING'"));
        assert!(interp("${}").is_err());
        assert!(interp("${TOKEN").is_err());
        assert!(interp("${1X}").is_err());
    }
    fn interp(value: &str) -> Result<String> {
        interpolate(value, &lookup)
    }

    #[test]
    fn interpolates_whole_value() {
        assert_eq!(interp("${TOKEN}").unwrap(), "s3cr3t");
    }

    #[test]
    fn interpolates_inside_larger_strings() {
        assert_eq!(interp("Bearer ${TOKEN}").unwrap(), "Bearer s3cr3t");
        assert_eq!(
            interp("https://${HOST}/hook/${TOKEN}?x=1").unwrap(),
            "https://hooks.example.com/hook/s3cr3t?x=1"
        );
    }

    #[test]
    fn leaves_values_without_references_unchanged() {
        for value in [
            "https://example.com/hook",
            "",
            "cost: $5",
            "$TOKEN",
            "a$$b",
            "{TOKEN}",
        ] {
            assert_eq!(interp(value).unwrap(), value);
        }
    }

    #[test]
    fn missing_variable_is_an_error_naming_it() {
        let err = interp("https://x/${MISSING_VAR}").unwrap_err().to_string();
        assert!(err.contains("'MISSING_VAR'"), "got: {}", err);
        assert!(err.contains("not set"), "got: {}", err);
    }

    #[test]
    fn empty_variable_name_is_an_error() {
        let err = interp("${}").unwrap_err().to_string();
        assert!(err.contains("empty variable name"), "got: {}", err);
        assert!(interp("${:-fallback}").is_err());
    }

    #[test]
    fn unterminated_and_invalid_references_are_errors() {
        assert!(interp("${TOKEN")
            .unwrap_err()
            .to_string()
            .contains("unterminated"));
        assert!(interp("${1ABC}")
            .unwrap_err()
            .to_string()
            .contains("invalid variable name"));
        assert!(interp("${A B}").is_err());
    }

    #[test]
    fn default_is_used_when_unset_or_empty() {
        assert_eq!(interp("${MISSING_VAR:-fallback}").unwrap(), "fallback");
        assert_eq!(interp("${EMPTY:-fallback}").unwrap(), "fallback");
        assert_eq!(interp("${TOKEN:-fallback}").unwrap(), "s3cr3t");
        assert_eq!(interp("${MISSING_VAR:-}").unwrap(), "");
        assert_eq!(
            interp("http://${MISSING_VAR:-localhost:8000}/x").unwrap(),
            "http://localhost:8000/x"
        );
    }

    #[test]
    fn empty_variable_without_default_resolves_to_empty() {
        assert_eq!(interp("a${EMPTY}b").unwrap(), "ab");
    }

    #[test]
    fn escaped_sequence_is_kept_literally() {
        assert_eq!(interp("$${TOKEN}").unwrap(), "${TOKEN}");
        assert_eq!(interp("$${MISSING_VAR}").unwrap(), "${MISSING_VAR}");
        assert_eq!(interp("$${TOKEN} ${TOKEN}").unwrap(), "${TOKEN} s3cr3t");
        assert_eq!(interp("$$${TOKEN}").unwrap(), "$${TOKEN}");
    }

    /// Serialises tests that mutate the process environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn headers_secrets_and_routing_keys_are_interpolated() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("TXWATCH_TEST_BEARER", "t0ken");
        env::set_var("TXWATCH_TEST_PD_KEY", "R0UT1NG");
        let cfg = parse_contract(
            r#"webhook_url = "https://example.com/hook"
            webhook_headers = { "Authorization" = "Bearer ${TXWATCH_TEST_BEARER}" }
            [[contracts.webhooks]]
            url = "https://events.pagerduty.com/v2/enqueue"
            format = "pagerduty"
            routing_key = "${TXWATCH_TEST_PD_KEY}"
            secret = "prefix-${TXWATCH_TEST_BEARER}"
            "#,
        );
        env::remove_var("TXWATCH_TEST_BEARER");
        env::remove_var("TXWATCH_TEST_PD_KEY");
        let cfg = cfg.unwrap();
        let destinations = cfg.contracts[0].destinations();
        assert_eq!(
            destinations[0].headers.iter().collect::<Vec<_>>(),
            [("Authorization", "Bearer t0ken")]
        );
        assert_eq!(destinations[1].routing_key.as_deref(), Some("R0UT1NG"));
        assert_eq!(destinations[1].secret.as_deref(), Some("prefix-t0ken"));
    }

    #[test]
    fn missing_header_variable_names_the_header_not_the_value() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("TXWATCH_TEST_UNSET");
        let err = parse_err(
            r#"webhook_url = "https://example.com/hook"
            webhook_headers = { "Authorization" = "Bearer ${TXWATCH_TEST_UNSET}" }"#,
        );
        assert!(
            err.contains("contracts[0].webhook_headers.Authorization"),
            "got: {}",
            err
        );
        assert!(err.contains("TXWATCH_TEST_UNSET"), "got: {}", err);
    }
    #[test]
    fn resolve_env_interpolation_reads_process_environment() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("TXWATCH_TEST_SET_VAR", "value");
        env::remove_var("TXWATCH_TEST_UNSET_VAR");

        assert_eq!(
            resolve_env_interpolation("${TXWATCH_TEST_SET_VAR}").unwrap(),
            "value"
        );
        assert!(resolve_env_interpolation("${TXWATCH_TEST_UNSET_VAR}").is_err());
        assert_eq!(resolve_env_interpolation("plain").unwrap(), "plain");
        assert!(resolve_env_interpolation("${}").is_err());

        env::remove_var("TXWATCH_TEST_SET_VAR");
    }

    #[test]
    fn parse_interpolates_urls_secrets_and_network_fields() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("TXWATCH_TEST_HOOK_TOKEN", "tok123");
        env::set_var("TXWATCH_TEST_SECRET", "shh");
        env::remove_var("TXWATCH_TEST_HORIZON");

        let raw = format!(
            r#"
            cursor_file = "$${{literal}}.json"
            [[contracts]]
            label = "x"
            contract_id = "{VALID_ID}"
            network = {{ horizon_url = "${{TXWATCH_TEST_HORIZON:-http://localhost:8000}}" }}
            webhook_url = "https://hooks.example.com/${{TXWATCH_TEST_HOOK_TOKEN}}"
            webhook_secret = "Bearer ${{TXWATCH_TEST_SECRET}}"
            [[contracts.rules]]
            type = "AnyTransaction"
            "#
        );
        let cfg = AppConfig::parse(&raw, Path::new("env.toml"));
        env::remove_var("TXWATCH_TEST_HOOK_TOKEN");
        env::remove_var("TXWATCH_TEST_SECRET");
        let cfg = cfg.unwrap();

        let contract = &cfg.contracts[0];
        assert_eq!(
            contract.webhook_url.as_deref(),
            Some("https://hooks.example.com/tok123")
        );
        assert_eq!(contract.webhook_secret.as_deref(), Some("Bearer shh"));
        assert_eq!(contract.network.horizon_base_url(), "http://localhost:8000");
        assert_eq!(cfg.cursor_file.as_deref(), Some("${literal}.json"));
    }

    #[test]
    fn parse_error_for_missing_variable_names_the_field() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("TXWATCH_TEST_MISSING");
        let raw = MINIMAL_TOML.replace(
            "https://example.com/hook",
            "https://example.com/${TXWATCH_TEST_MISSING}",
        );
        let err = format!(
            "{:#}",
            AppConfig::parse(&raw, Path::new("env.toml")).unwrap_err()
        );
        assert!(err.contains("contracts[0].webhook_url"), "got: {}", err);
        assert!(err.contains("TXWATCH_TEST_MISSING"), "got: {}", err);
    }
}
