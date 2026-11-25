use chrono::Utc;
use glob::glob;
use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TOML in {path}: {source}")]
    ParseError {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("environment variable interpolation failed for {field}: {reason}")]
    EnvInterpolation { field: String, reason: String },
    #[error("validation failed:\n{}", .0.join("\n"))]
    Validation(Vec<String>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub include: Vec<String>,
    pub network: NetworkConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub webhook: WebhookDefaults,
    #[serde(default)]
    pub contracts: Vec<WatchedContract>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    Testnet,
    Mainnet,
    Custom,
}

impl NetworkKind {
    pub fn default_horizon_url(&self) -> Option<&'static str> {
        match self {
            NetworkKind::Testnet => Some("https://horizon-testnet.stellar.org"),
            NetworkKind::Mainnet => Some("https://horizon.stellar.org"),
            NetworkKind::Custom => None,
        }
    }

    pub fn default_passphrase(&self) -> Option<&'static str> {
        match self {
            NetworkKind::Testnet => Some("Test SDF Network ; September 2015"),
            NetworkKind::Mainnet => Some("Public Global Stellar Network ; September 2015"),
            NetworkKind::Custom => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    #[serde(default = "default_network_kind")]
    pub kind: NetworkKind,
    #[serde(default)]
    pub horizon_url: Option<String>,
    #[serde(default)]
    pub network_passphrase: Option<String>,
    #[serde(default)]
    pub rpc_url: Option<String>,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_page_limit")]
    pub page_limit: u32,
}

fn default_network_kind() -> NetworkKind {
    NetworkKind::Testnet
}

fn default_poll_interval_ms() -> u64 {
    5_000
}

fn default_page_limit() -> u32 {
    100
}

impl NetworkConfig {
    pub fn resolved_horizon_url(&self) -> Option<&str> {
        self.horizon_url
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.kind.default_horizon_url())
    }

    pub fn resolved_passphrase(&self) -> Option<&str> {
        self.network_passphrase
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.kind.default_passphrase())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,
    #[serde(default)]
    pub admin_token: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            metrics_path: default_metrics_path(),
            admin_token: None,
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    #[serde(default = "default_db_path")]
    pub sqlite_path: PathBuf,
    #[serde(default = "default_retention_days")]
    pub alert_retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            sqlite_path: default_db_path(),
            alert_retention_days: default_retention_days(),
        }
    }
}

fn default_db_path() -> PathBuf {
    PathBuf::from("./txwatch.db")
}

fn default_retention_days() -> u32 {
    30
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AlertFormat {
    Json,
    Slack,
    Discord,
    Template,
}

impl Default for AlertFormat {
    fn default() -> Self {
        AlertFormat::Json
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookDefaults {
    #[serde(default = "default_webhook_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    #[serde(default = "default_concurrency")]
    pub max_concurrency: usize,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default)]
    pub allow_private_ips: bool,
    #[serde(default)]
    pub client_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub client_key_path: Option<PathBuf>,
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    #[serde(default = "default_circuit_breaker_threshold")]
    pub circuit_breaker_threshold: u32,
    #[serde(default = "default_circuit_breaker_reset_ms")]
    pub circuit_breaker_reset_ms: u64,
}

impl Default for WebhookDefaults {
    fn default() -> Self {
        Self {
            timeout_ms: default_webhook_timeout_ms(),
            max_attempts: default_max_attempts(),
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            max_concurrency: default_concurrency(),
            user_agent: default_user_agent(),
            allow_private_ips: false,
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
            circuit_breaker_threshold: default_circuit_breaker_threshold(),
            circuit_breaker_reset_ms: default_circuit_breaker_reset_ms(),
        }
    }
}

fn default_webhook_timeout_ms() -> u64 {
    10_000
}
fn default_max_attempts() -> u32 {
    5
}
fn default_initial_backoff_ms() -> u64 {
    500
}
fn default_max_backoff_ms() -> u64 {
    30_000
}
fn default_concurrency() -> usize {
    16
}
fn default_user_agent() -> String {
    concat!("txwatch/", env!("CARGO_PKG_VERSION")).to_string()
}
fn default_circuit_breaker_threshold() -> u32 {
    5
}
fn default_circuit_breaker_reset_ms() -> u64 {
    60_000
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl Default for AlertSeverity {
    fn default() -> Self {
        AlertSeverity::Info
    }
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Some(AlertSeverity::Info),
            "warning" | "warn" => Some(AlertSeverity::Warning),
            "critical" | "crit" | "error" => Some(AlertSeverity::Critical),
            _ => None,
        }
    }

    pub fn meets_minimum(&self, minimum: AlertSeverity) -> bool {
        *self >= minimum
    }
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WebhookEndpoint {
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub format: AlertFormat,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub min_severity: Option<AlertSeverity>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchedContract {
    pub id: String,
    pub label: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_secret: Option<String>,
    #[serde(default)]
    pub webhook_format: AlertFormat,
    #[serde(default)]
    pub webhook_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub webhook_template: Option<String>,
    #[serde(default)]
    pub webhook_content_type: Option<String>,
    #[serde(default)]
    pub webhooks: Vec<WebhookEndpoint>,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    #[serde(default)]
    pub start_ledger: Option<u64>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub mute_until: Option<String>,
    #[serde(default)]
    pub rate_limit: Option<ContractRateLimit>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ContractRateLimit {
    pub max_alerts: u32,
    pub window_seconds: u64,
}

impl WatchedContract {
    pub fn resolved_webhooks(&self) -> Vec<WebhookEndpoint> {
        let mut endpoints = Vec::new();
        if let Some(url) = self.webhook_url.as_ref().filter(|u| !u.trim().is_empty()) {
            endpoints.push(WebhookEndpoint {
                url: url.clone(),
                secret: self.webhook_secret.clone(),
                format: self.webhook_format.clone(),
                headers: self.webhook_headers.clone(),
                template: self.webhook_template.clone(),
                content_type: self.webhook_content_type.clone(),
                min_severity: None,
            });
        }
        endpoints.extend(self.webhooks.iter().cloned());
        endpoints
    }

    pub fn is_muted(&self) -> bool {
        let Some(raw) = self.mute_until.as_deref() else {
            return false;
        };
        let Ok(until) = chrono::DateTime::parse_from_rfc3339(raw) else {
            return false;
        };
        until.with_timezone(&Utc) > Utc::now()
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleConfig {
    #[serde(flatten)]
    pub rule: AlertRule,
    #[serde(default)]
    pub cooldown_seconds: u64,
    #[serde(default)]
    pub cooldown_summary: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_secret: Option<String>,
    #[serde(default)]
    pub severity: AlertSeverity,
}

impl From<AlertRule> for RuleConfig {
    fn from(rule: AlertRule) -> Self {
        Self {
            rule,
            cooldown_seconds: 0,
            cooldown_summary: false,
            enabled: true,
            webhook_url: None,
            webhook_secret: None,
            severity: AlertSeverity::Info,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Any,
    In,
    Out,
}

impl Default for TransferDirection {
    fn default() -> Self {
        TransferDirection::Any
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchOperator {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    Regex,
    Exists,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DataMatcher {
    pub pointer: String,
    pub op: MatchOperator,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleCombineMode {
    All,
    Any,
}

impl Default for RuleCombineMode {
    fn default() -> Self {
        RuleCombineMode::All
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AlertRule {
    AnyTransaction,
    FailedTransaction,
    FunctionCall {
        function: String,
        #[serde(default)]
        arg_contains: Option<String>,
        #[serde(default)]
        arg_regex: Option<String>,
    },
    EventEmitted {
        #[serde(default)]
        topic_contains: Option<String>,
        #[serde(default)]
        topic_regex: Option<String>,
        #[serde(default)]
        topics: Vec<Option<String>>,
        #[serde(default)]
        data_contains: Option<String>,
        #[serde(default)]
        data_match: Vec<DataMatcher>,
    },
    HighFee {
        #[serde(default)]
        threshold_stroops: u64,
        #[serde(default)]
        threshold_xlm: Option<f64>,
        #[serde(skip)]
        computed_threshold_stroops: u64,
    },
    LargeTransfer {
        threshold_stroops: u64,
        #[serde(default)]
        threshold_xlm: Option<u64>,
        #[serde(default)]
        asset: Option<String>,
        #[serde(default)]
        direction: TransferDirection,
    },
    SourceAccount {
        #[serde(default)]
        account: Option<String>,
        #[serde(default)]
        accounts: Vec<String>,
        #[serde(default)]
        match_muxed_base: bool,
    },
    Composite {
        #[serde(default)]
        mode: RuleCombineMode,
        #[serde(default)]
        rules: Vec<AlertRule>,
    },
    Not {
        rule: Box<AlertRule>,
    },
    RateSpike {
        max_transactions: u32,
        window_seconds: u64,
    },
    Inactivity {
        silence_seconds: u64,
        #[serde(default)]
        repeat_interval_seconds: Option<u64>,
    },
}

const KNOWN_RULE_TYPES: &[&str] = &[
    "AnyTransaction",
    "FailedTransaction",
    "FunctionCall",
    "EventEmitted",
    "HighFee",
    "LargeTransfer",
    "SourceAccount",
    "Composite",
    "Not",
    "RateSpike",
    "Inactivity",
];

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
enum AlertRuleRepr {
    AnyTransaction,
    FailedTransaction,
    FunctionCall {
        function: String,
        #[serde(default)]
        arg_contains: Option<String>,
        #[serde(default)]
        arg_regex: Option<String>,
    },
    EventEmitted {
        #[serde(default)]
        topic_contains: Option<String>,
        #[serde(default)]
        topic_regex: Option<String>,
        #[serde(default)]
        topics: Vec<Option<String>>,
        #[serde(default)]
        data_contains: Option<String>,
        #[serde(default)]
        data_match: Vec<DataMatcher>,
    },
    HighFee {
        #[serde(default)]
        threshold_stroops: u64,
        #[serde(default)]
        threshold_xlm: Option<f64>,
    },
    LargeTransfer {
        #[serde(default)]
        threshold_stroops: u64,
        #[serde(default)]
        threshold_xlm: Option<u64>,
        #[serde(default)]
        asset: Option<String>,
        #[serde(default)]
        direction: TransferDirection,
    },
    SourceAccount {
        #[serde(default)]
        account: Option<String>,
        #[serde(default)]
        accounts: Vec<String>,
        #[serde(default)]
        match_muxed_base: bool,
    },
    Composite {
        #[serde(default)]
        mode: RuleCombineMode,
        #[serde(default)]
        rules: Vec<AlertRule>,
    },
    Not {
        rule: Box<AlertRule>,
    },
    RateSpike {
        max_transactions: u32,
        window_seconds: u64,
    },
    Inactivity {
        silence_seconds: u64,
        #[serde(default)]
        repeat_interval_seconds: Option<u64>,
    },
}

impl From<AlertRuleRepr> for AlertRule {
    fn from(r: AlertRuleRepr) -> Self {
        match r {
            AlertRuleRepr::AnyTransaction => AlertRule::AnyTransaction,
            AlertRuleRepr::FailedTransaction => AlertRule::FailedTransaction,
            AlertRuleRepr::FunctionCall {
                function,
                arg_contains,
                arg_regex,
            } => AlertRule::FunctionCall {
                function,
                arg_contains,
                arg_regex,
            },
            AlertRuleRepr::EventEmitted {
                topic_contains,
                topic_regex,
                topics,
                data_contains,
                data_match,
            } => AlertRule::EventEmitted {
                topic_contains,
                topic_regex,
                topics,
                data_contains,
                data_match,
            },
            AlertRuleRepr::HighFee {
                threshold_stroops,
                threshold_xlm,
            } => AlertRule::HighFee {
                threshold_stroops,
                threshold_xlm,
                computed_threshold_stroops: threshold_stroops,
            },
            AlertRuleRepr::LargeTransfer {
                threshold_stroops,
                threshold_xlm,
                asset,
                direction,
            } => AlertRule::LargeTransfer {
                threshold_stroops,
                threshold_xlm,
                asset,
                direction,
            },
            AlertRuleRepr::SourceAccount {
                account,
                accounts,
                match_muxed_base,
            } => AlertRule::SourceAccount {
                account,
                accounts,
                match_muxed_base,
            },
            AlertRuleRepr::Composite { mode, rules } => AlertRule::Composite { mode, rules },
            AlertRuleRepr::Not { rule } => AlertRule::Not { rule },
            AlertRuleRepr::RateSpike {
                max_transactions,
                window_seconds,
            } => AlertRule::RateSpike {
                max_transactions,
                window_seconds,
            },
            AlertRuleRepr::Inactivity {
                silence_seconds,
                repeat_interval_seconds,
            } => AlertRule::Inactivity {
                silence_seconds,
                repeat_interval_seconds,
            },
        }
    }
}

impl From<&AlertRule> for AlertRuleRepr {
    fn from(r: &AlertRule) -> Self {
        match r {
            AlertRule::AnyTransaction => AlertRuleRepr::AnyTransaction,
            AlertRule::FailedTransaction => AlertRuleRepr::FailedTransaction,
            AlertRule::FunctionCall {
                function,
                arg_contains,
                arg_regex,
            } => AlertRuleRepr::FunctionCall {
                function: function.clone(),
                arg_contains: arg_contains.clone(),
                arg_regex: arg_regex.clone(),
            },
            AlertRule::EventEmitted {
                topic_contains,
                topic_regex,
                topics,
                data_contains,
                data_match,
            } => AlertRuleRepr::EventEmitted {
                topic_contains: topic_contains.clone(),
                topic_regex: topic_regex.clone(),
                topics: topics.clone(),
                data_contains: data_contains.clone(),
                data_match: data_match.clone(),
            },
            AlertRule::HighFee {
                threshold_stroops,
                threshold_xlm,
                ..
            } => AlertRuleRepr::HighFee {
                threshold_stroops: *threshold_stroops,
                threshold_xlm: *threshold_xlm,
            },
            AlertRule::LargeTransfer {
                threshold_stroops,
                threshold_xlm,
                asset,
                direction,
            } => AlertRuleRepr::LargeTransfer {
                threshold_stroops: *threshold_stroops,
                threshold_xlm: *threshold_xlm,
                asset: asset.clone(),
                direction: direction.clone(),
            },
            AlertRule::SourceAccount {
                account,
                accounts,
                match_muxed_base,
            } => AlertRuleRepr::SourceAccount {
                account: account.clone(),
                accounts: accounts.clone(),
                match_muxed_base: *match_muxed_base,
            },
            AlertRule::Composite { mode, rules } => AlertRuleRepr::Composite {
                mode: mode.clone(),
                rules: rules.clone(),
            },
            AlertRule::Not { rule } => AlertRuleRepr::Not { rule: rule.clone() },
            AlertRule::RateSpike {
                max_transactions,
                window_seconds,
            } => AlertRuleRepr::RateSpike {
                max_transactions: *max_transactions,
                window_seconds: *window_seconds,
            },
            AlertRule::Inactivity {
                silence_seconds,
                repeat_interval_seconds,
            } => AlertRuleRepr::Inactivity {
                silence_seconds: *silence_seconds,
                repeat_interval_seconds: *repeat_interval_seconds,
            },
        }
    }
}

impl<'de> Deserialize<'de> for AlertRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = toml::Value::deserialize(deserializer)?;
        if let Some(table) = value.as_table() {
            if let Some(toml::Value::String(ty)) = table.get("type") {
                if !KNOWN_RULE_TYPES.contains(&ty.as_str()) {
                    let suggestion = closest_rule_type(ty)
                        .map(|s| format!(" (did you mean '{s}'?)"))
                        .unwrap_or_default();
                    return Err(serde::de::Error::custom(format!(
                        "unknown rule type '{ty}'{suggestion}; expected one of: {}",
                        KNOWN_RULE_TYPES.join(", ")
                    )));
                }
            }
        }
        AlertRuleRepr::deserialize(value)
            .map(AlertRule::from)
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for AlertRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        AlertRuleRepr::from(self).serialize(serializer)
    }
}

fn closest_rule_type(input: &str) -> Option<&'static str> {
    let lower = input.to_ascii_lowercase();
    KNOWN_RULE_TYPES
        .iter()
        .filter_map(|candidate| {
            let d = levenshtein(&lower, &candidate.to_ascii_lowercase());
            (d <= 4).then_some((d, *candidate))
        })
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

impl AlertRule {
    pub fn label(&self) -> String {
        match self {
            AlertRule::AnyTransaction => "AnyTransaction".to_string(),
            AlertRule::FailedTransaction => "FailedTransaction".to_string(),
            AlertRule::FunctionCall { function, .. } => format!("FunctionCall:{function}"),
            AlertRule::EventEmitted {
                topic_contains,
                topic_regex,
                topics,
                ..
            } => {
                if let Some(t) = topic_contains {
                    format!("EventEmitted:{t}")
                } else if let Some(r) = topic_regex {
                    format!("EventEmitted:/{r}/")
                } else if !topics.is_empty() {
                    let rendered: Vec<&str> = topics
                        .iter()
                        .map(|t| t.as_deref().unwrap_or("*"))
                        .collect();
                    format!("EventEmitted:[{}]", rendered.join(","))
                } else {
                    "EventEmitted:*".to_string()
                }
            }
            AlertRule::HighFee {
                threshold_stroops,
                threshold_xlm,
                computed_threshold_stroops,
            } => {
                if *computed_threshold_stroops > 0 {
                    format!("HighFee>={computed_threshold_stroops}")
                } else if let Some(xlm) = threshold_xlm {
                    format!("HighFee>={xlm}XLM")
                } else {
                    format!("HighFee>={threshold_stroops}")
                }
            }
            AlertRule::LargeTransfer {
                threshold_stroops,
                threshold_xlm,
                asset,
                direction,
            } => {
                let effective = match threshold_xlm {
                    Some(xlm) if *threshold_stroops == 0 => xlm.saturating_mul(10_000_000),
                    _ => *threshold_stroops,
                };
                let dir_tag = match direction {
                    TransferDirection::Any => "",
                    TransferDirection::In => ":in",
                    TransferDirection::Out => ":out",
                };
                match asset {
                    Some(a) => format!("LargeTransfer:{a}{dir_tag}>={effective}"),
                    None => format!("LargeTransfer{dir_tag}>={effective}"),
                }
            }
            AlertRule::SourceAccount {
                account,
                accounts,
                match_muxed_base,
            } => {
                let mut all = Vec::new();
                if let Some(a) = account {
                    all.push(a.as_str());
                }
                for a in accounts {
                    all.push(a.as_str());
                }
                let tag = if *match_muxed_base { "+muxed" } else { "" };
                format!("SourceAccount{tag}:{}", all.join("|"))
            }
            AlertRule::Composite { mode, rules } => {
                let joiner = match mode {
                    RuleCombineMode::All => " && ",
                    RuleCombineMode::Any => " || ",
                };
                let inner: Vec<String> = rules.iter().map(|r| r.label()).collect();
                format!("({})", inner.join(joiner))
            }
            AlertRule::Not { rule } => format!("!({})", rule.label()),
            AlertRule::RateSpike {
                max_transactions,
                window_seconds,
            } => format!("RateSpike>{max_transactions}/{window_seconds}s"),
            AlertRule::Inactivity {
                silence_seconds, ..
            } => format!("Inactivity>={silence_seconds}s"),
        }
    }

    pub fn effective_threshold_stroops(&self) -> Option<u64> {
        match self {
            AlertRule::LargeTransfer {
                threshold_stroops,
                threshold_xlm,
                ..
            } => match threshold_xlm {
                Some(xlm) if *threshold_stroops == 0 => Some(xlm.saturating_mul(10_000_000)),
                _ => Some(*threshold_stroops),
            },
            AlertRule::HighFee {
                threshold_stroops,
                computed_threshold_stroops,
                ..
            } => Some((*threshold_stroops).max(*computed_threshold_stroops)),
            _ => None,
        }
    }

    pub fn configured_accounts(&self) -> Vec<&str> {
        match self {
            AlertRule::SourceAccount {
                account, accounts, ..
            } => {
                let mut out = Vec::new();
                if let Some(a) = account.as_deref() {
                    if !a.is_empty() {
                        out.push(a);
                    }
                }
                for a in accounts {
                    if !a.is_empty() && !out.contains(&a.as_str()) {
                        out.push(a.as_str());
                    }
                }
                out
            }
            _ => Vec::new(),
        }
    }
}

pub fn load_from_path(path: impl AsRef<Path>) -> Result<AppConfig, ConfigError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadError {
        path: path.to_path_buf(),
        source,
    })?;
    let mut config = parse_toml_with_path(&raw, path)?;

    if !config.include.is_empty() {
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut seen = HashSet::new();
        if let Ok(canon) = std::fs::canonicalize(path) {
            seen.insert(canon);
        }
        let patterns = std::mem::take(&mut config.include);
        let mut include_errors = Vec::new();
        for pattern in &patterns {
            let resolved_pattern = if Path::new(pattern).is_absolute() {
                pattern.clone()
            } else {
                base_dir.join(pattern).to_string_lossy().into_owned()
            };
            let matches: Vec<_> = match glob(&resolved_pattern) {
                Ok(paths) => paths.collect(),
                Err(err) => {
                    include_errors.push(format!("invalid include glob '{pattern}': {err}"));
                    continue;
                }
            };
            let mut matched_any = false;
            for entry in matches {
                let inc_path = match entry {
                    Ok(p) => p,
                    Err(err) => {
                        include_errors
                            .push(format!("error expanding include glob '{pattern}': {err}"));
                        continue;
                    }
                };
                if inc_path.is_dir() {
                    continue;
                }
                matched_any = true;
                if let Ok(canon) = std::fs::canonicalize(&inc_path) {
                    if !seen.insert(canon) {
                        continue;
                    }
                }
                let inc_raw =
                    std::fs::read_to_string(&inc_path).map_err(|source| ConfigError::ReadError {
                        path: inc_path.clone(),
                        source,
                    })?;
                let fragment = parse_include_fragment(&inc_raw, &inc_path)?;
                config.contracts.extend(fragment.contracts);
            }
            if !matched_any {
                include_errors.push(format!(
                    "include pattern '{pattern}' matched no contract files"
                ));
            }
        }
        if !include_errors.is_empty() {
            return Err(ConfigError::Validation(include_errors));
        }
    }

    config.validate()?;
    Ok(config)
}

#[derive(Debug, Default, Deserialize)]
struct IncludeFragment {
    #[serde(default)]
    contracts: Vec<WatchedContract>,
}

fn parse_include_fragment(raw: &str, path: &Path) -> Result<IncludeFragment, ConfigError> {
    let mut table: toml::Value = toml::from_str(raw).map_err(|source| ConfigError::ParseError {
        path: path.to_path_buf(),
        source,
    })?;
    interpolate_toml_value(&mut table, "$include")?;
    table.try_into().map_err(|source| ConfigError::ParseError {
        path: path.to_path_buf(),
        source,
    })
}

pub fn parse_toml_str(raw: &str) -> Result<AppConfig, ConfigError> {
    let mut config = parse_toml_with_path(raw, Path::new("<memory>"))?;
    config.validate()?;
    Ok(config)
}

fn parse_toml_with_path(raw: &str, path: &Path) -> Result<AppConfig, ConfigError> {
    let mut table: toml::Value = toml::from_str(raw).map_err(|source| ConfigError::ParseError {
        path: path.to_path_buf(),
        source,
    })?;
    interpolate_toml_value(&mut table, "$")?;
    let config: AppConfig = table.try_into().map_err(|source| ConfigError::ParseError {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(config)
}

/// Replace `${VAR}` or `${VAR:-default}` references inside any TOML string value.
///
/// Escaping: `\${` produces a literal `${` without looking up an environment variable, so
/// values like webhook secrets or regex patterns containing `${...}` can be expressed
/// safely. `\\` before `${` produces a literal `\` followed by normal interpolation.
fn interpolate_toml_value(value: &mut toml::Value, path: &str) -> Result<(), ConfigError> {
    match value {
        toml::Value::String(s) => {
            *s = interpolate_env_string(s, path)?;
        }
        toml::Value::Array(items) => {
            for (idx, item) in items.iter_mut().enumerate() {
                interpolate_toml_value(item, &format!("{path}[{idx}]"))?;
            }
        }
        toml::Value::Table(map) => {
            for (k, v) in map.iter_mut() {
                interpolate_toml_value(v, &format!("{path}.{k}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn interpolate_env_string(input: &str, field: &str) -> Result<String, ConfigError> {
    if !input.contains("${") {
        return Ok(input.to_string());
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        let prefix = &rest[..start];
        let trailing_slashes = prefix.bytes().rev().take_while(|&b| b == b'\\').count();
        if trailing_slashes > 0 {
            out.push_str(&prefix[..prefix.len() - trailing_slashes]);
            for _ in 0..(trailing_slashes / 2) {
                out.push('\\');
            }
            if trailing_slashes % 2 == 1 {
                out.push_str("${");
                rest = &rest[start + 2..];
                continue;
            }
        } else {
            out.push_str(prefix);
        }

        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return Err(ConfigError::EnvInterpolation {
                field: field.to_string(),
                reason: "unclosed '${' placeholder".to_string(),
            });
        };
        let expr = &after[..end];
        let (var_name, default_val) = match expr.split_once(":-") {
            Some((name, def)) => (name.trim(), Some(def)),
            None => (expr.trim(), None),
        };
        if var_name.is_empty() {
            return Err(ConfigError::EnvInterpolation {
                field: field.to_string(),
                reason: "empty variable name in '${}'".to_string(),
            });
        }
        match std::env::var(var_name) {
            Ok(val) if !val.is_empty() => out.push_str(&val),
            _ => match default_val {
                Some(def) => out.push_str(def),
                None => {
                    return Err(ConfigError::EnvInterpolation {
                        field: field.to_string(),
                        reason: format!("environment variable '{var_name}' is not set"),
                    });
                }
            },
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

impl AppConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        match self.network.resolved_horizon_url() {
            Some(url) => {
                if let Err(reason) = validate_http_url(url, true) {
                    errors.push(format!("network.horizon_url: {reason}"));
                }
            }
            None => {
                errors.push(
                    "network.horizon_url is required when network.kind = \"custom\"".to_string(),
                );
            }
        }

        if let Some(rpc) = self.network.rpc_url.as_deref() {
            if !rpc.trim().is_empty() {
                if let Err(reason) = validate_http_url(rpc, true) {
                    errors.push(format!("network.rpc_url: {reason}"));
                }
            }
        }

        if self.network.resolved_passphrase().is_none() {
            errors.push(
                "network.network_passphrase is required when network.kind = \"custom\"".to_string(),
            );
        }

        if self.network.poll_interval_ms < 250 {
            errors.push(format!(
                "network.poll_interval_ms ({}) must be at least 250ms",
                self.network.poll_interval_ms
            ));
        }

        if !(1..=200).contains(&self.network.page_limit) {
            errors.push(format!(
                "network.page_limit ({}) must be between 1 and 200",
                self.network.page_limit
            ));
        }

        if !self.server.metrics_path.starts_with('/') {
            errors.push("server.metrics_path must start with '/'".to_string());
        }

        if self.server.bind.parse::<std::net::SocketAddr>().is_err() {
            errors.push(format!(
                "server.bind ('{}') is not a valid host:port socket address",
                self.server.bind
            ));
        }

        if self.webhook.max_attempts == 0 {
            errors.push("webhook.max_attempts must be >= 1".to_string());
        }
        if self.webhook.timeout_ms < 100 {
            errors.push("webhook.timeout_ms must be >= 100ms".to_string());
        }
        if self.webhook.max_concurrency == 0 {
            errors.push("webhook.max_concurrency must be >= 1".to_string());
        }
        if self.webhook.initial_backoff_ms == 0
            || self.webhook.max_backoff_ms < self.webhook.initial_backoff_ms
        {
            errors.push(
                "webhook.max_backoff_ms must be >= webhook.initial_backoff_ms > 0".to_string(),
            );
        }

        match (&self.webhook.client_cert_path, &self.webhook.client_key_path) {
            (Some(_), None) => {
                errors.push(
                    "webhook.client_key_path is required when webhook.client_cert_path is set"
                        .to_string(),
                );
            }
            (None, Some(_)) => {
                errors.push(
                    "webhook.client_cert_path is required when webhook.client_key_path is set"
                        .to_string(),
                );
            }
            (Some(cert), Some(key)) => {
                if !cert.is_file() {
                    errors.push(format!(
                        "webhook.client_cert_path ('{}') does not exist or is not a file",
                        cert.display()
                    ));
                }
                if !key.is_file() {
                    errors.push(format!(
                        "webhook.client_key_path ('{}') does not exist or is not a file",
                        key.display()
                    ));
                }
            }
            (None, None) => {}
        }

        if let Some(ca) = &self.webhook.ca_cert_path {
            if !ca.is_file() {
                errors.push(format!(
                    "webhook.ca_cert_path ('{}') does not exist or is not a file",
                    ca.display()
                ));
            }
        }

        if self.webhook.circuit_breaker_threshold == 0 {
            errors.push("webhook.circuit_breaker_threshold must be >= 1".to_string());
        }
        if self.webhook.circuit_breaker_reset_ms < 100 {
            errors.push("webhook.circuit_breaker_reset_ms must be >= 100ms".to_string());
        }

        if self.contracts.is_empty() {
            errors.push("at least one [[contracts]] entry must be configured".to_string());
        }

        let mut seen_ids = HashMap::new();
        let mut seen_labels = HashSet::new();
        for (idx, contract) in self.contracts.iter_mut().enumerate() {
            let prefix = format!("contracts[{idx}]");
            if contract.label.trim().is_empty() {
                errors.push(format!("{prefix}.label must not be empty"));
            } else if !seen_labels.insert(contract.label.clone()) {
                errors.push(format!(
                    "{prefix}.label ('{}') is duplicated; labels must be unique",
                    contract.label
                ));
            }

            if let Err(reason) = validate_contract_id(&contract.id) {
                errors.push(format!("{prefix}.id ('{}'): {reason}", contract.id));
            } else if let Some(prev) = seen_ids.insert(contract.id.clone(), idx) {
                errors.push(format!(
                    "{prefix}.id ('{}') duplicates contracts[{prev}]",
                    contract.id
                ));
            }

            if let Some(until) = contract.mute_until.as_deref() {
                if chrono::DateTime::parse_from_rfc3339(until).is_err() {
                    errors.push(format!(
                        "{prefix}.mute_until ('{until}') must be a valid RFC-3339 timestamp"
                    ));
                }
            }

            if let Some(rl) = &contract.rate_limit {
                if rl.max_alerts == 0 {
                    errors.push(format!("{prefix}.rate_limit.max_alerts must be >= 1"));
                }
                if rl.window_seconds == 0 {
                    errors.push(format!("{prefix}.rate_limit.window_seconds must be >= 1"));
                }
            }

            let endpoints = contract.resolved_webhooks();
            if endpoints.is_empty() {
                errors.push(format!(
                    "{prefix} ('{}') has no webhook destination; set webhook_url or at least one [[contracts.webhooks]] entry",
                    contract.label
                ));
            }
            for (ep_idx, ep) in endpoints.iter().enumerate() {
                let ep_label = if contract.webhook_url.is_some() && ep_idx == 0 {
                    format!("{prefix}.webhook_url")
                } else {
                    let sub_idx = if contract.webhook_url.is_some() {
                        ep_idx - 1
                    } else {
                        ep_idx
                    };
                    format!("{prefix}.webhooks[{sub_idx}]")
                };
                if let Err(reason) = validate_http_url(&ep.url, self.webhook.allow_private_ips) {
                    errors.push(format!("{ep_label}.url: {reason}"));
                }
                if ep.format == AlertFormat::Template {
                    match ep.template.as_deref() {
                        Some(tpl) if !tpl.trim().is_empty() => {}
                        _ => errors.push(format!(
                            "{ep_label} uses format = \"template\" but no template string was provided"
                        )),
                    }
                } else if ep.template.is_some() {
                    errors.push(format!(
                        "{ep_label} sets a template string without format = \"template\""
                    ));
                }
                if let Some(ct) = ep.content_type.as_deref() {
                    if ct.trim().is_empty() {
                        errors.push(format!("{ep_label}.content_type must not be empty"));
                    } else if ep.format != AlertFormat::Template {
                        errors.push(format!(
                            "{ep_label}.content_type is only supported with format = \"template\""
                        ));
                    }
                }
                for header_name in ep.headers.keys() {
                    if header_name.trim().is_empty()
                        || header_name.chars().any(|c| c.is_control() || c == ':')
                    {
                        errors.push(format!(
                            "{ep_label}.headers contains invalid header name '{header_name}'"
                        ));
                    }
                }
            }

            if contract.rules.is_empty() {
                errors.push(format!(
                    "{prefix} ('{}') has no rules configured",
                    contract.label
                ));
            }
            for (r_idx, rule_cfg) in contract.rules.iter_mut().enumerate() {
                if let Some(url) = rule_cfg.webhook_url.as_deref() {
                    if let Err(reason) = validate_http_url(url, self.webhook.allow_private_ips) {
                        errors.push(format!("{prefix}.rules[{r_idx}].webhook_url: {reason}"));
                    }
                }
                if rule_cfg.cooldown_summary && rule_cfg.cooldown_seconds == 0 {
                    errors.push(format!(
                        "{prefix}.rules[{r_idx}].cooldown_summary requires cooldown_seconds > 0"
                    ));
                }
                validate_rule(
                    &mut rule_cfg.rule,
                    &format!("{prefix}.rules[{r_idx}]"),
                    &mut errors,
                );
            }
        }

        if !errors.is_empty() {
            return Err(ConfigError::Validation(errors));
        }

        Ok(())
    }

    pub fn webhook_timeout(&self) -> Duration {
        Duration::from_millis(self.webhook.timeout_ms)
    }

    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.network.poll_interval_ms)
    }
}

fn validate_rule(rule: &mut AlertRule, path: &str, errors: &mut Vec<String>) {
    match rule {
        AlertRule::FunctionCall {
            function,
            arg_regex,
            ..
        } => {
            if function.trim().is_empty() {
                errors.push(format!("{path}.function must not be empty"));
            }
            if let Some(pattern) = arg_regex {
                if let Err(e) = Regex::new(pattern) {
                    errors.push(format!("{path}.arg_regex ('{pattern}') invalid: {e}"));
                }
            }
        }
        AlertRule::EventEmitted {
            topic_regex,
            topics,
            data_match,
            ..
        } => {
            if let Some(pattern) = topic_regex {
                if let Err(e) = Regex::new(pattern) {
                    errors.push(format!("{path}.topic_regex ('{pattern}') invalid: {e}"));
                }
            }
            if topics.iter().any(|t| matches!(t.as_deref(), Some(""))) {
                errors.push(format!(
                    "{path}.topics must not contain empty string entries (omit or use null to wildcard a position)"
                ));
            }
            for (m_idx, matcher) in data_match.iter().enumerate() {
                let m_path = format!("{path}.data_match[{m_idx}]");
                if !matcher.pointer.is_empty() && !matcher.pointer.starts_with('/') {
                    errors.push(format!(
                        "{m_path}.pointer ('{}') must be empty or start with '/' (RFC 6901 JSON Pointer)",
                        matcher.pointer
                    ));
                }
                match matcher.op {
                    MatchOperator::Exists => {}
                    MatchOperator::Regex => match matcher.value.as_deref() {
                        Some(pat) if !pat.is_empty() => {
                            if let Err(e) = Regex::new(pat) {
                                errors.push(format!("{m_path}.value ('{pat}') invalid regex: {e}"));
                            }
                        }
                        _ => errors.push(format!(
                            "{m_path}.value is required for operator 'regex'"
                        )),
                    },
                    MatchOperator::Gt
                    | MatchOperator::Gte
                    | MatchOperator::Lt
                    | MatchOperator::Lte => match matcher.value.as_deref() {
                        Some(v) if v.trim().parse::<f64>().is_ok() => {}
                        Some(v) => errors.push(format!(
                            "{m_path}.value ('{v}') must be numeric for comparison operator"
                        )),
                        None => errors.push(format!(
                            "{m_path}.value is required for comparison operator"
                        )),
                    },
                    MatchOperator::Eq | MatchOperator::Neq | MatchOperator::Contains => {
                        if matcher.value.is_none() {
                            errors.push(format!("{m_path}.value is required"));
                        }
                    }
                }
            }
        }
        AlertRule::HighFee {
            threshold_stroops,
            threshold_xlm,
            computed_threshold_stroops,
        } => {
            const MAX_STROOPS: u64 = 100_000_000_000_000_000;
            const MAX_XLM: f64 = 10_000_000_000.0;
            const STROOPS_PER_XLM: f64 = 10_000_000.0;

            match (*threshold_stroops, *threshold_xlm) {
                (0, None) => {
                    errors.push(format!(
                        "{path}: must specify either threshold_stroops > 0 or threshold_xlm > 0"
                    ));
                }
                (s, Some(_)) if s > 0 => {
                    errors.push(format!(
                        "{path}: specify only one of threshold_stroops or threshold_xlm, not both"
                    ));
                }
                (s, None) => {
                    if s > MAX_STROOPS {
                        errors.push(format!(
                            "{path}.threshold_stroops ({s}) exceeds maximum realistic value ({MAX_STROOPS})"
                        ));
                    } else {
                        *computed_threshold_stroops = s;
                    }
                }
                (0, Some(xlm)) => {
                    if !xlm.is_finite() || xlm <= 0.0 {
                        errors.push(format!(
                            "{path}.threshold_xlm ({xlm}) must be finite and greater than 0"
                        ));
                    } else if xlm > MAX_XLM {
                        errors.push(format!(
                            "{path}.threshold_xlm ({xlm}) exceeds maximum realistic value ({MAX_XLM} XLM)"
                        ));
                    } else {
                        let stroops = (xlm * STROOPS_PER_XLM).round() as u64;
                        if stroops == 0 {
                            errors.push(format!(
                                "{path}.threshold_xlm ({xlm}) rounds to 0 stroops; minimum is 0.0000001 XLM (1 stroop)"
                            ));
                        } else {
                            *computed_threshold_stroops = stroops;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        AlertRule::LargeTransfer {
            threshold_stroops,
            threshold_xlm,
            asset,
            ..
        } => {
            if *threshold_stroops == 0 && threshold_xlm.is_none() {
                errors.push(format!(
                    "{path}: LargeTransfer must specify threshold_stroops > 0 or threshold_xlm > 0"
                ));
            }
            if *threshold_stroops > 0 && threshold_xlm.is_some() {
                errors.push(format!(
                    "{path}: LargeTransfer cannot set both threshold_stroops and threshold_xlm"
                ));
            }
            if let Some(0) = threshold_xlm {
                errors.push(format!("{path}.threshold_xlm must be > 0"));
            }
            if let Some(a) = asset.as_deref() {
                if !a.eq_ignore_ascii_case("XLM") && !a.eq_ignore_ascii_case("native") {
                    match a.split_once(':') {
                        Some((code, issuer)) => {
                            if code.is_empty() || code.len() > 12 {
                                errors.push(format!(
                                    "{path}.asset ('{a}'): asset code must be 1..=12 chars"
                                ));
                            }
                            if let Err(reason) = validate_stellar_address(issuer) {
                                errors.push(format!("{path}.asset ('{a}'): issuer {reason}"));
                            }
                        }
                        None => errors.push(format!(
                            "{path}.asset ('{a}') must be 'XLM' or '<CODE>:<ISSUER_G_ADDRESS>'"
                        )),
                    }
                }
            }
        }
        AlertRule::SourceAccount {
            account, accounts, ..
        } => {
            let mut all: Vec<&str> = Vec::new();
            if let Some(a) = account.as_deref() {
                if !a.trim().is_empty() {
                    all.push(a);
                }
            }
            for a in accounts {
                all.push(a.as_str());
            }
            if all.is_empty() {
                errors.push(format!(
                    "{path}: SourceAccount requires `account` or at least one entry in `accounts`"
                ));
            }
            for addr in all {
                if let Err(reason) = validate_stellar_address(addr) {
                    errors.push(format!("{path} ('{addr}'): {reason}"));
                }
            }
        }
        AlertRule::Composite { rules, .. } => {
            if rules.len() < 2 {
                errors.push(format!(
                    "{path}: Composite rule requires at least 2 child rules"
                ));
            }
            for (idx, child) in rules.iter_mut().enumerate() {
                validate_rule(child, &format!("{path}.rules[{idx}]"), errors);
            }
        }
        AlertRule::Not { rule: inner } => {
            validate_rule(inner, &format!("{path}.rule"), errors);
        }
        AlertRule::RateSpike {
            max_transactions,
            window_seconds,
        } => {
            if *max_transactions == 0 {
                errors.push(format!("{path}.max_transactions must be >= 1"));
            }
            if *window_seconds == 0 {
                errors.push(format!("{path}.window_seconds must be >= 1"));
            }
        }
        AlertRule::Inactivity {
            silence_seconds,
            repeat_interval_seconds,
        } => {
            if *silence_seconds == 0 {
                errors.push(format!("{path}.silence_seconds must be >= 1"));
            }
            if let Some(0) = repeat_interval_seconds {
                errors.push(format!(
                    "{path}.repeat_interval_seconds must be >= 1 when set"
                ));
            }
        }
        AlertRule::AnyTransaction | AlertRule::FailedTransaction => {}
    }
}

/// Validates a Soroban StrKey contract ID (`C...`, 56 uppercase base32 chars, version byte 0x10,
/// valid CRC16-XModem checksum).
pub fn validate_contract_id(id: &str) -> Result<(), String> {
    if id.len() != 56 {
        return Err(format!("expected 56 characters, got {}", id.len()));
    }
    if !id.starts_with('C') {
        return Err("contract ID must start with 'C'".to_string());
    }
    let decoded = decode_strkey_base32(id)?;
    // Version byte for StrKey contract IDs is 2 << 3 = 16 (0x10).
    if decoded[0] != 0x10 {
        return Err(format!(
            "unexpected StrKey version byte 0x{:02x}",
            decoded[0]
        ));
    }
    let expected_crc = crc16_xmodem(&decoded[..33]);
    let actual_crc = u16::from_le_bytes([decoded[33], decoded[34]]);
    if expected_crc != actual_crc {
        return Err(format!(
            "invalid StrKey CRC16 checksum (expected 0x{expected_crc:04x}, got 0x{actual_crc:04x})"
        ));
    }
    Ok(())
}

/// Validates a Stellar StrKey account address (`G...` ed25519 public key or `M...` muxed account,
/// version byte 0x30 or 0x60, valid CRC16-XModem checksum).
pub fn validate_stellar_address(account: &str) -> Result<(), String> {
    if account.is_empty() {
        return Err("Stellar account address must not be empty".to_string());
    }

    if account.starts_with('G') {
        if account.len() != 56 {
            return Err(format!(
                "G-account must be 56 characters, got {}",
                account.len()
            ));
        }
        let decoded = decode_strkey_base32(account)?;
        if decoded.len() != 35 {
            return Err("invalid G-account decoded length".to_string());
        }
        // Version byte for Ed25519 public key is 6 << 3 = 48 (0x30).
        if decoded[0] != 0x30 {
            return Err(format!(
                "unexpected StrKey version byte 0x{:02x} for G-account",
                decoded[0]
            ));
        }
        let expected_crc = crc16_xmodem(&decoded[..33]);
        let actual_crc = u16::from_le_bytes([decoded[33], decoded[34]]);
        if expected_crc != actual_crc {
            return Err("invalid StrKey CRC16 checksum".to_string());
        }
        Ok(())
    } else if account.starts_with('M') {
        if account.len() != 69 {
            return Err(format!(
                "muxed M-account must be 69 characters, got {}",
                account.len()
            ));
        }
        let decoded = decode_strkey_base32(account)?;
        if decoded.len() != 43 {
            return Err("invalid M-account decoded length".to_string());
        }
        // Version byte for muxed Ed25519 account is 12 << 3 = 96 (0x60).
        if decoded[0] != 0x60 {
            return Err(format!(
                "unexpected StrKey version byte 0x{:02x} for M-account",
                decoded[0]
            ));
        }
        let expected_crc = crc16_xmodem(&decoded[..41]);
        let actual_crc = u16::from_le_bytes([decoded[41], decoded[42]]);
        if expected_crc != actual_crc {
            return Err("invalid StrKey CRC16 checksum".to_string());
        }
        Ok(())
    } else {
        Err("Stellar address must start with 'G' or 'M'".to_string())
    }
}

fn decode_strkey_base32(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((input.len() * 5) / 8);
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    for b in input.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => {
                return Err(format!(
                    "invalid base32 character '{}' in StrKey",
                    b as char
                ));
            }
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Validates a webhook or Horizon URL, optionally rejecting loopback/private/link-local hosts
/// to protect against SSRF when webhook URLs are operator- or API-supplied.
pub fn validate_http_url(raw: &str, allow_private_ips: bool) -> Result<(), String> {
    let parsed = Url::parse(raw).map_err(|e| format!("invalid URL: {e}"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_private_ips => {}
        "http" => {
            return Err(
                "plaintext http:// URLs are disallowed unless webhook.allow_private_ips = true"
                    .to_string(),
            );
        }
        other => return Err(format!("unsupported URL scheme '{other}'")),
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must contain a host".to_string())?;
    if !allow_private_ips {
        let lower = host.to_ascii_lowercase();
        if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
            return Err(format!("host '{host}' points to a local/loopback address"));
        }
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            if is_disallowed_ip(ip) {
                return Err(format!("IP address {ip} is in a private or reserved range"));
            }
        }
    }
    Ok(())
}

fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64 // CGNAT 100.64/10
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Generates a valid Soroban `C...` StrKey contract ID from 32 payload bytes.
pub fn encode_contract_id(payload: &[u8; 32]) -> String {
    encode_strkey(0x10, payload)
}

/// Generates a valid Stellar `G...` StrKey Ed25519 public key from 32 payload bytes.
pub fn encode_account_id(payload: &[u8; 32]) -> String {
    encode_strkey(0x30, payload)
}

fn encode_strkey(version: u8, payload: &[u8; 32]) -> String {
    let mut raw = [0u8; 35];
    raw[0] = version;
    raw[1..33].copy_from_slice(payload);
    let crc = crc16_xmodem(&raw[..33]).to_le_bytes();
    raw[33] = crc[0];
    raw[34] = crc[1];

    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(56);
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    for &byte in &raw {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub path: Option<PathBuf>,
    pub config: AppConfig,
}

#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    pub generation: u64,
    pub path: Option<PathBuf>,
    pub config: AppConfig,
    pub loaded_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadDiff {
    pub generation: u64,
    pub added_contracts: Vec<String>,
    pub removed_contracts: Vec<String>,
    pub updated_contracts: Vec<String>,
    pub unchanged_contracts: Vec<String>,
    pub network_changed: bool,
}

impl ReloadDiff {
    pub fn has_contract_changes(&self) -> bool {
        !self.added_contracts.is_empty()
            || !self.removed_contracts.is_empty()
            || !self.updated_contracts.is_empty()
    }
}

pub struct ConfigManager {
    inner: std::sync::RwLock<ConfigSnapshot>,
    reload_lock: std::sync::Mutex<()>,
}

impl ConfigManager {
    pub fn new(path: Option<PathBuf>, config: AppConfig) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            inner: std::sync::RwLock::new(ConfigSnapshot {
                generation: 1,
                path,
                config,
                loaded_at_unix: now,
            }),
            reload_lock: std::sync::Mutex::new(()),
        }
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let p = path.as_ref().to_path_buf();
        let cfg = load_from_path(&p)?;
        Ok(Self::new(Some(p), cfg))
    }

    pub fn current(&self) -> ConfigSnapshot {
        self.inner
            .read()
            .expect("config lock poisoned")
            .clone()
    }

    pub fn generation(&self) -> u64 {
        self.inner.read().expect("config lock poisoned").generation
    }

    pub fn reload_from_disk(&self) -> Result<ReloadDiff, ConfigError> {
        let _guard = self.reload_lock.lock().expect("reload lock poisoned");
        let path = self
            .inner
            .read()
            .expect("config lock poisoned")
            .path
            .clone()
            .ok_or_else(|| {
                ConfigError::Validation(vec![
                    "cannot reload configuration: no file path associated with ConfigManager"
                        .to_string(),
                ])
            })?;

        let new_cfg = load_from_path(&path)?;
        self.apply_new_config(new_cfg)
    }

    pub fn reload_from_str(&self, raw: &str) -> Result<ReloadDiff, ConfigError> {
        let _guard = self.reload_lock.lock().expect("reload lock poisoned");
        let new_cfg = parse_toml_str(raw)?;
        self.apply_new_config(new_cfg)
    }

    pub fn apply_new_config(&self, new_cfg: AppConfig) -> Result<ReloadDiff, ConfigError> {
        let mut snap = self.inner.write().expect("config lock poisoned");
        let old_cfg = &snap.config;
        let diff = compute_diff(snap.generation + 1, old_cfg, &new_cfg);
        snap.generation += 1;
        snap.config = new_cfg;
        snap.loaded_at_unix = chrono::Utc::now().timestamp();
        info!(
            generation = snap.generation,
            added = ?diff.added_contracts,
            removed = ?diff.removed_contracts,
            updated = ?diff.updated_contracts,
            "reloaded configuration"
        );
        Ok(diff)
    }
}

fn contract_fingerprint(c: &WatchedContract) -> String {
    serde_json::to_string(c).unwrap_or_default()
}

fn compute_diff(generation: u64, old: &AppConfig, new: &AppConfig) -> ReloadDiff {
    let old_map: HashMap<&str, &WatchedContract> =
        old.contracts.iter().map(|c| (c.id.as_str(), c)).collect();
    let new_map: HashMap<&str, &WatchedContract> =
        new.contracts.iter().map(|c| (c.id.as_str(), c)).collect();

    let mut added_contracts = Vec::new();
    let mut updated_contracts = Vec::new();
    let mut unchanged_contracts = Vec::new();
    for (id, new_c) in &new_map {
        match old_map.get(id) {
            None => added_contracts.push((*id).to_string()),
            Some(old_c) => {
                if contract_fingerprint(old_c) != contract_fingerprint(new_c) {
                    updated_contracts.push((*id).to_string());
                } else {
                    unchanged_contracts.push((*id).to_string());
                }
            }
        }
    }

    let mut removed_contracts: Vec<String> = old_map
        .keys()
        .filter(|id| !new_map.contains_key(*id))
        .map(|id| (*id).to_string())
        .collect();

    added_contracts.sort();
    removed_contracts.sort();
    updated_contracts.sort();
    unchanged_contracts.sort();

    let network_changed = old.network.resolved_horizon_url() != new.network.resolved_horizon_url()
        || old.network.resolved_passphrase() != new.network.resolved_passphrase()
        || old.network.poll_interval_ms != new.network.poll_interval_ms;

    debug!(generation, ?added_contracts, ?removed_contracts, ?updated_contracts, "computed config diff");

    ReloadDiff {
        generation,
        added_contracts,
        removed_contracts,
        updated_contracts,
        unchanged_contracts,
        network_changed,
    }
}

/// Ensures global config lookup works cleanly in helper paths without needing thread-locals.
static VERSION_BANNER: OnceLock<&'static str> = OnceLock::new();

pub fn version_banner() -> &'static str {
    VERSION_BANNER.get_or_init(|| concat!("txwatch/", env!("CARGO_PKG_VERSION")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn valid_contract_id_round_trips() {
        let id = encode_contract_id(&[7u8; 32]);
        assert_eq!(id.len(), 56);
        assert!(id.starts_with('C'));
        assert!(validate_contract_id(&id).is_ok());

        let mut tampered = id.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert!(validate_contract_id(&tampered).is_err());
    }

    #[test]
    fn env_interpolation_supports_defaults_and_errors() {
        std::env::set_var("TXWATCH_TEST_SECRET", "s3cr3t");
        let raw = r#"
[network]
kind = "testnet"

[[contracts]]
id = "${TXWATCH_TEST_CID}"
label = "test-contract"
webhook_url = "https://example.com/hook"
webhook_secret = "${TXWATCH_TEST_SECRET}"

[[contracts.rules]]
type = "AnyTransaction"
"#;
        let cid = encode_contract_id(&[1u8; 32]);
        std::env::set_var("TXWATCH_TEST_CID", &cid);
        let cfg = parse_toml_str(raw).expect("config should parse");
        assert_eq!(cfg.contracts[0].id, cid);
        assert_eq!(
            cfg.contracts[0].webhook_secret.as_deref(),
            Some("s3cr3t")
        );

        let with_default =
            interpolate_env_string("${TXWATCH_UNSET_VAR:-fallback}", "field").unwrap();
        assert_eq!(with_default, "fallback");

        let err = interpolate_env_string("${TXWATCH_UNSET_VAR}", "field").unwrap_err();
        assert!(err.to_string().contains("TXWATCH_UNSET_VAR"));
    }

    #[test]
    fn rejects_private_webhook_urls_by_default() {
        assert!(validate_http_url("http://127.0.0.1:9000/hook", false).is_err());
        assert!(validate_http_url("https://127.0.0.1:9000/hook", false).is_err());
        assert!(validate_http_url("https://localhost/hook", false).is_err());
        assert!(validate_http_url("https://10.0.0.5/hook", false).is_err());
        assert!(validate_http_url("https://192.168.1.1/hook", false).is_err());
        assert!(validate_http_url("https://169.254.169.254/latest/meta-data", false).is_err());
        assert!(validate_http_url("https://hooks.example.com/txwatch", false).is_ok());
        assert!(validate_http_url("http://127.0.0.1:9000/hook", true).is_ok());
    }

    #[test]
    fn validates_data_matchers_and_topics() {
        let cid = encode_contract_id(&[9u8; 32]);
        let bad = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "bad-matcher"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "EventEmitted"
topics = ["transfer", ""]
data_match = [{{ pointer = "no_leading_slash", op = "gt", value = "not_a_number" }}]
"#
        );
        let err = parse_toml_str(&bad).unwrap_err().to_string();
        assert!(err.contains("topics"));
        assert!(err.contains("JSON Pointer"));
        assert!(err.contains("numeric"));
    }

    #[test]
    fn rejects_unknown_rule_type_with_suggestion() {
        let cid = encode_contract_id(&[4u8; 32]);
        let bad = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "typo-rule"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "FunctonCall"
function = "swap"
"#
        );
        let err = parse_toml_str(&bad).unwrap_err().to_string();
        assert!(err.contains("unknown rule type 'FunctonCall'"));
        assert!(err.contains("FunctionCall"));
    }

    #[test]
    fn rejects_invalid_source_account_strkey() {
        let cid = encode_contract_id(&[5u8; 32]);
        let bad = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "bad-account"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "SourceAccount"
account = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#
        );
        let err = parse_toml_str(&bad).unwrap_err().to_string();
        assert!(err.contains("CRC16"));

        let good_acct = encode_account_id(&[3u8; 32]);
        let ok = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "good-account"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "SourceAccount"
account = "{good_acct}"
"#
        );
        assert!(parse_toml_str(&ok).is_ok());
    }

    #[test]
    fn config_manager_reloads_and_computes_diff() {
        let cid1 = encode_contract_id(&[10u8; 32]);
        let cid2 = encode_contract_id(&[11u8; 32]);
        let v1 = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid1}"
label = "c1"
webhook_url = "https://example.com/1"

[[contracts.rules]]
type = "AnyTransaction"
"#
        );
        let v2 = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid1}"
label = "c1"
webhook_url = "https://example.com/1-updated"

[[contracts.rules]]
type = "AnyTransaction"

[[contracts]]
id = "{cid2}"
label = "c2"
webhook_url = "https://example.com/2"

[[contracts.rules]]
type = "FailedTransaction"
"#
        );
        let mgr = ConfigManager::new(None, parse_toml_str(&v1).unwrap());
        assert_eq!(mgr.generation(), 1);
        let diff = mgr.reload_from_str(&v2).unwrap();
        assert_eq!(diff.generation, 2);
        assert_eq!(diff.added_contracts, vec![cid2]);
        assert_eq!(diff.updated_contracts, vec![cid1]);
        assert!(diff.removed_contracts.is_empty());
        assert!(!diff.network_changed);
    }

    #[test]
    fn mtls_paths_must_be_paired_and_exist_on_disk() {
        let cid = encode_contract_id(&[12u8; 32]);
        let cert_only = format!(
            r#"
[network]
kind = "testnet"

[webhook]
client_cert_path = "/nonexistent/cert.pem"

[[contracts]]
id = "{cid}"
label = "mtls-half"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "AnyTransaction"
"#
        );
        let err = parse_toml_str(&cert_only).unwrap_err().to_string();
        assert!(err.contains("client_key_path is required"));

        let missing_files = format!(
            r#"
[network]
kind = "testnet"

[webhook]
client_cert_path = "/nonexistent/cert.pem"
client_key_path = "/nonexistent/key.pem"
ca_cert_path = "/nonexistent/ca.pem"

[[contracts]]
id = "{cid}"
label = "mtls-missing"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "AnyTransaction"
"#
        );
        let err = parse_toml_str(&missing_files).unwrap_err().to_string();
        assert!(err.contains("client_cert_path"));
        assert!(err.contains("client_key_path"));
        assert!(err.contains("ca_cert_path"));
    }

    #[test]
    fn template_format_requires_template_and_content_type_requires_template_format() {
        let cid = encode_contract_id(&[13u8; 32]);
        let missing_tpl = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "tpl-missing"
webhook_url = "https://example.com/hook"
webhook_format = "template"

[[contracts.rules]]
type = "AnyTransaction"
"#
        );
        let err = parse_toml_str(&missing_tpl).unwrap_err().to_string();
        assert!(err.contains("no template string was provided"));

        let stray_ct = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "ct-wrong-format"
webhook_url = "https://example.com/hook"
webhook_content_type = "text/plain"

[[contracts.rules]]
type = "AnyTransaction"
"#
        );
        let err = parse_toml_str(&stray_ct).unwrap_err().to_string();
        assert!(err.contains("only supported with format = \"template\""));

        let valid = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "tpl-ok"
webhook_url = "https://example.com/hook"
webhook_format = "template"
webhook_template = "alert={{id}}"
webhook_content_type = "application/x-www-form-urlencoded"

[[contracts.rules]]
type = "AnyTransaction"
"#
        );
        assert!(parse_toml_str(&valid).is_ok());
    }

    #[test]
    fn include_directive_merges_contracts_from_globbed_files() {
        let dir = tempfile::tempdir().unwrap();
        let contracts_dir = dir.path().join("contracts");
        std::fs::create_dir_all(&contracts_dir).unwrap();

        let cid1 = encode_contract_id(&[21u8; 32]);
        let cid2 = encode_contract_id(&[22u8; 32]);

        std::fs::write(
            contracts_dir.join("a.toml"),
            format!(
                r#"
[[contracts]]
id = "{cid1}"
label = "alpha"
webhook_url = "https://example.com/alpha"

[[contracts.rules]]
type = "AnyTransaction"
"#
            ),
        )
        .unwrap();

        std::fs::write(
            contracts_dir.join("b.toml"),
            format!(
                r#"
[[contracts]]
id = "{cid2}"
label = "beta"
webhook_url = "https://example.com/beta"

[[contracts.rules]]
type = "FailedTransaction"
"#
            ),
        )
        .unwrap();

        let root_path = dir.path().join("txwatch.toml");
        std::fs::write(
            &root_path,
            r#"
include = ["contracts/*.toml"]

[network]
kind = "testnet"
"#,
        )
        .unwrap();

        let loaded = load_from_path(&root_path).expect("include config should load");
        assert_eq!(loaded.contracts.len(), 2);
        let labels: Vec<&str> = loaded.contracts.iter().map(|c| c.label.as_str()).collect();
        assert!(labels.contains(&"alpha"));
        assert!(labels.contains(&"beta"));
    }

    #[test]
    fn include_glob_matching_no_files_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let root_path = dir.path().join("txwatch.toml");
        std::fs::write(
            &root_path,
            r#"
include = ["does-not-exist/*.toml"]

[network]
kind = "testnet"
"#,
        )
        .unwrap();

        let err = load_from_path(&root_path).unwrap_err().to_string();
        assert!(err.contains("matched no contract files"));
    }

    const RULE_SPELLINGS: &[&str] = &[
        "AnyTransaction",
        "FailedTransaction",
        "FunctionCall",
        "EventEmitted",
        "HighFee",
        "LargeTransfer",
        "SourceAccount",
        "RateSpike",
        "Inactivity",
    ];

    fn minimal_config_with_rule(rule_toml: &str) -> String {
        let cid = encode_contract_id(&[42u8; 32]);
        format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "prop-contract"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
{rule_toml}
"#
        )
    }

    proptest! {
        #[test]
        fn strkey_contract_id_encoding_always_validates(payload in any::<[u8; 32]>()) {
            let encoded = encode_contract_id(&payload);
            prop_assert_eq!(encoded.len(), 56);
            prop_assert!(encoded.starts_with('C'));
            prop_assert!(validate_contract_id(&encoded).is_ok());
        }

        #[test]
        fn strkey_account_id_encoding_always_validates(payload in any::<[u8; 32]>()) {
            let encoded = encode_account_id(&payload);
            prop_assert_eq!(encoded.len(), 56);
            prop_assert!(encoded.starts_with('G'));
            prop_assert!(validate_stellar_address(&encoded).is_ok());
        }

        #[test]
        fn single_char_mutation_breaks_strkey_checksum(
            payload in any::<[u8; 32]>(),
            pos in 1usize..56,
        ) {
            let encoded = encode_contract_id(&payload);
            let mut bytes = encoded.into_bytes();
            bytes[pos] = if bytes[pos] == b'A' { b'B' } else { b'A' };
            let corrupted = String::from_utf8(bytes).unwrap();
            prop_assert!(validate_contract_id(&corrupted).is_err());
        }

        #[test]
        fn arbitrary_strings_never_panic_strkey_or_url_validators(s in ".*") {
            let _ = validate_contract_id(&s);
            let _ = validate_stellar_address(&s);
            let _ = validate_http_url(&s, false);
            let _ = validate_http_url(&s, true);
        }

        #[test]
        fn unknown_rule_type_never_panics_and_rejects_non_canonical_names(
            raw_type in "[A-Za-z0-9_-]{1,24}"
        ) {
            prop_assume!(!RULE_SPELLINGS.contains(&raw_type.as_str()));
            prop_assume!(raw_type != "Composite" && raw_type != "Not");
            let toml_src = minimal_config_with_rule(&format!("type = \"{raw_type}\""));
            let res = parse_toml_str(&toml_src);
            prop_assert!(res.is_err());
            let msg = res.unwrap_err().to_string();
            prop_assert!(msg.contains("unknown rule type"));
        }

        #[test]
        fn single_char_typo_in_rule_type_produces_did_you_mean_suggestion(
            idx in 0usize..9,
            pos in 0usize..12,
        ) {
            let canonical = RULE_SPELLINGS[idx];
            let mut chars: Vec<char> = canonical.chars().collect();
            let target = pos % chars.len();
            chars[target] = if chars[target] == 'x' { 'y' } else { 'x' };
            let typo: String = chars.into_iter().collect();
            prop_assume!(!RULE_SPELLINGS.contains(&typo.as_str()));

            let toml_src = minimal_config_with_rule(&format!("type = \"{typo}\""));
            let err = parse_toml_str(&toml_src).unwrap_err().to_string();
            prop_assert!(
                err.contains("did you mean"),
                "expected suggestion for typo '{typo}' of '{canonical}', got: {err}"
            );
        }

        #[test]
        fn large_transfer_rejects_zero_or_both_thresholds(
            stroops in 0u64..1_000_000_000,
            xlm in 0u64..1_000,
            set_stroops in any::<bool>(),
            set_xlm in any::<bool>(),
        ) {
            let mut lines = vec!["type = \"LargeTransfer\"".to_string()];
            if set_stroops {
                lines.push(format!("threshold_stroops = {stroops}"));
            }
            if set_xlm {
                lines.push(format!("threshold_xlm = {xlm}"));
            }
            let effective_stroops = if set_stroops { stroops } else { 0 };
            let should_succeed = (effective_stroops > 0) ^ (set_xlm && xlm > 0)
                && !(set_stroops && stroops > 0 && set_xlm)
                && !(set_xlm && xlm == 0);

            let res = parse_toml_str(&minimal_config_with_rule(&lines.join("\n")));
            prop_assert_eq!(
                res.is_ok(),
                should_succeed,
                "stroops={stroops} (set={set_stroops}), xlm={xlm} (set={set_xlm}) => {:?}",
                res
            );
        }

        #[test]
        fn random_toml_never_panics_parser(body in "[\\x20-\\x7E\\n\\t]{0,300}") {
            let _ = parse_toml_str(&body);
        }
    }

    #[test]
    fn interpolation_supports_embedded_defaults_and_escapes() {
        std::env::remove_var("TXWATCH_PROP_UNSET_A");
        std::env::set_var("TXWATCH_PROP_SET_B", "https://hooks.example.org");

        assert_eq!(
            interpolate_env_string(
                "${TXWATCH_PROP_SET_B}/v1/${TXWATCH_PROP_UNSET_A:-default-tenant}/events",
                "url"
            )
            .unwrap(),
            "https://hooks.example.org/v1/default-tenant/events"
        );

        assert_eq!(
            interpolate_env_string(r"secret-\${NOT_A_VAR}-tail", "secret").unwrap(),
            "secret-${NOT_A_VAR}-tail"
        );

        assert_eq!(
            interpolate_env_string(r"prefix-\\${TXWATCH_PROP_SET_B}", "url").unwrap(),
            r"prefix-\https://hooks.example.org"
        );

        assert_eq!(
            interpolate_env_string(r"prefix-\\\${NOT_A_VAR}", "url").unwrap(),
            r"prefix-\${NOT_A_VAR}"
        );

        let err = interpolate_env_string("${}", "field").unwrap_err();
        assert!(err.to_string().contains("empty variable name"));

        let err = interpolate_env_string("${UNCLOSED", "field").unwrap_err();
        assert!(err.to_string().contains("unclosed"));
    }

    #[test]
    fn missing_client_cert_file_is_reported_with_field_path() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("client.key");
        std::fs::write(&key_path, b"dummy key").unwrap();

        let cid = encode_contract_id(&[55u8; 32]);
        let toml_src = format!(
            r#"
[network]
kind = "testnet"

[webhook]
client_cert_path = "/nonexistent/txwatch-missing-cert.pem"
client_key_path = "{}"

[[contracts]]
id = "{cid}"
label = "mtls-test"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "AnyTransaction"
"#,
            key_path.display()
        );
        let err = parse_toml_str(&toml_src).unwrap_err().to_string();
        assert!(err.contains("webhook.client_cert_path"));
        assert!(!err.contains("webhook.client_key_path"));
    }

    #[test]
    fn content_type_is_optional_and_only_valid_with_template_format() {
        let cid = encode_contract_id(&[56u8; 32]);
        let bad = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "ct-test"
webhook_url = "https://example.com/hook"
webhook_format = "json"
webhook_content_type = "application/vnd.custom+json"

[[contracts.rules]]
type = "AnyTransaction"
"#
        );
        let err = parse_toml_str(&bad).unwrap_err().to_string();
        assert!(err.contains("content_type"));

        let ok = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "ct-ok"
webhook_url = "https://example.com/hook"
webhook_format = "template"
webhook_template = "tx={{{{tx_hash}}}}"
webhook_content_type = "text/plain; charset=utf-8"

[[contracts.rules]]
type = "AnyTransaction"
"#
        );
        let cfg = parse_toml_str(&ok).expect("template with custom content-type should validate");
        let ep = &cfg.contracts[0].resolved_webhooks()[0];
        assert_eq!(
            ep.content_type.as_deref(),
            Some("text/plain; charset=utf-8")
        );
    }

    #[test]
    fn high_fee_accepts_threshold_stroops() {
        let mut rule = AlertRule::HighFee {
            threshold_stroops: 500_000,
            threshold_xlm: None,
            computed_threshold_stroops: 0,
        };
        let mut errors = Vec::new();
        validate_rule(&mut rule, "contracts[0].rules[0]", &mut errors);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        assert_eq!(rule.effective_threshold_stroops(), Some(500_000));
        assert_eq!(rule.label(), "HighFee>=500000");
    }

    #[test]
    fn high_fee_accepts_threshold_xlm() {
        let mut rule = AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: Some(2.5),
            computed_threshold_stroops: 0,
        };
        let mut errors = Vec::new();
        validate_rule(&mut rule, "contracts[0].rules[0]", &mut errors);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        assert_eq!(rule.effective_threshold_stroops(), Some(25_000_000));
        assert_eq!(rule.label(), "HighFee>=25000000");
    }

    #[test]
    fn high_fee_accepts_fractional_xlm_to_single_stroop() {
        let mut rule = AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: Some(0.0000001),
            computed_threshold_stroops: 0,
        };
        let mut errors = Vec::new();
        validate_rule(&mut rule, "contracts[0].rules[0]", &mut errors);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        assert_eq!(rule.effective_threshold_stroops(), Some(1));
    }

    #[test]
    fn high_fee_rejects_missing_thresholds() {
        let mut rule = AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: None,
            computed_threshold_stroops: 0,
        };
        let mut errors = Vec::new();
        validate_rule(&mut rule, "contracts[0].rules[0]", &mut errors);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("must specify either threshold_stroops > 0 or threshold_xlm > 0"));
    }

    #[test]
    fn high_fee_rejects_both_thresholds() {
        let mut rule = AlertRule::HighFee {
            threshold_stroops: 100,
            threshold_xlm: Some(1.0),
            computed_threshold_stroops: 0,
        };
        let mut errors = Vec::new();
        validate_rule(&mut rule, "contracts[0].rules[0]", &mut errors);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("specify only one of threshold_stroops or threshold_xlm"));
    }

    #[test]
    fn high_fee_rejects_zero_or_negative_xlm() {
        for bad in [0.0, -0.5, f64::NAN, f64::INFINITY] {
            let mut rule = AlertRule::HighFee {
                threshold_stroops: 0,
                threshold_xlm: Some(bad),
                computed_threshold_stroops: 0,
            };
            let mut errors = Vec::new();
            validate_rule(&mut rule, "contracts[0].rules[0]", &mut errors);
            assert!(
                !errors.is_empty(),
                "expected validation error for threshold_xlm={bad}"
            );
        }
    }

    #[test]
    fn high_fee_rejects_sub_stroop_xlm() {
        let mut rule = AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: Some(0.00000001),
            computed_threshold_stroops: 0,
        };
        let mut errors = Vec::new();
        validate_rule(&mut rule, "contracts[0].rules[0]", &mut errors);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("rounds to 0 stroops"));
    }

    #[test]
    fn high_fee_rejects_excessive_values() {
        let mut rule_stroops = AlertRule::HighFee {
            threshold_stroops: u64::MAX,
            threshold_xlm: None,
            computed_threshold_stroops: 0,
        };
        let mut errors = Vec::new();
        validate_rule(&mut rule_stroops, "contracts[0].rules[0]", &mut errors);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("exceeds maximum realistic value"));

        let mut rule_xlm = AlertRule::HighFee {
            threshold_stroops: 0,
            threshold_xlm: Some(1e15),
            computed_threshold_stroops: 0,
        };
        errors.clear();
        validate_rule(&mut rule_xlm, "contracts[0].rules[0]", &mut errors);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("exceeds maximum realistic value"));
    }

    #[test]
    fn high_fee_validation_is_idempotent_and_round_trips() {
        let cid = encode_contract_id(&[77u8; 32]);
        let toml_input = format!(
            r#"
[network]
kind = "testnet"

[[contracts]]
id = "{cid}"
label = "fee-watch"
webhook_url = "https://example.com/hook"

[[contracts.rules]]
type = "HighFee"
threshold_xlm = 1.25
"#
        );

        let mut cfg = parse_toml_str(&toml_input).expect("initial parse and validate");
        assert_eq!(
            cfg.contracts[0].rules[0]
                .rule
                .effective_threshold_stroops(),
            Some(12_500_000)
        );

        // Re-validating an already validated config must succeed cleanly.
        cfg.validate().expect("re-validation must be idempotent");
        assert_eq!(
            cfg.contracts[0].rules[0]
                .rule
                .effective_threshold_stroops(),
            Some(12_500_000)
        );

        // Re-serializing and parsing again must preserve the effective threshold.
        let serialized = toml::to_string(&cfg).expect("serialize");
        let reparsed = parse_toml_str(&serialized).expect("reparse");
        assert_eq!(
            reparsed.contracts[0].rules[0]
                .rule
                .effective_threshold_stroops(),
            Some(12_500_000)
        );
    }

    #[test]
    fn validate_stellar_address_accepts_valid_g_and_m_accounts() {
        let g = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7";
        assert!(validate_stellar_address(g).is_ok());

        // Valid muxed account (version byte 0x60 + 32-byte key + 8-byte id + CRC16).
        let m = "MAAAAAAAAAAAAAB7BQ2L7E5NBWMXDUCMZSIPOBKRDSBYVLMXGSSKF6YNPIB7Y77ITLVL6";
        assert!(validate_stellar_address(m).is_ok());
    }

    #[test]
    fn validate_stellar_address_rejects_invalid_inputs() {
        assert!(validate_stellar_address("").is_err());

        // Wrong prefix (contract ID C... instead of G... or M...)
        let c = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
        assert!(validate_stellar_address(c).is_err());

        // G-account with corrupted checksum
        let bad_g = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN8";
        assert!(validate_stellar_address(bad_g).is_err());

        // Wrong length
        assert!(validate_stellar_address("GAAZI4TCR3").is_err());
        assert!(validate_stellar_address("MAAAAAAAAA").is_err());

        // Non-base32 character ('0', '1', '8', '9')
        let invalid_char = "G0AZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7";
        assert!(validate_stellar_address(invalid_char).is_err());
    }
}