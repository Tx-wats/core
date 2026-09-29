//! txwatch-poller runs the Horizon polling loop, enriches transactions, evaluates rules,
//! and sends webhook alerts through `txwatch-notifier`.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};
use txwatch_config::{AppConfig, WatchedContract, WebhookDestination};
use txwatch_notifier::{send_to_destination, send_webhook_batch, MAX_BATCH_SIZE};
use txwatch_rules::{
    check_no_activity, evaluate, ContractEvent, CooldownTracker, EnrichedTransaction, EvalContext,
    HorizonTransaction, NoActivityState, WarningSuppressor,
};

pub mod db_snapshot;
pub use db_snapshot::{PostgresSnapshotRoutine, SnapshotMetadata};
pub mod event_stream;
pub use event_stream::{EventFilter, GetEventsParams, SorobanEvent, SorobanEventStreamer};
pub mod plan_cache;
pub use plan_cache::{PlanCache, PlanStatistics};

// ── Optional Prometheus metrics ───────────────────────────────────────────────

#[cfg(feature = "metrics")]
pub mod metrics;

/// Starts the optional `/metrics`, `/healthz` and `/readyz` HTTP endpoint.
#[cfg(feature = "metrics")]
pub use metrics::serve_metrics;

// ── Horizon response shapes ───────────────────────────────────────────────────

/// Horizon operation record — we only need the fields relevant to Soroban.
#[derive(Deserialize)]
struct HorizonOperation {
    #[serde(rename = "type")]
    op_type: String,
    /// Present on `invoke_host_function` operations.
    function: Option<String>,
    /// Present on `payment` operations (string, e.g. "1000.0000000").
    amount: Option<String>,
}

/// A Horizon transaction record that may include inline operations via `join=operations`.
#[derive(Deserialize)]
struct HorizonTransactionWithOps {
    #[serde(flatten)]
    tx: HorizonTransaction,
    /// Inline operations embedded when `join=operations` is used.
    #[serde(default)]
    operations: Vec<HorizonOperation>,
}

#[derive(Deserialize)]
struct HorizonPage {
    _embedded: Embedded,
}

#[derive(Deserialize)]
struct Embedded {
    records: Vec<HorizonTransactionWithOps>,
}

#[derive(Deserialize)]
struct OperationsPage {
    _embedded: OpsEmbedded,
}

#[derive(Deserialize)]
struct OpsEmbedded {
    records: Vec<HorizonOperation>,
}

// ── Soroban RPC response shapes ───────────────────────────────────────────────

/// JSON-RPC envelope returned by Soroban RPC.
#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

/// `getEvents` result (requested with `xdrFormat: "json"`).
#[derive(Deserialize)]
struct GetEventsResult {
    #[serde(default)]
    events: Vec<RpcEvent>,
    cursor: Option<String>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RpcEvent {
    ledger: u32,
    contract_id: String,
    tx_hash: String,
    #[serde(default)]
    topic_json: Vec<serde_json::Value>,
    #[serde(default)]
    value_json: serde_json::Value,
}

/// Page size for `getEvents`; one ledger rarely holds more events for a
/// single contract.
const RPC_EVENTS_PAGE_LIMIT: usize = 1000;

// ── Summary counters ──────────────────────────────────────────────────────────

#[derive(Default)]
struct Counters {
    contracts: AtomicU64,
    transactions: AtomicU64,
    alerts: AtomicU64,
    interval_transactions: AtomicU64,
    interval_alerts: AtomicU64,
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Backwards-compatible wrapper: default (non-dry) run.
pub async fn run(cfg: AppConfig) -> Result<()> {
    run_with(cfg, false).await
}

/// Run the polling loop forever. Each contract is polled concurrently via a
/// tokio JoinSet; one slow or failing contract never blocks the others.
/// Logs a summary every 60 seconds: contracts watched, transactions processed,
/// alerts fired.
pub async fn run_with(cfg: AppConfig, dry_run: bool) -> Result<()> {
    // No shutdown signal: hold the sender so the receiver never fires.
    let (_tx, rx) = watch::channel(false);
    run_with_shutdown(cfg, dry_run, rx).await
}

/// Run the polling loop until `shutdown` reports `true`, then finish the
/// in-flight cycle and return. The CLI drives this from its Ctrl-C handler.
pub async fn run_with_shutdown(
    cfg: AppConfig,
    dry_run: bool,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    // No reloads: hold the sender so the channel never closes.
    let (_reload_tx, reload_rx) = mpsc::channel(1);
    run_with_reload(cfg, dry_run, shutdown, reload_rx).await
}

/// Like [`run_with_shutdown`], but also applies every validated config received
/// on `reload` (the CLI sends one per SIGHUP). Contracts that are still present
/// keep their cursors; new contracts start from the start-cursor rules
/// (`cursor_file` entry, else `now`). HTTP client settings are not reloaded.
pub async fn run_with_reload(
    mut cfg: AppConfig,
    dry_run: bool,
    mut shutdown: watch::Receiver<bool>,
    mut reload: mpsc::Receiver<AppConfig>,
) -> Result<()> {
    // `build_poll_client` applies `http_tcp_keepalive_secs` itself.
    let client = build_poll_client(&cfg)?;
    // Shared so each contract's task can persist the whole cursor map after a
    // cycle that advanced its own cursor.
    let cursors = Arc::new(Mutex::new(load_cursors(&cfg)));
    let cursor_file = cfg.cursor_file.clone().map(PathBuf::from);

    #[cfg(feature = "metrics")]
    {
        metrics::set_poll_interval(cfg.poll_interval_seconds);
        metrics::register_build_info();
    }
    let summary_every = Duration::from_secs(60);
    let counters = Arc::new(Counters::default());
    let n_contracts = cfg.contracts.len();
    counters
        .contracts
        .store(n_contracts as u64, Ordering::Relaxed);

    let contracts_list = cfg
        .contracts
        .iter()
        .map(|c| c.label.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let mut networks: Vec<&str> = cfg.contracts.iter().map(|c| c.network.as_str()).collect();
    networks.sort();
    networks.dedup();
    let networks_str = networks.join(", ");

    let mut horizon_urls: Vec<(&str, &str)> = cfg
        .contracts
        .iter()
        .map(|c| (c.network.as_str(), c.network.horizon_base_url()))
        .collect();
    horizon_urls.sort();
    horizon_urls.dedup();
    let horizon_urls_str = horizon_urls
        .iter()
        .map(|(net, url)| format!("{}={}", net, url))
        .collect::<Vec<_>>()
        .join(", ");

    info!(
        version        = env!("CARGO_PKG_VERSION"),
        contracts      = n_contracts,
        contracts_list = %contracts_list,
        networks       = %networks_str,
        horizon_urls   = %horizon_urls_str,
        interval_secs  = cfg.poll_interval_seconds,
        "TxWatch polling engine started"
    );

    let fast_contracts = cfg
        .contracts
        .iter()
        .filter(|c| c.enabled && c.effective_poll_interval(cfg.poll_interval_seconds) < 10)
        .count();
    if fast_contracts > 5 {
        warn!(
            poll_interval_seconds = cfg.poll_interval_seconds,
            contracts = fast_contracts,
            "polling interval is very short with many contracts — Horizon rate limits may apply; \
             consider poll_interval_seconds >= 10"
        );
    }

    let counters_for_summary = Arc::clone(&counters);
    let _summary_guard = tokio::spawn(async move {
        loop {
            let c = Arc::clone(&counters_for_summary);
            let handle = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(summary_every).await;
                    let interval_txs = c.interval_transactions.swap(0, Ordering::Relaxed);
                    let interval_alerts = c.interval_alerts.swap(0, Ordering::Relaxed);
                    info!(
                        contracts = c.contracts.load(Ordering::Relaxed),
                        transactions_total = c.transactions.load(Ordering::Relaxed),
                        alerts_total = c.alerts.load(Ordering::Relaxed),
                        transactions_interval = interval_txs,
                        alerts_interval = interval_alerts,
                        "60-second summary"
                    );
                }
            });
            if let Err(e) = handle.await {
                error!(error = ?e, "summary logger panicked — restarting");
            }
        }
    });

    loop {
        // Each contract runs on its own task and interval, so a slow contract or
        // a short per-contract interval never affects the schedule of the others.
        // `stop` ends this generation of tasks on shutdown or reload.
        let (stop_tx, stop_rx) = watch::channel(false);
        let mut tasks = JoinSet::new();
        for contract in &cfg.contracts {
            let interval =
                Duration::from_secs(contract.effective_poll_interval(cfg.poll_interval_seconds));
            tasks.spawn(poll_contract_forever(
                client.clone(),
                contract.clone(),
                interval,
                dry_run,
                Arc::clone(&counters),
                stop_rx.clone(),
                CursorPersistence {
                    cursors: Arc::clone(&cursors),
                    path: cursor_file.clone(),
                },
            ));
        }

        let new_cfg = tokio::select! {
            () = wait_for_shutdown(&mut shutdown) => None,
            Some(new_cfg) = reload.recv() => Some(new_cfg),
        };

        // Tasks finish their in-flight poll, then hand back their cursor.
        let _ = stop_tx.send(true);
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((contract_id, cursor)) => {
                    lock(&cursors).insert(contract_id, cursor);
                }
                Err(e) => error!(error = ?e, "contract polling task panicked"),
            }
        }
        // Issue #5: flush once more on the way out, so a graceful shutdown
        // persists cursors advanced since the last per-cycle write.
        if let Err(e) = save_cursors(&cfg, &lock(&cursors)) {
            error!(error = %e, "failed to flush cursors on shutdown");
        }

        let Some(new_cfg) = new_cfg else { break };
        let start = load_cursors(&new_cfg);
        // Existing cursors win over the reloaded config's file; contracts new
        // to the config start from the saved cursor, else `now`.
        let merged: HashMap<String, String> = new_cfg
            .contracts
            .iter()
            .map(|c| {
                let id = c.contract_id.clone();
                let cursor = lock(&cursors)
                    .get(&id)
                    .or_else(|| start.get(&id))
                    .cloned()
                    .unwrap_or_else(|| "now".to_string());
                (id, cursor)
            })
            .collect();
        *lock(&cursors) = merged;
        counters
            .contracts
            .store(new_cfg.contracts.len() as u64, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        metrics::set_poll_interval(new_cfg.poll_interval_seconds);
        info!(
            contracts = new_cfg.contracts.len(),
            interval_secs = new_cfg.poll_interval_seconds,
            "configuration reloaded"
        );
        cfg = new_cfg;
    }

    info!("TxWatch polling engine stopped cleanly");
    Ok(())
}

/// Resolves once `shutdown` reports `true`. A dropped sender never signals
/// shutdown.
async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow_and_update() {
        if shutdown.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Polls one contract every `interval` until `stop` reports `true`, finishing
/// the in-flight poll first. Returns the contract ID and its latest cursor.
async fn poll_contract_forever(
    client: Client,
    contract: WatchedContract,
    interval: Duration,
    dry_run: bool,
    counters: Arc<Counters>,
    mut stop: watch::Receiver<bool>,
    persist: CursorPersistence,
) -> (String, String) {
    let contract_id = contract.contract_id.clone();
    let cursor = lock(&persist.cursors)
        .get(&contract_id)
        .cloned()
        .unwrap_or_else(|| "now".to_string());
    let mut cursors = HashMap::from([(contract_id.clone(), cursor)]);
    let mut state = ContractPollState::default();
    // A single tracker for this contract's lifetime, so cooldowns survive
    // across poll cycles rather than deduping only within one.
    let mut cooldowns = CooldownTracker::new();
    loop {
        match poll_contract(
            &client,
            &contract,
            &mut cursors,
            &mut state,
            &mut cooldowns,
            dry_run,
        )
        .await
        {
            Ok((txs, alerts, _webhook_failures)) => {
                counters.transactions.fetch_add(txs, Ordering::Relaxed);
                counters.alerts.fetch_add(alerts, Ordering::Relaxed);
                counters
                    .interval_transactions
                    .fetch_add(txs, Ordering::Relaxed);
                counters
                    .interval_alerts
                    .fetch_add(alerts, Ordering::Relaxed);
                // Issue #25: increment Prometheus counters when metrics feature is enabled.
                #[cfg(feature = "metrics")]
                {
                    let network = contract.network.as_str();
                    metrics::inc_transactions(&contract.label, network, txs);
                    metrics::inc_alerts(&contract.label, network, alerts);
                    metrics::record_poll_success(&contract.label, network);
                    metrics::mark_poll_success();
                }
                // Issue #5: persist the cursor as soon as it advances, so a
                // restart does not replay transactions we have already seen.
                if let Some(path) = &persist.path {
                    if let Some(latest) = cursors.get(&contract_id) {
                        let mut guard = lock(&persist.cursors);
                        if guard.get(&contract_id) != Some(latest) {
                            guard.insert(contract_id.clone(), latest.clone());
                            if let Err(e) = write_cursor_file(path, &guard) {
                                error!(
                                    contract = %contract.label, error = %e,
                                    "failed to persist cursor file; cursors may be replayed after a restart"
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!(contract = %contract.label, error = %e, "contract polling task failed");
                #[cfg(feature = "metrics")]
                metrics::record_poll_failure(&contract.label, contract.network.as_str());
            }
        }
        if *stop.borrow() {
            break;
        }

        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
        }
    }

    (
        contract.contract_id.clone(),
        cursors
            .get(&contract.contract_id)
            .cloned()
            .unwrap_or_else(|| "now".to_string()),
    )
}

/// Load the cursor map from `cfg.cursor_file`, defaulting every configured
/// contract without a saved cursor to Horizon's `now`. An unreadable or
/// unparseable file is logged and every contract starts from `now`.
fn load_cursors(cfg: &AppConfig) -> HashMap<String, String> {
    let mut cursors: HashMap<String, String> = HashMap::new();
    if let Some(path) = &cfg.cursor_file {
        match fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<HashMap<String, String>>(&raw) {
                Ok(map) => cursors = map,
                Err(e) => {
                    warn!(error = ?e, "failed to parse cursor_file; starting from 'now' for all contracts")
                }
            },
            Err(e) => debug!(error = ?e, "could not read cursor_file; starting from 'now'"),
        }
    }
    // Ensure every configured contract has a cursor entry.
    for c in &cfg.contracts {
        cursors
            .entry(c.contract_id.clone())
            .or_insert_with(|| "now".to_string());
    }
    cursors
}

/// Write the cursor map to `cfg.cursor_file`, if one is configured. Writes to a
/// temporary file first so an interrupted write never corrupts the saved map.
fn save_cursors(cfg: &AppConfig, cursors: &HashMap<String, String>) -> Result<()> {
    let Some(path) = &cfg.cursor_file else {
        return Ok(());
    };
    write_cursor_file(Path::new(path), cursors)
}

/// Shared cursor state a per-contract task needs to persist the whole cursor
/// file after advancing its own entry.
struct CursorPersistence {
    /// Every contract's latest cursor, shared across tasks.
    cursors: Arc<Mutex<HashMap<String, String>>>,
    /// `None` when `cursor_file` is not configured.
    path: Option<PathBuf>,
}

/// Lock a mutex, recovering the contents if a previous holder panicked.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Write the cursor map to `path` atomically: a temp file in the same directory
/// is written and fsynced, then renamed over the target, and the directory is
/// fsynced so the rename itself survives a crash. An interrupted write
/// therefore leaves the previous file intact rather than a truncated one.
fn write_cursor_file(path: &Path, cursors: &HashMap<String, String>) -> Result<()> {
    let raw = serde_json::to_string_pretty(cursors).context("failed to serialize cursors")?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("failed to create cursor file '{}'", tmp.display()))?;
        f.write_all(raw.as_bytes())
            .with_context(|| format!("failed to write cursor file '{}'", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("failed to sync cursor file '{}'", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to replace cursor file '{}'", path.display()))?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        // Persist the rename itself. Failure here is not fatal: the data is
        // already durable, only the directory entry may be lost on a crash.
        if let Ok(handle) = fs::File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    Ok(())
}

fn build_poll_client(cfg: &AppConfig) -> Result<Client> {
    // 0 disables keepalive, as documented on `AppConfig::http_tcp_keepalive_secs`.
    let keepalive =
        (cfg.http_tcp_keepalive_secs > 0).then(|| Duration::from_secs(cfg.http_tcp_keepalive_secs));

    Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(cfg.http_pool_max_idle_per_host)
        .tcp_keepalive(keepalive)
        .build()
        .context("failed to build HTTP client")
}

/// Outcome of a single poll cycle, used by [`run_once`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CycleReport {
    pub transactions: u64,
    pub alerts: u64,
    /// Contracts whose poll returned an error.
    pub poll_failures: u64,
    /// Webhooks that could not be delivered after all retries.
    pub webhook_failures: u64,
}

impl CycleReport {
    pub fn is_success(&self) -> bool {
        self.poll_failures == 0 && self.webhook_failures == 0
    }
}

/// Run exactly one poll cycle over every contract, persist the cursors to
/// `cfg.cursor_file` (if set) and return what happened. Used by
/// `txwatch watch --once` for cron/CI/scheduler runs.
pub async fn run_once(cfg: AppConfig, dry_run: bool) -> Result<CycleReport> {
    let client = build_poll_client(&cfg)?;
    let mut cursors = load_cursors(&cfg);
    let mut report = CycleReport::default();
    // A single cycle: cooldowns only dedupe within this run.
    let mut cooldowns = CooldownTracker::new();

    for contract in &cfg.contracts {
        if !contract.enabled {
            info!(contract = %contract.label, "contract is disabled — skipping");
            continue;
        }
        let mut state = ContractPollState::default();
        match poll_contract(
            &client,
            contract,
            &mut cursors,
            &mut state,
            &mut cooldowns,
            dry_run,
        )
        .await
        {
            Ok((txs, alerts, webhook_failures)) => {
                report.transactions += txs;
                report.alerts += alerts;
                report.webhook_failures += webhook_failures;
            }
            Err(e) => {
                error!(contract = %contract.label, error = %e, "contract polling task failed");
                report.poll_failures += 1;
            }
        }
    }

    save_cursors(&cfg, &cursors)?;
    Ok(report)
}

// ── Per-contract poll ─────────────────────────────────────────────────────────

/// Per-contract mutable state carried across poll cycles.
#[derive(Default)]
pub struct ContractPollState {
    /// Last transaction timestamp seen for this contract. `None` until the
    /// first transaction is observed.
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    /// One `NoActivityState` entry per rule index.  Entries are created on
    /// demand so the vector may be shorter than `contract.rules`.
    pub no_activity_states: Vec<NoActivityState>,
    /// Suppresses repeated evaluation warnings for broken rules.
    pub suppressor: WarningSuppressor,
}

/// Returns `(transactions_processed, alerts_fired, webhook_failures)`.
///
/// Uses `join=operations` on the transactions endpoint so that Horizon returns
/// operations inline, eliminating one HTTP request per transaction (#23).
/// Falls back to a separate `/transactions/{hash}/operations` fetch only when
/// the inline `operations` array is absent (older Horizon versions).
#[tracing::instrument(skip(client, contract, cursors, state, cooldowns), fields(
    contract    = %contract.label,
    contract_id = %contract.contract_id,
    network     = %contract.network.as_str()
))]
async fn poll_contract(
    client: &Client,
    contract: &WatchedContract,
    cursors: &mut HashMap<String, String>,
    state: &mut ContractPollState,
    cooldowns: &mut CooldownTracker,
    dry_run: bool,
) -> Result<(u64, u64, u64)> {
    let cursor = cursors
        .get(&contract.contract_id)
        .cloned()
        .unwrap_or_else(|| "now".to_string());

    // `poll_base` is used for all Horizon HTTP requests (may be overridden in tests).
    // `canonical_base` is always the production Horizon URL and is used only for
    // building horizon_link in payloads, so links always point to the real network.
    let poll_base = contract
        .horizon_base_url_override
        .as_deref()
        .unwrap_or_else(|| contract.network.horizon_base_url());
    let canonical_base = contract.network.horizon_base_url();

    // Collect all pages of transactions.
    let mut all_records: Vec<HorizonTransactionWithOps> = Vec::new();
    let mut page_cursor = cursor.clone();

    loop {
        // Issue #23: use join=operations to fetch operations inline, eliminating
        // one HTTP request per transaction.
        let url = format!(
            "{}/accounts/{}/transactions?cursor={}&order=asc&limit=200&join=operations",
            poll_base, contract.contract_id, page_cursor
        );

        #[cfg(feature = "metrics")]
        let started = std::time::Instant::now();
        let response = client.get(&url).send().await;
        #[cfg(feature = "metrics")]
        metrics::observe_horizon_request(
            contract.network.as_str(),
            started.elapsed().as_secs_f64(),
        );
        let response = response.with_context(|| format!("GET {} failed", url))?;

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(5);
            warn!(contract = %contract.label, retry_after, "Horizon returned 429 — backing off");
            tokio::time::sleep(Duration::from_secs(retry_after)).await;
            return Ok((0, 0, 0));
        }

        let status = response.status();
        let page: HorizonPage = response
            .error_for_status()
            .with_context(|| format!("Horizon returned HTTP {} for {}", status, url))?
            .json()
            .await
            .with_context(|| format!("failed to parse Horizon response from {}", url))?;

        let records = page._embedded.records;
        if records.is_empty() {
            break;
        }

        let last_token = records.last().map(|r| r.tx.paging_token.clone());
        let count = records.len();
        for r in records {
            all_records.push(r);
        }

        if count < 200 {
            break;
        }
        if let Some(token) = last_token {
            page_cursor = token;
        } else {
            break;
        }
    }

    if !all_records.is_empty() {
        info!(contract = %contract.label, count = all_records.len(), "fetched new transactions");
    } else {
        debug!(contract = %contract.label, cursor = %cursor, "no new transactions");
    }

    let mut tx_count = 0u64;
    let mut alert_count = 0u64;
    let mut webhook_failures = 0u64;
    // Contract events per ledger, fetched at most once per cycle and only
    // when the contract has an EventEmitted rule.
    let mut events_by_ledger: HashMap<u32, Vec<RpcEvent>> = HashMap::new();
    // With `batch_alerts`, alerts are collected here and sent after the loop.
    let mut batch: Vec<txwatch_rules::AlertPayload> = Vec::new();

    // Build a reusable EvalContext for per-transaction rule evaluation.
    // We use the canonical (production) Horizon base for links in payloads.
    let eval_ctx = EvalContext {
        label: &contract.label,
        contract_id: &contract.contract_id,
        network: contract.network.as_str(),
        horizon_base: canonical_base,
        explorer_base: contract.network.explorer_base_url(),
    };

    for record in all_records {
        let paging_token = record.tx.paging_token.clone();
        let tx_hash = record.tx.hash.clone();

        // Advance cursor before enrichment so the tx is not re-processed even if
        // op enrichment fails.
        cursors.insert(contract.contract_id.clone(), paging_token.clone());

        // Issue #23: if Horizon returned inline operations, use them directly.
        // Otherwise fall back to a separate /operations fetch.
        let (function_names, amount_stroops) = if !record.operations.is_empty() {
            debug!(contract = %contract.label, tx = %tx_hash, "using inline operations (join=operations)");
            extract_soroban_details(record.operations)
        } else {
            match fetch_soroban_details(client, poll_base, &tx_hash).await {
                Ok(details) => details,
                Err(e) => {
                    warn!(
                        contract = %contract.label, tx = %tx_hash, error = %e,
                        "could not fetch operation details — evaluating rules without them"
                    );
                    (Vec::new(), None)
                }
            }
        };

        let ledger = record.tx.ledger;
        let enriched = match EnrichedTransaction::from_horizon(
            record.tx,
            function_names,
            amount_stroops,
            None,
        ) {
            Ok(t) => t,
            Err(e) => {
                warn!(contract = %contract.label, tx = %tx_hash, error = %e,
                    "skipping transaction due to enrichment error");
                continue;
            }
        };

        // Track the most recent transaction timestamp for NoActivity evaluation.
        state.last_seen = Some(
            state
                .last_seen
                .map(|prev| prev.max(enriched.timestamp))
                .unwrap_or(enriched.timestamp),
        );

        let enriched = if contract.needs_events() {
            let events =
                transaction_events(client, contract, &tx_hash, ledger, &mut events_by_ledger).await;
            enriched.with_events(events)
        } else {
            enriched
        };

        tx_count += 1;

        let payloads = evaluate_contract(contract, canonical_base, &enriched);

        if payloads.is_empty() {
            debug!(contract = %contract.label, tx = %tx_hash,
                "transaction evaluated but no rules matched");
        }
        let payloads = cooldowns.apply(&contract.rules, payloads, chrono::Utc::now());

        for payload in payloads {
            alert_count += 1;
            if contract.batch_alerts {
                batch.push(payload);
            } else {
                deliver_payload(client, contract, &payload, dry_run, &mut webhook_failures).await;
            }
        }
    }

    // ── NoActivity poll-cycle check ───────────────────────────────────────────
    let now = chrono::Utc::now();
    // Ensure we have enough slots for all rules.
    if state.no_activity_states.len() < contract.rules.len() {
        state
            .no_activity_states
            .resize_with(contract.rules.len(), Default::default);
    }
    for (idx, rule) in contract.rules.iter().enumerate() {
        if !matches!(rule.rule, txwatch_config::AlertRule::NoActivity { .. }) {
            continue;
        }
        if let Some(payload) = check_no_activity(
            &rule.rule,
            state.last_seen,
            now,
            &mut state.no_activity_states[idx],
            &eval_ctx,
        ) {
            let resolved = payload.resolved;
            if resolved {
                info!(contract = %contract.label, rule = %payload.rule_triggered,
                    "NoActivity resolved — activity resumed");
            } else {
                info!(contract = %contract.label, rule = %payload.rule_triggered,
                    "NoActivity threshold exceeded — firing alert");
            }
            alert_count += 1;
            if contract.batch_alerts {
                batch.push(payload);
            } else {
                deliver_payload(client, contract, &payload, dry_run, &mut webhook_failures).await;
            }
        }
    }

    // One POST per chunk of at most MAX_BATCH_SIZE alerts; each failed chunk
    // counts as one webhook failure.
    for chunk in batch.chunks(MAX_BATCH_SIZE) {
        if dry_run {
            info!(contract = %contract.label, alerts = chunk.len(),
                "dry-run enabled: not sending batched webhook");
            continue;
        }
        info!(contract = %contract.label, alerts = chunk.len(), "sending batched webhook");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        #[cfg(feature = "metrics")]
        let started = std::time::Instant::now();
        let Some(url) = contract.webhook_url.as_deref() else {
            warn!(contract = %contract.label, "batch_alerts is set but no webhook_url is configured");
            continue;
        };
        let delivery = send_webhook_batch(
            client,
            url,
            chunk,
            contract.webhook_secret.as_deref(),
            shutdown_rx,
        )
        .await;
        #[cfg(feature = "metrics")]
        metrics::observe_webhook_delivery(started.elapsed().as_secs_f64());
        if let Err(e) = delivery {
            error!(contract = %contract.label, alerts = chunk.len(), error = %e,
                "batched webhook delivery failed");
            webhook_failures += 1;
            #[cfg(feature = "metrics")]
            metrics::inc_webhook_failures(&contract.label, contract.network.as_str());
        }
    }

    if tx_count > 0 {
        info!(contract = %contract.label, transactions = tx_count, alerts = alert_count,
            "poll cycle complete");
    }

    Ok((tx_count, alert_count, webhook_failures))
}

/// Deliver a single `AlertPayload` to the contract's webhook, counting any
/// failures into `webhook_failures`.
async fn deliver_payload(
    client: &Client,
    contract: &WatchedContract,
    payload: &txwatch_rules::AlertPayload,
    dry_run: bool,
    webhook_failures: &mut u64,
) {
    info!(contract = %contract.label, rule = %payload.rule_triggered,
        tx = %payload.transaction_hash, "rule matched");

    if dry_run {
        info!(contract = %contract.label, rule = %payload.rule_triggered,
            tx = %payload.transaction_hash, "dry-run enabled: not sending webhook");
        return;
    }
    info!(contract = %contract.label, rule = %payload.rule_triggered,
        tx = %payload.transaction_hash, "rule fired — sending webhook");

    // `destinations()` combines the `webhook_url` shorthand with the `webhooks`
    // array. A rule may override the URL and secret; when it does, the
    // shorthand slot is redirected rather than the array being ignored.
    let destinations: Vec<WebhookDestination> = match (
        &payload.effective_webhook_url,
        &payload.effective_webhook_secret,
    ) {
        (Some(url), secret) => {
            let mut d = contract.destinations();
            if let Some(first) = d.first_mut() {
                first.url = url.clone();
                if let Some(secret) = secret {
                    first.secret = Some(secret.clone());
                }
            }
            d
        }
        (None, _) => contract.destinations(),
    };
    if destinations.is_empty() {
        warn!(contract = %contract.label, "no webhook destination configured — dropping alert");
        return;
    }

    *webhook_failures += deliver_to_all(client, contract, &destinations, payload).await;
}

/// Delivers `payload` to every destination concurrently; each destination has
/// its own retries, so a slow or failing receiver never blocks the others.
/// Returns the number of destinations that could not be reached.
async fn deliver_to_all(
    client: &Client,
    contract: &WatchedContract,
    destinations: &[WebhookDestination],
    payload: &txwatch_rules::AlertPayload,
) -> u64 {
    let deliveries = destinations.iter().map(|destination| async move {
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        #[cfg(feature = "metrics")]
        let started = std::time::Instant::now();
        let delivery = send_to_destination(client, destination, payload, shutdown_rx).await;
        #[cfg(feature = "metrics")]
        metrics::observe_webhook_delivery(started.elapsed().as_secs_f64());
        (destination, delivery)
    });

    let mut failures = 0;
    for (destination, delivery) in futures::future::join_all(deliveries).await {
        if let Err(e) = delivery {
            error!(contract = %contract.label, rule = %payload.rule_triggered,
                tx = %payload.transaction_hash, url = %destination.url,
                format = %destination.format, error = %e, "webhook delivery failed");
            failures += 1;
            #[cfg(feature = "metrics")]
            metrics::inc_webhook_failures(&contract.label, contract.network.as_str());
        }
    }
    failures
}

// ── Replay ────────────────────────────────────────────────────────────────────

/// Fetch one historical transaction and its operations from Horizon and run the
/// contract's rules against it, exactly as the poller would. Returns the
/// payloads of every rule that matched; nothing is delivered. Used by
/// `txwatch replay`.
pub async fn replay_transaction(
    client: &Client,
    contract: &WatchedContract,
    tx_hash: &str,
) -> Result<Vec<txwatch_rules::AlertPayload>> {
    let base = contract
        .horizon_base_url_override
        .as_deref()
        .unwrap_or_else(|| contract.network.horizon_base_url());
    let url = format!("{}/transactions/{}", base, tx_hash);

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {} failed", url))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!(
            "transaction {} not found on {}",
            tx_hash,
            contract.network.as_str()
        );
    }
    let tx: HorizonTransaction = response
        .error_for_status()
        .with_context(|| format!("GET {} failed", url))?
        .json()
        .await
        .with_context(|| format!("failed to parse Horizon transaction from {}", url))?;

    let (function_names, amount_stroops) = fetch_soroban_details(client, base, tx_hash).await?;
    let ledger = tx.ledger;
    let mut enriched = EnrichedTransaction::from_horizon(tx, function_names, amount_stroops, None)?;
    if contract.needs_events() {
        let events =
            transaction_events(client, contract, tx_hash, ledger, &mut HashMap::new()).await;
        enriched = enriched.with_events(events);
    }

    Ok(evaluate_contract(
        contract,
        contract.network.horizon_base_url(),
        &enriched,
    ))
}

/// Runs the contract's rules against `tx`, linking to `horizon_base`.
fn evaluate_contract(
    contract: &WatchedContract,
    horizon_base: &str,
    tx: &EnrichedTransaction,
) -> Vec<txwatch_rules::AlertPayload> {
    let ctx = EvalContext {
        label: &contract.label,
        contract_id: &contract.contract_id,
        network: contract.network.as_str(),
        horizon_base,
        explorer_base: contract.network.explorer_base_url(),
    };
    let mut payloads = evaluate(&ctx, &contract.rules, tx, None);
    // A custom network without `explorer_url` has no explorer; link to the
    // transaction on Horizon instead.
    if contract.network.explorer_base_url().is_none() {
        for payload in &mut payloads {
            payload.explorer_link = payload.horizon_link.clone();
        }
    }
    payloads
}

// ── Soroban operation enrichment ──────────────────────────────────────────────

/// Extract Soroban details from a slice of already-fetched operations.
/// Used for both inline (join=operations) and separately-fetched operations.
fn extract_soroban_details(ops: Vec<HorizonOperation>) -> (Vec<String>, Option<u64>) {
    let mut function_names: Vec<String> = Vec::new();
    let mut total_stroops: u64 = 0;
    let mut has_payment = false;

    for op in ops {
        if op.op_type == "invoke_host_function" {
            if let Some(f) = op.function {
                function_names.push(f);
            }
        }
        if op.op_type == "payment" {
            if let Some(amt_str) = op.amount {
                if let Ok(xlm) = amt_str.parse::<f64>() {
                    total_stroops = total_stroops.saturating_add((xlm * 10_000_000.0) as u64);
                    has_payment = true;
                }
            }
        }
    }

    (
        function_names,
        if has_payment {
            Some(total_stroops)
        } else {
            None
        },
    )
}

/// Fetch operations for a single transaction from Horizon.
/// Used as a fallback when `join=operations` is not supported or returned no ops.
#[tracing::instrument(skip(client), fields(tx = %tx_hash))]
async fn fetch_soroban_details(
    client: &Client,
    base: &str,
    tx_hash: &str,
) -> Result<(Vec<String>, Option<u64>)> {
    let url = format!("{}/transactions/{}/operations", base, tx_hash);

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {} failed", url))?;
    let status = response.status();
    let page: OperationsPage = response
        .error_for_status()
        .with_context(|| format!("Horizon returned HTTP {} for {}", status, url))?
        .json()
        .await
        .with_context(|| format!("failed to parse operations from {}", url))?;

    Ok(extract_soroban_details(page._embedded.records))
}

// ── Soroban contract events ───────────────────────────────────────────────────

/// Contract events emitted by `tx_hash` for this contract. Failures (no RPC
/// endpoint, unknown ledger, RPC error, ledger outside the RPC retention
/// window) are logged and yield no events, so `EventEmitted` rules simply do
/// not match — the other rules are still evaluated.
async fn transaction_events(
    client: &Client,
    contract: &WatchedContract,
    tx_hash: &str,
    ledger: Option<u32>,
    cache: &mut HashMap<u32, Vec<RpcEvent>>,
) -> Vec<ContractEvent> {
    let Some(rpc_url) = contract.effective_soroban_rpc_url() else {
        warn!(contract = %contract.label, tx = %tx_hash,
            "no Soroban RPC endpoint configured — cannot fetch contract events");
        return Vec::new();
    };
    let Some(ledger) = ledger else {
        warn!(contract = %contract.label, tx = %tx_hash,
            "Horizon did not report the transaction's ledger — cannot fetch contract events");
        return Vec::new();
    };

    if let std::collections::hash_map::Entry::Vacant(slot) = cache.entry(ledger) {
        match fetch_ledger_events(client, rpc_url, &contract.contract_id, ledger).await {
            Ok(events) => {
                slot.insert(events);
            }
            Err(e) => {
                warn!(contract = %contract.label, tx = %tx_hash, ledger, error = %e,
                    "could not fetch contract events — EventEmitted rules will not match");
                return Vec::new();
            }
        }
    }

    cache
        .get(&ledger)
        .map(|events| {
            events
                .iter()
                .filter(|e| e.tx_hash == tx_hash)
                .map(|e| ContractEvent {
                    contract_id: e.contract_id.clone(),
                    topics: e.topic_json.clone(),
                    data: e.value_json.clone(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// All events `contract_id` emitted in `ledger`, via Soroban RPC `getEvents`
/// with `xdrFormat: "json"` so topics and data arrive as decoded `ScVal` JSON.
#[tracing::instrument(skip(client))]
async fn fetch_ledger_events(
    client: &Client,
    rpc_url: &str,
    contract_id: &str,
    ledger: u32,
) -> Result<Vec<RpcEvent>> {
    let mut events = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        // `startLedger` and `pagination.cursor` are mutually exclusive.
        let mut params = serde_json::json!({
            "filters": [{ "type": "contract", "contractIds": [contract_id] }],
            "pagination": { "limit": RPC_EVENTS_PAGE_LIMIT },
            "xdrFormat": "json",
        });
        match &cursor {
            Some(c) => params["pagination"]["cursor"] = serde_json::json!(c),
            None => params["startLedger"] = serde_json::json!(ledger),
        }
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getEvents",
            "params": params,
        });

        let response: RpcResponse<GetEventsResult> = client
            .post(rpc_url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {} (getEvents) failed", rpc_url))?
            .error_for_status()
            .with_context(|| format!("POST {} (getEvents) failed", rpc_url))?
            .json()
            .await
            .with_context(|| format!("failed to parse getEvents response from {}", rpc_url))?;

        if let Some(err) = response.error {
            anyhow::bail!("getEvents error {}: {}", err.code, err.message);
        }
        let page = response
            .result
            .context("getEvents response has neither result nor error")?;

        let count = page.events.len();
        let past_ledger = page.events.iter().any(|e| e.ledger > ledger);
        events.extend(page.events.into_iter().filter(|e| e.ledger == ledger));

        if count < RPC_EVENTS_PAGE_LIMIT || past_ledger {
            break;
        }
        match page.cursor {
            Some(next) if cursor.as_ref() != Some(&next) => cursor = Some(next),
            _ => break,
        }
    }

    Ok(events)
}

// ── Startup log field helpers (for testing) ──────────────────────────────────

#[cfg(test)]
fn startup_log_fields(cfg: &AppConfig) -> (String, String, String, String) {
    let contracts_list = cfg
        .contracts
        .iter()
        .map(|c| c.label.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let mut networks: Vec<&str> = cfg.contracts.iter().map(|c| c.network.as_str()).collect();
    networks.sort();
    networks.dedup();
    let networks_str = networks.join(", ");
    let mut horizon_urls: Vec<(&str, &str)> = cfg
        .contracts
        .iter()
        .map(|c| (c.network.as_str(), c.network.horizon_base_url()))
        .collect();
    horizon_urls.sort();
    horizon_urls.dedup();
    let horizon_urls_str = horizon_urls
        .iter()
        .map(|(net, url)| format!("{}={}", net, url))
        .collect::<Vec<_>>()
        .join(", ");
    (
        env!("CARGO_PKG_VERSION").to_string(),
        contracts_list,
        networks_str,
        horizon_urls_str,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use txwatch_config::{AlertRule, Network, RuleConfig};
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ops_page(function_name: &str) -> serde_json::Value {
        serde_json::json!({
            "_embedded": {
                "records": [{ "type": "invoke_host_function", "function": function_name }]
            }
        })
    }

    fn empty_page() -> serde_json::Value {
        serde_json::json!({ "_embedded": { "records": [] } })
    }

    fn rule(r: AlertRule) -> RuleConfig {
        RuleConfig {
            rule: r,
            cooldown_seconds: None,
        }
    }

    /// Issue #23: when Horizon returns inline operations via join=operations,
    /// the poller must parse them correctly without making a separate /operations request.
    #[tokio::test]
    async fn inline_operations_parsed_correctly() {
        let server = MockServer::start().await;

        // Transactions page with inline operations (join=operations response shape)
        let tx_with_ops = serde_json::json!({
            "_embedded": {
                "records": [{
                    "hash":         "inlinetx1",
                    "created_at":   "2024-06-01T10:00:00Z",
                    "successful":   true,
                    "paging_token": "1",
                    "fee_charged":  "100",
                    "envelope_xdr": null,
                    "result_xdr":   null,
                    "operations": [
                        { "type": "invoke_host_function", "function": "withdraw" }
                    ]
                }]
            }
        });

        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tx_with_ops))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Subsequent requests return empty page
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_page()))
            .mount(&server)
            .await;

        // Webhook receiver
        let receiver = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&receiver)
            .await;

        let client = Client::new();
        let contract = WatchedContract {
            label: "test".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
            network: Network::Testnet,
            rules: vec![RuleConfig {
                rule: AlertRule::FunctionCalled {
                    function_name: "withdraw".into(),
                    match_mode: Default::default(),
                },
                cooldown_seconds: None,
            }],
            webhook_url: Some(format!("{}/hook", receiver.uri())),
            webhook_secret: None,
            poll_interval_seconds: None,
            enabled: true,
            soroban_rpc_url: None,
            horizon_base_url_override: Some(server.uri()),
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: Vec::new(),
            batch_alerts: false,
        };
        let mut cursors: HashMap<String, String> = HashMap::new();
        cursors.insert(contract.contract_id.clone(), "now".to_string());

        let (txs, alerts, _) = poll_contract(
            &client,
            &contract,
            &mut cursors,
            &mut ContractPollState::default(),
            &mut CooldownTracker::new(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(txs, 1);
        assert_eq!(
            alerts, 1,
            "FunctionCalled(withdraw) should fire from inline operations"
        );

        // Verify no /operations request was made (inline ops used instead)
        let reqs = server.received_requests().await.unwrap();
        assert!(
            reqs.iter().all(|r| !r.url.path().contains("/operations")),
            "no separate /operations request should be made when inline ops are present"
        );
    }

    #[tokio::test]
    async fn poll_returns_ok_on_empty_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_page()))
            .mount(&server)
            .await;

        let client = Client::new();
        let url = format!(
            "{}/accounts/{}/transactions?cursor=now&order=asc&limit=200&join=operations",
            server.uri(),
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        );
        let page: HorizonPage = client.get(&url).send().await.unwrap().json().await.unwrap();
        assert!(page._embedded.records.is_empty());
    }

    #[tokio::test]
    async fn fetch_soroban_details_extracts_function_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ops_page("withdraw")))
            .mount(&server)
            .await;

        let client = Client::new();
        let (fn_names, amount) = fetch_soroban_details(&client, &server.uri(), "abc123")
            .await
            .unwrap();

        assert_eq!(fn_names, vec!["withdraw"]);
        assert!(amount.is_none());
    }

    #[tokio::test]
    async fn fetch_soroban_details_extracts_payment_amount() {
        let server = MockServer::start().await;
        let ops = serde_json::json!({
            "_embedded": { "records": [{ "type": "payment", "amount": "1000.0000000" }] }
        });
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ops))
            .mount(&server)
            .await;

        let client = Client::new();
        let (fn_names, amount) = fetch_soroban_details(&client, &server.uri(), "abc123")
            .await
            .unwrap();

        assert!(fn_names.is_empty());
        assert_eq!(amount, Some(10_000_000_000));
    }

    #[tokio::test]
    async fn fetch_soroban_details_returns_none_on_empty_ops() {
        let server = MockServer::start().await;
        let ops = serde_json::json!({ "_embedded": { "records": [] } });
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ops))
            .mount(&server)
            .await;

        let client = Client::new();
        let (fn_names, amount) = fetch_soroban_details(&client, &server.uri(), "abc123")
            .await
            .unwrap();

        assert!(fn_names.is_empty());
        assert!(amount.is_none());
    }

    #[tokio::test]
    async fn horizon_429_returns_meaningful_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let client = Client::new();
        let contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
        let mut cursors: HashMap<String, String> = HashMap::new();
        cursors.insert(contract_id.to_string(), "now".to_string());

        let contract = WatchedContract {
            label: "test".into(),
            contract_id: contract_id.into(),
            network: Network::Testnet,
            rules: vec![rule(txwatch_config::AlertRule::AnyTransaction)],
            webhook_url: Some("https://hooks.example.com/test".into()),
            webhook_secret: None,
            poll_interval_seconds: None,
            enabled: true,
            soroban_rpc_url: None,
            horizon_base_url_override: Some(server.uri()),
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: Vec::new(),
            batch_alerts: false,
        };

        // 429 is handled with a back-off and returns Ok((0,0,0)), not an error
        let result = poll_contract(
            &client,
            &contract,
            &mut cursors,
            &mut ContractPollState::default(),
            &mut CooldownTracker::new(),
            false,
        )
        .await;
        assert!(result.is_ok(), "429 should return Ok after back-off");
        assert_eq!(result.unwrap(), (0, 0, 0));
    }

    #[tokio::test]
    async fn horizon_503_error_contains_status_code() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let client = Client::new();
        let contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
        let mut cursors: HashMap<String, String> = HashMap::new();
        cursors.insert(contract_id.to_string(), "now".to_string());

        let contract = WatchedContract {
            label: "test".into(),
            contract_id: contract_id.into(),
            network: Network::Testnet,
            rules: vec![rule(txwatch_config::AlertRule::AnyTransaction)],
            webhook_url: Some("https://hooks.example.com/test".into()),
            webhook_secret: None,
            poll_interval_seconds: None,
            enabled: true,
            soroban_rpc_url: None,
            horizon_base_url_override: Some(server.uri()),
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: Vec::new(),
            batch_alerts: false,
        };

        let err = poll_contract(
            &client,
            &contract,
            &mut cursors,
            &mut ContractPollState::default(),
            &mut CooldownTracker::new(),
            false,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("503"),
            "error must contain HTTP status 503, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn poll_contract_does_not_advance_cursor_on_fetch_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = Client::new();
        let contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
        let mut cursors: HashMap<String, String> = HashMap::new();
        cursors.insert(contract_id.to_string(), "now".to_string());

        let contract = WatchedContract {
            label: "test".into(),
            contract_id: contract_id.into(),
            network: Network::Testnet,
            rules: vec![rule(AlertRule::AnyTransaction)],
            webhook_url: Some("https://hooks.example.com/test".into()),
            webhook_secret: None,
            poll_interval_seconds: None,
            enabled: true,
            soroban_rpc_url: None,
            horizon_base_url_override: Some(server.uri()),
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: Vec::new(),
            batch_alerts: false,
        };

        let result = poll_contract(
            &client,
            &contract,
            &mut cursors,
            &mut ContractPollState::default(),
            &mut CooldownTracker::new(),
            false,
        )
        .await;
        assert!(result.is_err(), "expected Err when Horizon returns 500");
        assert_eq!(
            cursors.get(contract_id).map(String::as_str),
            Some("now"),
            "cursor must not advance when the transactions fetch fails"
        );
    }

    #[test]
    fn startup_log_includes_version_contracts_list_and_networks() {
        let r = rule(txwatch_config::AlertRule::AnyTransaction);
        let cfg = AppConfig {
            poll_interval_seconds: 10,
            http_pool_max_idle_per_host: 10,
            http_tcp_keepalive_secs: 30,
            http_connection_verbose: None,
            max_contracts: None,
            cursor_file: None,
            contracts: vec![
                WatchedContract {
                    label: "Contract A".into(),
                    contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
                    network: txwatch_config::Network::Testnet,
                    rules: vec![r.clone()],
                    webhook_url: Some("https://hooks.example.com/a".into()),
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
                },
                WatchedContract {
                    label: "Contract B".into(),
                    contract_id: "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526".into(),
                    network: txwatch_config::Network::Mainnet,
                    rules: vec![r.clone()],
                    webhook_url: Some("https://hooks.example.com/b".into()),
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
                },
                WatchedContract {
                    label: "Contract C".into(),
                    contract_id: "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ".into(),
                    network: txwatch_config::Network::Mainnet,
                    rules: vec![r.clone()],
                    webhook_url: Some("https://hooks.example.com/c".into()),
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
                },
            ],
        };

        let (version, contracts_list, networks, horizon_urls) = startup_log_fields(&cfg);
        assert!(!version.is_empty());
        assert_eq!(contracts_list, "Contract A, Contract B, Contract C");
        assert_eq!(networks, "mainnet, testnet");
        assert!(horizon_urls.contains("mainnet=https://horizon.stellar.org"));
        assert!(horizon_urls.contains("testnet=https://horizon-testnet.stellar.org"));
    }

    // ── cursor_file loading ──────────────────────────────────────────────────

    const ID_A: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
    const ID_B: &str = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526";

    fn cursor_config(cursor_file: Option<String>) -> AppConfig {
        let contract = |id: &str| WatchedContract {
            label: id[..4].into(),
            contract_id: id.into(),
            network: Network::Testnet,
            rules: vec![rule(AlertRule::AnyTransaction)],
            webhook_url: Some("https://hooks.example.com/x".into()),
            webhook_secret: None,
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: Vec::new(),
            poll_interval_seconds: None,
            enabled: true,
            soroban_rpc_url: None,
            batch_alerts: false,
            horizon_base_url_override: None,
        };
        AppConfig {
            poll_interval_seconds: 10,
            contracts: vec![contract(ID_A), contract(ID_B)],
            cursor_file,
            http_pool_max_idle_per_host: 10,
            http_tcp_keepalive_secs: 30,
            http_connection_verbose: None,
            max_contracts: None,
        }
    }

    /// A fresh path in the temp dir, unique per test.
    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("txwatch-{}-{}", std::process::id(), name))
    }

    fn all_now() -> HashMap<String, String> {
        HashMap::from([(ID_A.into(), "now".into()), (ID_B.into(), "now".into())])
    }

    #[test]
    fn load_cursors_without_cursor_file_starts_from_now() {
        assert_eq!(load_cursors(&cursor_config(None)), all_now());
    }

    #[test]
    fn load_cursors_reads_valid_cursor_file() {
        let path = temp_path("valid.json");
        fs::write(&path, format!(r#"{{"{ID_A}": "111", "{ID_B}": "222"}}"#)).unwrap();
        let cursors = load_cursors(&cursor_config(Some(path.display().to_string())));
        let _ = fs::remove_file(&path);
        assert_eq!(
            cursors,
            HashMap::from([(ID_A.into(), "111".into()), (ID_B.into(), "222".into())])
        );
    }

    #[test]
    fn load_cursors_falls_back_to_now_only_for_missing_contracts() {
        let path = temp_path("partial.json");
        fs::write(&path, format!(r#"{{"{ID_A}": "111"}}"#)).unwrap();
        let cursors = load_cursors(&cursor_config(Some(path.display().to_string())));
        let _ = fs::remove_file(&path);
        assert_eq!(cursors.get(ID_A).map(String::as_str), Some("111"));
        assert_eq!(cursors.get(ID_B).map(String::as_str), Some("now"));
    }

    #[test]
    fn load_cursors_ignores_malformed_cursor_file() {
        let path = temp_path("malformed.json");
        fs::write(&path, "{ not json").unwrap();
        let cursors = load_cursors(&cursor_config(Some(path.display().to_string())));
        let _ = fs::remove_file(&path);
        assert_eq!(cursors, all_now());
    }

    #[test]
    fn load_cursors_ignores_cursor_file_with_wrong_shape() {
        let path = temp_path("wrong-shape.json");
        fs::write(&path, format!(r#"{{"{ID_A}": 111}}"#)).unwrap();
        let cursors = load_cursors(&cursor_config(Some(path.display().to_string())));
        let _ = fs::remove_file(&path);
        assert_eq!(cursors, all_now());
    }

    #[test]
    fn load_cursors_ignores_unreadable_cursor_file() {
        // A directory exists but cannot be read as a file.
        let dir = temp_path("unreadable-dir");
        fs::create_dir_all(&dir).unwrap();
        let cursors = load_cursors(&cursor_config(Some(dir.display().to_string())));
        let _ = fs::remove_dir(&dir);
        assert_eq!(cursors, all_now());

        let missing = temp_path("does-not-exist.json");
        assert_eq!(
            load_cursors(&cursor_config(Some(missing.display().to_string()))),
            all_now()
        );
    }

    #[tokio::test]
    async fn poll_handles_pagination_two_pages() {
        let server = MockServer::start().await;

        let mut records1 = Vec::new();
        for i in 1..=200u64 {
            records1.push(serde_json::json!({
                "hash": format!("tx{}", i),
                "created_at": "2020-01-01T00:00:00Z",
                "successful": true,
                "paging_token": format!("{}", i),
            }));
        }
        let page1 = serde_json::json!({ "_embedded": { "records": records1 }});
        let page2 = serde_json::json!({ "_embedded": { "records": [
            { "hash": "tx201", "created_at": "2020-01-01T00:00:01Z", "successful": true, "paging_token": "201" }
        ] }});

        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page1))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page2))
            .mount(&server)
            .await;

        // Fallback /operations endpoint for transactions without inline ops
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_page()))
            .mount(&server)
            .await;

        let client = Client::new();
        let contract = WatchedContract {
            label: "Contract".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
            network: Network::Testnet,
            rules: vec![rule(AlertRule::AnyTransaction)],
            webhook_url: Some(format!("{}/hooks", server.uri())),
            webhook_secret: None,
            poll_interval_seconds: None,
            enabled: true,
            soroban_rpc_url: None,
            horizon_base_url_override: Some(server.uri()),
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: Vec::new(),
            batch_alerts: false,
        };
        let mut cursors: HashMap<String, String> = HashMap::new();
        cursors.insert(contract.contract_id.clone(), "now".to_string());

        // Dry run: the assertions are about pagination and the counters, and
        // delivering 201 alerts to an unmocked endpoint would retry each one.
        let (txs, alerts, failures) = poll_contract(
            &client,
            &contract,
            &mut cursors,
            &mut ContractPollState::default(),
            &mut CooldownTracker::new(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(txs, 201);
        assert_eq!(alerts, 201);
        assert_eq!(failures, 0);
        assert_eq!(
            cursors.get(&contract.contract_id).map(String::as_str),
            Some("201")
        );
    }

    // ── Issue #50: contract events from Soroban RPC ───────────────────────────

    fn rpc_event(ledger: u32, tx_hash: &str, symbol: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "contract",
            "ledger": ledger,
            "contractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "id": format!("{}-{}", ledger, symbol),
            "txHash": tx_hash,
            "topicJson": [{ "symbol": symbol }, { "address": "GFROM" }],
            "valueJson": { "i128": "1000" }
        })
    }

    fn event_contract(rpc_url: String) -> WatchedContract {
        WatchedContract {
            label: "Events".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            network: Network::Mainnet,
            rules: vec![rule(AlertRule::EventEmitted {
                topic: "transfer".into(),
                topics: vec![],
            })],
            webhook_url: Some("https://example.com/hook".into()),
            webhook_secret: None,
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: Vec::new(),
            poll_interval_seconds: None,
            enabled: true,
            soroban_rpc_url: Some(rpc_url),
            batch_alerts: false,
            horizon_base_url_override: None,
        }
    }

    #[tokio::test]
    async fn transaction_events_keeps_only_this_tx_and_ledger() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "events": [
                        rpc_event(100, "tx1", "transfer"),
                        rpc_event(100, "tx2", "mint"),
                        rpc_event(101, "tx1", "burn")
                    ],
                    "latestLedger": 200,
                    "cursor": "c1"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new();
        let contract = event_contract(server.uri());
        let mut cache = HashMap::new();
        let events = transaction_events(&client, &contract, "tx1", Some(100), &mut cache).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].topics[0],
            serde_json::json!({ "symbol": "transfer" })
        );
        assert_eq!(events[0].data, serde_json::json!({ "i128": "1000" }));

        // Same ledger is served from the cache (the mock expects one call).
        let events = transaction_events(&client, &contract, "tx2", Some(100), &mut cache).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].topics[0], serde_json::json!({ "symbol": "mint" }));
    }

    #[tokio::test]
    async fn transaction_events_rpc_error_yields_no_events() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32600,
                    "message": "startLedger must be within the ledger range"
                }
            })))
            .mount(&server)
            .await;

        let client = Client::new();
        let contract = event_contract(server.uri());
        let events =
            transaction_events(&client, &contract, "tx1", Some(1), &mut HashMap::new()).await;
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn transaction_events_without_ledger_yields_no_events() {
        let client = Client::new();
        let contract = event_contract("http://127.0.0.1:9".into());
        let events = transaction_events(&client, &contract, "tx1", None, &mut HashMap::new()).await;
        assert!(events.is_empty());
    }
    // ── Multiple destinations ────────────────────────────────────────────────

    /// One alert goes to every destination; a destination that keeps failing
    /// is counted as one failure and does not stop delivery to the others.
    #[tokio::test]
    async fn alerts_go_to_every_destination_independently() {
        let horizon = MockServer::start().await;
        let tx_page = serde_json::json!({
            "_embedded": { "records": [{
                "hash": "multi1",
                "created_at": "2024-06-01T10:00:00Z",
                "successful": true,
                "paging_token": "1",
                "operations": [{ "type": "invoke_host_function", "function": "withdraw" }]
            }] }
        });
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tx_page))
            .mount(&horizon)
            .await;

        let good = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&good)
            .await;
        let slack = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&slack)
            .await;
        let broken = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&broken)
            .await;

        let contract = WatchedContract {
            label: "multi".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            network: Network::Testnet,
            rules: vec![rule(AlertRule::AnyTransaction)],
            webhook_url: Some(good.uri()),
            webhook_secret: None,
            poll_interval_seconds: None,
            horizon_base_url_override: Some(horizon.uri()),
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: vec![
                WebhookDestination {
                    url: broken.uri(),
                    secret: None,
                    format: txwatch_config::WebhookFormat::Txwatch,
                    headers: Default::default(),
                    routing_key: None,
                },
                WebhookDestination {
                    url: slack.uri(),
                    secret: None,
                    format: txwatch_config::WebhookFormat::Slack,
                    headers: Default::default(),
                    routing_key: None,
                },
            ],
            enabled: true,
            soroban_rpc_url: None,
            batch_alerts: false,
        };

        let client = Client::new();
        let mut cursors: HashMap<String, String> = HashMap::new();
        cursors.insert(contract.contract_id.clone(), "now".to_string());
        let mut state = ContractPollState::default();
        let mut cooldowns = CooldownTracker::new();

        let (_, alerts, failures) = poll_contract(
            &client,
            &contract,
            &mut cursors,
            &mut state,
            &mut cooldowns,
            false,
        )
        .await
        .unwrap();
        assert_eq!(alerts, 1);

        // The reachable destinations each received the alert...
        for dest in [&good, &slack] {
            let reqs = dest.received_requests().await.unwrap();
            assert!(!reqs.is_empty(), "every destination must receive the alert");
        }
        // ...and the broken one was retried rather than silently skipped.
        let broken_reqs = broken.received_requests().await.unwrap();
        assert!(!broken_reqs.is_empty(), "failing destination was contacted");
        assert!(
            failures >= 1,
            "a destination that always fails must count at least one failure"
        );
    }

    // ── Batched delivery ─────────────────────────────────────────────────────

    /// Mounts a Horizon returning `n` transactions (one page) on `server`, and
    /// returns a contract that batches its alerts to `receiver`.
    async fn batching_contract(
        server: &MockServer,
        receiver: &MockServer,
        n: u64,
    ) -> WatchedContract {
        let records: Vec<_> = (1..=n)
            .map(|i| {
                serde_json::json!({
                    "hash": format!("tx{}", i),
                    "created_at": "2020-01-01T00:00:00Z",
                    "successful": true,
                    "paging_token": i.to_string(),
                    "operations": [{ "type": "invoke_host_function", "function": "withdraw" }],
                })
            })
            .collect();
        Mock::given(method("GET"))
            .and(path_regex("/accounts/.*/transactions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "_embedded": { "records": records } })),
            )
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(receiver)
            .await;

        WatchedContract {
            label: "batch".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            network: Network::Testnet,
            rules: vec![RuleConfig {
                rule: AlertRule::AnyTransaction,
                cooldown_seconds: None,
            }],
            webhook_url: Some(format!("{}/hook", receiver.uri())),
            webhook_secret: None,
            webhook_format: Default::default(),
            webhook_headers: Default::default(),
            webhook_routing_key: None,
            webhooks: Vec::new(),
            poll_interval_seconds: None,
            enabled: true,
            soroban_rpc_url: None,
            batch_alerts: true,
            horizon_base_url_override: Some(server.uri()),
        }
    }

    async fn batch_sizes(receiver: &MockServer) -> Vec<usize> {
        receiver
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| {
                let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
                body["alerts"].as_array().expect("batched body").len()
            })
            .collect()
    }

    #[tokio::test]
    async fn batch_alerts_sends_one_post_per_cycle() {
        let (server, receiver) = (MockServer::start().await, MockServer::start().await);
        let contract = batching_contract(&server, &receiver, 3).await;
        let mut cursors = HashMap::from([(contract.contract_id.clone(), "now".to_string())]);

        let (txs, alerts, failures) = poll_contract(
            &Client::new(),
            &contract,
            &mut cursors,
            &mut ContractPollState::default(),
            &mut CooldownTracker::new(),
            false,
        )
        .await
        .unwrap();
        assert_eq!((txs, alerts, failures), (3, 3, 0));
        // One POST carrying all three alerts, not three single-alert POSTs.
        assert_eq!(batch_sizes(&receiver).await, vec![3]);
    }

    #[tokio::test]
    async fn batch_alerts_splits_large_batches() {
        let (server, receiver) = (MockServer::start().await, MockServer::start().await);
        let contract = batching_contract(&server, &receiver, 120).await;
        let mut cursors = HashMap::from([(contract.contract_id.clone(), "now".to_string())]);

        let (_, alerts, _) = poll_contract(
            &Client::new(),
            &contract,
            &mut cursors,
            &mut ContractPollState::default(),
            &mut CooldownTracker::new(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(alerts, 120);
        assert_eq!(batch_sizes(&receiver).await, vec![50, 50, 20]);
    }

    #[tokio::test]
    async fn batch_alerts_sends_nothing_in_dry_run_or_without_alerts() {
        let (server, receiver) = (MockServer::start().await, MockServer::start().await);
        let contract = batching_contract(&server, &receiver, 3).await;
        let mut cursors = HashMap::from([(contract.contract_id.clone(), "now".to_string())]);
        poll_contract(
            &Client::new(),
            &contract,
            &mut cursors,
            &mut ContractPollState::default(),
            &mut CooldownTracker::new(),
            true,
        )
        .await
        .unwrap();
        assert!(receiver.received_requests().await.unwrap().is_empty());

        let (server, receiver) = (MockServer::start().await, MockServer::start().await);
        let contract = batching_contract(&server, &receiver, 0).await;
        let mut cursors = HashMap::from([(contract.contract_id.clone(), "now".to_string())]);
        poll_contract(
            &Client::new(),
            &contract,
            &mut cursors,
            &mut ContractPollState::default(),
            &mut CooldownTracker::new(),
            false,
        )
        .await
        .unwrap();
        assert!(receiver.received_requests().await.unwrap().is_empty());
    }
}
