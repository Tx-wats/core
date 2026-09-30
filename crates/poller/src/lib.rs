//! txwatch-poller runs the Horizon polling loop, enriches transactions, evaluates rules,
//! and sends webhook alerts through `txwatch-notifier`.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::fs;
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
mod poll_health;
use poll_health::{jitter_percent_from_env, poll_ticker, start_offset, PollHealth};

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
    /// Present on `invoke_host_function` operations. This is the *host function
    /// type* (e.g. `HostFunctionTypeHostFunctionTypeInvokeContract`), not the
    /// invoked contract function; see `contract_function_name`.
    #[serde(rename = "function")]
    host_function_type: Option<String>,
    /// XDR-encoded `ScVal` arguments, base64 in a `value` string. The `Sym` entry
    /// is the invoked contract function name.
    #[serde(default)]
    parameters: Vec<HorizonParameter>,
    /// Present on `payment` operations (string, e.g. "1000.0000000").
    /// Present on `invoke_host_function` operations.
    function: Option<String>,
    /// Present on `payment` operations (string, e.g. "1000.0000000"). On path
    /// payments this is the amount the destination receives.
    amount: Option<String>,
    /// Present on `create_account` operations: the native starting balance.
    starting_balance: Option<String>,
    /// Present on path payment operations: the amount the source sends.
    source_amount: Option<String>,
    /// Asset of `amount` on path payments (`"native"` for XLM).
    asset_type: Option<String>,
    /// Asset of `source_amount` on path payments (`"native"` for XLM).
    source_asset_type: Option<String>,
    /// Present on `invoke_host_function` operations: Stellar Asset Contract
    /// balance changes caused by the call.
    asset_balance_changes: Option<Vec<AssetBalanceChange>>,
}

/// One `{"type": ..., "value": ...}` entry of an operation's `parameters` array.
#[derive(Debug, Deserialize)]
struct HorizonParameter {
    /// The `ScVal` type name, e.g. `Address`, `Sym`, `U64`, `Bytes`.
    #[serde(rename = "type")]
    scv_type: String,
    /// Base64 of the XDR-encoded `ScVal`.
    value: String,
}

/// Decode the `Sym` parameter of an `invoke_host_function` operation, which holds
/// the invoked contract function name.
///
/// The value is a base64 XDR-encoded `ScVal`. Only the `Symbol` variant is
/// decoded: its XDR is a 4-byte big-endian discriminant, a 4-byte big-endian
/// byte length, then the UTF-8 bytes. Everything else returns `None` — the
/// remaining `ScVal` variants are not needed to identify the function and each
/// needs its own decoder.
fn contract_function_name(parameters: &[HorizonParameter]) -> Option<String> {
    let sym = parameters.iter().find(|p| p.scv_type == "Sym")?;
    let raw = base64_decode(&sym.value)?;
    if raw.len() < 8 {
        return None;
    }
    // 15 == SCV_SYMBOL
    if u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) != 15 {
        return None;
    }
    let len = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let end = 8usize.checked_add(len)?;
    let bytes = raw.get(8..end)?;
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// Minimal standard-alphabet base64 decoder, so the poller does not need a
/// new dependency for the one `ScVal` it decodes. Padding is optional.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a') as u32 + 26),
            b'0'..=b'9' => Some((b - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in input.bytes() {
        if b == b'=' || b == b'\n' || b == b'\r' {
            continue;
        }
        acc = (acc << 6) | value(b)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// A Horizon transaction record that may include inline operations via `join=operations`.
/// One entry of `asset_balance_changes` on an `invoke_host_function` operation.
#[derive(Deserialize)]
struct AssetBalanceChange {
    #[serde(rename = "type")]
    change_type: String,
    amount: Option<String>,
    asset_type: Option<String>,
    /// Present on `payment` operations: `native`, `credit_alphanum4` or
    /// `credit_alphanum12`. Only `native` payments count as XLM.
    asset_type: Option<String>,
    /// Present on non-native `payment` operations.
    #[allow(dead_code)]
    asset_code: Option<String>,
    /// Present on non-native `payment` operations.
    #[allow(dead_code)]
    asset_issuer: Option<String>,
}

/// A Horizon transaction record from the account transactions endpoint.
#[derive(Deserialize)]
struct HorizonTransactionWithOps {
    #[serde(flatten)]
    tx: HorizonTransaction,
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
    #[serde(default)]
    _links: Option<PageLinks>,
}

#[derive(Deserialize)]
struct PageLinks {
    next: Option<PageLink>,
}

#[derive(Deserialize)]
struct PageLink {
    href: String,
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

/// Horizon returns at most this many transactions per page (`limit=200`).
const HORIZON_PAGE_LIMIT: usize = 200;

// ── Summary counters ──────────────────────────────────────────────────────────

#[derive(Default)]
struct Counters {
    contracts: AtomicU64,
    transactions: AtomicU64,
    alerts: AtomicU64,
    skipped: AtomicU64,
    interval_transactions: AtomicU64,
    interval_alerts: AtomicU64,
    interval_skipped: AtomicU64,
}

impl Counters {
    /// Adds the outcome of one poll of one contract to the running totals.
    fn record_poll(&self, txs: u64, alerts: u64, skipped: u64) {
        self.transactions.fetch_add(txs, Ordering::Relaxed);
        self.alerts.fetch_add(alerts, Ordering::Relaxed);
        self.skipped.fetch_add(skipped, Ordering::Relaxed);
        self.interval_transactions.fetch_add(txs, Ordering::Relaxed);
        self.interval_alerts.fetch_add(alerts, Ordering::Relaxed);
        self.interval_skipped.fetch_add(skipped, Ordering::Relaxed);
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Backwards-compatible wrapper: default (non-dry) run.
pub async fn run(cfg: AppConfig) -> Result<()> {
    run_with(cfg, false).await
}

/// Run the polling loop forever. Each contract is polled concurrently via a
/// tokio JoinSet; one slow or failing contract never blocks the others.
/// Logs a summary every 60 seconds: contracts watched, transactions processed,
/// transactions skipped, alerts fired.
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
    let mut cursors = load_cursors(&cfg);

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
                    let interval_skipped = c.interval_skipped.swap(0, Ordering::Relaxed);
                    info!(
                        contracts = c.contracts.load(Ordering::Relaxed),
                        transactions_total = c.transactions.load(Ordering::Relaxed),
                        alerts_total = c.alerts.load(Ordering::Relaxed),
                        skipped_total = c.skipped.load(Ordering::Relaxed),
                        transactions_interval = interval_txs,
                        alerts_interval = interval_alerts,
                        skipped_interval = interval_skipped,
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
        let max_pages = cfg.effective_max_pages_per_cycle();
        for contract in &cfg.contracts {
            if !contract.enabled {
                info!(contract = %contract.label, "contract is disabled — skipping");
                continue;
            }
            let interval =
                Duration::from_secs(contract.effective_poll_interval(cfg.poll_interval_seconds));
            let cursor = cursors
                .get(&contract.cursor_key())
                .cloned()
                .unwrap_or_else(|| "now".to_string());
            tasks.spawn(poll_contract_forever(
                client.clone(),
                contract.clone(),
                cursor,
                interval,
                max_pages,
                dry_run,
                Arc::clone(&counters),
                stop_rx.clone(),
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
                Ok((key, cursor)) => {
                    cursors.insert(key, cursor);
                }
                Err(e) => error!(error = ?e, "contract polling task panicked"),
            }
        }

        let Some(new_cfg) = new_cfg else { break };
        let start = load_cursors(&new_cfg);
        cursors = new_cfg
            .contracts
            .iter()
            .map(|c| {
                let key = c.cursor_key();
                let cursor = cursors
                    .get(&key)
                    .or_else(|| start.get(&key))
                    .cloned()
                    .unwrap_or_else(|| "now".to_string());
                (key, cursor)
            })
            .collect();
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

/// Logs a failed poll with enough context to tell contracts apart.
fn log_poll_failure(contract: &WatchedContract, consecutive_failures: u32, error: &anyhow::Error) {
    error!(
        contract = %contract.label,
        network = %contract.network.as_str(),
        contract_id = %contract.contract_id,
        consecutive_failures,
        error = %error,
        "contract polling task failed"
    );
}

/// Polls one contract every `interval` until `stop` reports `true`, finishing
/// the in-flight poll first. Returns the contract's cursor key and its latest
/// cursor.
#[allow(clippy::too_many_arguments)]
async fn poll_contract_forever(
    client: Client,
    contract: WatchedContract,
    cursor: String,
    interval: Duration,
    max_pages: usize,
    dry_run: bool,
    counters: Arc<Counters>,
    mut stop: watch::Receiver<bool>,
) -> (String, String) {
    let key = contract.cursor_key();
    let mut cursors = HashMap::from([(key.clone(), cursor)]);
    // Poll state and cooldowns live as long as this contract's task.
    let mut state = ContractPollState::default();
    let mut cursors = HashMap::from([(contract.contract_id.clone(), cursor)]);
    let mut state = ContractPollState::default();
    // A single tracker for this contract's lifetime, so cooldowns survive
    // across poll cycles rather than deduping only within one.
    let mut cooldowns = CooldownTracker::new();
    let mut health = PollHealth::default();
    // Polls are paced by a fixed-period ticker, so the period stays at
    // `interval` however long a cycle takes. The first poll happens
    // immediately; the per-contract offset staggers every poll after it so
    // contracts do not all hit Horizon at the same instant.
    let offset = start_offset(&contract.contract_id, interval, jitter_percent_from_env());
    let mut ticker = poll_ticker(interval, offset);
    loop {
        let cycle_started = std::time::Instant::now();
        match poll_contract(
            &client,
            &contract,
            &mut cursors,
            &mut state,
            &mut cooldowns,
            max_pages,
            dry_run,
        )
        .await
        {
            Ok((txs, alerts, _webhook_failures, skipped)) => {
                counters.record_poll(txs, alerts, skipped);
            Ok((txs, alerts, _webhook_failures)) => {
                if let Some(failures) = health.record_success() {
                    info!(
                        contract = %contract.label,
                        network = %contract.network.as_str(),
                        contract_id = %contract.contract_id,
                        previous_consecutive_failures = failures,
                        "contract recovered"
                    );
                }
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
                    metrics::inc_transactions_skipped(&contract.label, network, skipped);
                    metrics::record_poll_success(&contract.label, network);
                    metrics::mark_poll_success();
                }
            }
            Err(e) => {
                let became_unhealthy = health.record_failure();
                log_poll_failure(&contract, health.consecutive_failures(), &e);
                if became_unhealthy {
                    warn!(
                        contract = %contract.label,
                        network = %contract.network.as_str(),
                        contract_id = %contract.contract_id,
                        consecutive_failures = health.consecutive_failures(),
                        seconds_since_last_success = ?health.since_last_success().map(|d| d.as_secs()),
                        "contract unhealthy: polling keeps failing, backing off"
                    );
                }
                #[cfg(feature = "metrics")]
                metrics::record_poll_failure(&contract.label, contract.network.as_str());
                // Back off (capped) while the contract keeps failing.
                ticker.reset_after(health.backoff_delay(interval));
            }
        }
        let cycle = cycle_started.elapsed();
        if cycle > interval {
            warn!(
                contract = %contract.label,
                network = %contract.network.as_str(),
                contract_id = %contract.contract_id,
                cycle_ms = cycle.as_millis() as u64,
                interval_ms = interval.as_millis() as u64,
                "poll cycle took longer than the configured interval"
            );
        }
        if *stop.borrow() {
            break;
        }

        tokio::select! {
            _ = ticker.tick() => {}
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
        }
    }

    let cursor = cursors.remove(&key).unwrap_or_else(|| "now".to_string());
    (key, cursor)
}

/// Reads the raw cursor map from `path`. An unreadable or unparseable file is
/// logged and treated as empty, so every contract starts from `now`.
fn read_saved_cursors(path: &str) -> HashMap<String, String> {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<HashMap<String, String>>(&raw) {
            Ok(map) => map,
            Err(e) => {
                warn!(error = ?e, "failed to parse cursor_file; starting from 'now' for all contracts");
                HashMap::new()
            }
        },
        Err(e) => {
            debug!(error = ?e, "could not read cursor_file; starting from 'now'");
            HashMap::new()
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

/// Resolves the saved cursor map against the configured contracts.
///
/// `configured` holds one `(cursor_key, contract_id)` pair per configured
/// contract. Cursors are keyed `<network>:<contract_id>`; files written before
/// that format existed key them by the bare contract ID. A legacy entry is
/// migrated to the new key only when exactly one configured contract has that
/// ID — with several (the same contract on more than one network) there is no
/// way to know which network the cursor belongs to, so those contracts start
/// from `now` rather than risk sending one network's paging token to another.
/// Entries in the new format for contracts that are not configured are kept
/// so they survive a save; unmigrated legacy entries are dropped.
fn migrate_saved_cursors(
    saved: HashMap<String, String>,
    configured: &[(String, String)],
) -> HashMap<String, String> {
    let mut cursors: HashMap<String, String> = saved
        .iter()
        .filter(|(key, _)| key.contains(':'))
        .map(|(key, cursor)| (key.clone(), cursor.clone()))
        .collect();

    for (key, contract_id) in configured {
        if cursors.contains_key(key) {
            continue;
        }
        let Some(legacy) = saved.get(contract_id) else {
            continue;
        };
        let owners = configured
            .iter()
            .filter(|(_, id)| id == contract_id)
            .count();
        if owners == 1 {
            info!(contract_id = %contract_id, "migrating legacy cursor to the per-network key");
            cursors.insert(key.clone(), legacy.clone());
        } else {
            warn!(
                contract_id = %contract_id,
                "cursor_file has a legacy cursor for a contract watched on several networks; \
                 starting those contracts from 'now'"
            );
        }
    }
    cursors
}

/// Load the cursor map, keyed `<network>:<contract_id>` (see
/// [`WatchedContract::cursor_key`]), from `cfg.cursor_file`, migrating legacy
/// contract-ID keys and defaulting every configured contract without a saved
/// cursor to Horizon's `now`.
fn load_cursors(cfg: &AppConfig) -> HashMap<String, String> {
    let saved = cfg
        .cursor_file
        .as_deref()
        .map(read_saved_cursors)
        .unwrap_or_default();
    let configured: Vec<(String, String)> = cfg
        .contracts
        .iter()
        .map(|c| (c.cursor_key(), c.contract_id.clone()))
        .collect();
    let mut cursors = migrate_saved_cursors(saved, &configured);
    // Ensure every configured contract has a cursor entry.
    for (key, _) in configured {
        cursors.entry(key).or_insert_with(|| "now".to_string());
    }
    cursors
}

/// Write the cursor map to `cfg.cursor_file`, if one is configured. Writes to a
/// temporary file first so an interrupted write never corrupts the saved map.
fn save_cursors(cfg: &AppConfig, cursors: &HashMap<String, String>) -> Result<()> {
    let Some(path) = &cfg.cursor_file else {
        return Ok(());
    };
    let raw = serde_json::to_string_pretty(cursors).context("failed to serialize cursors")?;
    let tmp = format!("{}.tmp", path);
    fs::write(&tmp, raw).with_context(|| format!("failed to write cursor file '{}'", tmp))?;
    fs::rename(&tmp, path).with_context(|| format!("failed to write cursor file '{}'", path))?;
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
    let max_pages = cfg.effective_max_pages_per_cycle();
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
            max_pages,
            dry_run,
        )
        .await
        {
            Ok((txs, alerts, webhook_failures, _skipped)) => {
            Ok((txs, alerts, webhook_failures)) => {
                report.transactions += txs;
                report.alerts += alerts;
                report.webhook_failures += webhook_failures;
            }
            Err(e) => {
                log_poll_failure(contract, 1, &e);
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

/// Returns `(transactions_processed, alerts_fired, webhook_failures, transactions_skipped)`.
///
/// Operations are fetched per transaction from `/transactions/{hash}/operations`;
/// see the note on the transactions URL below for why they are not joined inline.
#[tracing::instrument(skip(client, contract, cursors, state), fields(
#[tracing::instrument(skip(client, contract, cursors, cooldowns), fields(
/// Uses `join=operations` on the transactions endpoint so that Horizon returns
/// operations inline, eliminating one HTTP request per transaction (#23).
/// Falls back to a separate `/transactions/{hash}/operations` fetch only when
/// the inline `operations` array is absent (older Horizon versions).
///
/// Pages are processed as they arrive rather than buffered, and at most
/// `max_pages` pages (200 transactions each) are fetched per call. When the cap
/// is hit a warning is logged and the next call resumes from the saved cursor.
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
    max_pages: usize,
    dry_run: bool,
) -> Result<(u64, u64, u64, u64)> {
    let cursor_key = contract.cursor_key();
    let cursor = cursors
        .get(&cursor_key)
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
        // Issue #2: `include_failed=true` is required or Horizon only returns
        // successful transactions, which makes `TransactionFailed` dead.
        let url = format!(
            "{}/accounts/{}/transactions?cursor={}&order=asc&limit=200&join=operations&include_failed=true",
        // Checked against horizon-testnet.stellar.org: `join=operations` on the
        // transactions endpoint is NOT supported. Horizon answers 200 but ignores
        // it and returns no `operations` array (only `join=transactions` exists,
        // on operation/payment/effect collections). Operations are therefore
        // fetched per transaction; see `fetch_soroban_details`.
        let url = format!(
            "{}/accounts/{}/transactions?cursor={}&order=asc&limit=200",
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
    let mut skipped = 0u64;
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

    let mut page_cursor = cursor.clone();
    let mut pages_fetched = 0usize;
    loop {
        if pages_fetched >= max_pages {
            warn!(
                contract = %contract.label,
                max_pages_per_cycle = max_pages,
                "reached max_pages_per_cycle; more transactions may be pending — continuing \
                 from the saved cursor next cycle"
            );
            break;
        }

        // Issue #23: use join=operations to fetch operations inline, eliminating
        // one HTTP request per transaction.
        let url = format!(
            "{}/accounts/{}/transactions?cursor={}&order=asc&limit={}&join=operations",
            poll_base, contract.contract_id, page_cursor, HORIZON_PAGE_LIMIT
        );
        let records = match fetch_transactions_page(client, contract, &url).await {
            Ok(PageFetch::Records(records)) => records,
            Ok(PageFetch::RateLimited { retry_after }) => {
                warn!(contract = %contract.label, retry_after, "Horizon returned 429 — backing off");
                tokio::time::sleep(Duration::from_secs(retry_after)).await;
                break;
            }
            // Nothing processed yet: surface the error and leave the cursor alone.
            Err(e) if pages_fetched == 0 => return Err(e),
            // Earlier pages were already processed and the cursor advanced past
            // them; stop here so their batched alerts and deliveries still finish.
        let (function_names, amount_stroops) =
            match fetch_soroban_details(client, poll_base, &tx_hash).await {
                Ok(details) => details,
                Err(e) => {
                    warn!(
                        contract = %contract.label, tx = %tx_hash, error = %e,
                        "could not fetch operation details — evaluating rules without them"
                    );
                    (Vec::new(), None)
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
                error!(contract = %contract.label, error = %e,
                    "failed to fetch a later page — continuing from the saved cursor next cycle");
                break;
            }
        };
        pages_fetched += 1;

        if records.is_empty() {
            if pages_fetched == 1 {
                debug!(contract = %contract.label, cursor = %cursor, "no new transactions");
            }
            break;
        }
        let page_len = records.len();
        let last_token = records.last().map(|r| r.tx.paging_token.clone());
        info!(contract = %contract.label, count = page_len, "fetched new transactions");

        for record in records {
            let paging_token = record.tx.paging_token.clone();
            let tx_hash = record.tx.hash.clone();

            // Advance cursor before enrichment so the tx is not re-processed even if
            // op enrichment fails.
            cursors.insert(cursor_key.clone(), paging_token.clone());

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
                    // The cursor already advanced past this transaction, so count
                    // the skip or it would be invisible in summaries and metrics.
                    skipped += 1;
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

            tx_count += 1;

            let payloads = evaluate(
                &eval_ctx,
                &contract.rules,
                &enriched,
                Some(&state.suppressor),
            );
            let enriched = if contract.needs_events() {
                let events = transaction_events(
                    client,
                    contract,
                    &tx_hash,
                    ledger,
                    &mut events_by_ledger,
                )
                .await;
                enriched.with_events(events)
            } else {
                enriched
            };

            tx_count += 1;
        let enriched = if contract.needs_events() {
            let events =
                transaction_events(client, contract, &tx_hash, ledger, &mut events_by_ledger).await;
            enriched.with_events(events)
        } else {
            enriched
        };

            let payloads = evaluate_contract(contract, canonical_base, &enriched);

            if payloads.is_empty() {
                debug!(contract = %contract.label, tx = %tx_hash,
                    "transaction evaluated but no rules matched");
            }
            let payloads = cooldowns.apply(&contract.rules, payloads, chrono::Utc::now());

            for payload in payloads {
                alert_count += 1;
                deliver_payload(
                    client, contract, &payload, dry_run, &mut webhook_failures,
                )
                .await;
            }
        }

        if page_len < HORIZON_PAGE_LIMIT {
            break;
        }
        match last_token {
            Some(token) => page_cursor = token,
            None => break,
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

    Ok((tx_count, alert_count, webhook_failures, skipped))
}

/// One page of a Horizon transactions request.
enum PageFetch {
    Records(Vec<HorizonTransactionWithOps>),
    /// Horizon answered 429; wait `retry_after` seconds before polling again.
    RateLimited { retry_after: u64 },
}

/// Fetches and parses one page of transactions from `url`.
async fn fetch_transactions_page(
    client: &Client,
    contract: &WatchedContract,
    url: &str,
) -> Result<PageFetch> {
    #[cfg(feature = "metrics")]
    let started = std::time::Instant::now();
    let response = client.get(url).send().await;
    #[cfg(feature = "metrics")]
    metrics::observe_horizon_request(contract.network.as_str(), started.elapsed().as_secs_f64());
    #[cfg(not(feature = "metrics"))]
    let _ = contract;
    let response = response.with_context(|| format!("GET {} failed", url))?;

    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5);
        return Ok(PageFetch::RateLimited { retry_after });
    }

    let status = response.status();
    let page: HorizonPage = response
        .error_for_status()
        .with_context(|| format!("Horizon returned HTTP {} for {}", status, url))?
        .json()
        .await
        .with_context(|| format!("failed to parse Horizon response from {}", url))?;
    Ok(PageFetch::Records(page._embedded.records))
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

/// Parses a Horizon decimal amount such as `"12.5000000"` into stroops
/// (1 XLM = 10^7 stroops) exactly, without going through floating point.
/// Returns `None` for anything that is not a non-negative decimal with at most
/// seven fractional digits.
fn parse_stroops(amount: &str) -> Option<u64> {
    let amount = amount.trim();
    let (whole, frac) = amount.split_once('.').unwrap_or((amount, ""));
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    if !whole.chars().all(|c| c.is_ascii_digit())
        || !frac.chars().all(|c| c.is_ascii_digit())
        || frac.len() > 7
    {
        return None;
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let frac: u64 = format!("{:0<7}", frac).parse().ok()?;
    whole.checked_mul(10_000_000)?.checked_add(frac)
}

fn is_native(asset_type: &Option<String>) -> bool {
    asset_type.as_deref() == Some("native")
}

/// Native XLM moved by one operation, in stroops, for the operation types that
/// move value besides `payment`:
///
/// - `create_account`: the `starting_balance`;
/// - `path_payment_strict_send` / `path_payment_strict_receive`: the native
///   leg — `amount` when the destination asset is native, otherwise
///   `source_amount` when the source asset is native (a path payment from XLM
///   into another asset). A native-to-native path payment counts once;
/// - `invoke_host_function`: every native `transfer` in `asset_balance_changes`
///   (Stellar Asset Contract transfers).
fn native_stroops_moved(op: &HorizonOperation) -> Option<u64> {
    match op.op_type.as_str() {
        "create_account" => op.starting_balance.as_deref().and_then(parse_stroops),
        "path_payment_strict_send" | "path_payment_strict_receive" => {
            if is_native(&op.asset_type) {
                op.amount.as_deref().and_then(parse_stroops)
            } else if is_native(&op.source_asset_type) {
                op.source_amount.as_deref().and_then(parse_stroops)
            } else {
                None
            }
        }
        "invoke_host_function" => {
            let mut total: Option<u64> = None;
            for change in op.asset_balance_changes.iter().flatten() {
                if change.change_type != "transfer" || !is_native(&change.asset_type) {
                    continue;
                }
                if let Some(stroops) = change.amount.as_deref().and_then(parse_stroops) {
                    total = Some(total.unwrap_or(0).saturating_add(stroops));
                }
            }
            total
        }
        _ => None,
    }
}

/// Extract Soroban details from a slice of already-fetched operations.
/// Used for both inline (join=operations) and separately-fetched operations.
///
/// The returned amount is the total native XLM moved by the transaction, in
/// stroops: `payment` operations plus the sources handled by
/// [`native_stroops_moved`]. `None` when no operation moved native XLM.
fn extract_soroban_details(ops: Vec<HorizonOperation>) -> (Vec<String>, Option<u64>) {
/// Number of fractional digits in a Horizon XLM amount (1 XLM = 10^7 stroops).
const STROOP_DECIMALS: usize = 7;

/// Largest operations page Horizon serves; a transaction has at most 100 operations.
const OPERATIONS_PAGE_LIMIT: usize = 200;

/// Safety cap on `_links.next` hops for a single transaction's operations.
const MAX_OPERATION_PAGES: usize = 10;

/// Number of separate `/transactions/{hash}/operations` requests made so far.
/// Horizon ignores `join=operations`, so this is one per transaction; logged at
/// debug level to make that N+1 behaviour visible.
static OPERATION_FETCHES: AtomicU64 = AtomicU64::new(0);

/// Parse a Horizon decimal amount string (e.g. `"1000.0000001"`) into stroops
/// using integer arithmetic only. Accepts 1..=7 fractional digits (or none) and
/// rejects signs, whitespace, empty parts and non-digits.
fn parse_stroops(amount: &str) -> Result<u64> {
    let (int_part, frac_part) = match amount.split_once('.') {
        Some((i, f)) => (i, f),
        None => (amount, ""),
    };
    if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!("malformed amount {:?}: invalid integer part", amount);
    }
    if amount.contains('.') && frac_part.is_empty() {
        anyhow::bail!("malformed amount {:?}: empty fractional part", amount);
    }
    if frac_part.len() > STROOP_DECIMALS || !frac_part.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!(
            "malformed amount {:?}: fractional part must be at most {} digits",
            amount,
            STROOP_DECIMALS
        );
    }

    let whole: u64 = int_part
        .parse()
        .with_context(|| format!("malformed amount {:?}: integer part out of range", amount))?;
    let padded = format!("{:0<width$}", frac_part, width = STROOP_DECIMALS);
    let frac: u64 = padded
        .parse()
        .with_context(|| format!("malformed amount {:?}: invalid fractional part", amount))?;

    whole
        .checked_mul(10u64.pow(STROOP_DECIMALS as u32))
        .and_then(|w| w.checked_add(frac))
        .with_context(|| format!("malformed amount {:?}: overflows u64 stroops", amount))
}

/// Extract Soroban details from a slice of already-fetched operations.
///
/// Only `payment` operations in the native asset (`asset_type == "native"`)
/// count towards the returned stroop total; payments in issued assets are not XLM.
/// A native payment with a malformed amount is an error.
fn extract_soroban_details(ops: Vec<HorizonOperation>) -> Result<(Vec<String>, Option<u64>)> {
    let mut function_names: Vec<String> = Vec::new();
    let mut total_stroops: u64 = 0;
    let mut has_amount = false;

    for op in ops {
        if let Some(stroops) = native_stroops_moved(&op) {
            total_stroops = total_stroops.saturating_add(stroops);
            has_amount = true;
        }
        if op.op_type == "invoke_host_function" {
            // Issue #3: `op.function` is the host function type, so matching
            // against it could never work. The contract function name is the
            // `Sym` argument.
            if let Some(name) = contract_function_name(&op.parameters) {
                function_names.push(name);
            } else {
                debug!(
                    host_function_type = ?op.host_function_type,
                    "invoke_host_function operation carried no Sym parameter;                      contract function name unavailable"
                );
            }
        }
        if op.op_type == "payment" && op.asset_type.as_deref() == Some("native") {
            if let Some(amt_str) = op.amount {
                if let Ok(xlm) = amt_str.parse::<f64>() {
                    total_stroops = total_stroops.saturating_add((xlm * 10_000_000.0) as u64);
                    has_amount = true;
                }
                let stroops = parse_stroops(&amt_str).map_err(|e| {
                    error!(error = %e, "invalid payment amount in Horizon operation");
                    e
                })?;
                total_stroops = total_stroops.saturating_add(stroops);
                has_payment = true;
            }
        }
    }

    Ok((
        function_names,
        if has_amount { Some(total_stroops) } else { None },
    )
        if has_payment {
            Some(total_stroops)
        } else {
            None
        },
    ))
}

/// Fetch all operations for a single transaction from Horizon.
/// Requests the maximum page size and follows `_links.next` while pages are full.
#[tracing::instrument(skip(client), fields(tx = %tx_hash))]
async fn fetch_soroban_details(
    client: &Client,
    base: &str,
    tx_hash: &str,
) -> Result<(Vec<String>, Option<u64>)> {
    let fetches = OPERATION_FETCHES.fetch_add(1, Ordering::Relaxed) + 1;
    debug!(tx = %tx_hash, fallback_operation_fetches = fetches, "fetching operations for transaction");

    let mut url = format!(
        "{}/transactions/{}/operations?limit={}",
        base, tx_hash, OPERATIONS_PAGE_LIMIT
    );
    let mut ops: Vec<HorizonOperation> = Vec::new();

    for _ in 0..MAX_OPERATION_PAGES {
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

        let count = page._embedded.records.len();
        ops.extend(page._embedded.records);

        let next = page._links.and_then(|l| l.next).map(|n| n.href);
        match next {
            Some(next_url) if count >= OPERATIONS_PAGE_LIMIT => url = next_url,
            _ => break,
        }
    }

    extract_soroban_details(ops)
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

    fn empty_page() -> serde_json::Value {
        serde_json::json!({ "_embedded": { "records": [] } })
    }

    /// Base64-encode `bytes` (standard alphabet, with padding).
    fn b64(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    /// The XDR-encoded `ScVal` base64 value of a `Sym`: a 4-byte big-endian
    /// discriminant (15 == SCV_SYMBOL), a 4-byte big-endian length, then the
    /// UTF-8 bytes padded to a 4-byte boundary.
    fn sym_param(name: &str) -> String {
        let mut raw = vec![0, 0, 0, 15];
        raw.extend_from_slice(&(name.len() as u32).to_be_bytes());
        raw.extend_from_slice(name.as_bytes());
        while raw.len() % 4 != 0 {
            raw.push(0);
        }
        b64(&raw)
    }

    /// A realistic `invoke_host_function` operation, where `function` is the
    /// host function type and the contract function name is the `Sym`
    /// parameter. See issue #3.
    fn invoke_op(function_name: &str) -> serde_json::Value {
        serde_json::json!({
            "type":     "invoke_host_function",
            "function": "HostFunctionTypeHostFunctionTypeInvokeContract",
            "parameters": [
                { "type": "Address", "value": "AAAAEgAAAAEJIX5C6S3X6ftDOw+T3MtGCdZN6Xv2zEfpPmTF42f8og==" },
                { "type": "Sym",     "value": sym_param(function_name) }
            ]
        })
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
                        invoke_op("withdraw")
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
            "{}/accounts/{}/transactions?cursor=now&order=asc&limit=200",
            server.uri(),
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        );
        let page: HorizonPage = client.get(&url).send().await.unwrap().json().await.unwrap();
        assert!(page._embedded.records.is_empty());
    }

    /// Issue #3: driven by a recorded real testnet `invoke_host_function`
    /// response, where `function` is the host function type and the contract
    /// function name is the `Sym` parameter.
    #[tokio::test]
    async fn fetch_soroban_details_extracts_contract_function_name() {
        let recorded: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/real_invoke_host_function.json"
        ))
        .expect("recorded fixture is valid JSON");
        assert_eq!(
            recorded["function"], "HostFunctionTypeHostFunctionTypeInvokeContract",
            "fixture must be a real response, where `function` is not the name"
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "_embedded": { "records": [recorded] } })),
            )
            .mount(&server)
            .await;

        let client = Client::new();
        let (fn_names, amount) = fetch_soroban_details(&client, &server.uri(), "abc123")
            .await
            .unwrap();

        assert_eq!(fn_names, vec!["push"], "the Sym parameter holds the name");
        assert!(amount.is_none());
    }

    /// The inline (`join=operations`) path must agree with the separate
    /// `/operations` fetch: `extract_soroban_details` is shared, so this covers
    /// the case where Horizon already returned the operation inline.
    #[test]
    fn extract_soroban_details_prefers_the_sym_parameter() {
        let recorded: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/real_invoke_host_function.json"
        ))
        .expect("recorded fixture is valid JSON");
        let op: HorizonOperation =
            serde_json::from_value(recorded).expect("operation deserialises");
        let (names, amount) = extract_soroban_details(vec![op]);
        assert_eq!(names, vec!["push"]);
        assert!(amount.is_none());
    }

    /// An `invoke_host_function` with no `Sym` argument yields no name rather
    /// than the host function type.
    #[test]
    fn extract_soroban_details_ignores_operations_without_a_sym() {
        let op = HorizonOperation {
            op_type: "invoke_host_function".into(),
            host_function_type: Some("HostFunctionTypeHostFunctionTypeInvokeContract".into()),
            parameters: vec![HorizonParameter {
                scv_type: "Address".into(),
                value: "AAAAEgAAAAEJIX5C6S3X6ftDOw+T3MtGCdZN6Xv2zEfpPmTF42f8og==".into(),
            }],
            amount: None,
        };
        let (names, _) = extract_soroban_details(vec![op]);
        assert!(names.is_empty(), "no Sym means no contract function name");
    }

    #[tokio::test]
    async fn fetch_soroban_details_extracts_payment_amount() {
        let server = MockServer::start().await;
        let ops = serde_json::json!({
            "_embedded": { "records": [{
                "type": "payment", "asset_type": "native", "amount": "1000.0000000"
            }] }
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

    fn payment_op(asset_type: &str, amount: &str) -> HorizonOperation {
        HorizonOperation {
            op_type: "payment".into(),
            function: None,
            amount: Some(amount.into()),
            asset_type: Some(asset_type.into()),
            asset_code: None,
            asset_issuer: None,
        }
    }

    #[test]
    fn parse_stroops_accepts_valid_amounts() {
        assert_eq!(parse_stroops("0.0000001").unwrap(), 1);
        assert_eq!(parse_stroops("0.29").unwrap(), 2_900_000);
        assert_eq!(parse_stroops("1000").unwrap(), 10_000_000_000);
        assert_eq!(parse_stroops("1000.0000001").unwrap(), 10_000_000_001);
        assert_eq!(
            parse_stroops("922337203685.4775807").unwrap(),
            9_223_372_036_854_775_807
        );
    }

    #[test]
    fn parse_stroops_rejects_malformed_amounts() {
        for bad in [
            "", ".", ".5", "1.", "abc", "1.2.3", "-1", "+1", " 1", "1 ", "1e3",
            "0.00000001", "1,5", "18446744073709.5516160",
        ] {
            assert!(parse_stroops(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn extract_soroban_details_errors_on_malformed_native_amount() {
        assert!(extract_soroban_details(vec![payment_op("native", "1.2.3")]).is_err());
    }

    #[test]
    fn extract_soroban_details_ignores_non_native_payments() {
        let ops = vec![
            payment_op("credit_alphanum4", "50000.0000000"),
            payment_op("native", "1.5"),
        ];
        let (_, amount) = extract_soroban_details(ops).unwrap();
        assert_eq!(amount, Some(15_000_000));

        let (_, amount) =
            extract_soroban_details(vec![payment_op("credit_alphanum4", "50000.0000000")])
                .unwrap();
        assert!(amount.is_none());
    }

    /// A large non-native payment must not populate the amount, so
    /// `LargeTransfer` cannot fire on it.
    #[tokio::test]
    async fn large_non_native_payment_does_not_fire_large_transfer() {
        let server = MockServer::start().await;
        let ops = serde_json::json!({
            "_embedded": { "records": [{
                "type": "payment", "asset_type": "credit_alphanum4",
                "asset_code": "USDC",
                "asset_issuer": "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                "amount": "50000.0000000"
            }] }
        });
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ops))
            .mount(&server)
            .await;

        let client = Client::new();
        let (_, amount) = fetch_soroban_details(&client, &server.uri(), "abc123")
            .await
            .unwrap();
        assert!(amount.is_none());
    }

    /// A 15-operation transaction whose matching function is the 12th op must
    /// not lose it, and the request must ask for the maximum page size.
    #[tokio::test]
    async fn fetch_soroban_details_reads_all_operations_of_large_transaction() {
        let server = MockServer::start().await;
        let records: Vec<serde_json::Value> = (1..=15)
            .map(|i| {
                if i == 12 {
                    serde_json::json!({ "type": "invoke_host_function", "function": "withdraw" })
                } else {
                    serde_json::json!({ "type": "bump_sequence" })
                }
            })
            .collect();
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "_embedded": { "records": records } })),
            )
            .mount(&server)
            .await;

        let client = Client::new();
        let (fn_names, _) = fetch_soroban_details(&client, &server.uri(), "abc123")
            .await
            .unwrap();
        assert_eq!(fn_names, vec!["withdraw"]);

        let reqs = server.received_requests().await.unwrap();
        assert!(reqs[0].url.query().unwrap_or("").contains("limit=200"));
    }

    /// Full pages are followed through `_links.next`.
    #[tokio::test]
    async fn fetch_soroban_details_follows_next_link() {
        let server = MockServer::start().await;
        let first: Vec<serde_json::Value> = (0..OPERATIONS_PAGE_LIMIT)
            .map(|_| serde_json::json!({ "type": "bump_sequence" }))
            .collect();
        let next_href = format!("{}/transactions/abc123/operations?cursor=200", server.uri());
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .and(wiremock::matchers::query_param("cursor", "200"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_embedded": { "records": [
                    { "type": "invoke_host_function", "function": "withdraw" }
                ] }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("/transactions/.*/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_embedded": { "records": first },
                "_links": { "next": { "href": next_href } }
            })))
            .mount(&server)
            .await;

        let client = Client::new();
        let (fn_names, _) = fetch_soroban_details(&client, &server.uri(), "abc123")
            .await
            .unwrap();
        assert_eq!(fn_names, vec!["withdraw"]);
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
            max_pages_per_cycle: None,
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
                "operations": [invoke_op("withdraw")]
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
                    "operations": [invoke_op("withdraw")],
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

    /// Issue #21: the failure log must identify which contract failed.
    #[test]
    fn poll_failure_log_carries_contract_context() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Capture;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let contract = WatchedContract {
            label: "Vault".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
            network: Network::Testnet,
            rules: vec![rule(AlertRule::AnyTransaction)],
            webhook_url: Some("https://hooks.example.com/test".into()),
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
        };

        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_poll_failure(&contract, 3, &anyhow::anyhow!("horizon unreachable"));
        });

        let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("contract polling task failed"), "{output}");
        assert!(output.contains("contract=Vault"), "{output}");
        assert!(output.contains("network=testnet"), "{output}");
        assert!(output.contains(&format!("contract_id={}", contract.contract_id)), "{output}");
        assert!(output.contains("consecutive_failures=3"), "{output}");
    }
}

// ── Tests: native amounts and cursor migration ────────────────────────────────

#[cfg(test)]
mod amount_and_cursor_tests {
    use super::*;

    fn ops(json: serde_json::Value) -> Vec<HorizonOperation> {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn parse_stroops_is_exact() {
        assert_eq!(parse_stroops("1"), Some(10_000_000));
        assert_eq!(parse_stroops("1.5"), Some(15_000_000));
        assert_eq!(parse_stroops("0.0000001"), Some(1));
        assert_eq!(parse_stroops("1000.0000000"), Some(10_000_000_000));
        assert_eq!(parse_stroops(".5"), Some(5_000_000));
        // f64 would turn this into 9_999_999.999… and truncate to 9_999_999.
        assert_eq!(parse_stroops("0.9999999"), Some(9_999_999));
    }

    #[test]
    fn parse_stroops_rejects_bad_input() {
        for bad in ["", ".", "-1", "1.00000001", "abc", "1.2.3", "1e3"] {
            assert_eq!(parse_stroops(bad), None, "{bad:?}");
        }
        assert_eq!(parse_stroops("99999999999999999999"), None);
    }

    #[test]
    fn payment_operations_still_count() {
        let (_, amount) = extract_soroban_details(ops(serde_json::json!([
            { "type": "payment", "amount": "1000.0000000" }
        ])));
        assert_eq!(amount, Some(10_000_000_000));
    }

    #[test]
    fn create_account_counts_starting_balance() {
        let (_, amount) = extract_soroban_details(ops(serde_json::json!([
            { "type": "create_account", "starting_balance": "2.5000000" }
        ])));
        assert_eq!(amount, Some(25_000_000));
    }

    #[test]
    fn path_payment_counts_the_native_leg() {
        // Destination receives XLM: count `amount`.
        let (_, to_native) = extract_soroban_details(ops(serde_json::json!([{
            "type": "path_payment_strict_send",
            "asset_type": "native", "amount": "10.0000000",
            "source_asset_type": "credit_alphanum4", "source_amount": "99.0000000"
        }])));
        assert_eq!(to_native, Some(100_000_000));

        // Source sends XLM: count `source_amount`.
        let (_, from_native) = extract_soroban_details(ops(serde_json::json!([{
            "type": "path_payment_strict_receive",
            "asset_type": "credit_alphanum4", "amount": "99.0000000",
            "source_asset_type": "native", "source_amount": "20.0000000"
        }])));
        assert_eq!(from_native, Some(200_000_000));

        // Native on both sides counts once.
        let (_, both) = extract_soroban_details(ops(serde_json::json!([{
            "type": "path_payment_strict_send",
            "asset_type": "native", "amount": "5.0000000",
            "source_asset_type": "native", "source_amount": "5.1000000"
        }])));
        assert_eq!(both, Some(50_000_000));
    }

    #[test]
    fn path_payment_between_non_native_assets_is_ignored() {
        let (_, amount) = extract_soroban_details(ops(serde_json::json!([{
            "type": "path_payment_strict_send",
            "asset_type": "credit_alphanum4", "amount": "10.0000000",
            "source_asset_type": "credit_alphanum4", "source_amount": "10.0000000"
        }])));
        assert_eq!(amount, None);
    }

    #[test]
    fn soroban_native_transfers_are_counted_from_asset_balance_changes() {
        let (functions, amount) = extract_soroban_details(ops(serde_json::json!([{
            "type": "invoke_host_function",
            "function": "HostFunctionTypeHostFunctionTypeInvokeContract",
            "asset_balance_changes": [
                { "type": "transfer", "asset_type": "native", "amount": "3.0000000" },
                { "type": "transfer", "asset_type": "native", "amount": "1.5000000" },
                { "type": "transfer", "asset_type": "credit_alphanum4", "amount": "500.0000000" },
                { "type": "mint", "asset_type": "native", "amount": "7.0000000" }
            ]
        }])));
        assert_eq!(functions.len(), 1);
        assert_eq!(amount, Some(45_000_000));
    }

    #[test]
    fn invoke_host_function_without_balance_changes_has_no_amount() {
        let (_, amount) = extract_soroban_details(ops(serde_json::json!([
            { "type": "invoke_host_function", "function": "withdraw" },
            { "type": "invoke_host_function", "function": "x", "asset_balance_changes": null }
        ])));
        assert_eq!(amount, None);
    }

    #[test]
    fn amounts_from_every_operation_type_are_summed() {
        let (_, amount) = extract_soroban_details(ops(serde_json::json!([
            { "type": "payment", "amount": "1.0000000" },
            { "type": "create_account", "starting_balance": "2.0000000" },
            { "type": "path_payment_strict_send", "asset_type": "native", "amount": "3.0000000" },
            { "type": "invoke_host_function", "asset_balance_changes": [
                { "type": "transfer", "asset_type": "native", "amount": "4.0000000" }
            ] }
        ])));
        assert_eq!(amount, Some(100_000_000));
    }

    const ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    fn saved(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn configured(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, id)| (k.to_string(), id.to_string()))
            .collect()
    }

    #[test]
    fn new_format_entries_are_kept_as_is() {
        let key = format!("testnet:{ID}");
        let migrated = migrate_saved_cursors(
            saved(&[(key.as_str(), "42")]),
            &configured(&[(key.as_str(), ID)]),
        );
        assert_eq!(migrated.get(&key).map(String::as_str), Some("42"));
    }

    #[test]
    fn legacy_entry_migrates_when_only_one_contract_has_that_id() {
        let key = format!("testnet:{ID}");
        let migrated = migrate_saved_cursors(saved(&[(ID, "42")]), &configured(&[(key.as_str(), ID)]));
        assert_eq!(migrated.get(&key).map(String::as_str), Some("42"));
        assert!(!migrated.contains_key(ID), "legacy key must be dropped");
    }

    #[test]
    fn legacy_entry_is_not_guessed_when_the_id_is_on_several_networks() {
        let testnet = format!("testnet:{ID}");
        let mainnet = format!("mainnet:{ID}");
        let migrated = migrate_saved_cursors(
            saved(&[(ID, "42")]),
            &configured(&[(testnet.as_str(), ID), (mainnet.as_str(), ID)]),
        );
        assert!(!migrated.contains_key(&testnet));
        assert!(!migrated.contains_key(&mainnet));
        assert!(!migrated.contains_key(ID));
    }

    #[test]
    fn existing_new_format_entry_wins_over_a_legacy_one() {
        let key = format!("testnet:{ID}");
        let migrated = migrate_saved_cursors(
            saved(&[(ID, "old"), (key.as_str(), "new")]),
            &configured(&[(key.as_str(), ID)]),
        );
        assert_eq!(migrated.get(&key).map(String::as_str), Some("new"));
    }

    #[test]
    fn new_format_entries_for_unconfigured_contracts_are_preserved() {
        let other = "mainnet:CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let key = format!("testnet:{ID}");
        let migrated = migrate_saved_cursors(
            saved(&[(other, "9")]),
            &configured(&[(key.as_str(), ID)]),
        );
        assert_eq!(migrated.get(other).map(String::as_str), Some("9"));
    }
}
