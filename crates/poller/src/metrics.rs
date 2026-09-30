//! Prometheus metrics for TxWatch (enabled with the `metrics` feature flag).
//!
//! Exposes, labelled by `contract` (label) and `network` where noted:
//! - `txwatch_transactions_total{contract,network}`      — transactions processed
//! - `txwatch_alerts_total{contract,network}`            — alert payloads sent (rules matched)
//! - `txwatch_transactions_skipped_total{contract,network}` — transactions dropped because they could not be enriched
//! - `txwatch_webhook_failures_total{contract,network}`  — permanent webhook delivery failures
//! - `txwatch_horizon_request_duration_seconds{network}` — Horizon request latency
//! - `txwatch_webhook_delivery_duration_seconds`         — webhook delivery latency (incl. retries)
//! - `txwatch_last_successful_poll_timestamp_seconds{contract,network}` — data freshness
//! - `txwatch_consecutive_poll_failures{contract,network}` — current failure streak
//! - `txwatch_build_info{version,git_sha}`               — always 1
//!
//! An optional HTTP server can be started by calling [`serve_metrics`]:
//!
//! - `GET /metrics` — Prometheus text exposition format
//! - `GET /healthz` — `200` while the process is running
//! - `GET /readyz`  — `200` once a poll has succeeded within the last
//!   2 × `poll_interval_seconds`, `503` otherwise
//!
//! Any other path returns `404`, and any other method `405`.

use anyhow::{Context, Result};
use prometheus::{
    register_histogram, register_histogram_vec, register_int_counter_vec, register_int_gauge_vec,
    Histogram, HistogramVec, IntCounterVec, IntGaugeVec,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use http_body_util::Full;
use hyper::{
    body::Bytes,
    header::{HeaderValue, CONTENT_TYPE},
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, sync::watch};

// ── Metrics ───────────────────────────────────────────────────────────────────

const CONTRACT_LABELS: &[&str] = &["contract", "network"];

fn transactions_total() -> &'static IntCounterVec {
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    C.get_or_init(|| {
        register_int_counter_vec!(
            "txwatch_transactions_total",
            "Total Stellar transactions processed, per watched contract",
            CONTRACT_LABELS
        )
        .expect("register txwatch_transactions_total")
    })
}

fn transactions_skipped_total() -> &'static IntCounterVec {
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    C.get_or_init(|| {
        register_int_counter_vec!(
            "txwatch_transactions_skipped_total",
            "Total transactions skipped because they could not be enriched (e.g. an unparseable created_at), per watched contract",
            CONTRACT_LABELS
        )
        .expect("register txwatch_transactions_skipped_total")
    })
}

fn alerts_total() -> &'static IntCounterVec {
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    C.get_or_init(|| {
        register_int_counter_vec!(
            "txwatch_alerts_total",
            "Total alert payloads sent (rules matched), per watched contract",
            CONTRACT_LABELS
        )
        .expect("register txwatch_alerts_total")
    })
}

fn webhook_failures_total() -> &'static IntCounterVec {
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    C.get_or_init(|| {
        register_int_counter_vec!(
            "txwatch_webhook_failures_total",
            "Total permanent webhook delivery failures (after all retries), per watched contract",
            CONTRACT_LABELS
        )
        .expect("register txwatch_webhook_failures_total")
    })
}

fn horizon_request_duration() -> &'static HistogramVec {
    static H: OnceLock<HistogramVec> = OnceLock::new();
    H.get_or_init(|| {
        register_histogram_vec!(
            "txwatch_horizon_request_duration_seconds",
            "Duration of Horizon HTTP requests",
            &["network"]
        )
        .expect("register txwatch_horizon_request_duration_seconds")
    })
}

fn webhook_delivery_duration() -> &'static Histogram {
    static H: OnceLock<Histogram> = OnceLock::new();
    H.get_or_init(|| {
        register_histogram!(
            "txwatch_webhook_delivery_duration_seconds",
            "Duration of webhook deliveries, including retries"
        )
        .expect("register txwatch_webhook_delivery_duration_seconds")
    })
}

fn last_successful_poll() -> &'static IntGaugeVec {
    static G: OnceLock<IntGaugeVec> = OnceLock::new();
    G.get_or_init(|| {
        register_int_gauge_vec!(
            "txwatch_last_successful_poll_timestamp_seconds",
            "Unix time of the last successful poll, per watched contract",
            CONTRACT_LABELS
        )
        .expect("register txwatch_last_successful_poll_timestamp_seconds")
    })
}

fn consecutive_poll_failures() -> &'static IntGaugeVec {
    static G: OnceLock<IntGaugeVec> = OnceLock::new();
    G.get_or_init(|| {
        register_int_gauge_vec!(
            "txwatch_consecutive_poll_failures",
            "Consecutive failed polls, per watched contract (0 after a success)",
            CONTRACT_LABELS
        )
        .expect("register txwatch_consecutive_poll_failures")
    })
}

/// Registers `txwatch_build_info{version,git_sha} 1`. `git_sha` comes from the
/// `TXWATCH_GIT_SHA` environment variable at build time, if set.
pub fn register_build_info() {
    static G: OnceLock<IntGaugeVec> = OnceLock::new();
    G.get_or_init(|| {
        let gauge = register_int_gauge_vec!(
            "txwatch_build_info",
            "Build information; the value is always 1",
            &["version", "git_sha"]
        )
        .expect("register txwatch_build_info");
        gauge
            .with_label_values(&[
                env!("CARGO_PKG_VERSION"),
                option_env!("TXWATCH_GIT_SHA").unwrap_or("unknown"),
            ])
            .set(1);
        gauge
    });
}

/// Increment `txwatch_transactions_total` for a contract by `n`.
pub fn inc_transactions(contract: &str, network: &str, n: u64) {
    transactions_total()
        .with_label_values(&[contract, network])
        .inc_by(n);
}

/// Increment `txwatch_transactions_skipped_total` for a contract by `n`.
/// Calling it with `0` creates the series so it is exported before any skip.
pub fn inc_transactions_skipped(contract: &str, network: &str, n: u64) {
    transactions_skipped_total()
        .with_label_values(&[contract, network])
        .inc_by(n);
}

/// Increment `txwatch_alerts_total` for a contract by `n`.
pub fn inc_alerts(contract: &str, network: &str, n: u64) {
    alerts_total()
        .with_label_values(&[contract, network])
        .inc_by(n);
}

/// Increment `txwatch_webhook_failures_total` for a contract by 1.
pub fn inc_webhook_failures(contract: &str, network: &str) {
    webhook_failures_total()
        .with_label_values(&[contract, network])
        .inc();
}

/// Record how long a Horizon request on `network` took.
pub fn observe_horizon_request(network: &str, seconds: f64) {
    horizon_request_duration()
        .with_label_values(&[network])
        .observe(seconds);
}

/// Record how long one webhook delivery (including retries) took.
pub fn observe_webhook_delivery(seconds: f64) {
    webhook_delivery_duration().observe(seconds);
}

/// Record a successful poll of a contract: freshness timestamp and reset
/// failure streak.
pub fn record_poll_success(contract: &str, network: &str) {
    last_successful_poll()
        .with_label_values(&[contract, network])
        .set(now_secs() as i64);
    consecutive_poll_failures()
        .with_label_values(&[contract, network])
        .set(0);
}

/// Record a failed poll of a contract.
pub fn record_poll_failure(contract: &str, network: &str) {
    consecutive_poll_failures()
        .with_label_values(&[contract, network])
        .inc();
}

// ── Readiness ─────────────────────────────────────────────────────────────────

/// Unix seconds of the last successful contract poll (0 = never).
static LAST_POLL_SUCCESS: AtomicU64 = AtomicU64::new(0);
/// Configured poll interval in seconds, used to judge readiness.
static POLL_INTERVAL_SECS: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Record the configured poll interval (called once by the poller at start-up).
pub fn set_poll_interval(secs: u64) {
    POLL_INTERVAL_SECS.store(secs, Ordering::Relaxed);
}

/// Record that a contract poll just succeeded (for readiness).
pub fn mark_poll_success() {
    LAST_POLL_SUCCESS.store(now_secs(), Ordering::Relaxed);
}

/// Ready when a poll succeeded within the last 2 × poll interval.
fn is_ready() -> bool {
    let last = LAST_POLL_SUCCESS.load(Ordering::Relaxed);
    let interval = POLL_INTERVAL_SECS.load(Ordering::Relaxed);
    if last == 0 || interval == 0 {
        return false;
    }
    now_secs().saturating_sub(last) <= interval.saturating_mul(2)
}

// ── HTTP server ───────────────────────────────────────────────────────────────

/// Serve `/metrics`, `/healthz` and `/readyz` on `addr` until `shutdown` fires.
///
/// Binds the listener, starts serving on a background task and returns the
/// address that was actually bound. Callers may pass port `0`, so the returned
/// address is the one to scrape. Returns an error only if the listener cannot
/// be bound.
pub async fn serve_metrics(
    addr: SocketAddr,
    shutdown: watch::Receiver<bool>,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind metrics listener on {addr}"))?;
    // The caller may pass port 0, so hand back what we actually bound.
    let bound = listener
        .local_addr()
        .with_context(|| format!("read local address of metrics listener on {addr}"))?;

    tokio::spawn(async move {
        if let Err(e) = accept_loop(listener, shutdown).await {
            tracing::error!(error = %e, "metrics endpoint stopped");
        }
    });

    Ok(bound)
}

async fn accept_loop(listener: TcpListener, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(error = %err, "metrics accept failed");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = hyper::service::service_fn(handle_request);
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        tracing::debug!(error = %err, "metrics connection error");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let response = match (req.method().as_str(), req.uri().path()) {
        ("GET", "/metrics") => text_response(
            StatusCode::OK,
            prometheus::TextEncoder::new()
                .encode_to_string(&prometheus::gather())
                .unwrap_or_default(),
        ),
        ("GET", "/healthz") => text_response(StatusCode::OK, "ok\n".to_string()),
        ("GET", "/readyz") => {
            if is_ready() {
                text_response(StatusCode::OK, "ready\n".to_string())
            } else {
                text_response(StatusCode::SERVICE_UNAVAILABLE, "not ready\n".to_string())
            }
        }
        ("GET", _) => text_response(StatusCode::NOT_FOUND, "not found\n".to_string()),
        _ => text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed\n".to_string(),
        ),
    };
    Ok(response)
}

fn text_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}
