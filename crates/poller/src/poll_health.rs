//! Per-contract poll scheduling and health tracking: failure streaks with
//! capped exponential back-off, unhealthy/recovered transitions, and a
//! deterministic per-contract start offset that spreads polls out in time.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use tokio::time::MissedTickBehavior;

/// Consecutive failed polls after which a contract is reported unhealthy.
pub(crate) const UNHEALTHY_THRESHOLD: u32 = 5;

/// Upper bound on the delay between polls of a failing contract. A poll
/// interval longer than this is never shortened.
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(600);

/// Default share of the poll interval used to spread contracts out (percent).
pub(crate) const DEFAULT_JITTER_PERCENT: u64 = 10;

/// Environment variable overriding [`DEFAULT_JITTER_PERCENT`]. `0` disables
/// the offset; values above `100` are clamped to `100`.
pub(crate) const JITTER_ENV: &str = "TXWATCH_POLL_JITTER_PERCENT";

/// Reads the jitter percentage from [`JITTER_ENV`], falling back to
/// [`DEFAULT_JITTER_PERCENT`] when unset or unparsable.
pub(crate) fn jitter_percent_from_env() -> u64 {
    std::env::var(JITTER_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_JITTER_PERCENT)
        .min(100)
}

/// Deterministic per-contract offset in `[0, interval * percent / 100)`,
/// derived from the contract ID so a contract keeps the same offset across
/// restarts and reloads. `percent == 0` disables it.
///
/// The ID is hashed with SHA-256 (#431): `DefaultHasher`'s algorithm is
/// unspecified and may change between Rust releases, which would reshuffle
/// every contract's offset on a toolchain bump.
pub(crate) fn start_offset(contract_id: &str, interval: Duration, percent: u64) -> Duration {
    if percent == 0 {
        return Duration::ZERO;
    }
    let digest = Sha256::digest(contract_id.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    let fraction = (u64::from_be_bytes(first) % 1000) as f64 / 1000.0;
    interval.mul_f64(percent.min(100) as f64 / 100.0 * fraction)
}

/// Builds the ticker that paces a contract's polls. The first tick fires
/// `interval + offset` from now (the caller polls once immediately), and a
/// cycle that overruns the interval delays the next tick instead of
/// bursting to catch up, so the period never drifts below `interval`.
pub(crate) fn poll_ticker(interval: Duration, offset: Duration) -> tokio::time::Interval {
    let mut ticker =
        tokio::time::interval_at(tokio::time::Instant::now() + interval + offset, interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker
}

/// Failure streak and last-success time for one contract.
///
/// Cloneable so the reload path can carry health state forward for contracts
/// whose rules did not change instead of recreating it (which would forget
/// failure streaks and re-trigger unhealthy/recovered transitions).
#[derive(Debug, Default, Clone)]
pub(crate) struct PollHealth {
    consecutive_failures: u32,
    last_success: Option<Instant>,
    unhealthy: bool,
}

impl PollHealth {
    pub(crate) fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Time since the last successful poll, or `None` if there has been none.
    pub(crate) fn since_last_success(&self) -> Option<Duration> {
        self.last_success.map(|t| t.elapsed())
    }

    /// Records a failed poll. Returns `true` exactly once per streak: on the
    /// failure that crosses [`UNHEALTHY_THRESHOLD`].
    pub(crate) fn record_failure(&mut self) -> bool {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if !self.unhealthy && self.consecutive_failures >= UNHEALTHY_THRESHOLD {
            self.unhealthy = true;
            return true;
        }
        false
    }

    /// Records a successful poll. Returns the length of the failure streak
    /// that just ended if the contract had been reported unhealthy.
    pub(crate) fn record_success(&mut self) -> Option<u32> {
        let recovered = self.unhealthy.then_some(self.consecutive_failures);
        self.consecutive_failures = 0;
        self.unhealthy = false;
        self.last_success = Some(Instant::now());
        recovered
    }

    /// Delay before the next poll: `interval` while healthy, doubling with
    /// every consecutive failure up to `max(MAX_BACKOFF, interval)`. The
    /// doubled delay is jittered (decorrelated) so contracts that failed
    /// together do not retry in lockstep and hammer Horizon on recovery.
    pub(crate) fn backoff_delay(&self, interval: Duration) -> Duration {
        if self.consecutive_failures == 0 {
            return interval;
        }
        let shift = self.consecutive_failures.min(16);
        let cap = MAX_BACKOFF.max(interval);
        let base = interval.saturating_mul(1 << shift).min(cap);
        jittered(base, cap)
    }
}

/// Applies decorrelated jitter to `base`: the result is drawn uniformly from
/// `[base / 2, base]`, then clamped to `cap`. This keeps the delay within the
/// same order of magnitude while breaking lockstep retries.
pub(crate) fn jittered(base: Duration, cap: Duration) -> Duration {
    let half = base / 2;
    let span = base.saturating_sub(half);
    let nanos = span.as_nanos();
    let offset = if nanos == 0 {
        0
    } else {
        // Cheap pseudo-random source; jitter need not be cryptographic.
        let mut hasher = DefaultHasher::new();
        Instant::now().hash(&mut hasher);
        (hasher.finish() % (nanos as u64 + 1)) as u128
    };
    half.saturating_add(Duration::from_nanos(offset as u64))
        .min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_is_capped() {
        let interval = Duration::from_secs(10);
        let mut health = PollHealth::default();
        assert_eq!(health.backoff_delay(interval), interval);

        // Expected deterministic (un-jittered) upper bounds per failure.
        let upper = [20u64, 40, 80, 160, 320, 600, 600, 600];
        for &max in &upper {
            health.record_failure();
            let delay = health.backoff_delay(interval).as_secs();
            // Jitter draws from [max/2, max], never exceeding the cap.
            assert!(
                delay >= max / 2 && delay <= max,
                "delay {delay}s out of bounds [{}, {max}]s",
                max / 2
            );
            assert!(delay <= MAX_BACKOFF.as_secs());
        }
    }

    #[test]
    fn backoff_never_shortens_a_long_interval() {
        let interval = Duration::from_secs(3600);
        let mut health = PollHealth::default();
        health.record_failure();
        let delay = health.backoff_delay(interval);
        assert!(delay >= interval / 2 && delay <= interval);
    }

    #[test]
    fn unhealthy_is_reported_once_per_streak_and_recovery_once() {
        let mut health = PollHealth::default();
        let crossings: Vec<bool> = (0..UNHEALTHY_THRESHOLD + 2)
            .map(|_| health.record_failure())
            .collect();
        assert_eq!(crossings.iter().filter(|c| **c).count(), 1);
        assert!(crossings[(UNHEALTHY_THRESHOLD - 1) as usize]);

        assert_eq!(health.record_success(), Some(UNHEALTHY_THRESHOLD + 2));
        assert_eq!(health.consecutive_failures(), 0);
        assert!(health.since_last_success().is_some());
        assert_eq!(health.record_success(), None);
    }

    #[test]
    fn brief_failure_streak_is_not_reported_as_recovery() {
        let mut health = PollHealth::default();
        health.record_failure();
        assert_eq!(health.record_success(), None);
    }

    #[test]
    fn start_offset_is_deterministic_bounded_and_disable_able() {
        let interval = Duration::from_secs(10);
        let a = start_offset("CONTRACT_A", interval, 10);
        assert_eq!(a, start_offset("CONTRACT_A", interval, 10));
        assert!(a < Duration::from_secs(1));
        assert_eq!(start_offset("CONTRACT_A", interval, 0), Duration::ZERO);

        let distinct: std::collections::HashSet<_> = (0..20)
            .map(|i| start_offset(&format!("CONTRACT_{i}"), interval, 10))
            .collect();
        assert!(
            distinct.len() > 1,
            "offsets should differ between contracts"
        );
    }

    /// #431: pin the offset for known IDs so a toolchain or hasher change that
    /// would reshuffle every contract's schedule fails this test. Expected
    /// values are the first 8 bytes of SHA-256(id), big-endian, mod 1000.
    #[test]
    fn start_offset_is_pinned_for_known_contract_ids() {
        let interval = Duration::from_secs(1000);
        // 100% of a 1000 s interval: the offset in seconds is the fraction * 1000.
        assert_eq!(
            start_offset("CONTRACT_A", interval, 100),
            Duration::from_secs(158)
        );
        assert_eq!(
            start_offset(
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
                interval,
                100
            ),
            Duration::from_secs(324)
        );
        // 10% of a 10 s interval for the same ID scales the same fraction.
        assert_eq!(
            start_offset("CONTRACT_A", Duration::from_secs(10), 10),
            Duration::from_millis(158)
        );
    }

    /// The period between ticks must equal the configured interval even though
    /// each cycle takes time (the old sleep-after-cycle loop drifted to
    /// interval + cycle duration).
    #[tokio::test(start_paused = true)]
    async fn ticks_happen_at_the_configured_period() {
        let interval = Duration::from_secs(10);
        let mut ticker = poll_ticker(interval, Duration::ZERO);

        let mut ticks = Vec::new();
        for _ in 0..4 {
            ticker.tick().await;
            ticks.push(tokio::time::Instant::now());
            // Simulated poll cycle.
            tokio::time::sleep(Duration::from_secs(4)).await;
        }
        for pair in ticks.windows(2) {
            assert_eq!(pair[1] - pair[0], interval);
        }
    }

    /// A cycle longer than the interval delays the next tick rather than
    /// firing a burst of catch-up ticks.
    #[tokio::test(start_paused = true)]
    async fn overrunning_cycle_delays_instead_of_bursting() {
        let interval = Duration::from_secs(10);
        let mut ticker = poll_ticker(interval, Duration::ZERO);

        ticker.tick().await;
        tokio::time::sleep(Duration::from_secs(35)).await;
        ticker.tick().await;
        let after_overrun = tokio::time::Instant::now();
        ticker.tick().await;
        assert_eq!(tokio::time::Instant::now() - after_overrun, interval);
    }
}
