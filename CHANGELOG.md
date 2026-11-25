# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- State writer temp files now use unique names (`tempfile::NamedTempFile`) to prevent collisions between concurrent writers (async state writer, `save_cursors` on shutdown, reload migrations, `txwatch cursors` and `prune-cursors` commands) (#444).
- State writer errors are now logged with `tracing::error!` instead of being silently discarded (#445).
- `StateHandle::flush()` now waits for the writer to actually persist the latest state using a oneshot acknowledgement channel. The writer also batches queued updates with `try_recv` and runs writes in `spawn_blocking` to avoid blocking Tokio workers (#446).
- `txwatch cursors` and `prune-cursors` commands now load and save through `persistence::load_state`/`save_state`, correctly handling the new `StateDocument` format (with `cursors`, `cooldowns`, and `no_activity` fields) introduced in #281. Legacy flat cursor maps are still supported for backward compatibility. When editing cursors, cooldowns and NoActivity states are preserved (#447).

### Added

- `FunctionCalled` argument matching: `args = [{ index = 1, eq = "G…" }]` matches decoded invocation parameters (Address, Symbol, integer and String `ScVal`s); decoded invocations are included in the alert payload as `function_args` (#266).
- `Rate { rule, count, window_seconds }` alert rule: fires when the wrapped rule matches at least `count` times within a sliding `window_seconds` window per contract, emitting one alert per breach with the observed count (#267).
- `Memo { memo_type, equals | prefix }` alert rule: matches transaction memos by type and exact value or text prefix, with validation (#268).
- `NoActivity { minutes }` alert rule: fires once when a contract goes quiet longer than the configured threshold, and again (with `resolved = true`) when activity resumes. Evaluated per poll cycle, not per transaction. Null transaction hash and synthetic Horizon/Explorer links are used for the alert payload (#62).
- `EvalContext` struct replaces the five positional `&str` parameters of `evaluate()`, preventing argument-order bugs at compile time; `EvalContext::from_contract` derives all fields from a `WatchedContract` (#59).
- `WarningSuppressor`: repeated rule evaluation errors for the same rule are logged on the first occurrence and every 100th recurrence thereafter, preventing log flooding from structurally broken rules (#60).
- Property-based tests for `LargeTransfer` and `HighFee` rule thresholds using `proptest`, covering the full u64 range and verifying `evaluate` never panics (#61).
- `resolved` field added to `AlertPayload` JSON (`false` for incident alerts, `true` for recovery alerts); docs/configuration.md and README updated accordingly.
- CI now diffs the output of `txwatch schema` against the committed `docs/txwatch-config.schema.json`, so the committed schema can no longer drift from the code (#201).
- CI runs `actionlint` over the workflows, catching duplicated or broken steps (#202).
- CI test matrix now covers `ubuntu-latest`, `macos-latest` and `windows-latest`, including a Windows test that the cursor file is atomically replaced (#203).
- `SourceAccount` gains an explicit `mode = "in" | "not_in"` with an `accounts` list, plus an `alert_unless` allowlist shorthand. `mode = "not_in"` never fires when the transaction has no source account, so it can safely express "alert on any unknown caller" (#250).
- `cooldown_summary = true` on a rule emits a summary alert carrying the accumulated `suppressed_count` once the cooldown window expires, so matches suppressed at the end of a burst are reported (#259).

### Changed

- `evaluate()` now accepts `&EvalContext` and an optional `&WarningSuppressor` instead of five positional string arguments and no suppressor (#59, #60).
- `WatchedContract::collect_errors` and `AppConfig::validate` now collect all validation errors before returning instead of stopping at the first failure (#60).
- Rule evaluation errors are rate-limited: only the first occurrence and every 100th recurrence are logged (#60).
- `SourceAccount`'s `allow`/`deny` fields are deprecated in favour of `mode` + `accounts`; both previously fired on list *membership*, which reversed the expected "alert on unknown caller" behaviour (#250).
- `NoActivity` incidents now carry a unique `alert_id` per incident, and the recovery alert reuses its incident's `alert_id` so the two can be correlated (#254, #255).
- `alert_id` now hashes the network cursor ID, the rule type, the rule label and the rule's index within its contract's `rules` list — previously it only hashed `contract_id`, `tx_hash` and `rule_triggered`, so two rules with identical labels on one contract (e.g. two `LargeTransfer(>=100XLM)` rules routed to different webhooks) produced the same ID and were deduplicated away by receivers (#252). **IDs change**: receivers that persist `alert_id` for deduplication will see new values for alerts generated after upgrading, so old entries can no longer be matched against new ones. `EvalContext` gains a `network_id` field and `check_no_activity` gains a `rule_index` parameter.

### Removed

- `PlanCache` (and its `txwatch-poller` re-export) removed as dead code: it cached results for a `GET /api/analytics/plan-statistics` endpoint that TxWatch does not have (#292).
- **Breaking:** `YieldCalculator` and `PoolYield` are no longer exported from `txwatch-rules`. The module returned hard-coded "live" testnet data, ignored `pool_id`, and performed I/O in a crate documented as pure; it had no callers. Use a dedicated crate for live yield queries (#269).


- `X-TxWatch-Version` header on every webhook request
- `${ENV_VAR}` interpolation for `webhook_secret`
- Graceful shutdown on Ctrl-C: the in-flight poll cycle finishes before exit
- Optional Prometheus metrics (`metrics` feature of `txwatch-poller`) with a `/metrics` endpoint
- `cursor_file` setting to persist per-contract cursors across restarts
- HTTP pool settings: `http_pool_max_idle_per_host`, `http_tcp_keepalive_secs`, `http_connection_verbose`
- `HighFee` accepts `threshold_xlm` as an alternative to `threshold_stroops`
- Alert payload fields `rule_type`, `fee_charged_stroops`, `timestamp_iso` and `explorer_link`
- `txwatch schema` command and a committed JSON Schema for editor validation
- `txwatch validate --check-webhooks` and `--check-horizon` pre-flight checks
- Horizon operations fetched inline with `join=operations`
- Custom / local networks: `network = { horizon_url = "…", explorer_url = "…", passphrase = "…" }`, reported as `network = "custom"`; `docker-compose.local.yml` runs `stellar/quickstart --local` with TxWatch
- `TXWATCH_CONFIG` environment variable for the config path
- `SIGHUP` reloads the config without restarting; cursors of remaining contracts are kept and an invalid file is ignored
- Per-contract `poll_interval_seconds` override; each contract is polled on its own schedule and `txwatch validate` shows the effective interval
- `EventEmitted` rule matching Soroban contract events by topic (symbol on topic 0, optional positional topics with `*` wildcard); events are fetched from Soroban RPC `getEvents` and included in the new `matched_events` payload field. New `soroban_rpc_url` contract setting and `rpc_url` custom-network setting
- `batch_alerts` setting to coalesce alerts for the same contract into a single webhook delivery
- Optional per-rule `cooldown_seconds`: matches of the same (contract, rule) inside the window are suppressed and reported in the new `suppressed_count` payload field of the next alert

### Changed

- Parsed transfer amounts and fees above the total XLM supply (`MAX_XLM_SUPPLY_STROOPS`, 5 × 10^17 stroops) are discarded as malformed
- `HighFee` docs now say the rule fires when the fee is greater than or equal to the threshold (matching the behaviour), name the `fee_charged_stroops` payload field correctly and document `threshold_xlm`

- `poll_interval_seconds` is bounded to 5–3600 seconds
- `txwatch test-webhook` exits with code 1 when delivery fails
- Config parse errors name the offending field path
- Config validation reports every error at once instead of stopping at the first error
- `--config` defaults to `./txwatch.toml` instead of `config/example.toml`, and a missing config file is an error
- `poll_interval_seconds` defaults to 10 and is no longer required
- `http_pool_max_idle_per_host` and `http_tcp_keepalive_secs` have concrete defaults (10 and 30) and are range-checked (1–100 and 0–7200); `http_tcp_keepalive_secs = 0` now disables keepalive as documented
- Contract labels are trimmed, must not contain control characters, are limited to 128 characters, and are compared case-insensitively for duplicates
- `FunctionCalled` / `AdminFunctionCalled` function names must be valid Soroban symbols (at most 32 characters from `[a-zA-Z0-9_]`)
- The unused `soroban-xdr` feature and its `stellar-xdr` dependency were removed from `txwatch-rules`; no XDR decoding is implemented, so the previous "Soroban XDR decoding" claim was dropped (#204)

## [0.1.0] - 2025-01-01

### Added

- Real-time Soroban smart contract monitoring and webhook alert engine
- Six alert rule types: `AnyTransaction`, `TransactionFailed`, `LargeTransfer`, `FunctionCalled`, `AdminFunctionCalled`, `HighFee`
- Horizon REST API integration with cursor-based pagination for efficient polling
- TOML-based configuration with contract, rule, and webhook setup
- Support for multiple Stellar networks: mainnet, testnet, futurenet
- Webhook notification delivery with exponential backoff retry logic (up to 3 attempts)
- Webhook secret sent as a plain `X-TxWatch-Secret` header (superseded by HMAC signing; see Unreleased)
- Structured JSON alert payloads with transaction details and Horizon links
- Transaction enrichment with operation-level details (function names, transfer amounts)
- Fee extraction and analysis for cost monitoring
- Configurable polling intervals
- CLI commands: `watch`, `validate`, `test-webhook`
- Comprehensive configuration reference and alert rules documentation
- Integration test suite using wiremock for HTTP mocking

---

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
