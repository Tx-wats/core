# Configuration Reference

Config is a TOML file passed via `--config`, or the `TXWATCH_CONFIG` environment variable, defaulting to
`./txwatch.toml`. TxWatch exits with an error if the file does not exist.

`txwatch validate` (and startup) reports every validation error at once, one per line, rather than stopping
at the first.

While `txwatch watch` is running, `SIGHUP` re-reads and validates the file. A valid config is applied in place:
contracts that remain keep their cursors, and new contracts start from their `cursor_file` entry or `now`. An
invalid config is logged and the previous one keeps running. HTTP pool settings only change on restart.

## Editor validation

The committed [`txwatch-config.schema.json`](txwatch-config.schema.json) describes the supported configuration shape. In Taplo or Even Better TOML, add this directive at the top of a TOML file to enable completion and inline validation:

```toml
#:schema ../docs/txwatch-config.schema.json
```

The schema is also available from the CLI with `txwatch schema`. CI verifies that the committed schema remains synchronized with the derived Rust model.

## Top-level fields

| Field                         | Type            | Required | Default | Description |
|-------------------------------|-----------------|----------|---------|-------------|
| `poll_interval_seconds`       | u64             | no       | `10`    | How often to poll Horizon (seconds). Must be ≥ 5 and ≤ 3600. Each contract can override it (see below). |
| `contracts`                   | array of tables | yes      | —       | The `[[contracts]]` entries (see below). At least one is required; labels must be unique (case-insensitive), and each `(network, contract_id)` pair may appear only once. |
| `cursor_file`                 | string (path)   | no       | unset   | JSON file used to persist the per-contract cursor map. Loaded on startup and rewritten after each poll cycle. When unset, cursors start at Horizon's `now` and are not persisted. A missing or unparsable file falls back to `now`. Cursors are keyed `<network>:<contract_id>`; a file written by an older version (keyed by bare contract ID) is migrated automatically, except for a contract ID watched on several networks, which starts from `now`. See [Cursor file locking and state](#cursor-file-locking-and-state). |
| `concurrency`                 | usize           | no       | `10`    | Maximum number of contracts polled concurrently by `txwatch watch --once`. Must be 1–1000. `txwatch watch` polls every contract in its own task and ignores this setting. |
| `http_pool_max_idle_per_host` | usize           | no       | `10`    | Maximum idle connections kept per host in the HTTP pool. Must be 1–100. Lower values use less memory; higher values help with many contracts. |
| `http_tcp_keepalive_secs`     | u64             | no       | `30`    | TCP keepalive interval (seconds) for pooled HTTP connections. Must be ≤ 7200; `0` disables keepalive. |
| `http_connection_verbose`     | bool            | no       | `false` | Reserved for HTTP connection-pool debug output. Accepted by the parser but currently has no effect. |
| `max_pages_per_cycle`         | usize           | no       | `10`    | Maximum Horizon pages (200 transactions each) fetched per contract in one poll cycle. Must be 1–1000. Pages are processed as they arrive; when the cap is hit a warning is logged and the next cycle continues from the saved cursor. |
| `max_contracts`               | usize           | no       | `100`   | Maximum number of `[[contracts]]` entries. Must be 1–10000. Raise it only when your Horizon instance (typically your own) can take the extra polling load. |
| `summary_interval_seconds`    | u64             | no       | `60`    | How often the poller logs a periodic summary line (seconds). Set to `0` to disable the periodic summary entirely. |

Unknown top-level keys are rejected.

### Cursor file locking and state

When `cursor_file` is set, TxWatch takes an exclusive advisory lock on `<cursor_file>.lock` at startup and
holds it for the lifetime of the process. If the lock is already held — for example because a second TxWatch
instance (a rolling deploy that has not finished draining) points at the same `cursor_file` — startup fails
immediately with an error naming the lock file, instead of letting the two instances overwrite each other's
cursors and deliver duplicate alerts. The lock is released automatically when the process exits, including on
a crash.

The cursor file is rewritten atomically: the new contents are written to a unique temporary file in the same
directory (named after the target file, the process ID and a random suffix) and then renamed over the target.
Concurrent writers therefore never observe a partially written file, and a `cursor_file` whose name already
ends in `.tmp` is handled correctly because the scratch path is never the target path.

The file is versioned and holds more than cursors:

```json
{
  "version": 2,
  "cursors": { "testnet:CAAA...": "1234567890" },
  "cooldowns": { "testnet:CAAA...:LargeTransfer(>=10000XLM)": 1705316096 },
  "no_activity": { "testnet:CAAA...:NoActivity": { "alerting": true, "since": 1705316096 } }
}
```

- `version` — format version. Version `2` is written by current releases.
- `cursors` — per-contract Horizon cursors, keyed `<network>:<contract_id>`.
- `cooldowns` — per-contract, per-rule timestamp (Unix seconds) of the last alert sent, so `cooldown_seconds`
  is enforced across restarts and across separate `txwatch watch --once` runs.
- `no_activity` — per-contract `NoActivity` state, so an open incident is not re-fired after a restart and a
  recovery alert is still sent if TxWatch restarted while alerting.

Both `txwatch watch` and `txwatch watch --once` load this state at startup and persist it after each poll cycle.

A file written by an older version — either the legacy cursor-only map (keyed by bare contract ID) or a
version-1 file with a top-level cursor map — is migrated automatically on load: cursors are re-keyed
`<network>:<contract_id>` where unambiguous, and cooldown and `NoActivity` state starts empty. As before, a
contract ID watched on several networks cannot be disambiguated from a legacy file and starts from `now`.

> **Horizon rate limits:** Polling too frequently across many contracts can exhaust Horizon's per-IP request quota,
> resulting in `429 Too Many Requests` responses. Sustained polling across six or more contracts at intervals below
> 10 seconds is known to trigger rate limiting in production. The recommended minimum is
> `poll_interval_seconds = 10`; for high-volume deployments with many contracts, `poll_interval_seconds = 30` or
> higher is advised. TxWatch logs a startup warning when more than 5 contracts are polled at an effective
> interval below 10 seconds.
>
> **Poll staggering:** each contract polls on its own fixed-period schedule. The first poll of a contract happens
> immediately at startup; every later poll is shifted by a deterministic per-contract offset of up to 10% of the
> contract's poll interval, so contracts do not all hit Horizon at the same instant every cycle. Set the
> `TXWATCH_POLL_JITTER_PERCENT` environment variable to change the percentage (clamped to 100); `0` disables the
> offset. A contract that keeps failing is polled less often (the delay doubles per consecutive failure, capped at
> 10 minutes), is reported once as unhealthy after 5 consecutive failures, and is reported once as recovered on its
> next success. `txwatch_consecutive_poll_failures` exposes the failure streak.

> **Contract limit:** a configuration may hold at most `max_contracts` (default `100`, `MAX_CONTRACTS` in `txwatch-config`) `[[contracts]]` entries; more is rejected at startup. Every contract is polled by its own task, so very large lists can exhaust memory, file descriptors or the public Horizon rate limit. Split large deployments across several TxWatch instances, or raise `max_contracts` (up to 10000) when polling your own Horizon.

## `[[contracts]]`

Each entry defines one watched Soroban contract. At least one entry is required.

| Field            | Type            | Required | Description |
|------------------|-----------------|----------|-------------|
| `label`          | string          | yes      | Human-readable name shown in logs and alert payloads. Surrounding whitespace is trimmed. Must not be blank, contain control characters (newlines, ANSI escapes, …) or exceed 128 characters; must be unique across contracts, ignoring case. |
| `contract_id`    | string          | yes      | Stellar contract StrKey (`C…`, 56 characters). The address is fully decoded: characters outside `A–Z2–7` (lowercase, `0`, `1`, `8`, `9`), a non-contract version byte (e.g. a `G…` account) and a bad checksum are each reported as a distinct error. |
| `network`        | string or table | yes      | `mainnet`, `testnet`, `futurenet`, or a custom network table (see below). |
| `rules`          | array of tables | yes      | The `[[contracts.rules]]` entries (see below). At least one is required. |
| `webhook_url`    | string          | yes      | `http://` or `https://` URL with a host that receives the alert JSON. |
| `enabled`        | bool            | no       | Default `true`. Set `false` to pause monitoring this contract without removing it. Shown as `(disabled)` in `txwatch validate`. |
| `webhook_url`    | string          | see below | `http://` or `https://` URL with a host that receives alerts. Shorthand for one destination, described by the `webhook_*` fields below. Required unless `webhooks` has at least one entry. |
| `poll_interval_seconds` | u64      | no       | Polls this contract at its own interval instead of the top-level `poll_interval_seconds`. Same bounds (5–3600). Contracts are scheduled independently; `txwatch validate` prints each contract's effective interval. |
| `webhook_secret` | string          | no       | When set, every webhook POST carries `X-TxWatch-Signature: sha256=<hex HMAC-SHA256 of the body>` **and** the raw secret in `X-TxWatch-Secret`. Supports [environment interpolation](#environment-variable-interpolation). |
| `webhook_format` | string          | no       | Body shape for `webhook_url`: `txwatch` (default), `slack`, `discord`, `pagerduty` or `teams`. See [Webhook formats](#webhook-formats). |
| `webhook_headers` | table          | no       | Extra HTTP headers for `webhook_url`, e.g. `{ "Authorization" = "Bearer ${TOKEN}" }`. See [Custom headers](#custom-headers). |
| `webhook_routing_key` | string     | no       | PagerDuty integration key; required when `webhook_format = "pagerduty"`, rejected otherwise. Supports interpolation. |
| `webhooks`       | array of tables | no       | Additional destinations (`[[contracts.webhooks]]`), each with `url`, optional `secret`, `format`, `headers` and `routing_key` (same meaning as the `webhook_*` fields), plus `min_severity`, `rule_types`, `template`/`template_file` and `client_cert`/`client_key`/`ca_cert`. See [Multiple destinations](#multiple-destinations). |
| `webhook_url`    | string          | yes      | `http://` or `https://` URL with a host that receives the alert JSON. Supports [environment interpolation](#environment-variable-interpolation). |
| `poll_interval_seconds` | u64      | no       | Polls this contract at its own interval instead of the top-level `poll_interval_seconds`. Same bounds (5–3600). Contracts are scheduled independently; `txwatch validate` prints each contract's effective interval. |
| `soroban_rpc_url` | string         | no       | Soroban RPC endpoint used to fetch contract events for `EventEmitted` rules. Defaults to `https://soroban-testnet.stellar.org` (testnet), `https://rpc-futurenet.stellar.org` (futurenet) or the custom network's `rpc_url`. Mainnet has no default, so a mainnet contract with an `EventEmitted` rule must set it. |
| `webhook_secret` | string          | no       | When set, every webhook POST carries `X-TxWatch-Signature: sha256=<hex HMAC-SHA256 of the body>` **and** the raw secret in `X-TxWatch-Secret`. Supports `${ENV_VAR}` interpolation (e.g. `webhook_secret = "${MY_SECRET}"`); an unset variable is a startup error. |
| `batch_alerts`   | bool            | no       | Default `false`. When `true`, all alerts from one poll cycle are sent as a single `{"alerts": [...]}` POST (at most 50 per request, larger bursts are split). Useful for digest receivers and rate-limited targets such as Slack. See [Batched payload](#batched-payload). |
| `webhook_secret` | string          | no       | When set, every webhook POST carries `X-TxWatch-Signature: sha256=<hex HMAC-SHA256 of the body>` **and** the raw secret in `X-TxWatch-Secret`. Supports [environment interpolation](#environment-variable-interpolation). |

Unknown keys inside a `[[contracts]]` entry (or a `[[contracts.webhooks]]` entry) are rejected. The
`webhook_*` fields other than `webhook_url` may only be set together with `webhook_url`.

### Multiple destinations

Every alert is delivered to each destination: the `webhook_url` shorthand (if set) and every
`[[contracts.webhooks]]` entry. Destinations are delivered to concurrently and retried
independently, so a slow or failing receiver never delays or blocks the others. Each destination
that still fails after its retries counts as one failed webhook delivery. Polling happens once per
contract no matter how many destinations it has, so there is no need to duplicate a contract block.

```toml
[[contracts]]
label       = "Treasury"
contract_id = "CAAA..."
network     = "mainnet"
webhook_url = "https://internal.example.com/txwatch"   # txwatch JSON, as before

  [[contracts.webhooks]]
  url    = "https://hooks.slack.com/services/T000/B000/XXXX"
  format = "slack"

  [[contracts.webhooks]]
  url         = "https://events.pagerduty.com/v2/enqueue"
  format      = "pagerduty"
  routing_key = "${PAGERDUTY_ROUTING_KEY}"

  [[contracts.rules]]
  type = "AdminFunctionCalled"
  function_names = ["upgrade", "set_admin"]
```

`txwatch validate` lists every destination with its format; secrets and routing keys are shown only
as set, and header values as `<redacted>`. `validate --check-webhooks` probes every destination,
and `txwatch test-webhook --contract <label>` sends a test alert to each of them.

> Only secrets, header values, routing keys, `template_file` and TLS file paths are interpolated;
> `url` is used as written.

#### Per-destination filters

`[[contracts.webhooks]]` entries can limit which alerts they receive, so one contract can page
PagerDuty only for critical alerts while Slack gets everything:

| Field          | Type             | Description |
|----------------|------------------|-------------|
| `min_severity` | string           | `info`, `warning` or `critical`. Only alerts at or above this severity are delivered; alerts whose rule has no `severity` are skipped. |
| `rule_types`   | array of strings | Only alerts from these rule types (e.g. `["LargeTransfer", "AdminFunctionCalled"]`) are delivered. Empty or omitted delivers every rule type. |

```toml
  [[contracts.webhooks]]
  url          = "https://events.pagerduty.com/v2/enqueue"
  format       = "pagerduty"
  routing_key  = "${PAGERDUTY_ROUTING_KEY}"
  min_severity = "critical"
```

`txwatch validate` shows each destination's filters.

#### Mutual TLS

Destinations that require client certificates set `client_cert` and `client_key` (PEM file paths,
set together) and, for a private CA, `ca_cert`. The URL must be `https`. Each such destination gets
its own HTTP client; the paths support `${ENV_VAR}` interpolation.

```toml
  [[contracts.webhooks]]
  url         = "https://alerts.internal.example.com/txwatch"
  client_cert = "/etc/txwatch/client.pem"
  client_key  = "${TXWATCH_CLIENT_KEY_PATH}"
  ca_cert     = "/etc/txwatch/internal-ca.pem"
```

### Webhook formats

| Format      | Receiver | Body |
|-------------|----------|------|
| `txwatch`   | Any HTTP endpoint (default) | The [webhook payload](#webhook-payload) below. |
| `slack`     | [Slack incoming webhook](https://api.slack.com/messaging/webhooks) | `text` fallback plus Block Kit `blocks`: rule, label and network; contract, transaction link, amount, fee, functions, source account, ledger, memo, severity, suppressed count, matched events and time; explorer, Horizon and alert ID. Texts and fields are truncated to Slack's Block Kit limits (3,000 / 2,000 characters, at most 10 fields) and link URLs are escaped. Recovery alerts use a `:white_check_mark: Resolved` headline. |
| `discord`   | [Discord webhook](https://discord.com/developers/docs/resources/webhook) | `content` plus one embed (title = rule, linked to the explorer; fields for contract, transaction, amount, fee, functions, Horizon). Mentions are disabled, so a label can never ping `@everyone`. Red for `TransactionFailed` / `AdminFunctionCalled`, blue otherwise; green with a "✅ Resolved" title for recovery alerts. |
| `pagerduty` | [PagerDuty Events API v2](https://developer.pagerduty.com/docs/events-api-v2/trigger-events/) (`https://events.pagerduty.com/v2/enqueue`) | A `trigger` event with the destination's `routing_key` and `dedup_key` = the alert's `alert_id`, so redelivering the same alert updates one incident instead of opening a new one. Severity: `error` for `TransactionFailed`, `critical` for `AdminFunctionCalled`, `warning` otherwise. The full alert is attached as `payload.custom_details`. |
| `teams`     | [Microsoft Teams](https://learn.microsoft.com/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) Incoming Webhook or Workflows "When a Teams webhook request is received" | A `message` with one [Adaptive Card](https://adaptivecards.io) (v1.4): a headline coloured by severity (green when resolved), a fact set with contract, transaction, the same details as Slack and time, plus *Explorer* and *Horizon* buttons. Batched delivery sends one card listing every alert. |
| `template`  | Any HTTP endpoint | The destination's `template` (or the contents of `template_file`), rendered with [minijinja](https://docs.rs/minijinja). See [Body templates](#body-templates). |

Example Slack body:

```json
{
  "text": "TxWatch alert: LargeTransfer(&gt;=10000XLM) on Treasury (mainnet)",
  "blocks": [
    { "type": "section", "text": { "type": "mrkdwn", "text": "*LargeTransfer(&gt;=10000XLM)* on *Treasury* (mainnet)" } },
    { "type": "section", "fields": [
      { "type": "mrkdwn", "text": "*Contract*\n`CAAA...`" },
      { "type": "mrkdwn", "text": "*Transaction*\n<https://stellar.expert/explorer/public/tx/abc123|abc123>" },
      { "type": "mrkdwn", "text": "*Amount*\n15000 XLM" },
      { "type": "mrkdwn", "text": "*Time*\n2024-01-15T12:00:00Z" }
    ] },
    { "type": "context", "elements": [
      { "type": "mrkdwn", "text": "<https://stellar.expert/explorer/public/tx/abc123|Explorer> · <https://horizon.stellar.org/transactions/abc123|Horizon> · alert `3f2b9c1d8e7a6b5c4d3e2f1a0b9c8d7e`" }
    ] }
  ]
}
```

Example Discord body:

```json
{
  "username": "TxWatch",
  "content": "TxWatch alert: LargeTransfer(>=10000XLM) on Treasury (mainnet)",
  "allowed_mentions": { "parse": [] },
  "embeds": [{
    "title": "LargeTransfer(>=10000XLM)",
    "url": "https://stellar.expert/explorer/public/tx/abc123",
    "description": "Treasury (mainnet)",
    "color": 3447003,
    "timestamp": "2024-01-15T12:00:00Z",
    "fields": [
      { "name": "Contract", "value": "`CAAA...`", "inline": false },
      { "name": "Transaction", "value": "[abc123](https://stellar.expert/explorer/public/tx/abc123)", "inline": false },
      { "name": "Amount", "value": "15000 XLM", "inline": true },
      { "name": "Horizon", "value": "[transaction](https://horizon.stellar.org/transactions/abc123)", "inline": true }
    ],
    "footer": { "text": "TxWatch · alert 3f2b9c1d8e7a6b5c4d3e2f1a0b9c8d7e" }
  }]
}
```

Example PagerDuty body:

```json
{
  "routing_key": "<your integration key>",
  "event_action": "trigger",
  "dedup_key": "3f2b9c1d8e7a6b5c4d3e2f1a0b9c8d7e",
  "client": "TxWatch",
  "client_url": "https://stellar.expert/explorer/public/tx/abc123",
  "links": [
    { "href": "https://stellar.expert/explorer/public/tx/abc123", "text": "View transaction" },
    { "href": "https://horizon.stellar.org/transactions/abc123", "text": "Horizon" }
  ],
  "payload": {
    "summary": "TxWatch alert: LargeTransfer(>=10000XLM) on Treasury (mainnet) — tx abc123",
    "source": "CAAA...",
    "severity": "warning",
    "timestamp": "2024-01-15T12:00:00Z",
    "component": "Treasury",
    "group": "mainnet",
    "class": "LargeTransfer",
    "custom_details": { "alert_id": "3f2b9c1d8e7a6b5c4d3e2f1a0b9c8d7e", "...": "the full alert" }
  }
}
```

The exact bodies are pinned by snapshot tests in `crates/notifier/src/format.rs`.

### Body templates

`format = "template"` covers receivers without a built-in format (Opsgenie, Telegram, Mattermost,
internal APIs). Set exactly one of `template` (inline) or `template_file` (a path read at config
load). Templates are checked for syntax errors when the config is loaded.

Every field of the [webhook payload](#webhook-payload) is available as a variable (`label`,
`contract_id`, `network`, `rule_type`, `rule_triggered`, `severity`, `transaction_hash`,
`amount_xlm`, `explorer_link`, `horizon_link`, `timestamp_iso`, `alert_id`, ...). Values are
JSON-escaped and quoted automatically, so write `{{ label }}`, not `"{{ label }}"`. Referencing an
unknown variable fails the delivery. The engine is sandboxed: templates cannot read files or make
network requests.

```toml
  [[contracts.webhooks]]
  url      = "https://chat.example.com/hooks/abc"
  format   = "template"
  template = '{"text": {{ rule_triggered }}, "contract": {{ label }}, "link": {{ explorer_link }}}'
```

### Custom headers

Receivers that authenticate with a bearer token or an API-key header, rather than the HMAC
signature, can get extra headers on every POST:

```toml
webhook_url     = "https://api.example.com/alerts"
webhook_headers = { "Authorization" = "Bearer ${ALERTS_API_TOKEN}", "X-Api-Key" = "${ALERTS_API_KEY}" }

  [[contracts.webhooks]]
  url     = "https://other.example.com/hook"
  headers = { "Authorization" = "Bearer ${OTHER_TOKEN}" }
```

- Header values support [environment interpolation](#environment-variable-interpolation), which
  keeps tokens out of the config file and out of the URL (where they would end up in logs).
- `Content-Type`, `Content-Length` and any `X-TxWatch-*` header are reserved and rejected, as are
  names that are not valid HTTP header names and values containing control characters.
- Header values are never logged, and `txwatch validate` (text and JSON) prints them as
  `<redacted>`. Validation errors name the header, never its value.

### Network field values

Valid `network` values and their corresponding Horizon endpoints:

| Value | Horizon URL |
|---|---|
| `mainnet` | https://horizon.stellar.org |
| `testnet` | https://horizon-testnet.stellar.org |
| `futurenet` | https://horizon-futurenet.stellar.org |

Any value outside this list will cause a TOML parse error. For example:

```
Error: unknown variant `main`, expected one of `mainnet`, `testnet`, `futurenet`
```

To fix: replace your `network` value with one of the valid values listed above.

### Custom / local networks

For `stellar/quickstart --local` or a private network, give `network` an inline table instead of a name:

```toml
network = { horizon_url = "http://localhost:8000", passphrase = "Standalone Network ; February 2017" }
```

| Field          | Required | Description |
|----------------|----------|-------------|
| `horizon_url`  | yes      | `http://` or `https://` Horizon base URL. |
| `explorer_url` | no       | Explorer base URL; alert `explorer_link` becomes `<explorer_url>/tx/<hash>`. Without it, `explorer_link` is the transaction's Horizon URL. |
| `passphrase`   | no       | Network passphrase, for reference. |
| `rpc_url`      | no       | Soroban RPC URL used for `EventEmitted` rules (e.g. `http://localhost:8000/rpc` for quickstart). |

Alert payloads and logs report such contracts with `network = "custom"`. See `docker-compose.local.yml` and
`config/local.toml` for a ready-made quickstart + TxWatch setup.

## `[[contracts.rules]]`

At least one rule is required per contract. All matching enabled rules fire independently.

Every rule entry supports these optional fields:

| Field            | Type   | Default | Description |
|------------------|--------|---------|-------------|
| `enabled`        | bool   | `true`  | Set `false` to silence a rule without removing it. Shown as `(disabled)` in `txwatch validate`. |
| `webhook_url`    | string | unset   | Override the contract-level `webhook_url` for this rule only. |
| `webhook_secret` | string | unset   | Override the contract-level `webhook_secret` for this rule only. |
| `severity`       | string | unset   | One of `info`, `warning`, `critical`. Included as `severity` in the alert payload when set. |

These fields can be combined with any rule type:

```toml
[[contracts.rules]]
type        = "AdminFunctionCalled"
function_names = ["set_admin", "upgrade"]
enabled     = true
webhook_url = "https://pagerduty.example.com/alert"
severity    = "critical"
```

Every rule accepts an optional `cooldown_seconds` (0–604800). After the rule fires for a contract, further
matches within that many seconds are suppressed and counted; the next alert that is sent carries the count in
`suppressed_count`. Unset or `0` disables the cooldown. Cooldown state is persisted in the `cursor_file` (see
[Cursor file locking and state](#cursor-file-locking-and-state)) when one is configured, so it is enforced
across restarts and across separate `txwatch watch --once` runs; without a `cursor_file` it is kept in memory
and resets on restart.

```toml
[[contracts.rules]]
type             = "TransactionFailed"
cooldown_seconds = 300   # at most one alert every 5 minutes
```
Keys that a rule type does not define are rejected, and the error names the rule
(e.g. ``unknown field `threshold_xml`, expected `threshold_stroops` or `threshold_xlm` (field: contracts[0].rules[1] …)``),
so a typo is never silently ignored.

### `AnyTransaction`
Fires on every transaction that appears in the contract's Horizon history.

```toml
[[contracts.rules]]
type = "AnyTransaction"
```

### `TransactionFailed`
Fires when `successful = false`.

```toml
[[contracts.rules]]
type = "TransactionFailed"
```

### `LargeTransfer`
Fires when the amount moved by the watched contract is ≥ `threshold_xlm` XLM.

Only balance changes where the watched contract is the sender or the receiver are counted: native
payments, `create_account`, path-payment legs and SAC transfers that do not involve the watched
contract are ignored, so unrelated traffic in the same transaction can never trigger an alert.

An optional `direction` selects which side of the movement counts:

| Value | Behaviour |
|-------|-----------|
| `"any"` (default) | Inflows and outflows are summed together |
| `"in"` | Only amounts received by the watched contract are counted |
| `"out"` | Only amounts sent by the watched contract are counted |

```toml
[[contracts.rules]]
type          = "LargeTransfer"
threshold_xlm = 10000          # must be > 0

[[contracts.rules]]
type          = "LargeTransfer"
threshold_xlm = 50000
direction     = "out"          # only alert on large outflows
```

### `FunctionCalled`
Fires when the Soroban invocation calls exactly `function_name` (case-sensitive) by default.
Function names must be valid Soroban symbols: at most 32 characters from `[a-zA-Z0-9_]`
(no spaces, hyphens or surrounding whitespace). The same applies to `AdminFunctionCalled`.

An optional `match` field controls how `function_name` is compared to the invoked function:

| Value | Behaviour |
|-------|-----------|
| `"exact"` (default) | The invoked name must equal `function_name` exactly |
| `"prefix"` | The invoked name must start with `function_name` |
| `"glob"` | The invoked name must match the glob pattern in `function_name` (`*` = any sequence, `?` = one character) |

Prefix and exact patterns must be valid Soroban symbols. Glob patterns may additionally contain
`*` and `?`; all other characters must be `[a-zA-Z0-9_]` and the pattern must be ≤ 64 characters.

```toml
[[contracts.rules]]
type          = "FunctionCalled"
function_name = "withdraw"
# match = "exact"   # default; omit for backward compatibility

[[contracts.rules]]
type          = "FunctionCalled"
function_name = "admin_"
match         = "prefix"          # fires on admin_set_fee, admin_pause, etc.

[[contracts.rules]]
type          = "FunctionCalled"
function_name = "admin_*"
match         = "glob"            # same as prefix example above
```

An optional `args` array additionally matches the invocation parameters (the Horizon operation's
`parameters`). Each entry constrains one positional argument:

| Field   | Type   | Required | Description |
|---------|--------|----------|-------------|
| `index` | u32    | yes      | Zero-based position of the argument in the invocation. |
| `eq`    | string | yes      | The argument must equal this value (max 128 characters, trimmed). |

At most 16 entries are allowed and each `index` may appear only once. Arguments are decoded from
their `ScVal` encoding: `Address` (compared as the `G…`/`C…` StrKey), `Symbol` and `String`
(compared as text), integer types and `Bool` (compared as their decimal / `true`/`false` string).
Other types are compared as their compact JSON. An argument that is absent never matches. All `args` entries must match for the rule to fire;
an empty `args` array is equivalent to omitting it.

```toml
# transfer where the destination is a specific account
[[contracts.rules]]
type          = "FunctionCalled"
function_name = "transfer"
args          = [{ index = 1, eq = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN" }]
```

The decoded invocations are included in the alert payload as `function_args` (see
[Webhook payload](#webhook-payload)).

### `AdminFunctionCalled`
Fires when the invoked function is any entry in `function_names`.

```toml
[[contracts.rules]]
type           = "AdminFunctionCalled"
function_names = ["set_admin", "upgrade", "initialize"]
```

### `HighFee`
Fires when the transaction's charged fee is greater than or equal to the threshold. Set exactly one of
`threshold_stroops` (raw stroops, must be > 0) or `threshold_xlm` (whole XLM, must be > 0;
converted to stroops during validation). The two are mutually exclusive; setting both is rejected.

```toml
[[contracts.rules]]
type              = "HighFee"
threshold_stroops = 1000000
```

### `SourceAccount`
Fires based on the transaction source account (the G-address that signed and submitted the transaction).

| Field          | Type         | Required | Description |
|----------------|--------------|----------|-------------|
| `mode`         | string       | no       | `"in"` (default) fires when the source is in `accounts`; `"not_in"` fires when it is not. |
| `accounts`     | [G-address]  | no       | Accounts the transaction source is matched against. |
| `alert_unless` | [G-address]  | no       | Allowlist shorthand: sets `accounts` and `mode = "not_in"` in one field. |
| `allow`        | [G-address]  | no       | *(Deprecated)* Legacy list; equivalent to `mode = "in"` with `accounts`. |
| `deny`         | [G-address]  | no       | *(Deprecated)* Legacy list; equivalent to `mode = "not_in"` with `accounts`. |

At least one address must be provided in `accounts` (or the deprecated `allow`/`deny`). Each entry must be a valid 56-character Stellar G-address. When a transaction has no source account the rule never fires, so `mode = "not_in"` is safe for alerting on unknown callers.

```toml
# Alert when called by anyone except the known admin (allowlist use case)
[[contracts.rules]]
type     = "SourceAccount"
mode     = "not_in"
accounts = ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNA"]

# Equivalent shorthand:
[[contracts.rules]]
type         = "SourceAccount"
alert_unless = ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNA"]
```

> **Migration Note:** The legacy `allow` and `deny` fields are deprecated. Both historically fired on list *membership*, which surprised users who expected `deny` to mean "alert unless listed". Use `mode = "in"` for a membership match and `mode = "not_in"` (or `alert_unless`) for an allowlist. The legacy fields continue to work.

The `source_account` field is included in the alert payload whenever a source account is present.

### `All`
Fires when **all** nested rules match (logical AND). Nesting is supported up to depth 5.

```toml
[[contracts.rules]]
type = "All"
[[contracts.rules.rules]]
type          = "FunctionCalled"
function_name = "withdraw"
[[contracts.rules.rules]]
type          = "LargeTransfer"
threshold_xlm = 10000
```

The `rule_triggered` payload field shows a readable label:
`All(FunctionCalled(withdraw), LargeTransfer(>=10000XLM))`.

### `Any`
Fires when **any** nested rule matches (logical OR).

```toml
[[contracts.rules]]
type = "Any"
[[contracts.rules.rules]]
type = "TransactionFailed"
[[contracts.rules.rules]]
type          = "HighFee"
threshold_xlm = 1
```

### `Not`
Fires when the nested rule does **not** match (logical NOT).

```toml
[[contracts.rules]]
type = "Not"
[contracts.rules.rule]
type = "TransactionFailed"
### `Rate`
Fires when the wrapped `rule` matches at least `count` times within a sliding `window_seconds` window
for the contract. Unlike `cooldown_seconds`, which only suppresses alerts, `Rate` counts matches and
emits one alert per breach, carrying the observed count.

| Field            | Type            | Required | Description |
|------------------|-----------------|----------|-------------|
| `rule`           | rule table      | yes      | The nested rule whose matches are counted. |
| `count`          | u64             | yes      | Number of matches that constitutes a breach. 1–1,000,000. |
| `window_seconds` | u64             | yes      | Length of the sliding window in seconds. 1–604,800 (one week). |

The window slides per contract: matches older than `window_seconds` are discarded before each
evaluation, and a breach clears the window. The alert's `rule_type` is `"Rate"`, its
`rule_triggered` is the rate label (e.g. `Rate(10x TransactionFailed in 300s)`), and the observed
count is reported in the payload as `observed_count`. Rate state is kept in memory by `txwatch watch` (it resets
on restart), so it has no effect across separate `txwatch watch --once` runs.

```toml
# at least 50 withdraw calls per hour
[[contracts.rules]]
type           = "Rate"
count          = 50
window_seconds = 3600
[contracts.rules.rule]
type          = "FunctionCalled"
function_name = "withdraw"

# at least 10 failed transactions in 5 minutes
[[contracts.rules]]
type           = "Rate"
count          = 10
window_seconds = 300
[contracts.rules.rule]
type = "TransactionFailed"
```

### `Memo`
Fires when the transaction memo matches. Exchanges and bridges commonly alert on specific memo IDs
or text prefixes.

| Field       | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `memo_type` | string | no       | Restrict to a memo type: `none`, `text`, `id`, `hash` or `return`. When omitted, any memo type is considered. |
| `equals`    | string | one of   | The memo must equal this value. |
| `prefix`    | string | one of   | The memo's text form must start with this value. |

Exactly one of `equals` or `prefix` must be set. Memos are compared in their textual form: `text`
memos as written, `id` memos as their decimal string, and `hash`/`return` memos as their hex
encoding. A transaction without a memo (`memo_type = "none"`) never matches.

```toml
[[contracts.rules]]
type      = "Memo"
memo_type = "id"
equals    = "1234567890"

[[contracts.rules]]
type   = "Memo"
prefix = "DEPOSIT-"
```

### `EventEmitted`
Fires when the transaction emitted a Soroban contract event matching `topic` and, optionally, `topics` and
`data`. Events are fetched from Soroban RPC `getEvents` (see `soroban_rpc_url`); events older than the RPC's
retention window (about 7 days on public endpoints) cannot be fetched, so this rule will not match them.

`topic` matches topic 0 and accepts any scalar `ScVal`, not only symbols:

| Pattern | Matches |
|---------|---------|
| `transfer` | The symbol `transfer` (a bare word is a symbol, as before) |
| `symbol:transfer` | The symbol `transfer`, explicitly typed |
| `string:Transfer` | The string `Transfer` |
| `address:GAAZI4…` | The address `GAAZI4…` (G- or C-address) |
| `u32:5`, `i128:-1` | An integer of the given type and value |
| `bytes:deadbeef` | The bytes `de ad be ef` (hex) |

`topics` optionally constrains the following topics positionally, using the same patterns; `"*"` matches any
value. A bare word is a symbol, so a string topic must be written `string:…`.

`data` optionally constrains the event's decoded data. Each entry is a table with a JSON pointer into the data
and a comparison:

| Field | Required | Description |
|-------|----------|-------------|
| `pointer` | yes | [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON pointer into the decoded data, e.g. `""` for the whole value, `/0` for the first element, `/amount` for a field. |
| `eq`  | one of | Value must equal the given value. |
| `gte` | one of | Value must be ≥ the given value. |
| `lte` | one of | Value must be ≤ the given value. |

Exactly one of `eq`, `gte` or `lte` must be set per entry. Values are TOML strings, integers or booleans;
`i128`/`u128` numbers are compared as integers, so `gte = "1000000000"` works for a token amount. Pointers and
comparison types are validated at load time: a malformed pointer, an unknown field, or a comparison that cannot
apply to the value's type is a startup error.

```toml
[[contracts.rules]]
type   = "EventEmitted"
topic  = "transfer"
topics = ["*", "GDESTINATION..."]   # optional: topic 1 = any, topic 2 = this address

  # SEP-41 transfer: data is {"from": …, "to": …, "amount": …}
  [[contracts.rules.data]]
  pointer = "/amount"
  gte     = "1000000000"            # at least 100 tokens (7 decimals)

  [[contracts.rules.data]]
  pointer = "/to"
  eq      = "GDESTINATION..."

[[contracts.rules]]
type  = "EventEmitted"
topic = "admin_changed"

  # data is the new admin address itself
  [[contracts.rules.data]]
  pointer = ""
  eq      = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"

[[contracts.rules]]
type   = "EventEmitted"
topic  = "string:Transfer"
topics = ["address:GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"]
```

### `ContractUpgraded`
Fires when the watched contract's executable changes, i.e. its WASM hash is replaced. This catches upgrades
performed through any function that calls `update_current_contract_wasm`, not only functions named `upgrade`.
The alert payload includes `old_wasm_hash` and `new_wasm_hash` (hex-encoded SHA-256 of the WASM).

```toml
[[contracts.rules]]
type     = "ContractUpgraded"
severity = "critical"
```

## Webhook payload

```json
{
  "schema_version":      1,
  "alert_id":            "a3f1bc20e94d77c1a3f1bc20e94d77c1",
  "alert_id":            "3f2b9c1d8e7a6b5c4d3e2f1a0b9c8d7e",
  "label":               "My Escrow Contract",
  "contract_id":         "CAAA...",
  "network":             "testnet",
  "rule_type":           "LargeTransfer",
  "rule_triggered":      "LargeTransfer(>=10000XLM)",
  "transaction_hash":    "abc123...",
  "function_name":       "transfer",
  "function_names":      ["transfer"],
  "amount_xlm":          15000,
  "amount_stroops":      150000000000000,
  "amount_xlm_decimal":  "15000.0000000",
  "fee_charged_stroops": 50000,
  "source_account":      "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
  "severity":            "critical",
  "timestamp":           1705316096,
  "timestamp_iso":       "2024-01-15T12:00:00Z",
  "horizon_link":        "https://horizon-testnet.stellar.org/transactions/abc123...",
  "explorer_link":       "https://stellar.expert/explorer/testnet/tx/abc123...",
  "resolved":            false,
  "matched_events":      [],
  "old_wasm_hash":       null,
  "new_wasm_hash":       null,
  "suppressed_count":    0
}
```

This example and the one in the README are checked against `AlertPayload` by
`crates/rules/tests/docs_payload.rs`, so they cannot drift from the code.

**Schema compatibility policy:** `schema_version` is `1`. Additive changes (new optional
fields added) keep the same version. Breaking changes (field removals, renames, or type
changes) bump the version. Receivers should check `schema_version` to detect incompatible
changes before parsing other fields.

- `schema_version` — integer version of this payload shape. Use this to detect breaking changes.
- `alert_id` — stable, deterministic identifier (32 hex chars) derived from
  `(network cursor ID, contract_id, tx_hash, rule_type, rule_triggered, rule_index)` via SHA-256,
  where `rule_index` is the rule's position in its contract's `rules` list. Identical for every
  retry of the same alert, but distinct for every rule — two rules with identical labels on one
  contract never share an ID (#252). Receivers should deduplicate on this value; PagerDuty uses it
  as the `dedup_key`. Also sent as the `X-TxWatch-Alert-Id` request header for deduplication
  without parsing the body.
- `rule_type` — stable machine-readable rule variant (e.g. `"LargeTransfer"`); use it for routing.
- `rule_triggered` — human-readable rule description including parameters.
- `amount_xlm` — whole-XLM transfer amount (truncated integer), or `null` when the transaction has none. Kept for backward compatibility — use `amount_xlm_decimal` for precise accounting.
- `amount_stroops` — raw transfer amount in stroops (1 XLM = 10,000,000 stroops), or `null` when the transaction has none.
- `amount_xlm_decimal` — transfer amount as a decimal string with 7 fractional digits (e.g. `"9999.9900000"`), or `null` when the transaction has none. Use this instead of `amount_xlm` when precision matters.
- `fee_charged_stroops` — fee charged for the transaction in stroops, or `null` if unknown.
- `source_account` — transaction source account (G-address); omitted from the payload when not present on the Horizon record.
- `severity` — the severity level from the rule definition (`info`, `warning`, `critical`); omitted when the rule has no `severity` set.
- `timestamp` / `timestamp_iso` — ledger close time as Unix seconds and as an ISO 8601 string.
- `function_name` — the first invoked Soroban function name (present for backward compatibility).
- `function_names` — all Soroban function names invoked in the transaction (one per `invoke_host_function` operation). Most transactions have zero or one entry.
- `function_args` — decoded invocations, as an array of `{ "function_name": "transfer", "args": [{ "index": 0, "value": "G…" }] }` entries (values rendered as text for the decoded `ScVal` types); omitted when the transaction has no decoded invocation parameters.
- `observed_count` — for `Rate` alerts, the number of matches observed in the sliding window that triggered the alert; omitted for other rules.
- `matched_events` — for `EventEmitted` alerts, the events that matched, each with `contract_id`, `topics` and `data` (decoded `ScVal` JSON, e.g. `{"symbol": "transfer"}`); empty for other rules.
- `old_wasm_hash` / `new_wasm_hash` — for `ContractUpgraded` alerts, the contract's WASM hash before and after the upgrade (hex); `null` for other rules.
- `suppressed_count` — matches of this rule suppressed by its `cooldown_seconds` since the previous alert was sent; `0` otherwise.
- `test` — present and `true` only on payloads sent by `txwatch test-webhook`, which also use
  `rule_type = "TestWebhook"`, the label exactly as given, and the synthetic but valid contract ID
  `CATXWATCHTESTCONTRACTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5UI`. Real alerts omit the field. The
  webhook URL is never included in a payload, since URLs often embed tokens.

### Batched payload

With `batch_alerts = true`, the alerts a contract fires during one poll cycle are
delivered together instead of one POST per alert. The body wraps the usual payloads
in an `alerts` array:

```json
{
  "alerts": [
    { "label": "My Escrow Contract", "rule_type": "LargeTransfer", "transaction_hash": "abc123...", "...": "..." },
    { "label": "My Escrow Contract", "rule_type": "FunctionCalled", "transaction_hash": "def456...", "...": "..." }
  ]
}
```

- Each element has exactly the single-alert shape above.
- A batch holds at most 50 alerts; a larger burst is split into several POSTs
  (e.g. 120 alerts → 50, 50, 20). Cycles without alerts send nothing.
- Retries, `X-TxWatch-Version`, and the `X-TxWatch-Secret` / `X-TxWatch-Signature`
  headers work as for single alerts; the signature covers the whole batch body.
- A batch that still fails after all retries counts as one failed webhook delivery.

## Environment variables

| Variable   | Default | Description                                      |
|------------|---------|--------------------------------------------------|
| `RUST_LOG` | `info`  | Log level: `error`, `warn`, `info`, `debug`, `trace` |

## `watch --once` concurrency

`txwatch watch --once` polls contracts concurrently, bounded by the top-level `concurrency` setting (default
`10`). This keeps a cron run within its schedule even with many contracts and slow Horizon responses. Lower it
when Horizon rate limits are a concern; raise it when polling your own Horizon. `txwatch watch` is unaffected:
it already polls every contract in its own task.

### Environment variable interpolation

Webhook secrets (`webhook_secret`, `webhooks[].secret`), header values (`webhook_headers`,
`webhooks[].headers`) and PagerDuty routing keys (`webhook_routing_key`, `webhooks[].routing_key`)
may reference environment variables anywhere in the value:

| Syntax            | Result |
|-------------------|--------|
| `${VAR}`          | Value of `VAR`. An unset variable is a startup error that names the field (never its value). |
| `${VAR:-default}` | Value of `VAR`, or `default` when `VAR` is unset or empty. |
| `$${`             | A literal `${`. |

For example `webhook_headers = { "Authorization" = "Bearer ${TOKEN}" }`. Variable names use letters,
digits and `_` and must not start with a digit.
These fields may reference environment variables anywhere in the value, so secrets
such as webhook tokens stay out of the config file:

- `webhook_url`, `webhook_secret`
- `webhooks[].url`, `webhooks[].secret`
- rule-level `webhook_url`, `webhook_secret` (inside `All`, `Any`, `Not` nested entries)
- `soroban_rpc_url`
- custom network `horizon_url`, `explorer_url`, `passphrase`, `rpc_url`
- `cursor_file`

| Syntax              | Result |
|---------------------|--------|
| `${VAR}`            | Value of `VAR`. An unset variable is a startup error naming the field. |
| `${VAR:-default}`   | Value of `VAR`, or `default` when `VAR` is unset or empty. |
| `$${`               | A literal `${` (escape). |

```toml
webhook_url    = "https://hooks.slack.com/services/${SLACK_WEBHOOK_PATH}"
webhook_secret = "Bearer ${TXWATCH_SECRET}"
network        = { horizon_url = "${HORIZON_URL:-http://localhost:8000}" }
```

Variable names use letters, digits and `_` and must not start with a digit; `${}` and an
unterminated `${` are errors.

## Pre-flight checks

`txwatch validate --check-webhooks` checks all endpoints concurrently. It tries `HEAD` first; when a receiver returns `405 Method Not Allowed` or `501 Not Implemented`, TxWatch retries with `OPTIONS`. A per-URL table reports `reachable`, `reachable (OPTIONS)`, `method not allowed`, or `unreachable`, and any unreachable endpoint makes validation exit non-zero. Some serverless receivers reject both probe methods; use a real test webhook for those endpoints.

`txwatch validate --check-horizon` checks Horizon reachability, prints the latest ledger reported by each network, and verifies every configured contract exists on that network. A missing contract is reported as `not found on <network>` and exits non-zero.

Note: setting `RUST_LOG=debug` will show per-contract idle poll cycles — the
poller emits `"no new transactions"` debug logs with the contract `label` and
current `cursor` when a poll returns an empty page.

## Full example

```toml
poll_interval_seconds = 10

[[contracts]]
label       = "My Escrow Contract"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
network     = "testnet"
webhook_url = "https://hooks.example.com/my-webhook"

  [[contracts.rules]]
  type          = "LargeTransfer"
  threshold_xlm = 10000

  [[contracts.rules]]
  type           = "AdminFunctionCalled"
  function_names = ["set_admin", "upgrade", "initialize"]

  [[contracts.rules]]
  type = "TransactionFailed"

  [[contracts.rules]]
  type     = "ContractUpgraded"
  severity = "critical"
```
