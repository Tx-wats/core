# Alert Rules Reference

Rules are evaluated per-transaction for each watched contract.
Multiple rules can match the same transaction — each fires an independent webhook call.
A rule evaluation error is logged as a warning and skipped; it never stops the engine.

## Common rule options

Every `[[contracts.rules]]` entry supports these optional fields regardless of rule type:

| Field          | Type    | Default | Description |
|----------------|---------|---------|-------------|
| `enabled`      | bool    | `true`  | Set `false` to silence a rule without removing it. Disabled rules are skipped in evaluation and shown as `(disabled)` in `txwatch validate`. |
| `webhook_url`  | string  | unset   | Override the contract-level `webhook_url` for this rule only. Same URL validation as the contract level. |
| `webhook_secret` | string | unset  | Override the contract-level `webhook_secret` for this rule only. |
| `severity`     | string  | unset   | One of `info`, `warning`, `critical`. Included as `severity` in the alert payload; not included when unset. |

Example — silence a noisy rule temporarily and route a critical one to PagerDuty:

```toml
[[contracts.rules]]
type    = "AnyTransaction"
enabled = false              # quiet for now; config history is preserved

[[contracts.rules]]
type         = "AdminFunctionCalled"
function_names = ["set_admin", "upgrade"]
webhook_url  = "https://pagerduty.example.com/alert"
severity     = "critical"
```

## Rule types

### `AnyTransaction`
Matches every transaction that appears in the contract's Horizon history.

**Use case:** full audit trail, low-volume contracts.

```toml
[[contracts.rules]]
type = "AnyTransaction"
```

### `TransactionFailed`
Matches transactions where `successful = false`.

**Use case:** detect reverted Soroban invocations or fee-bump failures.

The poller requests transactions with `include_failed=true`, so failed
transactions are fetched. Horizon omits them by default, which would leave this
rule unable to match anything.

```toml
[[contracts.rules]]
type = "TransactionFailed"
```

### `LargeTransfer`

| Field           | Type | Required | Description                        |
|-----------------|------|----------|------------------------------------|
| `threshold_xlm` | u64  | yes      | Minimum transfer amount in XLM (> 0) |

Matches when the payment amount (extracted from Horizon operations) is ≥ `threshold_xlm` XLM.
The `amount_xlm` field in the webhook payload contains the actual transferred amount.

**Note:** The amount is the total native XLM moved by the transaction, summed across:

- `payment` operations;
- `create_account` operations (`starting_balance`);
- `path_payment_strict_send` / `path_payment_strict_receive` operations, for the native leg
  (`amount` when the destination asset is XLM, otherwise `source_amount` when the source asset
  is XLM);
- native `transfer` entries in `asset_balance_changes` on `invoke_host_function` operations
  (Stellar Asset Contract transfers of XLM).

Transfers of non-native assets are not counted, and a transaction that moves no native XLM does
not populate `amount_xlm`.

**Native-only:** Only payments whose `asset_type` is `native` (XLM) are counted. Payments in
issued assets (`credit_alphanum4` / `credit_alphanum12`, e.g. USDC) are ignored, so a large
non-native payment never fires `LargeTransfer` and never sets `amount_xlm`.

**Precision:** Amounts are parsed as fixed-point stroops (up to 7 fractional digits), not as
floating point. A native payment with a malformed amount is logged as an error and its
operation details are not used for rule evaluation.

```toml
[[contracts.rules]]
type          = "LargeTransfer"
threshold_xlm = 10000
```

### `FunctionCalled`

| Field           | Type   | Required | Default   | Description                              |
|-----------------|--------|----------|-----------|------------------------------------------|
| `function_name` | string | yes      | —         | Pattern to match against the invoked function name |
| `match`         | string | no       | `"exact"` | Matching mode: `"exact"`, `"prefix"`, or `"glob"` |

Matches when the Soroban `invoke_host_function` operation calls a function that satisfies the
match condition. `"exact"` (the default) requires an identical name; `"prefix"` requires the
invoked name to start with `function_name`; `"glob"` matches using `*` (any sequence) and `?`
(exactly one character).

```toml
# Exact match (default — backward compatible)
[[contracts.rules]]
type          = "FunctionCalled"
function_name = "withdraw"

# Prefix match: fires on admin_set_fee, admin_pause, admin_upgrade, …
[[contracts.rules]]
type          = "FunctionCalled"
function_name = "admin_"
match         = "prefix"

# Glob match: fires on set_fee, set_admin, set_pause, …
[[contracts.rules]]
type          = "FunctionCalled"
function_name = "set_*"
match         = "glob"
```

### `AdminFunctionCalled`

| Field            | Type     | Required | Description                              |
|------------------|----------|----------|------------------------------------------|
| `function_names` | [string] | yes      | Non-empty list of function names to watch |

Matches when the invoked function is any entry in `function_names`.
Equivalent to multiple `FunctionCalled` rules but produces a single
`AdminFunctionCalled([...])` label in the alert.

```toml
[[contracts.rules]]
type           = "AdminFunctionCalled"
function_names = ["set_admin", "upgrade", "initialize"]
```

### `HighFee`

| Field                | Type | Required        | Description                                   |
|----------------------|------|-----------------|-----------------------------------------------|
| `threshold_stroops`  | u64  | one of the two  | Fee threshold in stroops (> 0)                |
| `threshold_xlm`      | u64  | one of the two  | Fee threshold in whole XLM (> 0)              |

Matches when the transaction's total fee is greater than or equal to the threshold.
The `fee_charged_stroops` field in the webhook payload contains the actual fee paid in stroops.

Set exactly one of `threshold_stroops` or `threshold_xlm`; they are mutually exclusive and
setting both is a validation error. `threshold_xlm` is converted to stroops during validation.

**Note:** Stroops are the smallest unit of XLM (1 XLM = 10,000,000 stroops).

```toml
[[contracts.rules]]
type               = "HighFee"
threshold_stroops  = 100000

# or, equivalently for a 1 XLM threshold:
[[contracts.rules]]
type          = "HighFee"
threshold_xlm = 1
```

### `SourceAccount`

| Field   | Type       | Required | Description |
|---------|------------|----------|-------------|
| `allow` | [G-address] | no      | If set, only fire when the transaction source account is one of these addresses. |
| `deny`  | [G-address] | no      | If set, fire when the transaction source account is one of these addresses. |

At least one of `allow` or `deny` must be non-empty. Each address must be a valid 56-character Stellar G-address.

Matches when the transaction `source_account` satisfies both:
- It is in `allow` (if `allow` is non-empty), **and**
- It is not in `deny` (if `deny` is non-empty).

**Use case:** alert when an admin function is called by an unexpected account, or watch a specific counterparty.

```toml
# Fire only when called by the known multisig
[[contracts.rules]]
type  = "SourceAccount"
allow = ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"]

# Fire when called by any account except the approved bot
[[contracts.rules]]
type = "SourceAccount"
deny = ["GBUKOFF2GVFNQRJFGHVGON2JKGB4VBUF2QQJFNJ6HQVTJRZTCGQX7ZR"]
```

The `source_account` field is included in the alert payload when this rule fires (and whenever `source_account` is present in the Horizon response).

### `All`

| Field   | Type              | Required | Description |
|---------|-------------------|----------|-------------|
| `rules` | [rule entry array] | yes      | Non-empty list of nested rule entries. All must match. |

Fires when **all** nested rules match the same transaction. Equivalent to a logical AND.
Each nested entry supports the same options as a top-level rule entry (`enabled`, `webhook_url`, `severity`, …).
Nesting is allowed up to depth 5.

The `rule_triggered` label in the payload uses the readable form, e.g.  
`All(FunctionCalled(withdraw), LargeTransfer(>=10000XLM))`.

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

### `Any`

| Field   | Type              | Required | Description |
|---------|-------------------|----------|-------------|
| `rules` | [rule entry array] | yes      | Non-empty list of nested rule entries. At least one must match. |

Fires when **any** nested rule matches. Equivalent to a logical OR.

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

| Field  | Type       | Required | Description |
|--------|------------|----------|-------------|
| `rule` | rule entry | yes      | A single nested rule entry. Fires when it does NOT match. |

Fires when the nested rule does **not** match. Equivalent to a logical NOT.

```toml
[[contracts.rules]]
type = "Not"
[contracts.rules.rule]
type = "TransactionFailed"
```

### `EventEmitted`

| Field    | Type     | Required | Description                                                         |
|----------|----------|----------|---------------------------------------------------------------------|
| `topic`  | string   | yes      | Symbol that event topic 0 must equal exactly (valid Soroban symbol) |
| `topics` | [string] | no       | Patterns for topics 1, 2, … in order; `"*"` matches any value       |

Matches when the transaction emitted a contract event whose first topic is the symbol `topic`
and whose following topics match `topics` positionally. A topic value matches a pattern when:

- it is a single-key scalar `ScVal` (`{"symbol": "x"}`, `{"address": "G…"}`, `{"u32": 5}`,
  `{"i128": "-1"}`, …) and the inner value's text equals the pattern, or
- otherwise, its compact JSON equals the pattern.

The matching events (topics and data, as decoded `ScVal` JSON) are included in the
`matched_events` payload field.

**Use case:** react to what a contract reports it did — `transfer`, `mint`, `admin_changed`, …

**Note:** Events come from Soroban RPC `getEvents` (Horizon does not expose them), so the
contract needs a Soroban RPC endpoint: `soroban_rpc_url` on the contract, the custom network's
`rpc_url`, or the testnet/futurenet default. Mainnet has no default endpoint. Events older than
the RPC retention window (about 7 days on public endpoints) cannot be fetched and will not match.
Events are only fetched for contracts that have at least one `EventEmitted` rule.

```toml
[[contracts.rules]]
type   = "EventEmitted"
topic  = "transfer"

[[contracts.rules]]
type   = "EventEmitted"
topic  = "transfer"
topics = ["*", "GDESTINATION..."]   # any sender, to this address
```

## Cooldowns

Every rule accepts an optional `cooldown_seconds` (0–604800):

```toml
[[contracts.rules]]
type             = "TransactionFailed"
cooldown_seconds = 300
```

After the rule fires for a contract, further matches of the same (contract, rule) within
`cooldown_seconds` are suppressed and counted. The next alert that is sent for that rule carries
the number of suppressed matches in `suppressed_count`. Unset or `0` disables the cooldown.

Cooldown state is kept in memory for the life of `txwatch watch`; it resets on restart and does
not carry over between `txwatch watch --once` runs.

## Evaluation order

Rules are evaluated in the order they appear in the config file.
Disabled rules (``enabled = false``) are skipped entirely.
All matching enabled rules fire; there is no short-circuit.

## Webhook payload fields

| Field                | Type        | Always present | Description                              |
|----------------------|-------------|----------------|------------------------------------------|
| `schema_version`     | u32         | yes            | Payload shape version (currently `1`); bump on breaking changes |
| `alert_id`           | string      | yes            | Deterministic 32-hex-char ID for deduplication (see below) |
| `label`              | string      | yes            | Contract label from config               |
| `contract_id`        | string      | yes            | Stellar C-address                        |
| `network`            | string      | yes            | `mainnet` / `testnet` / `futurenet`      |
| `rule_type`          | string      | yes            | Stable machine-readable rule variant     |
| `rule_triggered`     | string      | yes            | Human-readable rule description          |
| `transaction_hash`   | string      | yes            | Stellar transaction hash                 |
| `function_name`      | string/null | no             | First Soroban function name; `null` for non-Soroban transactions |
| `function_names`     | [string]    | yes            | All Soroban function names in the transaction |
| `amount_xlm`         | u64/null    | no             | Transfer amount in XLM if available      |
| `fee_charged_stroops`| u64/null    | no             | Transaction fee in stroops               |
| `timestamp`          | i64         | yes            | Unix timestamp (seconds) of transaction  |
| `timestamp_iso`      | string      | yes            | ISO 8601 timestamp string                |
| `horizon_link`       | string      | yes            | Direct link to transaction on Horizon    |
| `explorer_link`      | string      | yes            | Stellar Expert explorer link             |
| `ledger`             | u32/null    | no             | Ledger sequence number (when available)  |
| `source_account`     | string/null | no             | Source account G-address (when available)|
| `memo`               | string/null | no             | Memo content (absent for `MemoNone`)     |
| `memo_type`          | string/null | no             | Memo type: `"none"`, `"text"`, `"id"`, `"hash"`, `"return"` |
| `operation_count`    | u32/null    | no             | Total operations in the transaction      |
| Field              | Type        | Always present | Description                              |
|--------------------|-------------|----------------|------------------------------------------|
| `label`            | string      | yes            | Contract label from config               |
| `contract_id`      | string      | yes            | Stellar C-address                        |
| `network`          | string      | yes            | `mainnet` / `testnet` / `futurenet`      |
| `rule_triggered`   | string      | yes            | Human-readable rule description          |
| `transaction_hash` | string      | yes            | Stellar transaction hash                 |
| `function_name`    | string/null | no             | Soroban function name if available; `null` indicates a non-Soroban transaction |
| `function_names`   | [string]    | yes            | All invoked function names (may be empty) |
| `amount_xlm`       | u64/null    | no             | Transfer amount in XLM if available      |
| `fee_charged_stroops` | u64/null | no            | Fee charged in stroops                   |
| `source_account`   | string/null | no             | Transaction source account (G-address); omitted when not present |
| `severity`         | string/null | no             | `info`, `warning`, or `critical`; omitted when unset on the rule |
| `amount_xlm`       | u64/null    | no             | Transfer amount in whole XLM (truncated). Kept for backward compatibility — use `amount_xlm_decimal` for precise accounting |
| `amount_stroops`   | u64/null    | no             | Raw transfer amount in stroops (1 XLM = 10,000,000 stroops), or `null` |
| `amount_xlm_decimal` | string/null | no           | Transfer amount as a decimal string with 7 fractional digits (e.g. `"9999.9900000"`), or `null` |
| `timestamp`        | i64         | yes            | Unix timestamp (seconds) of transaction  |
| `timestamp_iso`    | string      | yes            | ISO 8601 timestamp of the transaction    |
| `horizon_link`     | string      | yes            | Direct link to transaction on Horizon    |
| `explorer_link`    | string      | yes            | Stellar Expert explorer link for the transaction |
| `fee_charged_stroops` | u64/null | no             | Fee charged for the transaction in stroops |
| `matched_events`   | array       | yes            | Events that matched an `EventEmitted` rule (`contract_id`, `topics`, `data`); empty for other rules |
| `suppressed_count` | u64         | yes            | Matches suppressed by this rule's `cooldown_seconds` since the previous alert; `0` otherwise |

> `horizon_link` and `explorer_link` are always present in every alert payload, even when `function_name` is `null` for a non-Soroban transaction.

### `alert_id` and deduplication

`alert_id` is derived deterministically from `(network, contract_id, tx_hash, rule_type, rule_triggered)`
via SHA-256 (first 16 bytes → 32 hex chars). The same alert always produces the same `alert_id`,
so receivers can safely deduplicate retries and cursor replays by storing and checking this value.
It is also sent as the `X-TxWatch-Alert-Id` request header, enabling deduplication without parsing
the JSON body.

### Schema compatibility policy

`schema_version` is currently `1`. The versioning policy:
- **Additive changes** (new optional fields added to the payload) keep the same version.
- **Breaking changes** (field removals, renames, or type changes) bump the version.

Receivers should read `schema_version` before processing other fields to detect incompatible
format changes in stored or queued payloads.

## Stable rule_type values

The webhook payload includes two rule-related fields:

| Field | Purpose | Example |
|-------|---------|---------|
| `rule_type` | Machine-readable, stable rule variant name; use for programmatic routing | `"LargeTransfer"` |
| `rule_triggered` | Human-readable description with parameters; use for display | `"LargeTransfer(>=10000XLM)"` |

### Rule type table

| Rule | `rule_type` value |
|------|-------------------|
| `AnyTransaction` | `"AnyTransaction"` |
| `TransactionFailed` | `"TransactionFailed"` |
| `LargeTransfer` | `"LargeTransfer"` |
| `FunctionCalled` | `"FunctionCalled"` |
| `AdminFunctionCalled` | `"AdminFunctionCalled"` |
| `HighFee` | `"HighFee"` |
| `SourceAccount` | `"SourceAccount"` |
| `All` | `"All"` |
| `Any` | `"Any"` |
| `Not` | `"Not"` |
| `EventEmitted` | `"EventEmitted"` |

## Adding a new rule type

1. Add a variant to `AlertRule` in `crates/config/src/lib.rs`
2. Add field validation in `AlertRule::validate_at_depth()` in the same file
3. Add the match arm in `eval_rule()` in `crates/rules/src/lib.rs`
4. Add the label string in `rule_label()` in the same file
5. Add a stable `rule_type` string in `rule_type()` in the same file
2. Add field validation in `AlertRule::validate()` in the same file
3. Add the match arm in `AlertRule::label()` in the same file
4. Add the match arm in `AlertRule::rule_type()` in the same file
5. Add the match arm in `eval_rule()` in `crates/rules/src/lib.rs`
6. Add unit tests in `crates/rules/src/lib.rs`
7. Update the rule type table in this section
8. Update the webhook payload example in README.md (if adding a new example)

**Note:** `rule_triggered` and `rule_type` in webhook payloads are now produced by `AlertRule::label()` and `AlertRule::rule_type()` from `txwatch-config`. There are no duplicate implementations in `txwatch-rules`. A single change to `AlertRule::label()` is reflected consistently in both CLI `validate` output and webhook payloads.
