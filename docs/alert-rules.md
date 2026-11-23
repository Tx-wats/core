# Alert Rules Reference

Rules are evaluated per-transaction for each watched contract.
Multiple rules can match the same transaction — each fires an independent webhook call.
A rule evaluation error is logged as a warning and skipped; it never stops the engine.

## Common rule options

Every `[[contracts.rules]]` entry supports these optional fields regardless of rule type:

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Set `false` to silence a rule without removing it. Disabled rules are skipped in evaluation and shown as `(disabled)` in `txwatch validate`. |
| `webhook_url` | string | unset | Override the contract-level `webhook_url` for this rule only. Same URL validation as the contract level. |
| `webhook_secret` | string | unset | Override the contract-level `webhook_secret` for this rule only. |
| `severity` | string | unset | One of `info`, `warning`, `critical`. Included as `severity` in the alert payload; not included when unset. |
| `cooldown_seconds` | u64 | unset | Minimum time in seconds between alerts from this rule. `0` or unset disables the cooldown. See [Cooldowns](#cooldowns). |
| `cooldown_summary` | bool | `false` | When `true`, the next alert fired after a cooldown window expires carries a `suppressed_count` of the matches that were suppressed during the window. **Requires `cooldown_seconds > 0`**; validation fails otherwise. See [Cooldowns](#cooldowns). |

Example — silence a noisy rule temporarily and route a critical one to PagerDuty:

```toml
[[contracts.rules]]
type    = "AnyTransaction"
enabled = false              # quiet for now; config history is preserved

[[contracts.rules]]
type           = "AdminFunctionCalled"
function_names = ["set_admin", "upgrade"]
webhook_url    = "https://pagerduty.example.com/alert"
severity       = "critical"
```

## Rule types

### AnyTransaction

Matches every transaction that appears in the contract's Horizon history.

Use case: full audit trail, low-volume contracts.

```toml
[[contracts.rules]]
type = "AnyTransaction"
```

### TransactionFailed

Matches transactions where `successful = false`.

Use case: detect reverted Soroban invocations or fee-bump failures.

The poller requests transactions with `include_failed=true`, so failed
transactions are fetched. Horizon omits them by default, which would leave this
rule unable to match anything.

```toml
[[contracts.rules]]
type = "TransactionFailed"
```

### LargeTransfer

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `threshold_xlm` | u64 | yes | — | Minimum transfer amount in XLM (> 0) |
| `direction` | string | no | `"any"` | `"in"`, `"out"`, or `"any"` (see below) |

Matches when the native XLM amount moved to or from the watched contract is ≥
`threshold_xlm` XLM. The `amount_xlm` field in the webhook payload contains the actual
transferred amount.

**Scoped to the watched contract:** Only balance changes where the watched contract is the
`from` or `to` party are counted. Native XLM moved by unrelated operations in the same
transaction (payments between other accounts, `create_account`, path-payment legs, or SAC
transfers that do not involve the watched contract) is ignored, so a busy transaction cannot
trigger a "large transfer" on a contract that moved nothing.

The counted native XLM balance changes come from:

- `payment` operations where `from` or `to` is the watched contract;
- `create_account` operations where the watched contract is the funder or the new account;
- `path_payment_strict_send` / `path_payment_strict_receive` operations, for the native leg
  (`amount` when the destination asset is XLM, otherwise `source_amount` when the source asset
  is XLM), when the watched contract is the source or destination;
- native `transfer` entries in `asset_balance_changes` on `invoke_host_function` operations
  (Stellar Asset Contract transfers of XLM) where the watched contract is `from` or `to`.

**Direction:** `direction` selects which side of the flow is counted:

- `"in"` — only inflows (the watched contract is the `to` party);
- `"out"` — only outflows (the watched contract is the `from` party);
- `"any"` (default) — inflows and outflows are summed together.

Transfers of non-native assets are not counted, and a transaction that moves no native XLM
involving the watched contract does not populate `amount_xlm`.

**Native-only:** Only payments whose `asset_type` is `native` (XLM) are counted. Payments in
issued assets (`credit_alphanum4` / `credit_alphanum12`, e.g. USDC) are ignored, so a large
non-native payment never fires `LargeTransfer` and never sets `amount_xlm`.

**Precision:** Amounts are parsed as fixed-point stroops (up to 7 fractional digits), not as
floating point. A native payment with a malformed amount is logged as an error and its
operation details are not used for rule evaluation.

```toml
# Any large flow involving the contract (in or out)
[[contracts.rules]]
type          = "LargeTransfer"
threshold_xlm = 10000

# Only large inflows into the contract
[[contracts.rules]]
type          = "LargeTransfer"
threshold_xlm = 10000
direction     = "in"

# Only large outflows from the contract
[[contracts.rules]]
type          = "LargeTransfer"
threshold_xlm = 5000
direction     = "out"
```

### FunctionCalled

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `function_name` | string | yes | — | Pattern to match against the invoked function name |
| `match` | string | no | `"exact"` | Matching mode: `"exact"`, `"prefix"`, or `"glob"` |
| `args` | [arg matcher] | no | unset | Argument matchers; all must match (see below) |

Matches when the Soroban `invoke_host_function` operation calls a function that satisfies the
`match` condition. `"exact"` (the default) requires an identical name; `"prefix"` requires the
invoked name to start with `function_name`; `"glob"` matches using `*` (any sequence) and `?`
(exactly one character).

#### Argument matching (`args`)

Each entry in `args` matches one invocation parameter by position:

| Field | Type | Required | Description |
|---|---|---|---|
| `index` | u32 | yes | Zero-based position in the operation's parameters array |
| `eq` | string | yes | Value the decoded argument must equal exactly (max 128 characters, trimmed) |

At most 16 matchers are allowed and each `index` may appear only once. All matchers must match
the same invocation for the rule to fire. An argument that is missing does not match, and a rule
with `args` never fires when the operation parameters could not be decoded.

The following ScVal parameter types are decoded to text for comparison:

| ScVal type | Decoded text |
|---|---|
| `address` | The `G-` or `C-`address string |
| `symbol` | The symbol text |
| `u32`, `i32`, `u64`, `i64`, `u128`, `i128` | Decimal representation |
| `bool` | `true` / `false` |
| `string` | The string contents |

Any other type is compared against its compact JSON rendering.

When the rule fires, the decoded invocations are included in the payload as `function_args`
(see [Webhook payload fields](#webhook-payload-fields)).

```toml
# Exact match (default — backward compatible)
[[contracts.rules]]
type          = "FunctionCalled"
function_name = "withdraw"

# Prefix match: fires on admin_set_fee, admin_pause, admin_upgrade, …
[[contracts.rules]]
type          = "FunctionCalled"
function_name = "admin_"
match_mode    = "prefix"

# Glob match: fires on set_fee, set_admin, set_pause, …
[[contracts.rules]]
type          = "FunctionCalled"
function_name = "set_*"
match         = "glob"

# Argument match: transfer where the first argument is this address
[[contracts.rules]]
type          = "FunctionCalled"
function_name = "transfer"
args          = [{ index = 0, eq = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN" }]
```

### Rate

| Field | Type | Required | Description |
|---|---|---|---|
| `rule` | rule entry | yes | The nested rule whose matches are counted |
| `count` | u32 | yes | Number of matches that constitutes a breach (> 0) |
| `window_seconds` | u64 | yes | Length of the sliding window in seconds (> 0) |

Fires when the nested rule matches at least `count` times within any `window_seconds`
sliding window for the contract. This expresses rate-based conditions such as "more than 10
failed transactions in 5 minutes" or "more than 50 `withdraw` calls per hour".

One alert is emitted per breach, and the observed count is included in the payload as
`observed_count`. The nested rule supports the same options as a top-level rule entry
(`enabled`, `webhook_url`, `severity`, …). The breach clears the window, so the next alert
needs another `count` matches. `count` may be at most 1,000,000 and `window_seconds` at most
604,800 (one week).

```toml
# At least 10 failed transactions in 5 minutes
[[contracts.rules]]
type           = "Rate"
count          = 10
window_seconds = 300
[contracts.rules.rule]
type = "TransactionFailed"

# At least 50 withdraw calls per hour
[[contracts.rules]]
type           = "Rate"
count          = 50
window_seconds = 3600
[contracts.rules.rule]
type          = "FunctionCalled"
function_name = "withdraw"
```

### Memo

| Field | Type | Required | Description |
|---|---|---|---|
| `memo_type` | string | no | Memo type to match: `"none"`, `"text"`, `"id"`, `"hash"`, or `"return"`. Omit to match any type |
| `equals` | string | one of the two | Exact memo value to match |
| `prefix` | string | one of the two | Memo value prefix to match |

Set exactly one of `equals` or `prefix`; setting both is a validation error. Matches when the
transaction has a memo whose content equals `equals` (or starts with `prefix`) and, when
`memo_type` is set, whose memo type equals it.

Use case: exchanges and bridges alerting on specific memo IDs or text prefixes.

```toml
# Alert on a specific deposit memo ID
[[contracts.rules]]
type      = "Memo"
memo_type = "id"
equals    = "123456789"

# Alert on any memo text starting with a known prefix
[[contracts.rules]]
type      = "Memo"
memo_type = "text"
prefix    = "DEPOSIT-"
```

### AdminFunctionCalled

| Field | Type | Required | Description |
|---|---|---|---|
| `function_names` | [string] | yes | Non-empty list of function names to watch |

Matches when the invoked function is any entry in `function_names`.
Equivalent to multiple `FunctionCalled` rules but produces a single
`AdminFunctionCalled([...])` label in the alert.

```toml
[[contracts.rules]]
type           = "AdminFunctionCalled"
function_names = ["set_admin", "upgrade", "initialize"]
```

### HighFee

| Field | Type | Required | Description |
|---|---|---|---|
| `threshold_stroops` | u64 | one of the two | Fee threshold in stroops (> 0) |
| `threshold_xlm` | u64 | one of the two | Fee threshold in whole XLM (> 0) |

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

### SourceAccount

| Field | Type | Required | Description |
|---|---|---|---|
| `mode` | string | no | `"in"` (default) to fire when source is in `accounts`; `"not_in"` to fire when source is not in `accounts`. |
| `accounts` | [G-address] | no | List of Stellar G-addresses to match against. |
| `alert_unless` | [G-address] | no | Convenience alias: sets `accounts` and defaults `mode` to `"not_in"`. |
| `allow` | [G-address] | no | (Deprecated) Legacy membership list. Use `mode = "in"` with `accounts`. |
| `deny` | [G-address] | no | (Deprecated) Legacy membership list. Use `mode = "not_in"` with `accounts`. |

**Migration Note:** The legacy `allow` and `deny` fields are deprecated. Previously, both `allow` and `deny` fired on membership, which was counter-intuitive for users wanting to alert on unknown callers. To alert when the caller is **not** on an allowlist, use `mode = "not_in"` with `accounts = [...]` (or `alert_unless = [...]`). This also prevents false alerts on missing transaction source accounts.

```toml
# Alert on any caller EXCEPT the approved admin (allowlist use case)
[[contracts.rules]]
type     = "SourceAccount"
mode     = "not_in"
accounts = ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNA"]

# Or equivalently using alert_unless:
[[contracts.rules]]
type         = "SourceAccount"
alert_unless = ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNA"]

# Alert only when called by a specific known account
[[contracts.rules]]
type     = "SourceAccount"
mode     = "in"
accounts = ["GBUKOFF2GVFNQRJFGHVGON2JKGB4VBUF2QQJFNJ6HQVTJRZTCGQX7ZRA"]
```

The `source_account` field is included in the alert payload when this rule fires (and whenever `source_account` is present in the Horizon response).

### All

| Field | Type | Required | Description |
|---|---|---|---|
| `rules` | [rule entry array] | yes | Non-empty list of nested rule entries. All must match. |

Fires when all nested rules match the same transaction. Equivalent to a logical AND.
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

### Any

| Field | Type | Required | Description |
|---|---|---|---|
| `rules` | [rule entry array] | yes | Non-empty list of nested rule entries. At least one must match. |

Fires when any nested rule matches. Equivalent to a logical OR.

```toml
[[contracts.rules]]
type = "Any"
[[contracts.rules.rules]]
type = "TransactionFailed"
[[contracts.rules.rules]]
type          = "HighFee"
threshold_xlm = 1
```

### Not

| Field | Type | Required | Description |
|---|---|---|---|
| `rule` | rule entry | yes | A single nested rule entry. Fires when it does NOT match. |

Fires when the nested rule does not match. Equivalent to a logical NOT.

```toml
[[contracts.rules]]
type = "Not"
[contracts.rules.rule]
type = "TransactionFailed"
```

### EventEmitted

| Field | Type | Required | Description |
|---|---|---|---|
| `topic` | string | yes | Pattern that event topic 0 must match (see below) |
| `topics` | [string] | no | Patterns for topics 1, 2, … in order; `"*"` matches any value |
| `data` | [matcher] | no | Matchers applied to the event's decoded data (see below) |

Matches when the transaction emitted a contract event whose first topic matches `topic`, whose
following topics match `topics` positionally, and whose data satisfies every `data` matcher.

#### Topic patterns

`topic` (and each entry of `topics`) may be:

- `"*"` — matches any topic value;
- a typed pattern of the form `<type>:<value>`, which only matches a topic of that ScVal
  type: `symbol:transfer`, `address:G…`, `u32:5`, `i128:-1`, `string:hello`, `bytes:deadbeef`;
- a bare pattern, which matches any single-key scalar ScVal (`{"symbol": "x"}`,
  `{"address": "G…"}`, `{"u32": 5}`, `{"i128": "-1"}`, …) whose inner value's text equals the
  pattern, or, for non-scalar values, whose compact JSON equals the pattern.

Topic 0 is not required to be a symbol: string, bytes, address, integer or enum topics can
all be matched. The "valid Soroban symbol" validation only applies when the pattern is a bare
pattern that is not a typed pattern and topic 0 is expected to be a symbol; typed patterns are
always accepted.

#### `data` matchers

Each `data` matcher is a table:

| Field | Type | Required | Description |
|---|---|---|---|
| `pointer` | string | yes | JSON pointer into the decoded data (e.g. `"/0"`, `"/amount"`, `""` for the whole value) |
| `eq` | scalar | one of | Match when the value at `pointer` equals this value |
| `gte` | scalar | one of | Match when the value at `pointer` is ≥ this value |
| `lte` | scalar | one of | Match when the value at `pointer` is ≤ this value |

Exactly one of `eq`, `gte`, `lte` must be set per matcher. Pointers and comparison types are
validated at load time: a malformed JSON pointer, or a comparison whose type is incompatible
with the value it is compared against, is a configuration error.

**Integer comparison:** `i128` and `u128` values (decoded as decimal strings) are compared as
integers, not lexicographically, so `"100" ≥ "20"` holds. Other scalars are compared by their
text/JSON representation.

The matching events (topics and data, as decoded ScVal JSON) are included in the
`matched_events` payload field.

Use case: react to what a contract reports it did — `transfer`, `mint`, `admin_changed`, …

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

# Typed topic patterns: only a symbol "transfer" from a specific address
[[contracts.rules]]
type   = "EventEmitted"
topic  = "symbol:transfer"
topics = ["address:GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN", "*"]

# SEP-41 transfer with amount >= 1000 (data = [from, to, amount])
[[contracts.rules]]
type   = "EventEmitted"
topic  = "transfer"
[[contracts.rules.data]]
pointer = "/2"
gte     = "1000"

# admin_changed whose data is a specific address
[[contracts.rules]]
type   = "EventEmitted"
topic  = "admin_changed"
[[contracts.rules.data]]
pointer = ""
eq      = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"
```

### ContractUpgraded

Matches when the watched contract's executable changes — i.e. its code is upgraded via
`update_current_contract_wasm` (or an equivalent host call), regardless of which contract
function triggered it. Detection uses the contract's ledger entry (or the corresponding system
event) to compare the executable before and after the transaction.

This catches upgrades performed through *any* function, not only one named `upgrade`, which
`AdminFunctionCalled` alone cannot do.

The webhook payload includes:

| Field | Type | Description |
|---|---|---|
| `old_wasm_hash` | string/null | Hex WASM hash before the upgrade, or `null` if previously absent |
| `new_wasm_hash` | string/null | Hex WASM hash after the upgrade |

Use case: the most security-critical event for a monitored contract — alert on any code change.

```toml
[[contracts.rules]]
type     = "ContractUpgraded"
severity = "critical"
```

## Cooldowns

Every rule accepts an optional `cooldown_seconds` (0–604800):

```toml
[[contracts.rules]]
type             = "TransactionFailed"
cooldown_seconds = 300
```

After the rule fires for a contract, further matches of the same `(contract, rule)` within
`cooldown_seconds` are suppressed and counted. The next alert that is sent for that rule carries
the number of suppressed matches in `suppressed_count`. Unset or `0` disables the cooldown.

Cooldown state is kept in memory for the life of `txwatch watch`; it resets on restart and does
not carry over between `txwatch watch --once` runs.

### Cooldown summaries (`cooldown_summary`)

By default, the matches that were suppressed during a cooldown window are counted but never
reported once the window ends — the next real alert simply goes out with `suppressed_count = 0`
unless it happens to be the first alert of a new window. Set `cooldown_summary = true` on the
rule to receive a synthetic "N matches were suppressed" alert the next time the rule would have
fired after its cooldown window expired:

```toml
[[contracts.rules]]
type             = "TransactionFailed"
cooldown_seconds = 300
cooldown_summary = true
```

`cooldown_summary` **requires `cooldown_seconds > 0`**. With no cooldown there is no window
to summarise, so a `cooldown_summary = true` rule with an unset or `0` `cooldown_seconds` is a
configuration error and is rejected by `txwatch validate`. This guards against the silent
no-op where a user sets `cooldown_summary = true`, receives nothing, and gets no hint why.

The summary alert is delivered through the same destination resolution as a normal alert from
that rule: it inherits the rule's `severity` and any `webhook_url` / `webhook_secret` overrides,
so a `severity = "critical"` rule routed to a dedicated PagerDuty endpoint sends its summary to
that endpoint with `severity = "critical"` — not to the contract's default webhook.

## Evaluation order

- Rules are evaluated in the order they appear in the config file.
- Disabled rules (`enabled = false`) are skipped entirely.
- All matching enabled rules fire; there is no short-circuit.

## Webhook payload fields

| Field | Type | Always present | Description |
|---|---|---|---|
| `schema_version` | u32 | yes | Payload shape version (currently `1`); bump on breaking changes |
| `alert_id` | string | yes | Deterministic 32-hex-char ID for deduplication (see below) |
| `label` | string | yes | Contract label from config |
| `contract_id` | string | yes | Stellar C-address |
| `network` | string | yes | `mainnet` / `testnet` / `futurenet` |
| `rule_type` | string | yes | Stable machine-readable rule variant |
| `rule_triggered` | string | yes | Human-readable rule description |
| `transaction_hash` | string | yes | Stellar transaction hash |
| `function_name` | string/null | no | First Soroban function name; `null` for non-Soroban transactions |
| `function_names` | [string] | yes | All Soroban function names in the transaction (may be empty) |
| `amount_xlm` | u64/null | no | Transfer amount in whole XLM (truncated). Kept for backward compatibility — use `amount_xlm_decimal` for precise accounting |
| `amount_stroops` | u64/null | no | Raw transfer amount in stroops (1 XLM = 10,000,000 stroops), or `null` |
| `amount_xlm_decimal` | string/null | no | Transfer amount as a decimal string with 7 fractional digits (e.g. `"9999.9900000"`), or `null` |
| `fee_charged_stroops` | u64/null | no | Transaction fee in stroops |
| `severity` | string/null | no | `info`, `warning`, or `critical`; omitted when unset on the rule |
| `timestamp` | i64 | yes | Unix timestamp (seconds) of transaction |
| `timestamp_iso` | string | yes | ISO 8601 timestamp string |
| `horizon_link` | string | yes | Direct link to transaction on Horizon |
| `explorer_link` | string | yes | Stellar Expert explorer link |
| `ledger` | u32/null | no | Ledger sequence number (when available) |
| `source_account` | string/null | no | Source account G-address (when available); omitted when not present |
| `memo` | string/null | no | Memo content (absent for `MemoNone`) |
| `memo_type` | string/null | no | Memo type: `"none"`, `"text"`, `"id"`, `"hash"`, `"return"` |
| `operation_count` | u32/null | no | Total operations in the transaction |
| `arguments` | [string] | no | Decoded invocation arguments (see [FunctionCalled](#functioncalled) `args`); present when the rule matched on arguments |
| `observed_count` | u32/null | no | Number of matches observed in the window for a `Rate` rule |
| `matched_events` | array | yes | Events that matched an `EventEmitted` rule (`contract_id`, `topics`, `data`); empty for other rules |
| `old_wasm_hash` | string/null | no | WASM hash before a `ContractUpgraded` match; omitted for other rules |
| `new_wasm_hash` | string/null | no | WASM hash after a `ContractUpgraded` match; omitted for other rules |
| `suppressed_count` | u64 | yes | Matches suppressed by this rule's `cooldown_seconds` since the previous alert; `0` otherwise |

`horizon_link` and `explorer_link` are always present in every alert payload, even when `function_name` is `null` for a non-Soroban transaction.