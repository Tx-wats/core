#![allow(dead_code)]
use txwatch_config::{AlertRule, Network, RuleConfig, WatchedContract};

/// Build a `WatchedContract` fixture with sensible test defaults.
///
/// Centralizes the literal so that new fields on `WatchedContract` only need
/// to be updated here (and in `WatchedContract::test_default`).
pub fn contract(webhook_url: &str, rules: Vec<AlertRule>) -> WatchedContract {
    WatchedContract {
        label: "Integration Test Contract".into(),
        contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
        network: Network::Testnet,
        rules: rules
            .into_iter()
            .map(|r| RuleConfig {
                rule: r,
                cooldown_seconds: None,
            })
            .collect(),
        webhook_url: Some(webhook_url.to_string()),
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

pub fn tx_page(hash: &str, paging_token: &str, successful: bool) -> serde_json::Value {
    serde_json::json!({
        "_embedded": {
            "records": [{
                "hash":         hash,
                "created_at":   "2024-06-01T10:00:00Z",
                "successful":   successful,
                "paging_token": paging_token,
                "fee_charged":  "100",
                "envelope_xdr": null,
                "result_xdr":   null
            }]
        }
    })
}

/// Base64-encode `bytes` (standard alphabet, with padding).
pub fn b64(bytes: &[u8]) -> String {
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

/// The XDR-encoded `ScVal` base64 value of a `Sym`, as Horizon returns it:
/// a 4-byte big-endian discriminant (15 == SCV_SYMBOL), a 4-byte big-endian
/// length, then the UTF-8 bytes padded to a 4-byte boundary.
pub fn sym_param(name: &str) -> String {
    let mut raw = vec![0, 0, 0, 15];
    raw.extend_from_slice(&(name.len() as u32).to_be_bytes());
    raw.extend_from_slice(name.as_bytes());
    while raw.len() % 4 != 0 {
        raw.push(0);
    }
    b64(&raw)
}

/// A realistic `invoke_host_function` operation.
///
/// `function` is the *host function type*, not the contract function name —
/// that is what Horizon actually returns, and matching against it is the bug
/// fixed in issue #3. The name is the `Sym` parameter.
pub fn invoke_op(function_name: &str) -> serde_json::Value {
    serde_json::json!({
        "type":     "invoke_host_function",
        "function": "HostFunctionTypeHostFunctionTypeInvokeContract",
        "parameters": [
            { "type": "Address", "value": "AAAAEgAAAAEJIX5C6S3X6ftDOw+T3MtGCdZN6Xv2zEfpPmTF42f8og==" },
            { "type": "Sym",     "value": sym_param(function_name) }
        ]
    })
}

pub fn ops_page(function_name: &str) -> serde_json::Value {
    serde_json::json!({ "_embedded": { "records": [invoke_op(function_name)] } })
}

pub fn payment_ops_page(amount_str: &str) -> serde_json::Value {
    serde_json::json!({
        "_embedded": {
            "records": [{
                "type":       "payment",
                "asset_type": "native",
                "amount": amount_str
            }]
        }
    })
}

pub fn empty_page() -> serde_json::Value {
    serde_json::json!({ "_embedded": { "records": [] } })
}

pub fn tx_page_3(hash1: &str, hash2: &str, hash3: &str) -> serde_json::Value {
    serde_json::json!({
        "_embedded": {
            "records": [
                {
                    "hash": hash1, "created_at": "2024-06-01T10:00:00Z",
                    "successful": true, "paging_token": "1",
                    "fee_charged": "100", "envelope_xdr": null, "result_xdr": null
                },
                {
                    "hash": hash2, "created_at": "2024-06-01T10:01:00Z",
                    "successful": true, "paging_token": "2",
                    "fee_charged": "100", "envelope_xdr": null, "result_xdr": null
                },
                {
                    "hash": hash3, "created_at": "2024-06-01T10:02:00Z",
                    "successful": true, "paging_token": "3",
                    "fee_charged": "100", "envelope_xdr": null, "result_xdr": null
                }
            ]
        }
    })
}
