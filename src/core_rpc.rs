// Bitcoin Core JSON-RPC adapter — the ONLY chain source for this indexer.
//
// One `getblock <hash> 3` call returns every transaction in the block —
// including `prevout` metadata (vin value + scriptPubKey) — so backfill
// runs at "as fast as the local node can serialize JSON", with no
// rate limits and no third-party trust.
//
// Requires Bitcoin Core 24.0+ for `verbosity=3` (released 2022-12).
// If the user's node is older, `fetch_block_all_txs` errors and the
// indexer halts — there is no Esplora fallback in this binary.
//
// Configuration is global (`CORE_RPC`) so source.rs helpers can read
// it without threading config through every call site. main.rs sets
// the OnceLock once on startup; the rest of the program treats it
// as immutable.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::{json, Value};

/// Per-request timeout. Local-network RPC is fast; 8s catches the
/// pathological case where the user pointed `--core-url` at a remote
/// node that's down without stalling the pipeline.
const RPC_TIMEOUT: Duration = Duration::from_secs(8);

/// Global Bitcoin Core RPC configuration, set once by `main.rs` from
/// the required `--core-url` / `--core-user` / `--core-password` CLI
/// args. Reads are lock-free.
pub static CORE_RPC: OnceLock<CoreRpcConfig> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct CoreRpcConfig {
 /// Full HTTP URL — `http://127.0.0.1:8332` for a localhost node,
 /// `http://lan-ip:8332` over a LAN, or `https://...` if the user
 /// fronts the node with TLS. We don't append paths — Bitcoin Core
 /// listens on `/` for JSON-RPC.
    pub url: String,
    pub user: String,
    pub password: String,
}

pub fn config() -> Option<&'static CoreRpcConfig> {
    CORE_RPC.get()
}

/// JSON-RPC response envelope. Bitcoin Core sets `result` on success
/// and `error` on failure; exactly one is populated.
#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
 #[allow(dead_code)]
    code: i64,
    message: String,
}

async fn call<T>(
    client: &reqwest::Client,
    cfg: &CoreRpcConfig,
    method: &str,
    params: Value,
) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let body = json!({
        "jsonrpc": "1.0",
        "id": "luckyprotocol-indexer",
        "method": method,
        "params": params,
    });
    let resp = client
        .post(&cfg.url)
        .basic_auth(&cfg.user, Some(&cfg.password))
        .timeout(RPC_TIMEOUT)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("core-rpc {} POST failed: {}", method, e))?;
    let status = resp.status();
    if !status.is_success() && status.as_u16() != 500 {
 // 500 is the path JSON-RPC uses for method-level errors with a
 // body that has the error JSON. Any other non-2xx is transport.
        return Err(anyhow!("core-rpc {} HTTP {}", method, status));
    }
    let parsed: RpcResponse<T> = resp
        .json()
        .await
        .map_err(|e| anyhow!("core-rpc {} JSON parse: {}", method, e))?;
    if let Some(err) = parsed.error {
        return Err(anyhow!("core-rpc {} error: {}", method, err.message));
    }
    parsed
        .result
        .ok_or_else(|| anyhow!("core-rpc {} returned neither result nor error", method))
}

// ============================================================================
// Esplora-shape adapters
// ============================================================================
// Each fetch_* below returns the same type as source.rs's matching
// Esplora fetcher, so source.rs can swap implementations without
// touching downstream logic.

pub async fn fetch_tip_height(client: &reqwest::Client) -> Result<u32> {
    let cfg = config().ok_or_else(|| anyhow!("core-rpc not configured"))?;
    let h: u64 = call(client, cfg, "getblockcount", json!([])).await?;
    Ok(h as u32)
}

pub async fn fetch_block_hash(client: &reqwest::Client, height: u32) -> Result<String> {
    let cfg = config().ok_or_else(|| anyhow!("core-rpc not configured"))?;
    let hash: String = call(client, cfg, "getblockhash", json!([height])).await?;
    Ok(hash)
}

/// Result of `getblockheader <hash>` (verbose=true). We only consume
/// the timestamp for the indexer's /block-info endpoint; the rest of
/// the fields exist on the wire but go unused.
#[derive(Debug, Deserialize)]
pub struct BlockHeader {
    /// Hash again — Core echoes it; keep it so callers don't have to
    /// re-thread the input hash through the result type.
    pub hash: String,
    /// Block-header timestamp (seconds-since-epoch). The miner sets
    /// this; consensus rules require it to fit a "median of past 11"
    /// window so it's roughly monotonic but NOT strictly so.
    pub time: u64,
}

/// `getblockheader <hash> true` — header-only metadata (no full
/// transaction list). Used by `/block-info/:height` to answer
/// "what is the timestamp of the block at this height?" with a
/// single RPC round-trip.
pub async fn fetch_block_header(
    client: &reqwest::Client,
    block_hash: &str,
) -> Result<BlockHeader> {
    let cfg = config().ok_or_else(|| anyhow!("core-rpc not configured"))?;
    call(client, cfg, "getblockheader", json!([block_hash, true])).await
}

/// Result of `getrawtransaction <txid> true` (the verbose form). We
/// surface only the fields the indexer's /tx-status endpoint exposes;
/// the verbose response carries more (vin/vout/hex/etc.) but we don't
/// need it here — the protocol indexer's own bet/transfer logs answer
/// the "what did this tx do?" question, /tx-status only answers
/// "did it confirm yet?".
#[derive(Debug, Deserialize)]
pub struct RawTxStatus {
    /// Hash of the block this tx landed in. Absent / empty when the
    /// tx is in the mempool (unconfirmed).
    #[serde(default)]
    pub blockhash: Option<String>,
    /// Number of confirmations so far. 0 = mempool, >=1 = in a block.
    /// Older Core versions sometimes omit this for unconfirmed txs;
    /// we default to 0.
    #[serde(default)]
    pub confirmations: u32,
    /// Block timestamp (seconds-since-epoch). Absent when unconfirmed.
    #[serde(default)]
    pub blocktime: Option<u64>,
}

/// `getrawtransaction <txid> true` — verbose form, includes block
/// hash + confirmations. Note: requires `txindex=1` in bitcoin.conf
/// for non-wallet, non-mempool txs — without it, Core returns
/// `"No such mempool or blockchain transaction"` for any historical
/// tx the node hasn't indexed. The official LUCKYPROTOCOL deploy is
/// expected to run with txindex=1.
pub async fn fetch_raw_tx_status(
    client: &reqwest::Client,
    txid: &str,
) -> Result<RawTxStatus> {
    let cfg = config().ok_or_else(|| anyhow!("core-rpc not configured"))?;
    call(client, cfg, "getrawtransaction", json!([txid, true])).await
}

/// One unspent output as returned by `scantxoutset`. The fields we
/// keep are the bare minimum the wallet needs for coin selection
/// (txid + vout outpoint, value in BTC, block height of the
/// containing block).
#[derive(Debug, Deserialize)]
pub struct ScanTxOutEntry {
    pub txid: String,
    pub vout: u32,
    /// Value as BTC (float). Callers convert to sats with `btc_to_sats`.
    pub amount: f64,
    /// Height of the block this UTXO landed in. `scantxoutset` only
    /// returns confirmed UTXOs, so this is always populated for a
    /// successful scan.
    pub height: u32,
}

#[derive(Debug, Deserialize)]
pub struct ScanTxOutResult {
    /// True if the scan ran to completion. False can mean an in-flight
    /// scan was aborted, the descriptor was malformed, or the node is
    /// still in IBD and refused.
    pub success: bool,
    /// Tip height the UTXO set was scanned at.
    #[serde(default)]
    pub height: u32,
    /// The UTXOs themselves.
    #[serde(default)]
    pub unspents: Vec<ScanTxOutEntry>,
}

/// `scantxoutset start [{"desc": "addr(<address>)"}]` — scan the
/// UTXO set for outputs paying the given address. Slow on first call
/// (~30-60s, walks the whole UTXO set) but cacheable for subsequent
/// requests within the CF edge-cache window.
///
/// scantxoutset is serialized at the bitcoind level — only one scan
/// can run at a time across all callers. The caller in server.rs
/// wraps invocations in a Tokio Mutex to queue concurrent requests
/// so we don't fire-and-fail on each one.
pub async fn scan_tx_out_set_for_address(
    client: &reqwest::Client,
    address: &str,
) -> Result<ScanTxOutResult> {
    let cfg = config().ok_or_else(|| anyhow!("core-rpc not configured"))?;
    // The "addr(...)" descriptor matches any output whose
    // scriptpubkey decodes to the given address. Works for every
    // standard address type Bitcoin Core understands (p2pkh, p2sh,
    // p2wpkh, p2wsh, p2tr).
    let descriptors = json!([{ "desc": format!("addr({})", address) }]);
    let res: ScanTxOutResult = call(
        client, cfg, "scantxoutset", json!(["start", descriptors]),
    ).await?;
    Ok(res)
}

/// Convert a BTC-denominated float (as serialized by Bitcoin Core's
/// JSON-RPC) to integer satoshis. Made pub so callers in server.rs
/// can use the same conversion path as the indexer's getblock parser.
pub fn btc_to_sats_pub(btc: f64) -> u64 {
    btc_to_sats(btc)
}

/// Result of `getblock <hash> 3` — full transactions with prevout
/// metadata included on every vin. The shape differs from Esplora's
/// `/block/:hash/txs[/:idx]` so we map fields in the adapter below.
#[derive(Debug, Deserialize)]
struct CoreBlockV3 {
 #[serde(default)]
    merkleroot: String,
 /// Core's field name is `nTx` (camelCase) — rename so the rust
 /// snake_case lint doesn't complain about the field literal.
 #[serde(default, rename = "nTx")]
    n_tx: u32,
    tx: Vec<CoreTx>,
}

#[derive(Debug, Deserialize)]
struct CoreTx {
    txid: String,
 #[serde(default)]
    vin: Vec<CoreVin>,
 #[serde(default)]
    vout: Vec<CoreVout>,
}

#[derive(Debug, Deserialize)]
struct CoreVin {
 /// Absent on coinbase txs.
 #[serde(default)]
    txid: String,
 /// Absent on coinbase txs.
 #[serde(default)]
    vout: u32,
 /// Present iff verbosity=3 AND prev tx is in pruned set / mempool.
 /// We accept None and fall through to the Esplora chain in that
 /// case (rare — verbosity=3 returns prevout for all confirmed txs).
    prevout: Option<CorePrevout>,
}

#[derive(Debug, Deserialize)]
struct CorePrevout {
 /// BTC (not sats). e.g. 0.00012345.
 #[serde(default)]
    value: f64,
 #[serde(default, alias = "scriptPubKey")]
    script_pub_key: CoreScriptPubKey,
}

#[derive(Debug, Deserialize)]
struct CoreVout {
 /// BTC.
 #[serde(default)]
    value: f64,
 #[serde(default, alias = "scriptPubKey")]
    script_pub_key: CoreScriptPubKey,
}

#[derive(Debug, Default, Deserialize)]
struct CoreScriptPubKey {
 #[serde(default)]
    hex: String,
 /// Core script type names like "nulldata" / "witness_v0_keyhash".
 /// We normalize to Esplora's vocabulary in the adapter below.
 #[serde(default, alias = "type")]
    ty: String,
 /// Bitcoin Core 22.0+: single `address`. Earlier versions used
 /// `addresses: [String]`. We try both.
 #[serde(default)]
    address: Option<String>,
 #[serde(default)]
    addresses: Option<Vec<String>>,
}

impl CoreScriptPubKey {
    fn primary_address(&self) -> Option<String> {
        if let Some(a) = &self.address {
            return Some(a.clone());
        }
        if let Some(list) = &self.addresses {
            return list.first().cloned();
        }
        None
    }
}

/// Normalize Core's script-type name to Esplora's. We only really care
/// that "op_return" reads right; other types are passed through as-is
/// for diagnostic logging in the indexer.
fn normalize_script_type(core_ty: &str) -> String {
    match core_ty {
        "nulldata" => "op_return".to_string(),
        "witness_v0_keyhash" => "v0_p2wpkh".to_string(),
        "witness_v0_scripthash" => "v0_p2wsh".to_string(),
        "witness_v1_taproot" => "v1_p2tr".to_string(),
        "pubkeyhash" => "p2pkh".to_string(),
        "scripthash" => "p2sh".to_string(),
        other => other.to_string(),
    }
}

fn btc_to_sats(btc: f64) -> u64 {
 // f64 → integer sats with rounding. Bitcoin amounts have at most
 // 8 decimal places (precision = 10^-8 BTC = 1 sat) so float
 // precision around 21M BTC is fine for round-trip.
    (btc * 100_000_000.0).round() as u64
}

/// Fetch every tx in a block via one `getblock <hash> 3` call. The
/// returned `Vec` matches what Esplora's `/block/:hash/txs` family
/// would have returned across multiple paginated requests — so the
/// downstream block-scan loop is identical.
/// Also returns the block's merkle root for the merkle-verification
/// step (source.rs::verify_block_merkle_root) — saves a separate
/// `/block/:hash` header fetch.
pub async fn fetch_block_all_txs(
    client: &reqwest::Client,
    block_hash: &str,
) -> Result<(Vec<crate::source::EsploraTxFull>, String, u32)> {
    let cfg = config().ok_or_else(|| anyhow!("core-rpc not configured"))?;
 // verbosity=3 → full tx data + prevouts. Requires Core 24.0+.
    let block: CoreBlockV3 = call(client, cfg, "getblock", json!([block_hash, 3])).await?;
    let tx_count = block.tx.len() as u32;
    let mut out = Vec::with_capacity(block.tx.len());
    for tx in block.tx {
        let mut vin_out = Vec::with_capacity(tx.vin.len());
        for v in tx.vin {
            let prevout = v.prevout.as_ref().map(|p| crate::source::EsploraVout {
                scriptpubkey_address: p.script_pub_key.primary_address(),
                value: btc_to_sats(p.value),
                scriptpubkey: p.script_pub_key.hex.clone(),
                scriptpubkey_type: normalize_script_type(&p.script_pub_key.ty),
            });
 // Coinbase has no prev tx — txid stays empty.
            vin_out.push(crate::source::EsploraVin {
                txid: v.txid,
                vout: v.vout,
                prevout,
            });
        }
        let mut vout_out = Vec::with_capacity(tx.vout.len());
        for v in tx.vout {
            vout_out.push(crate::source::EsploraVout {
                scriptpubkey_address: v.script_pub_key.primary_address(),
                value: btc_to_sats(v.value),
                scriptpubkey: v.script_pub_key.hex,
                scriptpubkey_type: normalize_script_type(&v.script_pub_key.ty),
            });
        }
        out.push(crate::source::EsploraTxFull {
            txid: tx.txid,
            vin: vin_out,
            vout: vout_out,
        });
    }
 // Bitcoin Core returns block.nTx as u32; if absent (older nodes
 // not returning the field), fall back to the length of the tx array.
    let n_tx = if block.n_tx > 0 { block.n_tx } else { tx_count };
    Ok((out, block.merkleroot, n_tx))
}

/// Subset of `getblockchaininfo` we care about. Used by callers that
/// want to distinguish "Core is fully synced" from "Core is still in
/// IBD" — relevant because the indexer can advance no further than
/// `blocks` (the node's current verified tip), and during IBD that's
/// often far below `headers` (the known best chain).
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields read by future /state JSON surfacing.
pub struct BlockchainInfo {
    /// Verified tip height — the latest block whose state Core has
    /// applied. Equal to `headers` once IBD finishes.
    pub blocks: u32,
    /// Highest known header height — set by the headers-first download
    /// phase. During IBD this is the true chain tip while `blocks`
    /// catches up; afterwards the two stay equal.
    pub headers: u32,
    /// True iff Core considers itself still in Initial Block Download.
    /// While true the indexer should NOT trust `blocks` as the chain
    /// tip for scan purposes — it should wait (or scan slowly, knowing
    /// the tip will advance steadily).
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
}

/// One-shot `getblockchaininfo` call. Used by the poll loop to detect
/// IBD state — when the node is still syncing, our derived state is
/// only as fresh as the node's verified tip, and the operator log
/// should reflect that distinction.
#[allow(dead_code)] // Surfaced via the HTTP server's /state endpoint when wired in.
pub async fn fetch_blockchain_info(client: &reqwest::Client) -> Result<BlockchainInfo> {
    let cfg = config().ok_or_else(|| anyhow!("core-rpc not configured"))?;
    call(client, cfg, "getblockchaininfo", json!([])).await
}
