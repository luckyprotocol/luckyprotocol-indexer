// Chain source — Core-only.
//
// Backfill from --start-height (default LCKPROTOCOL_START_HEIGHT) up to tip,
// then poll for new blocks. Parses every OP_RETURN per block and dispatches
// to the indexer state.
//
// Transport: ONLY Bitcoin Core JSON-RPC. There is no Esplora / Alchemy /
// mempool.space fallback in this binary by design — self-hosted indexer =
// every byte must come from a node the operator controls. If Core is
// unreachable, the indexer retries with backoff rather than serving
// derived state from an unverified source. See main.rs for rationale.

use anyhow::{anyhow, Result};
use bitcoin::hashes::Hash;
use bitcoin::{Network, TxMerkleNode, Txid};
use parking_lot::RwLock;
use serde::Deserialize;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::indexer::IndexerState;
use crate::protocol::parse_payload;

/// Reorg-detection horizon — on every poll, we re-fetch hashes for the
/// last K indexed blocks and compare against our snapshot. If any hash
/// diverged from what we stored when we indexed it, the chain
/// reorganized; we roll back state past the divergence point and re-scan
/// forward. K=12 covers ~2 hours on mainnet, well past the deepest
/// historic reorg (10 blocks in the 2013 0.7→0.8 fork; routine reorgs
/// are 1-2 blocks). Running cost: 12 extra `getblockhash <h>` RPC calls
/// per poll, each a single integer round-trip — negligible on a local
/// node.
const REORG_HORIZON: u32 = 12;

/// Reorg-storm circuit breaker. If the indexer detects this many reorgs
/// inside REORG_STORM_WINDOW, the poll loop trips and pauses for
/// REORG_STORM_COOLDOWN before resuming. A genuine chain experiences
/// at most a handful of 1-2 block reorgs per day; >5 reorgs in 5
/// minutes is either Core deserialization corruption or an active 51%
/// attack — either way, continuing to thrash the snapshot ring is
/// worse than pausing.
const REORG_STORM_THRESHOLD: usize = 5;
const REORG_STORM_WINDOW: Duration = Duration::from_secs(300);
const REORG_STORM_COOLDOWN: Duration = Duration::from_secs(600);

/// Watchdog deadline for a single poll-loop iteration. A wedged Core
/// RPC call (network blip on a remote node, deserialization deadlock)
/// gets force-cancelled rather than freezing the entire poll loop. On
/// timeout we drop all in-flight RPC futures (cancel-safe — every
/// `state.write()` block is sync) and switch to fast cadence to retry.
const POLL_ITER_WATCHDOG: Duration = Duration::from_secs(120);

/// Number of blocks whose data is being fetched IN PARALLEL ahead of
/// the apply-state loop. State mutations (`apply_payload`) MUST run
/// in chain order (a SEND that depends on a prior SEND's debit must
/// see the updated balance), so we use `stream::buffered` (not
/// `buffer_unordered`) — futures run concurrently but yield in the
/// original order. The sequential apply loop drains them as they
/// complete.
///
/// Why parallelism still helps with a local Core node: each `getblock
/// <hash> 3` RPC returns a multi-MB JSON blob whose parsing is CPU-
/// bound; the apply path is also CPU-bound (HashMap mutation, payload
/// decode). Buffering 4 blocks lets the I/O + JSON parse for blocks
/// N+1..N+3 run concurrently with the apply pass for block N.
const BLOCK_FETCH_CONCURRENCY: usize = 4;

/// Hard cap on declared OP_RETURN push-data length we'll trust. Bitcoin's
/// standardness limits OP_RETURN to 80 payload bytes, but PUSHDATA2/4
/// can technically declare up to 64 KiB / 4 GiB respectively. We cap
/// at 256 bytes so a malformed-but-mineable script can't trick the
/// parser into a giant slice; any declared length above this is
/// treated as garbage and the OP_RETURN is skipped.
const MAX_OP_RETURN_PAYLOAD: usize = 256;

/// Disk path for snapshot persistence. Set by main.rs at startup; None
/// disables persistence (purely in-memory mode). Using OnceLock so the
/// path can be set once and read concurrently from the snapshot trigger
/// in backfill_range without locking.
pub static SNAPSHOT_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

pub fn parse_network(s: &str) -> Result<Network> {
    match s.to_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        other => Err(anyhow!(
            "{} not supported — LUCKYPROTOCOL indexer is mainnet-only", other
        )),
    }
}

// ---------------------------------------------------------------------------
// Canonical tx shape consumed by indexer.rs::apply_tx.
//
// The names `Esplora*` are historical — pre-Core-only the indexer
// ingested Esplora JSON directly and these structs deserialized that
// shape with serde. Now `core_rpc::fetch_block_all_txs` constructs
// them from `getblock <hash> 3` instead, and serde Deserialize is no
// longer strictly required (the field reads in core_rpc.rs are
// direct struct literals). We keep `#[derive(Deserialize)]` for
// snapshot round-trips and future extensibility.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct EsploraVin {
    /// Txid of the previous tx whose output this vin is spending. Empty
    /// for coinbase txs (no real previous output).
    #[serde(default)]
    pub txid: String,
    /// vout index of the previous output. Pairs with `txid` to form the
    /// outpoint key used in `utxo_balances` lookups.
    #[serde(default)]
    pub vout: u32,
    pub prevout: Option<EsploraVout>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EsploraVout {
    pub scriptpubkey_address: Option<String>,
    /// Value in sats. For `prevout`-context this is what
    /// `resolve_sender_from_json` uses to pick the largest-contributor
    /// address; for vout-context it's the output's value.
    #[serde(default)]
    pub value: u64,
    /// Hex-encoded raw script. Used to extract the OP_RETURN payload.
    #[serde(default)]
    pub scriptpubkey: String,
    /// Classified script type — "op_return", "v0_p2wpkh", "p2sh", etc.
    /// Lets the OP_RETURN-detection fast-path skip non-OP_RETURN outputs
    /// without parsing the hex.
    #[serde(default)]
    pub scriptpubkey_type: String,
}

/// Full tx as constructed by `core_rpc::fetch_block_all_txs` from
/// Bitcoin Core's `getblock <hash> 3` response (one RPC = whole block
/// with prevout context for every input).
#[derive(Debug, Deserialize, Clone)]
pub struct EsploraTxFull {
    pub txid: String,
    pub vin: Vec<EsploraVin>,
    pub vout: Vec<EsploraVout>,
}

/// Pre-fetched data for one block, ready to be applied to state.
/// `merkle_root_claimed` is the block-header value we'll verify the
/// page contents against (defense-in-depth corruption check — Core
/// already validates this at consensus level, but a one-page
/// recomputation is cheap insurance against RPC serialization bugs).
struct BlockData {
    block_hash: String,
    merkle_root_claimed: String,
    pages: Vec<(usize, Vec<EsploraTxFull>)>,
}

// ---------------------------------------------------------------------------
// OP_RETURN extraction + sender resolution from EsploraTxFull.
// Pure functions — no IO. Same protocol rules as the JS indexer.
// ---------------------------------------------------------------------------

/// OP_RETURN check on a canonical tx. Skips non-OP_RETURN vouts via the
/// cheap `scriptpubkey_type` string compare BEFORE touching the hex
/// script — most outputs in any block are non-OP_RETURN, so this
/// short-circuits ~99% of vouts at zero parse cost.
///
/// Push-opcode coverage:
/// * 0x01..=0x4b — direct push (1-75 bytes), opcode IS the length
/// * 0x4c (OP_PUSHDATA1) — next 1 byte = length (0-255)
/// * 0x4d (OP_PUSHDATA2) — next 2 bytes LE = length (0-65535)
/// * 0x4e (OP_PUSHDATA4) — next 4 bytes LE = length (0-4294967295)
///
/// Bitcoin standardness rules require the SHORTEST push opcode that
/// fits, so a 50-byte payload SHOULD use direct push. But miners can
/// include non-standard txs directly, so a malicious miner could put
/// our protocol payload behind PUSHDATA2 to make permissive indexers
/// accept it while strict indexers reject it (consensus-divergence
/// attack vector). Supporting all four cases byte-for-byte equally
/// closes that gap. The hard MAX_OP_RETURN_PAYLOAD cap ensures a
/// PUSHDATA4 declaring a 4 GiB payload can't crash the parser.
///
/// Multi-OP_RETURN reject: a tx with >1 OP_RETURN output is rejected
/// outright (returns None even if one carries a valid payload). This
/// matches Bitcoin Core's standardness rule and prevents an attacker
/// from embedding multiple competing payloads in one tx.
fn extract_luckyprotocol_payload_from_json(tx: &EsploraTxFull) -> Option<crate::protocol::ProtocolPayload> {
    let mut op_return_count = 0usize;
    let mut luckyprotocol_payload: Option<crate::protocol::ProtocolPayload> = None;

    for vout in &tx.vout {
        if vout.scriptpubkey_type != "op_return" {
            continue;
        }
        op_return_count += 1;
        if op_return_count > 1 {
            return None;
        }
        let bytes = match hex::decode(&vout.scriptpubkey) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bytes.len() < 2 || bytes[0] != 0x6a {
            continue;
        }
        let push_op = bytes[1];
        // STRICT script termination: the script bytes MUST be EXACTLY
        //   <OP_RETURN> <push_op> [push_len_bytes] <payload>
        // No trailing opcodes allowed.
        let payload: &[u8] = match push_op {
            n @ 0x01..=0x4b => {
                let len = n as usize;
                let expected_total = 2 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total {
                    continue;
                }
                &bytes[2..expected_total]
            }
            0x4c if bytes.len() >= 3 => {
                let len = bytes[2] as usize;
                let expected_total = 3 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total {
                    continue;
                }
                &bytes[3..expected_total]
            }
            0x4d if bytes.len() >= 4 => {
                let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
                let expected_total = 4 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total {
                    continue;
                }
                &bytes[4..expected_total]
            }
            0x4e if bytes.len() >= 6 => {
                let len = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
                let expected_total = 6 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total {
                    continue;
                }
                &bytes[6..expected_total]
            }
            _ => continue,
        };
        if let Some(p) = parse_payload(payload) {
            luckyprotocol_payload = Some(p);
            // Keep scanning so a 2nd OP_RETURN still triggers reject.
        }
    }

    luckyprotocol_payload
}

/// Largest-contributor sender resolution from already-loaded vin
/// prevouts. Audit-only: NOT used for authorization (UTXO consensus
/// already authorizes the spend) — recorded in audit logs.
fn resolve_sender_from_json(tx: &EsploraTxFull) -> Option<String> {
    if tx.vin.is_empty() {
        return None;
    }
    let mut by_addr: std::collections::HashMap<String, (u64, usize)> = std::collections::HashMap::new();
    for (i, v) in tx.vin.iter().enumerate() {
        let prev = match v.prevout.as_ref() {
            Some(p) => p,
            None => continue,
        };
        let addr = match prev.scriptpubkey_address.as_ref() {
            Some(a) => a.clone(),
            None => continue,
        };
        let entry = by_addr.entry(addr).or_insert((0, i));
        entry.0 = entry.0.saturating_add(prev.value);
    }
    by_addr.into_iter()
        .max_by(|a, b| {
            let (val_a, idx_a) = a.1;
            let (val_b, idx_b) = b.1;
            val_a.cmp(&val_b).then(idx_b.cmp(&idx_a))
        })
        .map(|(addr, _)| addr)
}

// ---------------------------------------------------------------------------
// Merkle-root verification — defense-in-depth corruption check.
// Core already validates this at consensus level before returning the
// block, so a mismatch here means RPC-layer corruption (extremely rare
// but cheap to catch).
// ---------------------------------------------------------------------------

fn verify_block_merkle_root(
    pages: &[(usize, Vec<EsploraTxFull>)],
    merkle_root_claimed: &str,
) -> Result<()> {
    if merkle_root_claimed.is_empty() {
        return Err(anyhow!(
            "block header missing merkle_root — can't verify body integrity"
        ));
    }
    let mut nodes: Vec<TxMerkleNode> = Vec::with_capacity(
        pages.iter().map(|(_, p)| p.len()).sum(),
    );
    for (_, page) in pages {
        for tx in page {
            let txid = Txid::from_str(&tx.txid)
                .map_err(|e| anyhow!("txid parse '{}': {:?}", tx.txid, e))?;
            nodes.push(TxMerkleNode::from_byte_array(txid.to_byte_array()));
        }
    }
    if nodes.is_empty() {
        return Err(anyhow!("block has no transactions to hash"));
    }
    let computed = bitcoin::merkle_tree::calculate_root(nodes.into_iter())
        .ok_or_else(|| anyhow!("merkle root calculation produced None"))?;
    let claimed = TxMerkleNode::from_str(merkle_root_claimed)
        .map_err(|e| anyhow!("merkle_root parse '{}': {:?}", merkle_root_claimed, e))?;
    if computed != claimed {
        return Err(anyhow!(
            "merkle root mismatch: computed={} claimed={} — tx list does NOT belong to this block",
            computed, claimed
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Block fetch + reorg detection — all via core_rpc.
// ---------------------------------------------------------------------------

/// Fetch one block's data via Bitcoin Core's `getblock <hash> 3`. This
/// is a single RPC call returning the full block (header + every tx
/// with prevouts) — replaces what used to be a 122-GET Esplora dance.
///
/// Returns Ok(None) on transient RPC failures (caller stops backfill at
/// this height; next poll retries from the same height).
async fn fetch_one_block_data(
    client: &reqwest::Client,
    h: u32,
) -> Result<Option<BlockData>> {
    let block_hash = match crate::core_rpc::fetch_block_hash(client, h).await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = ?e, height = h, "core-rpc getblockhash failed");
            return Ok(None);
        }
    };

    match crate::core_rpc::fetch_block_all_txs(client, &block_hash).await {
        Ok((txs, merkle, _n_tx)) => Ok(Some(BlockData {
            block_hash,
            merkle_root_claimed: merkle,
            pages: vec![(0usize, txs)],
        })),
        Err(e) => {
            tracing::warn!(error = ?e, height = h, block_hash = %block_hash,
                "core-rpc getblock failed");
            Ok(None)
        }
    }
}

/// Walk back from indexed_height for up to REORG_HORIZON blocks,
/// re-fetching each height's current hash via Core RPC and comparing
/// against what we stored in `block_hashes`. Returns:
/// - `Ok(None)` — no divergence; chain agrees with our snapshot.
/// - `Ok(Some(h))` — first height where the canonical hash differs
///   from our stored hash. Caller should rebuild past that point.
/// - `Err(_)` — RPC call failed (transient); caller should retry.
async fn detect_reorg(
    client: &reqwest::Client,
    state: &Arc<RwLock<IndexerState>>,
) -> Result<Option<u32>> {
    // Snapshot the relevant fields under the read lock so we don't hold
    // it across await points.
    let (indexed_height, snapshots): (u32, Vec<(u32, String)>) = {
        let s = state.read();
        if s.indexed_height == 0 {
            return Ok(None); // nothing to compare against yet
        }
        let from = s.indexed_height.saturating_sub(REORG_HORIZON - 1);
        let mut pairs: Vec<(u32, String)> = (from..=s.indexed_height)
            .filter_map(|h| s.block_hashes.get(&h).map(|hash| (h, hash.clone())))
            .collect();
        // Walk old → new so the FIRST divergence is the deepest one.
        pairs.sort_by_key(|(h, _)| *h);
        (s.indexed_height, pairs)
    };

    if snapshots.is_empty() {
        return Ok(None);
    }

    for (h, stored_hash) in &snapshots {
        let on_chain_hash = match crate::core_rpc::fetch_block_hash(client, *h).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, height = h, "reorg probe: hash RPC failed, skipping");
                continue;
            }
        };
        if &on_chain_hash != stored_hash {
            tracing::warn!(
                height = h,
                stored = %stored_hash,
                on_chain = %on_chain_hash,
                indexed_height,
                "reorg probe: hash divergence"
            );
            return Ok(Some(*h));
        }
    }
    Ok(None)
}

/// Re-fetch the on-chain block hash at every height present in the
/// in-memory snapshot ring. Used during reorg recovery to decide which
/// snapshots are still on the canonical chain (and therefore safe to
/// restore from). Returns a partial map on transient RPC errors —
/// snapshot validation tolerates missing entries.
async fn fetch_canonical_hashes_for_snapshots(
    client: &reqwest::Client,
    state: &Arc<RwLock<IndexerState>>,
) -> Result<std::collections::HashMap<u32, String>> {
    let heights: Vec<u32> = {
        let s = state.read();
        s.snapshots.iter().map(|snap| snap.indexed_height).collect()
    };
    let mut out = std::collections::HashMap::new();
    for h in heights {
        if let Ok(hash) = crate::core_rpc::fetch_block_hash(client, h).await {
            out.insert(h, hash);
        }
    }
    Ok(out)
}

/// Verify that a snapshot's recorded block hashes still match the
/// canonical chain. Used at warm-restart (`main.rs::try_load_snapshot`)
/// to refuse a stale snapshot whose tail blocks were reorganized while
/// the indexer was down.
///
/// Returns `Ok(true)` if every checked hash matches, `Ok(false)` if a
/// divergence was found, `Err` for transient RPC failures (caller
/// treats the same as a divergence — refuse the snapshot).
pub async fn validate_snapshot_against_canonical(
    snap: &crate::indexer::StateSnapshot,
) -> Result<bool> {
    if snap.block_hashes.is_empty() {
        // Empty snapshots (height 0 / first run) are trivially canonical.
        return Ok(true);
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("luckyprotocol-indexer/", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Pick the K most recent heights from the snapshot — these are the
    // blocks most likely to have been reorganized while the indexer was
    // down. Blocks deeper than REORG_HORIZON ago are extremely unlikely
    // to reorg (deepest historic Bitcoin reorg is 10 blocks, 2013), but
    // we still spot-check the tail since a deep reorg-during-downtime
    // is the exact attack we're defending against.
    let mut heights: Vec<u32> = snap.block_hashes.keys().copied().collect();
    heights.sort_unstable();
    heights.reverse();
    let check_count = (REORG_HORIZON as usize).min(heights.len());
    for h in heights.into_iter().take(check_count) {
        let recorded = match snap.block_hashes.get(&h) {
            Some(s) => s.clone(),
            None => continue,
        };
        let canonical = match crate::core_rpc::fetch_block_hash(&client, h).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(height = h, error = %e,
                    "snapshot validate: failed to fetch canonical hash — refusing snapshot");
                return Ok(false);
            }
        };
        if !recorded.eq_ignore_ascii_case(&canonical) {
            tracing::warn!(
                height = h,
                snapshot_hash = %recorded,
                canonical_hash = %canonical,
                "snapshot validate: divergence detected — refusing snapshot, will cold-scan"
            );
            return Ok(false);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Backfill + steady-state poll loop.
// ---------------------------------------------------------------------------

async fn backfill_range(
    state: Arc<RwLock<IndexerState>>,
    client: &reqwest::Client,
    from_height: u32,
    to_height: u32,
) -> Result<()> {
    use futures::stream::{self, StreamExt};

    // CROSS-BLOCK PIPELINE: keep BLOCK_FETCH_CONCURRENCY blocks' fetches
    // in flight at once. `stream::buffered` (NOT `buffer_unordered`)
    // preserves the ORIGINAL order, so the apply loop sees blocks in
    // chain order even though their RPC I/O completed in arbitrary
    // order. Decouples I/O + JSON parsing from sequential state
    // mutation; apply (state.write) MUST stay sequential — a SEND that
    // depends on a prior SEND's debit must see the updated balance.
    let client_arc = client.clone();
    let fetch_stream = stream::iter(from_height..=to_height)
        .map(move |h| {
            let client = client_arc.clone();
            async move { (h, fetch_one_block_data(&client, h).await) }
        })
        .buffered(BLOCK_FETCH_CONCURRENCY);

    tokio::pin!(fetch_stream);
    while let Some((h, fetch_result)) = fetch_stream.next().await {
        let block_data = match fetch_result {
            Ok(Some(data)) => data,
            Ok(None) => {
                // Sub-fetch failed (already logged). Stop backfill —
                // do NOT advance indexed_height. Next poll retries.
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(error = ?e, height = h, "block fetch errored — stopping backfill");
                return Ok(());
            }
        };
        let BlockData {
            block_hash,
            merkle_root_claimed,
            pages,
        } = block_data;

        // === MERKLE ROOT VERIFICATION (defense-in-depth) ===
        // Core consensus-validates this before returning the block, so
        // a mismatch here means RPC serialization corruption — abort
        // backfill, do NOT advance indexed_height. The same height
        // is re-attempted next poll.
        if !pages.is_empty() {
            if let Err(e) = verify_block_merkle_root(&pages, &merkle_root_claimed) {
                tracing::error!(
                    height = h,
                    block_hash = %block_hash,
                    error = %e,
                    "MERKLE ROOT VERIFICATION FAILED — refusing to ingest block (Core RPC corruption?)"
                );
                state.write().push_error(crate::indexer::ErrorEvent {
                    at: crate::indexer::now_unix(),
                    kind: crate::indexer::ErrorKind::Merkle,
                    host: None,
                    height: Some(h),
                    detail: format!(
                        "block {} merkle root verification failed — Core RPC returned tx list \
                         that does not hash to the header's claimed root; block refused",
                        h
                    ),
                });
                return Ok(());
            }
        }

        // === SEQUENTIAL APPLY in chain order ===
        // Single-block settlement migration hook (no-op for steady state).
        {
            let mut s = state.write();
            s.advance_settlement(h, &block_hash);
        }

        // Walk EVERY tx in chain order (non-LUCKYPROTOCOL txs that
        // happen to spend a token-bearing UTXO still need processing
        // so the input pool routes per PROTOCOL.md §7.4).
        let mut applied_count = 0usize;
        for (_, page) in &pages {
            for tx in page {
                let payload_opt = extract_luckyprotocol_payload_from_json(tx);
                let sender = resolve_sender_from_json(tx).unwrap_or_default();

                // Build spent outpoints from vin. Coinbase has empty
                // txid (no real previous output) — skip those entries.
                let spent: Vec<(String, u32)> = tx
                    .vin
                    .iter()
                    .filter_map(|v| {
                        if v.txid.is_empty() {
                            None
                        } else {
                            Some((v.txid.clone(), v.vout))
                        }
                    })
                    .collect();

                // Identify OP_RETURN vouts so apply can refuse to
                // assign tokens to provably-unspendable outputs
                // (PROTOCOL.md §7.5).
                let op_return_vouts: Vec<u32> = tx
                    .vout
                    .iter()
                    .enumerate()
                    .filter_map(|(i, vo)| {
                        if vo.scriptpubkey_type == "op_return" {
                            Some(i as u32)
                        } else {
                            None
                        }
                    })
                    .collect();

                // Address per vout (for reverse-index tracking on
                // utxo_balances). None for unparseable / OP_RETURN
                // scripts; apply handles None gracefully.
                let vout_addresses: Vec<Option<String>> = tx
                    .vout
                    .iter()
                    .map(|vo| vo.scriptpubkey_address.clone())
                    .collect();

                // Sats per vout — apply_tx needs this for the
                // three-fee consensus checks (PROTOCOL.md §5/§3.2).
                let vout_values: Vec<u64> = tx
                    .vout
                    .iter()
                    .map(|vo| vo.value)
                    .collect();

                let ctx = crate::indexer::TxContext {
                    txid: &tx.txid,
                    block_height: h,
                    block_hash: &block_hash,
                    sender: &sender,
                    spent_outpoints: &spent,
                    vout_count: tx.vout.len() as u32,
                    op_return_vouts: &op_return_vouts,
                    vout_addresses: &vout_addresses,
                    vout_values: &vout_values,
                };

                let mut s = state.write();
                if s.apply_tx(ctx, payload_opt) {
                    applied_count += 1;
                }
            }
        }

        {
            let mut s = state.write();
            s.indexed_height = h;
            s.touch_progress();
            s.block_hashes.insert(h, block_hash.clone());
            // Bound memory: keep only the last 200 entries (well past
            // REORG_HORIZON). HashMap::retain is linear in size and we
            // never grow past 200.
            if h > 200 {
                s.prune_block_hashes(h - 200);
            }
            // Periodic full-state snapshot for reorg recovery + warm
            // restart. SNAPSHOT_INTERVAL_BLOCKS-spaced.
            if h % crate::indexer::SNAPSHOT_INTERVAL_BLOCKS == 0 {
                let snap = s.take_snapshot();
                if let Some(path) = SNAPSHOT_PATH.get() {
                    let path = path.clone();
                    tokio::spawn(async move {
                        if let Err(e) = persist_snapshot_to_disk(&path, &snap).await {
                            tracing::warn!(error = ?e, "snapshot persist failed");
                        }
                    });
                }
            }
        }

        if applied_count > 0 {
            tracing::info!(height = h, hash = %block_hash, applied_count, "indexed LUCKYPROTOCOL tx");
        }
    }
    Ok(())
}

/// Single poll-loop iteration extracted so the outer loop can wrap it
/// in `tokio::time::timeout` cleanly. Returns:
/// - `Some(next_cadence)` on normal completion — caller updates the
///   poll interval.
/// - `None` on a `continue`-like early exit (transient skip — tip
///   regression, reorg-storm cooldown, reorg-probe failure, etc.);
///   caller keeps the current cadence.
///
/// Cancel-safe: every `state.write()` block is sync (parking_lot,
/// no awaits inside the guard) so cancelling the outer future never
/// strands a half-mutated state.
async fn run_one_poll_iteration(
    state: &Arc<RwLock<IndexerState>>,
    client: &reqwest::Client,
    recent_reorgs: &mut std::collections::VecDeque<std::time::Instant>,
    normal_poll_secs: u64,
    fast_poll_secs: u64,
) -> Option<u64> {
    let cur_tip = match crate::core_rpc::fetch_tip_height(client).await {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("{:?}", e);
            tracing::warn!(error = %crate::indexer::mask_secrets(&msg), "core-rpc tip poll failed; will retry");
            state.write().push_error(crate::indexer::ErrorEvent {
                at: crate::indexer::now_unix(),
                kind: crate::indexer::ErrorKind::Network,
                host: None,
                height: None,
                detail: format!("tip poll failed (Bitcoin Core unreachable?): {}",
                    crate::indexer::mask_secrets(&msg)).chars().take(220).collect(),
            });
            return None;
        }
    };

    // TIP REGRESSION GUARD — Core could briefly report a tip below
    // our indexed height if (a) we're talking to a node that just
    // got reorg'd backwards, or (b) someone restarted the node from
    // a pruned/lower state. We MUST NOT treat that as authoritative
    // — neither rewind state nor truncate indexed_height. Just skip
    // this poll tick; the next one will see the real tip.
    let indexed_height = state.read().indexed_height;
    if cur_tip < indexed_height {
        tracing::warn!(
            cur_tip,
            indexed_height,
            "tip regression detected — Core returned tip below our indexed height; skipping"
        );
        state.write().push_error(crate::indexer::ErrorEvent {
            at: crate::indexer::now_unix(),
            kind: crate::indexer::ErrorKind::TipRegress,
            host: None,
            height: Some(cur_tip),
            detail: format!(
                "Core returned tip={} below our indexed_height={}; skipping (no rewind)",
                cur_tip, indexed_height
            ),
        });
        return None;
    }

    // REORG DETECTION — re-fetch hashes for the last REORG_HORIZON
    // blocks and compare against our snapshot.
    match detect_reorg(client, state).await {
        Ok(None) => { /* clean — no reorg, proceed normally */ }
        Ok(Some(divergence_height)) => {
            let indexed_height = state.read().indexed_height;
            tracing::warn!(
                divergence_height,
                indexed_height,
                "REORG DETECTED — attempting snapshot-based recovery"
            );

            // ---- REORG-STORM CIRCUIT BREAKER ----
            let now = std::time::Instant::now();
            while let Some(&t) = recent_reorgs.front() {
                if now.duration_since(t) > REORG_STORM_WINDOW {
                    recent_reorgs.pop_front();
                } else {
                    break;
                }
            }
            recent_reorgs.push_back(now);
            if recent_reorgs.len() > REORG_STORM_THRESHOLD {
                tracing::error!(
                    recent_reorg_count = recent_reorgs.len(),
                    cooldown_secs = REORG_STORM_COOLDOWN.as_secs(),
                    "REORG STORM — too many reorgs in window; pausing poll loop"
                );
                state.write().push_error(crate::indexer::ErrorEvent {
                    at: crate::indexer::now_unix(),
                    kind: crate::indexer::ErrorKind::ReorgStorm,
                    host: None,
                    height: Some(divergence_height),
                    detail: format!(
                        "reorg-storm circuit breaker tripped ({} reorgs in window); cooling down {}s",
                        recent_reorgs.len(),
                        REORG_STORM_COOLDOWN.as_secs()
                    ),
                });
                recent_reorgs.clear();
                tokio::time::sleep(REORG_STORM_COOLDOWN).await;
                return None;
            }

            // SMART RECOVERY: restore from the most recent in-memory
            // snapshot whose height < divergence AND whose recorded
            // hash for that height still matches the chain. Falls
            // back to wholesale rewind only if no usable snapshot
            // exists.
            let cutoff = divergence_height.saturating_sub(1);
            let canonical_hashes = match fetch_canonical_hashes_for_snapshots(
                client, state,
            ).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(error = ?e, "could not fetch canonical hashes for snapshot validation");
                    std::collections::HashMap::new()
                }
            };
            let rebuild_from = {
                let mut s = state.write();
                match s.restore_to_snapshot_at_or_before(cutoff, &canonical_hashes) {
                    Some(restored_h) => {
                        tracing::info!(
                            restored_h,
                            "reorg: restored from snapshot — re-scanning forward only"
                        );
                        restored_h + 1
                    }
                    None => {
                        tracing::warn!(
                            divergence_height,
                            "reorg: no usable snapshot in lookback; falling back to full rewind"
                        );
                        s.wipe_for_reorg();
                        crate::protocol::LCKPROTOCOL_START_HEIGHT
                    }
                }
            };
            let rebuild_from = rebuild_from.min(cur_tip);
            if let Err(e) = backfill_range(
                state.clone(),
                client,
                rebuild_from,
                cur_tip,
            ).await {
                tracing::error!(error = ?e, "post-reorg rebuild failed; will retry next poll");
            }
            state.write().tip_height = cur_tip;
            return None;
        }
        Err(e) => {
            let msg = format!("{:?}", e);
            tracing::warn!(error = %crate::indexer::mask_secrets(&msg), "reorg-detection probe failed; skipping this tick");
            state.write().push_error(crate::indexer::ErrorEvent {
                at: crate::indexer::now_unix(),
                kind: crate::indexer::ErrorKind::Network,
                host: None,
                height: None,
                detail: format!("reorg-detection probe failed: {}",
                    crate::indexer::mask_secrets(&msg)).chars().take(220).collect(),
            });
            return None;
        }
    }

    let last = {
        let s = state.read();
        s.indexed_height
    };
    if cur_tip > last {
        tracing::info!(from = last + 1, to = cur_tip, "indexing new blocks");
        if let Err(e) = backfill_range(
            state.clone(),
            client,
            last + 1,
            cur_tip,
        )
        .await
        {
            let msg = format!("{:?}", e);
            tracing::warn!(error = %crate::indexer::mask_secrets(&msg), "indexing failed; will retry next poll");
            state.write().push_error(crate::indexer::ErrorEvent {
                at: crate::indexer::now_unix(),
                kind: crate::indexer::ErrorKind::Network,
                host: None,
                height: Some(last + 1),
                detail: format!("backfill failed at height {}: {}",
                    last + 1,
                    crate::indexer::mask_secrets(&msg)).chars().take(220).collect(),
            });
        }
        state.write().tip_height = cur_tip;
        // Persist a snapshot after every poll cycle that ingested
        // new blocks — bounds the warm-restart "lost work" window
        // to exactly ONE poll cycle.
        persist_current_snapshot(state).await;
    }

    // Adaptive cadence: stay fast if backfill couldn't catch up
    // (indexed < tip), else back to normal.
    let post_indexed_height = state.read().indexed_height;
    let next_cadence = if post_indexed_height < cur_tip {
        fast_poll_secs
    } else {
        normal_poll_secs
    };
    Some(next_cadence)
}

/// Steady-state poll loop. `poll_notify` is the external wake signal —
/// the HTTP server's `POST /poll-now` handler calls `notify_one()` on
/// this so a front-end that's already aware of a new tip can kick the
/// indexer awake without waiting for the next natural poll cycle.
pub async fn run_poller(
    state: Arc<RwLock<IndexerState>>,
    start_height: Option<u32>,
    poll_secs: u64,
    poll_notify: Arc<tokio::sync::Notify>,
) -> Result<()> {
    // Local reqwest client used to talk to Core's JSON-RPC endpoint.
    // Tuned for low-latency localhost: tcp_nodelay (Nagle off — we send
    // tiny JSON requests), pool_idle_timeout 180s (keep TCP+TLS warm
    // between polls), http2 keepalive (PINGs prevent intermediaries
    // from dropping the connection mid-window).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("luckyprotocol-indexer/", env!("CARGO_PKG_VERSION")))
        .tcp_nodelay(true)
        .pool_idle_timeout(Duration::from_secs(180))
        .http2_adaptive_window(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_while_idle(true)
        .build()?;

    // Initial tip lookup — retry indefinitely with backoff. A single
    // transient RPC error at boot must NOT kill the poller; e.g.,
    // Bitcoin Core might still be loading the block index when we
    // start (mempool warmup takes 10-30s on a Storage VPS class node).
    // Exponential backoff from 1s capped at 30s.
    let tip;
    {
        let mut delay_ms: u64 = 1_000;
        loop {
            match crate::core_rpc::fetch_tip_height(&client).await {
                Ok(t) => { tip = t; break; }
                Err(e) => {
                    tracing::warn!(error = ?e, delay_ms,
                        "initial tip fetch failed — retrying (is Bitcoin Core up + RPC reachable?)");
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms.saturating_mul(2)).min(30_000);
                }
            }
        }
    }
    {
        let mut s = state.write();
        s.tip_height = tip;
    }

    // Default to FULL coverage from the protocol activation height.
    // The user can override with `--start-height` to scan from a
    // higher (= shallower) block — useful for testing — but never
    // BELOW the activation height (pre-activation blocks are not
    // protocol-relevant).
    let backfill_from = start_height
        .unwrap_or(crate::protocol::LCKPROTOCOL_START_HEIGHT);
    let backfill_from = backfill_from.max(crate::protocol::LCKPROTOCOL_START_HEIGHT);
    let backfill_from = backfill_from.min(tip);

    tracing::info!(tip, backfill_from, "starting backfill");
    backfill_range(
        state.clone(),
        &client,
        backfill_from,
        tip,
    )
    .await?;
    // PROTOCOL.md §12 (warm-restart hygiene) — write a snapshot at
    // backfill end regardless of SNAPSHOT_INTERVAL_BLOCKS alignment,
    // so a relaunch doesn't redo the un-aligned tail blocks.
    persist_current_snapshot(&state).await;
    tracing::info!(tip, "backfill complete; entering poll loop");

    // Steady-state poll loop.
    let mut recent_reorgs: std::collections::VecDeque<std::time::Instant> =
        std::collections::VecDeque::new();

    // Adaptive poll cadence:
    // * `normal_poll_secs` (caller-provided, default 10s) once caught
    //   up. Bitcoin's 10-min block time means polling more often is
    //   wasted, but 30s was visibly laggy in the UI.
    // * `fast_poll_secs` (5s) when behind — usually after a network
    //   blip during backfill, or right after warm-restart while
    //   catching up from the snapshot height to current tip. Auto-
    //   reverts to normal as soon as indexed_height == tip_height.
    let normal_poll_secs: u64 = poll_secs;
    let fast_poll_secs: u64 = 5;
    let mut current_poll_secs = normal_poll_secs;

    loop {
        // Wait until EITHER the sleep elapses OR an external wake fires.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(current_poll_secs)) => {}
            _ = poll_notify.notified() => {
                tracing::debug!("poll loop woken by external /poll-now");
            }
        }

        // === WATCHDOG-WRAPPED ITERATION ===
        // The body runs inside `tokio::time::timeout(POLL_ITER_WATCHDOG, ...)`
        // so any wedged RPC call (TLS handshake hang on a remote node,
        // local Core deadlock) gets force-cancelled rather than freezing
        // the entire poll loop. Normal exit returns Some(new_cadence);
        // outer timeout falls through to fast cadence and a NETWORK event.
        let state_inner = state.clone();
        let client_inner = client.clone();
        let iter_outcome = tokio::time::timeout(POLL_ITER_WATCHDOG, async {
            run_one_poll_iteration(
                &state_inner, &client_inner,
                &mut recent_reorgs, normal_poll_secs, fast_poll_secs,
            ).await
        }).await;

        match iter_outcome {
            Ok(Some(next_cadence)) => {
                if next_cadence != current_poll_secs {
                    tracing::info!(
                        from_secs = current_poll_secs, to_secs = next_cadence,
                        "poll cadence adjusted"
                    );
                }
                current_poll_secs = next_cadence;
            }
            Ok(None) => {
                // Iteration `continue`d — keep whatever cadence we had.
            }
            Err(_elapsed) => {
                tracing::error!(
                    budget_secs = POLL_ITER_WATCHDOG.as_secs(),
                    "poll iteration exceeded watchdog budget — cancelled, will retry at fast cadence"
                );
                state.write().push_error(crate::indexer::ErrorEvent {
                    at: crate::indexer::now_unix(),
                    kind: crate::indexer::ErrorKind::Network,
                    host: None,
                    height: None,
                    detail: format!(
                        "poll iteration wedged past {}s watchdog (likely Bitcoin Core RPC hang); \
                         cancelled and resuming.",
                        POLL_ITER_WATCHDOG.as_secs()
                    ),
                });
                current_poll_secs = fast_poll_secs;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot persistence.
// ---------------------------------------------------------------------------

/// Snapshot the live IndexerState and write it to the configured disk
/// path. Used at backfill-complete and after every poll-cycle that
/// advanced indexed_height — so the on-disk snapshot tracks the live
/// state within ~one poll cycle.
/// No-op when SNAPSHOT_PATH isn't configured (purely-in-memory mode).
async fn persist_current_snapshot(state: &Arc<RwLock<IndexerState>>) {
    let path = match SNAPSHOT_PATH.get() {
        Some(p) => p.clone(),
        None => return,
    };
    let snap = {
        let mut s = state.write();
        s.take_snapshot()
    };
    if let Err(e) = persist_snapshot_to_disk(&path, &snap).await {
        tracing::warn!(error = ?e, "persist_current_snapshot: write failed");
    }
}

/// One-shot serializer that writes the latest StateSnapshot to disk as
/// JSON. Tolerates a missing parent directory (creates it) and uses
/// tmp+rename to avoid partial writes on crash.
async fn persist_snapshot_to_disk(
    path: &std::path::Path,
    snap: &crate::indexer::StateSnapshot,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(snap)?;
    tokio::fs::write(&tmp, &bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}
