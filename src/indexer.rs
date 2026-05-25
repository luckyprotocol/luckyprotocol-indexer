// In-memory derived state — UTXO-bound (LUCKYPROTOCOL v1 protocol).
// Token balances are stored per-UTXO (`utxo_balances`), not per-address.
// Token authority is enforced at Bitcoin's UTXO consensus layer: only the
// holder of a UTXO's spending key can move its tokens (via SEND or by
// spending into a default-output routing). See PROTOCOL.md.
// Updated by source.rs as it parses blocks. Read by server.rs for HTTP API.
// Concurrency: wrapped in `parking_lot::RwLock` at the call site (main.rs).
// Snapshot model:
// - Every SNAPSHOT_INTERVAL_BLOCKS, the entire derived state is cloned
// into a rolling deque of the last SNAPSHOT_RING_SIZE snapshots.
// - The newest snapshot is also serialized to disk so restarts can
// resume from the latest cold-bootable point.
// - On reorg detection, source.rs walks the deque to find the most
// recent snapshot whose recorded block-hash for its height still
// matches Esplora; that snapshot is restored and the indexer
// re-scans forward from there.

use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::protocol::{is_hit, tier_reward, ProtocolPayload};

/// How often (in blocks) we take a full state snapshot.
pub const SNAPSHOT_INTERVAL_BLOCKS: u32 = 12;

/// How many snapshots to keep in memory. 8 × 12 = 96-block lookback.
pub const SNAPSHOT_RING_SIZE: usize = 8;

/// FIFO eviction caps for the audit-log vecs — bound DoS surface for
/// spam-rejected entries (e.g. BET on undeployed ticker, SEND with
/// insufficient pool).
pub const MAX_BETS_VEC: usize = 100_000;
pub const MAX_TRANSFERS_VEC: usize = 100_000;
pub const MAX_DEPLOYS_VEC: usize = 10_000;

/// Max diagnostic events retained in `IndexerState::recent_errors` for
/// UI surfacing. The buffer fills FIFO; older events drop off the
/// front. 16 is enough to show a multi-failure cluster without
/// unbounded memory growth (each event is ~150 bytes).
pub const MAX_RECENT_ERRORS: usize = 16;

/// Stall threshold (seconds) the SERVER side uses when computing the
/// `stalled` flag returned by `/`. Frontend may apply its own (usually
/// looser) threshold on top of this — that's fine, the field is purely
/// advisory. Default tuned for a 10s poll cadence: 120s ≈ 12 missed
/// polls, well past the noise of one or two transient failures.
pub const STALL_THRESHOLD_SECS: u64 = 120;

/// Classification of a diagnostic event for UI surfacing. Distinct
/// from log severity — these are events the UI ENUMERATES (ring
/// buffer) and AGGREGATES (count by kind in last N minutes). The
/// enum is intentionally narrow: each variant maps to a single
/// recoverable failure mode with its own UX hint.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ErrorKind {
 /// MERKLE ROOT VERIFICATION FAILED — the tx list returned by an
 /// Esplora host doesn't hash to the merkle root claimed in the
 /// block header. Upstream is misbehaving / returning a corrupted
 /// page; indexer refused to ingest. Rotates to next fallback host.
    Merkle,
 /// Network-level fetch failure — TLS handshake EOF, connection
 /// reset, timeout. Usually transient or ISP-level interference.
    Network,
 /// 429 Too Many Requests from upstream. Alchemy free-tier quota
 /// exhausted, or per-IP rate limit on a public mirror.
    RateLimit,
 /// Esplora returned a tip-height LOWER than our indexed height.
 /// CDN edge serving stale view, host failover mid-block, etc.
 /// Indexer skips this poll tick — does NOT rewind state.
    TipRegress,
 /// Reorg-storm circuit breaker tripped — too many reorg
 /// detections in the rolling window. Indexer paused for cooldown.
    ReorgStorm,
}

/// One diagnostic event in the ring buffer. Each one renders as a row
/// in the SETTINGS → INDEXER DIAGNOSTICS panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEvent {
 /// Unix epoch seconds. Frontend renders relative ("3 min ago").
    pub at: u64,
    pub kind: ErrorKind,
 /// Upstream host that produced this error (mempool.space /
 /// blockstream.info / alchemy.com / etc.) — populated where the
 /// failure was tied to a specific host. None for kinds that don't
 /// have an upstream (e.g. ReorgStorm).
 #[serde(default)]
    pub host: Option<String>,
 /// Block height the error concerns, if applicable. Merkle errors
 /// are per-block; most others aren't.
 #[serde(default)]
    pub height: Option<u32>,
 /// One-line human-readable detail. MUST NOT contain secrets — any
 /// URL with an API key (e.g. Alchemy) MUST be run through
 /// `mask_secrets` BEFORE push_error.
    pub detail: String,
}

/// Wall-clock unix epoch seconds. Centralized so every diagnostic-
/// recording site agrees on the same time source. Returns 0 if the
/// system clock is somehow before UNIX_EPOCH (effectively impossible
/// but we don't want to panic on a runtime fluke).
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Strip the Alchemy API key from a URL so it's safe to log or to
/// surface in `recent_errors` (which travels to the frontend in
/// plain JSON over the loopback HTTP socket). Alchemy URLs follow
/// `https://bitcoin-mainnet.g.alchemy.com/v2/<KEY>/...`; we replace
/// `<KEY>` with the literal `<KEY-REDACTED>`. Idempotent — URLs
/// already redacted pass through unchanged. URLs without an alchemy
/// segment are returned as-is.
pub fn mask_secrets(url: &str) -> String {
    const NEEDLE: &str = "alchemy.com/v2/";
    if let Some(i) = url.find(NEEDLE) {
        let start = i + NEEDLE.len();
        let rest = &url[start..];
        let key_end = rest.find('/').unwrap_or(rest.len());
 // Already redacted? Don't double-wrap.
        if &rest[..key_end] == "<KEY-REDACTED>" {
            return url.to_string();
        }
        let mut out = String::with_capacity(url.len());
        out.push_str(&url[..start]);
        out.push_str("<KEY-REDACTED>");
        out.push_str(&rest[key_end..]);
        return out;
    }
    url.to_string()
}

/// Vestigial constant — single-block settlement makes "expiry" obsolete.
/// Kept for snapshot-load compatibility only.
#[allow(dead_code)]
pub const BET_EXPIRY_BLOCKS: u32 = 1008;

/// Format a Bitcoin outpoint as the `"txid:vout"` string used as the key
/// of `utxo_balances`. Centralized so every callsite agrees on the
/// canonical form (lowercase txid, decimal vout, no leading zeros).
pub fn outpoint_key(txid: &str, vout: u32) -> String {
    format!("{}:{}", txid.to_lowercase(), vout)
}

/// Per-UTXO token balances. Inner map: ticker → smallest-units. A UTXO
/// not present in `utxo_balances` carries zero protocol tokens.
pub type RuneBalance = HashMap<String, u64>;

/// One UTXO's full record in `utxo_balances`. Beyond the per-ticker
/// amounts, we store the spending address so the server can answer
/// `/balances/:address` from the in-memory state without an extra
/// Esplora round-trip.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UtxoEntry {
 /// Address that controls this UTXO (None for unparseable / non-
 /// standard scripts). Populated from `EsploraVout.scriptpubkey_address`
 /// at apply time.
 #[serde(default)]
    pub address: Option<String>,
 /// Per-ticker balance carried by this UTXO.
    pub balances: RuneBalance,
}

/// Lifecycle of a LUCKYPROTOCOL BET inside the indexer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BetStatus {
 /// Bet tx confirmed at block N; outcome decided immediately from
 /// `hash_N`'s last K hex chars.
    Settled,
 /// BET pointed at an undeployed ticker, OR `win_out_idx` referenced
 /// an OP_RETURN / out-of-range vout — protocol-rejected at apply
 /// time. No UTXO balance change. Recorded for audit visibility.
    Invalid,
 /// Reserved for backward-compat with snapshots written by earlier
 /// versions. Loaded entries with this status are re-settled on
 /// restore. Never produced by the current code path.
 #[serde(rename = "pending")]
    LegacyPending,
 /// Same compat reservation for the old V2 (intermediate) "Expired" terminal state.
 #[serde(rename = "expired")]
    LegacyExpired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BetView {
    pub txid: String,
    pub block_height: u32,
    pub block_hash: String,
    pub sender: String,
    pub tier: String,
    pub pick: String,
    pub ticker: String,
 /// vout index that received the won tokens. Always recorded
 /// even on Invalid bets so consumers can tell which output the
 /// bettor INTENDED as the carrier.
    pub win_out_idx: u32,
 /// vout index that should receive any residual input-pool tokens
 /// when this MINE tx happens to spend a token-bearing UTXO.
 ///
 /// `None` for legacy 5-field MINEs broadcast before protocol v2
 /// activation — those follow the strict-burn rule and any
 /// residual is destroyed.
 ///
 /// `Some(idx)` for v2 6-field MINEs. If `idx` is a valid non-
 /// OP_RETURN vout of this tx, residual routes there; otherwise
 /// the indexer treats it as missing (residual still burns).
 #[serde(default)]
    pub change_out_idx: Option<u32>,
    pub status: BetStatus,
 /// Vestigial fields kept for snapshot-schema compatibility with
 /// the legacy BTCASINO codebase. Always `None` for LUCKYPROTOCOL.
    pub reveal_block_height: Option<u32>,
    pub reveal_block_hash: Option<String>,
 /// None on Invalid; Some(true|false) on Settled.
    pub win: Option<bool>,
 /// 0 unless Settled+win+reward; this is the actual credited amount
 /// (after supply-cap clamp).
    pub reward_smallest: u64,
 /// Predicate hit but supply was already exhausted. `win=false`,
 /// `reward=0`, but UI can render explanatory subtitle.
 #[serde(default)]
    pub cap_exhausted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferView {
    pub txid: String,
    pub block_height: u32,
    pub block_hash: String,
    pub sender: String,
    pub ticker: String,
    pub amount: u64,
 /// Recipient vout index per the SEND payload.
    pub to_out_idx: u32,
 /// Explicit change vout index, or None if the default rule ()
 /// applies.
    pub change_out_idx: Option<u32>,
 /// True iff `input_pool[ticker] >= amount` at apply time. False
 /// means the SEND failed and tokens flowed to default routing.
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployView {
    pub txid: String,
    pub block_height: u32,
    pub block_hash: String,
    pub deployer: String,
    pub ticker: String,
    pub supply: u64,
 /// false if the ticker had already been deployed in an earlier block
 /// (first-write-wins) and this DEPLOY was therefore ignored.
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRegistryEntry {
    pub ticker: String,
    pub supply: u64, // declared cap from the DEPLOY
    pub minted: u64, // sum of credited BET wins for this ticker
    pub deployer: String,
    pub deploy_txid: String,
    pub deploy_block: u32,
}

/// Genesis cohort for LUCKYPROTOCOL v1 (UTXO-bound). Older snapshots
/// (any SNAPSHOT_VERSION < current) are refused at load time and
/// the indexer cold-scans from LCKPROTOCOL_V1_HEIGHT (950,950).
/// History:
///  7 — LUCKYPROTOCOL v1 pre-genesis (activation 949,090). Withdrawn
///      after the 949,366 LUCKY burn incident.
///  8 — LUCKYPROTOCOL v1 short-lived rebuild (activation 949,375).
///      Withdrawn during LuckyProtocol rebrand.
///  9 — LUCKYPROTOCOL v1 genesis (activation 949,375, wire prefix
///      "LUCKYPROTOCOL"). Withdrawn during fee-model unification.
/// 10 — **CURRENT.** Cohort v950950. Three-fee consensus model:
///      DEPLOY == 5,460, MINE == 546, SEND == 546 (all EXACT, to
///      PROJECT_FEE_ADDRESS). Activation height moves to 950,950.
///      Closes the latent Rust(949,375)/JS(950,382) divergence.
pub const SNAPSHOT_VERSION: u32 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
 #[serde(default)]
    pub version: u32,
    pub indexed_height: u32,
 /// UTXO-bound balances. Key: `outpoint_key(txid, vout)` = "txid:vout".
 /// Value: `UtxoEntry { address, balances }`. (Cannot use a struct key
 /// because JSON object keys must be strings.)
    pub utxo_balances: HashMap<String, UtxoEntry>,
 /// Reverse index: address → set of outpoint_keys it controls. Lets
 /// `/balances/:address` answer in O(|address's UTXOs|) without
 /// scanning the entire utxo_balances map. Maintained in lockstep
 /// with utxo_balances on every apply_tx.
 #[serde(default)]
    pub address_utxos: HashMap<String, HashSet<String>>,
    pub bets: VecDeque<BetView>,
    pub transfers: VecDeque<TransferView>,
    pub deploys: VecDeque<DeployView>,
    pub by_txid: HashMap<String, EntryRef>,
    pub tokens: HashMap<String, TokenRegistryEntry>,
    pub block_hashes: HashMap<u32, String>,
 #[serde(default)]
    pub bet_offset: u64,
 #[serde(default)]
    pub transfer_offset: u64,
 #[serde(default)]
    pub deploy_offset: u64,
}

pub struct IndexerState {
    pub network: Network,
    pub esplora_base: String,
    pub indexed_height: u32,
    pub tip_height: u32,
 /// UTXO-bound balances — see StateSnapshot.utxo_balances.
    pub utxo_balances: HashMap<String, UtxoEntry>,
 /// Reverse index: address → outpoint_keys. See StateSnapshot.address_utxos.
    pub address_utxos: HashMap<String, HashSet<String>>,
    pub bets: VecDeque<BetView>,
    pub transfers: VecDeque<TransferView>,
    pub deploys: VecDeque<DeployView>,
    pub bet_offset: u64,
    pub transfer_offset: u64,
    pub deploy_offset: u64,
    pub by_txid: HashMap<String, EntryRef>,
    pub tokens: HashMap<String, TokenRegistryEntry>,
    pub block_hashes: HashMap<u32, String>,
    pub snapshots: VecDeque<StateSnapshot>,
 /// Unix epoch seconds when `indexed_height` last advanced. Initialized
 /// to the indexer's start timestamp; updated by `touch_progress()`
 /// whenever a backfill or poll step extends the indexed height.
 /// Together with `now`, this lets the `/` endpoint compute a
 /// `stalled` flag the UI uses to distinguish "still working" from
 /// "wedged". Runtime-only; never serialized into a snapshot.
    pub last_progress_at: u64,
 /// Ring buffer of recent diagnostic events for UI surfacing.
 /// Push at the back via `push_error(...)`; oldest evicts when len
 /// reaches `MAX_RECENT_ERRORS`. Runtime-only; not snapshotted —
 /// errors are per-process state and a warm-restart should start
 /// with a clean buffer.
    pub recent_errors: VecDeque<ErrorEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum EntryRef {
    Bet { idx: u64 },
    Transfer { idx: u64 },
    Deploy { idx: u64 },
}

/// Per-tx context fed to `apply_tx`. Bundled so the apply loop can stay
/// within a single state.write() guard without juggling a half-dozen
/// arguments.
pub struct TxContext<'a> {
    pub txid: &'a str,
    pub block_height: u32,
    pub block_hash: &'a str,
 /// Audit-only: address that contributed the most input value.
 /// NOT used for authorization (UTXO consensus already authorizes
 /// the spend). Recorded in audit logs.
    pub sender: &'a str,
 /// Outpoints spent by this tx (vin × prevout). For each, if it's
 /// in `utxo_balances`, its tokens flow into the input pool.
    pub spent_outpoints: &'a [(String, u32)],
 /// Total number of vouts on this tx.
    pub vout_count: u32,
 /// vout indices that are OP_RETURN outputs (cannot receive tokens).
    pub op_return_vouts: &'a [u32],
 /// Address controlling each vout, indexed by vout_idx. None for
 /// vouts whose script can't be parsed to an address (e.g. raw
 /// scripts, non-standard outputs). Used to maintain the
 /// address_utxos reverse index alongside utxo_balances.
    pub vout_addresses: &'a [Option<String>],
 /// Sats paid by each vout, indexed by vout_idx. Used by the
 /// DEPLOY protocol-fee consensus check (PROTOCOL.md §5.1.2): a
 /// DEPLOY tx must include at least one output paying
 /// `>= DEPLOY_PROTOCOL_FEE_SATS` to `PROJECT_FEE_ADDRESS`.
    pub vout_values: &'a [u64],
}

impl IndexerState {
    pub fn new(network: Network, esplora_base: String) -> Self {
        Self {
            network,
            esplora_base,
            indexed_height: 0,
            tip_height: 0,
            utxo_balances: HashMap::new(),
            address_utxos: HashMap::new(),
            bets: VecDeque::new(),
            transfers: VecDeque::new(),
            deploys: VecDeque::new(),
            bet_offset: 0,
            transfer_offset: 0,
            deploy_offset: 0,
            by_txid: HashMap::new(),
            tokens: HashMap::new(),
            block_hashes: HashMap::new(),
            snapshots: VecDeque::with_capacity(SNAPSHOT_RING_SIZE),
            last_progress_at: now_unix(),
            recent_errors: VecDeque::with_capacity(MAX_RECENT_ERRORS),
        }
    }

 /// Mark a successful forward step — called by source.rs immediately
 /// after `indexed_height` advances (per block in backfill, per poll
 /// step). Updates the progress timestamp the UI's stall detector
 /// reads via `/`. Cheap (one syscall + integer store).
    pub fn touch_progress(&mut self) {
        self.last_progress_at = now_unix();
    }

 /// Append a diagnostic event to the ring buffer for UI surfacing.
 /// FIFO-evicts the oldest entry once `MAX_RECENT_ERRORS` is reached.
 /// `ev.detail` MUST be free of API keys — callers handling URLs
 /// (especially Alchemy) MUST pass them through `mask_secrets` first.
    pub fn push_error(&mut self, ev: ErrorEvent) {
        if self.recent_errors.len() >= MAX_RECENT_ERRORS {
            self.recent_errors.pop_front();
        }
        self.recent_errors.push_back(ev);
    }

 /// LAST RESORT: wipe everything (used when reorg recovery can't find
 /// a usable snapshot). The poll loop then re-scans from
 /// LCKPROTOCOL_V1_HEIGHT, rebuilding the canonical view from scratch.
    pub fn wipe_for_reorg(&mut self) {
        self.indexed_height = 0;
        self.utxo_balances.clear();
        self.address_utxos.clear();
        self.bets.clear();
        self.transfers.clear();
        self.deploys.clear();
        self.bet_offset = 0;
        self.transfer_offset = 0;
        self.deploy_offset = 0;
        self.by_txid.clear();
        self.tokens.clear();
        self.block_hashes.clear();
        self.snapshots.clear();
 // BASELINE SNAPSHOT / HIGH-3).
 // Without this, the next snapshot only gets taken when the
 // post-wipe rebuild crosses a `h % SNAPSHOT_INTERVAL_BLOCKS == 0`
 // height in backfill_range. LCKPROTOCOL_V1_HEIGHT (949,375) is NOT a
 // multiple of 12, so a reorg hitting any of the first ~3 blocks
 // after wipe has zero snapshots to restore from and gets stuck
 // wiping again — pathological-but-possible reorg-storm trap.
 // Pushing one empty-state snapshot at indexed_height=0 right
 // here gives the next reorg-detection probe a valid base to
 // restore to instead of forcing another full wipe.
        let baseline = StateSnapshot {
            version: SNAPSHOT_VERSION,
            indexed_height: 0,
            utxo_balances: Default::default(),
            address_utxos: Default::default(),
            bets: Default::default(),
            transfers: Default::default(),
            deploys: Default::default(),
            by_txid: Default::default(),
            tokens: Default::default(),
            block_hashes: Default::default(),
            bet_offset: 0,
            transfer_offset: 0,
            deploy_offset: 0,
        };
        self.snapshots.push_back(baseline);
    }

    pub fn prune_block_hashes(&mut self, oldest_keep: u32) {
        self.block_hashes.retain(|h, _| *h >= oldest_keep);
    }

    pub fn take_snapshot(&mut self) -> StateSnapshot {
        let snap = StateSnapshot {
            version: SNAPSHOT_VERSION,
            indexed_height: self.indexed_height,
            utxo_balances: self.utxo_balances.clone(),
            address_utxos: self.address_utxos.clone(),
            bets: self.bets.clone(),
            transfers: self.transfers.clone(),
            deploys: self.deploys.clone(),
            by_txid: self.by_txid.clone(),
            tokens: self.tokens.clone(),
            block_hashes: self.block_hashes.clone(),
            bet_offset: self.bet_offset,
            transfer_offset: self.transfer_offset,
            deploy_offset: self.deploy_offset,
        };
        if self.snapshots.len() >= SNAPSHOT_RING_SIZE {
            self.snapshots.pop_front();
        }
        self.snapshots.push_back(snap.clone());
        snap
    }

    pub fn restore_from_snapshot(&mut self, snap: StateSnapshot) {
        self.indexed_height = snap.indexed_height;
        self.utxo_balances = snap.utxo_balances;
        self.address_utxos = snap.address_utxos;
        self.bets = snap.bets;
        self.transfers = snap.transfers;
        self.deploys = snap.deploys;
        self.by_txid = snap.by_txid;
        self.tokens = snap.tokens;
        self.block_hashes = snap.block_hashes;
        self.bet_offset = snap.bet_offset;
        self.transfer_offset = snap.transfer_offset;
        self.deploy_offset = snap.deploy_offset;
    }

 /// Find the most recent snapshot whose `indexed_height ≤ cutoff` AND
 /// whose recorded block_hash for that height still appears in
 /// `still_valid_hashes` (canonical chain). Used by reorg recovery.
    pub fn restore_to_snapshot_at_or_before(
        &mut self,
        cutoff: u32,
        still_valid_hashes: &HashMap<u32, String>,
    ) -> Option<u32> {
        let mut chosen_idx: Option<usize> = None;
        for (i, snap) in self.snapshots.iter().enumerate().rev() {
            if snap.indexed_height > cutoff {
                continue;
            }
            let height = snap.indexed_height;
            if let Some(stored_hash) = snap.block_hashes.get(&height) {
                if let Some(canonical_hash) = still_valid_hashes.get(&height) {
                    if stored_hash == canonical_hash {
                        chosen_idx = Some(i);
                        break;
                    }
                }
            }
        }
        let i = chosen_idx?;
        while self.snapshots.len() > i + 1 {
            self.snapshots.pop_back();
        }
        let snap = self.snapshots.pop_back()?;
        let restored_height = snap.indexed_height;
        self.restore_from_snapshot(snap);
        Some(restored_height)
    }

 /// Lookup a single UTXO's full record. None if the UTXO carries no
 /// tokens or doesn't exist in the index.
 #[allow(dead_code)]
    pub fn utxo_balance(&self, txid: &str, vout: u32) -> Option<&UtxoEntry> {
        self.utxo_balances.get(&outpoint_key(txid, vout))
    }

 /// Sum every UTXO's balance for a given ticker.
 #[allow(dead_code)]
    pub fn total_minted_in_utxos(&self, ticker: &str) -> u64 {
        self.utxo_balances
            .values()
            .filter_map(|e| e.balances.get(ticker).copied())
            .fold(0u64, |a, b| a.saturating_add(b))
    }

 /// Sum a single address's balances per ticker. Used by `/balances/:address`.
 /// O(|address's UTXO count| × tickers-per-UTXO), bounded by the
 /// reverse index (no scan over the full utxo_balances map).
    pub fn address_balances(&self, address: &str) -> RuneBalance {
        let mut totals: RuneBalance = HashMap::new();
        if let Some(set) = self.address_utxos.get(address) {
            for opkey in set {
                if let Some(entry) = self.utxo_balances.get(opkey) {
                    for (ticker, amt) in &entry.balances {
                        let cur = totals.entry(ticker.clone()).or_insert(0);
 *cur = cur.saturating_add(*amt);
                    }
                }
            }
        }
        totals
    }

 /// Internal: register a UTXO at `key` controlled by `address` so the
 /// reverse index stays in sync.
    fn track_address_utxo(&mut self, address: Option<&str>, key: &str) {
        if let Some(addr) = address {
            self.address_utxos
                .entry(addr.to_string())
                .or_insert_with(HashSet::new)
                .insert(key.to_string());
        }
    }

 /// Internal: remove `key` from the address's reverse-index set.
 /// Drops the entire address entry when its set goes empty so the
 /// map doesn't grow unboundedly with one-shot addresses.
    fn untrack_address_utxo(&mut self, address: Option<&str>, key: &str) {
        if let Some(addr) = address {
            let drop_addr = match self.address_utxos.get_mut(addr) {
                Some(set) => {
                    set.remove(key);
                    set.is_empty()
                }
                None => false,
            };
            if drop_addr {
                self.address_utxos.remove(addr);
            }
        }
    }

 // ============================================================
 // FIFO-evicting push helpers — every audit-log addition goes
 // through one of these so the cap + by_txid coupling stays
 // invariant. Returns the LOGICAL index of the new entry.
 // ============================================================
    fn push_bet(&mut self, bet: BetView) -> u64 {
        while self.bets.len() >= MAX_BETS_VEC {
            if let Some(old) = self.bets.pop_front() {
                self.by_txid.remove(&old.txid);
                self.bet_offset = self.bet_offset.saturating_add(1);
            } else {
                break;
            }
        }
        let logical_idx = self.bet_offset.saturating_add(self.bets.len() as u64);
        self.bets.push_back(bet);
        logical_idx
    }

    fn push_transfer(&mut self, t: TransferView) -> u64 {
        while self.transfers.len() >= MAX_TRANSFERS_VEC {
            if let Some(old) = self.transfers.pop_front() {
                self.by_txid.remove(&old.txid);
                self.transfer_offset = self.transfer_offset.saturating_add(1);
            } else {
                break;
            }
        }
        let logical_idx = self
            .transfer_offset
            .saturating_add(self.transfers.len() as u64);
        self.transfers.push_back(t);
        logical_idx
    }

    fn push_deploy(&mut self, d: DeployView) -> u64 {
        while self.deploys.len() >= MAX_DEPLOYS_VEC {
            if let Some(old) = self.deploys.pop_front() {
                self.by_txid.remove(&old.txid);
                self.deploy_offset = self.deploy_offset.saturating_add(1);
            } else {
                break;
            }
        }
        let logical_idx = self
            .deploy_offset
            .saturating_add(self.deploys.len() as u64);
        self.deploys.push_back(d);
        logical_idx
    }

 #[allow(dead_code)]
    pub fn resolve_bet_idx(&self, logical_idx: u64) -> Option<&BetView> {
        let phys = logical_idx.checked_sub(self.bet_offset)? as usize;
        self.bets.get(phys)
    }
 #[allow(dead_code)]
    pub fn resolve_transfer_idx(&self, logical_idx: u64) -> Option<&TransferView> {
        let phys = logical_idx.checked_sub(self.transfer_offset)? as usize;
        self.transfers.get(phys)
    }
 #[allow(dead_code)]
    pub fn resolve_deploy_idx(&self, logical_idx: u64) -> Option<&DeployView> {
        let phys = logical_idx.checked_sub(self.deploy_offset)? as usize;
        self.deploys.get(phys)
    }

 /// Is this vout an OP_RETURN (i.e. cannot carry tokens)?
    fn is_op_return_vout(ctx: &TxContext, vout: u32) -> bool {
        ctx.op_return_vouts.contains(&vout)
    }

 /// Vestigial helper from earlier permissive-routing drafts. Under
 /// the strict burn-on-non-protocol-spend rule (PROTOCOL.md §7),
 /// the apply path no longer has a fallback "default output" —
 /// input-pool residuals route ONLY to a SEND's `change_out_idx`
 /// and burn otherwise. Kept here so any future protocol revision
 /// that needs the smallest-index non-OP_RETURN vout can call it
 /// without re-deriving the loop.
 #[allow(dead_code)]
    fn default_out_idx(ctx: &TxContext, exclude: Option<u32>) -> Option<u32> {
        let primary = (0..ctx.vout_count).find(|v| {
            !ctx.op_return_vouts.contains(v) && exclude.map_or(true, |e| *v != e)
        });
        if primary.is_some() {
            return primary;
        }
        (0..ctx.vout_count).find(|v| !ctx.op_return_vouts.contains(v))
    }

 /// Validate that an output index points at a real, non-OP_RETURN
 /// vout. Returns the index iff valid.
    fn validate_out_idx(ctx: &TxContext, idx: u32) -> Option<u32> {
        if idx >= ctx.vout_count {
            return None;
        }
        if Self::is_op_return_vout(ctx, idx) {
            return None;
        }
        Some(idx)
    }

 /// Cohort-v950950 consensus protocol-fee check.
 ///
 /// Returns true iff the tx has at least one vout that pays
 /// EXACTLY `expected_sats` to PROJECT_FEE_ADDRESS. The
 /// strict-equality rule (== not ≥) makes the protocol-fee
 /// output unambiguous: each tx has at most one "this is the
 /// fee" output, distinct from any voluntary donation outputs
 /// (which would carry a different amount).
 ///
 /// Used by all three opcode apply branches:
 ///   DEPLOY: expected_sats = 5,460
 ///   BET:    expected_sats = 546
 ///   Xfer:   expected_sats = 546
    fn has_exact_project_fee(ctx: &TxContext, expected_sats: u64) -> bool {
        ctx.vout_values
            .iter()
            .zip(ctx.vout_addresses.iter())
            .any(|(value, addr)| {
 *value == expected_sats
                    && addr.as_deref() == Some(crate::protocol::PROJECT_FEE_ADDRESS)
            })
    }

 /// Apply a tx's combined effect — drain its input UTXO balances,
 /// apply (optional) LUCKYPROTOCOL payload edicts, route the residual
 /// pool to the change/default output. Mutates state. Returns true
 /// iff any state change occurred (audit log push counts as a change).
 /// Activation gate: pre-activation blocks return false unconditionally —
 /// no pre-LUCKYPROTOCOL state is replayed, no LUCKYPROTOCOL state is mutated.
    pub fn apply_tx(&mut self, ctx: TxContext, payload: Option<ProtocolPayload>) -> bool {
        if ctx.block_height < crate::protocol::LCKPROTOCOL_V1_HEIGHT {
            return false;
        }

 // === STEP 1: Build the input pool by draining spent UTXOs ===
        let mut input_pool: RuneBalance = HashMap::new();
        for (txid, vout) in ctx.spent_outpoints.iter() {
            let key = outpoint_key(txid, *vout);
            if let Some(entry) = self.utxo_balances.remove(&key) {
 // Drop the reverse-index entry so /balances/:address
 // stops counting this UTXO immediately.
                self.untrack_address_utxo(entry.address.as_deref(), &key);
                for (ticker, amt) in entry.balances {
                    let pool_entry = input_pool.entry(ticker).or_insert(0);
 *pool_entry = pool_entry.saturating_add(amt);
                }
            }
        }

 // Track whether we touched any state (input drain, log push, etc.).
        let mut changed = !input_pool.is_empty();

 // === STEP 1b: Multi-ticker input rejection ===
 // PROTOCOL.md §7.2: a single tx may consume token UTXOs of AT
 // MOST ONE ticker. If the input pool contains two or more
 // distinct tickers, the entire tx is treated as protocol-
 // invalid and the FULL input pool BURNS — no edict is
 // applied, no UTXO assignment happens, and even the LUCKYPROTOCOL
 // payload (if any) is recorded with `applied=false`.
 // Rationale: mixing tickers in inputs is ambiguous — a SEND
 // payload only declares ONE ticker, leaving the indexer to
 // either silently drop the other tickers or "default-route"
 // them somewhere the user didn't specify. Either resolution
 // is a footgun + an indexer-divergence vector (different
 // implementations may resolve differently). The strict rule
 // is "one ticker per tx or no tokens move" — wallets that
 // need to spend multiple tickers MUST construct one tx per
 // ticker. The LUCKYPROTOCOL wallet's coin selector already does
 // this; non-protocol-aware spenders trigger BURN.
        if input_pool.len() > 1 {
            let mixed: Vec<(String, u64)> = input_pool
                .iter()
                .map(|(t, a)| (t.clone(), *a))
                .collect();
            tracing::info!(
                txid = ctx.txid,
                height = ctx.block_height,
                ?mixed,
                "burn: multi-ticker input pool — entire tx invalidated, all tokens destroyed"
            );
 // Clear the pool so step 2's edict matching can't see any
 // tokens. The audit log still records the LUCKYPROTOCOL payload
 // (if any) as applied=false / status=Invalid so the user
 // / indexer-consumer can see why their tx didn't credit.
            input_pool.clear();
        }

 // Idempotency: only the audit-log + tokens map need txid dedup;
 // utxo_balances is naturally idempotent (UTXOs are spent at most
 // once on the chain). Don't double-record audit entries.
        let already_logged = self.by_txid.contains_key(ctx.txid);

 // === STEP 2: Apply the payload edict (if any) ===
        let mut output_assignments: HashMap<u32, RuneBalance> = HashMap::new();
        let mut explicit_change_idx: Option<u32> = None;

        match payload {
            Some(ProtocolPayload::Bet {
                tier,
                pick,
                ticker,
                win_out_idx,
                change_out_idx,
            }) if !already_logged => {
                changed = true;
                let win_idx_valid = Self::validate_out_idx(&ctx, win_out_idx);
                let ticker_deployed = self.tokens.contains_key(&ticker);
 // CONSENSUS PROTOCOL FEE (cohort v950950) — a MINE tx must
 // include at least one output paying EXACTLY MINE_PROTOCOL_FEE_SATS
 // (546) to PROJECT_FEE_ADDRESS. Without it the BET is rejected:
 // no reward credit even on predicate hit, status = Invalid.
 // Residual input pool still routes per change_out_idx (so any
 // token UTXO inadvertently spent as MINE funding is preserved
 // via explicit change rather than burned for the fee miss).
 //
 // Wallets that omit the fee output are either non-protocol-aware
 // or trying to evade the PROJECT_FEE_ADDRESS-history fast-bootstrap
 // sweep; either way the BET is invisible to /balances queries.
                let fee_paid = Self::has_exact_project_fee(
                    &ctx,
                    crate::protocol::MINE_PROTOCOL_FEE_SATS,
                );

 // Decide validity + outcome upfront.
                let mut status = BetStatus::Settled;
                let mut win = None;
                let mut reward: u64 = 0;
                let mut cap_exhausted = false;

                if !ticker_deployed || win_idx_valid.is_none() || !fee_paid {
                    if !fee_paid {
                        tracing::info!(
                            txid = ctx.txid,
                            ticker = %ticker,
                            tier = %tier,
                            height = ctx.block_height,
                            "MINE rejected: protocol fee output missing (needs EXACTLY {} sat to {})",
                            crate::protocol::MINE_PROTOCOL_FEE_SATS,
                            crate::protocol::PROJECT_FEE_ADDRESS,
                        );
                    }
                    status = BetStatus::Invalid;
                } else {
                    let predicate_hit = is_hit(&tier, &pick, ctx.block_hash).unwrap_or(false);
                    if predicate_hit {
                        let raw_reward = tier_reward(&tier).unwrap_or(0);
                        if let Some(reg) = self.tokens.get_mut(&ticker) {
                            let remaining = reg.supply.saturating_sub(reg.minted);
                            let credit = raw_reward.min(remaining);
                            reg.minted = reg.minted.saturating_add(credit);
                            reward = credit;
                            if credit == 0 {
                                cap_exhausted = true;
                            }
                        }
                    }
                    win = Some(reward > 0);
                    if reward > 0 {
 // Mint to the declared win output.
                        let target_idx = win_idx_valid.expect("validated above");
                        let entry = output_assignments
                            .entry(target_idx)
                            .or_insert_with(HashMap::new);
                        let cur = entry.entry(ticker.clone()).or_insert(0);
 *cur = cur.saturating_add(reward);
                    }
                }

 // v2 PROTOCOL: if the MINE declared a change_out_idx and it
 // points at a valid non-OP_RETURN vout, route residual input
 // pool there in STEP 3. Same semantics as SEND's
 // change_out_idx — preserves any token UTXO inadvertently
 // spent as MINE funding.
 //
 // Legacy 5-field MINEs (change_out_idx == None) still burn
 // residual: STEP 3's BURN branch runs when
 // explicit_change_idx stays None.
 //
 // Out-of-bounds / OP_RETURN-pointing change_out_idx is
 // silently downgraded to burn — same as SEND's behavior for
 // an invalid index. The BetView still records the raw
 // declared index so consumers can audit intent vs. effect.
                if let Some(c) = change_out_idx {
                    if Self::validate_out_idx(&ctx, c).is_some() {
                        explicit_change_idx = Some(c);
                    }
                }

                let logical = self.push_bet(BetView {
                    txid: ctx.txid.to_string(),
                    block_height: ctx.block_height,
                    block_hash: ctx.block_hash.to_string(),
                    sender: ctx.sender.to_string(),
                    tier,
                    pick,
                    ticker,
                    win_out_idx,
                    change_out_idx,
                    status,
                    reveal_block_height: None,
                    reveal_block_hash: None,
                    win,
                    reward_smallest: reward,
                    cap_exhausted,
                });
                self.by_txid
                    .insert(ctx.txid.to_string(), EntryRef::Bet { idx: logical });
            }
            Some(ProtocolPayload::Xfer {
                ticker,
                amount,
                to_out_idx,
                change_out_idx,
            }) if !already_logged => {
                changed = true;
                let to_valid = Self::validate_out_idx(&ctx, to_out_idx);
                let pool_amt = input_pool.get(&ticker).copied().unwrap_or(0);
 // CONSENSUS PROTOCOL FEE (cohort v950950) — a SEND tx must
 // include at least one output paying EXACTLY SEND_PROTOCOL_FEE_SATS
 // (546) to PROJECT_FEE_ADDRESS. Without it the SEND is rejected:
 // no balance transfer, recipient gets nothing. Residual still
 // routes via change_out_idx so the sender's tokens aren't
 // burned unfairly — they're recovered by explicit change vs.
 // the strict-burn fallback (§7.4).
 //
 // The JS browser indexer enforced this since the previous cohort;
 // the Rust indexer is being brought into agreement here so the
 // two implementations produce byte-identical state.
                let fee_paid = Self::has_exact_project_fee(
                    &ctx,
                    crate::protocol::SEND_PROTOCOL_FEE_SATS,
                );
                let applied = to_valid.is_some() && pool_amt >= amount && fee_paid;
                if !fee_paid {
                    tracing::info!(
                        txid = ctx.txid,
                        ticker = %ticker,
                        amount = amount,
                        height = ctx.block_height,
                        "SEND rejected: protocol fee output missing (needs EXACTLY {} sat to {})",
                        crate::protocol::SEND_PROTOCOL_FEE_SATS,
                        crate::protocol::PROJECT_FEE_ADDRESS,
                    );
                }

                if applied {
                    let target_idx = to_valid.expect("validated above");
                    let entry = output_assignments
                        .entry(target_idx)
                        .or_insert_with(HashMap::new);
                    let cur = entry.entry(ticker.clone()).or_insert(0);
 *cur = cur.saturating_add(amount);
 // Decrement the pool — remainder will route to change.
                    if let Some(rem) = input_pool.get_mut(&ticker) {
 *rem = rem.saturating_sub(amount);
                        if *rem == 0 {
                            input_pool.remove(&ticker);
                        }
                    }
                }

 // Validate change index if specified.
                if let Some(c) = change_out_idx {
                    if Self::validate_out_idx(&ctx, c).is_some() {
                        explicit_change_idx = Some(c);
                    }
                }

                let logical = self.push_transfer(TransferView {
                    txid: ctx.txid.to_string(),
                    block_height: ctx.block_height,
                    block_hash: ctx.block_hash.to_string(),
                    sender: ctx.sender.to_string(),
                    ticker,
                    amount,
                    to_out_idx,
                    change_out_idx,
                    applied,
                });
                self.by_txid
                    .insert(ctx.txid.to_string(), EntryRef::Transfer { idx: logical });
            }
            Some(ProtocolPayload::Deploy { ticker }) if !already_logged => {
                changed = true;
                let already = self.tokens.contains_key(&ticker);
 // CONSENSUS PROTOCOL FEE — a DEPLOY tx must include at least one
 // output paying EXACTLY DEPLOY_PROTOCOL_FEE_SATS (5,460) to
 // PROJECT_FEE_ADDRESS. Without this gate the append-only `tokens`
 // registry would be griefable: an attacker could mass-deploy
 // 1-8-char tickers at ~546-sat dust cost and pollute every
 // indexer's memory.
 //
 // As of cohort v950950 the rule is EXACT amount (==), unifying
 // with the MINE/SEND fee enforcement below. The 5,460-sat exact-
 // amount output uniquely identifies a DEPLOY in PROJECT_FEE_ADDRESS
 // history (vs 546-sat for MINE/SEND).
                let fee_paid = Self::has_exact_project_fee(
                    &ctx,
                    crate::protocol::DEPLOY_PROTOCOL_FEE_SATS,
                );
                let applied = !already && fee_paid;
                if !fee_paid {
                    tracing::info!(
                        txid = ctx.txid,
                        ticker = %ticker,
                        height = ctx.block_height,
                        "DEPLOY rejected: protocol fee output missing (needs EXACTLY {} sat to {})",
                        crate::protocol::DEPLOY_PROTOCOL_FEE_SATS,
                        crate::protocol::PROJECT_FEE_ADDRESS,
                    );
                }
                if applied {
                    self.tokens.insert(
                        ticker.clone(),
                        TokenRegistryEntry {
                            ticker: ticker.clone(),
                            supply: crate::protocol::REQUIRED_TOKEN_SUPPLY,
                            minted: 0,
                            deployer: ctx.sender.to_string(),
                            deploy_txid: ctx.txid.to_string(),
                            deploy_block: ctx.block_height,
                        },
                    );
                }
                let logical = self.push_deploy(DeployView {
                    txid: ctx.txid.to_string(),
                    block_height: ctx.block_height,
                    block_hash: ctx.block_hash.to_string(),
                    deployer: ctx.sender.to_string(),
                    ticker,
                    supply: crate::protocol::REQUIRED_TOKEN_SUPPLY,
                    applied,
                });
                self.by_txid
                    .insert(ctx.txid.to_string(), EntryRef::Deploy { idx: logical });
            }
            _ => {
 // No payload, OR duplicate txid (already in by_txid).
 // Either way, fall through to default routing of any
 // residual input_pool — UTXOs that carried tokens are
 // still consumed at the Bitcoin layer, so their tokens
 // MUST go somewhere.
            }
        }

 // === STEP 3: Route residual input pool — strict BURN policy ===
 // V2 PROTOCOL RULE: when a token-carrying UTXO is spent, its
 // tokens are preserved ONLY when the spending tx carries an
 // operation whose `change_out_idx` is valid. The operations
 // that can declare a change_out_idx are:
 //   - SEND (always, since v1)
 //   - MINE (since v2, optional 6th field)
 //
 // ANY other case — DEPLOY payload, no payload, MINE without
 // a valid change_out_idx (legacy 5-field), SEND with
 // missing/invalid change_out_idx — destroys the residual.
 // Rationale: prevents non-LUCKYPROTOCOL wallets from accidentally
 // moving tokens when consolidating UTXOs, AND prevents a
 // malicious wallet from constructing a tx that funnels other
 // people's tokens to its own address by spending a dust UTXO
 // it happens to receive. Users MUST use the LUCKYPROTOCOL wallet
 // (which always emits a valid change_out_idx on SEND and v2-
 // compatible MINE) for any operation involving a token UTXO.
 // Audit consequence: `applied=false` SEND (insufficient pool)
 // still routes residual to `change_out_idx` since the user
 // explicitly declared a destination; only payload-less,
 // DEPLOY, or change_out_idx-less spends BURN.
        if !input_pool.is_empty() {
            if let Some(idx) = explicit_change_idx {
                let entry = output_assignments.entry(idx).or_insert_with(HashMap::new);
                for (ticker, amt) in input_pool.drain() {
                    let cur = entry.entry(ticker).or_insert(0);
 *cur = cur.saturating_add(amt);
                }
            } else {
 // BURN — collect the burned amounts for the audit log,
 // then explicitly clear input_pool to match the
 // explicit-change branch's `drain()` posture. Either
 // call achieves the same observable outcome (an empty
 // map dropped on scope exit), but the explicit `.clear()`
 // makes "tokens destroyed here" obvious to anyone
 // reading this branch — without it the burn is implicit
 // (rely-on-Drop), which the audit flagged as a
 // maintenance hazard./ MED-8.
                let burned_tickers: Vec<(String, u64)> = input_pool
                    .iter()
                    .map(|(t, a)| (t.clone(), *a))
                    .collect();
                input_pool.clear();
                tracing::info!(
                    txid = ctx.txid,
                    height = ctx.block_height,
                    ?burned_tickers,
                    "burn: token UTXO spent without valid SEND change_out_idx — residual destroyed"
                );
            }
        }

 // === STEP 4: Commit output assignments to utxo_balances ===
        for (vout_idx, balance) in output_assignments {
            if balance.is_empty() {
                continue;
            }
            let key = outpoint_key(ctx.txid, vout_idx);
            let address = ctx
                .vout_addresses
                .get(vout_idx as usize)
                .and_then(|o| o.clone());
 // Maintain the reverse index BEFORE we mutate utxo_balances
 // so a panicking borrow can't desync the two maps.
            self.track_address_utxo(address.as_deref(), &key);
 // Merge into any existing entry (shouldn't normally happen
 // since txids are fresh, but defensive).
            let entry = self
                .utxo_balances
                .entry(key)
                .or_insert_with(UtxoEntry::default);
 // If the address wasn't yet recorded on this entry, fill it
 // in now. If it was recorded as a different address (also
 // unusual), trust the input-side classification.
            if entry.address.is_none() {
                entry.address = address;
            }
            for (ticker, amt) in balance {
                let cur = entry.balances.entry(ticker).or_insert(0);
 *cur = cur.saturating_add(amt);
            }
        }

        changed
    }

 /// VESTIGIAL — under the single-block settlement scheme bets are
 /// resolved inline by apply_tx. Survives so source.rs's existing
 /// call site stays a no-op for the common case. Re-settles any
 /// LegacyPending bets carried over from old snapshots.
    pub fn advance_settlement(&mut self, _this_height: u32, _this_hash: &str) {
        for i in 0..self.bets.len() {
            if !matches!(self.bets[i].status, BetStatus::LegacyPending) {
                continue;
            }
            let (tier, pick, hash_n) = {
                let b = &self.bets[i];
                (b.tier.clone(), b.pick.clone(), b.block_hash.clone())
            };
            let win = is_hit(&tier, &pick, &hash_n).unwrap_or(false);
            let bet = &mut self.bets[i];
            bet.status = BetStatus::Settled;
            bet.win = Some(win);
            bet.reward_smallest = 0; // cannot retroactively credit a UTXO
            bet.reveal_block_height = None;
            bet.reveal_block_hash = None;
        }
    }
}
