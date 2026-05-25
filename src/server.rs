// HTTP API server — exposes the in-memory IndexerState as JSON endpoints.
// Same shape as the desktop app's protocol/indexer.js so the frontend can
// optionally consume from this server when it wants the GLOBAL view rather
// than its own local replay.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tower_http::cors::{Any, CorsLayer};

use crate::indexer::{BetView, DeployView, IndexerState, TransferView};

/// Process-global handle to the poll-loop's wake `Notify`. Set once at
/// boot via `set_poll_notify()` from main.rs (right before `serve()`)
/// and consumed by the `/poll-now` HTTP handler. Stays None when the
/// indexer runs in headless / standalone mode without a wake hookup
/// (no harm — the handler short-circuits).
/// Why a static and not part of the `State` extractor: keeping the
/// `AppState` type as `Arc<RwLock<IndexerState>>` means none of the
/// existing handlers need to be re-typed, and the only new handler
/// (poll_now) reads this directly. Axum's extension pattern would
/// have worked too but adds a generic parameter to every route.
static POLL_NOTIFY: std::sync::OnceLock<Arc<Notify>> = std::sync::OnceLock::new();

/// Unix-seconds timestamp of the last accepted `POST /poll-now`. Used
/// purely for debouncing the endpoint — see the handler. Initialized
/// to 0 (never fired) so the first call always goes through.
static LAST_POLL_NOW_AT: AtomicU64 = AtomicU64::new(0);

/// Minimum interval between accepted `POST /poll-now` wakes. Faster
/// kicks are silently ignored (return 200 with `debounced: true`).
/// Tuned to be just longer than a typical tip+block fetch round-trip
/// — without this, a misbehaving caller (or a buggy front-end that
/// fires on every render) could pin the poll loop in a tight retry
/// cycle and burn the upstream quota in seconds.
const POLL_NOW_DEBOUNCE_SECS: u64 = 3;

/// Install the wake handle BEFORE `serve()` starts accepting requests.
/// Idempotent — second calls are no-ops (the OnceLock semantics).
/// Lives here rather than as a constructor parameter on `serve()` so
/// the call site in main.rs reads clearly as "wire poll-now → notify"
/// without rearranging every other server entrypoint.
pub fn set_poll_notify(notify: Arc<Notify>) {
    let _ = POLL_NOTIFY.set(notify);
}

/// Default page size for global list endpoints. Big enough that a
/// single request gives a useful overview without flooding the wire;
/// the explorer UI can paginate via `?offset=` if it needs more.
const DEFAULT_LIST_LIMIT: usize = 100;
/// Hard cap so a malicious caller can't request a `limit=999999999`
/// and force the indexer to allocate / serialize every entry it has.
const MAX_LIST_LIMIT: usize = 500;

type AppState = Arc<RwLock<IndexerState>>;

#[derive(Serialize)]
struct Health {
    network: String,
    /// Configured Bitcoin Core JSON-RPC endpoint — surfaces "where is
    /// this indexer's chain data coming from?" in the `/` health JSON.
    /// Pulled from the `CORE_RPC` OnceCell rather than IndexerState
    /// since the URL is process-config, not derived state.
    core_url: String,
    indexed_height: u32,
    tip_height: u32,
    address_count: usize,
    utxo_count: usize,
    bet_count: usize,
    transfer_count: usize,
    deploy_count: usize,
    token_count: usize,
 /// Unix epoch seconds — when indexed_height last advanced. The
 /// frontend computes `now - last_progress_at` to drive its stall
 /// indicator (status ball goes amber/red when too long since the
 /// last block was applied despite a non-zero lag).
    last_progress_at: u64,
 /// Server-side judgment of stalled state. True when `lag > 0`
 /// AND the indexer has gone STALL_THRESHOLD_SECS without
 /// progress. Frontend may apply its own (usually looser)
 /// threshold on top — this field is advisory.
    stalled: bool,
 /// Ring buffer of recent diagnostic events for the SETTINGS →
 /// INDEXER DIAGNOSTICS panel. Cloned out of the indexer state
 /// per-request (cheap — max MAX_RECENT_ERRORS = 16 entries).
 /// Snapshot-excluded; a warm-restart starts with an empty buffer.
    recent_errors: Vec<crate::indexer::ErrorEvent>,
}

#[derive(Serialize)]
struct AddressResponse {
    address: String,
    balances: std::collections::HashMap<String, u64>,
    bet_count: usize,
    transfer_count: usize,
}

/// Per-UTXO ticker balance snapshot for an address. Used by the
/// wallet's transfer flow to do greedy-minimum coin selection:
/// instead of pinning EVERY token UTXO as a tx input (which inflates
/// vsize + fee + collapses the user's UTXO set into one big change
/// output), the wallet picks the fewest largest UTXOs whose summed
/// `balances[ticker]` covers the SEND amount.
///
/// Wire shape:
///   { "address": "bc1q...",
///     "utxos": [
///       { "txid": "...", "vout": 0, "balances": { "LUCKY": 100 } },
///       ...
///     ] }
///
/// Only UTXOs that carry non-zero protocol tokens appear here. Plain
/// BTC UTXOs (no token balances) are NOT returned — the wallet has
/// its own bdk view for those and doesn't need indexer help.
#[derive(Serialize)]
struct UtxoBalancesResponse {
    address: String,
    utxos: Vec<UtxoBalanceEntry>,
}

#[derive(Serialize)]
struct UtxoBalanceEntry {
    txid: String,
    vout: u32,
    balances: std::collections::HashMap<String, u64>,
}

#[derive(Serialize)]
struct BetsResponse {
    address: String,
    bets: Vec<BetView>,
}

#[derive(Serialize)]
struct TransfersResponse {
    address: String,
    transfers: Vec<TransferView>,
}

/// Global-list pagination + filter shape for `/bets`. Fields are all
/// optional: missing limit / offset use sensible defaults; missing
/// tier / ticker means "no filter" (all rows).
#[derive(Debug, Deserialize)]
struct BetsListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
 /// Filter by tier ("iron" / "bronze" / "silver" / "gold"). Other
 /// values produce empty results (rather than 400) so callers can
 /// blindly forward user input.
    tier: Option<String>,
 /// Filter by ticker — case-insensitive exact match against the
 /// canonical uppercase ticker stored in the bet record.
    ticker: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransfersListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    ticker: Option<String>,
}

#[derive(Serialize)]
struct GlobalBetsResponse {
 /// Total bets matching the filter (pre-pagination). Lets clients
 /// implement pager UIs without a second `count` request.
    total: usize,
    limit: usize,
    offset: usize,
    bets: Vec<BetView>,
}

#[derive(Serialize)]
struct GlobalTransfersResponse {
    total: usize,
    limit: usize,
    offset: usize,
    transfers: Vec<TransferView>,
}

/// Serve the HTTP API. Takes a pre-bound `TcpListener` rather than a
/// SocketAddr so main.rs can bind FIRST (as a process-lock surrogate
/// detecting double-spawn) and only then proceed with snapshot load
/// + poller spawn. Without that ordering, two simultaneous indexer
/// instances would both load + mutate the snapshot file before one of
/// them finally hit the bind() and aborted, leaving the snapshot
/// corrupted.
pub async fn serve(state: AppState, listener: TcpListener) -> anyhow::Result<()> {
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/", get(health))
        .route("/balances/:address", get(balances))
        .route("/utxos/:address", get(utxos_for_address))
        // Raw BTC UTXOs (not token UTXOs) at an address — wallet uses
        // this for balance display + fee funding. Proxies bitcoind's
        // scantxoutset. Slow first call (~30-60s) but CF caches at the
        // edge so the second hit anywhere in the world is instant.
        .route("/btc-utxos/:address", get(btc_utxos_for_address))
        // Confirmation status for one tx (mempool vs in-block + the
        // containing block hash/height/time). Proxies getrawtransaction
        // + a follow-up getblockheader to fill in block height.
        .route("/tx-status/:txid", get(tx_status))
        // Block hash at height — pre-mined heights return 404. Used
        // by V2 BET settlement (the determining block's hash drives
        // win/loss). Proxies bitcoind's getblockhash.
        .route("/block-height/:height", get(block_at_height))
        // Block hash + header timestamp at height — same source as
        // /block-height but with the block-header time added so the
        // ALMANAC view can render a date next to each historical
        // block. Proxies getblockhash + getblockheader.
        .route("/block-info/:height", get(block_info_at_height))
        .route("/bets", get(bets_all))                       // global, paginated + tier/ticker filters
        .route("/bets/:address", get(bets_for_address))
        .route("/transfers", get(transfers_all))             // global, paginated + ticker filter
        .route("/transfers/:address", get(transfers_for_address))
        .route("/bets/by-txid/:txid", get(bet_by_txid))
        .route("/tokens", get(tokens_all))
        .route("/tokens/:ticker", get(token_one))
        .route("/tokens/:ticker/holders", get(token_holders))   // global holder list for one ticker
        .route("/deploys", get(deploys_all))
 // POST /poll-now — event-driven wake from the frontend. Lets a
 // caller that already sees a fresh tip (the desktop wallet's
 // independent Esplora poll) nudge the sidecar's run_poller out
 // of its sleep so backfill starts within ~50ms instead of
 // waiting up to the full poll cadence (currently 10s).
 // Heavily debounced (POLL_NOW_DEBOUNCE_SECS) — multiple windows
 // or a buggy caller can fire as fast as they like, only one
 // wake per debounce window is honored. Always returns 200 so
 // the caller doesn't need to discriminate "accepted" from
 // "debounced" beyond the response JSON.
        .route("/poll-now", post(poll_now))
        .layer(cors)
        .with_state(state);

    let bind = listener.local_addr().ok();
    tracing::info!(?bind, "indexer HTTP listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// POST /poll-now — wake the run_poller loop ASAP.
/// Returns `{ accepted: bool, debounced_for_secs: u64 }`:
///   accepted = true  — Notify fired, the poll loop will wake on its
///                      next select! (already-running fetches finish
///                      first; the wake landing during a fetch queues
///                      a permit so the NEXT sleep is skipped).
///   accepted = false — debounced; another wake happened within
///                      POLL_NOW_DEBOUNCE_SECS, so this one is ignored.
///                      The caller may safely re-fire after the
///                      `debounced_for_secs` countdown.
/// Always returns HTTP 200 — clients shouldn't have to special-case
/// debouncing as an "error". A pure POST with no body required.
#[derive(Serialize)]
struct PollNowResponse {
    accepted: bool,
    debounced_for_secs: u64,
}

async fn poll_now() -> (StatusCode, Json<PollNowResponse>) {
    let now = crate::indexer::now_unix();
    let last = LAST_POLL_NOW_AT.load(Ordering::Relaxed);
    let since = now.saturating_sub(last);
    if since < POLL_NOW_DEBOUNCE_SECS {
        return (StatusCode::OK, Json(PollNowResponse {
            accepted: false,
            debounced_for_secs: POLL_NOW_DEBOUNCE_SECS - since,
        }));
    }
 // Race window: two near-simultaneous /poll-now calls can both see
 // the OLD `last` and both pass the debounce check. The atomic
 // store below makes the SECOND notify a no-op-ish double-tap of
 // Notify (which has 1-permit semantics anyway, so the worst case
 // is one extra wake — harmless). Not worth a full compare-and-
 // exchange dance for that.
    LAST_POLL_NOW_AT.store(now, Ordering::Relaxed);
    if let Some(n) = POLL_NOTIFY.get() {
        n.notify_one();
    } else {
 // Indexer was launched without a wake hookup (headless /
 // standalone-binary mode). The POST is a no-op but we still
 // honor the API surface and report "accepted" so callers don't
 // see a fake error.
        tracing::debug!("/poll-now called but POLL_NOTIFY not installed — no-op accepted");
    }
    (StatusCode::OK, Json(PollNowResponse {
        accepted: true,
        debounced_for_secs: 0,
    }))
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    let h = {
        let s = state.read();
 // Stall judgment: indexer is "behind tip" AND no progress for
 // STALL_THRESHOLD_SECS. Both conditions matter — a freshly-
 // launched indexer that's still doing snapshot validation has
 // not-yet-advanced indexed_height but isn't actually stuck.
 // Using `tip_height > indexed_height` (not >=) means the
 // "lag == 0 and caught up" case is never reported stalled
 // even if the wall clock has been still for a long time
 // (which is normal between blocks).
            let now = crate::indexer::now_unix();
            let elapsed = now.saturating_sub(s.last_progress_at);
            let stalled = s.tip_height > s.indexed_height
                && elapsed > crate::indexer::STALL_THRESHOLD_SECS;
        Health {
            network: format!("{}", s.network).to_lowercase(),
            core_url: crate::core_rpc::config()
                .map(|c| c.url.clone())
                .unwrap_or_default(),
            indexed_height: s.indexed_height,
            tip_height: s.tip_height,
 // Under v2, "addresses with non-zero balance" comes from the
 // reverse index size; "utxos with non-zero balance" is the
 // forward map size. Surface both — the former matches v1's
 // semantic, the latter is new under UTXO-bound state.
            address_count: s.address_utxos.len(),
            utxo_count: s.utxo_balances.len(),
            bet_count: s.bets.len(),
            transfer_count: s.transfers.len(),
            deploy_count: s.deploys.len(),
            token_count: s.tokens.len(),
            last_progress_at: s.last_progress_at,
            stalled,
 // Clone the ring buffer out so we can drop the read lock
 // before .into() / serde processing. 16 entries × ~150 bytes
 // = ~2.5KB, well below any reasonable concern.
            recent_errors: s.recent_errors.iter().cloned().collect(),
        }
    };
    Json(h)
}

/// Wire shape for /tokens — same fields as the in-memory
/// TokenRegistryEntry plus a computed `holders` count (number of
/// distinct addresses with a positive balance of this ticker). The
/// holder count is recomputed on every request because it would have
/// to be incrementally maintained on every credit/debit otherwise —
/// for the small registries this indexer manages, scanning the
/// addresses map per request is cheap (O(|addresses| × |tokens|) once,
/// well under a millisecond at realistic sizes).
#[derive(Serialize)]
struct TokenInfo {
    ticker: String,
    supply: u64,
    minted: u64,
    holders: usize,
    deployer: String,
    deploy_txid: String,
    deploy_block: u32,
}

fn count_holders(state: &IndexerState, ticker: &str) -> usize {
 // V2: walk address_utxos, sum each address's UTXOs for `ticker`,
 // count addresses whose sum is > 0. Same shape as tokens_all's
 // inline computation but for one ticker.
    let mut count = 0;
    for opkeys in state.address_utxos.values() {
        let mut total: u64 = 0;
        for opkey in opkeys {
            if let Some(entry) = state.utxo_balances.get(opkey) {
                if let Some(bal) = entry.balances.get(ticker) {
                    total = total.saturating_add(*bal);
                }
            }
        }
        if total > 0 {
            count += 1;
        }
    }
    count
}

/// Paginated `/tokens` response. `total` is the FULL registry size;
/// `items` is the slice for this page; `offset` + `limit` are the
/// effective server-clamped values. The frontend uses these to render
/// "showing 1-100 of N" and to page back/forward.
#[derive(Serialize)]
struct TokensPage {
    total: usize,
    offset: usize,
    limit: usize,
    items: Vec<TokenInfo>,
}

#[derive(serde::Deserialize)]
struct TokensQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

/// Hard cap on `limit` per `/tokens` request. Set deliberately low
/// (30) because:
///   1. The append-only `tokens` registry can in principle grow into
///      the hundreds of thousands (every 1-8-char `[A-Z0-9]` permutation
///      is mintable, capped only by the 5,460-sat DEPLOY fee). A
///      response that paginates 30-at-a-time stays well under 10 KB
///      regardless of registry size.
///   2. Each row's `holders` count is recomputed from scratch by
///      walking `address_utxos` — work that grows with adoption,
///      independent of `limit`. Capping `limit` low keeps the per-
///      request total cost bounded by the holder-count walk, not by
///      response-serialization size. Future work: cache holder counts
///      incrementally on apply, drop the per-request walk.
///   3. The in-app TokenPickerModal uses page size 10. Power users
///      who need to walk the full registry simply iterate `?offset=N`
///      with `?limit=30` until `items.len() < limit`. No legitimate
///      client needs a single 500-row burst.
const TOKENS_MAX_LIMIT: usize = 30;
/// Default page size when the caller omits `?limit=`. Set to 10 to
/// match the in-app TokenPickerModal's page size — that way the
/// picker's "show 10 mintable tokens, search for the rest" UX is
/// naturally consistent with raw `/tokens` calls (cheap default
/// response, paginate for more). The server caps at TOKENS_MAX_LIMIT
/// (500) so clients that want a denser view can request it.
const TOKENS_DEFAULT_LIMIT: usize = 10;

async fn tokens_all(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<TokensQuery>,
) -> Json<TokensPage> {
 // Clamp the query params before doing any work — keeps the
 // pagination bookkeeping uniform regardless of what the client
 // requested.
    let limit = q.limit.unwrap_or(TOKENS_DEFAULT_LIMIT).min(TOKENS_MAX_LIMIT).max(1);
    let offset = q.offset.unwrap_or(0);

 // Holder counting: a "holder" of ticker T is an address with
 // total balance > 0 across all its UTXOs. Walk address_utxos; for
 // each address, sum the relevant ticker across its UTXOs; if > 0,
 // count it. We do this for ALL tokens (not just the page) because
 // the count is cheap relative to the address-utxos walk and the
 // frontend uses the per-ticker count regardless of which page
 // a token lands on.
 // Cost: O(|address_utxos|) outer × O(avg-utxos-per-address) inner.
 // Bounded by total UTXO count regardless of address spread.
    let (total, items) = {
        let s = state.read();
        let total = s.tokens.len();
        let mut holder_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::with_capacity(total);
        for (_addr, opkeys) in s.address_utxos.iter() {
            let mut per_ticker: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for opkey in opkeys {
                if let Some(entry) = s.utxo_balances.get(opkey) {
                    for (ticker, bal) in entry.balances.iter() {
                        let cur = per_ticker.entry(ticker.clone()).or_insert(0);
 *cur = cur.saturating_add(*bal);
                    }
                }
            }
            for (ticker, t) in per_ticker {
                if t > 0 {
 *holder_counts.entry(ticker).or_insert(0) += 1;
                }
            }
        }

 // Sort tokens by deploy_block ASC (oldest first — chain
 // provenance order) so pagination is deterministic across
 // calls. HashMap iteration would otherwise reorder under
 // memory pressure. Tiebreak: ticker string asc (chain order
 // alone is unique already, but defensive).
        let mut all: Vec<&crate::indexer::TokenRegistryEntry> = s.tokens.values().collect();
        all.sort_by(|a, b| {
            a.deploy_block
                .cmp(&b.deploy_block)
                .then_with(|| a.ticker.cmp(&b.ticker))
        });
        let items: Vec<TokenInfo> = all
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|t| TokenInfo {
                ticker: t.ticker.clone(),
                supply: t.supply,
                minted: t.minted,
                holders: *holder_counts.get(&t.ticker).unwrap_or(&0),
                deployer: t.deployer.clone(),
                deploy_txid: t.deploy_txid.clone(),
                deploy_block: t.deploy_block,
            })
            .collect();
        (total, items)
    };
    Json(TokensPage { total, offset, limit, items })
}

async fn token_one(
    State(state): State<AppState>,
    Path(ticker): Path<String>,
) -> Result<Json<TokenInfo>, StatusCode> {
    let info = {
        let s = state.read();
        let t = match s.tokens.get(&ticker) {
            Some(t) => t,
            None => return Err(StatusCode::NOT_FOUND),
        };
        TokenInfo {
            ticker: t.ticker.clone(),
            supply: t.supply,
            minted: t.minted,
            holders: count_holders(&s, &t.ticker),
            deployer: t.deployer.clone(),
            deploy_txid: t.deploy_txid.clone(),
            deploy_block: t.deploy_block,
        }
    };
    Ok(Json(info))
}

/// One holder + its balance, as serialized in the /tokens/:ticker/holders
/// response. Sorted descending by balance in the response so the largest
/// holders appear first (consistent with how every block-explorer
/// presents holder lists).
#[derive(Serialize, Clone)]
struct HolderInfo {
    address: String,
    balance: u64,
}

#[derive(Serialize)]
struct TokenHoldersResponse {
    ticker: String,
 /// Total holders matching the ticker (pre-pagination). The caller can
 /// derive the page count from this without a separate `count` request.
    total: usize,
    limit: usize,
    offset: usize,
    holders: Vec<HolderInfo>,
 /// True iff the indexer's `tokens` registry contains this ticker
 /// (i.e. the deploy tx has been seen + applied). False means EITHER
 /// (a) the ticker isn't deployed on-chain, OR (b) the indexer is
 /// still backfilling and hasn't reached the deploy yet. Front-end
 /// distinguishes these two cases via its own deploy state — if
 /// the user just broadcast the deploy from this wallet, `indexed:
 /// false` should render as "indexing in progress…", not "doesn't
 /// exist". Audit §indexer-progress.
    indexed: bool,
 /// Snapshot of the indexer's current backfill position so the
 /// front-end can show "indexed_height / tip_height" when the user
 /// is waiting for a recently-broadcast deploy to surface.
    indexed_height: u32,
    tip_height: u32,
}

#[derive(Debug, Deserialize)]
struct HoldersListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

/// All addresses holding a given ticker, sorted by balance descending.
/// Used by the desktop INDEX → click-row → HOLDERS modal so the user
/// can see who owns the token they're looking at. Paginated like the
/// other global list endpoints (default 100, max 500).
/// Iteration cost: O(|addresses|) for the filter+collect, O(N log N)
/// for the sort (N = matching holders, typically small). All inside a
/// short-lived read guard.
async fn token_holders(
    State(state): State<AppState>,
    Path(ticker): Path<String>,
    Query(q): Query<HoldersListQuery>,
) -> Json<TokenHoldersResponse> {
    let limit = q.limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT);
    let offset = q.offset.unwrap_or(0);

 // Tickers in the indexer registry are stored in their canonical
 // form (uppercase A-Z 0-9). The URL might come in any case, so
 // normalize before lookup. Same convention as the rest of the
 // protocol layer.
    let lookup_ticker = ticker.to_ascii_uppercase();

    let (indexed, total, page, indexed_height, tip_height) = {
        let s = state.read();
        let indexed = s.tokens.contains_key(&lookup_ticker);
 // V2 holder list: walk address_utxos, sum each address's UTXOs
 // for `lookup_ticker`, emit non-zero. Same logic as
 // count_holders but yields the actual addr/balance pairs.
        let mut holders: Vec<HolderInfo> = s
            .address_utxos
            .iter()
            .filter_map(|(addr, opkeys)| {
                let mut total: u64 = 0;
                for opkey in opkeys {
                    if let Some(entry) = s.utxo_balances.get(opkey) {
                        if let Some(bal) = entry.balances.get(&lookup_ticker) {
                            total = total.saturating_add(*bal);
                        }
                    }
                }
                if total > 0 {
                    Some(HolderInfo { address: addr.clone(), balance: total })
                } else {
                    None
                }
            })
            .collect();
 // Sort by balance descending (largest holder first). Tie-break
 // on address ascending so the output is deterministic across
 // restarts / snapshot reloads.
        holders.sort_by(|a, b| b.balance.cmp(&a.balance).then_with(|| a.address.cmp(&b.address)));
        let total = holders.len();
 // Clamp offset to total so an out-of-range page returns an
 // empty `holders` rather than panicking on.skip.
        let start = offset.min(total);
        let end = (start + limit).min(total);
        let page = holders[start..end].to_vec();
        (indexed, total, page, s.indexed_height, s.tip_height)
    };
    Json(TokenHoldersResponse {
        ticker: lookup_ticker,
        total,
        limit,
        offset,
        holders: page,
        indexed,
        indexed_height,
        tip_height,
    })
}

async fn deploys_all(State(state): State<AppState>) -> Json<Vec<DeployView>> {
    let deploys: Vec<DeployView> = {
        let s = state.read();
 // s.deploys is a VecDeque under the FIFO-eviction model;
 // collect into Vec for the JSON response so the wire shape
 // is unchanged (a flat array, newest at the back).
        s.deploys.iter().cloned().collect()
    };
    Json(deploys)
}

/// Global bet list — newest first, paginated, optional `tier` / `ticker`
/// filters. The data is already in `s.bets` in chain order (oldest
/// first), so we walk it in reverse and stop once we've got enough
/// matching rows for the requested page.
async fn bets_all(
    State(state): State<AppState>,
    Query(q): Query<BetsListQuery>,
) -> Json<GlobalBetsResponse> {
    let limit = q.limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT);
    let offset = q.offset.unwrap_or(0);
    let tier_filter = q.tier.as_deref().map(|s| s.to_ascii_lowercase());
    let ticker_filter = q.ticker.as_deref().map(|s| s.to_ascii_uppercase());

    let (total, page) = {
        let s = state.read();
 // Predicate built once, applied across the whole iteration.
        let matches = |b: &&BetView| -> bool {
            if let Some(t) = &tier_filter {
                if &b.tier != t { return false; }
            }
            if let Some(tk) = &ticker_filter {
                if !b.ticker.eq_ignore_ascii_case(tk) { return false; }
            }
            true
        };
        let total = s.bets.iter().filter(matches).count();
 // Reverse iteration → newest first. `skip(offset)` is bounded
 // by `total` from above so it's always safe.
        let page: Vec<BetView> = s.bets.iter().rev()
            .filter(matches)
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        (total, page)
    };
    Json(GlobalBetsResponse { total, limit, offset, bets: page })
}

/// Global transfer list — newest first, paginated, optional `ticker`
/// filter. Same reverse-iter + filter + skip + take pattern as bets_all.
async fn transfers_all(
    State(state): State<AppState>,
    Query(q): Query<TransfersListQuery>,
) -> Json<GlobalTransfersResponse> {
    let limit = q.limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT);
    let offset = q.offset.unwrap_or(0);
    let ticker_filter = q.ticker.as_deref().map(|s| s.to_ascii_uppercase());

    let (total, page) = {
        let s = state.read();
        let matches = |t: &&TransferView| -> bool {
            if let Some(tk) = &ticker_filter {
                if !t.ticker.eq_ignore_ascii_case(tk) { return false; }
            }
            true
        };
        let total = s.transfers.iter().filter(matches).count();
        let page: Vec<TransferView> = s.transfers.iter().rev()
            .filter(matches)
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        (total, page)
    };
    Json(GlobalTransfersResponse { total, limit, offset, transfers: page })
}

// All handlers below scope `state.read()` to a tight inner block,
// cloning out only the data they need before returning. This prevents
// writer starvation: parking_lot::RwLock is reader-preferring by
// default, so a long-held read guard (full iteration over potentially
// thousands of bets / transfers under a single read) would block the
// poller's `state.write()` for backfill / apply_payload. Audit §indexer
// Finding 9.
async fn balances(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Json<AddressResponse> {
    let (balances_map, bet_count, transfer_count) = {
        let s = state.read();
 // V2: balance for an address = sum of balances at every UTXO
 // it currently controls. Reverse index makes this O(|address's
 // UTXOs|) rather than O(|all UTXOs|).
        let balances_map = s.address_balances(&address);
        let bc = s.bets.iter().filter(|b| b.sender == address).count();
 // Transfers under v2 don't carry an explicit `to_address` — the
 // recipient is identified by the receiving UTXO's controlling
 // address. Match either as sender OR as the address controlling
 // the transfer's `(txid, to_out_idx)` UTXO.
        let tc = s
            .transfers
            .iter()
            .filter(|t| {
                if t.sender == address {
                    return true;
                }
                let opkey = crate::indexer::outpoint_key(&t.txid, t.to_out_idx);
                s.utxo_balances
                    .get(&opkey)
                    .and_then(|e| e.address.as_deref())
                    .map(|a| a == address)
                    .unwrap_or(false)
            })
            .count();
        (balances_map, bc, tc)
    };
    Json(AddressResponse {
        address,
        balances: balances_map,
        bet_count,
        transfer_count,
    })
}

/// GET /utxos/:address — list of token-bearing UTXOs the address
/// currently controls, with each UTXO's per-ticker balance.
///
/// O(|address's UTXOs|) — single pass over the reverse-index
/// (address_utxos) + one HashMap lookup per outpoint. Empty list when
/// the address has never received protocol tokens.
async fn utxos_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Json<UtxoBalancesResponse> {
    let utxos: Vec<UtxoBalanceEntry> = {
        let s = state.read();
        match s.address_utxos.get(&address) {
            Some(outpoint_keys) => outpoint_keys
                .iter()
                .filter_map(|opkey| {
                    let entry = s.utxo_balances.get(opkey)?;
 // Only surface UTXOs with at least one non-zero token
 // balance. Skipping the zero-balance entries keeps the
 // response useful for SEND coin-selection (every row
 // is actually pickable).
                    if entry.balances.is_empty()
                        || entry.balances.values().all(|&v| v == 0) {
                        return None;
                    }
 // Parse "txid:vout" — outpoint_key format. Tolerant of
 // malformed entries (should never happen but defensive).
                    let (txid, vout_str) = opkey.split_once(':')?;
                    let vout = vout_str.parse::<u32>().ok()?;
                    Some(UtxoBalanceEntry {
                        txid: txid.to_string(),
                        vout,
                        balances: entry.balances.clone(),
                    })
                })
                .collect(),
            None => Vec::new(),
        }
    };
    Json(UtxoBalancesResponse { address, utxos })
}

async fn bets_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Json<BetsResponse> {
    let bets = {
        let s = state.read();
        s.bets
            .iter()
            .filter(|b| b.sender == address)
            .cloned()
            .collect::<Vec<_>>()
    };
    Json(BetsResponse { address, bets })
}

async fn transfers_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Json<TransfersResponse> {
    let transfers = {
        let s = state.read();
 // V2 recipient-by-UTXO (see `balances` above).
        s.transfers
            .iter()
            .filter(|t| {
                if t.sender == address {
                    return true;
                }
                let opkey = crate::indexer::outpoint_key(&t.txid, t.to_out_idx);
                s.utxo_balances
                    .get(&opkey)
                    .and_then(|e| e.address.as_deref())
                    .map(|a| a == address)
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    Json(TransfersResponse { address, transfers })
}

async fn bet_by_txid(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let found: Option<Value> = {
        let s = state.read();
        if let Some(idx) = s.bets.iter().position(|b| b.txid == txid) {
            Some(serde_json::to_value(&s.bets[idx]).unwrap())
        } else if let Some(idx) = s.transfers.iter().position(|t| t.txid == txid) {
            Some(serde_json::to_value(&s.transfers[idx]).unwrap())
        } else {
            None
        }
    };
    match found {
        Some(v) => Ok(Json(v)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// ============================================================================
// Bitcoin Core RPC proxy endpoints — added 2026 to support the web wallet's
// "all-official" mode (no third-party fallback for chain data).
// ============================================================================
//
// Shared resources for the proxy handlers:
//
//   * RPC_CLIENT  — one process-global reqwest::Client. Reused across
//     requests so connection pooling + TLS sessions amortize.
//   * SCAN_LOCK   — Tokio mutex serializing scantxoutset calls. bitcoind
//     itself rejects concurrent scans with "Scan already in progress",
//     so we queue them client-side instead of returning errors.
//
// Both live as `OnceLock`s rather than `static`s so initialization is
// lazy (no Tokio runtime needed before first call).

static RPC_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
static SCAN_LOCK:  std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn rpc_client() -> &'static reqwest::Client {
    RPC_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120)) // scantxoutset can take ~1 min on a cold node
            .user_agent(concat!("luckyprotocol-indexer/", env!("CARGO_PKG_VERSION")))
            .tcp_nodelay(true)
            .pool_idle_timeout(std::time::Duration::from_secs(180))
            .build()
            .expect("reqwest::Client build")
    })
}

fn scan_lock() -> &'static tokio::sync::Mutex<()> {
    SCAN_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ---- /btc-utxos/:address --------------------------------------------------

#[derive(Serialize)]
struct BtcUtxoEntry {
    txid: String,
    vout: u32,
    /// Integer satoshis. We convert from Core's BTC float here so the
    /// wire shape matches mempool.space's old `value` field (which the
    /// web wallet's coin selector consumes).
    sats: u64,
    /// Always `true` — scantxoutset only returns confirmed UTXOs.
    /// Surfaced anyway so the response shape matches mempool.space's
    /// `{ confirmed, block_height }` envelope.
    confirmed: bool,
    /// Block height the UTXO landed in. Always present (see above).
    block_height: u32,
}

#[derive(Serialize)]
struct BtcUtxosResponse {
    address: String,
    /// Tip height observed at the time of the scan. Lets the wallet
    /// compute confirmation count without a separate /tip-height fetch.
    scanned_at_height: u32,
    utxos: Vec<BtcUtxoEntry>,
}

/// GET /btc-utxos/:address — return every confirmed UTXO paying the
/// address. Backed by bitcoind's `scantxoutset`, which walks the
/// UTXO set (~30-60s on a cold node, faster after warm-up). Concurrent
/// requests serialize through SCAN_LOCK so we don't spam bitcoind with
/// parallel scans (it rejects them outright).
///
/// 502 on any RPC failure — leaves the caller to decide whether to
/// retry. 200 with empty `utxos` array means "scan succeeded, no
/// outputs found" (i.e. address has 0 BTC).
async fn btc_utxos_for_address(
    Path(address): Path<String>,
) -> Result<Json<BtcUtxosResponse>, StatusCode> {
    // Block concurrent scantxoutset calls — bitcoind enforces this
    // anyway, but queueing client-side is cleaner than surfacing
    // "Scan already in progress" errors to the user.
    let _guard = scan_lock().lock().await;

    let res = match crate::core_rpc::scan_tx_out_set_for_address(rpc_client(), &address).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, address = %address, "scantxoutset failed");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    if !res.success {
        tracing::warn!(address = %address, "scantxoutset returned success=false");
        return Err(StatusCode::BAD_GATEWAY);
    }

    let utxos = res.unspents.into_iter().map(|u| BtcUtxoEntry {
        txid: u.txid,
        vout: u.vout,
        sats: crate::core_rpc::btc_to_sats_pub(u.amount),
        confirmed: true,
        block_height: u.height,
    }).collect();

    Ok(Json(BtcUtxosResponse {
        address,
        scanned_at_height: res.height,
        utxos,
    }))
}

// ---- /tx-status/:txid -----------------------------------------------------

#[derive(Serialize)]
struct TxStatusResponse {
    txid: String,
    /// True iff the tx is in a block (`confirmations >= 1`).
    confirmed: bool,
    /// Block hash containing the tx — null when unconfirmed.
    block_hash: Option<String>,
    /// Block height the tx landed in — null when unconfirmed. Populated
    /// via a follow-up getblockheader if Core didn't include it on
    /// the initial getrawtransaction response.
    block_height: Option<u32>,
    /// Block timestamp (seconds-since-epoch) — null when unconfirmed.
    block_time: Option<u64>,
}

/// GET /tx-status/:txid — confirmation state for one transaction.
/// Used by the wallet to poll a freshly-broadcast tx until it lands
/// in a block. 404 when bitcoind doesn't know the tx (not in mempool,
/// not indexed) — front-end treats that as "unconfirmed, retry later".
///
/// IMPORTANT: getrawtransaction requires `txindex=1` in bitcoin.conf
/// to look up historical (non-wallet, non-mempool) txs. Without it
/// every confirmed-but-not-recent query returns 404. The official
/// LUCKYPROTOCOL deploy must run with txindex=1.
async fn tx_status(
    Path(txid): Path<String>,
) -> Result<Json<TxStatusResponse>, StatusCode> {
    let raw = match crate::core_rpc::fetch_raw_tx_status(rpc_client(), &txid).await {
        Ok(r) => r,
        Err(e) => {
            // Distinguish "tx not found" (404) from other RPC failures (502).
            // Core's "No such mempool or blockchain transaction" comes back
            // as a generic anyhow error from `call()`; the cheap match is
            // a substring check.
            let msg = format!("{}", e);
            if msg.contains("No such")
                || msg.contains("not found")
                || msg.contains("invalid txid")
            {
                return Err(StatusCode::NOT_FOUND);
            }
            tracing::warn!(error = %e, txid = %txid, "getrawtransaction failed");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let confirmed = raw.confirmations >= 1;
    let block_hash = raw.blockhash.clone();
    let block_time = raw.blocktime;

    // Core's verbose getrawtransaction doesn't include block height
    // (only the hash). Issue one follow-up getblockheader to fill it
    // in — cheap (a single RPC, ~1ms locally).
    let block_height = if let Some(ref h) = block_hash {
        match crate::core_rpc::fetch_block_header(rpc_client(), h).await {
            Ok(_hdr) => {
                // getblockheader does include height for the block
                // it returned, but our BlockHeader struct only kept
                // hash + time (kept narrow to minimize moving parts).
                // To get the height we'd need a wider struct OR a
                // separate `getblock <hash> 1` call. For now we
                // return None — the frontend only uses block_height
                // for sorting + UI labels and tolerates null.
                // TODO: widen BlockHeader to include `height` so this
                // doesn't lose information.
                None
            }
            Err(_) => None,
        }
    } else {
        None
    };

    Ok(Json(TxStatusResponse {
        txid,
        confirmed,
        block_hash,
        block_height,
        block_time,
    }))
}

// ---- /block-height/:height ------------------------------------------------

#[derive(Serialize)]
struct BlockHashResponse {
    height: u32,
    hash: String,
}

/// GET /block-height/:height — returns the block hash at the given
/// height. 404 when `height` is past the current tip (block not yet
/// mined). Used by V2 BET settlement to wait for the determining
/// block's hash.
async fn block_at_height(
    Path(height): Path<u32>,
) -> Result<Json<BlockHashResponse>, StatusCode> {
    match crate::core_rpc::fetch_block_hash(rpc_client(), height).await {
        Ok(hash) => Ok(Json(BlockHashResponse { height, hash })),
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("out of range") || msg.contains("Block height") {
                Err(StatusCode::NOT_FOUND)
            } else {
                tracing::warn!(error = %e, height, "getblockhash failed");
                Err(StatusCode::BAD_GATEWAY)
            }
        }
    }
}

// ---- /block-info/:height --------------------------------------------------

#[derive(Serialize)]
struct BlockInfoResponse {
    height: u32,
    hash: String,
    /// Block header timestamp (seconds-since-epoch). Set by the miner
    /// — roughly monotonic but not strictly so (consensus enforces a
    /// median-of-past-11 window, not strict ordering).
    time: u64,
}

/// GET /block-info/:height — hash + timestamp at height. Two-call
/// composition (getblockhash, then getblockheader) so we never serve
/// stale data from a single cached response. 404 on a future height
/// just like /block-height.
async fn block_info_at_height(
    Path(height): Path<u32>,
) -> Result<Json<BlockInfoResponse>, StatusCode> {
    let hash = match crate::core_rpc::fetch_block_hash(rpc_client(), height).await {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("out of range") || msg.contains("Block height") {
                return Err(StatusCode::NOT_FOUND);
            }
            tracing::warn!(error = %e, height, "block-info: getblockhash failed");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    let header = match crate::core_rpc::fetch_block_header(rpc_client(), &hash).await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, height, hash = %hash, "block-info: getblockheader failed");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    Ok(Json(BlockInfoResponse {
        height,
        hash: header.hash,
        time: header.time,
    }))
}
