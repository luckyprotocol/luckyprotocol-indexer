// Esplora REST chain source — backfill from --start-height up to tip,
// then poll for new blocks. Parses every OP_RETURN per block and dispatches
// to the indexer state.

use anyhow::{anyhow, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::{Network, TxMerkleNode, Txid};
use parking_lot::RwLock;
use serde::Deserialize;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::indexer::IndexerState;
use crate::protocol::parse_payload;

// LUCKYPROTOCOL is mainnet-only. testnet/signet/regtest were dropped from the
// indexer in lockstep with the desktop app — the protocol activation
// height + fixed-supply token economy only make sense on a single
// canonical chain, and supporting test networks bloated the surface for
// a feature nobody used.
const MAINNET_BASE_URL: &str = "https://mempool.space/api";

/// Public Esplora-compatible fallback hosts. Tried in order AFTER
/// Alchemy (if configured) and AFTER the user-provided / default
/// `--esplora` URL. Mirror of the desktop app's fallback chain in
/// `protocol/chain.js`. Without this, a single mempool.space outage
/// stalls the indexer; with it, blockstream.info picks up the slack.
/// blockstream.info exposes the same Esplora REST shape as
/// mempool.space — `/blocks/tip/height`, `/block-height/{h}`,
/// `/block/{hash}/txs[/{idx}]` are all compatible. CORS is open
/// for both. They use different anycast networks so a regional
/// mempool.space drop usually doesn't affect blockstream and vice
/// versa.
const PUBLIC_FALLBACK_BASES: &[&str] = &[
 // Primary fallback — anycast, globally reachable, runs the same
 // Esplora REST shape as mempool.space.
    "https://blockstream.info/api",
 // Community-run public Esplora mirrors. Both confirmed reachable
 // from networks that block / drop mempool.space (e.g. some CN
 // ISPs). They run the same Esplora REST shape so no client-side
 // changes beyond adding the URL.
    "https://mempool.emzy.de/api",
    "https://mempool.bitcoin-21.org/api",
];

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-request timeout when hitting Alchemy specifically. Alchemy's
/// Bitcoin-Esplora endpoint can silently stall during throttling —
/// returning 200 OK but taking 30+ seconds per page — which previously
/// pinned the pipeline to alchemy and starved the mempool/blockstream
/// fallback. Capping alchemy at 10s lets a slow response fail fast
/// and slide to the next base, trading a slightly longer worst-case
/// per-page latency for a 5-10x better backfill throughput when the
/// alchemy free tier is being rate-shaped.
const ALCHEMY_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP retries for transient errors (Esplora 5xx, network drops). Each
/// retry doubles the delay starting from `HTTP_RETRY_BASE_MS`.
const HTTP_MAX_RETRIES: u32 = 3;
const HTTP_RETRY_BASE_MS: u64 = 400;

/// Hard ceiling on a 429 `Retry-After` honor — if a server tells us to
/// wait an hour we'd rather fall through to the next base than block
/// the entire pipeline. 60s lets short-term rate limits resolve while
/// preventing a misconfigured server from indefinitely stalling us.
const MAX_RETRY_AFTER_SECS: u64 = 60;

/// Max in-flight tx-page fetches PER BLOCK. Each page returns 25
/// fully-decoded txs (`/block/:hash/txs[/:start_index]`).
/// History:
/// * 8 — original, sized for mempool.space's ~10 RPS free-tier
/// cap from one IP.
/// * 32 — bumped 2026-05 on the assumption the sidecar always runs
/// against Alchemy's enterprise tier (`--alchemy-key`). REVERTED
/// 2026-05-11 after observing the 128-concurrent peak (4 × 32)
/// reliably 429s free / starter Alchemy keys AND cascades through
/// to mempool.space (ConnectionReset) AND blockstream.info (429
/// + TLS handshake EOF on retry). Symptom: backfill stalls for
/// minutes on big blocks (≥3000 txs needing 120+ pages) every
/// time the indexer warm-restarts.
/// * 8 — was the conservative default.
/// * 10 — empirically-tuned bump. Free-tier Alchemy reliably
/// sustains ~1500 CU/sec; each Esplora `/block/H/txs/N` page is
/// ~60 CU. At 16 in-flight (old default) the steady-state burn
/// was ~1000 CU/sec (~33% under cap). At 20 in-flight (BLOCK=2
/// × TX=10) we project ~1500 CU/sec — right at the sustained
/// limit, with no excursion into burst territory. Expected
/// per-block speedup: ~20-25%.
/// If you've confirmed your endpoint can absorb more, raise this
/// locally; 10 is the safe shared default.
const TX_FETCH_CONCURRENCY: usize = 10;

/// Number of blocks whose data is being fetched IN PARALLEL ahead of
/// the apply-state loop. State mutations (`apply_payload`) MUST run
/// in chain order (a SEND that depends on a prior SEND's debit must
/// see the updated balance), so we use `stream::buffered` (not
/// `buffer_unordered`) — futures run concurrently but yield in the
/// original order. The sequential apply loop drains them as they
/// complete.
///
/// History:
/// * 2 — original conservative default (2 × 10 = 20 in-flight,
///   sized to fit free-tier Alchemy's ~1500 CU/sec sustained cap).
/// * 4 — bumped 2026-05-16 after benchmarking against the BITAI
///   miner indexer (which uses concurrency 4 on a similar Esplora
///   fetch path and reports 5× speedup over its pre-pipeline
///   baseline). Effective peak now 4 × 10 = 40 in-flight, ~3000
///   CU/sec at sustained burn. Free-tier Alchemy will see brief
///   429s during cold scan; the HTTP retry helper handles them
///   without user impact (per-host backoff + multi-endpoint
///   failover). Paid Alchemy / private Esplora users get the
///   full ~2× cold-scan speedup with no rate-limit churn.
///   The previous 2x in-flight gain was bottlenecked on
///   per-block serialization latency (`/block-hash` → `/block`
///   → N × tx pages is inherently sequential within one block);
///   bumping cross-block concurrency is where the remaining
///   wall-clock headroom lives.
const BLOCK_FETCH_CONCURRENCY: usize = 4;

/// Build a reqwest::Client tuned for the indexer's bursty backfill
/// workload. Encapsulates HTTP/2 + connection-pool + TCP knobs so all
/// callsites (run_poller, validate_snapshot_against_canonical) share
/// the same configuration.
/// Why each knob:
/// * `tcp_nodelay(true)` — disables Nagle's algorithm. Our requests
/// are tiny GETs (a few KB JSON response), and Nagle adds ~40ms
/// of latency by buffering small TCP sends. With 128 concurrent
/// reqs that's 5+ seconds of pure Nagle overhead per block.
/// * `pool_idle_timeout(180s)` — keeps a single TCP+TLS connection
/// to Alchemy / mempool.space warm for 3 min between bursts. Each
/// fresh TLS handshake is ~50-100ms; dodging it saves real time
/// on the 30s incremental polls.
/// * `http2_adaptive_window(true)` — lets the HTTP/2 flow-control
/// window grow with bandwidth-delay product. Without it the fixed
/// 65535-byte initial window throttles large block-page responses.
/// * `http2_keep_alive_interval(30s) + while_idle(true)` — sends a
/// PING frame every 30s on idle connections so intermediaries
/// don't drop them mid-poll-window. Cheap insurance.
/// HTTP/2 itself is auto-negotiated via ALPN over TLS — reqwest with
/// the `rustls-tls` feature offers `h2` in its ALPN list and any
/// modern Esplora server (mempool.space, blockstream.info, Alchemy)
/// accepts it. So our 128 concurrent reqs multiplex over ~1-2 TCP
/// connections, not 128 separate sockets.
fn build_http_client() -> Result<reqwest::Client> {
    let c = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(concat!("luckyprotocol-indexer/", env!("CARGO_PKG_VERSION")))
        .tcp_nodelay(true)
        .pool_idle_timeout(Duration::from_secs(180))
        .http2_adaptive_window(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_while_idle(true)
        .build()?;
    Ok(c)
}

/// Reorg-detection horizon — on every poll, we re-fetch hashes for the
/// last K indexed blocks and compare against our snapshot. If any hash
/// diverges, we roll back state past the divergence point and re-scan
/// forward. K=12 covers ~2 hours on mainnet, well past the deepest
/// historic reorg (10 blocks in the 2013 0.7→0.8 fork; routine reorgs
/// are 1-2 blocks). Running cost: 12 extra `/block-height/{h}` GETs
/// per poll, each a few hundred bytes — negligible.
const REORG_HORIZON: u32 = 12;

/// Reorg-storm circuit breaker. If the indexer detects this many reorgs
/// inside REORG_STORM_WINDOW, the poll loop trips and pauses for
/// REORG_STORM_COOLDOWN before resuming. A genuine chain experiences
/// at most a handful of 1-2 block reorgs per day; >5 reorgs in 5
/// minutes is either an Esplora source serving inconsistent data
/// (CDN cache pollution) or an active 51% attack — either way,
/// continuing to thrash the snapshot ring is worse than pausing.
const REORG_STORM_THRESHOLD: usize = 5;
const REORG_STORM_WINDOW: Duration = Duration::from_secs(300);    // 5 min
const REORG_STORM_COOLDOWN: Duration = Duration::from_secs(600);  // 10 min

pub fn parse_network(s: &str) -> Result<Network> {
    match s.to_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        other => Err(anyhow!(
            "{} not supported — LUCKYPROTOCOL indexer is mainnet-only", other
        )),
    }
}

pub fn default_esplora_for(_net: Network) -> &'static str {
 // Network arg is kept for API symmetry with prior multi-net builds;
 // LUCKYPROTOCOL is mainnet-only so the answer is always mempool.space's
 // mainnet endpoint.
    MAINNET_BASE_URL
}

#[derive(Debug, Deserialize, Clone)]
pub struct EsploraVin {
 /// Txid of the previous tx whose output this vin is spending. Always
 /// populated EXCEPT for coinbase txs (which have no real previous
 /// output). Required by v2 protocol to identify spent token UTXOs.
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
 /// Value in sats. For `prevout`-context this is what `resolve_sender`
 /// uses to pick the largest-contributor address; for vout-context
 /// it's the output's value.
 #[serde(default)]
    pub value: u64,
 /// Hex-encoded raw script. Present on the `/block/:hash/txs[/idx]`
 /// paginated response (current-tx outputs); absent / empty when
 /// only a `prevout` slice is being deserialized. We use it to
 /// extract the OP_RETURN payload without a separate raw-hex fetch.
 #[serde(default)]
    pub scriptpubkey: String,
 /// Esplora's classified script type — "op_return", "v0_p2wpkh",
 /// "p2sh", etc. Lets the OP_RETURN-detection fast-path skip non-
 /// OP_RETURN outputs without parsing the hex.
 #[serde(default)]
    pub scriptpubkey_type: String,
}

/// Full tx as returned by `GET /block/:hash/txs[/:start_index]`.
/// One Esplora call yields 25 of these — replaces 25 individual
/// `/tx/:txid/hex` calls AND the per-bet `/tx/:txid` lookup that
/// was previously needed to resolve the sender. Net effect: ~25×
/// fewer HTTP calls per block on initial backfill.
#[derive(Debug, Deserialize, Clone)]
pub struct EsploraTxFull {
    pub txid: String,
    pub vin: Vec<EsploraVin>,
    pub vout: Vec<EsploraVout>,
}

/// Block header summary returned by `GET /block/:hash`. We use:
/// * `tx_count` — to know how many pages to issue in parallel
/// * `merkle_root` — to verify the tx list Esplora returned actually
/// belongs to this block (anti-poisoning check, see
/// `verify_block_merkle_root`).
/// Esplora's field name is `merkle_root` (mempool.space / blockstream).
/// Older Electrum-style servers used `merkleroot`; alias both so the
/// indexer works against either.
#[derive(Debug, Deserialize)]
struct EsploraBlockHeader {
 #[serde(default)]
    tx_count: usize,
 #[serde(default, alias = "merkleroot")]
    merkle_root: String,
}

/// Optional Alchemy API key, set ONCE at boot from main.rs's `--alchemy-key`.
/// When set, every HTTP fetch tries Alchemy's Bitcoin Esplora endpoint
/// first and falls back to the configured Esplora URL on failure. Mirrors
/// the desktop app's chain.rs::esplora_bases pattern.
pub static ALCHEMY_KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Build the ordered list of Esplora bases for an HTTP fetch:
/// 1. Alchemy (if a key is configured) — private RPC, fastest, no
/// regional drops, no rate limit at enterprise tier
/// 2. User-supplied / default Esplora URL — typically mempool.space
/// 3. PUBLIC_FALLBACK_BASES — blockstream.info etc., for resilience
/// when both private + primary public hosts are down
/// Each base is tried in order with HTTP_MAX_RETRIES per base. A 429
/// from any single base does NOT exhaust all retries on it (we honor
/// `Retry-After` once then fall through to the next base — rate-limited
/// hosts shouldn't tie up the pipeline).
fn esplora_bases(default_base: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(2 + PUBLIC_FALLBACK_BASES.len());
    if let Some(key) = ALCHEMY_KEY.get() {
        if !key.is_empty() {
            out.push(format!("https://bitcoin-mainnet.g.alchemy.com/v2/{}", key));
        }
    }
 // PUBLIC_FALLBACK_BASES come BEFORE the default base. mempool.space
 // (our usual default) is unreachable from some regions; trying it
 // first wastes a per-request timeout on every fall-through before
 // we get to blockstream.info, which is anycast and globally
 // reachable.
    for fb in PUBLIC_FALLBACK_BASES {
        if !out.iter().any(|b| b == fb) {
            out.push(fb.to_string());
        }
    }
    if !out.iter().any(|b| b == default_base) {
        out.push(default_base.to_string());
    }
    out
}

/// Outcome of a single GET attempt — distinguishes "this host is
/// rate-limiting us, fall through" from "transient server error,
/// retry within this host" so the caller can route correctly.
enum HttpOnceResult {
    Ok(reqwest::Response),
 /// 429 — server told us to back off. `Retry-After` (capped at
 /// MAX_RETRY_AFTER_SECS) included so the caller can wait
 /// appropriately before falling through to the next base.
    RateLimited { retry_after: Duration, reason: String },
 /// 5xx / network error / 4xx — retry on the same base for
 /// transient, fall through after retries exhausted.
    Err(anyhow::Error),
}

/// Single-attempt GET + status classification. Returns RateLimited on
/// 429 (caller should wait then SKIP this base), Err on any other
/// non-2xx (caller retries within this base).
/// `per_request_timeout` lets the caller shorten the wait for known-
/// slow bases (currently Alchemy). On free tier, alchemy can stall
/// 30+ seconds on a rate-shaped page; we cap that at 10s so the
/// pipeline doesn't pin to alchemy when mempool/blockstream is
/// serving the same data instantly.
async fn http_get_once(
    client: &reqwest::Client,
    url: &str,
    per_request_timeout: Duration,
) -> HttpOnceResult {
    let req = client.get(url).timeout(per_request_timeout);
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return HttpOnceResult::Err(anyhow!(
 // Both the explicit URL and reqwest::Error's Debug-formatted
 // representation (which embeds `url: "..."` in its internal
 // state) carry the Alchemy API key when this fetch was aimed
 // at Alchemy. Mask both before they enter the error chain.
            "GET {} failed: {}",
            crate::indexer::mask_secrets(url),
            crate::indexer::mask_secrets(&format!("{:?}", e))
        )),
    };
    let status = resp.status();
    if status.is_success() {
        return HttpOnceResult::Ok(resp);
    }
    if status.as_u16() == 429 {
 // Honor Retry-After — RFC 7231 says it's either an HTTP-date
 // or a delta-seconds integer. We only handle the integer
 // form (mempool.space / Cloudflare / Alchemy all use it).
 // Cap at MAX_RETRY_AFTER_SECS so a hostile server can't park
 // us indefinitely. Default to 5s if missing or unparseable.
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|s| s.min(MAX_RETRY_AFTER_SECS))
            .unwrap_or(5);
        return HttpOnceResult::RateLimited {
            retry_after: Duration::from_secs(retry_after),
 // Mask any Alchemy key in the URL before it lands in `reason`
 // — `reason` flows through `last_err` and eventually into
 // tracing::warn! / tracing::error! / push_error, all of which
 // are user-visible (log file + /state JSON). Without masking
 // here, every Alchemy 429 was writing the user's API key
 // into LUCKYPROTOCOL.log on each rate-limit attempt.
            reason: format!("{} → 429 (Retry-After {}s)", crate::indexer::mask_secrets(url), retry_after),
        };
    }
 // Mask URL for the same reason as above — this Err() variant gets
 // captured into last_err and surfaces in higher-level tracing /
 // diagnostic events.
    HttpOnceResult::Err(anyhow!("GET {} returned {}", crate::indexer::mask_secrets(url), status))
}

/// GET a path with Alchemy → Esplora fallback + per-base retry. Tries
/// each base in order; for each base, retries up to HTTP_MAX_RETRIES
/// times with exponential backoff. Returns the first successful
/// response or the last error.
/// `path` should start with `/` (e.g. "/blocks/tip/height", "/tx/.../hex").
async fn http_get_text(
    client: &reqwest::Client,
    default_base: &str,
    path: &str,
) -> Result<String> {
    let bases = esplora_bases(default_base);
    let mut last_err: Option<anyhow::Error> = None;
    for base in &bases {
 // Short per-request timeout across every base. Users on a
 // network that can't reach mempool.space (CN / restricted
 // regions) would otherwise sink 30s per failed page waiting
 // for the TCP connect to time out — turning a 100-block
 // backfill into a 30-min wall-clock. 10s is generous against
 // a healthy esplora (typical page = 1-3s) and surfaces
 // unreachable hosts quickly enough to fall through to the
 // next base in the same retry budget.
        let per_request_timeout = ALCHEMY_REQUEST_TIMEOUT;
 // Sticky retry on alchemy: when the user has paid for alchemy
 // (their key is configured), 429s there usually mean a short
 // burst limit that clears in seconds — we'd rather wait it out
 // than dump traffic onto blockstream/mempool public mirrors.
 // For other bases the historical fast-fail behavior is kept so
 // a permanently-down public host doesn't pin the pipeline.
        let is_alchemy = base.contains("alchemy.com");
        let mut rate_limited_on_this_base = false;
        for attempt in 0..=HTTP_MAX_RETRIES {
            if attempt > 0 {
                let delay = HTTP_RETRY_BASE_MS << (attempt - 1);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            match http_get_once(client, &url, per_request_timeout).await {
                HttpOnceResult::Ok(resp) => match resp.text().await {
                    Ok(body) => return Ok(body),
                    Err(e) => {
 // `e` here is reqwest::Error from .text() — Debug-format
 // can include the URL the body was being read from. Mask
 // before stashing in last_err (which surfaces upstream
 // through tracing + push_error).
                        last_err = Some(anyhow!("body read: {}",
                            crate::indexer::mask_secrets(&format!("{:?}", e))));
                    }
                },
                HttpOnceResult::RateLimited { retry_after, reason } => {
                    tokio::time::sleep(retry_after).await;
                    last_err = Some(anyhow!(reason.clone()));
                    if is_alchemy {
 // Stay sticky on alchemy: consume an attempt
 // and loop back so the next iteration retries
 // alchemy itself. Only after HTTP_MAX_RETRIES
 // 429s in a row do we fall through to public
 // mirrors. Comment kept verbose because this
 // policy intentionally trades a few extra
 // seconds of alchemy waiting for ZERO public-
 // mirror traffic when the user's paid endpoint
 // is healthy.
                        tracing::debug!(reason = %reason, attempt, "alchemy rate-limited; sticky-retrying");
                        continue;
                    } else {
                        tracing::debug!(reason = %reason, "rate-limited; sleeping then falling to next base");
                        rate_limited_on_this_base = true;
                        break;
                    }
                }
                HttpOnceResult::Err(e) => { last_err = Some(e); }
            }
        }
        let _ = rate_limited_on_this_base; // already routed above
 // exhausted retries on this base — fall to next
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no esplora base configured")))
}

async fn http_get_json<T: for<'de> serde::Deserialize<'de>>(
    client: &reqwest::Client,
    default_base: &str,
    path: &str,
) -> Result<T> {
    let body = http_get_text(client, default_base, path).await?;
    serde_json::from_str::<T>(&body)
        .with_context(|| format!("JSON parse failed for {}", path))
}

/// Binary GET variant of `http_get_text`. Same Alchemy → public-mirror
/// fallback + per-base retry semantics, but returns the raw response
/// bytes (no UTF-8 decode). Used by `fetch_block_raw_bytes` for the
/// `/block/:hash/raw` endpoint which serves the raw block as a binary
/// stream (~few MB), too large to round-trip as a UTF-8 String and not
/// representable as one anyway.
async fn http_get_bytes(
    client: &reqwest::Client,
    default_base: &str,
    path: &str,
) -> Result<Vec<u8>> {
    let bases = esplora_bases(default_base);
    let mut last_err: Option<anyhow::Error> = None;
    for base in &bases {
        let per_request_timeout = ALCHEMY_REQUEST_TIMEOUT;
        let is_alchemy = base.contains("alchemy.com");
        let mut rate_limited_on_this_base = false;
        for attempt in 0..=HTTP_MAX_RETRIES {
            if attempt > 0 {
                let delay = HTTP_RETRY_BASE_MS << (attempt - 1);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            match http_get_once(client, &url, per_request_timeout).await {
                HttpOnceResult::Ok(resp) => match resp.bytes().await {
                    Ok(body) => return Ok(body.to_vec()),
                    Err(e) => {
                        last_err = Some(anyhow!("bytes read: {}",
                            crate::indexer::mask_secrets(&format!("{:?}", e))));
                    }
                },
                HttpOnceResult::RateLimited { retry_after, reason } => {
                    tokio::time::sleep(retry_after).await;
                    last_err = Some(anyhow!(reason.clone()));
                    if is_alchemy {
                        continue;
                    } else {
                        rate_limited_on_this_base = true;
                        break;
                    }
                }
                HttpOnceResult::Err(e) => { last_err = Some(e); }
            }
        }
        let _ = rate_limited_on_this_base;
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no esplora base configured")))
}

// `poll_notify` is the external wake signal — the HTTP server's
// `POST /poll-now` handler calls `notify_one()` on this. The
// steady-state poll loop `tokio::select!`s between the normal
// `sleep(poll_secs)` and `notify.notified()`, so a front-end that
// already sees a new tip (via its own faster Esplora poll) can kick
// the sidecar awake without waiting for the next natural poll cycle.
// Notify's 1-permit semantics mean back-to-back notifications
// collapse to at most one wake — protects against multi-window /
// DoS abuse without an explicit channel.
pub async fn run_poller(
    state: Arc<RwLock<IndexerState>>,
    start_height: Option<u32>,
    poll_secs: u64,
    poll_notify: Arc<tokio::sync::Notify>,
) -> Result<()> {
    let client = build_http_client()?;

    let esplora_base = {
        let s = state.read();
        s.esplora_base.clone()
    };

 // Initial tip lookup — retry indefinitely with backoff so a
 // temporary network failure (mempool.space drop, DNS hiccup) does
 // NOT kill the poller. The earlier `?` propagation here meant a
 // single transient HTTP error at boot left the indexer with
 // tip_height = 0 forever, which the desktop UI surfaces as a stuck
 // "connecting to indexer…" overlay. With Alchemy key forwarded
 // (see sidecar.rs::start) `fetch_tip_height` falls through to it
 // automatically; this loop is a final safety net for the rare
 // case where BOTH Alchemy + mempool.space are momentarily down.
    let tip;
    {
        let mut delay_ms: u64 = 1_000;
        loop {
            match fetch_tip_height(&client, &esplora_base).await {
                Ok(t) => { tip = t; break; }
                Err(e) => {
                    tracing::warn!(error = ?e, delay_ms,
                        "initial tip fetch failed — retrying");
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
 // Exponential backoff capped at 30s — sufficient for
 // long network outages without burning CPU.
                    delay_ms = (delay_ms.saturating_mul(2)).min(30_000);
                }
            }
        }
    }
    {
        let mut s = state.write();
        s.tip_height = tip;
    }

 // Default to FULL coverage from the protocol activation height. Any
 // LUCKYPROTOCOL tx at or after LCKPROTOCOL_START_HEIGHT must be visible to
 // the indexer; capping at `tip - N` (the prior behavior) silently
 // dropped older protocol history once the chain advanced past the
 // cap. The user can still override with `--start-height` to ask
 // for a deeper or shallower window — but the default no longer
 // truncates protocol coverage.
    let backfill_from = start_height
        .unwrap_or(crate::protocol::LCKPROTOCOL_START_HEIGHT);
    let backfill_from = backfill_from.max(crate::protocol::LCKPROTOCOL_START_HEIGHT);
    let backfill_from = backfill_from.min(tip);

    tracing::info!(tip, backfill_from, "starting backfill");
    backfill_range(
        state.clone(),
        &client,
        &esplora_base,
        backfill_from,
        tip,
    )
    .await?;
 // PROTOCOL.md §12 (warm-restart hygiene) — write a snapshot at the
 // END of backfill, regardless of whether the catch-up landed on a
 // SNAPSHOT_INTERVAL_BLOCKS boundary. Without this, an indexer that
 // catches up to e.g. height 949,107 (not 12-aligned) and is closed
 // before reaching the next aligned height (949,116) loses the
 // un-snapshotted blocks. Next launch reads the OLD snapshot (last
 // 12-aligned save, e.g. 949,096) and re-scans 11 blocks → user sees
 // "PREPARING THE INDEXER" overlay on every relaunch.
    persist_current_snapshot(&state).await;
    tracing::info!(tip, "backfill complete; entering poll loop");

 // Steady-state poll loop.
 // Reorg-storm circuit breaker state: a sliding window of recent
 // reorg-detection timestamps. When length exceeds
 // REORG_STORM_THRESHOLD inside REORG_STORM_WINDOW, we pause for
 // REORG_STORM_COOLDOWN before re-engaging. Per-iteration cost is
 // O(N) where N is the number of recent reorgs (small).
    let mut recent_reorgs: std::collections::VecDeque<std::time::Instant> =
        std::collections::VecDeque::new();

 // Adaptive poll cadence:
 // * `normal_poll_secs` (= caller-provided, default 10s) when the
 // indexer is caught up to tip. Bitcoin's 10-min block time means
 // we can poll more leisurely than during catchup, but 30s was
 // visibly laggy in the UI (users see "1 block behind" for up to
 // a full poll cycle after each new block). 10s gives ~5s expected
 // lag with ~26k tip-height queries/month — well under Alchemy
 // free-tier quota and public Esplora mirror per-IP limits.
 // * `fast_poll_secs` (5s) when the indexer is behind — usually
 // because a previous `backfill_range` call failed mid-flight
 // (network blip) and left indexed_height < tip_height, OR the
 // app was just launched and is catching up from the warm-restart
 // snapshot to the current tip. 5s polls let the "PREPARING THE
 // INDEXER" overlay clear within a poll cycle of each indexed
 // block being persisted. Alchemy's paid quota handles the
 // higher cadence easily.
 // Auto-reverts to normal as soon as indexed_height == tip_height.
    let normal_poll_secs: u64 = poll_secs;
    let fast_poll_secs: u64 = 5;
    let mut current_poll_secs = normal_poll_secs;

    loop {
 // Wait until EITHER the sleep elapses OR an external wake fires.
 // The wake path lets the frontend (which already polls its own
 // tip via the wallet's chain.rs) nudge us the instant it sees a
 // tip advance, dropping observed lag from ~half the poll cadence
 // (~5s at 10s default) to one HTTP round-trip (~50ms localhost).
 // If we're mid-fetch when the notify fires, Notify stores a
 // permit and the NEXT `.notified()` call returns immediately —
 // no lost wakeups, no queued thundering herd.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(current_poll_secs)) => {}
            _ = poll_notify.notified() => {
                tracing::debug!("poll loop woken by external /poll-now");
            }
        }

 // === WATCHDOG-WRAPPED ITERATION ===
 // The body runs inside `tokio::time::timeout(POLL_ITER_WATCHDOG, ...)`
 // so any wedged HTTP/TLS/DNS call gets force-cancelled rather than
 // freezing the entire poll loop for hours. Internal `continue`
 // becomes `return None` (skip cadence update, keep current cadence);
 // normal exit returns `Some(new_cadence)`. On outer timeout we
 // record a NETWORK event so DIAGNOSTICS shows WHY the indexer
 // hiccupped, and fall through to fast cadence to retry promptly.
        let state_inner = state.clone();
        let client_inner = client.clone();
        let base_inner = esplora_base.clone();
        let iter_outcome = tokio::time::timeout(POLL_ITER_WATCHDOG, async {
            run_one_poll_iteration(
                &state_inner, &client_inner, &base_inner,
                &mut recent_reorgs, normal_poll_secs, fast_poll_secs,
            ).await
        }).await;

        match iter_outcome {
            Ok(Some(next_cadence)) => {
 // Normal exit — apply the cadence the iteration computed.
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
 // Watchdog tripped. The body was cancelled mid-flight; all
 // its reqwest futures were dropped. Record the event so the
 // user sees this in DIAGNOSTICS, and switch to fast cadence
 // so the next attempt happens sooner.
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
                        "poll iteration wedged past {}s watchdog (likely TLS/DNS hang on a single upstream); \
                         cancelled and resuming. If this repeats, switch endpoints in SETTINGS.",
                        POLL_ITER_WATCHDOG.as_secs()
                    ),
                });
                current_poll_secs = fast_poll_secs;
            }
        }
    }
}

/// Single poll-loop iteration extracted so the outer loop can wrap it
/// in `tokio::time::timeout` cleanly. Returns:
/// - `Some(next_cadence)` on normal completion — caller updates the
///   poll interval.
/// - `None` on a `continue`-like early exit (transient skip — tip
///   regression, reorg-storm cooldown, reorg-probe failure, etc.);
///   caller keeps the current cadence.
/// Cancel-safe: every `state.write()` block is sync (parking_lot,
/// no awaits inside the guard) so cancelling the outer future never
/// strands a half-mutated state.
async fn run_one_poll_iteration(
    state: &Arc<RwLock<IndexerState>>,
    client: &reqwest::Client,
    esplora_base: &str,
    recent_reorgs: &mut std::collections::VecDeque<std::time::Instant>,
    normal_poll_secs: u64,
    fast_poll_secs: u64,
) -> Option<u64> {
        let cur_tip = match fetch_tip_height(client, esplora_base).await {
            Ok(h) => h,
            Err(e) => {
                let msg = format!("{:?}", e);
                tracing::warn!(error = %crate::indexer::mask_secrets(&msg), "tip poll failed; will retry");
                state.write().push_error(crate::indexer::ErrorEvent {
                    at: crate::indexer::now_unix(),
                    kind: crate::indexer::ErrorKind::Network,
                    host: None,
                    height: None,
                    detail: format!("tip poll failed across all fallback hosts: {}",
                        crate::indexer::mask_secrets(&msg)).chars().take(220).collect(),
                });
                return None;
            }
        };

 // TIP REGRESSION GUARD — Esplora hosts can briefly return a
 // tip lower than what we've already indexed (CDN edge serving
 // a stale view, host failover mid-block, etc.). We MUST NOT
 // treat that as authoritative — neither rewind state nor
 // truncate indexed_height. Just skip this poll tick; the next
 // one will see the real tip. Without this, a single stale
 // response could trigger a wholesale state corruption.
        let indexed_height = state.read().indexed_height;
        if cur_tip < indexed_height {
            tracing::warn!(
                cur_tip,
                indexed_height,
                "tip regression detected — Esplora returned tip below our indexed height; skipping"
            );
            state.write().push_error(crate::indexer::ErrorEvent {
                at: crate::indexer::now_unix(),
                kind: crate::indexer::ErrorKind::TipRegress,
                host: None,
                height: Some(cur_tip),
                detail: format!(
                    "upstream returned tip={} below our indexed_height={}; skipping (no rewind)",
                    cur_tip, indexed_height
                ),
            });
            return None;
        }

 // REORG DETECTION — re-fetch hashes for the last REORG_HORIZON
 // blocks and compare against our snapshot. If any height's hash
 // diverged from what we stored when we indexed it, the chain
 // reorganized: at least one of our recorded LUCKYPROTOCOL txs may
 // have been undone (or replaced by a different one in the
 // replacement block). Without this, the indexer would happily
 // continue forward, leaving its state permanently divergent
 // from honest indexers.
        match detect_reorg(client, esplora_base, state).await {
            Ok(None) => { /* clean — no reorg, proceed normally */ }
            Ok(Some(divergence_height)) => {
                let indexed_height = state.read().indexed_height;
                tracing::warn!(
                    divergence_height,
                    indexed_height,
                    "REORG DETECTED — attempting snapshot-based recovery"
                );

 // ---- REORG-STORM CIRCUIT BREAKER ----
 // Drop reorg timestamps outside the rolling window,
 // then record this one. If we've crossed the threshold,
 // pause the poll loop for REORG_STORM_COOLDOWN so we
 // don't thrash the snapshot ring on a misbehaving
 // Esplora source / 51% attack scenario.
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
 // Drop the timestamps so we don't immediately
 // re-trip after the cooldown expires.
                    recent_reorgs.clear();
                    tokio::time::sleep(REORG_STORM_COOLDOWN).await;
 // Skip the rest of this iteration — next loop
 // pass re-evaluates tip / reorg state from
 // scratch.
                    return None;
                }
 // SMART RECOVERY: try to restore from the most recent
 // in-memory snapshot whose height < divergence AND whose
 // recorded hash for that height still matches the chain.
 // Falls back to wholesale rewind only if no usable
 // snapshot exists (e.g. divergence sits past the
 // SNAPSHOT_RING_SIZE × SNAPSHOT_INTERVAL_BLOCKS lookback).
                let cutoff = divergence_height.saturating_sub(1);
 // Re-fetch the canonical hashes for the snapshot heights
 // so restore can decide which snapshot is still valid.
                let canonical_hashes = match fetch_canonical_hashes_for_snapshots(
                    client, esplora_base, state,
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
                    esplora_base,
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
                esplora_base,
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
 // new blocks, regardless of SNAPSHOT_INTERVAL_BLOCKS
 // alignment. Bounds the warm-restart "lost work" window to
 // exactly ONE poll cycle (10-30s). Without this, an indexer
 // that catches the chain a few blocks short of the next
 // 12-aligned snapshot would have to redo those few blocks
 // on every relaunch.
            persist_current_snapshot(state).await;
        }

 // Adaptive cadence — caller applies the returned value to its
 // `current_poll_secs`. If backfill failed (indexed < tip), stay
 // fast so the next attempt is in fast_poll_secs; otherwise back
 // to normal_poll_secs.
        let post_indexed_height = state.read().indexed_height;
        let next_cadence = if post_indexed_height < cur_tip {
            fast_poll_secs
        } else {
            normal_poll_secs
        };
        Some(next_cadence)
}

/// Walk back from the indexed_height for up to REORG_HORIZON blocks,
/// re-fetching each height's current hash from Esplora and comparing
/// against what we stored in `block_hashes`. Returns:
/// - `Ok(None)` — no divergence; chain agrees with our snapshot.
/// - `Ok(Some(h))` — first height where the on-chain hash differs
/// from our stored hash. Caller should rebuild past that point.
/// - `Err(_)` — Esplora call failed (transient); caller should retry.
async fn detect_reorg(
    client: &reqwest::Client,
    base: &str,
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
 // No stored hashes (e.g., first poll after backfill skipped them).
 // Treat as clean — nothing to detect against.
        return Ok(None);
    }

    for (h, stored_hash) in &snapshots {
        let on_chain_hash = match fetch_block_hash(client, base, *h).await {
            Ok(s) => s,
            Err(e) => {
 // If Esplora dropped a block-height lookup transiently,
 // treat as clean (the next poll will retry). We don't
 // want a single missing hash to wipe state.
                tracing::warn!(error = ?e, height = h, "reorg probe: hash GET failed, skipping");
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

/// Tip-fetch per-host deadline when racing in parallel. Tip queries
/// are a single plaintext line over HTTP — anything taking longer than
/// 8s is functionally dead on that host. Tightening this from the
/// generic HTTP_TIMEOUT (30s) is the single biggest reliability win
/// for users on flaky networks (CN/GFW environments routinely have ONE
/// of {Alchemy, mempool.space, blockstream, emzy, bitcoin-21}
/// effectively dead while the others respond in milliseconds — the
/// sequential fallback waited the full 30s per dead host).
const TIP_RACE_DEADLINE: Duration = Duration::from_secs(8);

/// After the FIRST successful tip response, how long to keep collecting
/// responses from the still-in-flight mirrors before returning the MAX.
/// Why we don't just take "first success wins":
///   We've observed one mirror in the CN backbone consistently returning
///   stale tip values (cached ~5 blocks behind canonical) while
///   responding fastest. With pure first-success, the sidecar always
///   accepted the stale answer, thought it was caught up, and silently
///   sat at the wrong height — no error event recorded, no watchdog
///   trip, just an invisible 19+ minute lag with the chain.
/// This gather window solves it: a slightly slower (but fresh) mirror
/// gets a chance to come in within 1.5s and bump the MAX. Fresh always
/// beats stale because integers compare by value, not by who answered
/// first.
/// Trade-off: typical case latency is ~first_success + 1.5s. Real cost
/// to user is ~1.5s extra per poll cycle (every 10s), invisible at
/// human scale. Bandwidth cost: zero — we already fire all 4 GETs in
/// parallel for the race; we just wait a beat longer before deciding.
const TIP_GATHER_WINDOW: Duration = Duration::from_millis(1500);

/// Watchdog deadline for a single poll-loop iteration. We've observed
/// reqwest TLS handshakes that don't honor their per-request timeout
/// on flaky networks (CN/GFW) — the underlying TCP socket gets into a
/// half-open state and the read blocks indefinitely. Without this
/// outer cancel, the entire indexer goes silent: no logs, no errors,
/// no progress, just the HTTP `/state` endpoint stuck on the last
/// successful tip. 120s budget is generous (tip race 8s + reorg probe
/// ~20s + a multi-block backfill ~50s) — anything taking longer is by
/// definition a wedge, NOT slow-but-progressing work. On timeout we
/// drop all in-flight reqwest futures (cancel-safe — no half-applied
/// state since `state.write()` blocks complete atomically), push a
/// NETWORK ErrorEvent into DIAGNOSTICS so the user sees the cause,
/// and loop back at fast cadence to retry.
const POLL_ITER_WATCHDOG: Duration = Duration::from_secs(120);

async fn fetch_tip_height(client: &reqwest::Client, base: &str) -> Result<u32> {
 // Try the user's Bitcoin Core node first when configured. A single
 // `getblockcount` RPC call is faster (local network, no rate limit)
 // and gives us a fresh tip without burning Esplora quota.
    if crate::core_rpc::is_configured() {
        match crate::core_rpc::fetch_tip_height(client).await {
            Ok(h) => return Ok(h),
            Err(e) => tracing::debug!("core-rpc fetch_tip_height failed, falling through: {}", e),
        }
    }

 // === RACED TIP FETCH ===
 // Fire one GET per esplora base concurrently, then GATHER multiple
 // responses within a tight window and take the MAX. This is NOT
 // "first success wins" — we observed in production that one CN-
 // backbone mirror consistently returned stale-cached tip values
 // while responding fastest, and a pure-first-success race always
 // accepted the stale answer (silent 19+ min stalls, watchdog not
 // tripped because each individual iteration "succeeded").
 // Gather semantics:
 //   1. Fire all N GETs in parallel.
 //   2. Wait for the FIRST successful response.
 //   3. Then keep collecting for an additional TIP_GATHER_WINDOW
 //      (~1.5s) — slower-but-fresher mirrors get to come in and
 //      bump the running MAX.
 //   4. Overall hard cap is TIP_RACE_DEADLINE (8s) for the case
 //      where ALL mirrors are slow/dead.
 //   5. Take the maximum height across all successful responses.
 // Why MAX is correct: every honest Bitcoin Esplora server reports
 // the height of its CURRENT best chain tip; stale mirrors report
 // older values, never newer. So MAX = freshest known tip. The
 // worst a malicious mirror could do is report a height it doesn't
 // actually have, but the subsequent block fetch would 404 on every
 // OTHER mirror and the indexer just doesn't advance — no state
 // corruption.
 // Bandwidth cost: same as v7's first-success-wins race (we
 // already fired all N in parallel; just waiting a beat longer).
 // Latency cost: ~+1.5s per poll cycle, negligible at 10s cadence.
    use futures::stream::{FuturesUnordered, StreamExt};
    use tokio::time::Instant;

    let bases = esplora_bases(base);
    if bases.is_empty() {
        return Err(anyhow!("no esplora bases configured"));
    }

    let mut in_flight: FuturesUnordered<_> = bases.into_iter().map(|b| {
        let url = format!("{}/blocks/tip/height", b.trim_end_matches('/'));
        let client = client.clone();
        async move {
            let resp = client.get(&url)
                .timeout(TIP_RACE_DEADLINE)
                .send().await
                .map_err(|e| anyhow!(
                    "tip GET to {} failed: {}",
                    crate::indexer::mask_secrets(&url),
                    crate::indexer::mask_secrets(&format!("{:?}", e))
                ))?;
            let status = resp.status();
            if !status.is_success() {
                return Err(anyhow!(
                    "tip GET to {} returned {}",
                    crate::indexer::mask_secrets(&url),
                    status
                ));
            }
            let body = resp.text().await
                .map_err(|e| anyhow!(
                    "tip body read from {} failed: {}",
                    crate::indexer::mask_secrets(&url),
                    crate::indexer::mask_secrets(&format!("{:?}", e))
                ))?;
            let height: u32 = body.trim().parse()
                .map_err(|e| anyhow!(
                    "tip body parse from {} failed (got '{}'): {}",
                    crate::indexer::mask_secrets(&url),
                    body.trim().chars().take(40).collect::<String>(),
                    e
                ))?;
            Ok::<u32, anyhow::Error>(height)
        }
    }).collect();

    let start = Instant::now();
    let overall_deadline = start + TIP_RACE_DEADLINE;
    let mut deadline = overall_deadline;
    let mut best: Option<u32> = None;
    let mut last_err: Option<anyhow::Error> = None;

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match tokio::time::timeout_at(deadline, in_flight.next()).await {
 // Stream produced a result before the deadline.
            Ok(Some(Ok(height))) => {
                if best.is_none() {
 // First success — shrink deadline to give slower
 // mirrors a chance to come in (and possibly report
 // a higher tip), but not so long that we stall the
 // poll loop. cmp::min ensures we never EXTEND past
 // the overall hard cap.
                    let gather_until = Instant::now() + TIP_GATHER_WINDOW;
                    deadline = std::cmp::min(overall_deadline, gather_until);
                }
                best = Some(best.map(|b| b.max(height)).unwrap_or(height));
            }
            Ok(Some(Err(e))) => {
 // One mirror failed; keep collecting from the others.
                last_err = Some(e);
            }
            Ok(None) => {
 // Stream drained — all mirrors finished (Ok or Err).
                break;
            }
            Err(_elapsed) => {
 // Deadline reached. If we have ANY successful response,
 // return its max. Otherwise propagate the last error.
                break;
            }
        }
    }

    match best {
        Some(h) => Ok(h),
        None => Err(anyhow!(
            "all tip GETs failed within {}s deadline; last error: {:?}",
            TIP_RACE_DEADLINE.as_secs(),
            last_err
        )),
    }
}

async fn fetch_block_hash(client: &reqwest::Client, base: &str, height: u32) -> Result<String> {
    if crate::core_rpc::is_configured() {
        match crate::core_rpc::fetch_block_hash(client, height).await {
            Ok(h) => return Ok(h),
            Err(e) => tracing::debug!("core-rpc fetch_block_hash({}) failed, falling through: {}", height, e),
        }
    }
    let path = format!("/block-height/{}", height);
    let body = http_get_text(client, base, &path).await?;
    Ok(body.trim().to_string())
}

/// Verify that a snapshot's recorded block hashes still match the
/// canonical chain. Used at warm-restart (`main.rs::try_load_snapshot`)
/// to refuse a stale snapshot whose tail blocks were reorganized while
/// the indexer was down.
/// Strategy: re-fetch the K most recent block hashes the snapshot
/// recorded, compare each against canonical. Any divergence → snapshot
/// is stale (some indexed blocks have been orphaned), caller must
/// cold-scan instead of resuming.
/// Returns `Ok(true)` if every checked hash matches, `Ok(false)` if a
/// divergence was found, `Err` for transient network failures (caller
/// should treat the same as a divergence — refuse the snapshot).
pub async fn validate_snapshot_against_canonical(
    snap: &crate::indexer::StateSnapshot,
    network: Network,
    alchemy_key: Option<&str>,
) -> Result<bool> {
    if snap.block_hashes.is_empty() {
 // Empty snapshots (height 0 / first run) are trivially canonical.
        return Ok(true);
    }
    let client = build_http_client()?;
    let base = default_esplora_for(network).to_string();
 // Plumb the alchemy key only for the duration of this call. We can't
 // use the global ALCHEMY_KEY OnceCell because main.rs sets it AFTER
 // try_load_snapshot returns; passing through the arg keeps the call
 // self-contained.
    if let Some(key) = alchemy_key {
 // Best-effort set — if already set we just continue with the
 // existing key (subsequent runs of validate would no-op the set).
        let _ = ALCHEMY_KEY.set(key.to_string());
    }

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
        let canonical = match fetch_block_hash(&client, &base, h).await {
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

/// Fetch the block header — provides `tx_count` (so we know how many
/// pages to fan out in parallel) and `merkle_root` (so we can verify
/// the paginated tx body against the block's committed merkle root in
/// `verify_block_merkle_root`). Without that verification the indexer
/// would trust Esplora's tx-list contents blindly; with it, a poisoned
/// upstream can only serve real-hash + real-tx-list pairs.
async fn fetch_block_header(
    client: &reqwest::Client,
    base: &str,
    block_hash: &str,
) -> Result<EsploraBlockHeader> {
    let path = format!("/block/{}", block_hash);
    http_get_json::<EsploraBlockHeader>(client, base, &path).await
}

/// Fetch one page (25 txs by Esplora convention) of full tx JSONs from
/// `/block/:hash/txs[/:start_index]`. The response is an array; pages
/// past the end return empty arrays. start_index MUST be a multiple
/// of 25 — Esplora rejects intermediate offsets.
async fn fetch_block_txs_page(
    client: &reqwest::Client,
    base: &str,
    block_hash: &str,
    start_index: usize,
) -> Result<Vec<EsploraTxFull>> {
    let path = if start_index == 0 {
        format!("/block/{}/txs", block_hash)
    } else {
        format!("/block/{}/txs/{}", block_hash, start_index)
    };
    http_get_json::<Vec<EsploraTxFull>>(client, base, &path).await
}

/// Hard cap on declared push-data length we'll trust. Bitcoin's
/// standardness limits OP_RETURN to 80 payload bytes, but PUSHDATA2/4
/// can technically declare up to 64 KiB / 4 GiB respectively. We cap
/// at 256 bytes so a malformed-but-mineable script can't trick the
/// parser into a giant slice; any declared length above this is
/// treated as garbage and the OP_RETURN is skipped.
const MAX_OP_RETURN_PAYLOAD: usize = 256;

/// OP_RETURN check on an Esplora-JSON tx. Skips non-OP_RETURN vouts
/// via the cheap `scriptpubkey_type` string compare BEFORE touching
/// the hex script — most outputs in any block are non-OP_RETURN, so
/// this short-circuits ~99% of vouts at zero parse cost. Mirrors the
/// rules of `extract_luckyprotocol_payload` (raw bitcoin::Transaction
/// version) including the multi-OP_RETURN reject.
/// Push-opcode coverage:
/// * 0x01..=0x4b — direct push (1-75 bytes), opcode IS the length
/// * 0x4c (OP_PUSHDATA1) — next 1 byte = length (0-255)
/// * 0x4d (OP_PUSHDATA2) — next 2 bytes LE = length (0-65535)
/// * 0x4e (OP_PUSHDATA4) — next 4 bytes LE = length (0-4294967295)
/// Bitcoin standardness rules require the SHORTEST push opcode that
/// fits, so a 50-byte payload SHOULD use direct push. But miners can
/// include non-standard txs directly, so a malicious miner could put
/// our protocol payload behind PUSHDATA2 to make permissive indexers
/// accept it while strict indexers reject it (consensus-divergence
/// attack vector). Supporting all four cases byte-for-byte equally
/// closes that gap. The hard MAX_OP_RETURN_PAYLOAD cap ensures a
/// PUSHDATA4 declaring a 4 GiB payload can't crash the parser.
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
 // <OP_RETURN> <push_op> [push_len_bytes] <payload>
 // No trailing opcodes allowed (e.g. `OP_RETURN PUSH(x) OP_NOP`
 // is NOT valid). Bitcoin Core's standardness rule already
 // rejects such scripts; we enforce the equivalent here so a
 // malicious miner can't slip a "looks-like-LUCKYPROTOCOL" script
 // past the indexer with trailing junk while strict implementations
 // reject it — protocol-divergence vector.
        let payload: &[u8] = match push_op {
 // Direct push 1-75 bytes — opcode IS the length.
            n @ 0x01..=0x4b => {
                let len = n as usize;
                let expected_total = 2 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total {
                    continue;
                }
                &bytes[2..expected_total]
            }
 // OP_PUSHDATA1 — next 1 byte = length.
            0x4c if bytes.len() >= 3 => {
                let len = bytes[2] as usize;
                let expected_total = 3 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total {
                    continue;
                }
                &bytes[3..expected_total]
            }
 // OP_PUSHDATA2 — next 2 bytes LE = length.
            0x4d if bytes.len() >= 4 => {
                let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
                let expected_total = 4 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total {
                    continue;
                }
                &bytes[4..expected_total]
            }
 // OP_PUSHDATA4 — next 4 bytes LE = length.
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
 // continue scanning so a 2nd OP_RETURN still triggers reject
        }
    }

    luckyprotocol_payload
}

/// Sender resolution from already-loaded JSON (no extra HTTP). Same
/// largest-contributor rule as `resolve_sender`, but operates on the
/// vin already in `EsploraTxFull` — saves one round-trip per BET /
/// SEND / DEPLOY.
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

// ============================================================================
// V2 RAW-BLOCK FETCH PATH
// ----------------------------------------------------------------------------
// The Esplora paginated path (`/block/:hash/txs/:idx`) issues ~⌈tx_count/25⌉
// GETs per block to retrieve enriched tx objects with prevout context. That
// gives the indexer everything in one shot (sender address per input,
// scriptpubkey classification, value-per-prevout for largest-contributor
// sender resolution) but the per-block GET count is dominated by Bitcoin's
// overall block throughput (~3000 txs/block on mainnet = ~120 GETs/block),
// not by the indexer's own protocol traffic.
//
// The V2 path replaces that with a single `/block/:hash/raw` fetch returning
// the binary block bytes (~1-3 MB), deserializes locally with bitcoin-rs,
// and ONLY fetches per-tx prevout context for txs whose OP_RETURN carries
// a `LUCKYPROTOCOL|` payload. Since prevouts are exclusively used in
// `resolve_sender_from_json` (audit log writer) and that's only called on
// payload-bearing txs, non-protocol txs need no prevout data — their
// outpoint references (txid + vout) come from the raw block bytes.
//
// Per-block GET count:
//   * V1 paginated: 2 + ⌈tx_count/25⌉  (≈122 for typical mainnet block)
//   * V2 raw:       1 + n + p           (n = protocol txs in this block,
//                                         p = 1 if no Core RPC, 0 if hot)
// At n=0 (the common case during cold-scan of historical blocks), V2 issues
// ~2 GETs vs V1's ~122 — a ~60× reduction. Even at n=100 (a wildly active
// block), V2 is still ~20% fewer GETs.
//
// Trade-off: the V2 path's merkle root verification becomes self-consistent
// (compute root from the same raw bytes that contain the claimed root).
// This downgrades the check from "different Esplora endpoint vs computed"
// to "raw block bytes self-consistent" — still useful as a corruption
// detector but no longer a cross-endpoint poisoning defense. Multi-endpoint
// failover at fetch time + the snapshot validate-on-load step retain
// independent attestations.

/// Fetch the raw block bytes for a confirmed block via `/block/:hash/raw`.
/// Returns the binary block (~1-3 MB) ready for bitcoin-rs deserialization.
async fn fetch_block_raw_bytes(
    client: &reqwest::Client,
    base: &str,
    block_hash: &str,
) -> Result<Vec<u8>> {
    let path = format!("/block/{}/raw", block_hash);
    http_get_bytes(client, base, &path).await
}

/// Fetch ONE tx's enriched JSON (with prevout context) via `/tx/:txid`.
/// Used by the V2 path to selectively fetch prevout data only for txs
/// whose raw-block scan flagged them as protocol-bearing.
async fn fetch_tx_full(
    client: &reqwest::Client,
    base: &str,
    txid: &str,
) -> Result<EsploraTxFull> {
    let path = format!("/tx/{}", txid);
    http_get_json::<EsploraTxFull>(client, base, &path).await
}

/// Classify a script's type as Esplora would — used by the V2 path to
/// populate `scriptpubkey_type` in synthesized EsploraTxFull structs so
/// downstream code (`extract_luckyprotocol_payload_from_json`,
/// op_return_vouts collection) sees the same string-shape it gets from
/// the paginated path. Strings match mempool.space's output exactly.
fn classify_script_type(script: &bitcoin::ScriptBuf) -> String {
    if script.is_op_return()        { return "op_return".to_string(); }
    if script.is_p2wpkh()           { return "v0_p2wpkh".to_string(); }
    if script.is_p2wsh()            { return "v0_p2wsh".to_string(); }
    if script.is_p2tr()             { return "v1_p2tr".to_string(); }
    if script.is_p2sh()             { return "p2sh".to_string(); }
    if script.is_p2pkh()            { return "p2pkh".to_string(); }
    if script.is_p2pk()             { return "p2pk".to_string(); }
    "unknown".to_string()
}

/// Derive a human-readable address string from a script_pubkey if the
/// script encodes a standard address type. Returns None for non-standard
/// scripts (bare multisig, OP_RETURN, custom Tapscript leaves, etc.).
/// Mirrors Esplora's `scriptpubkey_address` field — the call site
/// (`apply_tx` → `vout_addresses`) treats None gracefully (the indexer
/// just doesn't add a reverse-index entry for that vout).
fn address_from_script(script: &bitcoin::ScriptBuf, network: Network) -> Option<String> {
    bitcoin::Address::from_script(script, network).ok().map(|a| a.to_string())
}

/// Scan a raw `bitcoin::Transaction`'s vouts for an OP_RETURN carrying
/// a LUCKYPROTOCOL payload. Same multi-OP_RETURN reject + push-opcode
/// coverage as `extract_luckyprotocol_payload_from_json` (the JSON
/// variant) — pre-filters protocol txs in the raw-block scan so we
/// only `/tx/:txid` fetch the ones that actually carry a payload.
fn extract_luckyprotocol_payload_from_raw_tx(
    tx: &bitcoin::Transaction,
) -> Option<crate::protocol::ProtocolPayload> {
    use crate::protocol::parse_payload;
    let mut op_return_count = 0usize;
    let mut payload_found: Option<crate::protocol::ProtocolPayload> = None;
    for vout in &tx.output {
        if !vout.script_pubkey.is_op_return() { continue; }
        op_return_count += 1;
        if op_return_count > 1 { return None; }
        let bytes = vout.script_pubkey.as_bytes();
        if bytes.len() < 2 || bytes[0] != 0x6a { continue; }
        let push_op = bytes[1];
        let payload: &[u8] = match push_op {
            n @ 0x01..=0x4b => {
                let len = n as usize;
                let expected_total = 2 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total { continue; }
                &bytes[2..expected_total]
            }
            0x4c if bytes.len() >= 3 => {
                let len = bytes[2] as usize;
                let expected_total = 3 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total { continue; }
                &bytes[3..expected_total]
            }
            0x4d if bytes.len() >= 4 => {
                let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
                let expected_total = 4 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total { continue; }
                &bytes[4..expected_total]
            }
            0x4e if bytes.len() >= 6 => {
                let len = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
                let expected_total = 6 + len;
                if len > MAX_OP_RETURN_PAYLOAD || bytes.len() != expected_total { continue; }
                &bytes[6..expected_total]
            }
            _ => continue,
        };
        if let Some(p) = parse_payload(payload) {
            payload_found = Some(p);
        }
    }
    payload_found
}

/// Convert a `bitcoin::Transaction` (raw, no prevout context) into the
/// `EsploraTxFull` shape the apply step expects. Vins carry only the
/// outpoint reference (`prevout = None`); vouts carry full
/// scriptpubkey/address/value/type derived locally from the script.
/// Caller is responsible for back-filling prevout for any tx that
/// needs sender resolution (i.e. payload-bearing txs); the V2 main
/// fetcher does this via `fetch_tx_full` for the small subset of
/// protocol txs in each block.
fn raw_tx_to_synthetic_esplora(
    tx: &bitcoin::Transaction,
    network: Network,
) -> EsploraTxFull {
    let txid = tx.compute_txid().to_string();
    let vin: Vec<EsploraVin> = tx.input.iter().map(|inp| EsploraVin {
        txid: inp.previous_output.txid.to_string(),
        vout: inp.previous_output.vout,
        prevout: None,
    }).collect();
    let vout: Vec<EsploraVout> = tx.output.iter().map(|out| EsploraVout {
        scriptpubkey_address: address_from_script(&out.script_pubkey, network),
        value: out.value.to_sat(),
        scriptpubkey: hex::encode(out.script_pubkey.as_bytes()),
        scriptpubkey_type: classify_script_type(&out.script_pubkey),
    }).collect();
    EsploraTxFull { txid, vin, vout }
}

/// Pre-fetched data for one block, ready to be applied to state.
/// `pages` is sorted by start_index (chain order within the block).
/// `merkle_root_claimed` is the block-header value we'll verify the
/// page contents against (anti-poisoning check).
struct BlockData {
    block_hash: String,
    merkle_root_claimed: String,
    pages: Vec<(usize, Vec<EsploraTxFull>)>,
}

/// Verify that the tx list Esplora returned for `block_hash` actually
/// hashes to the merkle_root that block's header declares. Closes the
/// "honest hash + fabricated body" attack class: an attacker who
/// poisons an Esplora endpoint can serve a real block hash but
/// fabricate the contained tx list (injecting fake LUCKYPROTOCOL payloads).
/// Without this check the indexer would replay the fabrication into
/// state. With it, fabricated tx lists produce a merkle root that
/// doesn't match the (cryptographically committed) header value, and
/// the entire block is rejected.
/// Algorithm:
/// 1. Iterate every tx in chain order, parse its txid as bitcoin::Txid
/// (which is the SHA256d hash of the tx — already-computed by
/// Esplora and returned in `txid` field of each entry).
/// 2. Convert each Txid to a TxMerkleNode (same underlying SHA256d
/// hash type, different newtype wrapper).
/// 3. Run `bitcoin::merkle_tree::calculate_root` over the iterator
/// — this implements Bitcoin's canonical merkle root algorithm
/// (pairwise SHA256d with the last hash duplicated when an
/// odd-sized layer occurs).
/// 4. Parse `merkle_root_claimed` (big-endian hex from Esplora JSON)
/// and compare. The bitcoin crate's `TxMerkleNode::from_str`
/// handles the endianness flip from displayed-hex to internal.
/// Returns `Ok(())` on match, `Err(...)` on mismatch or parse failure.
/// Caller treats Err the same as a fetch failure — abort backfill,
/// retry next poll. A persistently-mismatching endpoint is an attack
/// indicator and operators should be alerted.
fn verify_block_merkle_root(
    pages: &[(usize, Vec<EsploraTxFull>)],
    merkle_root_claimed: &str,
) -> Result<()> {
    if merkle_root_claimed.is_empty() {
        return Err(anyhow!(
            "block header missing merkle_root — indexer can't verify body integrity"
        ));
    }
 // Convert Txid → TxMerkleNode (both wrap sha256d). We use the
 // raw byte-array form so we don't have to round-trip through
 // the displayed-hex representation.
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

/// Toggle for the V2 raw-block fetch path. When true (default), the
/// indexer first tries `/block/:hash/raw` + selective `/tx/:txid`
/// prevout fetches; on failure falls back to the V1 paginated path.
/// Flip to false to force the V1 paginated path everywhere — useful
/// for benchmarking, or as an emergency revert if a future bitcoin-rs
/// version regresses raw-block deserialization.
const USE_V2_RAW_BLOCK_PATH: bool = true;

/// Fetch one block's worth of data — header + all paginated tx pages.
/// Returns Ok(None) if any single HTTP fails (caller stops backfill
/// at this height; next poll retries). Page fetches within the block
/// run with TX_FETCH_CONCURRENCY parallelism.
///
/// Three-tier fetch strategy:
///   1. Core RPC fast path — single `getblock <hash> 3` call returns
///      the entire block including prevouts. Active only when the
///      operator has configured `--core-rpc-url`.
///   2. V2 raw-block path — single `/block/:hash/raw` returns the
///      binary block, deserialized locally, then ONE `/tx/:txid` GET
///      per protocol tx (typically 0-5 per block). ~60× fewer GETs
///      than V1 at the cost of self-consistent (rather than
///      cross-endpoint) merkle verification.
///   3. V1 paginated path — the legacy `/block/:hash/txs/:idx` page
///      walk. Retained as a fallback when V2 fails on a specific
///      block (rare: corrupt raw bytes, missing endpoint, or
///      bitcoin-rs deserialization failure on a non-standard block).
async fn fetch_one_block_data(
    client: &reqwest::Client,
    base: &str,
    h: u32,
) -> Result<Option<BlockData>> {
    let block_hash = match fetch_block_hash(client, base, h).await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = ?e, height = h, "block hash GET failed");
            return Ok(None);
        }
    };

 // Tier 1: Bitcoin Core RPC fast path. `getblock <hash> 3` returns the
 // whole block — header + every tx with prevouts — in one round
 // trip. That replaces (1) the header fetch + (2) the N paginated
 // tx-page fetches with a single local-network call. On a healthy
 // node, backfill speed goes from "~6 blocks/min over public
 // esplora" to "limited only by the RPC server" (~minutes for the
 // whole chain history). Errors silently fall through to the
 // esplora path below.
    if crate::core_rpc::is_configured() {
        match crate::core_rpc::fetch_block_all_txs(client, &block_hash).await {
            Ok((txs, merkle, _n_tx)) => {
                return Ok(Some(BlockData {
                    block_hash,
                    merkle_root_claimed: merkle,
                    pages: vec![(0usize, txs)],
                }));
            }
            Err(e) => {
                tracing::debug!(error = %e, height = h,
                    "core-rpc getblock failed, falling through to esplora");
            }
        }
    }

 // Tier 2: V2 raw-block path. Fast for blocks with 0-5 protocol txs
 // (~99% of mainnet history). On failure (rare), fall through to V1.
    if USE_V2_RAW_BLOCK_PATH {
        match fetch_one_block_data_via_raw(client, base, h, &block_hash).await {
            Ok(Some(data)) => return Ok(Some(data)),
            Ok(None) => {
 // V2 explicitly returned None (raw fetch failed transiently
 // — block hash still valid). Don't fall through — the
 // outer backfill loop already treats None as "retry next
 // poll", which is the right behavior for transient failures.
                return Ok(None);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e, height = h,
                    "V2 raw-block path errored — falling through to V1 paginated"
                );
            }
        }
    }

 // Tier 3: V1 paginated path. Legacy fallback used when V2 fails to
 // deserialize a specific block (suspect non-standard block bytes)
 // or when USE_V2_RAW_BLOCK_PATH is force-disabled.
    fetch_one_block_data_via_pagination(client, base, h, block_hash).await
}

/// V2 raw-block path: `/block/:hash/raw` → bitcoin-rs deserialize →
/// scan locally → selectively `/tx/:txid` for the small subset of
/// protocol txs. See the "V2 RAW-BLOCK FETCH PATH" comment block
/// above for full rationale.
///
/// Returns:
///   * `Ok(Some(data))` — success
///   * `Ok(None)` — transient fetch failure (caller treats same as V1's
///     None: stop backfill at this height, retry next poll)
///   * `Err(...)` — V2-path-specific failure (deserialize error,
///     merkle mismatch on raw bytes). Caller falls through to V1.
async fn fetch_one_block_data_via_raw(
    client: &reqwest::Client,
    base: &str,
    h: u32,
    block_hash: &str,
) -> Result<Option<BlockData>> {
    use futures::stream::{self, StreamExt};

 // LUCKYPROTOCOL is mainnet-only — see `parse_network`. Hardcode here
 // so address derivation from raw scripts uses the right HRP (bc1q vs
 // tb1q etc.). If/when the indexer goes multi-network this needs to
 // thread `Network` down from `IndexerState`.
    let network = Network::Bitcoin;

    let raw_bytes = match fetch_block_raw_bytes(client, base, block_hash).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = ?e, height = h, "raw block bytes GET failed");
            return Ok(None);
        }
    };

 // bitcoin-rs deserialize. Errors here mean either truncated bytes
 // (network corruption) or a block whose encoding bitcoin-rs can't
 // parse (extraordinarily unlikely on mainnet, but defensive). Returning
 // Err triggers fallback to V1 paginated at the call site.
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&raw_bytes)
        .with_context(|| format!("deserialize raw block {} ({} bytes)", h, raw_bytes.len()))?;

 // The merkle root from the deserialized header. Because raw bytes
 // contain both header and tx list, our merkle verification later
 // is self-consistent (same source). It still catches bit-flip
 // corruption: if some bytes flipped, header.merkle_root and
 // compute_root(txs) would diverge.
    let merkle_root_claimed = block.header.merkle_root.to_string();

 // Walk the local Block once: classify each tx as
 //   * protocol-bearing (has a LUCKYPROTOCOL OP_RETURN) → fetch prevouts
 //   * non-protocol → just synthesize from raw, prevouts not needed
 // We deliberately DON'T fetch prevouts for txs that spend a token UTXO
 // but carry no payload — those go to §6.6 strict burn, which needs
 // only the spent-outpoint reference (already in raw bytes) and never
 // calls resolve_sender_from_json.
    let mut needs_prevouts: Vec<String> = Vec::new();
    for tx in &block.txdata {
        if extract_luckyprotocol_payload_from_raw_tx(tx).is_some() {
            needs_prevouts.push(tx.compute_txid().to_string());
        }
    }

 // Fetch prevout-enriched JSON for each protocol tx in parallel.
 // For most blocks during cold scan, needs_prevouts is empty and this
 // entire stream resolves immediately. When protocol traffic ramps
 // (popular ticker mint window), this stream runs at TX_FETCH_CONCURRENCY
 // parallelism, same envelope as V1's tx-page fetch.
    let prevout_map: std::collections::HashMap<String, EsploraTxFull> = if needs_prevouts.is_empty() {
        std::collections::HashMap::new()
    } else {
        let client_arc = client.clone();
        let base_owned = base.to_string();
        let stream = stream::iter(needs_prevouts.into_iter().map(move |txid| {
            let client = client_arc.clone();
            let base = base_owned.clone();
            async move {
                fetch_tx_full(&client, &base, &txid).await.map(|tx| (txid, tx))
            }
        })).buffer_unordered(TX_FETCH_CONCURRENCY);

        let mut map = std::collections::HashMap::new();
        tokio::pin!(stream);
        while let Some(r) = stream.next().await {
            match r {
                Ok((txid, tx)) => { map.insert(txid, tx); }
                Err(e) => {
                    tracing::warn!(error = ?e, height = h,
                        "V2 protocol-tx prevout fetch failed — falling back to V1");
                    return Err(e);
                }
            }
        }
        map
    };

 // Build the synthetic page: for protocol txs use the fetched
 // prevout-enriched record; for everything else, synthesize from
 // raw bytes (vin.prevout = None).
    let synthetic_txs: Vec<EsploraTxFull> = block.txdata.iter().map(|tx| {
        let txid = tx.compute_txid().to_string();
        if let Some(fetched) = prevout_map.get(&txid) {
            return fetched.clone();
        }
        raw_tx_to_synthetic_esplora(tx, network)
    }).collect();

    tracing::info!(
        height = h,
        tx_count = synthetic_txs.len(),
        protocol_tx_count = prevout_map.len(),
        raw_bytes = raw_bytes.len(),
        "V2 raw-block path hit"
    );

    Ok(Some(BlockData {
        block_hash: block_hash.to_string(),
        merkle_root_claimed,
        pages: vec![(0usize, synthetic_txs)],
    }))
}

/// V1 paginated path: legacy `/block/:hash` header + `/block/:hash/txs/:idx`
/// page walk. Retained as a fallback when V2 raw-fetch fails on a specific
/// block. Same logic as the original `fetch_one_block_data` pre-V2.
async fn fetch_one_block_data_via_pagination(
    client: &reqwest::Client,
    base: &str,
    h: u32,
    block_hash: String,
) -> Result<Option<BlockData>> {
    use futures::stream::{self, StreamExt};

    let header = match fetch_block_header(client, base, &block_hash).await {
        Ok(hdr) => hdr,
        Err(e) => {
            tracing::warn!(error = ?e, height = h, "block header GET failed");
            return Ok(None);
        }
    };
    let total_txs = header.tx_count;
    let merkle_root_claimed = header.merkle_root.clone();
    if total_txs == 0 {
 // Empty block (impossible on mainnet — every block has a
 // coinbase — but the indexer is defensive). No txs to verify
 // against merkle_root, so we accept the empty body as-is.
        return Ok(Some(BlockData {
            block_hash,
            merkle_root_claimed,
            pages: vec![],
        }));
    }

    let page_indices: Vec<usize> = (0..total_txs).step_by(25).collect();
    let client_arc = client.clone();
    let base_owned = base.to_string();
    let block_hash_owned = block_hash.clone();
    let page_stream = stream::iter(page_indices.into_iter().map(move |start_idx| {
        let client = client_arc.clone();
        let base = base_owned.clone();
        let hash = block_hash_owned.clone();
        async move {
            let page = fetch_block_txs_page(&client, &base, &hash, start_idx).await
                .with_context(|| format!("page {}", start_idx))?;
            Ok::<(usize, Vec<EsploraTxFull>), anyhow::Error>((start_idx, page))
        }
    }))
    .buffer_unordered(TX_FETCH_CONCURRENCY);

    let mut pages: Vec<(usize, Vec<EsploraTxFull>)> = Vec::new();
    tokio::pin!(page_stream);
    while let Some(r) = page_stream.next().await {
        match r {
            Ok(p) => pages.push(p),
            Err(e) => {
                tracing::warn!(error = ?e, height = h, "tx page fetch failed");
                return Ok(None);
            }
        }
    }
    pages.sort_by_key(|(idx, _)| *idx);
    Ok(Some(BlockData {
        block_hash,
        merkle_root_claimed,
        pages,
    }))
}

async fn backfill_range(
    state: Arc<RwLock<IndexerState>>,
    client: &reqwest::Client,
    base: &str,
    from_height: u32,
    to_height: u32,
) -> Result<()> {
    use futures::stream::{self, StreamExt};

 // CROSS-BLOCK PIPELINE (introduced 2026-05): instead of fetching
 // block N and waiting on its HTTP I/O before starting block N+1,
 // we keep BLOCK_FETCH_CONCURRENCY blocks' fetches in flight at
 // once. `stream::buffered` (NOT `buffer_unordered`) preserves
 // the ORIGINAL order, so the apply loop below sees blocks in
 // chain order even though their HTTP I/O completed in arbitrary
 // order. This decouples the network-bound side from the state-
 // mutation side and gives a ~4× speedup on top of the per-block
 // 25× from paginated fetches — combined throughput up to ~100×
 // the original per-tx-hex flow.
 // Apply (state mutation) MUST stay sequential — a SEND that
 // depends on a prior SEND's debit must see the updated balance.
 // Two-stage pipeline (fetch async ‖, apply sync) keeps that
 // invariant while exploiting all available HTTP parallelism.
    let client_arc = client.clone();
    let base_owned = base.to_string();
    let fetch_stream = stream::iter(from_height..=to_height)
        .map(move |h| {
            let client = client_arc.clone();
            let base = base_owned.clone();
            async move { (h, fetch_one_block_data(&client, &base, h).await) }
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

 // === MERKLE ROOT VERIFICATION ===
 // Before applying ANY state mutation from this block, prove
 // the tx list Esplora returned actually hashes to the block
 // header's committed merkle_root. Closes the "honest hash +
 // fabricated body" attack — see verify_block_merkle_root()
 // doc + PROTOCOL.md §11.5.
 // On mismatch: log error + ABORT backfill. We do NOT advance
 // indexed_height, so the next poll retries from this height.
 // If the same endpoint persistently mismatches, the indexer
 // stalls (correctly — we'd rather stall than ingest poisoned
 // data); operators see the tracing::error! line and can
 // switch endpoints or escalate. A correctly-running Esplora
 // never produces this error.
        if !pages.is_empty() {
            if let Err(e) = verify_block_merkle_root(&pages, &merkle_root_claimed) {
                tracing::error!(
                    height = h,
                    block_hash = %block_hash,
                    error = %e,
                    "MERKLE ROOT VERIFICATION FAILED — refusing to ingest block. \
                     Esplora endpoint is either misbehaving, compromised, or \
                     returned data for a different block."
                );
                state.write().push_error(crate::indexer::ErrorEvent {
                    at: crate::indexer::now_unix(),
                    kind: crate::indexer::ErrorKind::Merkle,
                    host: None,
                    height: Some(h),
                    detail: format!(
                        "block {} merkle root verification failed — upstream returned tx list \
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

 // Walk EVERY tx in chain order (non-LUCKYPROTOCOL txs that happen
 // to spend a token-bearing UTXO still need processing so the
 // input pool routes per PROTOCOL.md §7.4). For each tx:
 // 1. Build spent_outpoints from vin (skipping coinbase, which
 // has empty txid).
 // 2. Identify op_return_vouts.
 // 3. Resolve sender (largest-contributor — audit only).
 // 4. Parse the (optional) LUCKYPROTOCOL payload.
 // 5. Hand to apply_tx which mutates state.
 // apply_tx fast-paths: returns false without touching state if
 // there's no input pool AND no payload AND not already in by_txid.
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

 // Identify OP_RETURN vouts so the apply path can
 // refuse to assign tokens to provably-unspendable
 // outputs (PROTOCOL.md §7.5).
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
 // scripts; the apply path handles None gracefully.
                let vout_addresses: Vec<Option<String>> = tx
                    .vout
                    .iter()
                    .map(|vo| vo.scriptpubkey_address.clone())
                    .collect();

 // Sats per vout — apply_tx needs this for the DEPLOY
 // protocol-fee consensus check (PROTOCOL.md §5.1.2).
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
 // Mark forward progress so the UI's stall detector can tell
 // "still working" from "wedged" via /state.last_progress_at.
 // Touching here (after EVERY block) gives the smoothest signal:
 // a slow-but-steady backfill shows the timestamp ticking, while
 // a wedged poller leaves it frozen.
            s.touch_progress();
 // Snapshot this block's hash so the next poll's reorg-detection
 // probe has something to compare against. Without this, a reorg
 // is undetectable.
            s.block_hashes.insert(h, block_hash.clone());
 // Bound memory: keep only the last 200 entries (well past the
 // REORG_HORIZON window). Pruning at every block is cheap —
 // HashMap::retain is linear in size and we never grow past 200.
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

/// Re-fetch the on-chain block hash at every height present in the
/// in-memory snapshot ring. Used during reorg recovery to decide which
/// snapshots are still on the canonical chain (and therefore safe to
/// restore from). Returns a partial map on transient HTTP errors —
/// snapshot validation tolerates missing entries (treats them as
/// "unverified" and skips).
async fn fetch_canonical_hashes_for_snapshots(
    client: &reqwest::Client,
    base: &str,
    state: &Arc<RwLock<IndexerState>>,
) -> Result<std::collections::HashMap<u32, String>> {
    let heights: Vec<u32> = {
        let s = state.read();
        s.snapshots.iter().map(|snap| snap.indexed_height).collect()
    };
    let mut out = std::collections::HashMap::new();
    for h in heights {
        if let Ok(hash) = fetch_block_hash(client, base, h).await {
            out.insert(h, hash);
        }
    }
    Ok(out)
}

/// Snapshot the live IndexerState and write it to the configured disk
/// path. Used at backfill-complete and after every poll-cycle that
/// advanced indexed_height — so the on-disk snapshot tracks the live
/// state within ~one poll cycle, instead of only updating at
/// SNAPSHOT_INTERVAL_BLOCKS boundaries.
/// No-op when SNAPSHOT_PATH isn't configured (purely-in-memory mode).
/// Errors are logged at warn level and swallowed: a failed disk write
/// degrades next-launch warm-restart by at most one poll cycle, never
/// affects correctness of the live state.
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

/// Disk path for snapshot persistence. Set by main.rs at startup; None
/// disables persistence (purely in-memory mode). Using OnceLock so the
/// path can be set once and read concurrently from the snapshot trigger
/// in backfill_range without locking.
pub static SNAPSHOT_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

// Note: the bitcoin::Transaction-based `extract_luckyprotocol_payload` and the
// per-tx `resolve_sender` HTTP helpers were removed in 2026-05 when the
// backfill switched to the paginated `/block/:hash/txs[/:start_index]`
// endpoint. The JSON-based equivalents (`extract_luckyprotocol_payload_from_json`
// + `resolve_sender_from_json`) live earlier in the file alongside
// `fetch_block_txs_page`. Same protocol rules (single OP_RETURN, push-
// opcode handling, largest-contributor sender) — just driven from the
// already-decoded JSON we got back with the block, no extra round trip.
