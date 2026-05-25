// LUCKYPROTOCOL global protocol indexer.
// Standalone binary that watches Bitcoin mainnet, parses LUCKYPROTOCOL
// OP_RETURN payloads, replays the protocol rules, and serves the derived
// per-address token balances + bet history via a JSON HTTP API.
//
// Endpoints:
//   GET /                — health + tip / scan state
//   GET /balances/:addr  — { ticker: amount } map
//   GET /bets/:addr      — list of bets known to involve this address
//   GET /bets/by-txid/:txid — single bet record by tx
//
// Operational model:
// * On startup, attempts to restore from the latest disk snapshot at
//   `--snapshot-path`. If present, indexing resumes from snapshot.height + 1
//   instead of re-scanning from LCKPROTOCOL_START_HEIGHT.
// * Otherwise, scans from `--start-height` (default: LCKPROTOCOL_START_HEIGHT)
//   up to the current tip, parsing every OP_RETURN. Stores derived state
//   in-memory + writes a fresh snapshot to disk every SNAPSHOT_INTERVAL_BLOCKS.
// * After catch-up, polls Bitcoin Core's tip height every `--poll-secs`
//   seconds; on new tip, fetches the block(s) + applies any new LUCKYPROTOCOL
//   payloads.
// * Reorg-aware: probes the last 12 blocks on every poll; on divergence,
//   restores from the most recent valid in-memory snapshot and re-scans
//   forward from there (NOT a full rewind to genesis).
//
// Transport: ONLY Bitcoin Core JSON-RPC. There is no Esplora / Alchemy /
// mempool.space fallback. Self-sovereign by construction — every byte of
// chain data comes from a node the operator controls. If you don't run
// your own node, you don't get to run this indexer.
//
// Protocol rules (must stay in lockstep with src/protocol/protocol.js +
// src-tauri/src/tx.rs):
//   BET payload: LUCKYPROTOCOL|<tier>|<pick>|<ticker>|<win_out_idx>
//     -> if isHit(tier, pick, hash_N) is true, the UTXO at
//        (txid, win_out_idx) is credited with TIER_REWARD[tier] of <ticker>.
//   SEND payload: LUCKYPROTOCOL|SEND|<ticker>|<amount>|<to_out_idx>[|<change_out_idx>]
//     -> drain input pool, credit to_out_idx by <amount>, route residual
//        to change_out_idx (or burn if absent).
//   DEPLOY payload: LUCKYPROTOCOL|DEPLOY|<ticker>
//     -> first-write-wins ticker registration.

mod core_rpc;
mod indexer;
mod protocol;
mod server;
mod source;

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
struct Cli {
    /// Network the indexer watches. Mainnet only — testnet/signet were
    /// dropped from the LUCKYPROTOCOL project. Kept as a CLI knob for
    /// symmetry only.
    #[arg(long, env = "LUCKYPROTOCOL_NETWORK", default_value = "bitcoin")]
    network: String,

    /// Bitcoin Core JSON-RPC URL (e.g. `http://127.0.0.1:8332`).
    /// REQUIRED — the indexer talks ONLY to your local Bitcoin Core
    /// node. There is no third-party HTTP fallback. If the node is
    /// unreachable, the indexer retries with backoff rather than
    /// silently serving derived state from an unverified source.
    /// Requires Core 24.0+ for `getblock <hash> 3` verbosity=3
    /// (prevout metadata in vin).
    #[arg(long, env = "LUCKYPROTOCOL_CORE_URL")]
    core_url: String,

    /// Bitcoin Core RPC username (matches the node's `rpcuser` config).
    #[arg(long, env = "LUCKYPROTOCOL_CORE_USER")]
    core_user: String,

    /// Bitcoin Core RPC password (matches the node's `rpcpassword`
    /// config). For cookie auth, read the cookie file and pass
    /// user=`__cookie__` + password=<contents-after-colon>.
    #[arg(long, env = "LUCKYPROTOCOL_CORE_PASSWORD")]
    core_password: String,

    /// Start scanning from this block height. Defaults to the protocol
    /// activation height (LCKPROTOCOL_START_HEIGHT) so a fresh indexer
    /// indexes EVERY post-activation LUCKYPROTOCOL tx.
    #[arg(long, env = "LUCKYPROTOCOL_START_HEIGHT")]
    start_height: Option<u32>,

    /// HTTP server bind address.
    #[arg(long, env = "LUCKYPROTOCOL_BIND", default_value = "127.0.0.1:8765")]
    bind: SocketAddr,

    /// Poll interval for new blocks (in seconds) once the indexer has
    /// caught up to chain tip. Lower = less lag between block arrival
    /// and indexer-side visibility, at the cost of more `getblockcount`
    /// RPC calls. 10s gives ~5s expected lag at negligible local-node
    /// load. While behind (post-restart or after a network blip), the
    /// poller auto-overrides to 5s regardless of this value.
    #[arg(long, env = "LUCKYPROTOCOL_POLL_SECS", default_value = "10")]
    poll_secs: u64,

    /// Path where the indexer dumps the latest state snapshot for
    /// warm-restart. Default puts it next to the binary as
    /// `luckyprotocol-indexer-snapshot.json`. Set to an empty string to
    /// disable snapshot persistence (purely in-memory mode — every
    /// restart re-scans from `--start-height`).
    #[arg(long, env = "LUCKYPROTOCOL_SNAPSHOT_PATH",
        default_value = "luckyprotocol-indexer-snapshot.json")]
    snapshot_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // NON-BLOCKING TRACING WRITER.
    // We wrap stdout in `tracing_appender::non_blocking` so log calls
    // submit to a bounded channel + a dedicated worker thread, and
    // ALWAYS return immediately (typically <1µs). Without this, every
    // tracing::info! / warn! / error! is a synchronous write to stdout
    // — which, when the consumer (systemd-journald, the OS pipe buffer)
    // is slow or wedged, BLOCKS the calling task indefinitely. We've
    // seen exactly that wedge in the original Tauri sidecar wrapper.
    // Capacity: default 128K-line channel. When/if the channel fills
    // (consumer too slow), the appender DROPS new lines rather than
    // blocking — so a slow downstream becomes "missing logs" (visible
    // in tracing's lost-line counter) instead of a hung indexer.
    // _guard must outlive `main` — `drop` flushes pending lines.
    let (non_blocking_writer, _tracing_guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("luckyprotocol_indexer=info,tower_http=info")),
        )
        .with_writer(non_blocking_writer)
        .init();

    let cli = Cli::parse();
    let network = source::parse_network(&cli.network)?;

    // Bitcoin Core RPC config — set BEFORE backfill kicks off so the
    // first fetch already routes to the node. clap enforces non-empty
    // url/user/password (all three are required CLI args).
    let _ = core_rpc::CORE_RPC.set(core_rpc::CoreRpcConfig {
        url: cli.core_url.trim().to_string(),
        user: cli.core_user.clone(),
        password: cli.core_password.clone(),
    });

    tracing::info!(
        ?network,
        core_url = %cli.core_url,
        "starting LUCKYPROTOCOL indexer (Core-only mode)"
    );

    // PROCESS-LOCK SURROGATE — bind the HTTP port BEFORE any state
    // mutation. If another indexer is already running on this bind
    // address, TcpListener::bind fails with EADDRINUSE; we surface
    // that as a clean exit message rather than racing with the other
    // instance over the snapshot file.
    let listener = match tokio::net::TcpListener::bind(cli.bind).await {
        Ok(l) => l,
        Err(e) => {
            anyhow::bail!(
                "failed to bind {} (is another luckyprotocol-indexer instance already running on this port?): {}",
                cli.bind, e
            );
        }
    };
    tracing::info!(bind = %cli.bind, "process-lock listener bound — proceeding with snapshot load");

    // Configure snapshot persistence path before any backfill kicks off
    // so the trigger inside backfill_range can fire on the very first
    // SNAPSHOT_INTERVAL_BLOCKS-aligned block.
    let snapshot_path: Option<PathBuf> = if cli.snapshot_path.trim().is_empty() {
        None
    } else {
        let p = PathBuf::from(cli.snapshot_path.clone());
        let _ = source::SNAPSHOT_PATH.set(p.clone());
        Some(p)
    };

    let mut state_init = indexer::IndexerState::new(network);

    // Attempt warm-restart from disk snapshot. Failure here just falls
    // through to a cold scan — never fatal.
    // CRITICAL: before accepting the snapshot, validate its tail block
    // hashes against the current canonical chain (per Bitcoin Core). If
    // even one diverges, a reorg happened while we were down and any
    // indexed BET / SEND / DEPLOY in the orphaned blocks must NOT be
    // replayed back into state — refuse the snapshot, cold-scan instead.
    let mut warm_started_at: Option<u32> = None;
    if let Some(p) = snapshot_path.as_ref() {
        match try_load_snapshot(p).await {
            Ok(Some(snap)) => {
                // Schema version gate: snapshots from a previous protocol
                // cohort (different SNAPSHOT_VERSION) carry state from
                // blocks that are now pre-activation. Refuse them so a
                // clean cold-scan re-derives the canonical state from
                // the new activation height.
                if snap.version != indexer::SNAPSHOT_VERSION {
                    tracing::warn!(
                        snapshot_version = snap.version,
                        current_version = indexer::SNAPSHOT_VERSION,
                        snapshot_path = %p.display(),
                        "snapshot version mismatch — refusing warm-restart, cold-scanning"
                    );
                    if let Err(e) = tokio::fs::remove_file(p).await {
                        tracing::warn!(error = ?e, "failed to remove stale-version snapshot file");
                    }
                } else {
                    let valid = source::validate_snapshot_against_canonical(&snap)
                        .await
                        .unwrap_or(false);
                    if valid {
                        let h = snap.indexed_height;
                        state_init.restore_from_snapshot(snap);
                        warm_started_at = Some(h);
                        tracing::info!(restored_height = h, snapshot_path = %p.display(),
                            "warm-restart from disk snapshot (canonical hashes verified)");
                    } else {
                        tracing::warn!(snapshot_path = %p.display(),
                            "snapshot tail diverges from canonical chain — refusing warm-restart, cold-scanning");
                        if let Err(e) = tokio::fs::remove_file(p).await {
                            tracing::warn!(error = ?e, "failed to remove stale snapshot file");
                        }
                    }
                }
            }
            Ok(None) => {
                tracing::info!(snapshot_path = %p.display(),
                    "no disk snapshot found — cold-scanning");
            }
            Err(e) => {
                tracing::warn!(error = ?e, snapshot_path = %p.display(),
                    "snapshot load failed — cold-scanning");
            }
        }
    }

    let state = std::sync::Arc::new(parking_lot::RwLock::new(state_init));

    // Event-driven wake handle — shared between the run_poller's
    // tokio::select! and the HTTP server's POST /poll-now handler.
    // Created here (not inside run_poller) so server::set_poll_notify
    // can register a clone BEFORE the HTTP server starts accepting
    // requests.
    let poll_notify = std::sync::Arc::new(tokio::sync::Notify::new());
    server::set_poll_notify(poll_notify.clone());

    // Background poller — does the initial backfill (from snapshot height
    // if warm-started, else from --start-height / activation) then keeps
    // up with the tip.
    let state_for_poll = state.clone();
    let effective_start = match (warm_started_at, cli.start_height) {
        // Warm restart wins — pick up where the snapshot left off.
        (Some(h), _) => Some(h + 1),
        // Cold scan — honor --start-height if given, else default in source.rs
        // (= LCKPROTOCOL_START_HEIGHT).
        (None, override_h) => override_h,
    };
    let poll_notify_for_loop = poll_notify.clone();
    tokio::spawn(async move {
        if let Err(e) = source::run_poller(
            state_for_poll, effective_start, cli.poll_secs, poll_notify_for_loop,
        ).await {
            tracing::error!(error = ?e, "poller died");
        }
    });

    // HTTP server — listener was bound at the top of main() as a
    // process-lock surrogate, so this just consumes it and serves.
    server::serve(state, listener).await
}

/// Best-effort load of the on-disk JSON snapshot. Returns:
///   Ok(Some) — snapshot loaded successfully
///   Ok(None) — file doesn't exist (first run / snapshot disabled)
///   Err     — file existed but parse / IO failed (caller logs + falls back)
async fn try_load_snapshot(
    path: &std::path::Path,
) -> anyhow::Result<Option<indexer::StateSnapshot>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = tokio::fs::read(path).await?;
    let snap: indexer::StateSnapshot = serde_json::from_slice(&bytes)?;
    Ok(Some(snap))
}
