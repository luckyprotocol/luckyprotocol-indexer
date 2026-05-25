# LUCKYPROTOCOL Indexer

Reference Rust implementation of the LUCKYPROTOCOL meta-protocol on Bitcoin
mainnet. Watches a Bitcoin node (or Esplora REST endpoint), parses every
LUCKYPROTOCOL `OP_RETURN` payload, replays the protocol rules, and serves
the derived per-address token balances + bet history via a small JSON HTTP
API.

The browser wallet at [`luckyprotocol-web`](https://github.com/luckyprotocol/luckyprotocol-web)
ships its own JS port of this indexer that runs entirely client-side. This
Rust version is what you self-host when you want zero-trust verification of
the protocol state — no Esplora dependency, no third-party indexer to trust.

**Status**: cohort v950950 (activation height 950,950, three-fee consensus
model). See [`PROTOCOL.md`](PROTOCOL.md) for the canonical wire spec.

## What this indexer does

1. Cold-scans the chain from the protocol activation height
   (`LCKPROTOCOL_V1_HEIGHT = 950,950`) to current tip.
2. Parses every `OP_RETURN` output, applies the three protocol opcodes
   (`DEPLOY`, MINE/BET, `SEND`) per the rules in `PROTOCOL.md`.
3. Maintains an in-memory state machine:
   - `tokens` — append-only registry of every deployed ticker.
   - `utxo_balances` — every UTXO carrying protocol tokens.
   - `bets` / `transfers` / `deploys` — audit logs (FIFO-bounded).
4. Persists a snapshot every N blocks so warm restarts skip the full
   re-scan.
5. Serves a JSON HTTP API:

   ```
   GET /                               — health + tip / scan state
   GET /balances/:address              — { ticker: amount } map
   GET /utxos/:address                 — UTXO-level breakdown
   GET /bets/:address                  — bets sent by this address
   GET /transfers/:address             — transfers sent by this address
   GET /tokens?limit=N&offset=N        — paginated token registry
   GET /tokens/:ticker/holders?...     — paginated holders for one ticker
   ```

## Hardware requirements

- 4 vCPU / 8 GB RAM minimum (16 GB comfortable)
- 1 TB SSD if running alongside a Bitcoin Core archival node
  (~50 GB if Bitcoin Core is pruned, see "Pruned mode" below)
- Stable internet, low-rate-limit (Alchemy key recommended over public
  Esplora if you go the Esplora route)

## Build

```bash
# Install Rust (one-liner)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Clone + build
git clone https://github.com/luckyprotocol/luckyprotocol-indexer.git
cd luckyprotocol-indexer
cargo build --release

# Binary lands at:
ls -lh target/release/luckyprotocol-indexer
```

First build takes 5–10 minutes (downloads + compiles ~250 crates). Subsequent
builds are incremental.

## Run

### Path A — with your own Bitcoin Core node (recommended, fully self-sovereign)

```bash
./target/release/luckyprotocol-indexer \
  --bind 127.0.0.1:8765 \
  --core-url http://127.0.0.1:8332 \
  --core-user luckyprotocol \
  --core-password <bitcoin-rpc-password> \
  --snapshot-path /var/lib/luckyprotocol/snapshot.json
```

The indexer pulls full blocks via `getblock <hash> 3` (requires Core 24+).
This is the **fastest and zero-trust** path — every block comes from a
Bitcoin node you control, every state transition is verified locally.

### Path B — with Alchemy + public Esplora (no Bitcoin node)

```bash
./target/release/luckyprotocol-indexer \
  --bind 127.0.0.1:8765 \
  --alchemy-key <your-alchemy-key> \
  --snapshot-path /var/lib/luckyprotocol/snapshot.json
```

Slower (rate-limited HTTP), and you trust Alchemy + mempool.space not to
serve fabricated blocks. The merkle-root check in the indexer catches gross
fabrication but a stale block hash at a given height is undetectable
without a second source.

### Pruned mode

If you're running Bitcoin Core with `prune=10000` or similar, that's fine —
the indexer only reads blocks via `getblock <hash> 3`, which works on pruned
chains (Bitcoin Core keeps the recent N blocks in the prune window plus the
UTXO set + undo data). Initial scan needs blocks 950,950 → tip to be present
in the prune window, so either:
- Set `prune` large enough to cover ≥ (current_tip - 950,950) × 1.5 MB
- Or let the indexer race Bitcoin Core's IBD so it captures blocks as
  they confirm before being pruned

## systemd unit (Linux production)

```ini
# /etc/systemd/system/luckyprotocol-indexer.service
[Unit]
Description=LUCKYPROTOCOL global indexer
After=bitcoind.service
Wants=bitcoind.service

[Service]
Type=simple
User=luckyprotocol
WorkingDirectory=/var/lib/luckyprotocol
ExecStart=/usr/local/bin/luckyprotocol-indexer \
  --bind 127.0.0.1:8765 \
  --core-url http://127.0.0.1:8332 \
  --core-user luckyprotocol \
  --core-password ${RPC_PASS} \
  --snapshot-path /var/lib/luckyprotocol/snapshot.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then `systemctl daemon-reload && systemctl enable --now luckyprotocol-indexer`.

## Verifying state agreement

Run two indexers (e.g. yours + a friend's) against the same tip and compare
`GET /tokens` + `GET /balances/:any-address`. They MUST produce byte-identical
output. Divergence = bug in one of them.

Conformance test fixtures live in `tests/` (TODO).

## Protocol versioning

Each protocol activation height bump invalidates ALL prior snapshots.
The indexer refuses to load a snapshot with a different `SNAPSHOT_VERSION`
and cold-rescans from `LCKPROTOCOL_V1_HEIGHT`. Current cohort: **v950950**.

See `PROTOCOL.md` for the full canonical spec.

## License

MIT — see [LICENSE](LICENSE).

The wire spec in `PROTOCOL.md` is the canonical reference. When this code
and the spec disagree, the spec wins — file an issue.
