# LUCKYPROTOCOL Indexer

Reference Rust implementation of the LUCKYPROTOCOL meta-protocol on Bitcoin
mainnet. Watches a Bitcoin Core node, parses every LUCKYPROTOCOL `OP_RETURN`
payload, replays the protocol rules, and serves the derived per-address
token balances + bet history via a small JSON HTTP API.

The browser wallet at [`luckyprotocol-web`](https://github.com/luckyprotocol/luckyprotocol-web)
ships its own JS port of this indexer that runs entirely client-side. This
Rust version is what you self-host when you want zero-trust verification of
the protocol state — **the only chain source is your own Bitcoin Core node**.
No Esplora dependency, no Alchemy fallback, no third-party indexer to trust.

**Status**: cohort v950950 (activation height 950,950, three-fee consensus
model). See [`PROTOCOL.md`](PROTOCOL.md) for the canonical wire spec.

## What this indexer does

1. Cold-scans the chain from the protocol activation height
   (`LCKPROTOCOL_V1_HEIGHT = 950,950`) to current tip via `getblock <hash> 3`.
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

## Why Core-only (no Esplora, no Alchemy)

The whole point of self-hosting an indexer is **zero-trust verification**.
If the indexer falls back to a third-party HTTP service the moment your
node hiccups, you've reintroduced exactly the trust assumption you were
trying to remove. So this binary refuses to compile that fallback in at
all — `getblock` over your local RPC is the only chain source. If your
node is down, the indexer retries with backoff and waits. It does not
serve derived state from somebody else's blockchain.

Performance bonus: a single `getblock <hash> 3` RPC call (verbosity=3
with prevout metadata) replaces what used to be ~50 Esplora HTTP
requests per block. Cold-scan throughput is bounded by your node's
JSON serialization speed, not by anyone's rate limit.

## Hardware requirements

- 4 vCPU / 8 GB RAM minimum (16 GB comfortable)
- 1 TB SSD if running alongside a Bitcoin Core archival node
  (~50 GB if Bitcoin Core is pruned — see "Pruned mode" below)
- A reachable Bitcoin Core 24.0+ node (verbosity=3 was added in 24.0)

## Build

```bash
# Install Rust (one-liner)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# System build deps (Ubuntu/Debian)
apt install -y build-essential pkg-config libssl-dev git

# Clone + build
git clone https://github.com/luckyprotocol/luckyprotocol-indexer.git
cd luckyprotocol-indexer
cargo build --release

# Binary lands at:
ls -lh target/release/luckyprotocol-indexer
```

First build takes 1–10 minutes depending on machine + whether your
cargo cache is warm. Subsequent builds are incremental.

## Run

```bash
./target/release/luckyprotocol-indexer \
  --bind 127.0.0.1:8765 \
  --core-url http://127.0.0.1:8332 \
  --core-user luckyprotocol \
  --core-password <bitcoin-rpc-password> \
  --snapshot-path /var/lib/luckyprotocol/snapshot.json
```

All three `--core-*` flags are **required** — there is no other way
for the indexer to get block data. If you don't have `rpcuser` /
`rpcpassword` in your `bitcoin.conf` yet, add them and restart
bitcoind:

```ini
# /etc/bitcoin/bitcoin.conf
server=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcuser=luckyprotocol
rpcpassword=<long-random-string>
```

Cookie auth is also supported — pass `--core-user __cookie__` and use
the password portion of `<datadir>/.cookie` (the part after the colon).
Note that cookies regenerate on every Core restart, so for a long-
running indexer you'll usually want explicit `rpcuser`/`rpcpassword`
instead.

### Pruned mode

If you're running Bitcoin Core with `prune=10000` or similar, that's
fine — `getblock <hash> 3` works on pruned chains as long as the block
is still in the prune window (or in the keep-recent set + UTXO undo
data). For initial cold-scan, blocks 950,950 → tip must be present
when the indexer reads them, so either:
- Set `prune` large enough to cover ≥ `(current_tip - 950,950) × 1.5 MB`,
  OR
- Let the indexer race Bitcoin Core's IBD so it captures blocks as
  they confirm before being pruned.

For a long-term-stable production indexer, archival mode (no pruning,
~600 GB at time of writing) is simpler.

## systemd unit (Linux production)

Recommended layout — keep the password out of the unit file by using
an `EnvironmentFile` that's readable only by the service user:

```ini
# /etc/luckyprotocol/env  (chmod 600, owned by luckyprotocol:luckyprotocol)
LUCKYPROTOCOL_BIND=127.0.0.1:8765
LUCKYPROTOCOL_CORE_URL=http://127.0.0.1:8332
LUCKYPROTOCOL_CORE_USER=luckyprotocol
LUCKYPROTOCOL_CORE_PASSWORD=<long-random-string>
LUCKYPROTOCOL_SNAPSHOT_PATH=/var/lib/luckyprotocol/snapshot.json
```

```ini
# /etc/systemd/system/luckyprotocol-indexer.service
[Unit]
Description=LUCKYPROTOCOL global indexer
After=bitcoind.service network-online.target
Wants=bitcoind.service
StartLimitBurst=5
StartLimitIntervalSec=300

[Service]
Type=simple
User=luckyprotocol
Group=luckyprotocol
WorkingDirectory=/var/lib/luckyprotocol
EnvironmentFile=/etc/luckyprotocol/env
ExecStart=/usr/local/bin/luckyprotocol-indexer
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/luckyprotocol
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Then:

```bash
useradd -r -s /bin/false luckyprotocol
mkdir -p /var/lib/luckyprotocol /etc/luckyprotocol
chown luckyprotocol:luckyprotocol /var/lib/luckyprotocol
# … write /etc/luckyprotocol/env (chmod 600 it) …
systemctl daemon-reload
systemctl enable --now luckyprotocol-indexer
journalctl -u luckyprotocol-indexer -f
```

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
