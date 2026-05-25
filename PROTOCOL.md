# LUCKYPROTOCOL Protocol Specification — v1 (UTXO-bound, cohort v950950)

**Version:** 1.0 (UTXO state-machine)
**Activation height:** 950,950 (mainnet)
**Status:** Canonical — every honest LUCKYPROTOCOL indexer MUST conform byte-for-byte.

**Cohort history** (each bump invalidates ALL prior on-chain state):
- 949,090 / 949,375 / 950,382 — earlier cohorts, withdrawn
- **950,950** — current. Adds the three-fee consensus model
  (DEPLOY == 5,460 sats, MINE == 546 sats, SEND == 546 sats, all
  EXACTLY to `PROJECT_FEE_ADDRESS`) and unifies the Rust + JS
  indexer activation heights (previously divergent at 949,375 vs
  950,382).

## 0. Design

LUCKYPROTOCOL is a UTXO-bound fungible-token + on-chain casino protocol on Bitcoin mainnet. State transitions are encoded in a single `OP_RETURN` output per transaction; the wire format is forward-compatible with existing Bitcoin tooling (no consensus changes, no soft-fork, no covenants).

Token authority is UTXO ownership. Whoever can produce a Bitcoin signature spending a token-bearing outpoint is the holder. There is no address ledger; there is no indexer arbitration; there is no off-chain attribution heuristic. The chain enforces what Bitcoin already enforces.

**All pre-activation history is unrecognized.** Indexers do NOT replay or carry over any state from blocks below the activation height. In particular, any payload that uses a different protocol prefix (including legacy `BTCASINO|*` bytes that may exist in earlier chain history) is invisible to a LUCKYPROTOCOL indexer.

---

## 1. Activation

```
LCKPROTOCOL_V1_HEIGHT = 950,950
```

- Blocks `< 950,950`: indexer treats as pre-activation, no state derived.
- Blocks `>= 950,950`: protocol applies.

The wire prefix is the literal ASCII string `LUCKYPROTOCOL`. Indexers MUST hard-gate on block height in addition to prefix match — the prefix alone does NOT activate the protocol.

---

## 2. Network

Mainnet only. Testnet / signet / regtest are not supported.

---

## 3. Wire format

### 3.1 OP_RETURN output — formal definition

A transaction output is an **OP_RETURN output** iff its `scriptPubKey` begins with the byte `0x6a` (`OP_RETURN`) AT INDEX 0. Specifically:

- **MUST**: `scriptPubKey[0] == 0x6a` — the very first script byte is `OP_RETURN`.
- The "segwit-friendly" form `OP_FALSE OP_RETURN <data>` (script starting with `0x00 0x6a`) is **NOT** an OP_RETURN output for protocol purposes. It is a normal anyone-can-spend output and is ignored as a payload carrier.
- A script that contains `OP_RETURN` mid-way (e.g. after a push) is **NOT** an OP_RETURN output and is ignored as a payload carrier.

A LUCKYPROTOCOL transaction MUST contain **EXACTLY ONE** OP_RETURN output as defined above. Transactions with **zero** OP_RETURN outputs carry no payload (input pool routes per §7.4 — strict burn unless the tx happens to be non-protocol-aware with no token-bearing inputs at all). Transactions with **two or more** OP_RETURN outputs have NO protocol effect — input UTXO balances route per §7.4 as if the payload weren't there.

### 3.1.1 Push-opcode coverage

After the leading `0x6a` (`OP_RETURN`), the indexer extracts the payload from **exactly one** subsequent push instruction. Coverage:

- `0x01..=0x4b` — direct push of `n` bytes (`n` is the opcode itself).
- `0x4c` (`OP_PUSHDATA1`) — next 1 byte = length (0..=255).
- `0x4d` (`OP_PUSHDATA2`) — next 2 bytes little-endian = length (0..=65535).
- `0x4e` (`OP_PUSHDATA4`) — next 4 bytes little-endian = length (0..=2^32-1).

A **hard cap** on the declared length is enforced: anything declaring more than **256 bytes** of payload is **REJECTED** outright (treated as no payload). This caps DoS surface from malicious PUSHDATA4 entries declaring 4 GiB.

**Multiple pushes after `OP_RETURN`**: if the script contains MORE than one push after the leading `OP_RETURN` opcode, the output is **REJECTED** as a payload carrier — the tx has no LUCKYPROTOCOL payload, input pool routes per §7.4. We do not concatenate pushes. Rationale: ambiguous parsing is a consensus-divergence vector (different implementations may differ on whether to concatenate or pick first / last).

**Pre-`OP_RETURN` bytes**: the leading byte at `scriptPubKey[0]` MUST be `0x6a`. Any prefix (e.g. `OP_FALSE OP_RETURN`) disqualifies the output.

### 3.1.2 Payload byte-level rules

The payload bytes extracted in §3.1.1 are parsed as a UTF-8 string:

- **MUST be valid UTF-8.** If `std::str::from_utf8(bytes)` fails, the payload is **REJECTED** (no LUCKYPROTOCOL effect). Bytes-mode parsing is NOT supported — we hard-gate UTF-8 to keep the wire format human-readable in any block explorer.
- The protocol prefix `LUCKYPROTOCOL` is matched **byte-for-byte, case-sensitive**. `luckyminer|...`, `Luckyminer|...`, etc. are NOT recognized.
- Opcodes (`DEPLOY`, `SEND`, `iron`, `bronze`, `silver`, `gold`) are matched **case-sensitive**. `deploy`, `Send`, `IRON`, `Gold` etc. are REJECTED.
- The `PICK` argument for hex-tier BETs (`bronze` / `silver` / `gold`) is matched **case-INsensitive** (the indexer lower-cases the input). All hex characters are valid (`[0-9a-fA-F]`).
- `TICKER` MUST match `[A-Z0-9]{1,8}` exactly, case-sensitive uppercase. `abc`, `Mixed1` etc. are REJECTED.
- Numeric fields (`AMT`, `TO_OUT_IDX`, `WIN_OUT_IDX`, `CHANGE_OUT_IDX`) MUST be canonical decimal (§3.3) — ASCII digits only, no leading zeros except single `0`, no plus / whitespace / sci-notation.

### 3.1.3 Field-count and delimiter rules

Each opcode declares an **exact** number of pipe-delimited fields (§3.2). Any payload with MORE OR FEWER fields than the opcode demands is **REJECTED**.

- **Trailing empty field**: `LUCKYPROTOCOL|SEND|ABC|100|1|2|` (trailing `|`) is treated as **6 args after the prefix** (`SEND`, `ABC`, `100`, `1`, `2`, ``) — one more than `SEND`'s maximum. **REJECTED.**
- **Trailing whitespace**: a payload ending in whitespace or any byte other than the last meaningful field's last char is **REJECTED**. No trimming.
- **Internal empty field**: `LUCKYPROTOCOL|SEND|ABC||1` (empty `AMT`) is **REJECTED** (empty `AMT` fails `is_canonical_uint`).

Indexers MUST implement the parser as a strict tokenizer: split on `|`, count tokens, fail on count mismatch BEFORE attempting field validation.

### 3.1.4 Form summary

```
LUCKYPROTOCOL|<opcode>|<arg1>|<arg2>|...|<argN>
```

The protocol prefix is the literal ASCII string `LUCKYPROTOCOL`. Each opcode (§3.2) defines the exact `N` and the per-field shape.

### 3.2 Three opcodes

#### DEPLOY

```
LUCKYPROTOCOL|DEPLOY|<TICKER>
```

- `TICKER`: 1-8 ASCII chars from `[A-Z0-9]`.
- Supply is IMPLICIT at exactly 21,000,000 (not in payload — unconditional).

**Effect:** First-write-wins. If `TICKER` already exists in the registry, OR the **consensus-required protocol fee** is missing (§3.2.0.1 below), this DEPLOY is recorded with `applied: false`. On success: `tokens[TICKER] = { supply: 21M, minted: 0, deployer: sender(largest-input-contributor of THIS tx) }`.

DEPLOY does NOT mint any tokens directly. Tokens are only minted by BET wins (§3.2.2) and only up to `supply - minted`.

##### 3.2.0.1 DEPLOY protocol fee (the protocol's ONE consensus-required fee)

A DEPLOY transaction MUST include at least one output paying **EXACTLY 5,460 satoshis** to the canonical project address:

```
PROJECT_FEE_ADDRESS      = bc1pyefhtnuz2gw04fsynlsseeh847cqy20dw7yt6fnavm9fgnewcr7q88gqf3
DEPLOY_PROTOCOL_FEE_SATS = 5_460
```

A DEPLOY tx that does NOT include such an output is rejected by every honest indexer (`applied=false`, ticker NOT registered). The fee output's `vout` position is unconstrained; the indexer scans every output of the DEPLOY tx for an EXACT match on (address, sat-value == 5,460).

**Strict-equality rule.** As of cohort v950950 the fee check is `==`, not `≥`. The same rule applies to MINE and SEND fees (see §3.2.1, §3.2.2). Rationale: each tx has at most one "this is the protocol fee" output, distinct from any voluntary donation outputs (which would carry a different amount). PROJECT_FEE_ADDRESS-history sweeps become unambiguous — every 5,460-sat output is a DEPLOY, every 546-sat output is a MINE or SEND.

**Anti-spam rationale.** The `tokens` map is append-only — once a ticker is registered, the indexer keeps the entry indefinitely. Without a meaningful fee, an attacker could mass-deploy permutations of 1-8-char tickers at ~546-sat dust cost and inflate every indexer's memory + frontend token-list response forever. 5,460 sat (≈ 10× dust, ≈ $0.50 at $10K/BTC) makes spam economically prohibitive while still being trivially affordable for honest deployers.

A wallet that emits DEPLOY without the fee output (or with a fee output paying any amount ≠ 5,460 sat, or to any address other than `PROJECT_FEE_ADDRESS`) will produce on-chain transactions that look valid at the Bitcoin layer but are rejected by every LUCKYPROTOCOL indexer — the ticker is never registered, the spent fees are gone.

#### 3.2.1 MINE protocol fee (cohort v950950+)

A MINE / BET transaction MUST include at least one output paying **EXACTLY 546 satoshis** to `PROJECT_FEE_ADDRESS`:

```
MINE_PROTOCOL_FEE_SATS = 546
```

A MINE tx without this output is rejected: `status = Invalid`, no reward credit even on predicate hit. Residual input pool still routes per `change_out_idx` so the sender's tokens aren't burned unfairly for the fee miss.

Before cohort v950950, the 546-sat output was wallet-only behavior. The bump to consensus closes the "free MINE" vector (a non-fee-paying tx earning token rewards) and guarantees every applied MINE pays a project fee — making PROJECT_FEE_ADDRESS history a complete record of every protocol op.

#### 3.2.2 SEND protocol fee (cohort v950950+)

A SEND transaction MUST include at least one output paying **EXACTLY 546 satoshis** to `PROJECT_FEE_ADDRESS`:

```
SEND_PROTOCOL_FEE_SATS = 546
```

A SEND tx without this output is rejected: `applied=false`, no balance transfer. Residual input pool still routes per `change_out_idx`.

Before cohort v950950 the rule was inconsistent (JS indexer enforced ≥ 546; Rust indexer didn't enforce at all). The v950950 bump unifies both at `== 546`.

#### BET

```
LUCKYPROTOCOL|<TIER>|<PICK>|<TICKER>|<WIN_OUT_IDX>
```

- `TIER` ∈ `{iron, bronze, silver, gold}`
- `PICK`: tier-dependent (see §5)
- `TICKER`: 1-8 ASCII chars from `[A-Z0-9]`
- `WIN_OUT_IDX`: decimal `[0..255]`, points at one of the tx's `vout` outputs that will receive the won tokens.

**Effect:** Settle inline at the BET tx's confirming block. If the predicate hits AND `TICKER` is deployed AND `WIN_OUT_IDX` is a valid vout AND that vout is NOT itself an OP_RETURN:

```
reward = tier_reward(TIER).min(supply - minted)
tokens[TICKER].minted += reward
utxo_balances[(tx.txid, WIN_OUT_IDX)][TICKER] += reward
```

Recorded in `bets` log either way (Settled / Invalid / cap_exhausted). NO sender attribution is required for BET — the WIN_OUT_IDX UTXO is the sole authority over the won tokens.

#### SEND

```
LUCKYPROTOCOL|SEND|<TICKER>|<AMT>|<TO_OUT_IDX>[|<CHANGE_OUT_IDX>]
```

- `TICKER`: 1-8 ASCII chars from `[A-Z0-9]`
- `AMT`: canonical decimal in token-smallest-units. **MUST be in `[1, MAX_SEND_AMT]` where `MAX_SEND_AMT = REQUIRED_TOKEN_SUPPLY = 21,000,000`.** Outside this range (including `0`, anything > 21,000,000, or any string that would parse as bignum on languages with unbounded ints) is REJECTED. Implementations MUST also reject any payload whose `AMT` source string is longer than 20 characters (u64::MAX's decimal width) — this is the cross-language overflow gate so a `999999999999999999999999999999999` payload is rejected by Python/JS/Go indexers identically to Rust's u64-parse-failure.
- `TO_OUT_IDX`: decimal `[0..255]`, recipient vout
- `CHANGE_OUT_IDX`: optional, decimal `[0..255]`. If absent, residual is BURNED (§7.4).

**Effect:** Pool the input UTXOs' balances of `TICKER` (§7.2). If pool >= AMT:

```
utxo_balances[(tx.txid, TO_OUT_IDX)][TICKER] += AMT
remainder_pool[TICKER] = pool[TICKER] - AMT
```

Then `remainder_pool` flows to the change output (§7.3-7.4).

If pool < AMT: SEND fails, ALL input pool tickers (including the requested one) route per §7.4 — to `CHANGE_OUT_IDX` if specified, otherwise BURNED.

### 3.3 Numeric form

Strict canonical decimal: ASCII digits only, no leading zeros (except single `0`), no plus / whitespace / sci-notation. Reference: `protocol.rs::is_canonical_uint`.

---

## 4. Tier rewards

Reward in token-smallest-units:

| Tier   | Reward    | Predicate K |
|--------|-----------|-------------|
| iron   | 100       | 1 hex char  |
| bronze | 1,000     | 1 hex char  |
| silver | 10,000    | 2 hex chars |
| gold   | 200,000   | 3 hex chars |

---

## 5. Settlement predicate

The bet's confirming block hash `hash_N` decides the outcome. Settlement tail = last K hex chars of `hash_N` (lowercase):

- iron: `die = (u32_from_hex(tail) % 6) + 1`. Pick `odd` wins iff `die % 2 == 1`; pick `even` wins iff `die % 2 == 0`.
- bronze/silver/gold: pick wins iff lowercase pick string equals settlement tail.

Picks are tier-validated:

| Tier   | Pick                             |
|--------|----------------------------------|
| iron   | `odd` or `even`                  |
| bronze | 1 lowercase hex char `[0-9a-f]`  |
| silver | 2 lowercase hex chars            |
| gold   | 3 lowercase hex chars            |

---

## 6. UTXO state

The indexer's authoritative state is:

```
utxo_balances : Map<Outpoint, UtxoEntry { address, balances }>
address_utxos : Map<Address, Set<Outpoint>>     -- reverse index
tokens        : Map<Ticker, RegistryEntry>
```

`Outpoint = "txid:vout"` (string-keyed for JSON compat). A given `Outpoint` exists in `utxo_balances` iff the associated UTXO carries protocol tokens. `UtxoEntry.address` is the spending address recorded when the UTXO was created (None for unparseable / non-standard scripts). `UtxoEntry.balances` is `Map<Ticker, u64>`.

`address_utxos` is a reverse index (address → set of outpoint keys) maintained in lockstep with `utxo_balances` so `/balances/:address` answers in O(|address's UTXOs|) without a full scan. Both maps are equally authoritative.

When a UTXO is spent (its outpoint appears in some tx's vin), its `UtxoEntry` is removed from `utxo_balances`, its outpoint is removed from `address_utxos[entry.address]` (and the address entry itself dropped if its set is now empty), and its tokens are routed per §7.

---

## 7. Tx-level accounting

Every confirmed tx in a protocol-active block is processed in chain order (§9). For each tx:

### 7.1 Input pool

Build a fresh `input_pool : Map<Ticker, u64>`:

```
for vin in tx.vin:
    outpoint = (vin.txid, vin.vout)
    if utxo_balances.contains(outpoint):
        for (ticker, amt) in utxo_balances.remove(outpoint):
            input_pool[ticker] += amt
```

`input_pool` aggregates all token balances released by the tx's inputs. The vins themselves are authorized by Bitcoin signatures — no further attribution check needed.

### 7.2 Multi-ticker input rejection

**A single tx may consume token UTXOs of AT MOST ONE ticker.** If `input_pool` contains two or more distinct tickers after Step 7.1, the entire tx is treated as protocol-invalid: the input pool is cleared (full BURN), no edict is applied, any LUCKYPROTOCOL payload on the tx is recorded with `applied=false` / `status=Invalid`.

Rationale: a SEND payload only declares ONE ticker. Allowing mixed-ticker inputs would either (a) silently drop the unmentioned tickers (a footgun + a divergence vector between indexer implementations that may resolve "what to do with them" differently), or (b) require complex per-ticker routing rules that bloat the spec. The strict rule is "one ticker per tx or no tokens move" — wallets that need to spend multiple tickers MUST construct one tx per ticker. The LUCKYPROTOCOL wallet's coin selector enforces this client-side; non-protocol-aware spenders trigger BURN.

### 7.3 Apply OP_RETURN payload (if any)

Parse the (single, valid) LUCKYPROTOCOL OP_RETURN. Its effect:

- **DEPLOY**: register ticker (no UTXO output assignment). `input_pool` falls through to step 7.4 untouched.
- **BET**: if predicate hits + ticker deployed + reward > 0, append `(TICKER → reward)` to `output_assignments[WIN_OUT_IDX]`. Note: BET does NOT consume `input_pool`. Token-bearing UTXOs in vin would just have their tokens routed per §7.4.
- **SEND**: if `input_pool[TICKER] >= AMT`, append `(TICKER → AMT)` to `output_assignments[TO_OUT_IDX]`, decrement `input_pool[TICKER] -= AMT`. If insufficient, no assignment (SEND fails); `input_pool` falls through unchanged.

### 7.4 Residual routing — STRICT BURN policy

A "residual" is whatever remains of `input_pool` after the (optional) LUCKYPROTOCOL edict has been applied. Routing rules:

| Tx shape | Residual destination |
|---|---|
| SEND payload with valid `change_out_idx` | `change_out_idx` vout |
| SEND payload with missing / invalid / OP_RETURN `change_out_idx` | **BURNED** |
| BET payload | **BURNED** (BET doesn't consume input pool — any tokens in vin are residual) |
| DEPLOY payload | **BURNED** |
| No LUCKYPROTOCOL payload | **BURNED** |

**Burn means the indexer drops the residual without assigning it to any UTXO.** There is no `default_output` fallback. Users MUST use a LUCKYPROTOCOL-aware wallet (which always emits a valid SEND `change_out_idx` for any token-UTXO spend) for any operation involving a token UTXO. Spending a token UTXO from any other wallet — Bitcoin Core's `sendtoaddress`, a hardware wallet's PSBT flow, a third-party multisig coordinator, anything that doesn't know about LUCKYPROTOCOL — destroys the tokens. This eliminates the "ghost balance" attack where a non-protocol wallet could be tricked into moving someone else's tokens to an unexpected destination.

Operationally: the LUCKYPROTOCOL wallet's `cmd_publish_transfer` ALWAYS emits SEND with `change_out_idx = 2` (vout 2 = drain output). So legitimate SENDs always preserve residual at the sender's drain address. Burns only happen for unintended spends.

### 7.5 OP_RETURN outputs are sterile

`utxo_balances` MUST NEVER assign to an outpoint whose vout is an OP_RETURN. Such outputs are not spendable on Bitcoin's UTXO set (they're provably-unspendable by `OP_RETURN`'s consensus rule). Tokens routed there are lost.

The indexer enforces this at edict-application time:
- `WIN_OUT_IDX` / `TO_OUT_IDX` / `CHANGE_OUT_IDX` referencing an OP_RETURN vout are rejected (treated as missing — SEND falls through to §7.4 burn; BET predicate-hit produces no credit + records `Invalid`).

---

## 8. Sender attribution (audit-only)

For BET / SEND / DEPLOY records (the audit log), a "sender" is recorded. This is purely informational — it does not authorize any state mutation. The rule is the "largest-contributor of input value" with vin-index tiebreak.

---

## 9. Apply order

Blocks in `block_height` ASC, txs within a block in their canonical block-tx index order (`/block/:hash/txs[/:start_index]` returns them in this order).

---

## 10. Idempotency

A given txid is processed at most once per session. The indexer's `by_txid` map ensures this.

---

## 11. State growth limits

Audit-log VecDeques are FIFO-evicting:

| Vec        | Cap     |
|------------|---------|
| `bets`     | 100,000 |
| `transfers`| 100,000 |
| `deploys`  |  10,000 |

`utxo_balances` and `tokens` are NOT evicted — they're consensus-relevant state. `utxo_balances` shrinks naturally as token UTXOs get spent; `tokens` only grows (one entry per deployed ticker, capped by economic gate of broadcasting a DEPLOY tx).

---

## 11.5 Block-body integrity (merkle root verification)

Every block fetched from Esplora is verified for body integrity before ANY state mutation:

1. Fetch the block header from `/block/:hash` — record `merkle_root` (the cryptographically committed root over all txids in canonical order).
2. Fetch the full tx list from the paginated `/block/:hash/txs[/:start_idx]` endpoint.
3. Walk the tx list in chain order, collect every `txid`, convert each to a `bitcoin::TxMerkleNode` (same SHA256d hash underlying as the txid).
4. Run `bitcoin::merkle_tree::calculate_root` over the iterator — this implements Bitcoin's canonical pairwise-SHA256d merkle algorithm.
5. Compare the computed root with the parsed `merkle_root_claimed` from step 1.
6. Match → proceed to apply. Mismatch → ABORT, log `tracing::error!`, do NOT advance `indexed_height`. Next poll retries from the same height.

This closes the "honest hash + fabricated body" attack class entirely. A malicious or compromised Esplora endpoint cannot feed the indexer fake LUCKYPROTOCOL tx entries: any fabricated tx list produces a merkle root that doesn't match the header's committed value, and the block is rejected.

What this still doesn't cover:
- Esplora could return a STALE block hash for a given height (claim block X is at height N when it's not on the canonical chain anymore). Defense: the indexer's reorg-detection probe (§12) re-checks recent block hashes against `/block-height/:h` on every poll cycle; cross-endpoint divergence is detected within one poll.
- Esplora could simply refuse to return certain blocks. Defense: this stalls the indexer but doesn't corrupt state — `indexed_height` is only advanced after a successful verification. Operators see the stall in `/health` and can switch endpoints.

For deployments demanding zero-trust: wire the indexer's `--core-url` flag at a self-hosted Bitcoin Core RPC. `getblock <hash> 3` returns a fully-verified block from the user's own node; the merkle check still applies as an extra safety belt.

## 12. Reorg + persistence

12-block detection horizon, snapshot ring of 8 × 12 blocks = 96, snapshot persisted every 12 blocks, canonical-hash validation on warm restart, reorg-storm circuit breaker (5 reorgs / 5 min → 10 min cooldown), tip regression guard.

`SNAPSHOT_VERSION` is `7` for LUCKYPROTOCOL v1 genesis. Snapshots from any earlier version (including the legacy BTCASINO codebase's v1-v6) are refused at load time and the indexer cold-scans from `LCKPROTOCOL_V1_HEIGHT`.

---

## 13. Wallet implementation notes

The following are RECOMMENDED safe-wallet practices. None of them are protocol-consensus rules — a wallet that ignores these will still produce valid transactions per the indexer's apply rules (§3-§7), but it can also produce transactions that DESTROY the user's tokens.

### 13.1 Input selection (consensus-adjacent)

**Strongly recommended**: BET and DEPLOY transactions SHOULD use **only pure-BTC UTXOs** as inputs. Spending a token-bearing UTXO in a BET or DEPLOY tx burns its tokens unconditionally (§7.4 — BET / DEPLOY without a SEND payload routes residual to BURN). A safe wallet maintains two pools and never mixes them:

- **BTC pool**: UTXOs at `utxo_balances[outpoint] == undefined` (no protocol tokens).
- **Token pool**: UTXOs at `utxo_balances[outpoint] != undefined`.

Inputs for BET / DEPLOY come from the BTC pool. Inputs for SEND come from the Token pool (of the relevant ticker) PLUS the BTC pool (for fee funding) — never a Token UTXO of a DIFFERENT ticker (§7.2 — multi-ticker rejection burns everything).

### 13.2 Output indices — compute, never hard-code

Wallets MUST compute `TO_OUT_IDX` / `CHANGE_OUT_IDX` / `WIN_OUT_IDX` from the actual constructed transaction's `vout` ordering AFTER building it. Hard-coded indices (e.g. "vout 2 is always change") break as soon as the coin-selector swaps inputs, the BTC fee output gets dropped (low fee, no change needed), or the wallet adds an extra recipient. The safe pattern is:

```
1. Build the tx with placeholder OP_RETURN (e.g. all-zero payload).
2. Iterate the resulting tx.vout, identify which vout is each role:
     - to_addr → TO_OUT_IDX
     - sender_drain_addr → CHANGE_OUT_IDX
     - sender_dust_to_self → WIN_OUT_IDX  (for BET)
3. Substitute the real OP_RETURN payload using those indices.
4. Re-sign.
```

### 13.3 SEND dry-run before signing

Wallets MUST simulate the SEND tx locally before showing the signing prompt. The simulation MUST verify, against the wallet's local view of `utxo_balances`:

- Sum of selected input UTXOs' `TICKER` balance ≥ `AMT`. (Else SEND fails per §3.2.)
- `TO_OUT_IDX` references a non-OP_RETURN vout that exists in the constructed tx.
- `CHANGE_OUT_IDX` references a non-OP_RETURN vout that exists in the constructed tx AND is distinct from `TO_OUT_IDX`.
- The fee output (= BTC change vout, if any) exists and is distinct from `TO_OUT_IDX` / `CHANGE_OUT_IDX`.
- Exactly one OP_RETURN output exists, at the expected vout index, with a payload byte-string that re-parses to the intended `ProtocolPayload::Xfer`.

Surface a confirmation screen showing:

- "Sending **X** of `TICKER` to **<to_addr>**"
- "Change **(pool − X)** returns to **<your drain addr>** (vout `CHANGE_OUT_IDX`)"
- "BTC fee: **N sats**"
- "Inputs consumed (these UTXOs will be spent):" — listed by `txid:vout` + sat value + token balance

Only after the user confirms does the wallet sign and broadcast. A wallet that signs without this dry-run can silently produce a SEND with the wrong indices, burning the entire input pool.

### 13.4 Dust output sizing

Each "real" output (TO, CHANGE, WIN) is a Bitcoin output and MUST be ≥ 546 sat (Bitcoin's standardness dust limit for P2WPKH). For SEND that means: `TO_OUT_IDX` and `CHANGE_OUT_IDX` outputs are each 546 sat regardless of token amount — token balances live in the indexer's derived state, not the Bitcoin output's sat value.

### 13.5 Project fees — all three opcodes consensus-enforce EXACT amounts (cohort v950950+)

All three protocol opcodes require a fee output to `PROJECT_FEE_ADDRESS`. The amount is checked with **strict equality** (==), not ≥:

| Opcode | Required fee (EXACT) |
|--------|----------------------|
| DEPLOY | 5,460 sats           |
| MINE   | 546 sats             |
| SEND   | 546 sats             |

Wallets that emit any other amount (e.g. 547 sats, or 1,000 sats) produce indexer-invalid transactions. The reference wallet's `PROJECT_FEE_SATS` constant (= 546) and `DEPLOY_PROTOCOL_FEE_SATS` constant (= 5,460) match these exactly.

**Why strict equality:**
- Each tx has at most ONE output that matches the protocol-fee pattern, distinct from any voluntary donation outputs (which would carry a different amount).
- PROJECT_FEE_ADDRESS history sweeps become unambiguous: every 5,460-sat output identifies a DEPLOY, every 546-sat output identifies a MINE or SEND. This makes the fee-address index a complete, precise enumeration of every protocol tx ever broadcast.
- Wallets can't quietly inflate fees and pocket the difference (since any amount > 546 / 5,460 fails the check).

**Why these specific amounts:**
- 5,460 sats for DEPLOY = 10× Bitcoin's P2WPKH dust limit. Makes the per-deploy spam cost equal to ~$0.50 (at $10K BTC), enough to deter attackers from mass-deploying junk tickers into the append-only registry while staying trivially affordable for honest deployers.
- 546 sats for MINE / SEND = exact Bitcoin dust limit. The smallest fee output the network will relay. Tiny enough that legitimate users pay a negligible amount per operation; high enough that fee-paying remains a real cost (prevents free MINE attempts).

**Historical evolution:**
- Cohort v950382 — only DEPLOY was consensus-enforced (≥ 5,460). JS indexer enforced SEND ≥ 546 unilaterally; Rust indexer didn't enforce SEND at all. State drifted between the two.
- Cohort v950950 — **all three consensus-enforced at EXACT amount**. Rust and JS now produce byte-identical state for every tx.

---

## 14. Reference implementation

The Rust crate at `luckyprotocol-indexer/` is canonical. Implementation lives in `protocol.rs` / `indexer.rs` / `source.rs`. When this document and the code disagree, the code wins.
