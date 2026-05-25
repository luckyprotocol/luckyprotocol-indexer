// LUCKYPROTOCOL protocol parsing — v1 (UTXO-bound, genesis cohort).
// The wire format, payload variants, and apply semantics defined here are
// the canonical LUCKYPROTOCOL protocol. See PROTOCOL.md for the human-readable
// spec.

use serde::{Deserialize, Serialize};

/// Wire prefix for every protocol payload. Indexers MUST hard-gate on
/// block height (`LCKPROTOCOL_V1_HEIGHT`) before recognizing the prefix;
/// the prefix alone does NOT activate the protocol.
pub const PROTOCOL_PREFIX: &str = "LUCKYPROTOCOL";

/// Required supply for every deployed token: EXACTLY 21,000,000.
/// Implicit (not in payload). Hard-locked, not user-configurable.
pub const REQUIRED_TOKEN_SUPPLY: u64 = 21_000_000;

/// Hard upper bound on the `AMT` field of a SEND payload, expressed in
/// the same units as `REQUIRED_TOKEN_SUPPLY` (token-smallest-units).
/// A SEND with `AMT > MAX_SEND_AMT` is REJECTED outright (canonical-
/// uint or not).
///
/// Why: the spec previously said only `AMT > 0`. That left the upper
/// bound at "whatever u64 parses to", which is portable enough for
/// Rust but a divergence vector for other languages (JS Number's
/// 53-bit precision, Python's bignum, Go's untyped literal handling).
/// Pinning the cap at the protocol's total supply gives every
/// implementation the same number to reject above, regardless of
/// integer width — and any amount beyond the supply is anyway
/// meaningless (no honest input pool can ever hold more than `supply`
/// of any ticker, so SEND with `AMT > supply` always fails apply).
pub const MAX_SEND_AMT: u64 = REQUIRED_TOKEN_SUPPLY;

/// Protocol activation height for v1 (UTXO-bound, genesis cohort).
/// All pre-activation history is unrecognized: any pre-950,950
/// payload (including legacy `BTCASINO|*` payloads that may exist
/// in the chain history, AND any LUCKYPROTOCOL-prefixed payload
/// broadcast at the earlier 949,090 / 949,375 / 950,382 test
/// cohorts) does not exist as far as LUCKYPROTOCOL is concerned.
///
/// The indexer cold-scans from this height on every fresh start.
///
/// Cohort history (each bump invalidates ALL prior on-chain state,
/// resets the tokens registry, wipes every wallet's localStorage
/// cohort key):
///   949,090 — initial pre-genesis test cohort (withdrawn)
///   949,375 — Rust-indexer-only cohort (withdrawn, never on web)
///   950,382 — web-cutover cohort (withdrawn during fee-model
///             standardization)
///   950,950 — **CURRENT cohort**. Marks the activation of the
///             three-fee consensus model:
///               DEPLOY: ≥ 5,460 sats (range — any amount above
///                       the floor is accepted; spam defense)
///               MINE:   == 546 sats (EXACT — protocol-fee
///                       output must be precisely 546)
///               SEND:   == 546 sats (EXACT — same as MINE)
///             all to PROJECT_FEE_ADDRESS. The exact-amount rule
///             for MINE/SEND makes the protocol-fee output
///             unambiguous: a single tx output of precisely 546
///             sats to the canonical address identifies the fee,
///             distinguishing it from any voluntary donation
///             outputs (which would be != 546). This also
///             prevents wallets from quietly inflating fees and
///             keeps PROJECT_FEE_ADDRESS-history sweeps
///             interpretable.
///             Also marks the unified Rust+JS indexer agreement
///             on activation height (previously divergent — Rust
///             used 949,375 while JS used 950,382, causing
///             potential state drift in that window).
pub const LCKPROTOCOL_V1_HEIGHT: u32 = 950_950;

/// Compatibility re-export.
pub const LCKPROTOCOL_START_HEIGHT: u32 = LCKPROTOCOL_V1_HEIGHT;

/// Maximum vout index acceptable in a payload's OUT_IDX field. Bitcoin
/// allows up to 65535 outputs per tx in theory; for protocol payloads
/// we cap at 255 (single-byte index, also matches tier_reward_mod).
/// Anything higher is treated as malformed.
pub const MAX_OUT_IDX: u32 = 255;

/// The single canonical project address that collects the DEPLOY
/// anti-spam fee. Mainnet bech32m P2TR (BIP-341). MUST match the
/// frontend wallet's `PROJECT_FEE_ADDRESS` constant byte-for-byte.
/// Changing this on either side requires a protocol activation
/// (LCKPROTOCOL_V1_HEIGHT bump).
pub const PROJECT_FEE_ADDRESS: &str = "bc1pyefhtnuz2gw04fsynlsseeh847cqy20dw7yt6fnavm9fgnewcr7q88gqf3";

/// Consensus-required protocol fee for DEPLOY operations, in sats.
/// A DEPLOY tx MUST have at least one output paying EXACTLY
/// `DEPLOY_PROTOCOL_FEE_SATS` (5,460) sats to `PROJECT_FEE_ADDRESS`,
/// or the DEPLOY is rejected by the indexer (`applied=false`, ticker
/// NOT registered).
///
/// As of cohort v950950 the rule is EXACT amount (==), not ≥. The
/// strict-equality rule makes the protocol-fee output unambiguous:
/// each tx has at most one "this is the fee" output, distinct from
/// any voluntary donation outputs (which would carry a different
/// amount). This keeps PROJECT_FEE_ADDRESS-history sweeps
/// interpretable: every tx with a 5,460-sat output to the canonical
/// address is a DEPLOY; every 546-sat output is a MINE or SEND.
///
/// Rationale for the 5,460-sat floor (anti-spam): `tokens` is an
/// append-only registry — an attacker who could spam DEPLOYs at
/// ~546-sat dust could permanently inflate every indexer's `tokens`
/// map. 5,460 sats (10× dust) makes the spam economic case strictly
/// worse than the value of the squatted ticker, while still keeping
/// legitimate DEPLOYs trivially affordable (~$0.50 at $10K BTC).
pub const DEPLOY_PROTOCOL_FEE_SATS: u64 = 5_460;

/// Consensus-required protocol fee for MINE (a.k.a. BET) operations,
/// in sats. A MINE tx MUST have at least one output paying EXACTLY
/// `MINE_PROTOCOL_FEE_SATS` (546) sats to `PROJECT_FEE_ADDRESS`, or
/// the BET payload is rejected (`applied=false`, no reward credit
/// even on predicate hit; residual still routes per change_out_idx).
///
/// Activated in cohort v950950 — previously the 546-sat output the
/// reference wallet emitted was wallet-only behavior. Making it
/// consensus closes the "free MINE" attack vector (a non-fee-paying
/// MINE that still gets rewarded if the predicate hits) and
/// guarantees every successfully-applied MINE pays a project fee,
/// which keeps the protocol-fee output a reliable filter for
/// indexer fast-bootstrap (every protocol tx is now discoverable
/// via PROJECT_FEE_ADDRESS history with a single 546 / 5,460 filter).
pub const MINE_PROTOCOL_FEE_SATS: u64 = 546;

/// Consensus-required protocol fee for SEND operations, in sats.
/// A SEND tx MUST have at least one output paying EXACTLY
/// `SEND_PROTOCOL_FEE_SATS` (546) sats to `PROJECT_FEE_ADDRESS`, or
/// the SEND payload is rejected (`applied=false`, no balance
/// transfer; residual still routes per change_out_idx so the
/// sender's tokens aren't burned unfairly).
///
/// Activated in cohort v950950 — previously the wallet emitted
/// this but the JS indexer enforced it while the Rust indexer did
/// not, creating a state-divergence vector for SENDs that lacked
/// the fee. Making both indexers enforce identically (with the
/// strict-equality rule shared across all three operations)
/// eliminates that divergence.
pub const SEND_PROTOCOL_FEE_SATS: u64 = 546;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ProtocolPayload {
 /// `LUCKYPROTOCOL|<tier>|<pick>|<ticker>|<win_out_idx>[|<change_out_idx>]`
 /// — game wager.
 ///
 /// On WIN, reward is minted to the UTXO at `(tx.txid, win_out_idx)`.
 /// The bettor's "ownership" of the won tokens is then enforced by
 /// Bitcoin's UTXO consensus (whoever can spend that UTXO can spend
 /// the tokens).
 ///
 /// `change_out_idx` (added in protocol v2 at block 949,367; see
 /// PROTOCOL.md §5.2 + WHITEPAPER §5.2) declares the output that
 /// should receive any residual token balance from the input pool.
 /// When present and valid, the input-pool tokens route to
 /// `(tx.txid, change_out_idx)` instead of burning. When absent
 /// (legacy 5-field MINE) the residual is destroyed under the
 /// strict-burn rule (§6.6) — this preserves byte-for-byte
 /// compatibility for every MINE tx broadcast before v2 activated.
 ///
 /// `change_out_idx == win_out_idx` is permitted: the win reward
 /// and the input residual sum at the same UTXO via
 /// `output_assignments` merge.
    Bet {
        tier: String,
        pick: String,
        ticker: String,
        win_out_idx: u32,
        change_out_idx: Option<u32>,
    },
 /// `LUCKYPROTOCOL|SEND|<ticker>|<amount>|<to_out_idx>[|<change_out_idx>]`
 /// — token transfer. Tokens move from the input pool (sum of token
 /// balances at all spent input UTXOs) to the recipient UTXO
 /// `(tx.txid, to_out_idx)`. Remaining input pool flows to
 /// `change_out_idx` (or default = first non-OP_RETURN vout).
    Xfer {
        ticker: String,
        amount: u64,
        to_out_idx: u32,
        change_out_idx: Option<u32>,
    },
 /// `LUCKYPROTOCOL|DEPLOY|<ticker>` — register a new ticker. Supply is
 /// implicit at 21,000,000 (no explicit supply field —
 /// alternative values are rejected). First-write-wins.
 /// DEPLOY does not mint tokens; tokens are only minted by BET wins.
    Deploy { ticker: String },
}

/// Parse a raw OP_RETURN payload (the bytes pushed onto OP_RETURN, NOT
/// including the OP_RETURN opcode + push prefix). Returns None if not a
/// LUCKYPROTOCOL payload, or if the format is malformed.
pub fn parse_payload(bytes: &[u8]) -> Option<ProtocolPayload> {
    let s = std::str::from_utf8(bytes).ok()?;
    let mut parts = s.split('|');
    if parts.next()? != PROTOCOL_PREFIX {
        return None;
    }
    let opcode = parts.next()?;
    match opcode {
        "iron" | "bronze" | "silver" | "gold" => {
 // BET (legacy): LUCKYPROTOCOL|<tier>|<pick>|<ticker>|<win_out_idx>
 // BET (v2):     LUCKYPROTOCOL|<tier>|<pick>|<ticker>|<win_out_idx>|<change_out_idx>
 //
 // The 6-field form was added at block 949,367 to let MINE txs
 // preserve any token UTXO inadvertently spent as funding (§6.6).
 // Both forms are valid forever — the indexer parses 5 OR 6 fields
 // and rejects anything with trailing extras.
            let pick = parts.next()?;
            let ticker = parts.next()?;
            let win_out_idx_str = parts.next()?;
            let change_out_idx_str = parts.next(); // Option — None for legacy 5-field
 // No further fields allowed beyond the optional change_out_idx.
            if parts.next().is_some() {
                return None;
            }
            if !valid_ticker(ticker) || !valid_pick(opcode, pick) {
                return None;
            }
            if !is_canonical_uint(win_out_idx_str) {
                return None;
            }
            let win_out_idx: u32 = win_out_idx_str.parse().ok()?;
            if win_out_idx > MAX_OUT_IDX {
                return None;
            }
            let change_out_idx = match change_out_idx_str {
                None => None,
                Some(c) => {
                    if !is_canonical_uint(c) {
                        return None;
                    }
                    let v: u32 = c.parse().ok()?;
                    if v > MAX_OUT_IDX {
                        return None;
                    }
 // Unlike SEND, we permit change_out_idx == win_out_idx
 // for MINE: the apply step merges into output_assignments
 // via saturating_add, so a win reward + input residual
 // landing at the same UTXO sum cleanly. No ambiguity.
                    Some(v)
                }
            };
            Some(ProtocolPayload::Bet {
                tier: opcode.to_string(),
                pick: pick.to_string(),
                ticker: ticker.to_string(),
                win_out_idx,
                change_out_idx,
            })
        }
        "SEND" => {
 // LUCKYPROTOCOL|SEND|<ticker>|<amount>|<to_out_idx>[|<change_out_idx>]
            let ticker = parts.next()?;
            let amount_str = parts.next()?;
            let to_out_idx_str = parts.next()?;
            let change_out_idx_str = parts.next(); // Option
 // No further fields allowed.
            if parts.next().is_some() {
                return None;
            }
            if !valid_ticker(ticker) {
                return None;
            }
            if !is_canonical_uint(amount_str) {
                return None;
            }
 // Length-gate BEFORE u64 parse: 20 digits is u64::MAX's width.
 // Any longer string would overflow u64::parse() on Rust (fine,
 // returns None via .ok()?) but might parse on other languages
 // (Python bignum, JS BigInt, Go untyped). Capping the source
 // string length keeps the reject point identical across every
 // canonical implementation regardless of integer width.
            if amount_str.len() > 20 {
                return None;
            }
            let amount: u64 = amount_str.parse().ok()?;
            if amount == 0 || amount > MAX_SEND_AMT {
                return None;
            }
            if !is_canonical_uint(to_out_idx_str) {
                return None;
            }
            let to_out_idx: u32 = to_out_idx_str.parse().ok()?;
            if to_out_idx > MAX_OUT_IDX {
                return None;
            }
            let change_out_idx = match change_out_idx_str {
                None => None,
                Some(c) => {
                    if !is_canonical_uint(c) {
                        return None;
                    }
                    let v: u32 = c.parse().ok()?;
                    if v > MAX_OUT_IDX {
                        return None;
                    }
                    if v == to_out_idx {
 // Same output for recipient and change is
 // ambiguous — reject. Caller can either omit
 // CHANGE_OUT_IDX (default rule kicks in) or
 // pick a distinct index.
                        return None;
                    }
                    Some(v)
                }
            };
            Some(ProtocolPayload::Xfer {
                ticker: ticker.to_string(),
                amount,
                to_out_idx,
                change_out_idx,
            })
        }
        "DEPLOY" => {
 // LUCKYPROTOCOL|DEPLOY|<ticker>
            let ticker = parts.next()?;
 // No further fields allowed.
            if parts.next().is_some() {
                return None;
            }
            if !valid_ticker(ticker) {
                return None;
            }
            Some(ProtocolPayload::Deploy {
                ticker: ticker.to_string(),
            })
        }
        _ => None,
    }
}

fn valid_ticker(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 8
        && t.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Canonical decimal-uint form check. Used by SEND amount + indices so
/// external indexer implementations can't disagree on edge cases.
fn is_canonical_uint(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if !s.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if s.len() > 1 && s.starts_with('0') {
        return false;
    }
    true
}

fn valid_pick(tier: &str, pick: &str) -> bool {
    let p = pick.to_lowercase();
    match tier {
        "iron" => p == "odd" || p == "even",
        "bronze" => p.len() == 1 && p.chars().all(|c| c.is_ascii_hexdigit()),
        "silver" => p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()),
        "gold" => p.len() == 3 && p.chars().all(|c| c.is_ascii_hexdigit()),
        _ => false,
    }
}

/// Reward amounts per tier in TOKEN-SMALLEST-UNITS.
/// EV-balanced — reward × hit-probability is roughly 50-65 across tiers
/// so no single tier dominates economically.
pub fn tier_reward(tier: &str) -> Option<u64> {
    Some(match tier {
        "iron" => 100,
        "bronze" => 1_000,
        "silver" => 10_000,
        "gold" => 200_000,
        _ => return None,
    })
}

/// SETTLEMENT TAIL — last K hex chars of the BET's confirming block hash
/// (lowercase).
pub fn settlement_tail(hash_n: &str, k: usize) -> String {
    let chars: Vec<char> = hash_n.chars().rev().take(k).collect();
    if chars.len() < k {
        return String::new();
    }
    chars.iter().rev().collect()
}

/// is_hit — outcome decided by `settlement_tail(hash_N, K)` where K depends
/// on tier.
pub fn is_hit(tier: &str, pick: &str, hash_n: &str) -> Option<bool> {
    let h = hash_n.to_lowercase();
    if h.is_empty() {
        return None;
    }
    match tier {
        "iron" => {
            let tail = settlement_tail(&h, 1);
            if tail.is_empty() {
                return None;
            }
            let v = u32::from_str_radix(&tail, 16).ok()?;
            let die = (v % 6) + 1;
            let p = pick.to_lowercase();
            if p == "odd" {
                Some(die % 2 == 1)
            } else if p == "even" {
                Some(die % 2 == 0)
            } else {
                None
            }
        }
        "bronze" => {
            let tail = settlement_tail(&h, 1);
            Some(pick.to_lowercase() == tail)
        }
        "silver" => {
            let tail = settlement_tail(&h, 2);
            Some(pick.to_lowercase() == tail)
        }
        "gold" => {
            let tail = settlement_tail(&h, 3);
            Some(pick.to_lowercase() == tail)
        }
        _ => None,
    }
}
