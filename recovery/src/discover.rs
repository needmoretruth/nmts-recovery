//! Finding an account's recovery list with nothing but the account code.
//!
//! # The whole idea in four lines
//! A blob id on Walrus is a hash of the blob's own bytes, so nothing predicts one from an account
//! code. Two other things are predictable, and together they are enough:
//!
//!   1. the WALLET that paid for the storage comes from the account code (NCF-3 §1.3), and the
//!      blob objects it registered are owned by it on Sui;
//!   2. the NAME the recovery list is stored under inside a quilt comes from the account code too
//!      (NCF-3 §2.5).
//!
//! So: derive the address, ask a Sui node what blob objects it owns, ask an aggregator each of
//! those quilts for a patch by that name, open what comes back. The first two questions are
//! public data; the third is answered only for someone holding the key.
//!
//! # What this costs a person's privacy, stated rather than skipped
//! The lookup itself tells a Sui RPC operator "somebody is interested in this address" and tells
//! an aggregator "somebody asked for these patches". Both are public services being asked public
//! questions. It does NOT hand either of them the account code, which never leaves this process.
//!
//! # Failure is quiet on purpose
//! Every step can legitimately find nothing — the account may never have turned the
//! storage-network copy on, may use an extension wallet whose address does not come from the code,
//! or may have uploaded only large files, which do not travel in quilts. "Not found" is therefore
//! an answer, not an error, and the caller says what to do about it.

use std::time::Duration;

use nmts_crypto::kdf::DerivedKeys;
use nmts_crypto::manifest::{recovery_patch_name, RecoveryManifest};

use crate::derive::sui_address;

/// Sui JSON-RPC endpoints tried when the caller names none, in order.
///
/// ⚠ Public MIRRORS, not the official fullnodes, and that is not a preference: the official
/// fullnodes retired JSON-RPC on both networks (measured by the NMTS team, 2026-07-29 testnet and
/// 2026-08-03 mainnet). `--rpc` replaces the whole list.
///
/// ⭐ 2026-09-01 — two operators now, not one, and the testnet entry that had been here was
/// measured DEAD that morning: `rpc-testnet.suiscan.xyz` completes the TCP handshake in 31 ms and
/// then sends nothing for 12 seconds, three times running. It had been dead for eleven days. The
/// hosts below all answered `sui_getChainIdentifier` with the right value the same morning.
///
/// ⛔ WHAT THE ORDER ACTUALLY DOES — read this before adding to it. [`owned_blob_ids`] returns
/// the FIRST host that answers at all, so the list is a failover chain, not a sweep across
/// networks: the testnet hosts are only ever asked when both mainnet hosts are unreachable. An
/// account created before the 2026-08-02 mainnet cutover therefore needs `--rpc` naming a testnet
/// node. Saying so here because the sentence that used to stand in this place claimed the
/// opposite.
pub const DEFAULT_RPCS: [&str; 4] = [
    "https://rpc-mainnet.suiscan.xyz",
    "https://sui-rpc.publicnode.com",
    "https://sui-testnet-rpc.publicnode.com",
    "https://testnet.suiet.app",
];

/// How many pages of owned objects one address is walked for.
///
/// A cap exists because an address can own an unbounded number of objects and a recovery must
/// finish. It is stated out loud when it is hit — a silent truncation would read as "your account
/// holds nothing" to the one person who most needs the opposite.
const MAX_PAGES: usize = 20;

/// Objects requested per page. The RPC's own maximum is larger; this keeps one response small
/// enough to parse without holding a whole account's object set in memory at once.
const PAGE_SIZE: u32 = 50;

/// The Move type suffix that identifies a Walrus blob object.
///
/// Matched by SUFFIX rather than by a pinned package id on purpose: the package differs per
/// network and moves on upgrades, and a pinned id would turn a Walrus release into a recovery
/// that finds nothing. The suffix is part of the type name and cannot be spoofed into mattering —
/// a stranger's object matching it simply fails the patch lookup a step later.
const BLOB_TYPE_SUFFIX: &str = "::blob::Blob";

/// One recovery list found on the storage network.
pub struct Found {
    /// Blob id of the quilt it was read out of. Own-quilt placements resolve against this.
    pub quilt_id: String,
    /// The opened document.
    pub manifest: RecoveryManifest,
    /// The address whose blobs it was found under — worth printing, since it may be one of several.
    pub owner: String,
}

/// What a search did, whether or not it found anything.
pub struct Search {
    /// The newest list found, by `seq`. `None` when nothing matched.
    pub found: Option<Found>,
    /// Addresses that were asked.
    pub owners: Vec<String>,
    /// Quilts examined across every address.
    pub quilts_seen: usize,
    /// True when an address had more pages of objects than [`MAX_PAGES`] allowed.
    pub truncated: bool,
    /// Everything that went wrong along the way. A search can succeed with these non-empty.
    pub problems: Vec<String>,
}

/// The three things that decide which of two recovery lists to recover from.
///
/// A struct rather than six loose arguments: `supersedes(a, b)` with six values is a function whose
/// call site can be wrong in a way that still compiles.
#[derive(Clone, Copy)]
pub(crate) struct Candidate<'a> {
    seq: u64,
    items: usize,
    generated_at: &'a str,
}

impl<'a> Candidate<'a> {
    pub(crate) fn of(m: &'a RecoveryManifest) -> Self {
        Self {
            seq: m.seq,
            items: m.items.len(),
            generated_at: &m.generated_at,
        }
    }
}

/// True when `candidate` should replace `current`.
///
/// ⛔ THE TIE IS THE POINT. `seq` decides, and it usually differs. When it
/// does NOT, the account wrote the same number twice — which happens because the browser picks
/// "stored seq + 1" and the call that stores it can fail without stopping anything. Two patches
/// then carry one `seq`, and the later of them describes MORE files. Comparing with `>` alone kept
/// whichever the RPC listed first: about half the time the older one.
///
/// ⚠ `generated_at` is a clock, and clocks lie — which is why it is never allowed to override
/// `seq`, and only ever separates two documents the account itself failed to order.
pub(crate) fn supersedes(candidate: Candidate<'_>, current: Candidate<'_>) -> bool {
    if candidate.seq != current.seq {
        return candidate.seq > current.seq;
    }
    if candidate.items != current.items {
        return candidate.items > current.items;
    }
    candidate.generated_at > current.generated_at
}

/// Search the chain and the aggregators for this account's newest recovery list.
///
/// `owner_override` is for accounts whose uploads were paid by a wallet the account code does not
/// derive — an extension wallet, or an imported key. There is no way to compute such an address,
/// so the person supplies it.
pub fn find(
    keys: &DerivedKeys,
    rpcs: &[String],
    aggregators: &[String],
    owner_override: Option<&str>,
    wallet_count: u32,
) -> Search {
    let owners: Vec<String> = match owner_override {
        Some(addr) => vec![addr.to_string()],
        None => (0..wallet_count.max(1))
            .map(|i| sui_address(&keys.wallet_seed_for(i)))
            .collect(),
    };
    let wanted = recovery_patch_name(&keys.data_key);

    let agent = http_agent();
    let mut search = Search {
        found: None,
        owners: owners.clone(),
        quilts_seen: 0,
        truncated: false,
        problems: Vec::new(),
    };

    for owner in &owners {
        let blobs = match owned_blob_ids(&agent, rpcs, owner) {
            Ok(page) => {
                search.truncated |= page.truncated;
                page.blob_ids
            }
            Err(why) => {
                search.problems.push(why);
                continue;
            }
        };
        for quilt_id in blobs {
            search.quilts_seen += 1;
            let sealed = match fetch_patch(&agent, aggregators, &quilt_id, &wanted) {
                Ok(None) => continue,
                Ok(Some(bytes)) => bytes,
                Err(why) => {
                    search.problems.push(why);
                    continue;
                }
            };
            // The envelope's key commitment settles "is this ours" before anything is decrypted,
            // so a patch that merely happens to sit under this name costs one comparison.
            let manifest = match RecoveryManifest::decrypt(&keys.data_key, &sealed) {
                Ok(m) => m,
                Err(e) => {
                    search.problems.push(format!(
                        "{quilt_id}: a patch under this account's name did not open ({e})"
                    ));
                    continue;
                }
            };
            // Highest `seq` wins — never the newest chain timestamp. Devices' clocks lie, and the
            // sequence is the one ordering the account itself asserted.
            //
            // ⛔ BUT A TIE IS NOT A COIN FLIP. `seq` is chosen by the
            //    browser as "the account's stored seq + 1", and the call that tells the server
            //    about it can fail — the browser logs that and carries on. The next upload then
            //    picks the SAME number for a list that describes MORE files. Two patches, one
            //    `seq`, and `>` alone kept whichever the RPC happened to list first: about half the
            //    time, the older one, which is the one missing the newest files. Nothing said so.
            //
            //    So the tie is broken by what the documents themselves say, in this order:
            //      1. more items — a later list of the same account almost always describes a
            //         superset, and "almost always" beats "whichever arrived first";
            //      2. later `generated_at` — a clock, used ONLY inside an equal `seq`, where the
            //         alternative is arbitrary. It never overrides the sequence.
            //    And the tie is REPORTED either way: a reused sequence means a record that never
            //    landed, and somebody recovering files deserves to know that happened.
            //
            // `map_or(true, …)` rather than the newer `is_none_or`: this crate promises to build on
            // the Rust in `Cargo.toml`'s `rust-version`, and somebody recovering files on an old
            // machine is exactly who that promise is for.
            let better = search.found.as_ref().map_or(true, |current| {
                supersedes(Candidate::of(&manifest), Candidate::of(&current.manifest))
            });
            if let Some(current) = search.found.as_ref() {
                if manifest.seq == current.manifest.seq && quilt_id != current.quilt_id {
                    search.problems.push(format!(
                        "two recovery lists share sequence {}: {} ({} items) and {} ({} items). \
                         The newer one was never recorded. Using the one with more items.",
                        manifest.seq,
                        current.quilt_id,
                        current.manifest.items.len(),
                        quilt_id,
                        manifest.items.len(),
                    ));
                }
            }
            if better {
                search.found = Some(Found {
                    quilt_id,
                    manifest,
                    owner: owner.clone(),
                });
            }
        }
    }
    search
}

/// Shared agent. Short by recovery standards: these are small JSON calls, and a hung one should
/// become a stated problem rather than a program that never returns.
fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into()
}

struct OwnedBlobs {
    blob_ids: Vec<String>,
    truncated: bool,
}

/// Every Walrus blob id an address owns, via `suix_getOwnedObjects`.
fn owned_blob_ids(agent: &ureq::Agent, rpcs: &[String], owner: &str) -> Result<OwnedBlobs, String> {
    let mut failures = Vec::new();
    for rpc in rpcs {
        match owned_blob_ids_from(agent, rpc, owner) {
            Ok(found) => return Ok(found),
            Err(why) => failures.push(format!("{rpc}: {why}")),
        }
    }
    Err(format!(
        "no Sui node answered for {owner} ({})",
        failures.join("; ")
    ))
}

fn owned_blob_ids_from(agent: &ureq::Agent, rpc: &str, owner: &str) -> Result<OwnedBlobs, String> {
    let mut blob_ids = Vec::new();
    let mut cursor = serde_json::Value::Null;
    for page in 0..MAX_PAGES {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": page + 1,
            "method": "suix_getOwnedObjects",
            "params": [owner, {"options": {"showType": true, "showContent": true}}, cursor, PAGE_SIZE],
        });
        // Sent as a string with an explicit content type rather than through ureq's JSON helper:
        // that helper is behind a cargo feature, and one `serde_json::to_string` is a smaller
        // thing to depend on than a feature flag in a program meant to be audited by reading.
        let payload = serde_json::to_string(&body).map_err(|e| format!("{e}"))?;
        let mut resp = agent
            .post(rpc)
            .header("content-type", "application/json")
            .send(&payload)
            .map_err(|e| format!("could not be reached ({e})"))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(format!("answered {status}"));
        }
        let text = resp
            .body_mut()
            .with_config()
            .limit(MAX_RPC_BYTES)
            .read_to_string()
            .map_err(|e| format!("stopped part way ({e})"))?;
        let doc: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("answered something that is not JSON ({e})"))?;
        if let Some(err) = doc.get("error") {
            return Err(format!("answered an error ({err})"));
        }
        let result = doc
            .get("result")
            .ok_or_else(|| "answered without a result".to_string())?;
        for entry in result
            .get("data")
            .and_then(|d| d.as_array())
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let Some(data) = entry.get("data") else {
                continue;
            };
            let is_blob = data
                .get("type")
                .and_then(|t| t.as_str())
                .is_some_and(|t| t.ends_with(BLOB_TYPE_SUFFIX));
            if !is_blob {
                continue;
            }
            if let Some(decimal) = data
                .pointer("/content/fields/blob_id")
                .and_then(|v| v.as_str())
            {
                match blob_id_from_u256(decimal) {
                    Some(id) => blob_ids.push(id),
                    None => {
                        return Err(format!("gave a blob id this build cannot read ({decimal})"))
                    }
                }
            }
        }
        let has_next = result
            .get("hasNextPage")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !has_next {
            return Ok(OwnedBlobs {
                blob_ids,
                truncated: false,
            });
        }
        cursor = result
            .get("nextCursor")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
    }
    Ok(OwnedBlobs {
        blob_ids,
        truncated: true,
    })
}

/// Sui stores a Walrus blob id as a `u256`; Walrus writes it as unpadded base64url of that number
/// in LITTLE-endian bytes, which is what BCS makes of a `u256`.
///
/// Getting the byte order wrong here produces a well-formed id that no aggregator has ever heard
/// of, so it fails as "not found" rather than as an error — which is why the direction is pinned
/// by a test rather than left to the reader's memory.
pub fn blob_id_from_u256(decimal: &str) -> Option<String> {
    let mut bytes = [0u8; 32];
    let mut value = parse_u256(decimal)?;
    for slot in bytes.iter_mut() {
        *slot = (value & 0xff) as u8;
        value >>= 8;
    }
    Some(nmts_crypto::b64::encode(&bytes))
}

/// A decimal string as a 256-bit number, in four 64-bit limbs, without pulling in a bignum crate.
///
/// Written out rather than depended on because the whole crate is auditable-by-reading and one
/// multiply-add loop is smaller than a dependency. Returns `None` on anything that is not a plain
/// decimal or that does not fit in 256 bits — both mean the node said something this build should
/// not guess about.
fn parse_u256(decimal: &str) -> Option<U256> {
    if decimal.is_empty() || !decimal.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut acc = U256::ZERO;
    for b in decimal.bytes() {
        acc = acc.mul10_add(b - b'0')?;
    }
    Some(acc)
}

/// A 256-bit unsigned integer, only as much of one as this file needs.
#[derive(Clone, Copy)]
struct U256([u64; 4]);

impl U256 {
    const ZERO: Self = Self([0; 4]);

    /// `self * 10 + digit`, or `None` on overflow past 256 bits.
    fn mul10_add(self, digit: u8) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = u128::from(digit);
        for (i, limb) in self.0.iter().enumerate() {
            let wide = u128::from(*limb) * 10 + carry;
            out[i] = wide as u64;
            carry = wide >> 64;
        }
        if carry != 0 {
            return None;
        }
        Some(Self(out))
    }
}

impl std::ops::BitAnd<u64> for U256 {
    type Output = u64;
    fn bitand(self, rhs: u64) -> u64 {
        self.0[0] & rhs
    }
}

impl std::ops::ShrAssign<u32> for U256 {
    fn shr_assign(&mut self, rhs: u32) {
        // Only byte-sized shifts are ever asked for here; a zero or oversized one would be a
        // shift-overflow rather than a wrong answer, so it is refused instead of wrapped.
        if rhs == 0 || rhs >= 64 {
            return;
        }
        let mut carry = 0u64;
        for limb in self.0.iter_mut().rev() {
            let next = *limb << (64 - rhs);
            *limb = (*limb >> rhs) | carry;
            carry = next;
        }
    }
}

/// Ask each aggregator for one patch by quilt id and identifier. `Ok(None)` = nobody has it.
fn fetch_patch(
    agent: &ureq::Agent,
    aggregators: &[String],
    quilt_id: &str,
    identifier: &str,
) -> Result<Option<Vec<u8>>, String> {
    let path = crate::source::BlobRef::InQuilt {
        quilt_id: quilt_id.to_string(),
        identifier: identifier.to_string(),
    }
    .url_path();
    let mut failures = Vec::new();
    let mut any_answered = false;
    for endpoint in aggregators {
        let url = format!("{endpoint}{path}");
        match agent.get(&url).call() {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                if status == 404 {
                    any_answered = true;
                    continue;
                }
                if status != 200 {
                    failures.push(format!("{endpoint} answered {status}"));
                    continue;
                }
                // A recovery list is one envelope and is bounded by the format's own ceiling; a
                // limit is set anyway so a hostile or broken endpoint cannot fill memory.
                let bytes = resp
                    .body_mut()
                    .with_config()
                    .limit(MAX_LIST_BYTES)
                    .read_to_vec()
                    .map_err(|e| format!("{endpoint} stopped part way ({e})"))?;
                return Ok(Some(bytes));
            }
            Err(e) => failures.push(format!("{endpoint} could not be reached ({e})")),
        }
    }
    if any_answered && failures.is_empty() {
        return Ok(None);
    }
    if failures.is_empty() {
        return Ok(None);
    }
    Err(format!("{quilt_id}: {}", failures.join("; ")))
}

/// Ceiling on one fetched list. The sealed file list's own practical ceiling is 8 MiB and a
/// recovery list is the same order of thing; 64 MiB is far above any real account and far below
/// anything that could exhaust a desktop.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;

/// Ceiling on one JSON-RPC answer. A page of 50 objects is kilobytes; this is room to spare and
/// still a bound, so a node answering with an endless body ends as an error rather than as memory.
const MAX_RPC_BYTES: u64 = 32 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(seq: u64, items: usize, at: &str) -> Candidate<'_> {
        Candidate {
            seq,
            items,
            generated_at: at,
        }
    }

    /// ⛔ This is the whole reason for the rule. The browser picks `seq` as "the sequence the
    /// server knows, plus one", and the call that tells the server about it can fail without
    /// stopping anything. The next upload then reuses that number for a list describing MORE
    /// files. Comparing with `>` alone kept whichever the RPC listed first — about half the time
    /// the older list, which is the one missing the newest files.
    #[test]
    fn a_tied_sequence_is_broken_by_which_list_describes_more() {
        assert!(supersedes(
            cand(5, 40, "2026-08-01T00:00:00Z"),
            cand(5, 12, "2026-08-02T00:00:00Z")
        ));
        assert!(!supersedes(
            cand(5, 12, "2026-08-02T00:00:00Z"),
            cand(5, 40, "2026-08-01T00:00:00Z")
        ));
    }

    /// ⛔ The other side of the same rule: a clock NEVER beats a sequence. Devices' clocks lie,
    /// and the sequence is the ordering the account itself asserted.
    #[test]
    fn a_newer_clock_never_beats_a_higher_sequence() {
        assert!(!supersedes(
            cand(4, 999, "2099-01-01T00:00:00Z"),
            cand(5, 1, "2026-08-01T00:00:00Z")
        ));
        assert!(supersedes(
            cand(5, 1, "2026-08-01T00:00:00Z"),
            cand(4, 999, "2099-01-01T00:00:00Z")
        ));
    }

    /// Equal sequence AND equal count falls back to the clock — inside a tie only, where the
    /// alternative is "whichever arrived first".
    #[test]
    fn an_equal_sequence_and_count_falls_back_to_the_clock() {
        assert!(supersedes(
            cand(5, 12, "2026-08-02T00:00:00Z"),
            cand(5, 12, "2026-08-01T00:00:00Z")
        ));
        assert!(!supersedes(
            cand(5, 12, "2026-08-01T00:00:00Z"),
            cand(5, 12, "2026-08-02T00:00:00Z")
        ));
        // Identical on all three keeps the incumbent: the search has to be deterministic, so
        // running it twice gives the same answer.
        assert!(!supersedes(
            cand(5, 12, "2026-08-01T00:00:00Z"),
            cand(5, 12, "2026-08-01T00:00:00Z")
        ));
    }

    /// ⛔ The byte order is the whole test. A big-endian reading produces a perfectly well-formed
    /// blob id that simply does not exist, so the failure it causes is "your files are not there"
    /// — the most alarming possible way to be told about an endianness bug.
    ///
    /// The pair below was read off Sui mainnet-style data: the decimal is what the node returns in
    /// `content.fields.blob_id`, the string is what Walrus calls the same blob.
    #[test]
    fn a_blob_id_is_the_little_endian_bytes_of_the_number_sui_stores() {
        let decimal =
            "99948925563890497458821702329675998710172654685512294950270493148941086336630";
        assert_eq!(
            blob_id_from_u256(decimal).as_deref(),
            Some("dqYHNuwRK5vsFI-pHDhEGtHIEOy_H-zkXFvTj04W-dw"),
        );
    }

    #[test]
    fn the_smallest_and_largest_numbers_still_produce_ids() {
        assert_eq!(
            blob_id_from_u256("0").as_deref(),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        );
        // 2^256 - 1: every byte 0xff, whichever end you start from.
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(
            blob_id_from_u256(max).as_deref(),
            Some("__________________________________________8"),
        );
    }

    #[test]
    fn a_number_that_is_not_a_number_is_refused_rather_than_guessed_at() {
        for bad in ["", " 12", "12 ", "0x1f", "-1", "1.0", "abc"] {
            assert!(blob_id_from_u256(bad).is_none(), "accepted {bad:?}");
        }
        // 2^256 exactly — one past what a blob id can hold.
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(blob_id_from_u256(over).is_none());
    }

    #[test]
    fn a_patch_is_asked_for_by_quilt_and_name() {
        let path = crate::source::BlobRef::InQuilt {
            quilt_id: "QUILT".into(),
            identifier: "a-b-c".into(),
        }
        .url_path();
        assert_eq!(path, "/v1/blobs/by-quilt-id/QUILT/a-b-c");
    }
}
