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

/// Sui JSON-RPC endpoints tried when the caller names none.
///
/// ⚠ Public MIRRORS, not the official fullnodes, and that is not a preference: the official
/// fullnodes retired JSON-RPC on both networks (measured by the NMTS team, 2026-07-29 testnet and
/// 2026-08-03 mainnet). Mainnet is first because that is where live NMTS data is; testnet follows
/// so an account from before the 2026-08-02 cutover still resolves. `--rpc` overrides both.
pub const DEFAULT_RPCS: [&str; 2] = [
    "https://rpc-mainnet.suiscan.xyz",
    "https://rpc-testnet.suiscan.xyz",
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
            // `map_or(true, …)` rather than the newer `is_none_or`: this crate promises to build on
            // the Rust in `Cargo.toml`'s `rust-version`, and somebody recovering files on an old
            // machine is exactly who that promise is for.
            let better = search
                .found
                .as_ref()
                .map_or(true, |current| manifest.seq > current.manifest.seq);
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
