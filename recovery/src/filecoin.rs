//! Getting a Filecoin part back (NMTS Heavy · NRM-5 · `docs/RECOVERY-MANIFEST.md` §2.4).
//!
//! # Where the bytes are
//! A Heavy part is one Filecoin piece, kept whole by storage companies (two by default). No public
//! service serves every piece the way a Walrus aggregator serves every blob, so the list records,
//! for each company, the address it served the piece from — and the company's number in a registry
//! contract on the chain, which is where its CURRENT address is kept if it has moved.
//!
//! # The order things are tried in
//! 1. Every address the list recorded, in the list's order. A plain `GET`, https only.
//! 2. When all of those fail: each company's current address, read from the registry with a
//!    JSON-RPC `eth_call` to a public Filecoin node, then `{that address}/piece/{PieceCID}`.
//!
//! ⛔ No PieceCID is recomputed. The bytes are an NCF-3 stream that authenticates itself against
//!    the file key, so a company serving the wrong bytes is refused by the same checks as a Walrus
//!    part; a second check on the same bytes would put a hash tree over 512 MiB in this program.
//!
//! # The contract call, written by hand
//! `getProductCapabilities(uint256 providerId, uint8 productType, string[] keys)` returns `bytes[]`.
//! Encoding one call and decoding one answer is a few dozen lines of fixed offsets, and it is not
//! cryptography, so it is written out here rather than pulled in as an Ethereum library — a
//! stranger reading this program before typing their key into it can check every byte. The
//! encoding is pinned against an answer a live registry gave (tests below).

use std::io::Read;
use std::time::Duration;

use nmts_crypto::manifest::{FilecoinCopy, Part};
use serde_json::Value;

use crate::source::SourceError;

/// One Filecoin network this program can look a company up on.
pub struct Chain {
    /// The word a list carries in `chain`.
    pub name: &'static str,
    /// The ServiceProviderRegistry contract.
    pub registry: &'static str,
    /// A public JSON-RPC node.
    pub rpc: &'static str,
}

/// The networks a list may name (`FILECOIN_CHAINS` in the crypto crate) and where to ask on each.
pub const CHAINS: [Chain; 2] = [
    Chain {
        name: "calibration",
        registry: "0x839e5c9988e4e9977d40708d0094103c0839Ac9D",
        rpc: "https://api.calibration.node.glif.io/rpc/v1",
    },
    Chain {
        name: "mainnet",
        registry: "0xf55dDbf63F1b55c3F1D4FA7e339a68AB7b64A5eB",
        rpc: "https://api.node.glif.io/rpc/v1",
    },
];

/// `keccak256("getProductCapabilities(uint256,uint8,string[])")[..4]`.
const SELECTOR: [u8; 4] = [0xa6, 0x43, 0x32, 0x40];
/// The registry's product type for PDP storage, which is what NMTS Heavy uses.
const PRODUCT_TYPE_PDP: u8 = 0;
/// The capability key under which a company publishes its address.
const KEY_SERVICE_URL: &[u8] = b"serviceURL";
/// A registry answer larger than this is not an address.
const MAX_RPC_BYTES: u64 = 64 * 1024;

/// One piece, as the list describes it — everything needed to ask for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// The PieceCIDv2 string (the part's `blob_id`).
    pub cid: String,
    /// `"calibration"` or `"mainnet"`.
    pub chain: String,
    /// The companies keeping it, in the order to try them.
    pub copies: Vec<FilecoinCopy>,
}

impl Piece {
    /// The piece a Filecoin part names, or `None` when a field the parse requires is missing.
    pub fn of(part: &Part) -> Option<Self> {
        Some(Self {
            cid: part.blob_id.clone()?,
            chain: part.chain.clone()?,
            copies: part.copies.clone()?,
        })
    }

    /// How many different companies keep it.
    pub fn companies(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = Vec::new();
        for c in &self.copies {
            if !ids.contains(&c.provider_id.as_str()) {
                ids.push(&c.provider_id);
            }
        }
        ids
    }
}

/// What one request came to.
pub enum Fetched {
    /// The bytes arrived and were handed to the caller, who said this.
    Consumed(Result<(), String>),
    /// Nothing usable arrived; why.
    Failed(String),
}

/// The two kinds of request this module makes. A trait so the order of attempts can be tested
/// without a network.
pub trait Transport {
    /// `GET url`, bounded at `cap` bytes, handing the body to `consume` on a 200.
    fn get(
        &self,
        url: &str,
        cap: u64,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<(), String>,
    ) -> Fetched;
    /// `POST body` as JSON, returning the answer's text.
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
}

/// The real network.
pub struct Web {
    pieces: ureq::Agent,
    rpc: ureq::Agent,
}

impl Web {
    pub fn new() -> Self {
        let agent = |secs| -> ureq::Agent {
            ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(secs)))
                // https only, redirects included: a company may send a reader elsewhere, but
                // never onto a plain-http address.
                .https_only(true)
                .build()
                .into()
        };
        // Pieces get the hour a 1 GiB Walrus part gets; a registry question is a small JSON call.
        Self {
            pieces: agent(3600),
            rpc: agent(60),
        }
    }
}

impl Default for Web {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for Web {
    fn get(
        &self,
        url: &str,
        cap: u64,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<(), String>,
    ) -> Fetched {
        match self.pieces.get(url).call() {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                if status != 200 {
                    return Fetched::Failed(format!("answered {status}"));
                }
                let mut reader = resp.body_mut().with_config().limit(cap).reader();
                Fetched::Consumed(consume(&mut reader))
            }
            Err(e) => Fetched::Failed(format!("could not be reached ({e})")),
        }
    }

    fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
        let mut resp = self
            .rpc
            .post(url)
            .header("content-type", "application/json")
            .send(body)
            .map_err(|e| format!("could not be reached ({e})"))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(format!("answered {status}"));
        }
        resp.body_mut()
            .with_config()
            .limit(MAX_RPC_BYTES)
            .read_to_string()
            .map_err(|e| format!("stopped part way ({e})"))
    }
}

/// Get one piece: the recorded addresses in order, then each company's current one.
///
/// ⛔ Once bytes have been handed to `consume`, its answer is final — trying the next company after
///    the caller has started writing would join two attempts into one file.
pub fn fetch_piece(
    t: &dyn Transport,
    piece: &Piece,
    cap: u64,
    consume: &mut dyn FnMut(&mut dyn Read) -> Result<(), String>,
) -> Result<(), SourceError> {
    let mut failures: Vec<String> = Vec::new();
    let mut tried: Vec<String> = Vec::new();
    for copy in &piece.copies {
        if let Some(done) = attempt(t, &copy.retrieval_url, cap, consume, &mut failures) {
            return done;
        }
        tried.push(copy.retrieval_url.clone());
    }
    let companies = piece.companies();
    if let Some(chain) = CHAINS.iter().find(|c| c.name == piece.chain) {
        for id in &companies {
            match service_url(t, chain, id) {
                Ok(base) => {
                    let url = format!("{}/piece/{}", base.trim_end_matches('/'), piece.cid);
                    if tried.contains(&url) {
                        continue;
                    }
                    if let Some(done) = attempt(t, &url, cap, consume, &mut failures) {
                        return done;
                    }
                    tried.push(url);
                }
                Err(why) => failures.push(format!("{} #{id}: {why}", chain.registry)),
            }
        }
    }
    Err(SourceError::NoCopy {
        companies: companies.len(),
        tried: failures.join("; "),
    })
}

/// One address. `None` means "try the next one"; `Some` is the final answer.
fn attempt(
    t: &dyn Transport,
    url: &str,
    cap: u64,
    consume: &mut dyn FnMut(&mut dyn Read) -> Result<(), String>,
    failures: &mut Vec<String>,
) -> Option<Result<(), SourceError>> {
    // https only: the list's addresses are checked at parse time, and a registry entry is
    // whatever the company wrote there.
    if !url.starts_with("https://") || !url.bytes().all(|b| b.is_ascii_graphic()) {
        failures.push(format!("{url} is not an https address"));
        return None;
    }
    match t.get(url, cap, consume) {
        Fetched::Consumed(done) => Some(done.map_err(SourceError::Consumer)),
        Fetched::Failed(why) => {
            failures.push(format!("{url} {why}"));
            None
        }
    }
}

/// A company's current address, from the registry on `chain`.
pub fn service_url(t: &dyn Transport, chain: &Chain, provider_id: &str) -> Result<String, String> {
    let data = encode_service_url_call(provider_id)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{ "to": chain.registry, "data": format!("0x{}", hex(&data)) }, "latest"],
    });
    let text = t
        .post_json(chain.rpc, &body.to_string())
        .map_err(|why| format!("{} {why}", chain.rpc))?;
    let doc: Value = serde_json::from_str(&text)
        .map_err(|e| format!("answered something that is not JSON ({e})"))?;
    if let Some(err) = doc.get("error") {
        return Err(format!("answered an error ({err})"));
    }
    let result = doc
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| "answered without a result".to_string())?;
    let raw = unhex(result.strip_prefix("0x").unwrap_or(result))?;
    let url = String::from_utf8(first_of_bytes_array(&raw)?)
        .map_err(|_| "answered an address that is not text".to_string())?;
    let url = url.trim();
    if url.is_empty() {
        return Err("answered with no address".to_string());
    }
    Ok(url.to_string())
}

/// The calldata for `getProductCapabilities(provider_id, 0, ["serviceURL"])`.
pub fn encode_service_url_call(provider_id: &str) -> Result<Vec<u8>, String> {
    let word = |n: usize| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(n as u64).to_be_bytes());
        w
    };
    let mut key = [0u8; 32];
    key[..KEY_SERVICE_URL.len()].copy_from_slice(KEY_SERVICE_URL);
    let mut out = SELECTOR.to_vec();
    out.extend_from_slice(&decimal_word(provider_id)?);
    out.extend_from_slice(&word(usize::from(PRODUCT_TYPE_PDP)));
    out.extend_from_slice(&word(0x60)); // where `keys` starts: after the three head words
    out.extend_from_slice(&word(1)); // one key
    out.extend_from_slice(&word(0x20)); // it starts one word into the array's contents
    out.extend_from_slice(&word(KEY_SERVICE_URL.len()));
    out.extend_from_slice(&key);
    Ok(out)
}

/// The first element of an ABI-encoded `bytes[]` return value. Every offset is bounds-checked: the
/// answer comes from a public node, and a wrong one must be an error rather than a panic.
pub fn first_of_bytes_array(ret: &[u8]) -> Result<Vec<u8>, String> {
    let bad = || "answered something that is not a list of values".to_string();
    let at = |offset: usize| -> Result<usize, String> {
        let w = ret
            .get(offset..offset.checked_add(32).ok_or_else(bad)?)
            .ok_or_else(bad)?;
        if w[..24].iter().any(|b| *b != 0) {
            return Err(bad());
        }
        usize::try_from(u64::from_be_bytes(w[24..].try_into().map_err(|_| bad())?))
            .map_err(|_| bad())
    };
    let array = at(0)?;
    if at(array)? == 0 {
        return Err("answered with no address".to_string());
    }
    let contents = array.checked_add(32).ok_or_else(bad)?;
    let element = contents.checked_add(at(contents)?).ok_or_else(bad)?;
    let len = at(element)?;
    let start = element.checked_add(32).ok_or_else(bad)?;
    let end = start.checked_add(len).ok_or_else(bad)?;
    ret.get(start..end).map(<[u8]>::to_vec).ok_or_else(bad)
}

/// A canonical decimal (already checked by the list's parser) as a 32-byte big-endian word.
fn decimal_word(s: &str) -> Result<[u8; 32], String> {
    let mut w = [0u8; 32];
    for d in s.bytes() {
        if !d.is_ascii_digit() {
            return Err(format!("{s:?} is not a company number"));
        }
        // w = w * 10 + d, carried from the low end.
        let mut carry = u32::from(d - b'0');
        for byte in w.iter_mut().rev() {
            let v = u32::from(*byte) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err(format!("{s:?} is larger than a company number can be"));
        }
    }
    Ok(w)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let bad = || "answered something that is not hex".to_string();
    if s.len() % 2 != 0 {
        return Err(bad());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .ok_or_else(bad)
        })
        .collect()
}

#[cfg(test)]
#[path = "filecoin_tests.rs"]
mod tests;
