//! Where the ciphertext comes from: a public Walrus aggregator, or a directory of files somebody
//! already fetched.
//!
//! # The two sources are not a convenience pair
//! The network source is what makes the tool usable. The directory source is what makes it
//! *trustworthy*: anyone who does not want this program opening sockets can fetch the blobs with
//! `curl` — `--print-fetch-plan` prints the exact commands — and hand it a folder. Everything
//! after the bytes arrive is identical either way, so the paranoid path is not a lesser one.
//!
//! # ⛔ Bytes are handed over as a STREAM, never as a buffer
//! A part of a large file is up to 1 GiB, and the
//! machine somebody rescues a drive onto is not chosen for its memory. So a source opens a reader
//! and the caller pulls from it; nothing here ever holds a whole part. That is also why the API
//! takes a callback rather than returning a reader — the HTTP body borrows its response, and the
//! shape that keeps the borrow honest is the shape that keeps the memory flat.
//!
//! # ⛔ A response is bounded before it is read
//! The list states each part's plaintext length, and NCF-3 fixes the framing overhead, so the
//! ciphertext's exact length is known BEFORE the request goes out. Reading is capped at that
//! figure plus a small margin: an aggregator that answers a 3 KB request with an endless stream
//! gets an error instead of this program's entire memory. The cap is not a security boundary on
//! its own — the AEAD is — but "the wrong bytes" should cost a message, not the machine.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nmts_crypto::manifest::RecoveryManifest;

/// NCF-3 §4.1: the fixed stream header.
const HEADER_LEN: u64 = 72;
/// NCF-3 §4.1: `chunk_size_log2 = 22`.
const CHUNK_SIZE: u64 = 1 << 22;
/// NCF-3 §4.1: the Poly1305 tag on every chunk.
const TAG_LEN: u64 = 16;
/// Slack over the computed length. A quilt patch is served as its own bytes, but an aggregator is
/// free to frame a response; a few hundred bytes of tolerance costs nothing and a wrong guess here
/// would refuse a perfectly good blob.
const LENGTH_SLACK: u64 = 4096;

/// The aggregators tried when the caller names none.
///
/// ⚠ BOTH NETWORKS ARE LISTED because a blob id does not say which chain issued it. Live NMTS data
/// is on mainnet, so mainnet is tried first and testnet follows, which keeps a list from before the
/// 2026-08-02 cutover resolving. A blob id that belongs to neither simply 404s on both.
///
/// ⭐ A LIST CAN NOW SAY WHICH CHAIN IT MEANS (`meta.storage.chain`) — this comment used
/// to end with *"the real fix is a field in the next list version"*, and that is the field. When it
/// is there, [`aggregators_for_chain`] puts the right endpoint first and the guessing stops. The
/// order below is what happens when it is not.
pub const DEFAULT_AGGREGATORS: [&str; 2] = [
    "https://aggregator.walrus-mainnet.walrus.space",
    "https://aggregator.walrus-testnet.walrus.space",
];

/// Which endpoints a run may read from, and which the list asked for but did not get.
#[derive(Debug)]
pub struct Endpoints {
    /// Tried, in order.
    pub use_now: Vec<String>,
    /// Named by the list and NOT contacted, because nobody asked for them. Empty in the usual case.
    pub held_back: Vec<String>,
}

/// The default endpoints, ordered by what the list says about itself.
///
/// # What is trusted here, and why that is safe
/// `chain` comes out of the SEALED document, and the bytes fetched are authenticated against the
/// file key regardless, so a wrong chain name costs a failed fetch and nothing else. ⛔ The
/// plaintext wrapper's own self-description is NOT used for this, or for anything else the program
/// acts on: anyone holding the file can edit it (`mapfile.rs`).
///
/// # ⛔ Why `recorded` is HELD BACK by default (2026-08-20)
/// It used to be appended and contacted automatically, on the argument that the sealed document was
/// "written by whoever holds the account code". **That argument died when the recovery kit started
/// carrying the account code**: a kit handed to somebody is a document its author sealed with
/// THEIR OWN code, so every field in it is attacker-chosen, and the program opens it with no
/// prompt at all.
///
/// And the safety sentence covered the wrong threat. Authenticating the bytes protects what
/// ARRIVES. It says nothing about the fact that **a request went out to a host the file chose** —
/// which is a beacon: the address it is made from, and the moment somebody sat down to recover.
///
/// So the recorded endpoints are still read, still shown, and still usable — with
/// `--use-recorded-aggregators`. They exist for the day this program's own defaults go dark, and
/// that is a day somebody is reading the output.
pub fn aggregators_for_chain(chain: Option<&str>, recorded: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // A chain name this build does not know leaves the built-in order alone rather than emptying
    // it: an unrecognised word is a reason to stop guessing, not a reason to fetch nothing.
    let prefer = match chain {
        Some("testnet") => Some("walrus-testnet"),
        Some("mainnet") => Some("walrus-mainnet"),
        _ => None,
    };
    if let Some(needle) = prefer {
        for d in DEFAULT_AGGREGATORS.iter().filter(|d| d.contains(needle)) {
            out.push((*d).to_string());
        }
    }
    for d in DEFAULT_AGGREGATORS.iter() {
        let d = (*d).to_string();
        if !out.contains(&d) {
            out.push(d);
        }
    }
    for r in recorded {
        let r = r.trim_end_matches('/').to_string();
        if !r.is_empty() && !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

/// The built-in endpoints for a chain, with nothing the list named.
fn built_in_for_chain(chain: Option<&str>) -> Vec<String> {
    aggregators_for_chain(chain, &[])
}

/// Which endpoints to read from, for one run — **the one place that decides it.**
///
/// ⛔ It is a function rather than two similar blocks because there are two doors into a restore:
/// the terminal and the control window. When the same decision was written at both, only one of
/// them would have learned that a list can now name its chain, and the other would have gone on
/// guessing while every test passed. A single source is only a single source when nothing is
/// allowed to go around it.
pub fn endpoints_for(
    named: &[String],
    manifest: &RecoveryManifest,
    allow_recorded: bool,
) -> Endpoints {
    // An explicit `--aggregator` wins outright: a person who named an endpoint meant it, and this
    // is also the escape hatch for the day both built-in hosts are gone.
    if !named.is_empty() {
        return Endpoints {
            use_now: named.to_vec(),
            held_back: Vec::new(),
        };
    }
    let storage = manifest.meta.as_ref().and_then(|m| m.storage.as_ref());
    let chain = storage.and_then(|s| s.chain.as_deref());
    let recorded = storage.map(|s| s.aggregators.as_slice()).unwrap_or(&[]);
    if allow_recorded {
        return Endpoints {
            use_now: aggregators_for_chain(chain, recorded),
            held_back: Vec::new(),
        };
    }
    let use_now = built_in_for_chain(chain);
    let held_back = recorded
        .iter()
        .map(|r| r.trim_end_matches('/').to_string())
        .filter(|r| !r.is_empty() && !use_now.contains(r))
        .collect();
    Endpoints { use_now, held_back }
}

/// The storage network name this build knows how to fetch from.
///
/// A list may name a network that did not exist when this build was made. Refusing by name is what
/// keeps such a part from being fetched from the wrong network's aggregator and failing later as
/// "damaged" — see `Part::network_name` in the crypto crate for why the field is a word.
pub const KNOWN_NETWORK: &str = "walrus";

/// Which bytes are wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobRef {
    /// A whole blob, by its Walrus blob id.
    Whole(String),
    /// One patch inside a quilt, by its patch id. Its bytes are a complete NCF-3 stream.
    Patch(String),
    /// One patch inside a NAMED quilt, by the identifier the writer gave it.
    ///
    /// Used for the items a storage-network manifest describes from inside the very quilt it was
    /// written into: that quilt's blob id is a hash of its own contents, this document included,
    /// so the writer could not name it and recorded the patch's identifier instead (NRM-3). The
    /// quilt id here is the one the READER fetched the document from.
    InQuilt {
        /// Blob id of the quilt the manifest was read out of.
        quilt_id: String,
        /// The patch's identifier within it.
        identifier: String,
    },
}

impl BlobRef {
    /// The id as it appears in the list — what a person sees in errors and in the fetch plan.
    pub fn id(&self) -> &str {
        match self {
            BlobRef::Whole(id) | BlobRef::Patch(id) => id,
            BlobRef::InQuilt { identifier, .. } => identifier,
        }
    }

    /// The aggregator path for this reference.
    pub fn url_path(&self) -> String {
        match self {
            BlobRef::Whole(id) => format!("/v1/blobs/{}", urlencode(id)),
            BlobRef::Patch(id) => format!("/v1/blobs/by-quilt-patch-id/{}", urlencode(id)),
            BlobRef::InQuilt {
                quilt_id,
                identifier,
            } => format!(
                "/v1/blobs/by-quilt-id/{}/{}",
                urlencode(quilt_id),
                urlencode(identifier)
            ),
        }
    }

    /// The filename `--blobs-dir` expects, and `--print-fetch-plan` prints.
    ///
    /// Ids are base64url-ish but not guaranteed to be, and a recovery must not depend on whether
    /// some future id form happens to be safe as a filename — so anything outside a conservative
    /// set becomes `_`. Both halves of the tool call this one function, which is what keeps the
    /// name it prints and the name it looks for the same name.
    pub fn file_name(&self) -> String {
        let prefix = match self {
            BlobRef::Whole(_) => "blob-",
            BlobRef::Patch(_) => "patch-",
            // Distinct from `patch-` on purpose: the two name DIFFERENT things (a patch id is
            // global, an identifier is only meaningful inside one quilt), and a `--blobs-dir`
            // holding both must not have one silently satisfy a request for the other.
            BlobRef::InQuilt { .. } => "inquilt-",
        };
        let safe: String = self
            .id()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!("{prefix}{safe}.bin")
    }
}

/// Percent-encode everything that is not unreserved. Ids should need none of this; doing it anyway
/// is what stops an id with a `/` or a `?` in it from rewriting the request path.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// The exact NCF-3 stream length for a part of `plaintext_len` bytes.
///
/// Zero-length plaintext is one empty chunk, not zero chunks (NCF-3 §4.1), so the tag is always
/// paid at least once.
pub fn expected_stream_len(plaintext_len: u64) -> u64 {
    let chunks = plaintext_len.div_ceil(CHUNK_SIZE).max(1);
    HEADER_LEN + plaintext_len + TAG_LEN * chunks
}

/// What went wrong while getting one part.
pub enum SourceError {
    /// No source could supply the bytes. Carries every attempt's reason.
    Unavailable(String),
    /// The bytes arrived and the caller rejected them (a bad header, a failed tag, a disk error).
    ///
    /// ⛔ Kept separate from `Unavailable` because it decides whether to try the next aggregator.
    ///    Re-fetching after the caller has already begun writing would restart a part halfway
    ///    through and quietly concatenate two attempts.
    Consumer(String),
}

/// A place bytes can be read from.
pub trait BlobSource {
    /// Open one part's ciphertext and hand a reader to `consume`.
    ///
    /// `plaintext_len` comes from the list and bounds the read. `consume` is called at most once.
    fn open(
        &self,
        r: &BlobRef,
        plaintext_len: u64,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<(), String>,
    ) -> Result<(), SourceError>;

    /// A one-line description for the summary a person reads.
    fn describe(&self) -> String;
}

/// Reads from public Walrus aggregators, trying each in order.
pub struct HttpSource {
    endpoints: Vec<String>,
    agent: ureq::Agent,
}

impl HttpSource {
    pub fn new(endpoints: Vec<String>) -> Self {
        let endpoints = if endpoints.is_empty() {
            DEFAULT_AGGREGATORS.iter().map(|s| s.to_string()).collect()
        } else {
            endpoints
        };
        let agent: ureq::Agent = ureq::Agent::config_builder()
            // Generous, because a 1 GiB part on a slow line is a legitimate case and a recovery is
            // not a page load. Present at all so a hung connection ends in an error rather than in
            // a program that never returns.
            .timeout_global(Some(Duration::from_secs(3600)))
            .build()
            .into();
        Self { endpoints, agent }
    }

    /// The endpoints in use — printed in the fetch plan so the URLs a person copies are the URLs
    /// this program would have used.
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }
}

impl BlobSource for HttpSource {
    fn open(
        &self,
        r: &BlobRef,
        plaintext_len: u64,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<(), String>,
    ) -> Result<(), SourceError> {
        let cap = expected_stream_len(plaintext_len) + LENGTH_SLACK;
        // Every endpoint's failure is kept. A recovery that says "could not fetch" without saying
        // that one aggregator answered 404 and the other refused the connection sends a person
        // looking at their own network for an hour.
        let mut failures = Vec::new();
        for endpoint in &self.endpoints {
            let url = format!("{endpoint}{}", r.url_path());
            match self.agent.get(&url).call() {
                Ok(mut resp) => {
                    let status = resp.status().as_u16();
                    if status != 200 {
                        failures.push(format!("{endpoint} answered {status}"));
                        continue;
                    }
                    let mut reader = resp.body_mut().with_config().limit(cap).reader();
                    return consume(&mut reader).map_err(SourceError::Consumer);
                }
                Err(e) => failures.push(format!("{endpoint} could not be reached ({e})")),
            }
        }
        Err(SourceError::Unavailable(failures.join("; ")))
    }

    fn describe(&self) -> String {
        format!("aggregators: {}", self.endpoints.join(", "))
    }
}

/// Reads from a directory somebody filled by hand.
pub struct DirSource {
    dir: PathBuf,
}

impl DirSource {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }
}

impl BlobSource for DirSource {
    fn open(
        &self,
        r: &BlobRef,
        _plaintext_len: u64,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<(), String>,
    ) -> Result<(), SourceError> {
        // No length cap here on purpose: these bytes are already on the caller's own disk, so a cap
        // would refuse a file the caller can see rather than protect them from anything.
        let path = self.dir.join(r.file_name());
        let mut file = File::open(&path).map_err(|e| {
            SourceError::Unavailable(format!("{} could not be read ({e})", path.display()))
        })?;
        consume(&mut file).map_err(SourceError::Consumer)
    }

    fn describe(&self) -> String {
        format!("directory: {}", self.dir.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with(chain: Option<&str>, recorded: &[&str]) -> RecoveryManifest {
        RecoveryManifest {
            v: 2,
            seq: 1,
            prev_manifest_blob_id: None,
            generated_at: "t".into(),
            account_id: "a".into(),
            meta: chain.map(|c| nmts_crypto::manifest::Meta {
                storage: Some(nmts_crypto::manifest::MetaStorage {
                    network: Some("walrus".into()),
                    chain: Some(c.into()),
                    aggregators: recorded.iter().map(|r| (*r).to_string()).collect(),
                    chain_rpc: None,
                }),
                ..Default::default()
            }),
            items: Vec::new(),
        }
    }

    /// ⭐ The list now says which chain it means, and the guessing stops (owner directive, 2026-08-19).
    #[test]
    fn the_chain_the_list_names_is_asked_first() {
        let testnet = aggregators_for_chain(Some("testnet"), &[]);
        assert!(testnet[0].contains("walrus-testnet"), "{testnet:?}");
        let mainnet = aggregators_for_chain(Some("mainnet"), &[]);
        assert!(mainnet[0].contains("walrus-mainnet"), "{mainnet:?}");
        // ⛔ And the other one is still THERE. A list that names its chain wrongly — an old build,
        //    a hand-edited document — must cost an extra request, not the recovery.
        assert_eq!(testnet.len(), DEFAULT_AGGREGATORS.len());
        assert!(testnet.iter().any(|e| e.contains("walrus-mainnet")));
    }

    /// A chain name this build has never heard of is a reason to stop guessing, not to fetch
    /// nothing: the built-in order stands unchanged.
    #[test]
    fn an_unknown_chain_leaves_the_order_alone() {
        let out = aggregators_for_chain(Some("some-future-chain"), &[]);
        assert_eq!(out, DEFAULT_AGGREGATORS.to_vec());
        assert_eq!(
            aggregators_for_chain(None, &[]),
            DEFAULT_AGGREGATORS.to_vec()
        );
    }

    /// The endpoints the list recorded come LAST, and never twice.
    ///
    /// They are the oldest information in the file — where one browser was reading on one day — so
    /// they are the fallback for when this program's own hosts have gone dark, not a preference.
    #[test]
    fn recorded_endpoints_are_a_last_resort_and_are_not_repeated() {
        let out = aggregators_for_chain(
            Some("mainnet"),
            &[
                "https://aggregator.walrus-mainnet.walrus.space/".to_string(),
                "https://someone-elses.example".to_string(),
            ],
        );
        assert_eq!(
            out.last().map(String::as_str),
            Some("https://someone-elses.example")
        );
        assert_eq!(
            out.iter().filter(|e| e.contains("walrus-mainnet")).count(),
            1,
            "a recorded endpoint that is already a default must not be listed twice: {out:?}"
        );
    }

    /// ⛔ An endpoint the person named wins outright — including over the list's own chain.
    #[test]
    fn an_explicit_aggregator_beats_everything_the_list_says() {
        let named = vec!["https://mine.example".to_string()];
        let out = endpoints_for(
            &named,
            &manifest_with(Some("testnet"), &["https://theirs.example"]),
            false,
        );
        assert_eq!(out.use_now, named);
        assert!(
            out.held_back.is_empty(),
            "nothing is held back when the person named the endpoint: {:?}",
            out.held_back
        );
    }

    #[test]
    fn without_an_explicit_endpoint_the_list_decides() {
        let out = endpoints_for(&[], &manifest_with(Some("testnet"), &[]), false);
        assert!(
            out.use_now[0].contains("walrus-testnet"),
            "{:?}",
            out.use_now
        );
        // A list with no block at all: the built-in order, exactly as before this existed.
        assert_eq!(
            endpoints_for(&[], &manifest_with(None, &[]), false).use_now,
            DEFAULT_AGGREGATORS.to_vec()
        );
    }

    /// ⛔ A HOST THE FILE NAMED IS NOT CONTACTED UNTIL SOMEBODY ASKS FOR IT.
    ///
    /// The document is sealed, but a recovery kit carries the account code, so a kit somebody hands
    /// you was sealed by them — this list of hosts included. Contacting one is a beacon whether or
    /// not the bytes that come back are genuine.
    #[test]
    fn an_endpoint_the_file_named_is_held_back_until_it_is_asked_for() {
        let manifest = manifest_with(Some("mainnet"), &["https://someone-elses.example/"]);
        let out = endpoints_for(&[], &manifest, false);
        assert!(
            !out.use_now.iter().any(|e| e.contains("someone-elses")),
            "a host the file chose must not be contacted by default: {:?}",
            out.use_now
        );
        assert_eq!(
            out.held_back,
            vec!["https://someone-elses.example".to_string()],
            "and it must be NAMED, so the person can decide"
        );
        // Asked for: it is appended, last, exactly as it used to be.
        let asked = endpoints_for(&[], &manifest, true);
        assert_eq!(
            asked.use_now.last().map(String::as_str),
            Some("https://someone-elses.example")
        );
        assert!(asked.held_back.is_empty());
    }

    /// A host the file names that this build already contacts is not "held back" — it is a default.
    #[test]
    fn a_recorded_endpoint_that_is_already_built_in_is_not_reported_as_withheld() {
        let out = endpoints_for(
            &[],
            &manifest_with(Some("mainnet"), &[DEFAULT_AGGREGATORS[0]]),
            false,
        );
        assert!(out.held_back.is_empty(), "{:?}", out.held_back);
    }

    #[test]
    fn stream_length_matches_the_format() {
        // One empty chunk still carries a tag.
        assert_eq!(expected_stream_len(0), 72 + 16);
        assert_eq!(expected_stream_len(1), 72 + 1 + 16);
        // Exactly one full chunk is one chunk, not two.
        assert_eq!(expected_stream_len(CHUNK_SIZE), 72 + CHUNK_SIZE + 16);
        assert_eq!(
            expected_stream_len(CHUNK_SIZE + 1),
            72 + CHUNK_SIZE + 1 + 32
        );
    }

    #[test]
    fn quilt_patches_and_whole_blobs_use_different_routes() {
        assert_eq!(BlobRef::Whole("abc".into()).url_path(), "/v1/blobs/abc");
        assert_eq!(
            BlobRef::Patch("abc".into()).url_path(),
            "/v1/blobs/by-quilt-patch-id/abc"
        );
    }

    /// ⛔ An id is not trusted to be URL-safe. If it ever stops being, a `?` in it must not turn
    ///    the rest of the path into a query string.
    #[test]
    fn an_id_cannot_rewrite_the_request_path() {
        let r = BlobRef::Whole("a/b?c=d".into());
        assert_eq!(r.url_path(), "/v1/blobs/a%2Fb%3Fc%3Dd");
    }

    /// The fetch plan prints these names and `--blobs-dir` looks for them; one function, so they
    /// cannot drift apart.
    #[test]
    fn file_names_are_safe_and_say_which_kind_they_are() {
        assert_eq!(BlobRef::Whole("aB-9_".into()).file_name(), "blob-aB-9_.bin");
        assert_eq!(BlobRef::Patch("a/b".into()).file_name(), "patch-a_b.bin");
    }

    #[test]
    fn a_directory_source_says_which_file_was_missing() {
        let src = DirSource::new(Path::new("/nonexistent-directory-for-this-test"));
        let err = src
            .open(&BlobRef::Whole("xyz".into()), 10, &mut |_| Ok(()))
            .expect_err("nothing is there");
        match err {
            SourceError::Unavailable(m) => assert!(m.contains("blob-xyz.bin"), "{m}"),
            SourceError::Consumer(m) => panic!("a missing file is not a rejection: {m}"),
        }
    }

    /// ⛔ The distinction the failover depends on: bytes that arrived and were rejected must not
    ///    send the program to the next aggregator with a half-written file already on disk.
    #[test]
    fn a_rejection_by_the_caller_is_not_an_availability_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("blob-xyz.bin"), b"bytes").expect("write");
        let src = DirSource::new(dir.path());
        let err = src
            .open(&BlobRef::Whole("xyz".into()), 5, &mut |_| {
                Err("the header is not NCF-3".to_string())
            })
            .expect_err("the caller rejected the bytes");
        assert!(matches!(err, SourceError::Consumer(_)));
    }
}
