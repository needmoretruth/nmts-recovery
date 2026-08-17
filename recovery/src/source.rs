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
//! The map states each part's plaintext length, and NCF-3 fixes the framing overhead, so the
//! ciphertext's exact length is known BEFORE the request goes out. Reading is capped at that
//! figure plus a small margin: an aggregator that answers a 3 KB request with an endless stream
//! gets an error instead of this program's entire memory. The cap is not a security boundary on
//! its own — the AEAD is — but "the wrong bytes" should cost a message, not the machine.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
/// ⚠ BOTH NETWORKS ARE LISTED, and the order is not a preference so much as an admission: an
/// NRM-2 map records the storage network by NAME (`"walrus"`) and nothing anywhere in the document
/// says whether that was Walrus mainnet or Walrus testnet. Live NMTS data is on mainnet, so it is
/// tried first; testnet follows so that a map from before the 2026-08-02 cutover still resolves.
/// A blob id that belongs to neither simply 404s on both, which is the same answer either way.
/// ▶ The real fix is a field in the next map version; until then, `--aggregator` overrides this.
pub const DEFAULT_AGGREGATORS: [&str; 2] = [
    "https://aggregator.walrus-mainnet.walrus.space",
    "https://aggregator.walrus-testnet.walrus.space",
];

/// The storage network name this build knows how to fetch from.
///
/// A map may name a network that did not exist when this build was made. Refusing by name is what
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
}

impl BlobRef {
    /// The id as it appears in the map — what a person sees in errors and in the fetch plan.
    pub fn id(&self) -> &str {
        match self {
            BlobRef::Whole(id) | BlobRef::Patch(id) => id,
        }
    }

    /// The aggregator path for this reference.
    pub fn url_path(&self) -> String {
        match self {
            BlobRef::Whole(id) => format!("/v1/blobs/{}", urlencode(id)),
            BlobRef::Patch(id) => format!("/v1/blobs/by-quilt-patch-id/{}", urlencode(id)),
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
    /// `plaintext_len` comes from the map and bounds the read. `consume` is called at most once.
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
        let mut file = File::open(&path)
            .map_err(|e| SourceError::Unavailable(format!("{} could not be read ({e})", path.display())))?;
        consume(&mut file).map_err(SourceError::Consumer)
    }

    fn describe(&self) -> String {
        format!("directory: {}", self.dir.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_length_matches_the_format() {
        // One empty chunk still carries a tag.
        assert_eq!(expected_stream_len(0), 72 + 16);
        assert_eq!(expected_stream_len(1), 72 + 1 + 16);
        // Exactly one full chunk is one chunk, not two.
        assert_eq!(expected_stream_len(CHUNK_SIZE), 72 + CHUNK_SIZE + 16);
        assert_eq!(expected_stream_len(CHUNK_SIZE + 1), 72 + CHUNK_SIZE + 1 + 32);
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
