//! The `.nmtsmap` file: a small self-describing wrapper around one sealed recovery list.
//!
//! The shape is `docs/RECOVERY-MANIFEST.md` §5, and NMTS's browser code writes it. Only the
//! fields this program acts on are read; the rest
//! (`note`, `generated_at`) are for the person who finds the file, not for the parser.
//!
//! # ⛔ `note` is `string` in wrapper v1 and `string[]` in v2, and this parser ignores it
//! Reading it would mean modelling that difference for a field nothing here uses. Ignoring it is
//! what lets one parser read both versions with no branch — and there is no third option worth
//! having, because a wrapper whose `note` failed to parse must still surrender its `sealed` field.
//! That is the whole point of the file.

use serde::Deserialize;

/// The marker every wrapper starts with. Checked before anything else is attempted, so that
/// "this is not a recovery list" is what a person is told when they point the tool at the wrong
/// file — rather than a decryption failure, which reads as "your list is damaged".
pub const FORMAT_MARKER: &str = "nmts-recovery-map";

/// The highest wrapper version this build knows how to read.
///
/// A HIGHER number is refused rather than read optimistically: a wrapper version rises when the
/// shell's own fields change meaning, and guessing at that during a recovery is how a person ends
/// up with files that are subtly wrong instead of an error they can act on.
pub const MAX_WRAPPER_VERSION: u64 = 2;

/// The highest NRM document version the sealed payload may declare.
///
/// Kept beside the wrapper's own ceiling because the two move independently — NRM-2 shipped
/// without touching the shell. The check is here rather than in the crypto crate because refusing
/// early means the account code is never even asked for on a list this build cannot use.
///
/// ⭐ Taken FROM the crypto crate rather than written out again (2026-08-18). It had been left at
/// `2` while the document format reached 3, so this build would have refused a list it could read
/// every byte of. Reading the number from the one crate that defines the document means the two
/// can no longer disagree — and the refusal keeps its point, because a list written by a NEWER
/// product than this program still stops here with "this list is newer than this program" rather
/// than somewhere deep in a recovery.
pub const MAX_NRM_VERSION: u64 = nmts_crypto::manifest::MANIFEST_VERSION as u64;

/// What the wrapper says before anything is decrypted.
#[derive(Debug, Clone, Deserialize)]
pub struct MapFile {
    pub format: String,
    pub version: u64,
    /// NRM version of the document sealed inside.
    pub nrm: u64,
    /// Which list this is. Higher wins when someone holds several.
    pub seq: u64,
    /// Public account id (base64url of 16 bytes) — NOT a secret, and NOT a key.
    pub account_id: String,
    /// base64url of one NCF-3 envelope.
    pub sealed: String,
    /// The lowest `nmts-recovery` version that reads this document — written by whoever wrote
    /// the list, absent in lists written before the field existed.
    ///
    /// # Why a program version beside the format version
    /// [`Self::nrm`] answers "which forms does this document use", which is the right question
    /// for any reader, ours or a stranger's re-implementation. It is the wrong question for the
    /// person holding this file during a recovery, whose actual question is "what do I need to
    /// download". Refusing with "this list is newer than this program" leaves them to work that
    /// out; refusing with a number they can go and get does not.
    ///
    /// ⚠ It is a CLAIM, not a check. This build never compares it against itself — the refusal is
    /// decided by `nrm`, which is about capability — it only repeats it back so the sentence is
    /// actionable. A claim is all it can be: the writer is naming a version of a DIFFERENT program.
    ///
    /// ⛔ And it does not make an old build work. Knowing you need 0.2.0 does not help if 0.2.0
    /// does not exist yet, which is why the program still ships before a format is switched on.
    #[serde(default)]
    pub min_tool: Option<String>,
}

/// Why a file could not be used as a recovery list.
#[derive(Debug)]
pub enum MapFileError {
    /// Not JSON, or not shaped like a wrapper at all.
    NotAMap(String),
    /// A wrapper, but from a future this build does not know.
    TooNew {
        wrapper: u64,
        nrm: u64,
        /// What the document says it needs, when it says so — see [`MapFile::min_tool`].
        min_tool: Option<String>,
    },
}

/// Read a wrapper, refusing anything that is not one.
pub fn parse(text: &str) -> Result<MapFile, MapFileError> {
    let doc: MapFile = serde_json::from_str(text)
        .map_err(|e| MapFileError::NotAMap(format!("the contents are not a recovery list ({e})")))?;
    if doc.format != FORMAT_MARKER {
        return Err(MapFileError::NotAMap(format!(
            "the format marker says \"{}\"",
            doc.format
        )));
    }
    if doc.sealed.is_empty() {
        return Err(MapFileError::NotAMap(
            "it carries no sealed list".to_string(),
        ));
    }
    if doc.version > MAX_WRAPPER_VERSION || doc.nrm > MAX_NRM_VERSION {
        return Err(MapFileError::TooNew {
            wrapper: doc.version,
            nrm: doc.nrm,
            min_tool: doc.min_tool.clone(),
        });
    }
    Ok(doc)
}

/// The sentence a person reads when a list is ahead of this build.
///
/// ⛔ Written HERE, once, because two callers needed it — the terminal and the control window —
/// and a refusal that says two different things depending on which door you came in is a refusal
/// nobody can be told to look up. It also sits next to the two ceilings it quotes.
pub fn too_new_sentence(wrapper: u64, nrm: u64, min_tool: Option<&str>, lang: crate::args::Lang) -> String {
    // When the list names the version it needs, say THAT: "get 0.2.0" is something a person can
    // act on, and "this is newer than this program" is not. The format numbers follow either way,
    // because they are what somebody re-implementing this would need.
    let head = match min_tool {
        Some(need) => crate::msg::MAP_NEEDS_VERSION
            .get(lang)
            .replace("{need}", need)
            .replace("{have}", env!("CARGO_PKG_VERSION")),
        None => crate::msg::MAP_TOO_NEW.get(lang).to_string(),
    };
    format!("{head} (wrapper v{wrapper}, NRM v{nrm}; this build reads up to v{MAX_WRAPPER_VERSION} / v{MAX_NRM_VERSION}).")
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2: &str = r#"{
      "format": "nmts-recovery-map", "version": 2, "nrm": 2, "seq": 7,
      "generated_at": "2026-08-17T00:00:00.000Z", "account_id": "AAAAAAAAAAAAAAAAAAAAAA",
      "sealed": "c2VhbGVk", "note": ["a line", "a second line"]
    }"#;

    #[test]
    fn reads_a_v2_wrapper() {
        let m = parse(V2).expect("v2 wrapper");
        assert_eq!(m.seq, 7);
        assert_eq!(m.sealed, "c2VhbGVk");
    }

    /// v1 wrote `note` as a single string. The field is not read, so the version difference must
    /// cost nothing — a person holding a two-year-old list file is exactly who this tool is for.
    #[test]
    fn reads_a_v1_wrapper_whose_note_is_a_bare_string() {
        let v1 = V2
            .replace("\"version\": 2", "\"version\": 1")
            .replace("\"nrm\": 2", "\"nrm\": 1")
            .replace("[\"a line\", \"a second line\"]", "\"a line\"");
        assert_eq!(parse(&v1).expect("v1 wrapper").nrm, 1);
    }

    #[test]
    fn refuses_a_file_that_is_not_a_map() {
        assert!(matches!(parse("hello"), Err(MapFileError::NotAMap(_))));
        let wrong = V2.replace("nmts-recovery-map", "something-else");
        assert!(matches!(parse(&wrong), Err(MapFileError::NotAMap(_))));
    }

    #[test]
    fn refuses_an_empty_payload_rather_than_asking_for_the_code_first() {
        let empty = V2.replace("\"sealed\": \"c2VhbGVk\"", "\"sealed\": \"\"");
        assert!(matches!(parse(&empty), Err(MapFileError::NotAMap(_))));
    }

    /// ⛔ A future format is refused, not guessed at. Reading a newer wrapper as if it were this
    ///    one is how a recovery produces files that look right and are not.
    ///
    /// ⚠ Written against `MAX_*_VERSION + 1` rather than a literal. It used to say `3`, and the
    ///   document ceiling has since moved twice — a literal here would have gone on passing while
    ///   testing that a version this build fully understands is refused.
    #[test]
    fn refuses_a_wrapper_or_document_from_the_future() {
        let ahead_shell = MAX_WRAPPER_VERSION + 1;
        let newer_shell = V2.replace("\"version\": 2", &format!("\"version\": {ahead_shell}"));
        assert!(matches!(
            parse(&newer_shell),
            Err(MapFileError::TooNew { wrapper, .. }) if wrapper == ahead_shell
        ));
        // ⭐ And the refusal carries what the document says it needs, so the sentence a person
        //    reads can name a version instead of only saying "newer".
        let with_claim = newer_shell.replace("\"nrm\": 2", "\"nrm\": 2, \"min_tool\": \"9.9.9\"");
        assert!(matches!(
            parse(&with_claim),
            Err(MapFileError::TooNew { ref min_tool, .. }) if min_tool.as_deref() == Some("9.9.9")
        ));
        let ahead_doc = MAX_NRM_VERSION + 1;
        let newer_doc = V2.replace("\"nrm\": 2", &format!("\"nrm\": {ahead_doc}"));
        assert!(matches!(
            parse(&newer_doc),
            Err(MapFileError::TooNew { nrm, .. }) if nrm == ahead_doc
        ));
    }

    /// ⭐ And a document at today's ceiling goes through. The pair is the point: with only the
    ///    refusal above, leaving `MAX_NRM_VERSION` behind the format — which is exactly what had
    ///    happened, at 2 while documents reached 3 — reads as a passing test suite.
    #[test]
    fn reads_a_document_at_the_current_ceiling() {
        let at_ceiling = V2.replace("\"nrm\": 2", &format!("\"nrm\": {MAX_NRM_VERSION}"));
        assert_eq!(parse(&at_ceiling).expect("today's format must open").nrm, MAX_NRM_VERSION);
    }
}
