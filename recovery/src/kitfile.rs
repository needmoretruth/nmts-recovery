//! The recovery kit: the one file that holds everything.
//!
//! # Two files, and only one of them is dangerous
//! NMTS hands a person two downloads, and the difference between them is the whole security story:
//!
//! * the **recovery list** (`.nmtsmap`) — the sealed index. Useless on its own; the account code
//!   opens it. Losing control of it costs nothing.
//! * the **recovery kit** (`.txt`) — the account code **in the clear**, and since kit version 2 the
//!   recovery list embedded alongside it. ⛔ Whoever holds this file holds the account: every file,
//!   and the wallet, because the same code derives both.
//!
//! This program reads either. When it is given a kit it says so out loud, because a person who
//! pointed at the wrong file should find out from a sentence rather than from the absence of a
//! question they expected to be asked.
//!
//! # ⛔ The machine block is delimited by fixed ASCII, not by the label above it
//! The kit's headings are written in whatever language the person was using. A parser that looked
//! for the heading would work in one language and fail in another — and it would fail on the day
//! somebody is trying to recover, which is the only day it matters. So the data sits between two
//! markers that are the same bytes in every language and every version.

use serde::Deserialize;

/// Start of the machine block. Fixed bytes, never translated.
pub const DATA_BEGIN: &str = "--- BEGIN NMTS RECOVERY KIT DATA ---";
/// End of the machine block.
pub const DATA_END: &str = "--- END NMTS RECOVERY KIT DATA ---";

/// The marker every kit's data block carries.
pub const FORMAT_MARKER: &str = "nmts-recovery-kit";

/// The highest kit version this build knows how to read.
///
/// v1 kits exist and are NOT readable here on purpose: they carry no recovery list (the field did
/// not exist) and no fixed markers, so there is nothing in one this program could act on. A person
/// holding a v1 kit still has their account code printed in it, which is what it was for.
pub const MAX_KIT_VERSION: u64 = 2;

/// What a kit says, once the machine block has been found.
#[derive(Debug, Clone, Deserialize)]
pub struct KitFile {
    pub format: String,
    pub version: u64,
    pub account_id: String,
    /// The account code, in the clear. ⛔ Never printed, never written anywhere by this program.
    pub account_code: Option<String>,
    /// The whole recovery-list document, embedded. `None` on a kit taken before any files existed.
    pub recovery_list: Option<serde_json::Value>,
}

/// Why a file could not be used as a recovery kit.
#[derive(Debug)]
pub enum KitFileError {
    /// No machine block, or one that is not a kit.
    NotAKit(String),
    /// A kit from a future this build does not know.
    TooNew { version: u64 },
}

/// True when the text looks like a kit at all — used to decide which parser to hand a file to.
///
/// Deliberately just the opening marker: a truncated kit should be reported as a DAMAGED kit, not
/// as "this is not a recovery file", because those two send a person to different places.
pub fn looks_like_kit(text: &str) -> bool {
    text.contains(DATA_BEGIN)
}

/// Pull the machine block out of a kit and read it.
pub fn parse(text: &str) -> Result<KitFile, KitFileError> {
    let start = text
        .find(DATA_BEGIN)
        .ok_or_else(|| KitFileError::NotAKit("it carries no recovery kit data".to_string()))?
        + DATA_BEGIN.len();
    let rest = &text[start..];
    let end = rest
        .find(DATA_END)
        .ok_or_else(|| KitFileError::NotAKit("the kit data has no end marker".to_string()))?;
    let doc: KitFile = serde_json::from_str(rest[..end].trim())
        .map_err(|e| KitFileError::NotAKit(format!("the kit data is not readable ({e})")))?;
    if doc.format != FORMAT_MARKER {
        return Err(KitFileError::NotAKit(format!(
            "the format marker says \"{}\"",
            doc.format
        )));
    }
    if doc.version > MAX_KIT_VERSION {
        return Err(KitFileError::TooNew {
            version: doc.version,
        });
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kit(body: &str) -> String {
        format!("# NMTS Recovery Kit\nsome heading in some language\n\n{DATA_BEGIN}\n{body}\n{DATA_END}\n")
    }

    const BODY: &str = r#"{
      "format": "nmts-recovery-kit", "version": 2, "generated_at": "2026-08-17T00:00:00Z",
      "account_id": "AAAAAAAAAAAAAAAAAAAAAA", "account_fingerprint": "AAAA-BBBB-CCCC-DDDD",
      "account_code": "AAAA-BBBB", "recovery_manifest_blob": null,
      "recovery_list": {"format":"nmts-recovery-map","version":2,"nrm":2,"seq":3,
        "account_id":"AAAAAAAAAAAAAAAAAAAAAA","sealed":"c2VhbGVk"}
    }"#;

    #[test]
    fn reads_a_kit_and_finds_the_list_inside_it() {
        let k = parse(&kit(BODY)).expect("a kit");
        assert_eq!(k.version, 2);
        assert_eq!(k.account_code.as_deref(), Some("AAAA-BBBB"));
        assert!(k.recovery_list.is_some());
    }

    /// ⛔ The markers, not the heading. The heading is written in the person's language and this
    ///    parser must work whatever that language was.
    #[test]
    fn the_heading_language_does_not_matter() {
        let korean = format!(
            "# NMTS 복구 키트\n기계가 읽는 부분\n\n{DATA_BEGIN}\n{BODY}\n{DATA_END}\n"
        );
        assert!(parse(&korean).is_ok());
    }

    #[test]
    fn a_file_that_is_not_a_kit_is_refused() {
        assert!(!looks_like_kit("hello"));
        assert!(matches!(parse("hello"), Err(KitFileError::NotAKit(_))));
        let wrong = kit(&BODY.replace("nmts-recovery-kit", "something-else"));
        assert!(matches!(parse(&wrong), Err(KitFileError::NotAKit(_))));
    }

    /// A kit cut off mid-way still LOOKS like a kit, and says so — "damaged" and "not a kit at all"
    /// send a person looking in two different places.
    #[test]
    fn a_truncated_kit_is_a_damaged_kit_not_a_stranger() {
        let cut = format!("# NMTS Recovery Kit\n\n{DATA_BEGIN}\n{{\"format\":");
        assert!(looks_like_kit(&cut));
        match parse(&cut) {
            Err(KitFileError::NotAKit(why)) => assert!(why.contains("end marker"), "{why}"),
            other => panic!("a truncated kit was not reported as damaged: {other:?}"),
        }
    }

    #[test]
    fn a_kit_from_the_future_is_refused_rather_than_guessed_at() {
        let newer = kit(&BODY.replace("\"version\": 2", "\"version\": 3"));
        assert!(matches!(parse(&newer), Err(KitFileError::TooNew { version: 3 })));
    }

    /// The first kits carried no list. Reading one should say what is missing, not pretend.
    #[test]
    fn a_kit_with_no_list_parses_and_says_the_list_is_absent() {
        let bare = kit(&BODY.replace(
            "\"recovery_list\": {\"format\":\"nmts-recovery-map\",\"version\":2,\"nrm\":2,\"seq\":3,\n        \"account_id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"sealed\":\"c2VhbGVk\"}",
            "\"recovery_list\": null",
        ));
        let k = parse(&bare).expect("a kit without a list");
        assert!(k.recovery_list.is_none());
    }
}
