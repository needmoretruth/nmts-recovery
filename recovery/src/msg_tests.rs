//! Tests for [`crate::msg`] — the two-language message table.
//!
//! ⛔ ITS OWN FILE BECAUSE `msg.rs` HAS A CEILING. `check:size` holds Rust files to 700 lines and
//!    the wallet messages did not fit beside these tests. Nothing about them moved: they are still
//!    `mod tests` inside the module (`#[cfg(test)] #[path = "msg_tests.rs"] mod tests;`), so
//!    `super::*` reaches `ALL_LINES` exactly as before.
//!
//! ⚠ The declaration count below still reads `msg.rs`, not this file. So the rule about not
//!   spelling the needles applies to `msg.rs`'s comments; a sentence written here cannot be
//!   counted as a message.

use super::*;

#[test]
fn byte_sizes_read_as_sizes() {
    assert_eq!(human_bytes(0), "0 B");
    assert_eq!(human_bytes(999), "999 B");
    assert_eq!(human_bytes(1_000), "1.0 KB");
    assert_eq!(human_bytes(1_500_000), "1.5 MB");
    assert_eq!(human_bytes(u64::MAX), "18446744.1 TB");
}

/// ⛔ A half-translated tool is worse than an English one: the person hits the Korean sentence,
///    trusts it, and then meets a blank where the next sentence should be.
#[test]
fn every_line_exists_in_both_languages() {
    for line in ALL_LINES {
        assert!(!line.0.trim().is_empty(), "an English line is empty");
        assert!(!line.1.trim().is_empty(), "a Korean line is empty");
    }
}

/// ⛔ The check above is only worth having if nothing can be declared and left out of the list
///    it walks. So this counts what the file actually declares, from the file itself.
///
/// ⚠ The count is taken from the source with every run of whitespace flattened to one space,
///   NOT line by line. A declaration split over two lines — the name and its type on one, the
///   `Line(` on the next — was invisible to both halves of this check at once: the counter
///   skipped the line, and nothing pushed whoever wrote it towards the list below. The two
///   numbers then agreed, and a message existed that neither language check had ever read.
///   Flattening first means how a declaration is wrapped cannot decide whether it is counted,
///   so rustfmt may rewrap this file freely. What flattening must not do is let one
///   declaration's search run on into the next one — see the `;` stop below.
///
/// ⚠ Both needles are spelled in two pieces, for the reason the network test in `args.rs`
///   spells its own in two pieces: written whole, the lines below would read as one more
///   declaration once the line breaks are gone, and this file would count a message it does
///   not have.
#[test]
fn no_message_can_be_added_without_joining_the_list_that_is_checked() {
    const DECL: &str = concat!("pub ", "const ");
    const OF_TYPE_LINE: &str = concat!(": Line = ", "Line");
    let source = include_str!("msg.rs");
    let flat = source.split_whitespace().collect::<Vec<_>>().join(" ");
    let declared = flat
        .match_indices(DECL)
        .filter(|&(at, _)| {
            let after_declaration = &flat[at + DECL.len()..];
            after_declaration
                .split_once('(')
                .is_some_and(|(name_and_type, _)| {
                    // ⚠ A `;` before that `(` means the declaration already ended and the
                    //   paren belongs to whatever comes next. Without this second stop, an
                    //   ordinary constant declared among the messages — say a length as a
                    //   `usize`, which ends at its own semicolon — reads on into the following
                    //   message's opening paren and is counted as a message. Measured on this
                    //   file: 62 counted where 61 exist, and the failure then told whoever
                    //   added the constant to register a message that does not exist. The
                    //   same stop is what keeps the list below out of the count wherever in
                    //   the file it sits, instead of only while it happens to be written last.
                    //   ⛔ No comment in `msg.rs` may spell either needle: the count is taken
                    //   from that file, so a sentence about a declaration would become one.
                    !name_and_type.contains(';') && name_and_type.ends_with(OF_TYPE_LINE)
                })
        })
        .count();
    println!("{declared} message declarations judged");
    // ⚠ A floor. A search that has stopped matching how this file is written would otherwise
    //   find nothing, and nothing would agree with an empty list without complaining.
    assert!(
        declared >= 55,
        "only {declared} declarations were found in this file — this search no longer matches \
         how the messages above are written"
    );
    // ⛔ Two numbers can be made to agree without the file being honest: list one message
    //   twice and leave another out, and the totals still match while the language checks
    //   above never read the one that was left out. Measured on this file — a message whose
    //   Korean half was an empty string, plus a second mention of an existing entry, and this
    //   check stayed green. Names are not visible here at run time, so the text stands in for
    //   the name: two entries carrying the same pair are either that trick or a copy-paste.
    let mut seen = std::collections::HashSet::new();
    for line in ALL_LINES {
        assert!(
            seen.insert((line.0, line.1)),
            "the list names the same message twice, which would let the totals below agree \
             while another message went unlisted and unread: {}",
            line.0
        );
    }
    assert_eq!(
        declared,
        ALL_LINES.len(),
        "{declared} messages are declared but {} are in ALL_LINES — add the new one there",
        ALL_LINES.len()
    );
}

/// The English text is what a person quotes when something goes wrong, so it may not be a
/// translation of nothing.
#[test]
fn the_two_languages_are_actually_different_text() {
    for line in ALL_LINES {
        assert_ne!(line.0, line.1, "a line was never translated: {}", line.0);
    }
}
