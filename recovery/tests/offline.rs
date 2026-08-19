//! The whole tool, end to end, with no network and no NMTS.
//!
//! # Why this runs the BINARY rather than calling functions
//! The claim the tool makes is "you can get your files back with this program". Calling its
//! internals proves the internals; running `nmts-recovery` with arguments, a list file, and a folder
//! of blobs proves the claim — argument handling, exit codes and all. Cargo hands the test the
//! built binary's path in `CARGO_BIN_EXE_nmts-recovery`, so no path is guessed here.
//!
//! # What is synthesised
//! A real account code, real NCF-3 streams under real per-file keys, and a real sealed list. The
//! bytes these tests feed the tool are produced by the same crate the browser compiles to WASM,
//! so a change that made the browser and the tool disagree fails here rather than in someone's
//! recovery.

use std::fs;
use std::path::Path;
use std::process::Command;

mod common;
use common::{sha256, Fixture, Padding};
use nmts_crypto::b64;
use nmts_crypto::codes::AccountCode;


fn restored(fx: &Fixture, rel: &str) -> Vec<u8> {
    fs::read(fx.path("out").join(rel)).unwrap_or_else(|e| panic!("{rel} was not restored: {e}"))
}

/// The claim, tested: an account code plus a list plus the stored bytes gives the files back.
#[test]
fn a_code_and_a_map_give_the_files_back() {
    let fx = Fixture::new();
    let small = b"the quick brown fox".to_vec();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let empty: Vec<u8> = Vec::new();
    let items = vec![
        fx.add_file("notes.txt", "/docs", &small, 1, false),
        fx.add_file("photo.raw", "/photos/2026", &big, 3, false),
        fx.add_file("empty.bin", "/", &empty, 1, false),
        fx.add_file("batched.txt", "/docs", b"inside a cohort", 1, true),
    ];
    fx.write_map(items);

    let out = fx.restore();
    assert!(
        out.status.success(),
        "restore failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(restored(&fx, "docs/notes.txt"), small);
    assert_eq!(restored(&fx, "photos/2026/photo.raw"), big);
    assert_eq!(restored(&fx, "empty.bin"), empty);
    assert_eq!(restored(&fx, "docs/batched.txt"), b"inside a cohort");
}

/// ⛔ THE DISCRIMINATING TEST for the defect `RECOVERY-MANIFEST.md` §2.1 exists for: two parts of
///    one file listed in the wrong order. Every part is internally valid and every tag
///    authenticates, so only a positional check catches it. If this ever passes, a person gets a
///    file back that is silently scrambled — the worst outcome this program has.
#[test]
fn parts_served_in_the_wrong_order_are_refused_rather_than_written() {
    let fx = Fixture::new();
    let bytes: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
    let mut item = fx.add_file("swapped.bin", "/", &bytes, 2, false);
    // Swap the two parts, and renumber them so the LIST is internally consistent — this is exactly
    // what a hostile or broken index looks like, and the only thing left to catch it is each
    // part's own sealed header.
    item.parts.swap(0, 1);
    item.parts[0].part_index = Some(0);
    item.parts[1].part_index = Some(1);
    fx.write_map(vec![item]);

    let out = fx.restore();
    assert!(!out.status.success(), "a scrambled file was accepted");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("where part 0 of 2 belongs"), "{text}");
    // ⛔ And nothing is left on disk that could be mistaken for the file.
    assert!(!fx.path("out/swapped.bin").exists(), "a bad file was written");
    assert_eq!(
        fs::read_dir(fx.path("out")).expect("out dir").count(),
        0,
        "a temporary file was left behind"
    );
}

/// ⛔ THE SAME DEFECT WITH THE SAFETY NET REMOVED. An item written before content hashes existed
///    has nothing spanning its parts, so the positional check is the ONLY thing standing between a
///    swapped part list and a silently scrambled file. Without this test the previous one passes on
///    the hash alone, and deleting `verify_placement` would look safe.
#[test]
fn wrong_order_is_caught_even_when_there_is_no_content_hash_to_fall_back_on() {
    let fx = Fixture::new();
    let bytes: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
    let mut item = fx.add_file("swapped.bin", "/", &bytes, 2, false);
    item.content_hash = None;
    item.parts.swap(0, 1);
    item.parts[0].part_index = Some(0);
    item.parts[1].part_index = Some(1);
    fx.write_map(vec![item]);

    let out = fx.restore();
    assert!(!out.status.success(), "a scrambled file was accepted with nothing left to catch it");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("where part 0 of 2 belongs"), "{text}");
    assert!(!fx.path("out/swapped.bin").exists(), "a scrambled file was written");
}

/// ⭐ SIZE PADDING. A stored part may be sealed larger than the bytes it contributes,
///    so that whoever can see the stored object cannot read the file's real size off it. The
///    padding goes INTO the plaintext — an NCF-3 header is authenticated but not encrypted, so
///    anything appended to the blob would leave the true length legible at offset 16 — and the
///    list therefore holds two numbers: what the part contributes and what its sealed header says.
///
/// The claim tested here is the only one that matters to a person: **they get their file back,
/// byte for byte, and the padding is not in it.** The content hash in the list is over the real
/// bytes, so a tool that wrote the padding out would fail this twice over.
#[test]
fn a_padded_part_gives_back_the_real_bytes_and_not_the_padding() {
    let fx = Fixture::new();
    let real = b"nineteen bytes here".to_vec();
    let item = fx.add_padded_file(
        "notes.txt",
        "/docs",
        &real,
        1,
        false,
        Some(Padding { bytes: 4096, recorded: true }),
    );
    fx.write_map(vec![item]);

    let out = fx.restore();
    assert!(
        out.status.success(),
        "a padded part was refused:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(restored(&fx, "docs/notes.txt"), real);
}

/// The multi-part shape a real upload produces: full parts, then a padded tail.
#[test]
fn padding_on_the_tail_of_a_multi_part_file_is_taken_off_again() {
    let fx = Fixture::new();
    let real: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let item = fx.add_padded_file(
        "photo.raw",
        "/photos",
        &real,
        3,
        false,
        Some(Padding { bytes: 65_536, recorded: true }),
    );
    fx.write_map(vec![item]);

    let out = fx.restore();
    assert!(
        out.status.success(),
        "a padded multi-part file was refused:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(restored(&fx, "photos/photo.raw"), real);
}

/// ⛔ THE DISCRIMINATING HALF. Tolerating padding must not become tolerating a length the list
///    and the stored bytes disagree about. Here the part really was padded and the list does NOT
///    say so — which is what an edited list looks like — and the tool must stop on the sealed
///    header exactly as it did before padding existed. If this ever passes, `padded_len` has
///    stopped being a claim the list has to make and the size check has become decorative.
#[test]
fn padding_the_list_did_not_record_is_still_refused() {
    let fx = Fixture::new();
    let item = fx.add_padded_file(
        "notes.txt",
        "/docs",
        b"nineteen bytes here",
        1,
        false,
        Some(Padding { bytes: 4096, recorded: false }),
    );
    fx.write_map(vec![item]);

    let out = fx.restore();
    assert!(!out.status.success(), "unrecorded padding was accepted");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("the part itself says"), "{text}");
    assert!(!fx.path("out/docs/notes.txt").exists(), "a padded file was written");
}

/// A list is a file somebody can edit. Changing the recorded size must not produce a file.
#[test]
fn a_length_the_map_invented_is_caught() {
    let fx = Fixture::new();
    let mut item = fx.add_file("a.bin", "/", b"twenty bytes exactly", 1, false);
    item.size = 19;
    item.parts[0].plaintext_len = 19;
    fx.write_map(vec![item]);

    let out = fx.restore();
    assert!(!out.status.success(), "a length mismatch was accepted");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("the part itself says"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The check that spans parts. A list naming the right bytes for the wrong file passes everything
/// else, because each part is internally perfect.
#[test]
fn a_content_hash_that_does_not_match_stops_the_file() {
    let fx = Fixture::new();
    let mut item = fx.add_file("a.bin", "/", b"some content", 1, false);
    item.content_hash = Some(b64::encode(&sha256(b"different content")));
    fx.write_map(vec![item]);

    let out = fx.restore();
    assert!(!out.status.success(), "a wrong hash was accepted");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("does not match the hash"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!fx.path("out/a.bin").exists());
}

/// ⛔ "Wrong code" and "damaged map" fail the same decryption. Telling them apart is what stops a
///    person hunting for a backup of a file that was never broken.
#[test]
fn a_different_accounts_code_says_so_instead_of_blaming_the_map() {
    let fx = Fixture::new();
    fx.write_map(vec![fx.add_file("a.bin", "/", b"x", 1, false)]);
    let other = AccountCode::generate();
    fs::write(fx.path("other.txt"), other.display()).expect("write");

    let out = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
        .args(["--map", fx.path("map.nmtsmap").to_str().expect("utf8")])
        .args(["--code-file", fx.path("other.txt").to_str().expect("utf8")])
        .args(["--lang", "en", "--list"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("different account"), "{err}");
}

/// A code that fails its own check symbol is named as such — before Argon2id runs, and long before
/// anything is fetched.
#[test]
fn a_mistyped_code_is_named_as_a_typo() {
    let fx = Fixture::new();
    fx.write_map(vec![fx.add_file("a.bin", "/", b"x", 1, false)]);
    fs::write(fx.path("typo.txt"), "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HH").expect("write");

    let out = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
        .args(["--map", fx.path("map.nmtsmap").to_str().expect("utf8")])
        .args(["--code-file", fx.path("typo.txt").to_str().expect("utf8")])
        .args(["--lang", "en", "--list"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("check symbol"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `--list` opens the list and touches nothing else: no network, no writes.
#[test]
fn listing_shows_the_contents_and_writes_nothing() {
    let fx = Fixture::new();
    fx.write_map(vec![
        fx.add_file("notes.txt", "/docs", b"hello", 1, false),
        fx.add_file("photo.raw", "/photos", b"world!", 1, false),
    ]);

    let out = fx.run(&["--list"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("/docs/notes.txt"), "{text}");
    assert!(text.contains("/photos/photo.raw"), "{text}");
    assert!(text.contains("2 files"), "{text}");
    assert_eq!(fs::read_dir(fx.path("out")).expect("out").count(), 0);
}

/// The fetch plan is the offline path's other half: what it prints must be fetchable, and the
/// names it prints must be the names `--blobs-dir` then looks for.
#[test]
fn the_fetch_plan_names_the_same_files_the_blob_folder_uses() {
    let fx = Fixture::new();
    fx.write_map(vec![fx.add_file("a.bin", "/", b"hello", 1, false)]);

    let out = fx.run(&["--print-fetch-plan"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("curl -fL -o blob-a-bin-0.bin"), "{text}");
    assert!(text.contains("/v1/blobs/a-bin-0"), "{text}");
    // And that is exactly the file the blob folder holds.
    assert!(fx.path("blobs/blob-a-bin-0.bin").exists());
}

/// A file already at the destination is not silently replaced.
#[test]
fn an_existing_file_is_left_alone_unless_overwrite_is_asked_for() {
    let fx = Fixture::new();
    fx.write_map(vec![fx.add_file("a.bin", "/", b"new bytes", 1, false)]);
    fs::write(fx.path("out/a.bin"), b"already here").expect("write");

    let out = fx.restore();
    assert!(!out.status.success());
    assert_eq!(restored(&fx, "a.bin"), b"already here");

    let out = fx.run(&[
        "--out",
        fx.path("out").to_str().expect("utf8"),
        "--blobs-dir",
        fx.path("blobs").to_str().expect("utf8"),
        "--overwrite",
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(restored(&fx, "a.bin"), b"new bytes");
}

/// One unreachable blob costs one file. The rest come back, and the exit code still says something
/// went wrong — a half recovery that exits 0 is one a script reports as a success.
#[test]
fn one_missing_blob_does_not_cost_the_other_files() {
    let fx = Fixture::new();
    fx.write_map(vec![
        fx.add_file("kept.txt", "/", b"still here", 1, false),
        fx.add_file("gone.txt", "/", b"not any more", 1, false),
    ]);
    fs::remove_file(fx.path("blobs/blob-gone-txt-0.bin")).expect("remove");

    let out = fx.restore();
    assert!(!out.status.success(), "a failure exited 0");
    assert_eq!(restored(&fx, "kept.txt"), b"still here");
    assert!(!fx.path("out/gone.txt").exists());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("1 restored, 1 failed"), "{text}");
}

/// `--only` narrows the work without changing anything else about it.
#[test]
fn only_restores_what_was_asked_for() {
    let fx = Fixture::new();
    fx.write_map(vec![
        fx.add_file("a.txt", "/keep", b"wanted", 1, false),
        fx.add_file("b.txt", "/other", b"unwanted", 1, false),
    ]);

    let out = fx.run(&[
        "--out",
        fx.path("out").to_str().expect("utf8"),
        "--blobs-dir",
        fx.path("blobs").to_str().expect("utf8"),
        "--only",
        "/keep",
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(restored(&fx, "keep/a.txt"), b"wanted");
    assert!(!fx.path("out/other").exists());
}

/// A folder name containing the path separator is escaped by the builder (`／`), and must come back
/// as one folder rather than two.
#[test]
fn an_escaped_folder_name_stays_one_folder() {
    let fx = Fixture::new();
    fx.write_map(vec![fx.add_file("x.txt", "/a／b", b"one folder", 1, false)]);

    let out = fx.restore();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(restored(&fx, "a／b/x.txt"), b"one folder");
    assert!(!Path::new(&fx.path("out/a/b")).exists(), "it split into two folders");
}


// --- the recovery kit: one file with everything in it -------------------------------------------

/// ⭐ The kit is the shape the product hands people when they want one file rather than two: the
///    account code and the recovery list together. This program has to accept it, take the list out
///    of it, and NOT ask for a code that is printed in the file it was just given.
#[test]
fn a_recovery_kit_alone_gives_the_files_back() {
    let fx = Fixture::new();
    let text = b"one file, everything in it".to_vec();
    let item = fx.add_file("kit.txt.restored", "/docs", &text, 1, false);
    fx.write_map(vec![item]);
    fx.write_kit();

    // ⛔ No --code-file. The kit carries the code, and the whole point is that it is enough.
    let out = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
        .args(["--map", fx.path("kit.txt").to_str().expect("utf8")])
        .args(["--out", fx.path("out").to_str().expect("utf8")])
        .args(["--blobs-dir", fx.path("blobs").to_str().expect("utf8")])
        .args(["--lang", "en"])
        .output()
        .expect("run");
    let said = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(said.contains("recovery list is inside it"), "{said}");
    // ⛔ And it says so out loud. Using a code without asking is right here; doing it quietly is not.
    assert!(said.contains("carries your account code in the clear"), "{said}");
    assert_eq!(restored(&fx, "docs/kit.txt.restored"), text);
}

/// A kit for one account holding a list for another was assembled by hand. Say so before the
/// account code goes anywhere near it.
#[test]
fn a_kit_and_a_list_that_disagree_about_the_account_are_refused() {
    let fx = Fixture::new();
    let item = fx.add_file("a.txt", "/", b"x", 1, false);
    fx.write_map(vec![item]);
    fx.write_kit();

    let kit = fs::read_to_string(fx.path("kit.txt")).expect("kit");
    let keys = nmts_crypto::kdf::derive(&fx.code).expect("derive");
    let swapped = kit.replacen(
        &format!("\"account_id\":\"{}\"", keys.account_id_b64()),
        "\"account_id\":\"AAAAAAAAAAAAAAAAAAAAAA\"",
        1,
    );
    fs::write(fx.path("kit.txt"), swapped).expect("write");

    let out = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
        .args(["--map", fx.path("kit.txt").to_str().expect("utf8")])
        .args(["--out", fx.path("out").to_str().expect("utf8")])
        .args(["--blobs-dir", fx.path("blobs").to_str().expect("utf8")])
        .args(["--lang", "en"])
        .output()
        .expect("run");
    assert!(!out.status.success(), "a mismatched kit was accepted");
    let said = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(said.contains("the kit is for account"), "{said}");
}

/// `--derive` needs no list at all — it is the answer to "what does this code give me".
#[test]
fn deriving_from_a_code_alone_prints_the_public_values_and_no_secrets() {
    let fx = Fixture::new();
    let out = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
        .args(["--derive", "--code-file", fx.path("code.txt").to_str().expect("utf8")])
        .args(["--lang", "en"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let said = String::from_utf8_lossy(&out.stdout).to_string();

    let keys = nmts_crypto::kdf::derive(&fx.code).expect("derive");
    assert!(said.contains(&keys.account_id_b64()), "{said}");
    assert!(said.contains("Public code"), "{said}");
    assert!(said.contains("0x"), "no wallet address: {said}");
    // ⛔ Not by default. Somebody checking an account id must not get a spendable key for free.
    assert!(!said.contains("suiprivkey"), "a private key was printed unasked: {said}");
    assert!(said.contains("--secrets"), "it does not say how to ask for them: {said}");
}

/// And with `--secrets`, the warning comes BEFORE the keys.
#[test]
fn asking_for_secrets_prints_them_after_the_warning_about_them() {
    let fx = Fixture::new();
    let out = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
        .args(["--derive", "--secrets", "--wallets", "2"])
        .args(["--code-file", fx.path("code.txt").to_str().expect("utf8")])
        .args(["--lang", "en"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let said = String::from_utf8_lossy(&out.stdout).to_string();

    assert_eq!(said.matches("suiprivkey").count(), 2, "two wallets, two keys: {said}");
    let warning = said.find("PRIVATE KEYS FOLLOW").expect("no warning");
    let first_key = said.find("suiprivkey").expect("no key");
    assert!(warning < first_key, "the warning came after the keys");
}

// ── What the list says about itself (owner directive, 2026-08-19) ────────────────────────────────────────────────

/// A restored file keeps the date the list recorded for it.
///
/// ⭐ The reason this is worth bytes in a format: a recovery used to hand a person four hundred
/// files all dated the moment of the recovery, which is the one date that is certainly wrong. The
/// dates come out of the storage layer and are checked against nothing, so they may not decide
/// anything — but writing them onto the files decides nothing.
#[test]
fn a_restored_file_keeps_the_date_the_list_recorded() {
    let fx = Fixture::new();
    let body = b"dated".to_vec();
    let item = fx.add_file("dated.txt", "/", &body, 1, false);
    fx.write_map(vec![item]);

    let out = fx.restore();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let meta = fs::metadata(fx.path("out").join("dated.txt")).expect("restored file");
    let modified = meta
        .modified()
        .expect("a modification time")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    assert_eq!(
        modified,
        common::UPDATED_AT_UNIX,
        "the file kept the date of the recovery instead of its own"
    );
}

/// A list with no dates leaves the file with the date it was written — not 1970.
///
/// ⛔ The discriminating half. An implementation that parsed nothing and passed the epoch through
/// would satisfy the test above's opposite and stamp every file "1 January 1970", which reads as
/// data corruption to anyone looking at the folder.
#[test]
fn a_file_the_list_gave_no_date_is_left_at_the_time_of_the_recovery() {
    let fx = Fixture::new();
    let body = b"undated".to_vec();
    let mut item = fx.add_file("undated.txt", "/", &body, 1, false);
    item.created_at = None;
    item.updated_at = None;
    fx.write_map(vec![item]);

    let out = fx.restore();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let modified = fs::metadata(fx.path("out").join("undated.txt"))
        .expect("restored file")
        .modified()
        .expect("a modification time")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    // Some time after this format was designed, and not the fixture's date either.
    assert!(modified > 1_750_000_000, "left at {modified}, which is not now");
    assert_ne!(modified, common::UPDATED_AT_UNIX);
}

/// The list's own account of itself is printed before what it covers.
#[test]
fn the_list_says_who_wrote_it_and_which_chain_it_belongs_to() {
    let fx = Fixture::new();
    let item = fx.add_file("a.txt", "/", b"x", 1, false);
    fx.write_map_with_meta(
        vec![item],
        nmts_crypto::manifest::Meta {
            product: Some("NMTS".into()),
            app_version: Some("9.9.9".into()),
            spec_url: Some("https://example.invalid/RECOVERY-MANIFEST.md".into()),
            storage: Some(nmts_crypto::manifest::MetaStorage {
                network: Some("walrus".into()),
                chain: Some("testnet".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let out = fx.run(&["--list"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("NMTS 9.9.9"), "{text}");
    assert!(text.contains("walrus/testnet"), "{text}");
    assert!(text.contains("https://example.invalid/RECOVERY-MANIFEST.md"), "{text}");
}

/// A list that does NOT carry the block says nothing extra — and still lists its files.
#[test]
fn a_list_without_the_block_prints_no_invented_facts() {
    let fx = Fixture::new();
    let item = fx.add_file("a.txt", "/", b"x", 1, false);
    fx.write_map(vec![item]);

    let out = fx.run(&["--list"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("a.txt"), "{text}");
    // ⛔ No stand-in chain, no guessed product version. "?" is only ever printed beside values the
    //    document did carry a block for; a document with none gets no line at all.
    assert!(!text.contains("Written by"), "{text}");
    assert!(!text.contains("walrus/"), "{text}");
}

/// The document's own count disagreeing with what was read is SAID, not swallowed.
#[test]
fn a_count_that_disagrees_with_what_was_read_is_reported() {
    let fx = Fixture::new();
    let item = fx.add_file("a.txt", "/", b"x", 1, false);
    fx.write_map_with_meta(
        vec![item],
        nmts_crypto::manifest::Meta {
            totals: Some(nmts_crypto::manifest::MetaTotals {
                items: Some(12),
                bytes: Some(999),
            }),
            ..Default::default()
        },
    );

    let out = fx.run(&["--list"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("says it holds 12 files"), "{text}");
    assert!(text.contains("1 were read"), "{text}");
    // ⛔ And it is a warning, not a refusal: the one file that IS in the list still comes back.
    assert!(out.status.success(), "{text}");
}
