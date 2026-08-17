//! The whole tool, end to end, with no network and no NMTS.
//!
//! # Why this runs the BINARY rather than calling functions
//! The claim the tool makes is "you can get your files back with this program". Calling its
//! internals proves the internals; running `nmts-recovery` with arguments, a map file, and a folder
//! of blobs proves the claim — argument handling, exit codes and all. Cargo hands the test the
//! built binary's path in `CARGO_BIN_EXE_nmts-recovery`, so no path is guessed here.
//!
//! # What is synthesised
//! A real account code, real NCF-3 streams under real per-file keys, and a real sealed map. The
//! bytes these tests feed the tool are produced by the same crate the browser compiles to WASM,
//! so a change that made the browser and the tool disagree fails here rather than in someone's
//! recovery.

use std::fs;
use std::path::Path;
use std::process::Command;

mod common;
use common::{sha256, Fixture};
use nmts_crypto::b64;
use nmts_crypto::codes::AccountCode;


fn restored(fx: &Fixture, rel: &str) -> Vec<u8> {
    fs::read(fx.path("out").join(rel)).unwrap_or_else(|e| panic!("{rel} was not restored: {e}"))
}

/// The claim, tested: an account code plus a map plus the stored bytes gives the files back.
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
    // Swap the two parts, and renumber them so the MAP is internally consistent — this is exactly
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

/// A map is a file somebody can edit. Changing the recorded size must not produce a file.
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

/// The check that spans parts. A map naming the right bytes for the wrong file passes everything
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

/// `--list` opens the map and touches nothing else: no network, no writes.
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
