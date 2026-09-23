//! The recovery phrase at the recovery tool: the NMTS key written as 15 words, in either BIP-39
//! list, wherever the tool reads the key. Runs the binary against a synthesised list, as
//! `offline.rs` does, and for the same reason.

use std::fs;

mod common;
use common::Fixture;
use nmts_crypto::PhraseLanguage;

/// A code file holding the phrase restores the same files as one holding the key — Korean words,
/// and English words written only by their first four letters, the way a faded page reads.
#[test]
fn the_recovery_phrase_opens_the_list_like_the_key_does() {
    let fx = Fixture::new();
    let body = b"opened from words".to_vec();
    let items = vec![fx.add_file("words.txt", "/", &body, 1, false)];
    fx.write_map(items);
    let korean = fx.code.to_phrase(PhraseLanguage::Korean);
    let english = fx.code.to_phrase(PhraseLanguage::English);
    let short: Vec<&str> = english.split(' ').map(|w| &w[..w.len().min(4)]).collect();

    for written in [korean, short.join(" ")] {
        fs::write(fx.path("code.txt"), format!("{written}\n")).expect("phrase file");
        let _ = fs::remove_dir_all(fx.path("out"));
        let out = fx.restore();
        assert!(
            out.status.success(),
            "restore from the phrase failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let got = fs::read(fx.path("out").join("words.txt")).expect("restored");
        assert_eq!(got, body);
    }
}
