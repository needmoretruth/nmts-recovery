//! The one test that proves the claim on the real network.
//!
//! Everything in `offline.rs` synthesises the stored bytes, which proves the format and the
//! checks but not the part nobody can synthesise: that the URLs this program builds are the URLs a
//! real Walrus aggregator answers. This test stores a real blob on Walrus **testnet** through the
//! public publisher (Mysten-sponsored — no wallet, no coins, nothing spent), then recovers it with
//! nothing but an account code, a list file, and a public aggregator.
//!
//! # Running it
//! ```text
//! RECOVERY_LIVE_WALRUS=1 cargo test --test live_walrus -- --ignored --nocapture
//! ```
//! It is `#[ignore]`d and additionally gated on the variable, so an ordinary `cargo test` never
//! reaches out to the network — a test suite that silently needs the internet is one that fails for
//! reasons that have nothing to do with the code.
//!
//! ⚠ It uses `curl` for the upload on purpose. Storing blobs is not something this program does,
//! and giving it a write path just to test its read path would be the wrong shape entirely.

use std::fs;
use std::process::Command;

use nmts_crypto::codes::AccountCode;
use nmts_crypto::framing::StreamEncryptor;
use nmts_crypto::manifest::{Item, Part, RecoveryManifest};
use nmts_crypto::{b64, kdf, wrap};

const PUBLISHER: &str = "https://publisher.walrus-testnet.walrus.space";
const AGGREGATOR: &str = "https://aggregator.walrus-testnet.walrus.space";

#[test]
#[ignore = "reaches the public Walrus testnet; set RECOVERY_LIVE_WALRUS=1"]
fn a_real_blob_on_walrus_comes_back_as_the_original_file() {
    if std::env::var("RECOVERY_LIVE_WALRUS").ok().as_deref() != Some("1") {
        eprintln!("RECOVERY_LIVE_WALRUS is not 1 — not touching the network.");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("out")).expect("out");

    // A plaintext with a shape a corrupted recovery could not accidentally reproduce.
    let plaintext: Vec<u8> = (0..40_000u32).map(|i| (i.wrapping_mul(31) % 251) as u8).collect();

    let code = AccountCode::generate();
    fs::write(dir.path().join("code.txt"), code.display()).expect("code");
    let keys = kdf::derive(&code).expect("derive");

    // Encrypt exactly as the browser would: a fresh per-file key, one NCF-3 stream, part 0 of 1.
    let dek = wrap::generate_dek();
    let mut enc = StreamEncryptor::new(&dek, plaintext.len() as u64);
    let mut stream = enc.header().to_vec();
    stream.extend_from_slice(&enc.push(&plaintext).expect("push"));
    stream.extend_from_slice(&enc.finish().expect("finish"));
    let ct_path = dir.path().join("ciphertext.bin");
    fs::write(&ct_path, &stream).expect("ciphertext");

    // Store it on testnet through the public publisher.
    let put = Command::new("curl")
        .args(["-sS", "-X", "PUT", "--data-binary"])
        .arg(format!("@{}", ct_path.display()))
        .arg(format!("{PUBLISHER}/v1/blobs?epochs=1&deletable=true"))
        .output()
        .expect("curl");
    let body = String::from_utf8_lossy(&put.stdout).to_string();
    let Some(blob_id) = blob_id_from(&body) else {
        // The publisher is a free public service and is allowed to say no. That is not this
        // program failing, and reporting it as such would train us to ignore a red test.
        eprintln!("the public testnet publisher did not store the blob; response was:\n{body}");
        eprintln!("SKIPPED — nothing was proven. Re-run when the publisher answers.");
        return;
    };
    eprintln!("stored on Walrus testnet as blob {blob_id}");

    // The list: what a person would have saved from NMTS.
    let manifest = RecoveryManifest {
        v: 2,
        seq: 1,
        prev_manifest_blob_id: None,
        generated_at: "2026-08-17T10:00:00Z".into(),
        account_id: keys.account_id_b64(),
        // The live gate proves the network path, not the self-description; absence is what a list
        // written before the self-description was added looks like and it must keep working.
        meta: None,
        items: vec![Item {
            id: "live-1".into(),
            name: "proof.bin".into(),
            path: "/".into(),
            size: plaintext.len() as u64,
            dek: b64::encode(&*dek),
            kind: "file".into(),
            created_at: None,
            updated_at: None,
            content_hash: Some(b64::encode(&sha256(&plaintext))),
            parts: vec![Part {
                part_index: Some(0),
                blob_id: Some(blob_id.clone()),
                plaintext_len: plaintext.len() as u64,
                padded_len: None,
                network: Some("walrus".into()),
                sui_object_id: None,
            }],
            quilt: None,
        }],
    };
    let sealed = manifest.encrypt(&keys.data_key).expect("seal");
    fs::write(
        dir.path().join("map.nmtsmap"),
        format!(
            r#"{{"format":"nmts-recovery-map","version":2,"nrm":2,"seq":1,
                 "generated_at":"2026-08-17T10:00:00Z","account_id":"{}",
                 "sealed":"{}","note":["live proof","second line"]}}"#,
            keys.account_id_b64(),
            b64::encode(&sealed)
        ),
    )
    .expect("map");

    // ⛔ No --blobs-dir. The bytes come off the real network, through the program's own fetch path.
    let out = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
        .args(["--map", dir.path().join("map.nmtsmap").to_str().expect("utf8")])
        .args(["--code-file", dir.path().join("code.txt").to_str().expect("utf8")])
        .args(["--out", dir.path().join("out").to_str().expect("utf8")])
        .args(["--aggregator", AGGREGATOR, "--lang", "en"])
        .output()
        .expect("run nmts-recovery");
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    assert!(
        out.status.success(),
        "the live recovery failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let got = fs::read(dir.path().join("out/proof.bin")).expect("restored file");
    assert_eq!(got, plaintext, "the recovered bytes are not the original");
}

/// Pull the blob id out of the publisher's answer without adding a JSON dependency to a test that
/// exists to prove one HTTP path. The publisher reports either shape depending on whether these
/// exact bytes were already stored by somebody else.
fn blob_id_from(body: &str) -> Option<String> {
    let at = body.find("\"blobId\"")?;
    let rest = &body[at + "\"blobId\"".len()..];
    let start = rest.find('"')? + 1;
    let end = rest[start..].find('"')? + start;
    Some(rest[start..end].to_string())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
