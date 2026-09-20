//! Opening an account with a wallet's signature, end to end and with nothing switched on.
//!
//! # Why this runs the BINARY
//! For the reason `offline.rs` does: the claim is "your wallet gets your files back when NMTS is
//! gone", and only the program with arguments, a slot file and a folder of blobs proves it. The
//! engine's own tests already prove the wrapping; what is proved here is that the wallet road ends
//! in the same restore the typed NMTS key ends in.
//!
//! # What is synthesised
//! A real Ed25519 keypair standing in for a wallet, its real Sui address, a real signature over
//! the real message the program prints, and a real slot sealed by the same crate the browser
//! compiles to WASM. Nothing in this path verifies a signature — the engine does not, and neither
//! does the program — so a keypair here is exactly as good as a wallet, and the thing under test
//! is the agreement between the message that is printed and the slot that opens.

use std::fs;
use std::process::{Command, Output};

mod common;
use common::Fixture;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as Blake2Digest};
use ed25519_dalek::{Signer, SigningKey};
use nmts_crypto::opener;

/// Sui's Ed25519 scheme flag, the first byte of both an address preimage and a serialized
/// signature.
const ED25519_FLAG: u8 = 0x00;

fn wallet() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// `0x` + hex of BLAKE2b-256 over the flag and the public key — Sui's address rule, applied here
/// rather than imported, because this crate is a binary and a test cannot reach into it.
fn address_of(key: &SigningKey) -> String {
    let mut h: Blake2b<U32> = Blake2b::new();
    Blake2Digest::update(&mut h, [ED25519_FLAG]);
    Blake2Digest::update(&mut h, key.verifying_key().as_bytes());
    format!("0x{}", hex(&h.finalize()))
}

/// What a wallet hands back: `flag || signature(64) || public key(32)`.
fn serialized_signature(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let mut out = vec![ED25519_FLAG];
    out.extend_from_slice(&key.sign(message).to_bytes());
    out.extend_from_slice(key.verifying_key().as_bytes());
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Padded standard base64 — the spelling a Sui wallet answers in.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 0x3f]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
        .args(args)
        .output()
        .expect("run nmts-recovery")
}

/// A fixture with one file in it, a list, and a slot holding its NMTS key under `signature`.
fn account_with_a_slot(signature: &[u8]) -> (Fixture, Vec<u8>) {
    let fx = Fixture::new();
    let items = vec![fx.add_file("notes.txt", "/docs", b"the quick brown fox", 1, false)];
    fx.write_map(items);
    let slot = opener::opener_from_signature(signature)
        .expect("an Ed25519 signature is accepted")
        .seal(fx.code.as_bytes())
        .expect("a wallet-signature slot");
    (fx, slot.to_vec())
}

/// ⛔ THE MESSAGE THE PROGRAM PRINTS IS THE MESSAGE THE ENGINE WRAPS UNDER. If these ever differ
///    by one byte, everyone who signed what this program printed gets a slot that never opens, and
///    the only symptom is a refusal that reads like the wrong wallet.
#[test]
fn the_printed_message_is_the_engines_bytes_and_nothing_more() {
    let address = address_of(&wallet());
    let out = run(&["--print-wallet-message", &address]);
    assert!(out.status.success(), "printing the message failed");
    let expected = opener::opener_message(&address, 1, None).expect("canonical address");
    assert_eq!(
        out.stdout, expected,
        "the printed bytes are not the engine's"
    );
    assert!(
        !out.stdout.ends_with(b"\n"),
        "a trailing newline was added — that is a different message"
    );

    // The account number and the app are inside those bytes, so the flags have to reach them.
    let out = run(&[
        "--print-wallet-message",
        &address,
        "--wallet-account",
        "3",
        "--wallet-app",
        "example.com",
    ]);
    assert_eq!(
        out.stdout,
        opener::opener_message(&address, 3, Some("example.com")).expect("canonical")
    );

    // ⚠ Everything that is not the message goes to stderr, so a redirect keeps the file exact —
    //   and the one fact a person cannot guess is in it.
    let said = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(said.contains("personal message"), "stderr: {said}");
}

/// The claim, tested: a slot file and a signature give the files back, with no NMTS key typed.
#[test]
fn a_slot_and_a_signature_restore_the_files() {
    let key = wallet();
    let address = address_of(&key);
    let message = opener::opener_message(&address, 1, None).expect("canonical");
    let signature = serialized_signature(&key, &message);
    let (fx, slot) = account_with_a_slot(&signature);
    fs::write(fx.path("slot.bin"), &slot).expect("slot file");

    // Both spellings a person can hand over, each driving the whole restore.
    for (name, text) in [
        ("sig.hex", hex(&signature)),
        ("sig.b64", base64(&signature)),
    ] {
        fs::write(fx.path(name), &text).expect("signature file");
        fs::remove_dir_all(fx.path("out")).ok();
        fs::create_dir_all(fx.path("out")).expect("out dir");
        let out = run(&[
            "--map",
            fx.path("map.nmtsmap").to_str().expect("utf8"),
            "--wallet-slot",
            fx.path("slot.bin").to_str().expect("utf8"),
            "--wallet-signature-file",
            fx.path(name).to_str().expect("utf8"),
            "--blobs-dir",
            fx.path("blobs").to_str().expect("utf8"),
            "--out",
            fx.path("out").to_str().expect("utf8"),
            "--lang",
            "en",
        ]);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(out.status.success(), "{name} did not restore:\n{stdout}");
        assert_eq!(
            fs::read(fx.path("out").join("docs/notes.txt")).expect("restored"),
            b"the quick brown fox"
        );
        // ⛔ Neither secret is echoed. The signature opens the account and so does the key it
        //    unwraps; a program that printed either would put both in a terminal's scrollback.
        let all = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
        assert!(
            !all.contains(&text),
            "{name}: the signature was printed back"
        );
        assert!(
            !all.contains(&fx.code.display()) && !all.contains(&fx.code.canonical()),
            "{name}: the NMTS key was printed"
        );
    }

    // ⛔ AND THE SAME SIGNATURE AS AN ARGUMENT IS REFUSED, with the file flag named. If this ever
    //    parses, a value that opens somebody's account starts landing in shell histories — and it
    //    would work, which is what makes it the mistake nobody notices making.
    let out = run(&[
        "--map",
        fx.path("map.nmtsmap").to_str().expect("utf8"),
        "--wallet-slot",
        fx.path("slot.bin").to_str().expect("utf8"),
        "--wallet-signature",
        &base64(&signature),
        "--blobs-dir",
        fx.path("blobs").to_str().expect("utf8"),
        "--out",
        fx.path("out").to_str().expect("utf8"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "--wallet-signature was accepted"
    );
    let said = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(said.contains("shell history"), "{said}");
    assert!(said.contains("--wallet-signature-file"), "{said}");
    // The refusal says what to do instead, and it does not say the signature back.
    assert!(
        !said.contains(&base64(&signature)),
        "the refusal printed the signature"
    );
}

/// ⛔ THE DISCRIMINATING TEST: a signature that is perfectly valid and simply not this one. It has
///    to fail, it has to say why in a way that does not narrow the guess, and it has to leave
///    nothing behind that looks like a restored file.
#[test]
fn another_wallets_signature_does_not_open_the_slot() {
    let key = wallet();
    let address = address_of(&key);
    let message = opener::opener_message(&address, 1, None).expect("canonical");
    let (fx, slot) = account_with_a_slot(&serialized_signature(&key, &message));
    fs::write(fx.path("slot.bin"), &slot).expect("slot file");

    // The same wallet, signing the message for account 2 — the near miss a person actually makes.
    let other = opener::opener_message(&address, 2, None).expect("canonical");
    fs::write(fx.path("sig.hex"), hex(&serialized_signature(&key, &other)))
        .expect("signature file");

    let out = run(&[
        "--map",
        fx.path("map.nmtsmap").to_str().expect("utf8"),
        "--wallet-slot",
        fx.path("slot.bin").to_str().expect("utf8"),
        "--wallet-signature-file",
        fx.path("sig.hex").to_str().expect("utf8"),
        "--blobs-dir",
        fx.path("blobs").to_str().expect("utf8"),
        "--out",
        fx.path("out").to_str().expect("utf8"),
        "--lang",
        "en",
    ]);
    assert!(!out.status.success(), "a wrong signature was accepted");
    let said = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        said.contains("does not open this wallet recovery file"),
        "{said}"
    );
    assert_eq!(
        fs::read_dir(fx.path("out")).expect("out dir").count(),
        0,
        "something was written after a refusal"
    );
}

/// A wallet whose signatures are never the same twice, and a file that is not a slot: each
/// refused on its own terms, before anything is read or written.
#[test]
fn a_wallet_that_cannot_be_used_and_a_file_that_is_not_a_slot_are_each_named() {
    let key = wallet();
    let address = address_of(&key);
    let message = opener::opener_message(&address, 1, None).expect("canonical");
    let signature = serialized_signature(&key, &message);
    let (fx, slot) = account_with_a_slot(&signature);
    fs::write(fx.path("slot.bin"), &slot).expect("slot file");
    fs::write(fx.path("sig.hex"), hex(&signature)).expect("signature file");

    // Flag 0x03 is multisig: the whole serialized form is a different shape, and the reason is
    // about the wallet rather than about these bytes.
    let mut multisig = vec![0x03u8];
    multisig.extend_from_slice(&signature[1..]);
    fs::write(fx.path("multisig.hex"), hex(&multisig)).expect("signature file");
    let out = run(&[
        "--map",
        fx.path("map.nmtsmap").to_str().expect("utf8"),
        "--wallet-slot",
        fx.path("slot.bin").to_str().expect("utf8"),
        "--wallet-signature-file",
        fx.path("multisig.hex").to_str().expect("utf8"),
        "--blobs-dir",
        fx.path("blobs").to_str().expect("utf8"),
        "--out",
        fx.path("out").to_str().expect("utf8"),
        "--lang",
        "en",
    ]);
    assert!(!out.status.success(), "a multisig signature was accepted");
    let said = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(said.contains("multisig"), "{said}");

    // A slot that is not 62 bytes is answered by length, not by "wrong wallet".
    fs::write(fx.path("not-a-slot.bin"), b"this is not a slot").expect("file");
    let out = run(&[
        "--map",
        fx.path("map.nmtsmap").to_str().expect("utf8"),
        "--wallet-slot",
        fx.path("not-a-slot.bin").to_str().expect("utf8"),
        "--wallet-signature-file",
        fx.path("sig.hex").to_str().expect("utf8"),
        "--blobs-dir",
        fx.path("blobs").to_str().expect("utf8"),
        "--out",
        fx.path("out").to_str().expect("utf8"),
        "--lang",
        "en",
    ]);
    assert!(!out.status.success(), "a file that is not a slot was used");
    let said = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(said.contains("62") && said.contains("18"), "{said}");
}

/// ⛔ A SLOT WITHOUT ITS SIGNATURE MUST NOT FALL THROUGH TO THE NMTS-KEY PROMPT. A person who set
///    out not to need their NMTS key would be asked for it by a program that had already been told
///    where the key is — and a flag that reaches nothing must not be accepted in silence either.
#[test]
fn half_a_wallet_road_is_refused_before_anything_is_read() {
    let fx = Fixture::new();
    let map = fx.path("map.nmtsmap");
    let map = map.to_str().expect("utf8");
    let slot = fx.path("slot.bin");
    let slot = slot.to_str().expect("utf8");
    let cases: [Vec<&str>; 4] = [
        vec!["--map", map, "--wallet-slot", slot, "--list"],
        vec!["--map", map, "--wallet-signature-file", slot, "--list"],
        vec![
            "--map",
            map,
            "--wallet-slot",
            slot,
            "--wallet-signature-file",
            slot,
            "--code-file",
            slot,
            "--list",
        ],
        vec!["--derive", "--wallet-account", "2"],
    ];
    for case in cases {
        let out = run(&case);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{case:?} was not refused: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
