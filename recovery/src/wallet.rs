//! Opening an account with a wallet's signature, offline (NCF-3 §1.7).
//!
//! # What this adds, and what it does not change
//! An NMTS account is still one secret: the 20-byte NMTS key. A **slot** is a 62-byte record that
//! holds that key wrapped under a key derived from a Sui wallet's signature over one fixed message,
//! and NMTS hands the file out from the account screen. Whoever has the slot file and can make that
//! signature again has the NMTS key — which is the whole point here: a person who never wrote their
//! NMTS key down, but still has their wallet and the slot file they saved, is not locked out.
//!
//! Everything downstream is untouched. This module answers with an [`AccountCode`], the same type
//! the terminal prompt produces, so the list, the fetch, the decryption and the writing cannot tell
//! the two roads apart — and no code path had to learn about wallets to keep working.
//!
//! # ⛔ No server, no verification, no cryptography of its own
//! Nothing here contacts anything: the slot comes from a file the person already has, and the
//! signature comes from their wallet, wherever they run it. Every byte of the derivation is a call
//! into `nmts-crypto`, the same crate the browser compiles to WASM.
//!
//! This does NOT check that the signature belongs to the address in the message — that check needs
//! the Sui library and it is the product's step, not this one's. Here it would buy nothing: a
//! signature that is not the right one fails to open the slot, which is the answer either way.
//!
//! # ⚠ The signature is key material
//! It unwraps the NMTS key, so it is handled like the NMTS key: read from a file and from nowhere
//! else — `args.rs` refuses `--wallet-signature` the way it refuses `--code` — held in
//! [`Zeroizing`] text, never printed, and never written anywhere by this program.
//!
//! # ⚠ The signature has to be a PERSONAL MESSAGE signature
//! Sui signs a personal message over an intent-prefixed hash of the bytes, and a transaction-intent
//! signature over the very same text is different bytes — a different wrapping key, and a slot that
//! does not open. [`msg::WALLET_HOW_TO_SIGN`] is where that is said to the person.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use nmts_crypto::codes::AccountCode;
use nmts_crypto::opener::{self, OpenerRefusal};
use zeroize::Zeroizing;

use crate::args::{Args, Lang};
use crate::msg;

/// Write the exact bytes a wallet must sign, and stop.
///
/// ⛔ THE BYTES GO TO STDOUT AND NOTHING ELSE DOES. A byte that is not in the message — a trailing
/// newline, a heading, a hint — is a different message, a different wrapping key, and a slot that
/// never opens. So the instructions are printed on stderr, where a redirect to a file leaves them
/// behind and the file holds the message and only the message.
pub fn print_message(a: &Args) -> Result<ExitCode, String> {
    let address = a
        .wallet_message_address
        .as_deref()
        .ok_or("no wallet address was given")?;
    let message = opener::opener_message(address, a.wallet_account, a.wallet_app.as_deref())
        .map_err(|why| refusal(&why, a.lang))?;
    eprintln!("{}", msg::WALLET_HOW_TO_SIGN.get(a.lang));
    let mut out = std::io::stdout();
    out.write_all(&message).map_err(|e| format!("{e}"))?;
    out.flush().map_err(|e| format!("{e}"))?;
    Ok(ExitCode::SUCCESS)
}

/// The NMTS key inside the slot file, opened by the wallet's signature.
///
/// The returned value is what a typed NMTS key produces, and it is produced the same way: the
/// signature goes into the engine, the engine answers with 20 bytes, and neither the signature nor
/// the wrapping key ever comes back out.
pub fn open_account_code(a: &Args, lang: Lang) -> Result<AccountCode, String> {
    let path = a.wallet_slot.as_deref().ok_or("no slot file was given")?;
    let slot = read_slot(path, lang)?;
    let text = read_signature_text(a)?;
    // ⚠ Wrapped the moment it exists. What comes back out of the decoder is the 64 signature bytes
    //   plus a scheme flag and a public key; the engine clears its own copy, and this is ours.
    let serialized = Zeroizing::new(
        decode_text(&text).ok_or_else(|| msg::WALLET_SIGNATURE_NOT_TEXT.get(lang).to_string())?,
    );
    let opener = opener::opener_from_signature(&serialized).map_err(|why| refusal(&why, lang))?;
    let key = opener.open(&slot).map_err(|why| refusal(&why, lang))?;
    Ok(AccountCode::from_bytes(*key))
}

/// The 62 bytes of a slot, however the person's machine happened to save them.
///
/// Raw bytes are what the account screen hands out. Text is accepted too — a slot that travelled
/// through a mail client, a chat window or an editor arrives base64 or hex — because refusing it
/// would tell a person their file is broken when it is merely written down.
fn read_slot(path: &Path, lang: Lang) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if raw.len() == opener::SLOT_LEN {
        return Ok(raw);
    }
    if let Ok(text) = std::str::from_utf8(&raw) {
        if let Some(decoded) = decode_text(text) {
            if decoded.len() == opener::SLOT_LEN {
                return Ok(decoded);
            }
        }
    }
    // The engine's own reason, with the length this file actually had — "a slot is 62 bytes, got
    // 1024" is the sentence that tells somebody they saved the wrong file.
    Err(refusal(&OpenerRefusal::SlotLength { got: raw.len() }, lang))
}

/// The signature text, from the one road there is.
///
/// ⚠ A FILE AND NOTHING ELSE, for the reason `args.rs` gives about the NMTS key: an argument lands
///   in a shell history and is visible in `ps` to every other user on the machine, and a signature
///   opens the account for as long as its slot exists. `--wallet-signature` is refused by name
///   there, so nothing can arrive here by any other route.
fn read_signature_text(a: &Args) -> Result<Zeroizing<String>, String> {
    let path = a
        .wallet_signature_file
        .as_deref()
        .ok_or("--wallet-slot needs the signature that opens it.")?;
    std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Bytes from text that is either hex or base64, and nothing else.
///
/// ⚠ Which one is DECIDED, not guessed twice: a `0x` prefix, or every character a hex digit over an
///   even length, means hex; anything else is put to the base64 decoder, which has the alphabet.
///   The two alphabets overlap, so a base64 string of only hex characters would be read as hex —
///   at which point it decodes to a length no signature has and is refused by length, with a
///   sentence that says so. Wallets return base64; hex is here because people paste hex.
fn decode_text(text: &str) -> Option<Vec<u8>> {
    let compact: Zeroizing<String> = Zeroizing::new(
        text.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    let said_hex = compact.starts_with("0x") || compact.starts_with("0X");
    let body = if said_hex {
        &compact[2..]
    } else {
        &compact[..]
    };
    if !body.is_empty() && body.len() % 2 == 0 && body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return from_hex(body);
    }
    // `0x` and then something that is not hex is a typo, not base64 — reading it as base64 would
    // answer a different question than the one that was asked.
    if said_hex {
        return None;
    }
    from_base64(&compact)
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Standard base64, the alphabet a Sui wallet answers in, decoded by the ENGINE's decoder.
///
/// ⛔ The engine speaks base64url without padding (NCF-1 §0), so the two symbols that differ are
/// translated and the padding is dropped before handing it over. Translating is the whole change:
/// the alphabet check, the length rule and the refusal all stay in the audited decoder, and this
/// program keeps its promise to add no encoding of its own.
fn from_base64(text: &str) -> Option<Vec<u8>> {
    let body = text.trim_end_matches('=');
    // Padding in the middle is not padding.
    if body.contains('=') {
        return None;
    }
    let urlsafe: Zeroizing<String> = Zeroizing::new(
        body.chars()
            .map(|c| match c {
                '+' => '-',
                '/' => '_',
                other => other,
            })
            .collect::<String>(),
    );
    nmts_crypto::b64::decode(&urlsafe).ok()
}

/// One sentence per reason the engine can refuse.
///
/// ⛔ ONE ARM PER VARIANT, never a catch-all. The answers differ: a multisig wallet cannot be used
/// at all, a slot from a newer build needs a newer program, and a slot that will not open is the
/// wrong wallet or the wrong message. A `_ =>` arm would turn all of them into the same shrug, and
/// the test below fails if two of these ever read alike.
fn refusal(why: &OpenerRefusal, lang: Lang) -> String {
    match why {
        OpenerRefusal::AddressNotCanonical => msg::WALLET_ADDRESS_NOT_CANONICAL.get(lang).into(),
        OpenerRefusal::AccountZero => msg::WALLET_ACCOUNT_ZERO.get(lang).into(),
        OpenerRefusal::AppNotCanonical => msg::WALLET_APP_NOT_CANONICAL.get(lang).into(),
        OpenerRefusal::Empty => msg::WALLET_SIGNATURE_EMPTY.get(lang).into(),
        OpenerRefusal::Multisig => msg::WALLET_MULTISIG.get(lang).into(),
        OpenerRefusal::ZkLogin => msg::WALLET_ZKLOGIN.get(lang).into(),
        OpenerRefusal::Passkey => msg::WALLET_PASSKEY.get(lang).into(),
        OpenerRefusal::UnknownScheme { flag } => msg::WALLET_UNKNOWN_SCHEME
            .get(lang)
            .replace("{flag}", &format!("0x{flag:02x}")),
        OpenerRefusal::WrongLength { expected, got, .. } => msg::WALLET_SIGNATURE_LENGTH
            .get(lang)
            .replace("{expected}", &expected.to_string())
            .replace("{got}", &got.to_string()),
        OpenerRefusal::SlotLength { got } => msg::WALLET_SLOT_LENGTH
            .get(lang)
            .replace("{expected}", &opener::SLOT_LEN.to_string())
            .replace("{got}", &got.to_string()),
        OpenerRefusal::SlotVersion { version } => msg::WALLET_SLOT_VERSION
            .get(lang)
            .replace("{version}", &version.to_string()),
        OpenerRefusal::SlotKind { kind } => msg::WALLET_SLOT_KIND
            .get(lang)
            .replace("{kind}", &format!("0x{kind:02x}")),
        OpenerRefusal::PrfLength { got } => msg::WALLET_PRF_LENGTH
            .get(lang)
            .replace("{expected}", &opener::PASSKEY_PRF_LEN.to_string())
            .replace("{got}", &got.to_string()),
        OpenerRefusal::DoesNotOpen => msg::WALLET_SLOT_DOES_NOT_OPEN.get(lang).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two spellings a wallet or a person hands over, decoded to the same bytes.
    #[test]
    fn base64_and_hex_are_both_read_and_nothing_else_is() {
        // 97 bytes: an Ed25519 serialized signature, flag first.
        let mut serialized = vec![opener::FLAG_ED25519];
        serialized.extend((0..96u32).map(|i| (i % 251) as u8));
        let hex: String = serialized.iter().map(|b| format!("{b:02x}")).collect();
        let b64 = standard_base64(&serialized);
        assert!(
            b64.contains('='),
            "the padded form is the one wallets return"
        );

        assert_eq!(decode_text(&hex).as_deref(), Some(&serialized[..]));
        assert_eq!(decode_text(&b64).as_deref(), Some(&serialized[..]));
        // Uppercase hex, a `0x` prefix, and text that arrived wrapped over lines.
        assert_eq!(
            decode_text(&hex.to_uppercase()).as_deref(),
            Some(&serialized[..])
        );
        assert_eq!(
            decode_text(&format!("0x{hex}")).as_deref(),
            Some(&serialized[..])
        );
        assert_eq!(
            decode_text(&format!("{}\n{}\n", &b64[..40], &b64[40..])).as_deref(),
            Some(&serialized[..])
        );

        // Neither alphabet: refused rather than salvaged.
        for bad in ["0xnothex", "not base64 either!", &hex[1..], "AA=BB"] {
            assert_eq!(decode_text(bad), None, "{bad:?} was decoded");
        }
        // ⚠ Nothing at all is NOT "neither alphabet": it decodes to no bytes, and the engine then
        //   answers with its own reason for an empty signature — which is the sentence a person
        //   whose clipboard was empty needs, rather than one about encodings.
        assert_eq!(decode_text("  \n ").as_deref(), Some(&[][..]));
        assert_eq!(
            opener::opener_from_signature(&[]).err(),
            Some(OpenerRefusal::Empty)
        );
    }

    /// ⛔ EVERY REASON READS DIFFERENTLY, in both languages. The mapping above exists so that a
    ///    person who cannot use their wallet learns which of these things happened; a
    ///    catch-all arm, or one message pasted twice, puts that back to a shrug — and this is the
    ///    only place that would notice.
    #[test]
    fn every_refusal_the_engine_can_give_has_a_sentence_of_its_own() {
        let all = [
            OpenerRefusal::AddressNotCanonical,
            OpenerRefusal::AccountZero,
            OpenerRefusal::AppNotCanonical,
            OpenerRefusal::Empty,
            OpenerRefusal::Multisig,
            OpenerRefusal::ZkLogin,
            OpenerRefusal::Passkey,
            OpenerRefusal::UnknownScheme { flag: 0x04 },
            OpenerRefusal::WrongLength {
                flag: opener::FLAG_ED25519,
                expected: opener::ED25519_SERIALIZED_LEN,
                got: 12,
            },
            OpenerRefusal::SlotLength { got: 12 },
            OpenerRefusal::SlotVersion { version: 0x02 },
            OpenerRefusal::SlotKind { kind: 0x09 },
            OpenerRefusal::PrfLength { got: 31 },
            OpenerRefusal::DoesNotOpen,
        ];
        for lang in [Lang::En, Lang::Ko] {
            let mut seen = std::collections::HashSet::new();
            for why in &all {
                let said = refusal(why, lang);
                assert!(!said.trim().is_empty(), "{why:?} says nothing");
                assert!(
                    !said.contains('{'),
                    "{why:?} left a placeholder unfilled: {said}"
                );
                assert!(seen.insert(said.clone()), "two reasons read alike: {said}");
            }
        }
        // The numbers the engine reported are in the sentence, not swallowed by it.
        let said = refusal(&OpenerRefusal::SlotLength { got: 12 }, Lang::En);
        assert!(said.contains("62") && said.contains("12"), "{said}");
        let said = refusal(&OpenerRefusal::UnknownScheme { flag: 0x04 }, Lang::En);
        assert!(said.contains("0x04"), "{said}");
    }

    /// Padded standard base64, written here so the test does not encode with the decoder it tests.
    fn standard_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

    /// ⛔ THE SIGNATURE IS NOWHERE IN `Args`, which derives `Debug`. A path is all that is carried,
    ///    so there is no field a `{a:?}` could print the secret out of and none to remember to
    ///    redact. This reads the struct's own source rather than a list kept by hand.
    #[test]
    fn the_arguments_carry_a_path_to_the_signature_and_never_the_signature() {
        let source = include_str!("args.rs");
        let (_, from_struct) = source
            .split_once("pub struct Args {")
            .expect("Args is declared in args.rs");
        let (fields, _) = from_struct.split_once("\n}").expect("the struct ends");
        for field in fields.lines().filter(|l| l.trim().starts_with("pub ")) {
            assert!(
                !field.contains("wallet_signature:"),
                "a signature field is back in Args: {field}"
            );
        }
        assert!(
            fields.contains("wallet_signature_file: Option<PathBuf>"),
            "the only road to a signature is a path, and it is not in Args"
        );
    }
}
