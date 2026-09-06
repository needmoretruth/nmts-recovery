//! Everything an account code turns into, printed on request.
//!
//! # Why this is in a recovery tool at all
//! In NMTS an account code is not a password — it is the ROOT. Every key the account has is
//! computed from it: the identity the server knows it by, the key that opens the recovery list,
//! the identity other people share files to, and the wallet that pays for storage. If NMTS is
//! gone, "get my files back" is only half of what a person needs; the other half is "get my
//! wallet back", and nothing else on earth can do that computation for them.
//!
//! So this module walks the same derivation the browser walks and prints the results. It invents
//! nothing: the chain from the code down to each key lives in the engine crate, and the two
//! things that engine does not do — turning a wallet seed into a Sui address, and into the
//! `suiprivkey1…` form a wallet app imports — are done here against fixtures taken from the
//! library the product itself uses (`tests/derive.rs`).
//!
//! # ⛔ Secrets are printed only when asked for twice
//! `--derive` prints the public half: account id, fingerprint, public code, wallet addresses. A
//! person checking "is this the right account?" should not have their wallet's private key land in
//! their terminal scrollback as a side effect. `--secrets` adds the private keys, behind a warning.
//! That is not security theatre — the code is right there in the caller's hand either way — it is
//! about not putting a key on a screen somebody did not ask to have it on.

use bech32::{Bech32, Hrp};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as Blake2Digest};
use ed25519_dalek::SigningKey;
use nmts_crypto::kdf::DerivedKeys;
use nmts_crypto::share;
use sha2::{Digest as ShaDigest, Sha256};

/// Sui's signature-scheme byte for Ed25519. It prefixes the public key before hashing, and the
/// secret key before bech32-encoding, so an address and a key both say which scheme they are.
const ED25519_FLAG: u8 = 0x00;

/// The human-readable part of an exported Sui secret key.
const SECRET_KEY_HRP: &str = "suiprivkey";

/// One wallet the account code derives.
pub struct Wallet {
    pub index: u32,
    /// `0x…` Sui address.
    pub address: String,
    /// `suiprivkey1…`, present only when the caller asked for secrets.
    pub secret: Option<String>,
}

/// One AI account the code derives (NCF-3 §1.5).
pub struct AiAccount {
    /// Where it sits in the tree: `2` is the second AI account, `2.3` the third one under it.
    pub path: String,
    /// Its account code, in the display form a person types back in.
    pub code: String,
}

/// How many AI accounts an account may have, at each level (product rule of 2026-09-06: three, and three under each).
pub const AI_ACCOUNTS_PER_LEVEL: u32 = 3;

/// Every AI-account code under `keys`, `depth` levels down (NCF-3 §1.5).
///
/// ⛔ Why a recovery tool computes these. The codes are EXPANDED from the account above them, not
/// drawn from randomness, so the top code is the only thing that has to survive — and this walk is
/// what turns it back into the whole tree with no network and no NMTS. Each level costs one full
/// Argon2id pass per account, because a child's own root comes from its own code like anybody's.
pub fn ai_accounts(keys: &DerivedKeys, depth: u32) -> Result<Vec<AiAccount>, String> {
    let mut out = Vec::new();
    walk_ai(keys, "", depth, &mut out)?;
    Ok(out)
}

fn walk_ai(
    keys: &DerivedKeys,
    prefix: &str,
    remaining: u32,
    out: &mut Vec<AiAccount>,
) -> Result<(), String> {
    if remaining == 0 {
        return Ok(());
    }
    for n in 1..=AI_ACCOUNTS_PER_LEVEL {
        let code = keys.ai_account_code_for(n).map_err(|e| format!("{e}"))?;
        let path = if prefix.is_empty() {
            n.to_string()
        } else {
            format!("{prefix}.{n}")
        };
        out.push(AiAccount {
            path: path.clone(),
            code: code.display(),
        });
        if remaining > 1 {
            let child = nmts_crypto::kdf::derive(&code).map_err(|e| format!("{e}"))?;
            walk_ai(&child, &path, remaining - 1, out)?;
        }
    }
    Ok(())
}

/// Everything derived, ready to print.
pub struct Derived {
    /// base64url of 16 bytes — what the server knows this account by. Public.
    pub account_id: String,
    /// Short, human-checkable form of the account id. Public.
    pub fingerprint: String,
    /// The address other people send shared files to. Public.
    pub public_code: String,
    pub wallets: Vec<Wallet>,
}

/// Walk the derivation and collect what it produced.
pub fn from_keys(keys: &DerivedKeys, wallet_count: u32, with_secrets: bool) -> Derived {
    let account_id = keys.account_id_b64();
    let wallets = (0..wallet_count)
        .map(|index| {
            let seed = keys.wallet_seed_for(index);
            Wallet {
                index,
                address: sui_address(&seed),
                secret: with_secrets.then(|| sui_secret_key(&seed)),
            }
        })
        .collect();
    Derived {
        fingerprint: fingerprint(&account_id),
        public_code: share::address_for(&keys.share_sig_seed).display(),
        account_id,
        wallets,
    }
}

/// The short form of an account id a person can read out loud to check two devices match.
///
/// ⛔ SHA-256 over the base64url STRING, not over the 16 raw bytes. That is what the browser
/// hashes, and a fingerprint that disagreed with the one printed on a recovery kit would send
/// somebody looking for a second account they do not have.
pub fn fingerprint(account_id: &str) -> String {
    let mut h = Sha256::new();
    ShaDigest::update(&mut h, account_id.as_bytes());
    let digest = h.finalize();
    let hex: String = digest[..8].iter().map(|b| format!("{b:02X}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// A wallet seed's Sui address: `0x` + hex of BLAKE2b-256 over the scheme flag and the public key.
pub fn sui_address(seed: &[u8; 32]) -> String {
    let verifying = SigningKey::from_bytes(seed).verifying_key();
    let mut h: Blake2b<U32> = Blake2b::new();
    Blake2Digest::update(&mut h, [ED25519_FLAG]);
    Blake2Digest::update(&mut h, verifying.as_bytes());
    let out = h.finalize();
    format!(
        "0x{}",
        out.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// A wallet seed in the form a Sui wallet imports: bech32 over the flag byte and the 32-byte seed.
pub fn sui_secret_key(seed: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(33);
    data.push(ED25519_FLAG);
    data.extend_from_slice(seed);
    let hrp = Hrp::parse(SECRET_KEY_HRP).expect("a constant, valid hrp");
    bech32::encode::<Bech32>(hrp, &data).expect("33 bytes always encode")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ Fixtures taken from the library the PRODUCT uses to make these values. If this file and
    ///    the browser ever disagree, a person following this program would fund the wrong address
    ///    or import a key that is not theirs — and nothing else in the program would notice.
    const CASES: [(&str, &str, &str); 3] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0x7a1378aafadef8ce743b72e8b248295c8f61c102c94040161146ea4d51a182b6",
            // Not a secret: a conformance vector built from a fixed seed, holding nothing.
            // nmts-secret-scan: allow
            "suiprivkey1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq509duq",
        ),
        (
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "0x7573c697fa68450f04fa0dee2d39dcdc8a5ccf5db547f3e47638a6f8eeeec110",
            // Not a secret: a conformance vector built from a fixed seed, holding nothing.
            // nmts-secret-scan: allow
            "suiprivkey1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqa4ffsr",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0x20a33b9a86e89aa22b4c6f7e4c53e8a37444c92a6f18a28bdbd7a37ba85e0646",
            // Not a secret: a conformance vector built from a fixed seed, holding nothing.
            // nmts-secret-scan: allow
            "suiprivkey1qrllllllllllllllllllllllllllllllllllllllllllllllllll7q9367r",
        ),
    ];

    fn seed_of(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    #[test]
    fn a_wallet_seed_gives_the_address_the_product_gives() {
        for (hex, address, _) in CASES {
            assert_eq!(sui_address(&seed_of(hex)), address, "seed {hex}");
        }
    }

    #[test]
    fn a_wallet_seed_gives_the_secret_key_a_wallet_app_imports() {
        for (hex, _, secret) in CASES {
            assert_eq!(sui_secret_key(&seed_of(hex)), secret, "seed {hex}");
        }
    }

    /// The fingerprint is what a recovery kit prints, so it has to be the same string.
    #[test]
    fn the_fingerprint_is_grouped_uppercase_hex_of_the_id_string() {
        let f = fingerprint("AAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(f.len(), 19, "four groups of four with three dashes: {f}");
        assert!(f.chars().all(|c| c.is_ascii_hexdigit() || c == '-'), "{f}");
        assert!(f.chars().filter(|c| *c == '-').count() == 3, "{f}");
        assert_eq!(f, f.to_uppercase(), "{f}");
        // Different ids, different fingerprints — the whole point of printing one.
        assert_ne!(
            fingerprint("AAAAAAAAAAAAAAAAAAAAAA"),
            fingerprint("BAAAAAAAAAAAAAAAAAAAAA")
        );
    }

    /// ⛔ Secrets appear only when asked for. A default that printed private keys would put them in
    ///    the scrollback of everyone who ran this to check an account id.
    #[test]
    fn private_keys_are_absent_unless_asked_for() {
        let code = nmts_crypto::codes::AccountCode::generate();
        let keys = nmts_crypto::kdf::derive(&code).expect("derive");
        let quiet = from_keys(&keys, 2, false);
        assert!(quiet.wallets.iter().all(|w| w.secret.is_none()));
        let loud = from_keys(&keys, 2, true);
        assert!(loud.wallets.iter().all(|w| w.secret.is_some()));
        // The public half is identical either way — asking for secrets must not change an address.
        assert_eq!(
            quiet
                .wallets
                .iter()
                .map(|w| w.address.clone())
                .collect::<Vec<_>>(),
            loud.wallets
                .iter()
                .map(|w| w.address.clone())
                .collect::<Vec<_>>(),
        );
    }

    /// The tree is three wide, and `--depth 2` is three plus nine. Paths say where each one sits.
    #[test]
    fn the_ai_account_tree_is_three_wide_and_nests() {
        let keys = nmts_crypto::kdf::derive(&nmts_crypto::codes::AccountCode::generate()).unwrap();
        let one = ai_accounts(&keys, 1).expect("depth 1");
        assert_eq!(one.len(), 3);
        assert_eq!(
            one.iter().map(|a| a.path.as_str()).collect::<Vec<_>>(),
            ["1", "2", "3"]
        );
        let two = ai_accounts(&keys, 2).expect("depth 2");
        assert_eq!(two.len(), 12, "three, and three under each");
        assert_eq!(two[1].path, "1.1");
        // Every code is a real, parseable account code, and no two of them are the same.
        let mut seen = std::collections::BTreeSet::new();
        for a in &two {
            nmts_crypto::codes::AccountCode::parse(&a.code).expect("an ordinary account code");
            assert!(seen.insert(a.code.clone()), "duplicate code at {}", a.path);
        }
        // Depth 0 is nothing, not an error — a caller asking for no levels gets no codes.
        assert!(ai_accounts(&keys, 0).expect("depth 0").is_empty());
    }

    /// Two accounts share nothing. A derivation that lost the code somewhere would show up here as
    /// two different codes producing one address.
    #[test]
    fn two_account_codes_derive_to_different_everything() {
        let a = nmts_crypto::kdf::derive(&nmts_crypto::codes::AccountCode::generate()).expect("a");
        let b = nmts_crypto::kdf::derive(&nmts_crypto::codes::AccountCode::generate()).expect("b");
        let (da, db) = (from_keys(&a, 1, false), from_keys(&b, 1, false));
        assert_ne!(da.account_id, db.account_id);
        assert_ne!(da.public_code, db.public_code);
        assert_ne!(da.wallets[0].address, db.wallets[0].address);
    }
}
