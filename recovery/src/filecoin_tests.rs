//! Tests for [`crate::filecoin`]: the hand-written contract call, and the order in which a Heavy
//! part's addresses are tried. A fake transport stands in for the network, so every case here runs
//! offline; the one live check is `#[ignore]`d and gated on an environment variable.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;

use super::*;

const CID: &str = "bafkzcibd5adqy3m4o5lm6dnp2wzflzkkmcesjj2ad3r6l3llemvbei4fkusi5zy5";

/// The registry's answer for Calibration provider 2, as a live node returned it on 2026-09-24
/// (the call this module encodes, sent by an independent script): `bytes[]` holding one address.
const LIVE_ANSWER_PROVIDER_2: &str = concat!(
    "0000000000000000000000000000000000000000000000000000000000000020",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000020",
    "0000000000000000000000000000000000000000000000000000000000000019",
    "68747470733a2f2f63616c6962322e657a7064707a2e6e657400000000000000",
);

/// The same registry's answer for a company that published no address (provider 3, same day).
const LIVE_ANSWER_EMPTY: &str = concat!(
    "0000000000000000000000000000000000000000000000000000000000000020",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000020",
    "0000000000000000000000000000000000000000000000000000000000000000",
);

/// ⛔ A FIXED ANSWER, not a round trip: the calldata for provider 2, word by word, as the live
///    registry accepted it (the answer above is what it said back).
#[test]
fn the_registry_call_is_encoded_byte_for_byte() {
    let want = concat!(
        "a6433240",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000060",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000020",
        "000000000000000000000000000000000000000000000000000000000000000a",
        "7365727669636555524c00000000000000000000000000000000000000000000",
    );
    assert_eq!(hex(&encode_service_url_call("2").expect("encode")), want);
}

#[test]
fn the_registry_answer_is_decoded_and_a_bad_one_is_an_error_not_a_panic() {
    let raw = unhex(LIVE_ANSWER_PROVIDER_2).expect("hex");
    assert_eq!(
        String::from_utf8(first_of_bytes_array(&raw).expect("decode")).expect("utf8"),
        "https://calib2.ezpdpz.net"
    );
    assert_eq!(
        first_of_bytes_array(&unhex(LIVE_ANSWER_EMPTY).unwrap()).unwrap(),
        b""
    );
    // Every truncation that cuts into the address, and offsets pointing past the end, are refused.
    // (The address ends at byte 4 × 32 + 25; what follows it is padding.)
    for cut in 0..4 * 32 + 25 {
        assert!(first_of_bytes_array(&raw[..cut]).is_err(), "cut at {cut}");
    }
    let mut wild = raw.clone();
    wild[31] = 0xff; // the array's offset now points far past the end
    assert!(first_of_bytes_array(&wild).is_err());
    wild[0] = 0x01; // and a number no usize can hold
    assert!(first_of_bytes_array(&wild).is_err());
}

#[test]
fn a_company_number_becomes_a_uint256_word() {
    assert_eq!(decimal_word("0").unwrap(), [0u8; 32]);
    let mut w = [0u8; 32];
    w[30] = 1;
    assert_eq!(decimal_word("256").unwrap(), w);
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    assert_eq!(decimal_word(max).unwrap(), [0xffu8; 32]);
    let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    assert!(decimal_word(over).is_err());
    assert!(decimal_word("1a").is_err());
}

/// A pretend network: each URL answers with bytes or a failure, and every request is recorded.
#[derive(Default)]
struct Fake {
    pieces: HashMap<String, Result<Vec<u8>, String>>,
    rpc: HashMap<String, String>,
    asked: RefCell<Vec<String>>,
}

impl Transport for Fake {
    fn get(
        &self,
        url: &str,
        _cap: u64,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<(), String>,
    ) -> Fetched {
        self.asked.borrow_mut().push(url.to_string());
        match self.pieces.get(url) {
            Some(Ok(bytes)) => Fetched::Consumed(consume(&mut bytes.as_slice())),
            Some(Err(why)) => Fetched::Failed(why.clone()),
            None => Fetched::Failed("answered 404".into()),
        }
    }

    fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
        let doc: Value = serde_json::from_str(body).expect("json");
        let data = doc["params"][0]["data"].as_str().expect("data").to_string();
        self.asked
            .borrow_mut()
            .push(format!("{url} {}", &data[..74]));
        // Keyed by the provider word's last byte — enough to tell 7 from 11 in these tests.
        let provider = u8::from_str_radix(&data[72..74], 16).expect("provider");
        self.rpc
            .get(&provider.to_string())
            .cloned()
            .ok_or_else(|| "answered 500".to_string())
    }
}

fn copy(provider: &str, url: &str) -> FilecoinCopy {
    FilecoinCopy {
        provider_id: provider.into(),
        data_set_id: "1".into(),
        piece_id: "0".into(),
        retrieval_url: url.into(),
    }
}

fn piece() -> Piece {
    Piece {
        cid: CID.into(),
        chain: "calibration".into(),
        copies: vec![
            copy("7", &format!("https://a.example/piece/{CID}")),
            copy("11", &format!("https://b.example/piece/{CID}")),
        ],
    }
}

/// Run a fetch and return what was consumed.
fn fetch(t: &Fake) -> (Result<(), SourceError>, Vec<u8>) {
    let mut got = Vec::new();
    let r = fetch_piece(t, &piece(), 1 << 20, &mut |r| {
        r.read_to_end(&mut got)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    (r, got)
}

fn registry_answer(url: &str) -> String {
    let mut body = url.as_bytes().to_vec();
    body.resize(body.len().div_ceil(32) * 32, 0);
    let word = |n: usize| format!("{n:064x}");
    let result = format!(
        "0x{}{}{}{}{}",
        word(32),
        word(1),
        word(32),
        word(url.len()),
        hex(&body)
    );
    serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
}

#[test]
fn a_copy_that_fails_is_followed_by_the_next_one() {
    let mut t = Fake::default();
    t.pieces.insert(
        format!("https://b.example/piece/{CID}"),
        Ok(b"stream".to_vec()),
    );
    let (r, got) = fetch(&t);
    assert!(r.is_ok());
    assert_eq!(got, b"stream");
    assert_eq!(
        *t.asked.borrow(),
        [
            format!("https://a.example/piece/{CID}"),
            format!("https://b.example/piece/{CID}")
        ],
        "the recorded addresses, in the list's order, and no registry question"
    );
}

#[test]
fn when_every_recorded_address_fails_the_registry_names_the_current_one() {
    let mut t = Fake::default();
    t.rpc
        .insert("11".into(), registry_answer("https://moved.example/"));
    t.pieces.insert(
        format!("https://moved.example/piece/{CID}"),
        Ok(b"moved".to_vec()),
    );
    let (r, got) = fetch(&t);
    assert!(r.is_ok());
    assert_eq!(got, b"moved");
    let asked = t.asked.borrow();
    assert_eq!(asked.len(), 5, "{asked:?}");
    assert!(asked[2].starts_with("https://api.calibration.node.glif.io/rpc/v1 0xa6433240"));
    assert_eq!(asked[4], format!("https://moved.example/piece/{CID}"));
}

#[test]
fn when_nothing_answers_the_error_counts_the_companies_and_names_every_attempt() {
    let mut t = Fake::default();
    // The registry names the address that already failed: it is not asked twice.
    t.rpc
        .insert("7".into(), registry_answer("https://a.example"));
    // And a company that published a plain-http address is not contacted at all.
    t.rpc
        .insert("11".into(), registry_answer("http://b.example"));
    let (r, _) = fetch(&t);
    match r {
        Err(SourceError::NoCopy { companies, tried }) => {
            assert_eq!(companies, 2);
            assert!(tried.contains("https://a.example/piece/"), "{tried}");
            assert!(tried.contains("http://b.example/piece/"), "{tried}");
            assert!(tried.contains("is not an https address"), "{tried}");
        }
        _ => panic!("expected the all-copies failure"),
    }
    assert_eq!(t.asked.borrow().len(), 4, "{:?}", t.asked.borrow());
}

/// ⛔ Bytes that arrived and were rejected end the attempt: the next company is NOT asked, because
///    the caller may already have written part of the file.
#[test]
fn a_rejection_by_the_caller_is_final() {
    let mut t = Fake::default();
    t.pieces
        .insert(format!("https://a.example/piece/{CID}"), Ok(b"x".to_vec()));
    t.pieces
        .insert(format!("https://b.example/piece/{CID}"), Ok(b"y".to_vec()));
    let r = fetch_piece(&t, &piece(), 16, &mut |_| Err("not NCF-3".into()));
    assert!(matches!(r, Err(SourceError::Consumer(_))));
    assert_eq!(t.asked.borrow().len(), 1);
}

/// The live registry, read once. `RECOVERY_LIVE_FILECOIN=1 cargo test filecoin -- --ignored`.
#[test]
#[ignore = "reaches a public Filecoin Calibration node; set RECOVERY_LIVE_FILECOIN=1"]
fn a_live_registry_names_an_https_address() {
    if std::env::var("RECOVERY_LIVE_FILECOIN").ok().as_deref() != Some("1") {
        eprintln!("RECOVERY_LIVE_FILECOIN is not 1 — not touching the network.");
        return;
    }
    let url = service_url(&Web::new(), &CHAINS[0], "2").expect("provider 2 on Calibration");
    assert!(url.starts_with("https://"), "{url}");
}
