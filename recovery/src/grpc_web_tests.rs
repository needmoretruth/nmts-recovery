//! The gRPC-web wire, held to bytes the SDK the product itself uses produced.
//!
//! ⛔ THE FIXTURES ARE NOT WRITTEN BY HAND. Each hex string below is what `@mysten/sui` 2.37.0's
//! generated message types (`GrpcTypes.ListOwnedObjectsRequest` / `…Response`, `toBinary`) wrote
//! for the values beside it, on 2026-10-21. A hand-written fixture would only prove this file
//! agrees with itself; these prove it agrees with the encoder every other NMTS program runs.

use super::*;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("fixture is hex"))
        .collect()
}

const OWNER: &str = "0xabababababababababababababababababababababababababababababababab";

/// `{ owner: OWNER, pageSize: 50, readMask: { paths: ["object_type", "contents"] } }`
const REQ_FIRST: &str = "0a42307861626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162103222170a0b6f626a6563745f747970650a08636f6e74656e7473";

/// The same, with `pageToken: [1, 2, 3]`.
const REQ_WITH_TOKEN: &str = "0a4230786162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616210321a0301020322170a0b6f626a6563745f747970650a08636f6e74656e7473";

/// Two objects — a Blob whose 131 content bytes are 0, 1, 2, … and which also carries fields this
/// tool never asks for (id, version, rebate, public-transfer flag), then a coin with a balance —
/// and `nextPageToken: [9, 9]`.
const RESP: &str = "0afd011242307831313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131184d32123078666463383a3a626c6f623a3a426c6f623801429a010a123078666463383a3a626c6f623a3a426c6f62128301000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818258c0c4070a671242307832323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232321e3078323a3a636f696e3a3a436f696e3c3078323a3a7375693a3a5355493ea8060512020909";

#[test]
fn the_request_is_byte_for_byte_what_the_sdk_writes() {
    assert_eq!(list_owned_objects_request(OWNER, 50, None), hex(REQ_FIRST));
    assert_eq!(
        list_owned_objects_request(OWNER, 50, Some(&[1, 2, 3])),
        hex(REQ_WITH_TOKEN)
    );
}

#[test]
fn a_page_reads_its_objects_and_skips_every_field_it_did_not_ask_for() {
    let page = owned_page(&hex(RESP)).expect("the SDK's own bytes parse");
    assert_eq!(page.objects.len(), 2);
    assert_eq!(
        page.objects[0].object_type.as_deref(),
        Some("0xfdc8::blob::Blob")
    );
    let contents: Vec<u8> = (0u8..131).collect();
    assert_eq!(page.objects[0].contents.as_deref(), Some(&contents[..]));
    assert_eq!(
        page.objects[1].object_type.as_deref(),
        Some("0x2::coin::Coin<0x2::sui::SUI>")
    );
    assert_eq!(page.objects[1].contents, None);
    assert_eq!(page.next_page_token.as_deref(), Some(&[9u8, 9][..]));
}

#[test]
fn an_empty_message_is_an_empty_last_page() {
    assert_eq!(owned_page(&[]).expect("empty parses"), OwnedPage::default());
}

/// ⛔ The byte order and the offset are the whole test. A wrong offset or a big-endian reading
/// produces a perfectly well-formed blob id that does not exist, and the failure it causes is
/// "your files are not there". 36 = the object's UID (32) + `registered_epoch: u32` (4).
#[test]
fn the_blob_id_is_bytes_36_to_68_of_a_blobs_contents() {
    let contents: Vec<u8> = (0u8..131).collect();
    assert_eq!(
        blob_id_from_contents(&contents).as_deref(),
        Some("JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkM")
    );
    assert_eq!(
        blob_id_from_contents(&contents[..67]),
        None,
        "too short to be a Blob"
    );
}

#[test]
fn a_frame_is_a_flag_a_big_endian_length_and_the_message() {
    assert_eq!(frame(&[7, 8, 9]), vec![0, 0, 0, 0, 3, 7, 8, 9]);
}

fn trailer(text: &str) -> Vec<u8> {
    let mut out = vec![0x80];
    out.extend_from_slice(&(text.len() as u32).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out
}

#[test]
fn an_answer_is_its_message_when_the_trailer_says_ok() {
    let mut body = frame(&[1, 2, 3]);
    body.extend(trailer("grpc-status:0\r\ngrpc-message:\r\n"));
    assert_eq!(split_answer(&body, None), Ok(vec![1, 2, 3]));
    // An OK answer with no message frame is an empty message — a last page with nothing on it.
    assert_eq!(
        split_answer(&trailer("grpc-status: 0\r\n"), None),
        Ok(Vec::new())
    );
}

#[test]
fn a_status_the_node_sends_is_its_answer_and_is_said_as_one() {
    let body = trailer("grpc-status:5\r\ngrpc-message:not found\r\n");
    assert_eq!(
        split_answer(&body, None),
        Err("answered gRPC status 5 (not found)".to_string())
    );
    // A trailers-only answer carries the status in the HTTP headers and nothing in the body.
    assert_eq!(
        split_answer(&[], Some("14")),
        Err("answered gRPC status 14".to_string())
    );
}

/// ⛔ An answer that never says how it ended is one the node did not finish. Reading "this
/// address owns nothing" off it would be a guess, so it is refused.
#[test]
fn an_answer_without_a_status_is_refused() {
    assert!(split_answer(&frame(&[1]), None).is_err());
    // A frame cut short is refused rather than read as a shorter message.
    let mut cut = frame(&[1, 2, 3, 4]);
    cut.truncate(6);
    assert!(split_answer(&cut, Some("0")).is_err());
}

#[test]
fn a_field_that_runs_past_the_end_is_refused_rather_than_read_short() {
    // Field 1, length-delimited, claims 100 bytes and has 2.
    assert!(owned_page(&[0x0a, 100, 1, 2]).is_err());
    // A varint that never ends.
    assert!(owned_page(&[0x10, 0xff, 0xff]).is_err());
}
