//! The one Sui question `--find` asks, spoken in gRPC-web: "which objects does this address own?"
//!
//! # Why this file exists (2026-10-21)
//! Sui removed JSON-RPC from its node software in October 2026, and the JSON question this tool
//! used to ask (`suix_getOwnedObjects`) went with it. Its replacement is the node's gRPC service,
//! `sui.rpc.v2.StateService/ListOwnedObjects`. A browser reaches it as gRPC-web over plain HTTPS,
//! and so does this tool: one POST, the same blocking HTTP client the blob fetches already use.
//!
//! # Why by hand, and why it is safe to read
//! A protobuf library and a gRPC stack would be thousands of lines to audit for one request with
//! four fields and one response with two. The wire format is small and fixed: a field is a number
//! and a type packed into one varint, followed by a varint or by a length and that many bytes.
//! What this file writes is exactly the four request fields below; what it reads is exactly the
//! response fields it needs, skipping every other field by its declared length — the forward
//! compatibility protobuf promises, and the reason a newer node does not break an older build.
//!
//! The field numbers are Sui's published `.proto` (`sui/rpc/v2/state_service.proto`,
//! `object.proto`, `bcs.proto`, `google/protobuf/field_mask.proto`), cross-checked against the
//! code `@mysten/sui` 2.37.0 generates from them.
//!
//! # What comes back, and why only two fields are asked for
//! `object_type` (to keep only Walrus blobs) and `contents` (the object's Move struct as BCS). A
//! `walrus::blob::Blob` begins `id: UID (32 bytes) · registered_epoch: u32 (4) · blob_id: u256 (32)`,
//! so the blob id is bytes 36..68 of the contents, already in the little-endian order Walrus names
//! a blob by. Measured on Sui mainnet 2026-10-21: 1,920 blob objects of one address, every one of
//! them equal to the decimal `blob_id` the node's JSON rendering gives.

/// The path of the one method this tool calls, appended to a node's base URL.
pub const LIST_OWNED_OBJECTS_PATH: &str = "/sui.rpc.v2.StateService/ListOwnedObjects";

/// The content type of a binary gRPC-web request and answer.
pub const CONTENT_TYPE: &str = "application/grpc-web+proto";

/// Protobuf wire types this file meets.
const VARINT: u8 = 0;
const FIXED64: u8 = 1;
const LEN: u8 = 2;
const FIXED32: u8 = 5;

/// One object of a page: its Move type and its contents, both as the node gave them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OwnedObject {
    pub object_type: Option<String>,
    pub contents: Option<Vec<u8>>,
}

/// One page of `ListOwnedObjects`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OwnedPage {
    pub objects: Vec<OwnedObject>,
    /// `None` at the end of the list.
    pub next_page_token: Option<Vec<u8>>,
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn put_key(out: &mut Vec<u8>, field: u32, wire_type: u8) {
    put_varint(out, (u64::from(field) << 3) | u64::from(wire_type));
}

fn put_bytes(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    put_key(out, field, LEN);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// The request: `owner = 1`, `page_size = 2`, `page_token = 3`, `read_mask = 4`
/// (a `FieldMask` whose `paths = 1` name the two fields above).
pub fn list_owned_objects_request(
    owner: &str,
    page_size: u32,
    page_token: Option<&[u8]>,
) -> Vec<u8> {
    let mut mask = Vec::new();
    put_bytes(&mut mask, 1, b"object_type");
    put_bytes(&mut mask, 1, b"contents");

    let mut out = Vec::new();
    put_bytes(&mut out, 1, owner.as_bytes());
    put_key(&mut out, 2, VARINT);
    put_varint(&mut out, u64::from(page_size));
    if let Some(token) = page_token {
        put_bytes(&mut out, 3, token);
    }
    put_bytes(&mut out, 4, &mask);
    out
}

/// One gRPC-web frame: a flag byte (0 for a message), a big-endian length, the message.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + message.len());
    out.push(0x00);
    // A request is a few hundred bytes; a length that does not fit 32 bits is not one this tool makes.
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// Reads protobuf fields one at a time, refusing anything that runs past the end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self
                .bytes
                .get(self.at)
                .ok_or("a number ran past the end of the answer")?;
            self.at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("a number in the answer is longer than ten bytes".to_string())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(len)
            .ok_or("a length in the answer overflows")?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or("a field ran past the end of the answer")?;
        self.at = end;
        Ok(slice)
    }

    /// The next field: its number, its wire type, and — for a length-delimited one — its bytes.
    /// Fields of any other type are consumed and handed back with no bytes.
    fn field(&mut self) -> Result<(u64, u8, &'a [u8]), String> {
        let key = self.varint()?;
        let number = key >> 3;
        let wire_type = (key & 0x7) as u8;
        match wire_type {
            VARINT => {
                self.varint()?;
                Ok((number, wire_type, &[]))
            }
            FIXED64 => {
                self.take(8)?;
                Ok((number, wire_type, &[]))
            }
            LEN => {
                let len = usize::try_from(self.varint()?)
                    .map_err(|_| "a length in the answer is too large")?;
                Ok((number, wire_type, self.take(len)?))
            }
            FIXED32 => {
                self.take(4)?;
                Ok((number, wire_type, &[]))
            }
            other => Err(format!(
                "the answer uses a protobuf wire type this build does not read ({other})"
            )),
        }
    }
}

/// `Bcs { name = 1, value = 2 }` → the value.
fn bcs_value(bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut r = Reader::new(bytes);
    let mut value = None;
    while !r.done() {
        let (number, wire_type, body) = r.field()?;
        if number == 2 && wire_type == LEN {
            value = Some(body.to_vec());
        }
    }
    Ok(value)
}

/// `Object { object_type = 6, contents = 8, … }` → the two fields this tool reads.
fn owned_object(bytes: &[u8]) -> Result<OwnedObject, String> {
    let mut r = Reader::new(bytes);
    let mut object = OwnedObject::default();
    while !r.done() {
        let (number, wire_type, body) = r.field()?;
        match (number, wire_type) {
            (6, LEN) => {
                let text = std::str::from_utf8(body)
                    .map_err(|_| "an object type in the answer is not text")?;
                object.object_type = Some(text.to_string());
            }
            (8, LEN) => object.contents = bcs_value(body)?,
            _ => {}
        }
    }
    Ok(object)
}

/// `ListOwnedObjectsResponse { objects = 1 (repeated), next_page_token = 2 }`.
pub fn owned_page(message: &[u8]) -> Result<OwnedPage, String> {
    let mut r = Reader::new(message);
    let mut page = OwnedPage::default();
    while !r.done() {
        let (number, wire_type, body) = r.field()?;
        match (number, wire_type) {
            (1, LEN) => page.objects.push(owned_object(body)?),
            (2, LEN) => page.next_page_token = Some(body.to_vec()),
            _ => {}
        }
    }
    Ok(page)
}

/// A gRPC-web answer body, split into its one message and the status its trailer carries.
///
/// The body is a run of frames — `0x00` for a message, `0x80` for the trailer, whose payload is
/// header lines (`grpc-status:0`). `header_status` is the `grpc-status` HTTP header, which a node
/// sends instead of a trailer frame when it answers with an error and no message.
///
/// ⛔ A MISSING STATUS IS NOT SUCCESS. An answer that ends without saying how it ended is one the
///    node did not finish, and "this address owns nothing" read off it would be a guess.
pub fn split_answer(body: &[u8], header_status: Option<&str>) -> Result<Vec<u8>, String> {
    let mut at = 0usize;
    let mut message: Option<Vec<u8>> = None;
    let mut status: Option<String> = header_status.map(str::to_string);
    let mut detail = String::new();
    while at < body.len() {
        let head = body
            .get(at..at + 5)
            .ok_or("the answer ends inside a frame header")?;
        let flag = head[0];
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        let payload = body
            .get(at + 5..at + 5 + len)
            .ok_or("the answer ends inside a frame")?;
        at += 5 + len;
        if flag & 0x80 != 0 {
            let text = String::from_utf8_lossy(payload);
            for line in text.split("\r\n") {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                match name.trim().to_ascii_lowercase().as_str() {
                    "grpc-status" => status = Some(value.trim().to_string()),
                    "grpc-message" => detail = value.trim().to_string(),
                    _ => {}
                }
            }
        } else if message.is_none() {
            message = Some(payload.to_vec());
        }
    }
    match status.as_deref() {
        Some("0") => Ok(message.unwrap_or_default()),
        Some(code) => Err(format!(
            "answered gRPC status {code}{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(" ({detail})")
            }
        )),
        None => Err("answered without saying how the answer ended".to_string()),
    }
}

/// The Walrus blob id inside a `blob::Blob`'s BCS contents: bytes 36..68, as Walrus writes ids
/// (unpadded base64url of those little-endian bytes). `None` when the contents are too short to be
/// a Blob — a shape this build should refuse rather than guess at.
pub fn blob_id_from_contents(contents: &[u8]) -> Option<String> {
    contents.get(36..68).map(nmts_crypto::b64::encode)
}

#[cfg(test)]
#[path = "grpc_web_tests.rs"]
mod tests;
