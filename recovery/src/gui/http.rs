//! Just enough HTTP/1.1 to talk to one page on this machine.
//!
//! # Why this is written out rather than imported
//! A recovery tool's dependency list is something a person should be able to finish reading before
//! they type an account code into it. A general HTTP server crate is tens of thousands of lines
//! solving problems this program does not have: no virtual hosts, no TLS, no routing, no
//! keep-alive, no compression, no uploads to disk, no concurrency beyond one browser tab. What is
//! left is a request line, a handful of headers, and a body with a stated length — and that fits
//! in one file a reader can check.
//!
//! # ⛔ Everything here is bounded before it is read
//! A malformed or hostile request must cost an error, never memory. The head is capped, the header
//! count is capped, the body is capped and read to an exact stated length, and a socket that goes
//! quiet mid-request times out. None of this is the security boundary — that is the token and the
//! `Host` check in `mod.rs` — but a parser that can be made to allocate without limit turns a
//! local convenience into a way to knock the machine over during a rescue.

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;

/// The request line plus all headers. Generous for the shape we serve, small enough that a stuck
/// or hostile client cannot grow it.
const MAX_HEAD: usize = 16 * 1024;

/// How many header lines are read before the request is refused.
const MAX_HEADERS: usize = 64;

/// The largest body accepted on the ONE route that carries a document. A recovery list for a very
/// large account is a few megabytes of base64; this leaves room for an order of magnitude more and
/// stops well short of a number that would matter on the kind of machine somebody rescues a drive
/// onto.
pub const MAX_BODY: usize = 32 * 1024 * 1024;

/// The largest body accepted on every other route.
///
/// ⛔ THE NUMBER IS NOT "WHAT COULD A LEGITIMATE REQUEST CARRY" (2026-08-20). Every other route
/// takes a short JSON object or nothing, and the checks that decide whether the caller may speak at
/// all live in `mod.rs`. So the question this constant answers is what somebody who is *about to be
/// refused* can make this program hold. 8 KiB is roomier than any of those routes needs and
/// disappears against `MAX_CONNECTIONS`.
const MAX_BODY_OTHER: usize = 8 * 1024;

/// The one route whose body is a document rather than a short instruction.
const DOCUMENT_PATH: &str = "/api/map";

/// Everything before the body: what was asked for, and by whom.
///
/// ⛔ IT IS A SEPARATE TYPE SO THE BODY CAN BE REFUSED WITHOUT BEING READ (2026-08-20). The head
/// carries every value the `Host` check and the token check need. Reading it first means a caller
/// who is about to be told 403 never gets to decide how many bytes this program waits for or holds.
pub struct Head {
    pub method: String,
    /// Path with the query string removed.
    pub path: String,
    /// Everything after the first `?`, still percent-encoded.
    pub query: String,
    pub host: Option<String>,
    pub origin: Option<String>,
    /// The value of the token header, if the client sent one.
    pub token_header: Option<String>,
    /// What the caller says the body's length is. A claim, not a fact.
    content_length: usize,
}

/// One request, already bounded: a head that passed its checks, and the body that followed.
pub struct Request {
    pub head: Head,
    pub body: Vec<u8>,
}

impl Head {
    /// One query parameter, percent-decoded. Absent and empty are not distinguished — neither is
    /// a usable token, and treating them alike removes a branch that could only ever be wrong.
    pub fn query_param(&self, name: &str) -> Option<String> {
        for pair in self.query.split('&') {
            let (k, v) = match pair.split_once('=') {
                Some(kv) => kv,
                None => (pair, ""),
            };
            if k == name && !v.is_empty() {
                return Some(percent_decode(v));
            }
        }
        None
    }
}

/// Read one request's head from `stream`, and hand back the reader positioned at its body.
///
/// ⛔ The body is NOT read here. See [`Head`].
pub fn read_head(stream: &TcpStream) -> Result<(Head, BufReader<TcpStream>), String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);

    let mut head_used = 0usize;
    let request_line = read_line(&mut reader, &mut head_used)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() {
        return Err("the request line is not a request line".to_string());
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };

    let mut host = None;
    let mut origin = None;
    let mut token_header = None;
    let mut content_length = 0usize;
    let mut head_ended = false;
    for _ in 0..MAX_HEADERS {
        let line = read_line(&mut reader, &mut head_used)?;
        if line.is_empty() {
            head_ended = true;
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("a header line has no name".to_string());
        };
        let value = value.trim();
        // Header names are case-insensitive; every comparison below goes through this one
        // lowercased copy so no check can be bypassed by changing the capitalisation.
        match name.trim().to_ascii_lowercase().as_str() {
            "host" => host = Some(value.to_string()),
            "origin" => origin = Some(value.to_string()),
            "x-recovery-token" => token_header = Some(value.to_string()),
            "content-length" => {
                content_length = value
                    .parse::<usize>()
                    .map_err(|_| "the stated body length is not a number".to_string())?;
                // The path is already parsed, so the cap can be the one this route actually needs
                // rather than the largest any route needs.
                let cap = if path == DOCUMENT_PATH {
                    MAX_BODY
                } else {
                    MAX_BODY_OTHER
                };
                if content_length > cap {
                    return Err("the body is larger than this program accepts".to_string());
                }
            }
            _ => {}
        }
    }
    // ⛔ Running out of header slots is not the end of the head. Carrying on would start reading
    //    the caller's remaining HEADERS as the body — which is how a request gets to mean one
    //    thing to the parser and another to whoever wrote it.
    if !head_ended {
        return Err("the request has more headers than this program accepts".to_string());
    }

    Ok((
        Head {
            method,
            path,
            query,
            host,
            origin,
            token_header,
            content_length,
        },
        reader,
    ))
}

/// Read the body that follows a head whose checks have already passed.
pub fn read_body(head: Head, reader: &mut BufReader<TcpStream>) -> Result<Request, String> {
    let stated = head.content_length;
    let mut body = Vec::new();
    if stated > 0 {
        // ⛔ NOT `vec![0u8; stated]`. That number is the caller's claim; turning it into memory
        //    before a single byte has arrived hands anyone who can open a socket the right to make
        //    this program hold that much for the length of the read timeout. Reading it in grows
        //    with what actually arrives, and the cap above is what stops it.
        reader
            .take(stated as u64)
            .read_to_end(&mut body)
            .map_err(|e| format!("the body did not arrive in full ({e})"))?;
        if body.len() != stated {
            return Err("the body did not arrive in full".to_string());
        }
    }
    Ok(Request { head, body })
}

/// One CRLF-terminated line, counted against the head budget.
fn read_line(reader: &mut BufReader<TcpStream>, used: &mut usize) -> Result<String, String> {
    let mut raw = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = reader
            .read(&mut byte)
            .map_err(|e| format!("the connection stopped ({e})"))?;
        if n == 0 {
            if raw.is_empty() {
                return Err("the connection closed before a request arrived".to_string());
            }
            break;
        }
        *used += 1;
        if *used > MAX_HEAD {
            return Err("the request head is larger than this program accepts".to_string());
        }
        if byte[0] == b'\n' {
            break;
        }
        raw.push(byte[0]);
    }
    if raw.last() == Some(&b'\r') {
        raw.pop();
    }
    String::from_utf8(raw).map_err(|_| "a header line is not text".to_string())
}

/// Write one response and close.
///
/// The header set is the same on every answer, including errors, because a hardening header that
/// is present on the page and absent on a 404 is a hardening header with a hole in it.
pub fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    extra: &[String],
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n",
        body.len()
    );
    for line in extra {
        head.push_str(line);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Percent-decoding, for query values. Invalid escapes are left as written rather than dropped: a
/// token that fails to decode should fail the comparison, not silently become a different string.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(query: &str) -> Head {
        Head {
            method: "GET".into(),
            path: "/".into(),
            query: query.into(),
            host: None,
            origin: None,
            token_header: None,
            content_length: 0,
        }
    }

    #[test]
    fn a_query_value_is_found_and_decoded() {
        assert_eq!(req("t=abc").query_param("t").as_deref(), Some("abc"));
        assert_eq!(req("a=1&t=x%2Dy").query_param("t").as_deref(), Some("x-y"));
    }

    /// ⛔ An empty value must not read as a present one. `?t=` is what a broken link looks like,
    ///    and answering it as though a token had been supplied would make the gate optional.
    #[test]
    fn an_empty_or_missing_value_is_not_a_value() {
        assert_eq!(req("t=").query_param("t"), None);
        assert_eq!(req("u=abc").query_param("t"), None);
        assert_eq!(req("").query_param("t"), None);
    }

    /// A parameter whose name merely ends with the one being looked for is a different parameter.
    #[test]
    fn a_name_must_match_whole() {
        assert_eq!(req("xt=abc").query_param("t"), None);
    }

    #[test]
    fn a_broken_escape_stays_as_written_rather_than_becoming_something_else() {
        assert_eq!(percent_decode("a%zzb"), "a%zzb");
        assert_eq!(percent_decode("a%2"), "a%2");
    }
}
