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

/// The largest body accepted. A recovery map for a very large account is a few megabytes of
/// base64; this leaves room for an order of magnitude more and stops well short of a number that
/// would matter on the kind of machine somebody rescues a drive onto.
pub const MAX_BODY: usize = 32 * 1024 * 1024;

/// One request, already bounded.
pub struct Request {
    pub method: String,
    /// Path with the query string removed.
    pub path: String,
    /// Everything after the first `?`, still percent-encoded.
    pub query: String,
    pub host: Option<String>,
    pub origin: Option<String>,
    /// The value of the token header, if the client sent one.
    pub token_header: Option<String>,
    pub body: Vec<u8>,
}

impl Request {
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

/// Read one request from `stream`.
pub fn read_request(stream: &TcpStream) -> Result<Request, String> {
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
                if content_length > MAX_BODY {
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

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("the body did not arrive in full ({e})"))?;
    }

    Ok(Request {
        method,
        path,
        query,
        host,
        origin,
        token_header,
        body,
    })
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

    fn req(query: &str) -> Request {
        Request {
            method: "GET".into(),
            path: "/".into(),
            query: query.into(),
            host: None,
            origin: None,
            token_header: None,
            body: Vec::new(),
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
