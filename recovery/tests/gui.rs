//! The control window, end to end: the same recovery, driven from a browser instead of a terminal.
//!
//! # What has to be proven here
//! Two separate things, and they fail in different ways:
//!
//! 1. **The recovery still happens.** A list handed over by the page and a set of ticked rows must
//!    put the same bytes on the disk that the terminal path puts there. If this were only tested
//!    by looking at JSON, the window could report a perfect success over an empty folder.
//! 2. **Nothing else on the machine can drive it.** A loopback server is reachable by every
//!    process on the machine and — through a hostname that resolves to 127.0.0.1 — by pages on the
//!    internet. Each of the four checks that stop that is tested on its own, with everything else
//!    correct, so a test that passes proves that one check and not the accident of another.
//!
//! ⛔ These tests speak raw HTTP over a socket rather than using an HTTP client, because half of
//!    them need to send a header a client would insist on setting correctly.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

mod common;
use common::Fixture;

/// How long a test waits for something the program does on its own — deriving keys from an account
/// code is deliberately slow (Argon2id, 64 MiB), so this is generous on purpose.
const PATIENCE: Duration = Duration::from_secs(120);

// ── Driving the program ───────────────────────────────────────────────────────────────────────

/// A running `--gui` process, its port, and its one-time token.
struct Window {
    child: Child,
    port: u16,
    token: String,
    lines: Receiver<String>,
}

impl Window {
    fn start(fx: &Fixture, extra: &[&str]) -> Window {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
            .arg("--gui")
            .arg("--no-open")
            .arg("--lang")
            .arg("en")
            .arg("--code-file")
            .arg(fx.path("code.txt"))
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start nmts-recovery --gui");

        let stdout = child.stdout.take().expect("stdout");
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });

        // The address is the only way in, and it is printed once.
        let deadline = Instant::now() + PATIENCE;
        let mut url = None;
        while Instant::now() < deadline {
            match lines.recv_timeout(Duration::from_secs(10)) {
                Ok(line) if line.contains("http://127.0.0.1:") => {
                    url = Some(line.trim().to_string());
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let url = url.expect("the program never printed an address");
        let rest = url.trim_start_matches("http://127.0.0.1:");
        let (port, token) = rest.split_once("/?t=").expect("address shape");
        Window {
            child,
            port: port.parse().expect("port"),
            token: token.to_string(),
            lines,
        }
    }

    /// Poll `/api/state` until `want` is the phase, or give up.
    fn wait_for(&self, want: &str) -> serde_json::Value {
        let deadline = Instant::now() + PATIENCE;
        let mut last = serde_json::Value::Null;
        while Instant::now() < deadline {
            last = self.state();
            if last["phase"] == want {
                return last;
            }
            thread::sleep(Duration::from_millis(150));
        }
        panic!("the window never reached \"{want}\"; it is at {last}");
    }

    fn state(&self) -> serde_json::Value {
        let answer = self.get("/api/state", Some(&self.token));
        assert_eq!(answer.status, 200, "state was refused: {}", answer.body);
        serde_json::from_str(&answer.body).expect("state is JSON")
    }

    /// Everything the program has printed in the terminal so far.
    fn terminal(&self) -> String {
        let mut out = String::new();
        while let Ok(line) = self.lines.try_recv() {
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    fn get(&self, target: &str, token: Option<&str>) -> Answer {
        let mut head = format!(
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n",
            self.port
        );
        if let Some(t) = token {
            head.push_str(&format!("X-Recovery-Token: {t}\r\n"));
        }
        head.push_str("\r\n");
        speak(self.port, head.as_bytes())
    }

    fn post(&self, target: &str, body: &str) -> Answer {
        let head = format!(
            "POST {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\
             X-Recovery-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            self.port,
            self.token,
            body.len()
        );
        let mut raw = head.into_bytes();
        raw.extend_from_slice(body.as_bytes());
        speak(self.port, &raw)
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Answer {
    status: u16,
    head: String,
    body: String,
}

/// One request, one answer, over a socket that is closed afterwards.
fn speak(port: u16, request: &[u8]) -> Answer {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    socket.write_all(request).expect("send");
    socket.flush().expect("flush");
    let mut raw = Vec::new();
    // The server answers `Connection: close`, so end-of-stream is end-of-answer.
    socket.read_to_end(&mut raw).expect("read");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text.clone(), String::new()),
    };
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Answer { status, head, body }
}

/// A fixture with two files in it and a list that covers both.
fn two_files() -> (Fixture, Vec<u8>, Vec<u8>) {
    let fx = Fixture::new();
    let letter = b"the list is the index, and the code is the key".to_vec();
    // Big enough to cross the tool's read chunk more than once, so the progress path is exercised
    // rather than skipped by a file that arrives in one go.
    let big: Vec<u8> = (0..900_000u32).map(|i| (i.wrapping_mul(37) % 251) as u8).collect();
    let a = fx.add_file("letter.txt", "/docs", &letter, 1, false);
    let b = fx.add_file("big.bin", "/", &big, 3, false);
    fx.write_map(vec![a, b]);
    (fx, letter, big)
}

// ── 1. The recovery still happens ─────────────────────────────────────────────────────────────

/// The claim, through the window: choose a list, tick the rows, and the files are on the disk.
#[test]
fn the_window_gives_the_files_back() {
    let (fx, letter, big) = two_files();
    let w = Window::start(
        &fx,
        &["--blobs-dir", fx.path("blobs").to_str().expect("utf8")],
    );

    assert_eq!(w.state()["phase"], "need-map");

    let map_text = std::fs::read_to_string(fx.path("map.nmtsmap")).expect("map");
    let sent = w.post(
        "/api/map",
        &serde_json::json!({ "name": "map.nmtsmap", "text": map_text }).to_string(),
    );
    assert_eq!(sent.status, 200, "the list was refused: {}", sent.body);

    // The account code came from --code-file, so the program walks through "need-code" on its own.
    let ready = w.wait_for("ready");
    assert_eq!(ready["items"].as_array().expect("items").len(), 2);
    assert_eq!(ready["seq"], 4);
    let names: Vec<String> = ready["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["name"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(names.contains(&"letter.txt".to_string()), "{names:?}");
    assert!(names.contains(&"big.bin".to_string()), "{names:?}");

    let out = fx.path("out");
    let started = w.post(
        "/api/restore",
        &serde_json::json!({
            "items": [0, 1],
            "out": out.to_str().expect("utf8"),
            "overwrite": false
        })
        .to_string(),
    );
    assert_eq!(started.status, 200, "the restore was refused: {}", started.body);

    let done = w.wait_for("finished");
    assert_eq!(done["job"]["failed"], 0, "something failed: {}", done["job"]["lines"]);
    assert_eq!(done["job"]["done"], 2);

    // ⛔ The bytes, not the report. A window that says "2 of 2 done" over an empty folder is the
    //    failure this test exists to catch.
    assert_eq!(std::fs::read(out.join("docs/letter.txt")).expect("letter"), letter);
    assert_eq!(std::fs::read(out.join("big.bin")).expect("big"), big);
}

/// ⛔ The account code must not appear in anything the program prints. It is read from a file here
///    rather than typed, so nothing echoes it — which is exactly the state a stray debug line would
///    quietly end, in the one program whose output somebody might paste into a support thread.
#[test]
fn the_terminal_never_prints_the_account_code() {
    let (fx, _, _) = two_files();
    let w = Window::start(
        &fx,
        &["--blobs-dir", fx.path("blobs").to_str().expect("utf8")],
    );
    let map_text = std::fs::read_to_string(fx.path("map.nmtsmap")).expect("map");
    w.post(
        "/api/map",
        &serde_json::json!({ "name": "m", "text": map_text }).to_string(),
    );
    w.wait_for("ready");
    w.post(
        "/api/restore",
        &serde_json::json!({ "items": [0, 1], "out": fx.path("out").to_str().expect("utf8") })
            .to_string(),
    );
    w.wait_for("finished");

    let said = w.terminal();
    let written = std::fs::read_to_string(fx.path("code.txt")).expect("code");
    let dashed = written.trim();
    let bare = dashed.replace('-', "");
    assert!(!dashed.is_empty() && bare.len() >= 32, "the fixture code is not a code");
    assert!(!said.contains(dashed), "the terminal printed the account code");
    assert!(!said.contains(&bare), "the terminal printed the account code");
    // And it did say the things it is supposed to say, so an empty capture cannot pass the above.
    // (The address line itself was consumed while starting the window, which is how the token got
    // here at all — so this looks at what came after it.)
    assert!(!w.token.is_empty(), "no address was printed");
    assert!(
        said.contains("never in the browser"),
        "the terminal never said where the code goes: {said}"
    );
    assert!(said.contains("The list is open"), "the terminal never said the list opened: {said}");
}

/// Ticking one row restores one file. The other must not appear — a control window that quietly
/// restores everything is one that fills a disk somebody was rationing.
#[test]
fn only_the_ticked_rows_are_written() {
    let (fx, letter, _big) = two_files();
    let w = Window::start(
        &fx,
        &["--blobs-dir", fx.path("blobs").to_str().expect("utf8")],
    );
    let map_text = std::fs::read_to_string(fx.path("map.nmtsmap")).expect("map");
    w.post(
        "/api/map",
        &serde_json::json!({ "name": "m", "text": map_text }).to_string(),
    );
    let ready = w.wait_for("ready");
    let letter_index = ready["items"]
        .as_array()
        .expect("items")
        .iter()
        .position(|i| i["name"] == "letter.txt")
        .expect("the letter is in the list");

    let out = fx.path("out");
    w.post(
        "/api/restore",
        &serde_json::json!({ "items": [letter_index], "out": out.to_str().expect("utf8") })
            .to_string(),
    );
    let done = w.wait_for("finished");
    assert_eq!(done["job"]["total"], 1);
    assert_eq!(std::fs::read(out.join("docs/letter.txt")).expect("letter"), letter);
    assert!(!out.join("big.bin").exists(), "an unticked file was written anyway");
}

/// A list that will not open leaves the window able to try another one, rather than dead.
#[test]
fn a_file_that_is_not_a_map_is_said_so_and_the_window_carries_on() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    w.post(
        "/api/map",
        &serde_json::json!({ "name": "notes.txt", "text": "hello" }).to_string(),
    );
    let deadline = Instant::now() + PATIENCE;
    let mut note = None;
    while Instant::now() < deadline {
        let s = w.state();
        if s["phase"] == "need-map" && !s["note"].is_null() {
            note = Some(s["note"].as_str().unwrap_or_default().to_string());
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let note = note.expect("the window never said what was wrong");
    assert!(note.contains("not an NMTS recovery list"), "{note}");
}

/// Asking for nothing is refused before anything is written, and the message says what to do.
#[test]
fn restoring_nothing_is_refused_rather_than_reported_as_success() {
    let (fx, _, _) = two_files();
    let w = Window::start(
        &fx,
        &["--blobs-dir", fx.path("blobs").to_str().expect("utf8")],
    );
    let map_text = std::fs::read_to_string(fx.path("map.nmtsmap")).expect("map");
    w.post(
        "/api/map",
        &serde_json::json!({ "name": "m", "text": map_text }).to_string(),
    );
    w.wait_for("ready");
    let answer = w.post(
        "/api/restore",
        &serde_json::json!({ "items": [], "out": fx.path("out").to_str().expect("utf8") })
            .to_string(),
    );
    assert_eq!(answer.status, 400);
    assert!(answer.body.contains("Tick at least one file"), "{}", answer.body);
    assert_eq!(w.state()["phase"], "ready", "the window left the list");
}

// ── 2. Nothing else on the machine can drive it ───────────────────────────────────────────────

/// The page itself is behind the token: without it, a process that guessed the port gets nothing.
#[test]
fn the_page_needs_the_token() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    assert_eq!(w.get("/?t=not-the-token", None).status, 403);
    assert_eq!(w.get("/", None).status, 403);

    let ok = speak(
        w.port,
        format!(
            "GET /?t={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            w.token, w.port
        )
        .as_bytes(),
    );
    assert_eq!(ok.status, 200);
    assert!(ok.body.contains("nmts-recovery"), "the page is not the page");
}

/// Every `/api/` route is behind the token too, and the token goes in a header rather than the
/// address so it is not carried into anything that records URLs.
#[test]
fn the_api_needs_the_token_in_a_header() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    assert_eq!(w.get("/api/state", None).status, 403);
    assert_eq!(w.get("/api/state", Some("wrong")).status, 403);
    // A token in the query string is not a token: only the header is read.
    assert_eq!(w.get(&format!("/api/state?t={}", w.token), None).status, 403);
    assert_eq!(w.get("/api/state", Some(&w.token)).status, 200);
}

/// ⛔ DNS rebinding. A page on the internet cannot open a socket to this port directly, but it can
///    load a name that resolves to 127.0.0.1 and then talk to whatever is listening. The socket is
///    genuinely local in that case; the ONLY thing that tells the two apart is the name the client
///    asked for. This test holds the check that reads it.
#[test]
fn a_request_addressed_to_a_name_rather_than_the_loopback_address_is_refused() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    for host in [
        "rebind.example.com",
        "localhost",
        &format!("127.0.0.1:{}", w.port + 1),
        "127.0.0.1",
    ] {
        let answer = speak(
            w.port,
            format!(
                "GET /?t={} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
                w.token
            )
            .as_bytes(),
        );
        assert_eq!(answer.status, 403, "Host: {host} was admitted");
    }
}

/// A request carrying another page's origin is refused even with a correct token and host, so a
/// page that somehow learned the token still cannot use it.
#[test]
fn a_request_from_another_page_is_refused() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    let answer = speak(
        w.port,
        format!(
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://evil.example\r\n\
             X-Recovery-Token: {}\r\nConnection: close\r\n\r\n",
            w.port, w.token
        )
        .as_bytes(),
    );
    assert_eq!(answer.status, 403);
}

/// The answer to a refusal says nothing about which check refused it.
#[test]
fn a_refusal_does_not_say_which_wall_was_hit() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    let wrong_token = w.get("/api/state", Some("wrong")).body;
    let wrong_host = speak(
        w.port,
        format!(
            "GET /api/state HTTP/1.1\r\nHost: elsewhere.example\r\nX-Recovery-Token: {}\r\n\
             Connection: close\r\n\r\n",
            w.token
        )
        .as_bytes(),
    )
    .body;
    assert_eq!(wrong_token, wrong_host);
}

/// The page is served with a policy that lets its own script run and nothing else, and no answer
/// invites another origin to read it.
#[test]
fn the_page_is_served_under_a_policy_and_never_shared_across_origins() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    let answer = speak(
        w.port,
        format!(
            "GET /?t={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            w.token, w.port
        )
        .as_bytes(),
    );
    let head = answer.head.to_ascii_lowercase();
    assert!(head.contains("content-security-policy:"), "{}", answer.head);
    assert!(head.contains("script-src 'nonce-"), "{}", answer.head);
    assert!(head.contains("default-src 'none'"), "{}", answer.head);
    // ⛔ Nothing may hand this window's answers to another origin.
    assert!(
        !head.contains("access-control-allow-origin"),
        "the server offered itself to other origins"
    );
    // The slot the server fills must not survive into what it serves.
    assert!(
        !answer.body.contains("__CSP_NONCE__"),
        "the page went out with its nonce slot unfilled"
    );
}

/// A body larger than the cap is refused on the strength of what it claims, before it is read.
#[test]
fn an_enormous_body_is_refused_without_being_read() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    let answer = speak(
        w.port,
        format!(
            "POST /api/map HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Recovery-Token: {}\r\n\
             Content-Length: 999999999999\r\nConnection: close\r\n\r\n",
            w.port, w.token
        )
        .as_bytes(),
    );
    assert_eq!(answer.status, 400);
}

/// A request with more headers than the parser reads is refused, and nothing is acted on.
///
/// ⚠ This one asserts an OUTCOME, not a check. Removing the header-budget check in `http.rs` leaves
///    this test green, because the body then gets read from the wrong offset and fails to parse as
///    JSON — a 400 either way. That is worth writing down rather than leaving as an implied gate:
///    the check is there so the parser cannot be made to disagree with the sender about where the
///    body starts, and what holds THAT is reading the code, not this test.
#[test]
fn a_request_with_more_headers_than_the_parser_reads_is_refused() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    let mut raw = format!(
        "POST /api/map HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Recovery-Token: {}\r\n",
        w.port, w.token
    );
    for i in 0..200 {
        raw.push_str(&format!("X-Padding-{i}: filler\r\n"));
    }
    raw.push_str("Content-Length: 2\r\n\r\n{}");
    let answer = speak(w.port, raw.as_bytes());
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert_eq!(w.state()["phase"], "need-map", "something was acted on anyway");
}

/// ⛔ The account code must not have a way in through this channel. There is no route that takes
///    one, and if one is ever added this test is what notices.
#[test]
fn no_route_accepts_an_account_code() {
    let (fx, _, _) = two_files();
    let w = Window::start(&fx, &[]);
    let code = std::fs::read_to_string(fx.path("code.txt")).expect("code");
    for target in ["/api/code", "/api/open", "/api/unlock", "/api/state"] {
        let answer = w.post(
            target,
            &serde_json::json!({ "code": code.trim(), "accountCode": code.trim() }).to_string(),
        );
        assert!(
            answer.status == 404 || answer.status == 400,
            "{target} did something with an account code (status {})",
            answer.status
        );
    }
    // And the program is still where it was, which it would not be if one of those had worked.
    assert_eq!(w.state()["phase"], "need-map");
}

// ── The page as a file ────────────────────────────────────────────────────────────────────────

/// `--write-gui` puts the page on disk so it can be read without running the program, and what it
/// writes is inert.
#[test]
fn the_page_can_be_written_out_and_does_nothing_on_its_own() {
    let dir = tempfile::tempdir().expect("tempdir");
    let to = dir.path().join("control.html");
    let out = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
        .args(["--write-gui", to.to_str().expect("utf8"), "--lang", "en"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let page = std::fs::read_to_string(&to).expect("the page was written");
    assert!(page.contains("</html>"));
    assert!(!page.contains("__CSP_NONCE__"), "a placeholder was left in the file");
    // Nothing in the page reaches outside this machine.
    for outside in ["http://", "https://"] {
        assert!(
            !page.contains(&format!("src=\"{outside}")),
            "the page loads something from {outside}"
        );
    }
}
