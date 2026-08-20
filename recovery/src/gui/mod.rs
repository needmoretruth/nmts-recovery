//! The control window: a page served to this machine only, driving the same recovery the terminal
//! drives.
//!
//! # What this is, and what it is not
//! It is a **second way to operate one program**. The recovery itself — deriving keys, fetching
//! ciphertext, checking placement, decrypting, hashing, writing files — happens in exactly the code
//! the terminal path runs. The browser draws a list and sends back which rows were ticked. It holds
//! no key, opens no blob, and writes no file. If this whole module were deleted, nothing about what
//! a recovery *is* would change.
//!
//! # ⛔ The account code is typed in the terminal, never in the browser
//! This is the one rule that shapes everything else here. A browser is the largest attack surface
//! on a personal machine: extensions can read any page's contents, password managers offer to
//! remember what looks like a credential, and form values outlive the tab. The account code is the
//! master secret for an account — every key in NMTS derives from it — so it does not go near any of
//! that. When the page has handed over a list file, this program asks for the code on the terminal
//! it was started from, and the page says to look there.
//!
//! # Why a page on this machine can be trusted at all
//! Four things together, and none of them is sufficient alone:
//! 1. The listener is bound to `127.0.0.1`. Nothing off this machine can connect.
//! 2. A fresh 32-byte token is minted per run and printed once, in the terminal. Every request
//!    carries it or is refused. It exists only in memory and dies with the process.
//! 3. The `Host` header must be the loopback address and port. This is what stops DNS rebinding —
//!    a name that resolves to 127.0.0.1 lets a remote page reach a local port, and the token alone
//!    would not know the difference.
//! 4. No response carries a cross-origin header of any kind, and any `Origin` other than this
//!    server's own is refused outright, so another page cannot read an answer even if it guessed
//!    the token.
//!
//! # ⛔ The page is served, not opened from disk
//! `gui/index.html` is in the repository to be read, and `--write-gui` writes a copy out. Opening
//! that copy directly does nothing on purpose: a page loaded from `file://` has no origin this
//! server could tell apart from any other page loaded from `file://`, so admitting it would mean
//! admitting all of them and leaving the token as the only wall. Serving the page keeps every
//! request same-origin.

pub mod http;

use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use nmts_crypto::manifest::RecoveryManifest;
use nmts_crypto::rng::OsRng;
use serde_json::{json, Value};

use crate::args::{Args, Lang};
use crate::mapfile;
use crate::msg;
use crate::restore;
use crate::source::{BlobSource, DirSource, HttpSource};

/// The page, compiled in. One copy of it exists: this file is what the repository ships, what
/// `--write-gui` writes out, and what the server serves — so no reader can be looking at a version
/// that is not the one running.
const PAGE: &str = include_str!("../../gui/index.html");

/// Replaced with a per-response random value so the page's inline script can be allowed by name
/// while nothing else can.
const NONCE_SLOT: &str = "__CSP_NONCE__";

/// Sockets served at once. One browser tab needs a handful; a number this size exists so a process
/// that opens connections and never speaks cannot make the server grow threads without limit.
const MAX_CONNECTIONS: usize = 32;

/// Where a request that has gone quiet is abandoned.
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Where the session is in the one sequence it can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the browser to hand over a recovery list.
    NeedMap,
    /// The list is readable and the terminal is asking for the account code.
    NeedCode,
    /// The list is open. The page is showing what it holds.
    Ready,
    /// Files are being fetched and written.
    Restoring,
    /// The restore ended, successfully or not.
    Finished,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::NeedMap => "need-map",
            Phase::NeedCode => "need-code",
            Phase::Ready => "ready",
            Phase::Restoring => "restoring",
            Phase::Finished => "finished",
        }
    }
}

/// One row in the page's list.
struct ItemView {
    name: String,
    path: String,
    size: u64,
    parts: usize,
}

/// How a running restore is going.
#[derive(Default)]
struct Job {
    total: usize,
    done: usize,
    failed: usize,
    bytes_total: u64,
    bytes_done: u64,
    current: String,
    current_bytes: u64,
    lines: Vec<String>,
}

/// Everything both threads can see.
struct Session {
    phase: Phase,
    /// The language of everything this run says, in the terminal and in the page alike.
    ///
    /// It lives here rather than in the parsed arguments because the page has a toggle and the
    /// terminal has the account-code prompt: two surfaces, one run, and a person who switched the
    /// window to Korean and then got an English prompt would reasonably wonder which program was
    /// asking.
    lang: Lang,
    /// The last thing worth telling the person, in their language. Cleared when it stops being true.
    note: Option<String>,
    map_name: Option<String>,
    account_id: Option<String>,
    seq: u64,
    generated_at: String,
    items: Vec<ItemView>,
    manifest: Option<RecoveryManifest>,
    /// Blob id of the bundle the open list was READ from, when it was found on the network.
    ///
    /// Reader's knowledge, not the document's: a list found on the storage network describes the
    /// files it rode along with as "in the bundle you found me in" (NRM-3), and this is that
    /// bundle. `None` for a list opened from a file, which is what makes such an item report
    /// itself as unresolvable instead of being fetched from somewhere plausible.
    own_quilt: Option<String>,
    out: String,
    job: Job,
}

impl Session {
    fn new(out: String, lang: Lang) -> Self {
        Self {
            phase: Phase::NeedMap,
            lang,
            note: None,
            map_name: None,
            account_id: None,
            seq: 0,
            generated_at: String::new(),
            items: Vec::new(),
            manifest: None,
            own_quilt: None,
            out,
            job: Job::default(),
        }
    }

    /// What the page polls for. Deliberately the whole picture rather than a diff: a control window
    /// that reconstructs state from a stream of changes can drift out of step with the program it
    /// is showing, and during a recovery the screen being wrong is the failure.
    fn to_json(&self) -> Value {
        json!({
            "phase": self.phase.as_str(),
            "note": self.note,
            "lang": match self.lang { Lang::En => "en", Lang::Ko => "ko" },
            "map": self.map_name,
            "accountId": self.account_id,
            "seq": self.seq,
            "generatedAt": self.generated_at,
            "out": self.out,
            "items": self.items.iter().map(|i| json!({
                "name": i.name,
                "path": i.path,
                "size": i.size,
                "parts": i.parts,
            })).collect::<Vec<_>>(),
            "job": {
                "total": self.job.total,
                "done": self.job.done,
                "failed": self.job.failed,
                "bytesTotal": self.job.bytes_total,
                "bytesDone": self.job.bytes_done,
                "current": self.job.current,
                "currentBytes": self.job.current_bytes,
                "lines": self.job.lines,
            },
        })
    }
}

/// What the server thread asks the main thread to do. Both of these need the terminal, which is the
/// main thread's alone — the account-code prompt must not be racing a second one.
enum Event {
    Map { name: String, text: String },
    Quit,
}

/// Serve the control window until the page says it is done.
pub fn run(a: &Args) -> Result<ExitCode, String> {
    run_with(a, None)
}

/// The control window, optionally starting from a list that was already FOUND on the network.
///
/// `seed` is `(the opened list, the bundle it came out of, what to call it on screen)`. When it is
/// present the account code has already been typed, so the page opens with the list open rather
/// than asking for a file first.
pub fn run_with(
    a: &Args,
    seed: Option<(RecoveryManifest, String, String)>,
) -> Result<ExitCode, String> {
    let lang = a.lang;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, a.port.unwrap_or(0)))
        .map_err(|e| format!("{} ({e})", msg::GUI_NO_PORT.get(lang)))?;
    let port = listener.local_addr().map_err(|e| format!("{e}"))?.port();

    // 32 bytes from the OS CSPRNG, minted per run, printed once. Not derived from anything, not
    // written anywhere, gone when the process ends.
    let token = nmts_crypto::b64::encode(&OsRng::bytes::<32>());

    let out = a
        .out
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
        .display()
        .to_string();
    let shared = Arc::new(Mutex::new(Session::new(out, a.lang)));
    let (tx, rx) = mpsc::channel::<Event>();

    {
        let shared = Arc::clone(&shared);
        let token = token.clone();
        let tx = tx.clone();
        let a = a.clone();
        thread::Builder::new()
            .name("nmts-recovery-control".to_string())
            .spawn(move || serve(listener, shared, tx, token, port, a))
            .map_err(|e| format!("{e}"))?;
    }

    let url = format!("http://127.0.0.1:{port}/?t={token}");
    println!("{}", msg::GUI_HEAD.get(lang));
    println!("\n    {url}\n");
    println!("{}", msg::GUI_LOCAL_ONLY.get(lang));
    println!("{}", msg::GUI_CODE_STAYS_HERE.get(lang));
    if !a.no_open && open_in_browser(&url) {
        println!("{}", msg::GUI_OPENED.get(lang));
    }
    let _ = std::io::stdout().flush();

    if let Some((manifest, quilt_id, name)) = seed {
        seed_from_network(&shared, manifest, quilt_id, name);
    }

    // A list named on the command line skips the first screen. The code is still asked for here.
    if !a.map.as_os_str().is_empty() {
        let name = a
            .map
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| a.map.display().to_string());
        match std::fs::read_to_string(&a.map) {
            Ok(text) => open_map(&shared, &name, &text, a),
            Err(e) => {
                let mut s = session(&shared);
                s.note = Some(format!("{}: {e}", a.map.display()));
            }
        }
    }

    // Ends on `Event::Quit`, and also on a closed channel: a server thread that is gone is not a
    // state this program can keep working in, because the page is the only way to drive it.
    while let Ok(Event::Map { name, text }) = rx.recv() {
        open_map(&shared, &name, &text, a);
    }
    println!("{}", msg::GUI_CLOSED.get(lang));
    // Long enough for the answer to `/api/quit` to reach a browser on the same machine. The process
    // exiting is what closes the listener, so this is the difference between the page showing
    // "finished" and the page showing a connection error at the end of a successful recovery.
    thread::sleep(Duration::from_millis(400));
    Ok(ExitCode::SUCCESS)
}

/// Parse a wrapper, ask for the code on the terminal, open the list. Runs on the main thread.
fn open_map(shared: &Arc<Mutex<Session>>, name: &str, text: &str, a: &Args) {
    let lang = current_lang(shared);
    let fail = |note: String| {
        let mut s = session(shared);
        s.phase = Phase::NeedMap;
        s.note = Some(note);
        s.manifest = None;
        s.items.clear();
        s.map_name = None;
    };

    // ⛔ A KIT MUST NOT BE OPENED HERE, EVER — and if one arrives, say why rather than calling it
    //    a broken list. A kit carries the account code in the clear; the page is told to refuse one
    //    before it reads the file, so reaching this line means that check was bypassed or the text
    //    came from somewhere else. Either way the answer is the terminal, not this window.
    //    ⛔ DO NOT "add kit support" here to make the GUI accept the one-file artefact. The reason
    //    the terminal asks for the code is that a browser is the wrong place for it, and that does
    //    not change because the code arrives inside a file instead of a text box.
    if crate::kitfile::looks_like_kit(text) {
        return fail(msg::KIT_NOT_IN_THE_BROWSER.get(lang).to_string());
    }

    let wrapper = match mapfile::parse(text) {
        Ok(w) => w,
        Err(mapfile::MapFileError::NotAMap(why)) => {
            return fail(format!("{} — {why}.", msg::MAP_NOT_A_MAP.get(lang)))
        }
        Err(mapfile::MapFileError::TooNew {
            wrapper,
            nrm,
            min_tool,
        }) => {
            return fail(mapfile::too_new_sentence(
                wrapper,
                nrm,
                min_tool.as_deref(),
                lang,
            ))
        }
    };

    {
        let mut s = session(shared);
        s.phase = Phase::NeedCode;
        s.note = None;
        s.map_name = Some(name.to_string());
        s.account_id = Some(wrapper.account_id.clone());
    }

    // ⛔ The lock is NOT held across the prompt. Reading a line from a terminal can take as long as
    //    a person takes, and the page polls throughout — holding it here would freeze the window
    //    that is telling them to type.
    println!("\n{}", msg::GUI_ASK_IN_TERMINAL.get(lang));
    let code = match crate::read_account_code(a.code_file.as_deref(), lang) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let keys = match nmts_crypto::kdf::derive(&code) {
        Ok(k) => k,
        Err(e) => return fail(format!("{e}")),
    };
    // Same order as the terminal path, for the same reason: "wrong account" and "damaged map" fail
    // the same decryption, and only one of them is worth going to look for a backup over.
    if keys.account_id_b64() != wrapper.account_id {
        return fail(msg::CODE_WRONG_ACCOUNT.get(lang).to_string());
    }
    let sealed = match nmts_crypto::b64::decode(&wrapper.sealed) {
        Ok(b) => b,
        Err(_) => {
            return fail(format!(
                "{} — the sealed list is not readable.",
                msg::MAP_NOT_A_MAP.get(lang)
            ))
        }
    };
    let manifest = match RecoveryManifest::decrypt(&keys.data_key, &sealed) {
        Ok(m) => m,
        Err(_) => return fail(msg::MAP_WILL_NOT_OPEN.get(lang).to_string()),
    };

    let note = (wrapper.seq != manifest.seq).then(|| {
        format!(
            "{} ({} / {}).",
            msg::MAP_SEQ_DISAGREES.get(lang),
            wrapper.seq,
            manifest.seq
        )
    });
    println!("{}", msg::GUI_MAP_OPEN.get(lang));

    let mut s = session(shared);
    s.items = manifest
        .items
        .iter()
        .map(|i| ItemView {
            name: i.name.clone(),
            path: i.path.clone(),
            size: i.size,
            parts: i.parts.len(),
        })
        .collect();
    s.seq = manifest.seq;
    s.generated_at = manifest.generated_at.clone();
    s.manifest = Some(manifest);
    // Cleared, not left over: a second list opened from a file after one was found on the network
    // must not inherit the network one's bundle. That would resolve an own-quilt item against a
    // bundle it has nothing to do with, and fetch a stranger's bytes.
    s.own_quilt = None;
    s.phase = Phase::Ready;
    s.note = note;
}

/// Fill the session from a list that was FOUND on the storage network, ready to restore.
///
/// The account code has already been typed by the time this runs, so there is no `NeedCode` phase
/// to pass through — the page opens with the list already open.
fn seed_from_network(
    shared: &Arc<Mutex<Session>>,
    manifest: RecoveryManifest,
    quilt_id: String,
    name: String,
) {
    let mut s = session(shared);
    s.items = manifest
        .items
        .iter()
        .map(|i| ItemView {
            name: i.name.clone(),
            path: i.path.clone(),
            size: i.size,
            parts: i.parts.len(),
        })
        .collect();
    s.seq = manifest.seq;
    s.generated_at = manifest.generated_at.clone();
    s.map_name = Some(name);
    s.account_id = Some(manifest.account_id.clone());
    s.manifest = Some(manifest);
    s.own_quilt = Some(quilt_id);
    s.phase = Phase::Ready;
    s.note = None;
}

/// Accept connections until the process ends.
fn serve(
    listener: TcpListener,
    shared: Arc<Mutex<Session>>,
    tx: Sender<Event>,
    token: String,
    port: u16,
    a: Args,
) {
    let live = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => {
                // A listener that keeps failing to accept — the process is out of file handles,
                // say — would otherwise spin this loop at full speed and take the machine's last
                // free capacity with it, during a rescue.
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        if live.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            // Dropped without an answer. A client that has opened thirty-two sockets and said
            // nothing on any of them is not the page.
            continue;
        }
        live.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::clone(&shared);
        let tx = tx.clone();
        let token = token.clone();
        let a = a.clone();
        let live_slot = Arc::clone(&live);
        let spawned = thread::Builder::new()
            .name("nmts-recovery-request".to_string())
            .spawn(move || {
                handle(stream, &shared, &tx, &token, port, &a);
                live_slot.fetch_sub(1, Ordering::Relaxed);
            });
        if spawned.is_err() {
            live.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// One request, from the checks through to the answer.
fn handle(
    mut stream: TcpStream,
    shared: &Arc<Mutex<Session>>,
    tx: &Sender<Event>,
    token: &str,
    port: u16,
    a: &Args,
) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

    let req = match http::read_request(&stream) {
        Ok(r) => r,
        Err(why) => {
            let _ = http::respond(
                &mut stream,
                400,
                "text/plain; charset=utf-8",
                &[],
                why.as_bytes(),
            );
            return;
        }
    };

    // ⛔ FIRST, BEFORE ANYTHING ELSE. A hostname that resolves to 127.0.0.1 is how a page on the
    //    internet reaches a port on this machine; the socket looks local because it is local. The
    //    only thing that tells the two apart is what the client asked for by name.
    let expect_host = format!("127.0.0.1:{port}");
    if req.host.as_deref() != Some(expect_host.as_str()) {
        deny(&mut stream);
        return;
    }
    // A request from another page carries that page's origin. Ours is the only one allowed, and a
    // request with no origin at all is the page's own fetch or the browser's first load.
    if let Some(origin) = &req.origin {
        if origin != &format!("http://{expect_host}") {
            deny(&mut stream);
            return;
        }
    }

    match (req.method.as_str(), req.path.as_str()) {
        // Answered before the token check because a browser asks for it unbidden, and a 403 in the
        // network log next to a working page reads as a fault that is not there.
        ("GET", "/favicon.ico") => {
            let _ = http::respond(&mut stream, 204, "text/plain", &[], b"");
        }
        ("GET", "/") => {
            if !constant_time_eq(req.query_param("t").as_deref().unwrap_or(""), token) {
                deny(&mut stream);
                return;
            }
            serve_page(&mut stream);
        }
        (_, path) if path.starts_with("/api/") => {
            if !constant_time_eq(req.token_header.as_deref().unwrap_or(""), token) {
                deny(&mut stream);
                return;
            }
            api(&mut stream, &req, shared, tx, a);
        }
        _ => {
            let _ = http::respond(
                &mut stream,
                404,
                "text/plain; charset=utf-8",
                &[],
                b"not here\n",
            );
        }
    }
}

/// One refusal, worded one way, for every reason a request can be refused.
///
/// ⛔ It does not say which check failed. A caller that learns "the host was wrong, the token was
///    fine" has been handed the token's validity as an oracle.
fn deny(stream: &mut TcpStream) {
    let _ = http::respond(
        stream,
        403,
        "text/plain; charset=utf-8",
        &[],
        b"This address is only for the nmts-recovery window that opened it.\n\
          Run nmts-recovery --gui and use the address it prints.\n",
    );
}

fn serve_page(stream: &mut TcpStream) {
    let nonce = nmts_crypto::b64::encode(&OsRng::bytes::<16>());
    let body = PAGE.replace(NONCE_SLOT, &nonce);
    let csp = format!(
        "Content-Security-Policy: default-src 'none'; script-src 'nonce-{nonce}'; \
         style-src 'nonce-{nonce}'; connect-src 'self'; img-src 'none'; font-src 'none'; \
         form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
    );
    let _ = http::respond(
        stream,
        200,
        "text/html; charset=utf-8",
        &[csp],
        body.as_bytes(),
    );
}

fn api(
    stream: &mut TcpStream,
    req: &http::Request,
    shared: &Arc<Mutex<Session>>,
    tx: &Sender<Event>,
    a: &Args,
) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/state") => {
            let body = session(shared).to_json().to_string();
            json_ok(stream, &body);
        }
        ("POST", "/api/map") => {
            let Some(doc) = body_json(stream, req) else {
                return;
            };
            let name = doc
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("map")
                .to_string();
            let Some(text) = doc.get("text").and_then(Value::as_str) else {
                bad(stream, "no list contents were sent");
                return;
            };
            {
                let s = session(shared);
                // The main thread is at a prompt; a second list now would queue behind it and be
                // opened with a code that was typed for the first one.
                if s.phase == Phase::NeedCode || s.phase == Phase::Restoring {
                    busy(stream);
                    return;
                }
            }
            let _ = tx.send(Event::Map {
                name,
                text: text.to_string(),
            });
            json_ok(stream, "{\"ok\":true}");
        }
        ("POST", "/api/restore") => {
            let Some(doc) = body_json(stream, req) else {
                return;
            };
            match start_restore(shared, &doc, a) {
                Ok(()) => json_ok(stream, "{\"ok\":true}"),
                Err(why) => bad(stream, &why),
            }
        }
        ("POST", "/api/lang") => {
            let Some(doc) = body_json(stream, req) else {
                return;
            };
            let wanted = doc.get("lang").and_then(Value::as_str).unwrap_or("");
            match wanted {
                "en" | "ko" => {
                    let mut s = session(shared);
                    s.lang = if wanted == "ko" { Lang::Ko } else { Lang::En };
                    json_ok(stream, "{\"ok\":true}");
                }
                _ => bad(stream, "that is not a language this program has"),
            }
        }
        ("POST", "/api/quit") => {
            json_ok(stream, "{\"ok\":true}");
            // Flushed and half-closed before the main thread is told, so the answer is on the wire
            // before the process that owns the socket goes away.
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let _ = tx.send(Event::Quit);
        }
        _ => {
            let _ = http::respond(stream, 404, "application/json", &[], b"{\"error\":\"no\"}");
        }
    }
}

/// Begin a restore for the rows the page ticked.
fn start_restore(shared: &Arc<Mutex<Session>>, doc: &Value, a: &Args) -> Result<(), String> {
    let lang = current_lang(shared);
    let out = doc
        .get("out")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| msg::GUI_NEED_DESTINATION.get(lang).to_string())?
        .to_string();
    let overwrite = doc
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let picked: Vec<usize> = doc
        .get("items")
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(Value::as_u64)
                .map(|n| n as usize)
                .collect()
        })
        .unwrap_or_default();
    if picked.is_empty() {
        return Err(msg::GUI_NEED_SELECTION.get(lang).to_string());
    }

    // A manifest holding only the chosen items. Planning against this rather than filtering after
    // the fact is what keeps the `(2)` numbering about the files being written and not about files
    // the person did not ask for.
    let subset = {
        let mut s = session(shared);
        if s.phase == Phase::Restoring {
            return Err(msg::GUI_ALREADY_RUNNING.get(lang).to_string());
        }
        let manifest = s
            .manifest
            .as_ref()
            .ok_or_else(|| "no list is open".to_string())?;
        let mut subset = manifest.clone();
        subset.items = picked
            .iter()
            .filter_map(|i| manifest.items.get(*i).cloned())
            .collect();
        if subset.items.is_empty() {
            return Err(msg::GUI_NEED_SELECTION.get(lang).to_string());
        }
        s.job = Job {
            total: subset.items.len(),
            bytes_total: subset.items.iter().map(|i| i.size).sum(),
            ..Job::default()
        };
        s.out = out.clone();
        s.note = None;
        s.phase = Phase::Restoring;
        subset
    };

    let own_quilt = session(shared).own_quilt.clone();
    let shared = Arc::clone(shared);
    let a = a.clone();
    thread::Builder::new()
        .name("nmts-recovery-restore".to_string())
        .spawn(move || run_restore(shared, subset, own_quilt, PathBuf::from(out), overwrite, a))
        .map_err(|e| format!("{e}"))?;
    Ok(())
}

/// The restore itself — the same calls the terminal path makes, reporting as it goes.
fn run_restore(
    shared: Arc<Mutex<Session>>,
    manifest: RecoveryManifest,
    own_quilt: Option<String>,
    out: PathBuf,
    overwrite: bool,
    a: Args,
) {
    let lang = current_lang(&shared);
    let source: Box<dyn BlobSource> = match &a.blobs_dir {
        Some(dir) => Box::new(DirSource::new(dir)),
        // ⛔ The SAME decision the terminal makes, from the same function: which endpoints to ask
        //    now depends on what the sealed list says about its chain (owner directive, 2026-08-19), and a second copy
        //    of that rule here is how one door learns something the other never does.
        None => Box::new(HttpSource::new(crate::source::endpoints_for(
            &a.aggregators,
            &manifest,
        ))),
    };
    let planned = restore::plan(&manifest, &out, None, own_quilt.as_deref());

    for p in &planned {
        let label = format!("{}/{}", p.item.path.trim_end_matches('/'), p.item.name);
        {
            let mut s = session(&shared);
            s.job.current = label.clone();
            s.job.current_bytes = 0;
        }
        let mut on_bytes = |delta: u64| {
            let mut s = session(&shared);
            s.job.current_bytes += delta;
        };
        match restore::restore_item(p, source.as_ref(), overwrite, lang, &mut on_bytes) {
            Ok(outcome) => {
                let mut s = session(&shared);
                s.job.done += 1;
                s.job.bytes_done += outcome.bytes;
                s.job.current_bytes = 0;
                s.job.lines.push(format!("✓ {label}"));
                for note in &outcome.notes {
                    let text = match note {
                        restore::Note::PartOrderUnverifiable => {
                            msg::PART_PLACEMENT_UNVERIFIABLE.get(lang)
                        }
                        restore::Note::NoContentHash => msg::NO_HASH_NOTE.get(lang),
                        restore::Note::DateNotRestored => msg::DATE_NOT_RESTORED.get(lang),
                    };
                    s.job.lines.push(format!("   {text}"));
                }
            }
            Err(e) => {
                let mut s = session(&shared);
                s.job.failed += 1;
                s.job.current_bytes = 0;
                s.job.lines.push(format!("⛔ {label} — {e}"));
            }
        }
    }

    let mut s = session(&shared);
    s.job.current = String::new();
    s.phase = Phase::Finished;
    s.note = Some(if s.job.failed == 0 {
        msg::DONE_ALL.get(lang).to_string()
    } else {
        msg::DONE_PARTIAL.get(lang).to_string()
    });
}

/// Take the session lock, and keep going even if a thread died holding it.
///
/// ⛔ The usual advice — treat a poisoned lock as fatal — is the wrong trade here. What is behind
///    this lock is a picture of what is happening, not an invariant anything depends on; a panic in
///    one request thread must not turn the control window into a page that answers nothing while
///    the person is halfway through getting their files back. The recovery itself is guarded by the
///    checks in `restore`, which do not consult this state at all.
fn session(shared: &Arc<Mutex<Session>>) -> MutexGuard<'_, Session> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The language this run is speaking, read without holding the lock any longer than the read.
fn current_lang(shared: &Arc<Mutex<Session>>) -> Lang {
    session(shared).lang
}

fn json_ok(stream: &mut TcpStream, body: &str) {
    let _ = http::respond(
        stream,
        200,
        "application/json; charset=utf-8",
        &[],
        body.as_bytes(),
    );
}

fn bad(stream: &mut TcpStream, why: &str) {
    let body = json!({ "error": why }).to_string();
    let _ = http::respond(
        stream,
        400,
        "application/json; charset=utf-8",
        &[],
        body.as_bytes(),
    );
}

fn busy(stream: &mut TcpStream) {
    let body =
        json!({ "error": "this program is busy with the last thing you asked for" }).to_string();
    let _ = http::respond(
        stream,
        409,
        "application/json; charset=utf-8",
        &[],
        body.as_bytes(),
    );
}

fn body_json(stream: &mut TcpStream, req: &http::Request) -> Option<Value> {
    match serde_json::from_slice::<Value>(&req.body) {
        Ok(v) => Some(v),
        Err(_) => {
            bad(stream, "that request was not readable");
            None
        }
    }
}

/// Compare two strings without letting how long the comparison took say how much of them matched.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    // Length is not a secret here: the token's length is fixed and public. What must not leak is
    // where two same-length strings first differ.
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Write the page out as a file, so it can be read without running anything.
pub fn write_page(to: &Path) -> Result<(), String> {
    std::fs::write(to, PAGE.replace(NONCE_SLOT, "")).map_err(|e| format!("{}: {e}", to.display()))
}

/// Ask the desktop to open the address. Best effort — the address is printed either way.
///
/// The URL is passed as its own argument on every platform, never interpolated into a command
/// string, so nothing in it can be read as a shell instruction.
fn open_in_browser(url: &str) -> bool {
    use std::process::{Command, Stdio};
    let mut command = if cfg!(target_os = "windows") {
        // ⚠ `cmd.exe` re-parses its own command line, so this is only safe because of what the URL
        //    can contain: a fixed scheme, a fixed loopback address, a decimal port, and a token
        //    drawn from the base64url alphabet. No `&`, no `%`, no `^`, nothing `cmd` treats as
        //    syntax. If the address this program prints ever gains a variable part, this is the
        //    line that has to be looked at again.
        let mut c = Command::new("cmd");
        // The empty argument is `start`'s window title. Without it `start` reads the URL as the
        // title and opens nothing.
        c.args(["/C", "start", "", url]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_matches_only_itself() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }

    /// ⛔ Two empty strings are equal, and if that counted as a match then a request with no token
    ///    would be admitted whenever the token was somehow empty. The gate must have no such case.
    #[test]
    fn nothing_is_never_a_matching_token() {
        assert!(!constant_time_eq("", ""));
    }

    /// The page is compiled in, so a build that shipped without it would be caught here rather
    /// than by a person meeting a blank window during a recovery.
    #[test]
    fn the_page_is_present_and_carries_the_slot_the_server_fills() {
        assert!(PAGE.contains(NONCE_SLOT), "the nonce slot is gone");
        assert!(PAGE.contains("</html>"), "the page is truncated");
    }

    /// ⛔ THE PAGE MUST NOT READ A CHOSEN FILE WHOLE BEFORE IT KNOWS WHAT THE FILE IS.
    ///
    /// A recovery kit is a text file with the account code written in it, and the rule this whole
    /// program is built around is that the code is typed in the terminal and never goes near a
    /// browser. Until 2026-08-20 the picker read whatever was chosen, whole, and posted it here —
    /// so choosing a kit put the code through the browser and only then got a refusal.
    ///
    /// ⚠ This is a check on HOW THE PAGE IS WRITTEN, which is normally the weakest kind of test.
    /// It is here because the page is JavaScript that no test in this crate can execute, and
    /// because what must not happen is the ABSENCE of a guard: there is one whole-file read, and
    /// it must sit downstream of the bounded head check. Delete the guard and this goes red.
    #[test]
    fn the_page_checks_a_bounded_head_before_it_reads_a_file_whole() {
        let guard = PAGE
            .find("file.slice(0, HEAD_BYTES)")
            .expect("the bounded head check is gone — a kit would be read into the browser whole");
        assert_eq!(
            PAGE.matches("file.text()").count(),
            1,
            "there must be exactly one whole-file read to reason about",
        );
        let whole = PAGE.find("file.text()").expect("counted above");
        assert!(
            whole > guard,
            "the whole-file read must come after the head check, not before it",
        );
    }
}
