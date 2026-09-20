//! Tests for [`crate::args`] — the hand-written command line.
//!
//! ⛔ ITS OWN FILE BECAUSE `args.rs` HAS A CEILING. `check:size` holds Rust files to 700 lines,
//!    and the wallet flags did not fit beside 300 lines of tests. Nothing about the tests moved:
//!    they are still `mod tests` inside the module (`#[cfg(test)] #[path = "args_tests.rs"] mod
//!    tests;`), so `super::*` reaches `USAGE` and the private constants exactly as before — and the
//!    network test below still spells no crate name, which is the property that made it work.

use super::*;

fn v(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

#[test]
fn map_is_required() {
    assert!(matches!(parse(&v(&["--list"])), Parsed::Print(_, 2)));
}

#[test]
fn restoring_needs_a_destination() {
    assert!(matches!(
        parse(&v(&["--map", "m.nmtsmap"])),
        Parsed::Print(_, 2)
    ));
}

#[test]
fn listing_does_not_need_a_destination() {
    assert!(matches!(
        parse(&v(&["--map", "m.nmtsmap", "--list"])),
        Parsed::Run(_)
    ));
}

/// The browser picks the list, so requiring one on the command line would mean typing a path
/// into a terminal to avoid typing a path into a terminal.
#[test]
fn the_gui_does_not_need_a_map_up_front() {
    match parse(&v(&["--gui"])) {
        Parsed::Run(a) => assert_eq!(a.mode, Mode::Gui),
        Parsed::Print(msg, _) => panic!("--gui was refused: {msg}"),
    }
}

/// ⛔ The refusal is the feature. If this ever passes as an ordinary flag, a secret starts
///    landing in shell histories.
#[test]
fn the_account_code_cannot_be_passed_as_an_argument() {
    match parse(&v(&["--map", "m.nmtsmap", "--code", "ABC"])) {
        Parsed::Print(msg, 2) => assert!(msg.contains("shell history")),
        _ => panic!("--code was accepted"),
    }
}

/// ⛔ English regardless of the environment. A tool that changes language on its own produces
///    output nobody can quote in a bug report, and the person reading the screen during a
///    recovery is not necessarily the person whose machine it is.
#[test]
fn english_is_the_default_and_only_a_flag_changes_it() {
    match parse(&v(&["--map", "m", "--list"])) {
        Parsed::Run(a) => assert_eq!(a.lang, Lang::En),
        _ => panic!("did not parse"),
    }
    match parse(&v(&["--map", "m", "--list", "--lang", "ko"])) {
        Parsed::Run(a) => assert_eq!(a.lang, Lang::Ko),
        _ => panic!("did not parse"),
    }
}

#[test]
fn a_flag_missing_its_value_is_refused_rather_than_swallowing_the_next_flag() {
    match parse(&v(&["--map", "--list"])) {
        Parsed::Print(msg, 2) => assert!(msg.contains("--map needs a value")),
        _ => panic!("--map swallowed --list"),
    }
}

#[test]
fn aggregators_keep_their_order_and_lose_a_trailing_slash() {
    match parse(&v(&[
        "--map",
        "m",
        "--list",
        "--aggregator",
        "https://a.example/",
        "--aggregator",
        "https://b.example",
    ])) {
        Parsed::Run(a) => {
            assert_eq!(
                a.aggregators,
                vec!["https://a.example", "https://b.example"]
            );
        }
        _ => panic!("did not parse"),
    }
}

/// Deriving needs the NMTS key and nothing else — no list, no network, no destination.
#[test]
fn deriving_needs_no_map_and_no_destination() {
    match parse(&v(&["--derive"])) {
        Parsed::Run(a) => {
            assert_eq!(a.mode, Mode::Derive);
            assert_eq!(a.wallets, 1);
            assert!(!a.secrets, "private keys are not the default");
        }
        Parsed::Print(msg, _) => panic!("--derive was refused: {msg}"),
    }
}

#[test]
fn a_wallet_count_that_is_not_one_is_refused() {
    for bad in ["0", "no", "1000"] {
        assert!(
            matches!(
                parse(&v(&["--derive", "--wallets", bad])),
                Parsed::Print(_, 2)
            ),
            "--wallets {bad} was accepted"
        );
    }
    match parse(&v(&["--derive", "--ai-accounts", "--depth", "2"])) {
        Parsed::Run(a) => {
            assert!(a.ai_accounts);
            assert_eq!(a.ai_depth, 2);
        }
        Parsed::Print(msg, _) => panic!("--ai-accounts was refused: {msg}"),
    }
    for bad in ["0", "3", "no"] {
        assert!(
            matches!(
                parse(&v(&["--derive", "--ai-accounts", "--depth", bad])),
                Parsed::Print(_, 2)
            ),
            "--depth {bad} was accepted"
        );
    }
    match parse(&v(&["--derive"])) {
        Parsed::Run(a) => assert!(!a.ai_accounts, "AI accounts' keys are not the default"),
        Parsed::Print(msg, _) => panic!("--derive was refused: {msg}"),
    }
    match parse(&v(&["--derive", "--wallets", "5", "--secrets"])) {
        Parsed::Run(a) => {
            assert_eq!(a.wallets, 5);
            assert!(a.secrets);
        }
        _ => panic!("did not parse"),
    }
}

#[test]
fn a_port_that_is_not_a_port_is_refused() {
    assert!(matches!(
        parse(&v(&["--gui", "--port", "no"])),
        Parsed::Print(_, 2)
    ));
    assert!(matches!(
        parse(&v(&["--gui", "--port", "70000"])),
        Parsed::Print(_, 2)
    ));
    match parse(&v(&["--gui", "--port", "8765"])) {
        Parsed::Run(a) => assert_eq!(a.port, Some(8765)),
        _ => panic!("did not parse"),
    }
}

/// The crate names `Cargo.toml` marks as the ones that talk to the network.
///
/// ⛔ THE NAME IS READ, NOT WRITTEN HERE. See the marker's own comment in `Cargo.toml`. If
///    nothing is marked this fails rather than returning an empty list: an empty list would
///    make the search below find no files, and a found set of nothing compared against a
///    table of two would look like an ordinary red — but a found set of nothing compared
///    against a table someone had emptied at the same time would look like health.
fn crates_that_talk_to_the_network(cargo_toml: &std::path::Path) -> Vec<String> {
    const MARKER: &str = "@opens-sockets";
    let text = std::fs::read_to_string(cargo_toml).expect("read Cargo.toml");
    let mut names: Vec<String> = Vec::new();
    let mut marked = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            marked |= line.contains(MARKER);
            continue;
        }
        if !marked {
            continue;
        }
        marked = false;
        let key = line.split_once('=').map_or("", |(k, _)| k.trim());
        assert!(
            !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "the {MARKER} marker is not sitting on a dependency line — it points at: {line}"
        );
        // A dependency written with a dash is spelled with an underscore in Rust source.
        names.push(key.replace('-', "_"));
    }
    assert!(
        !marked,
        "a {MARKER} marker in Cargo.toml has no dependency under it"
    );
    assert!(
        !names.is_empty(),
        "no dependency in Cargo.toml carries the {MARKER} marker, so the test below has no \
         name to search the source for"
    );
    names
}

/// ⛔ EVERY PART OF THIS PROGRAM THAT OPENS A SOCKET IS NAMED IN THE HELP.
///
/// The help used to end its "what it needs" paragraph with *"Neither is ever sent anywhere"*.
/// That sentence was true about the two things it named — the NMTS key and the list — and
/// false about the impression it left, because `--find` asks a public Sui node a question
/// derived from the NMTS key. A person deciding whether to type `--find` read the reassuring
/// sentence and had nowhere else to look; the README's correcting paragraph is not in the
/// terminal.
///
/// So the rule is not "do not write that sentence" — anyone can reword their way past a banned
/// phrase. It is: **the set of source files that call the HTTP client must equal the set the
/// help describes.** Adding a third destination turns this red until both the table below and
/// the help have been told about it.
///
/// ⚠ Which files those are is decided by two things this test no longer writes down itself:
///   the client crate's NAME, which comes from the `@opens-sockets` marker in `Cargo.toml`,
///   and the three ways a Rust file can name a crate — a path through it, an import of it, and
///   an import that renames it, including inside a brace group. The
///   version before this one searched for one hard-coded spelling, the crate's name followed
///   by two colons. A file that imported the same crate under a different name and then called
///   it by that other name reached the network without ever containing the thing being
///   searched for: invisible here, the found set still equal to the table, and the help green
///   while a third destination existed. Measured — with the old search that file passed.
///
/// ⚠ THE CLIENT CRATE IS NOT SPELLED ANYWHERE IN THIS FILE, and that is deliberate. This is
///   the third gate in this repository to learn that a test which reads source code must think
///   about ITSELF first: written out, the name in a sentence like the one above is indexed by
///   this very search, and the test reports the file it lives in as a thing that opens sockets.
#[test]
fn every_part_of_this_program_that_opens_a_socket_is_named_in_the_help() {
    // file stem → the phrase in the help that describes what it contacts.
    const NAMED: [(&str, &str); 2] = [("source", "Walrus aggregator"), ("discover", "Sui node")];
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let clients = crates_that_talk_to_the_network(&crate_dir.join("Cargo.toml"));
    // The three ways a file can name a crate: a path through it, an import of it, and an
    // import that renames it. Built here from the name that was just read, so no spelling of
    // the client is written in this file at all — which is also why this test cannot match its
    // own search the way an ordinary needle would.
    //
    // ⚠ The third form is not a duplicate of the second. An import group puts the rename
    //   inside braces — `use {std::time::Duration, name as web};` — and that line contains
    //   neither a path through the crate nor an import beginning with its name. Measured with
    //   only the first two forms: a module written that way called the network from a file
    //   this test judged and reported as clean, and the run was green.
    let needles: Vec<String> = clients
        .iter()
        .flat_map(|c| [format!("{c}::"), format!("use {c}"), format!("{c} as ")])
        .collect();
    let mut judged = 0usize;
    let mut opens_a_socket: Vec<String> = Vec::new();
    let mut stack = vec![crate_dir.join("src")];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("read src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read");
            judged += 1;
            if needles.iter().any(|n| text.contains(n.as_str())) {
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                opens_a_socket.push(stem.to_string());
            }
        }
    }
    println!(
        "{judged} source files judged against {} network crate name(s): {}",
        clients.len(),
        clients.join(", ")
    );
    // ⚠ A floor, because a search that reads nothing agrees with everything. Set below what
    //   the crate holds today, so growth is free and a walk that stops walking is not.
    assert!(
        judged >= 8,
        "only {judged} source files were read — this test walked less of src/ than the crate \
         has, so its answer is about nothing"
    );
    opens_a_socket.sort();
    let mut expected: Vec<String> = NAMED.iter().map(|(f, _)| (*f).to_string()).collect();
    expected.sort();
    assert_eq!(
        opens_a_socket, expected,
        "a source file that talks to the network is not in this test's table — add it here \
         AND say in the help what it contacts"
    );
    // ⚠ THE PHRASE MUST BE INSIDE THE OUTBOUND BLOCK, not merely somewhere in the help
    //   (learned while writing this: "Sui node" also appears in the `--rpc` option line, so
    //   the first version of this check stayed green with the sentence deleted).
    let start = USAGE
        .find("WHAT GOES OUT")
        .expect("the help lost its outbound section");
    let block = &USAGE[start..];
    let block = match block.find("\n\nOPTIONS") {
        Some(end) => &block[..end],
        None => block,
    };
    for (file, phrase) in NAMED {
        assert!(
            block.contains(phrase),
            "{file}.rs opens a socket and WHAT GOES OUT never says so: \"{phrase}\" is missing"
        );
    }
}
