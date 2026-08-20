//! Command-line parsing, written by hand.
//!
//! # Why not a parsing crate
//! This program's entire value is that a stranger can read all of it before typing their account
//! code into it. A general-purpose argument parser is several thousand lines of someone else's
//! code sitting in front of the one input that must never leak, and it buys us derive macros and
//! shell completions we do not need for a dozen flags. A hundred lines here cost less to audit than
//! one dependency, and there is no version of this file that can surprise a reader.
//!
//! # ⛔ The account code is not an option here, and that is deliberate
//! There is no `--code` flag anywhere in this program. A secret passed as an argument is written
//! to the shell's history file, is visible in `ps` to every other user on the machine, and is
//! captured verbatim by CI logs and crash reporters. The code is read from the terminal, or from
//! a file the caller controls the permissions of. See `read_account_code` in `main.rs`.
//!
//! # English is the default, in every environment
//! Not auto-detected. A recovery may be run by whoever ends up holding the drive, on a machine
//! whose locale says nothing about who is reading the screen, and a tool that changes language
//! based on a variable is a tool whose output cannot be quoted in a bug report. `--lang ko`
//! switches it, and nothing else does.

use std::path::PathBuf;

/// What the program was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Open the list and print what it covers. No network, nothing written.
    List,
    /// Print the exact URLs a person could fetch by hand. No network, nothing written.
    FetchPlan,
    /// Fetch, decrypt, verify, and write the files out.
    Restore,
    /// Open a local control window in the browser and be driven from there.
    Gui,
    /// Write the GUI page out as a file and stop. Nothing else happens.
    WriteGui,
    /// Print what the account code derives — no list, no network, nothing written.
    Derive,
}

/// Message language. English unless `--lang ko` says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// English.
    En,
    /// Korean.
    Ko,
}

/// Everything the program was told, already validated.
#[derive(Debug, Clone)]
pub struct Args {
    pub mode: Mode,
    pub lang: Lang,
    /// The `.nmtsmap` file. Empty in [`Mode::Gui`] until the browser picks one, and when the list
    /// is to be looked for on the storage network instead ([`Args::find`]).
    pub map: PathBuf,
    /// Look the recovery list up on the storage network from the account code alone.
    ///
    /// Explicit rather than inferred from an absent `--map`, because the two mistakes are not
    /// symmetric: a mistyped path should say the file is missing, not quietly start asking public
    /// services about an address.
    pub find: bool,
    /// Sui JSON-RPC endpoints for `--find`, in order. Empty means the built-in list.
    pub rpcs: Vec<String>,
    /// The wallet address that paid for the uploads, when the account code does not derive it.
    ///
    /// For accounts that upload through a browser-extension wallet or an imported key: their blob
    /// objects are owned by an address nothing can compute from the code, so the person gives it.
    pub owner: Option<String>,
    /// Where restored files go. Required for [`Mode::Restore`]; a starting value in [`Mode::Gui`].
    pub out: Option<PathBuf>,
    /// A file holding the account code, instead of typing it.
    pub code_file: Option<PathBuf>,
    /// Aggregators to try, in order. Empty means the built-in list.
    pub aggregators: Vec<String>,
    /// May the run read from endpoints the LIST names, as well as the ones built into this program?
    ///
    /// ⛔ Off unless asked. A recovery kit carries the account code, so a kit somebody hands you is
    /// a document they sealed themselves — every field in it is theirs, including this list of
    /// hosts. Contacting one is a beacon: it tells its operator the address you recover from and
    /// the moment you did it. The bytes are authenticated either way, which protects what arrives
    /// and says nothing about the request going out.
    pub use_recorded_aggregators: bool,
    /// Read blobs from this directory instead of the network.
    pub blobs_dir: Option<PathBuf>,
    /// Restore only items whose path or name contains this text.
    pub only: Option<String>,
    /// Replace a file that already exists at the destination.
    pub overwrite: bool,
    /// Fixed port for [`Mode::Gui`]. `None` means ask the operating system for a free one.
    pub port: Option<u16>,
    /// Leave the browser alone; print the address instead.
    pub no_open: bool,
    /// Where [`Mode::WriteGui`] puts the page.
    pub gui_out: Option<PathBuf>,
    /// How many wallets [`Mode::Derive`] walks.
    pub wallets: u32,
    /// Whether [`Mode::Derive`] also prints private keys.
    pub secrets: bool,
}

/// Parsing outcome: either arguments, or text to print and an exit code.
pub enum Parsed {
    Run(Box<Args>),
    Print(String, i32),
}

/// Wallets walked by `--derive` when the caller names no number.
///
/// NMTS gives an account one wallet unless the person asked for more, so one is the answer for
/// almost everybody; `--wallets` is there for the rest.
const DEFAULT_WALLETS: u32 = 1;

/// A ceiling on `--wallets`. Each one costs a key derivation, and a number past this is a typo
/// rather than a request.
const MAX_WALLETS: u32 = 100;

const USAGE: &str = "\
nmts-recovery — restore files uploaded with NMTS, without NMTS.

USAGE
  nmts-recovery --map FILE --out DIR      restore, in the terminal
  nmts-recovery --find --out DIR          restore with only your account code
  nmts-recovery --gui                     restore, from a page in your browser
  nmts-recovery --map FILE --list         show what a list covers and stop
  nmts-recovery --derive                  show what your account code derives

WHAT IT NEEDS
  Your account code, and your recovery list. The list is encrypted; the code opens
  it. You can hand over the file you saved from NMTS, or use --find and let this
  program look the list up on the storage network.

WHAT GOES OUT
  Your account code never goes out. Keys are derived from it here and it is not part
  of any request this program makes.
  Every restore asks a public Walrus aggregator for blobs by their public ids.
  --print-fetch-plan prints those requests so you can make them yourself, and
  --blobs-dir then reads what you fetched, so the program opens no socket at all.
  --find asks a public Sui node which blobs a wallet owns, and the wallet address and
  the name it looks for are BOTH derived from your account code. Neither server can
  work back to the code, but asking tells them somebody is looking for this account's
  files, from this address, right now. --rpc names your own node; --map avoids it.
  A recovery list can name storage addresses of its own. Those are not contacted
  unless you ask, with --use-recorded-aggregators.

OPTIONS
  --map FILE           the recovery list (.nmtsmap) you saved, OR a recovery kit
                       (.txt), which has the list inside it. Required unless --find,
                       --gui or --derive.
  --find               look the recovery list up on the storage network using your
                       account code alone — no saved file needed. Works when the
                       account turned the storage-network copy on and paid with the
                       wallet the account code derives.
  --rpc URL            a Sui node for --find to ask. Repeatable; tried in order.
  --owner 0xADDRESS    with --find, the wallet that paid for the uploads. Needed only
                       when that wallet is a browser extension or an imported key,
                       because the account code cannot derive such an address.
  --out DIR            where to write recovered files. Required when restoring.
  --code-file FILE     read the account code from a file instead of typing it.
  --aggregator URL     a Walrus aggregator to read from. Repeatable; tried in order.
  --use-recorded-aggregators
                       also read from the storage addresses written inside the
                       recovery list itself. Off by default: whoever sealed the list
                       chose those addresses, and contacting one tells its operator
                       where and when you recovered. The run names them either way.
  --blobs-dir DIR      read blobs from a directory instead of the network. Each file
                       is named after its blob id (or quilt patch id).
  --only TEXT          restore only files whose path or name contains TEXT.
  --overwrite          replace files that already exist. Off by default.
  --list               print what the list covers and stop. No network.
  --print-fetch-plan   print the URLs to fetch by hand, and stop. No network.
  --gui                serve a control page on this machine and open it. The page
                       cannot be reached from anywhere else, and your account code
                       is still typed here in the terminal, never in the browser.
  --port N             fixed port for --gui. Default: whatever is free.
  --no-open            with --gui, print the address instead of opening a browser.
  --write-gui FILE     write the control page out as a file and stop, so you can
                       read it. Opening that file on its own does nothing.
  --derive             print what your account code derives — the account id, its
                       fingerprint, your public code, and your wallet addresses.
                       No list, no network, nothing written.
  --wallets N          how many wallets --derive walks, and how many --find looks
                       under. Default: 1.
  --secrets            with --derive, also print the wallet private keys. Anyone
                       who reads them can spend from those wallets.
  --lang en|ko         message language. Default: en.
  --help               this text.
  --version            version and license.

THE ACCOUNT CODE IS NEVER AN ARGUMENT. It is typed when this program asks, or read
from --code-file. An argument would land in your shell history and be visible to every
other user on the machine.
";

/// Parse `argv` (without the program name).
pub fn parse(argv: &[String]) -> Parsed {
    let mut a = Args {
        mode: Mode::Restore,
        lang: Lang::En,
        map: PathBuf::new(),
        find: false,
        rpcs: Vec::new(),
        owner: None,
        out: None,
        code_file: None,
        aggregators: Vec::new(),
        use_recorded_aggregators: false,
        blobs_dir: None,
        only: None,
        overwrite: false,
        port: None,
        no_open: false,
        gui_out: None,
        wallets: DEFAULT_WALLETS,
        secrets: false,
    };
    let mut map_seen = false;

    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        // A flag needing a value: return it and step past both.
        let value = |name: &str| -> Result<String, String> {
            match argv.get(i + 1) {
                Some(v) if !v.starts_with("--") => Ok(v.clone()),
                _ => Err(format!("{name} needs a value.")),
            }
        };
        let taken = match arg {
            "--help" | "-h" => return Parsed::Print(USAGE.to_string(), 0),
            "--version" | "-V" => {
                // ⭐ The list format ceiling is printed beside the program's own number, because
                //    that is the question a person actually has: "will my copy open this list?"
                //    A recovery list says which format it is, and a build that predates it stops
                //    rather than guessing — so the two numbers together are the whole answer, and
                //    neither is guessable from the other.
                return Parsed::Print(
                    format!(
                        "nmts-recovery {} — AGPL-3.0-only\nreads recovery lists up to NRM-{}\n",
                        env!("CARGO_PKG_VERSION"),
                        crate::mapfile::MAX_NRM_VERSION
                    ),
                    0,
                );
            }
            "--list" => {
                a.mode = Mode::List;
                1
            }
            "--print-fetch-plan" => {
                a.mode = Mode::FetchPlan;
                1
            }
            "--gui" => {
                a.mode = Mode::Gui;
                1
            }
            "--derive" => {
                a.mode = Mode::Derive;
                1
            }
            "--find" => {
                a.find = true;
                1
            }
            "--secrets" => {
                a.secrets = true;
                1
            }
            "--overwrite" => {
                a.overwrite = true;
                1
            }
            "--use-recorded-aggregators" => {
                a.use_recorded_aggregators = true;
                1
            }
            "--no-open" => {
                a.no_open = true;
                1
            }
            "--map" => match value("--map") {
                Ok(v) => {
                    a.map = PathBuf::from(v);
                    map_seen = true;
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--out" => match value("--out") {
                Ok(v) => {
                    a.out = Some(PathBuf::from(v));
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--code-file" => match value("--code-file") {
                Ok(v) => {
                    a.code_file = Some(PathBuf::from(v));
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--blobs-dir" => match value("--blobs-dir") {
                Ok(v) => {
                    a.blobs_dir = Some(PathBuf::from(v));
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--rpc" => match value("--rpc") {
                Ok(v) => {
                    a.rpcs.push(v.trim_end_matches('/').to_string());
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--owner" => match value("--owner") {
                Ok(v) => {
                    a.owner = Some(v.to_string());
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--aggregator" => match value("--aggregator") {
                Ok(v) => {
                    a.aggregators.push(v.trim_end_matches('/').to_string());
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--only" => match value("--only") {
                Ok(v) => {
                    a.only = Some(v);
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--write-gui" => match value("--write-gui") {
                Ok(v) => {
                    a.mode = Mode::WriteGui;
                    a.gui_out = Some(PathBuf::from(v));
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--wallets" => match value("--wallets") {
                Ok(v) => match v.parse::<u32>() {
                    Ok(n) if (1..=MAX_WALLETS).contains(&n) => {
                        a.wallets = n;
                        2
                    }
                    _ => {
                        return Parsed::Print(
                            format!("--wallets takes a number from 1 to {MAX_WALLETS}."),
                            2,
                        )
                    }
                },
                Err(e) => return Parsed::Print(e, 2),
            },
            "--port" => match value("--port") {
                Ok(v) => match v.parse::<u16>() {
                    // Port 0 means "any free port" to the operating system, which is the default
                    // anyway; accepting it as an explicit request would make `--port 0` print an
                    // address the caller did not ask for and could not have predicted.
                    Ok(p) if p > 0 => {
                        a.port = Some(p);
                        2
                    }
                    _ => return Parsed::Print(format!("--port does not understand \"{v}\"."), 2),
                },
                Err(e) => return Parsed::Print(e, 2),
            },
            "--lang" => match value("--lang") {
                Ok(v) if v == "ko" => {
                    a.lang = Lang::Ko;
                    2
                }
                Ok(v) if v == "en" => {
                    a.lang = Lang::En;
                    2
                }
                Ok(v) => return Parsed::Print(format!("--lang does not know \"{v}\"."), 2),
                Err(e) => return Parsed::Print(e, 2),
            },
            // ⛔ The one argument this program refuses on purpose. Saying so beats an "unknown
            //    option" that reads as a typo and invites the caller to look for the right
            //    spelling of a flag that must never exist.
            "--code" | "--account-code" => {
                return Parsed::Print(
                    "The account code is not an argument: it would be written to your shell \
                     history and visible to other users on this machine. Run without it and let \
                     this program ask for it, or use --code-file.\n"
                        .to_string(),
                    2,
                )
            }
            other => return Parsed::Print(format!("Unknown option \"{other}\".\n\n{USAGE}"), 2),
        };
        i += taken;
    }

    // The GUI picks its list in the browser, writing the page out reads nothing, and deriving
    // needs only the account code.
    let map_optional = matches!(a.mode, Mode::Gui | Mode::WriteGui | Mode::Derive) || a.find;
    if !map_seen && !map_optional {
        return Parsed::Print(
            format!("--map is required, or --find to look the list up on the storage network.\n\n{USAGE}"),
            2,
        );
    }
    // Both at once is a person telling the program two different places to get the same document.
    // Picking one would work most of the time and be wrong exactly when it mattered.
    if map_seen && a.find {
        return Parsed::Print(
            format!("--map and --find both say where the recovery list is. Use one.\n\n{USAGE}"),
            2,
        );
    }
    if a.owner.is_some() && !a.find {
        return Parsed::Print(
            format!("--owner only means something with --find.\n\n{USAGE}"),
            2,
        );
    }
    if a.mode == Mode::Restore && a.out.is_none() {
        return Parsed::Print(format!("--out is required when restoring.\n\n{USAGE}"), 2);
    }
    Parsed::Run(Box::new(a))
}

#[cfg(test)]
mod tests {
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

    /// Deriving needs the account code and nothing else — no list, no network, no destination.
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
    /// ⛔ EVERY PART OF THIS PROGRAM THAT OPENS A SOCKET IS NAMED IN THE HELP.
    ///
    /// The help used to end its "what it needs" paragraph with *"Neither is ever sent anywhere"*.
    /// That sentence was true about the two things it named — the account code and the list — and
    /// false about the impression it left, because `--find` asks a public Sui node a question
    /// derived from the account code. A person deciding whether to type `--find` read the reassuring
    /// sentence and had nowhere else to look; the README's correcting paragraph is not in the
    /// terminal.
    ///
    /// So the rule is not "do not write that sentence" — anyone can reword their way past a banned
    /// phrase. It is: **the set of source files that call the HTTP client must equal the set the
    /// help describes.** Adding a third destination turns this red until both the table below and
    /// the help have been told about it.
    #[test]
    fn every_part_of_this_program_that_opens_a_socket_is_named_in_the_help() {
        // file stem → the phrase in the help that describes what it contacts.
        const NAMED: [(&str, &str); 2] =
            [("source", "Walrus aggregator"), ("discover", "Sui node")];
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut opens_a_socket: Vec<String> = Vec::new();
        let mut stack = vec![dir];
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
                // Spelled in two pieces so THIS file does not match its own search and report
                // itself as a thing that opens sockets.
                if text.contains(concat!("ureq", "::")) {
                    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                    opens_a_socket.push(stem.to_string());
                }
            }
        }
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
}
