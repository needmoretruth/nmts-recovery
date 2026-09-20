//! Command-line parsing, written by hand.
//!
//! # Why not a parsing crate
//! This program's entire value is that a stranger can read all of it before typing their NMTS
//! key into it. A general-purpose argument parser is several thousand lines of someone else's
//! code sitting in front of the one input that must never leak, and it buys us derive macros and
//! shell completions we do not need for a dozen flags. A hundred lines here cost less to audit than
//! one dependency, and there is no version of this file that can surprise a reader.
//!
//! # ⛔ The NMTS key is not an option here, and that is deliberate
//! There is no `--code` flag anywhere in this program. A secret passed as an argument is written
//! to the shell's history file, is visible in `ps` to every other user on the machine, and is
//! captured verbatim by CI logs and crash reporters. The key is read from the terminal, or from
//! a file the caller controls the permissions of. See `read_account_code` in `main.rs`.
//!
//! The same rule covers the wallet signature that opens a slot, because it unwraps the same key:
//! there is no `--wallet-signature`, only `--wallet-signature-file`. Both spellings are refused by
//! name rather than as unknown options, so the answer is the road to take and not a spelling hunt.
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
    /// Print what the NMTS key derives — no list, no network, nothing written.
    Derive,
    /// Write out the exact bytes a wallet must sign. No key, no list, no network.
    PrintWalletMessage,
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
    /// Look the recovery list up on the storage network from the NMTS key alone.
    ///
    /// Explicit rather than inferred from an absent `--map`, because the two mistakes are not
    /// symmetric: a mistyped path should say the file is missing, not quietly start asking public
    /// services about an address.
    pub find: bool,
    /// Sui JSON-RPC endpoints for `--find`, in order. Empty means the built-in list.
    pub rpcs: Vec<String>,
    /// The wallet address that paid for the uploads, when the NMTS key does not derive it.
    ///
    /// For accounts that upload through a browser-extension wallet or an imported key: their blob
    /// objects are owned by an address nothing can compute from the key, so the person gives it.
    pub owner: Option<String>,
    /// Where restored files go. Required for [`Mode::Restore`]; a starting value in [`Mode::Gui`].
    pub out: Option<PathBuf>,
    /// A file holding the NMTS key, instead of typing it.
    pub code_file: Option<PathBuf>,
    /// Aggregators to try, in order. Empty means the built-in list.
    pub aggregators: Vec<String>,
    /// May the run read from endpoints the LIST names, as well as the ones built into this program?
    ///
    /// ⛔ Off unless asked. A recovery kit carries the NMTS key, so a kit somebody hands you is
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
    /// Whether [`Mode::Derive`] also prints the AI accounts' NMTS keys (NCF-3 §1.5).
    pub ai_accounts: bool,
    /// How many levels of AI accounts `--ai-accounts` walks. 1 = three keys, 2 = twelve.
    pub ai_depth: u32,
    /// The address whose sign-in message [`Mode::PrintWalletMessage`] writes out (NCF-3 §1.7).
    pub wallet_message_address: Option<String>,
    /// The `Account:` line of that message. Inside the signed bytes, so it decides the slot.
    pub wallet_account: u32,
    /// The optional `App:` line of that message. Also inside the signed bytes.
    pub wallet_app: Option<String>,
    /// The slot file a wallet's signature opens, standing in for a typed NMTS key.
    pub wallet_slot: Option<PathBuf>,
    /// A file holding the serialized signature. The only road: a signature is key material, and
    /// `--wallet-signature` is refused for the reason `--code` is.
    pub wallet_signature_file: Option<PathBuf>,
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

/// Levels of AI accounts walked when `--ai-accounts` names no depth.
const DEFAULT_AI_DEPTH: u32 = 1;

/// The `Account:` line's number when `--wallet-account` names none.
///
/// ⚠ One, because an account is numbered from 1 and almost every wallet opens the first. The
/// number is INSIDE the signed bytes, so a default that drifted would print a message that signs
/// to a different slot — which is why it is a named constant rather than a literal in two places.
const DEFAULT_WALLET_ACCOUNT: u32 = 1;

/// A ceiling on `--depth`. Two is the whole tree the product can create (product rule of 2026-09-06: three accounts,
/// and three under each). Deeper costs a full Argon2id pass per account for codes nothing made.
const MAX_AI_DEPTH: u32 = 2;

// The facts the OPENING WITH A WALLET block below has to carry, if it is ever reworded: a slot file is 62 bytes, holds the NMTS key wrapped
//   under a wallet's signature, and is downloaded from the account screen; opening one contacts
//   nothing; the signature must be made with the wallet's PERSONAL MESSAGE signing (Sui's
//   PersonalMessage intent, what a wallet calls "sign message"), because a transaction-intent
//   signature over the same text hashes different bytes and will not open the slot; the message
//   must be signed exactly as printed, with no trailing newline added; and a signature is never an
//   argument, for the reason the NMTS key is never one.
const USAGE: &str = "\
nmts-recovery — restore files uploaded with NMTS, without NMTS.

USAGE
  nmts-recovery --map FILE --out DIR      restore, in the terminal
  nmts-recovery --find --out DIR          restore with only your NMTS key
  nmts-recovery --gui                     restore, from a page in your browser
  nmts-recovery --map FILE --list         show what a list covers and stop
  nmts-recovery --derive                  show what your NMTS key derives
  nmts-recovery --print-wallet-message 0xADDRESS > message.txt
                                          the exact text your wallet must sign

WHAT IT NEEDS
  Your NMTS key, and your recovery list. The list is encrypted; the key opens
  it. You can hand over the file you saved from NMTS, or use --find and let this
  program look the list up on the storage network.

WHAT GOES OUT
  Your NMTS key never goes out. Keys are derived from it here and it is not part
  of any request this program makes.
  Every restore asks a public Walrus aggregator for blobs by their public ids.
  --print-fetch-plan prints those requests so you can make them yourself, and
  --blobs-dir then reads what you fetched, so the program opens no socket at all.
  --find asks a public Sui node which blobs a wallet owns, and the wallet address and
  the name it looks for are BOTH derived from your NMTS key. Neither server can
  work back to the key, but asking tells them somebody is looking for this account's
  files, from this address, right now. --rpc names your own node; --map avoids it.
  A recovery list can name storage addresses of its own. Those are not contacted
  unless you ask, with --use-recorded-aggregators.
  A wallet recovery file and the signature that opens it are read on this machine
  and go nowhere. No NMTS server is contacted for either, and neither is --print-wallet-message.

OPTIONS
  --map FILE           the recovery list (.nmtsmap) you saved, OR a recovery kit
                       (.txt), which has the list inside it. Required unless --find,
                       --gui or --derive.
  --find               look the recovery list up on the storage network using your
                       NMTS key alone — no saved file needed. Works when the account
                       turned the storage-network copy on and paid with the wallet
                       the NMTS key derives.
  --rpc URL            a Sui node for --find to ask. Repeatable; tried in order.
  --owner 0xADDRESS    with --find, the wallet that paid for the uploads. Needed only
                       when that wallet is a browser extension or an imported key,
                       because the NMTS key cannot derive such an address.
  --out DIR            where to write recovered files. Required when restoring.
  --code-file FILE     read your NMTS key from a file instead of typing it (same flag name).
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
                       cannot be reached from anywhere else, and your NMTS key is
                       still typed here in the terminal, never in the browser.
  --port N             fixed port for --gui. Default: whatever is free.
  --no-open            with --gui, print the address instead of opening a browser.
  --write-gui FILE     write the control page out as a file and stop, so you can
                       read it. Opening that file on its own does nothing.
  --derive             print what your NMTS key derives — the account id, its
                       fingerprint, your public code, and your wallet addresses.
                       No list, no network, nothing written.
  --wallets N          how many wallets --derive walks, and how many --find looks
                       under. Default: 1.
  --secrets            with --derive, also print the wallet private keys. Anyone
                       who reads them can spend from those wallets.
  --ai-accounts        with --derive, also print the NMTS keys of the AI accounts
                       your key makes. Each one is a full NMTS key: whoever reads
                       it is that sub-account.
  --depth N            how many levels --ai-accounts walks. 1 (default) prints
                       three keys; 2 prints those and the nine under them.
  --lang en|ko         message language. Default: en.
  --help               this text.
  --version            version and license.

OPENING WITH A WALLET
  A wallet recovery file comes from your NMTS account screen. It holds your NMTS
  key, locked so that only your wallet's signature of one message opens it. This
  program opens it with no NMTS key typed and nothing contacted. Your wallet must
  sign the message as a PERSONAL MESSAGE, byte for byte as printed; a transaction
  signature over the same text is made of different bytes and will not open it.
  --print-wallet-message 0xADDRESS
                       write the exact bytes your wallet must sign to the screen,
                       and stop. Redirect it to a file to keep it byte for byte.
  --wallet-account N   the account number inside that message. Default: 1.
  --wallet-app NAME    the optional product scope inside that message.
  --wallet-slot FILE   the wallet recovery file you saved from your NMTS account
                       screen. With the signature below it gives the NMTS key, so
                       nothing is typed. Takes the place of --code-file.
  --wallet-signature-file FILE
                       the signature your wallet returned, in a file. Base64 or hex.
                       There is no --wallet-signature: that signature opens your
                       account, and an argument lands in your shell history and is
                       visible to every other user on this machine.

THE NMTS KEY IS NEVER AN ARGUMENT. It is typed when this program asks, or read
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
        ai_accounts: false,
        ai_depth: DEFAULT_AI_DEPTH,
        wallet_message_address: None,
        wallet_account: DEFAULT_WALLET_ACCOUNT,
        wallet_app: None,
        wallet_slot: None,
        wallet_signature_file: None,
    };
    let mut map_seen = false;
    let mut wallet_account_seen = false;

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
                        "nmts-recovery {} — Apache-2.0\nreads recovery lists up to NRM-{}\n",
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
            "--ai-accounts" => {
                a.ai_accounts = true;
                1
            }
            "--depth" => match value("--depth") {
                Ok(v) => match v.parse::<u32>() {
                    Ok(n) if (1..=MAX_AI_DEPTH).contains(&n) => {
                        a.ai_depth = n;
                        2
                    }
                    _ => {
                        return Parsed::Print(
                            format!("--depth takes a number from 1 to {MAX_AI_DEPTH}."),
                            2,
                        )
                    }
                },
                Err(e) => return Parsed::Print(e, 2),
            },
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
            "--print-wallet-message" => match value("--print-wallet-message") {
                Ok(v) => {
                    a.mode = Mode::PrintWalletMessage;
                    // ⛔ Not checked here. `0x` + 64 lowercase hex is the engine's rule, the
                    //    address sits inside the bytes a person reads in the wallet popup, and a
                    //    second copy of that rule in this file is a second thing to drift.
                    a.wallet_message_address = Some(v);
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--wallet-account" => match value("--wallet-account") {
                Ok(v) => match v.parse::<u32>() {
                    Ok(n) => {
                        // Zero is left to the engine, which refuses it with its own reason. This
                        // only catches what is not a number at all.
                        a.wallet_account = n;
                        wallet_account_seen = true;
                        2
                    }
                    _ => {
                        return Parsed::Print(
                            format!("--wallet-account does not understand \"{v}\"."),
                            2,
                        )
                    }
                },
                Err(e) => return Parsed::Print(e, 2),
            },
            "--wallet-app" => match value("--wallet-app") {
                Ok(v) => {
                    a.wallet_app = Some(v);
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--wallet-slot" => match value("--wallet-slot") {
                Ok(v) => {
                    a.wallet_slot = Some(PathBuf::from(v));
                    2
                }
                Err(e) => return Parsed::Print(e, 2),
            },
            "--wallet-signature-file" => match value("--wallet-signature-file") {
                Ok(v) => {
                    a.wallet_signature_file = Some(PathBuf::from(v));
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
            // ⛔ The arguments this program refuses on purpose. Saying so beats an "unknown
            //    option" that reads as a typo and invites the caller to look for the right
            //    spelling of a flag that must never exist.
            "--code" | "--account-code" => {
                return Parsed::Print(
                    "Your NMTS key is not an argument: it would be written to your shell \
                     history and visible to other users on this machine. Run without it and let \
                     this program ask for it, or use --code-file.\n"
                        .to_string(),
                    2,
                )
            }
            // ⛔ A wallet's signature unwraps the NMTS key, so it is key material and the rule
            //    above is the rule here: whoever holds it holds the account for as long as the
            //    slot exists, and an argument is the one place a secret cannot be taken back from.
            "--wallet-signature" => {
                return Parsed::Print(
                    "A wallet signature is not an argument: it opens the file that holds your \
                     NMTS key, and as an argument it would be written to your shell history and visible to other \
                     users on this machine. Put it in a file and use --wallet-signature-file.\n"
                        .to_string(),
                    2,
                )
            }
            other => return Parsed::Print(format!("Unknown option \"{other}\".\n\n{USAGE}"), 2),
        };
        i += taken;
    }

    // The GUI picks its list in the browser, writing the page out reads nothing, and deriving
    // needs only the NMTS key.
    let map_optional = matches!(
        a.mode,
        Mode::Gui | Mode::WriteGui | Mode::Derive | Mode::PrintWalletMessage
    ) || a.find;
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
    // ── The wallet road: a slot and the signature that opens it, or neither ──────────────────
    //
    // Every check here is the same shape as the ones above: two flags that say the same thing are
    // refused rather than ranked, and a half of a pair is named by its missing half. A slot
    // without a signature would otherwise fall through to the NMTS-key prompt, and the person
    // would type the secret they had just arranged not to need.
    let signature_seen = a.wallet_signature_file.is_some();
    if a.wallet_slot.is_some() && !signature_seen {
        return Parsed::Print(
            format!("--wallet-slot needs the signature that opens it: --wallet-signature-file FILE.\n\n{USAGE}"),
            2,
        );
    }
    if signature_seen && a.wallet_slot.is_none() {
        return Parsed::Print(
            format!("a wallet signature only means something with --wallet-slot.\n\n{USAGE}"),
            2,
        );
    }
    if a.wallet_slot.is_some() && a.code_file.is_some() {
        return Parsed::Print(
            format!("--wallet-slot and --code-file both say where your NMTS key comes from. Use one.\n\n{USAGE}"),
            2,
        );
    }
    // ⚠ Both of these are lines of the SIGNED MESSAGE and nothing else reads them. Accepted
    //   quietly elsewhere, they would look like they had been applied to an opening that never
    //   saw them.
    if (wallet_account_seen || a.wallet_app.is_some()) && a.mode != Mode::PrintWalletMessage {
        return Parsed::Print(
            format!("--wallet-account and --wallet-app only mean something with --print-wallet-message.\n\n{USAGE}"),
            2,
        );
    }
    Parsed::Run(Box::new(a))
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
