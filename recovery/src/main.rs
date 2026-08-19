//! # nmts-recovery — get your files back without NMTS
//!
//! NMTS encrypts every file in the browser before it is uploaded, and the keys come from the
//! account code. That design has an obligation attached to it: if NMTS disappears, the files must
//! still be recoverable, and the person must not have to take our word for it. This program is
//! that obligation, discharged — it needs the account code and the recovery list, reads public
//! Walrus aggregators, and **contacts no NMTS server at any point**.
//!
//! ## Two ways to run it, one program underneath
//! * In the terminal: `--map FILE --out DIR`, and everything is printed as it happens.
//! * From a browser: `--gui` opens a control window served to this machine only. The window shows
//!   what the list holds and sends back which files were ticked; every key, every fetch, every
//!   decryption and every write still happens here. See `gui/mod.rs`.
//!
//! ## What it does not do, stated plainly
//! * It cannot find your files without the recovery list. The list is what holds each file's key
//!   and where its pieces are stored. Blob addresses on Walrus come from the CONTENT, so nothing
//!   derives them from an account code; the list is the index, and today it lives either in NMTS's
//!   database or in the `.nmtsmap` file you saved.
//! * It cannot recover anything you deleted. Deletion in NMTS destroys the key, and the key is
//!   what this program needs.
//! * It cannot prove a blob is still stored. It finds out by fetching it.
//!
//! ## The account code
//! It is read from the terminal, or from `--code-file`. ⛔ There is no `--code` flag, on purpose —
//! see `args.rs` — and it is never typed into the control window either. Nothing here writes the
//! code anywhere, and the only thing that ever crosses the network is a request for a public blob
//! by its public id.

#![forbid(unsafe_code)]

mod args;
mod derive;
mod discover;
mod gui;
mod kitfile;
mod mapfile;
mod msg;
mod restore;
mod source;

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use args::{Lang, Mode, Parsed};
use nmts_crypto::codes::AccountCode;
use nmts_crypto::manifest::RecoveryManifest;
use restore::Note;
use source::{BlobSource, DirSource, HttpSource};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = match args::parse(&argv) {
        Parsed::Print(text, code) => {
            if code == 0 {
                print!("{text}");
            } else {
                eprint!("{text}");
            }
            return ExitCode::from(u8::try_from(code).unwrap_or(2));
        }
        Parsed::Run(a) => a,
    };

    let outcome = match a.mode {
        // The list is found BEFORE the window opens, because finding it needs the account code
        // and the account code is typed in the terminal — never in the browser.
        Mode::Gui if a.find => find_on_network(&a, a.lang).and_then(|(manifest, quilt_id)| {
            let name = msg::FIND_LIST_NAME.get(a.lang).to_string();
            gui::run_with(&a, Some((manifest, quilt_id, name)))
        }),
        Mode::Gui => gui::run(&a),
        Mode::WriteGui => write_gui(&a),
        Mode::Derive => show_derived(&a),
        _ => run(&a),
    };
    match outcome {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

/// Put the control page on disk so it can be read without running anything.
fn write_gui(a: &args::Args) -> Result<ExitCode, String> {
    let to = a.gui_out.as_deref().ok_or("no destination was given")?;
    gui::write_page(to)?;
    println!("{}\n  {}", msg::GUI_PAGE_WRITTEN.get(a.lang), to.display());
    Ok(ExitCode::SUCCESS)
}

/// Print everything an account code turns into. No list, no network, nothing written.
fn show_derived(a: &args::Args) -> Result<ExitCode, String> {
    let lang = a.lang;
    let code = read_account_code(a.code_file.as_deref(), lang)?;
    let keys = nmts_crypto::kdf::derive(&code).map_err(|e| format!("{e}"))?;
    let d = derive::from_keys(&keys, a.wallets, a.secrets);

    println!("\n{}", msg::DERIVE_HEAD.get(lang));
    println!("  {:<16} {}", msg::DERIVE_ACCOUNT_ID.get(lang), d.account_id);
    println!("  {:<16} {}", msg::DERIVE_FINGERPRINT.get(lang), d.fingerprint);
    println!("  {:<16} {}", msg::DERIVE_PUBLIC_CODE.get(lang), d.public_code);
    for w in &d.wallets {
        println!(
            "  {:<16} {}",
            format!("{} {}", msg::DERIVE_WALLET.get(lang), w.index),
            w.address
        );
    }
    if a.secrets {
        // ⛔ The warning comes BEFORE the keys, not after. A person scrolling back to read a
        //    caution that was printed underneath the thing it cautions about has already read it.
        println!("\n{}", msg::DERIVE_SECRET_WARNING.get(lang));
        for w in &d.wallets {
            if let Some(secret) = &w.secret {
                println!(
                    "  {:<16} {}",
                    format!("{} {} {}", msg::DERIVE_WALLET.get(lang), w.index, msg::DERIVE_SECRET_KEY.get(lang)),
                    secret
                );
            }
        }
    } else {
        println!("\n{}", msg::DERIVE_PUBLIC_ONLY.get(lang));
    }
    println!("{}", msg::DERIVE_NOTHING_ELSE.get(lang));
    Ok(ExitCode::SUCCESS)
}

fn run(a: &args::Args) -> Result<ExitCode, String> {
    let lang = a.lang;
    // Two ways in, one place they meet. Either a person hands over a file, or the account code is
    // used to go and look for the list where it is stored (NCF-3 §2.5).
    let (manifest, own_quilt) = if a.find {
        let (m, quilt) = find_on_network(a, lang)?;
        (m, Some(quilt))
    } else {
        open_from_file(a, lang)?
    };
    proceed(&manifest, own_quilt.as_deref(), a, lang)
}

/// Look the recovery list up on the storage network with nothing but the account code.
fn find_on_network(a: &args::Args, lang: Lang) -> Result<(RecoveryManifest, String), String> {
    let code = read_account_code(a.code_file.as_deref(), lang)?;
    let keys = nmts_crypto::kdf::derive(&code).map_err(|e| format!("{e}"))?;

    let rpcs: Vec<String> = if a.rpcs.is_empty() {
        discover::DEFAULT_RPCS.iter().map(|s| s.to_string()).collect()
    } else {
        a.rpcs.clone()
    };
    let aggregators: Vec<String> = if a.aggregators.is_empty() {
        source::DEFAULT_AGGREGATORS.iter().map(|s| s.to_string()).collect()
    } else {
        a.aggregators.clone()
    };

    println!("{}", msg::FIND_LOOKING.get(lang));
    let search = discover::find(&keys, &rpcs, &aggregators, a.owner.as_deref(), a.wallets);
    for owner in &search.owners {
        println!("  {owner}");
    }
    if search.truncated {
        eprintln!("⚠ {}", msg::FIND_TRUNCATED.get(lang));
    }
    // Problems are printed whether or not the search succeeded: a list found under one address
    // while another address could not be reached is a partial answer, and saying so is the
    // difference between "you have nothing" and "one node was down".
    for problem in &search.problems {
        eprintln!("⚠ {problem}");
    }

    let Some(found) = search.found else {
        return Err(format!(
            "{} ({} {})",
            msg::FIND_NOTHING.get(lang),
            search.quilts_seen,
            msg::FIND_BUNDLES_SEEN.get(lang)
        ));
    };
    // The address is printed too, and not as decoration: when several were searched, which one
    // holds the list is the difference between "this account" and "a wallet you also control".
    println!(
        "{} {} · {} {} · {} {}",
        msg::FIND_FOUND.get(lang),
        found.quilt_id,
        msg::FIND_SEQ.get(lang),
        found.manifest.seq,
        msg::FIND_UNDER.get(lang),
        found.owner
    );
    Ok((found.manifest, found.quilt_id))
}

/// Open a recovery list — or a recovery kit, which has one inside it — from a file.
fn open_from_file(a: &args::Args, lang: Lang) -> Result<(RecoveryManifest, Option<String>), String> {
    let raw = std::fs::read_to_string(&a.map).map_err(|e| format!("{}: {e}", a.map.display()))?;
    // A recovery kit has the list inside it, so either file gets a person to the same place.
    let (wrapper, code_in_kit) = if kitfile::looks_like_kit(&raw) {
        open_kit(&raw, lang)?
    } else {
        (parse_list(&raw, lang)?, None)
    };

    // ⛔ A kit that carries the code is used WITHOUT asking, and the program says so. Asking a
    //    person to type a code that is printed in the file they just handed over would protect
    //    nothing — whoever has the file has the code — while teaching them the question means
    //    something. `--code-file` still wins, for anyone keeping the two apart deliberately.
    let code = match (a.code_file.as_deref(), code_in_kit) {
        (Some(path), _) => read_account_code(Some(path), lang)?,
        (None, Some(from_kit)) => {
            println!("{}", msg::KIT_CARRIES_CODE.get(lang));
            parse_account_code(&from_kit, lang)?
        }
        (None, None) => read_account_code(None, lang)?,
    };
    let keys = nmts_crypto::kdf::derive(&code).map_err(|e| format!("{e}"))?;

    // ⛔ THE ACCOUNT IS CHECKED BEFORE THE LIST IS OPENED, and the order is the point. Both a wrong
    //    code and a damaged list fail the same decryption, and a person told "the list would not
    //    open" when the truth is "that is a different account's code" will go looking for a backup
    //    of a file that was never broken. The account id is public and carried in the wrapper
    //    exactly so this distinction can be made.
    if keys.account_id_b64() != wrapper.account_id {
        return Err(msg::CODE_WRONG_ACCOUNT.get(lang).to_string());
    }

    let sealed = nmts_crypto::b64::decode(&wrapper.sealed).map_err(|_| {
        format!(
            "{} — the sealed list is not readable.",
            msg::MAP_NOT_A_MAP.get(lang)
        )
    })?;
    let manifest = RecoveryManifest::decrypt(&keys.data_key, &sealed)
        .map_err(|_| msg::MAP_WILL_NOT_OPEN.get(lang).to_string())?;

    // The wrapper's plaintext header is editable by anyone holding the file; the sealed document
    // is not. They should agree, and when they do not the sealed one is the truth — but a person
    // should hear that the file they are holding was altered after it was written.
    if wrapper.seq != manifest.seq {
        eprintln!(
            "⚠ {} ({} / {}).",
            msg::MAP_SEQ_DISAGREES.get(lang),
            wrapper.seq,
            manifest.seq
        );
    }

    Ok((manifest, None))
}

/// List, plan or restore — the same three things whichever way the document arrived.
fn proceed(
    manifest: &RecoveryManifest,
    own_quilt: Option<&str>,
    a: &args::Args,
    lang: Lang,
) -> Result<ExitCode, String> {
    let out_dir = a.out.clone().unwrap_or_else(|| Path::new(".").to_path_buf());
    let planned = restore::plan(manifest, &out_dir, a.only.as_deref(), own_quilt);
    if planned.is_empty() {
        println!("{}", msg::NOTHING_MATCHED.get(lang));
        return Ok(ExitCode::from(1));
    }

    match a.mode {
        Mode::List => {
            print_summary(manifest, &planned, lang);
            Ok(ExitCode::SUCCESS)
        }
        Mode::FetchPlan => {
            print_summary(manifest, &planned, lang);
            print_fetch_plan(&planned, a, lang);
            Ok(ExitCode::SUCCESS)
        }
        _ => {
            print_summary(manifest, &planned, lang);
            do_restore(&planned, a, lang)
        }
    }
}

/// Read a `.nmtsmap` document, turning its refusals into sentences.
fn parse_list(raw: &str, lang: Lang) -> Result<mapfile::MapFile, String> {
    match mapfile::parse(raw) {
        Ok(w) => Ok(w),
        Err(mapfile::MapFileError::NotAMap(why)) => {
            Err(format!("{} — {why}.", msg::MAP_NOT_A_MAP.get(lang)))
        }
        Err(mapfile::MapFileError::TooNew { wrapper, nrm, min_tool }) => Err(
            mapfile::too_new_sentence(wrapper, nrm, min_tool.as_deref(), lang),
        ),
    }
}

/// Open a recovery kit and take the list — and the account code — out of it.
fn open_kit(raw: &str, lang: Lang) -> Result<(mapfile::MapFile, Option<String>), String> {
    let kit = match kitfile::parse(raw) {
        Ok(k) => k,
        Err(kitfile::KitFileError::NotAKit(why)) => {
            return Err(format!("{} — {why}.", msg::KIT_DAMAGED.get(lang)))
        }
        Err(kitfile::KitFileError::TooNew { version }) => {
            return Err(format!(
                "{} (kit v{version}; this build reads up to v{}).",
                msg::KIT_TOO_NEW.get(lang),
                kitfile::MAX_KIT_VERSION
            ))
        }
    };
    println!("{}", msg::KIT_OPENED.get(lang));
    let list = kit
        .recovery_list
        .ok_or_else(|| msg::KIT_NO_LIST.get(lang).to_string())?;
    let wrapper = parse_list(&list.to_string(), lang)?;
    // ⛔ The kit says which account it is for, and so does the list sealed inside it. They come
    //    from the same moment, so they agree — unless somebody assembled this file by hand, in
    //    which case a person should hear it before their account code goes anywhere near it.
    if kit.account_id != wrapper.account_id {
        return Err(format!(
            "{} — the kit is for account {} and the list inside it is for {}.",
            msg::KIT_DAMAGED.get(lang),
            kit.account_id,
            wrapper.account_id
        ));
    }
    Ok((wrapper, kit.account_code))
}

/// What the list covers. Printed in every mode, because a person should see what they are about to
/// act on before anything is fetched or written.
fn print_summary(manifest: &RecoveryManifest, planned: &[restore::PlannedItem<'_>], lang: Lang) {
    let bytes: u64 = planned.iter().map(|p| p.item.size).sum();
    println!(
        "{} {} files, {} (list #{}, taken {})",
        msg::SUMMARY_HEAD.get(lang),
        planned.len(),
        msg::human_bytes(bytes),
        manifest.seq,
        manifest.generated_at
    );
    for p in planned {
        let path = p.item.path.trim_end_matches('/');
        println!(
            "  {}/{}  {}",
            path,
            p.item.name,
            msg::human_bytes(p.item.size)
        );
        if let Some(original) = &p.renamed_from {
            println!("      ← {original}");
        }
    }
}

/// The URLs to fetch by hand. The names printed here are the names `--blobs-dir` looks for.
fn print_fetch_plan(planned: &[restore::PlannedItem<'_>], a: &args::Args, lang: Lang) {
    // Built the same way `do_restore` builds it, and asked for its endpoints, so the URLs printed
    // here cannot drift from the URLs the program would have fetched.
    let http = HttpSource::new(a.aggregators.clone());
    let base = http.endpoints().first().map(String::as_str).unwrap_or("");
    println!("\n{}", msg::FETCH_PLAN_HEAD.get(lang));
    for p in planned {
        let refs = match p.refs() {
            Ok(refs) => refs,
            Err(problem) => {
                let why = match problem {
                    restore::RefProblem::UnknownNetwork => msg::UNKNOWN_NETWORK.get(lang),
                    restore::RefProblem::OwnQuiltUnknown => msg::OWN_QUILT_UNKNOWN.get(lang),
                };
                println!("  # \"{}\" {why}", p.item.name);
                continue;
            }
        };
        for (blob, _) in refs {
            println!("  curl -fL -o {} {}{}", blob.file_name(), base, blob.url_path());
        }
    }
}

fn do_restore(
    planned: &[restore::PlannedItem<'_>],
    a: &args::Args,
    lang: Lang,
) -> Result<ExitCode, String> {
    let source: Box<dyn BlobSource> = match &a.blobs_dir {
        Some(dir) => Box::new(DirSource::new(dir)),
        None => Box::new(HttpSource::new(a.aggregators.clone())),
    };
    println!("\n{} ({})", msg::RESTORE_HEAD.get(lang), source.describe());

    let mut failed: Vec<String> = Vec::new();
    let mut restored = 0usize;
    let mut bytes = 0u64;
    for p in planned {
        let label = format!("{}/{}", p.item.path.trim_end_matches('/'), p.item.name);
        print!("  {label} … ");
        let _ = std::io::stdout().flush();
        // Nothing to report as it goes: the terminal prints one line per file when the file is
        // finished, which is the only moment at which anything true can be said about it.
        let mut ignore_progress = |_: u64| {};
        match restore::restore_item(p, source.as_ref(), a.overwrite, lang, &mut ignore_progress) {
            Ok(outcome) => {
                restored += 1;
                bytes += outcome.bytes;
                println!("{}", msg::human_bytes(outcome.bytes));
                for note in &outcome.notes {
                    let line = match note {
                        Note::PartOrderUnverifiable => msg::PART_PLACEMENT_UNVERIFIABLE.get(lang),
                        Note::NoContentHash => msg::NO_HASH_NOTE.get(lang),
                    };
                    println!("      {line}");
                }
            }
            Err(e) => {
                println!("—");
                println!("      {e}");
                failed.push(label);
            }
        }
    }

    println!();
    if failed.is_empty() {
        println!(
            "{} ({restored} files, {})",
            msg::DONE_ALL.get(lang),
            msg::human_bytes(bytes)
        );
        Ok(ExitCode::SUCCESS)
    } else {
        for label in &failed {
            println!("  ⛔ {label}");
        }
        println!(
            "{} ({restored} restored, {} failed)",
            msg::DONE_PARTIAL.get(lang),
            failed.len()
        );
        // ⛔ Non-zero, always. A recovery that half worked and exited 0 is a recovery somebody's
        //    script will report as a success.
        Ok(ExitCode::from(3))
    }
}

/// Read the account code: from a file if asked, otherwise from the terminal.
///
/// ⛔ Terminal echo is turned off on every platform this program builds for, and if that fails the
///    person is TOLD rather than left to assume otherwise. Silently echoing a secret that the
///    caller believes is hidden is worse than echoing one they know is visible.
pub(crate) fn read_account_code(
    code_file: Option<&Path>,
    lang: Lang,
) -> Result<AccountCode, String> {
    let raw = match code_file {
        Some(path) => {
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?
        }
        None => prompt_for_code(lang)?,
    };
    parse_account_code(&raw, lang)
}

/// Turn text into an account code, whatever it was read from.
pub(crate) fn parse_account_code(raw: &str, lang: Lang) -> Result<AccountCode, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(msg::CODE_EMPTY.get(lang).to_string());
    }
    AccountCode::parse(trimmed).map_err(|_| msg::CODE_MALFORMED.get(lang).to_string())
}

fn prompt_for_code(lang: Lang) -> Result<String, String> {
    eprint!("{}", msg::ASK_CODE.get(lang));
    let _ = std::io::stderr().flush();

    // Piped input has no terminal to hide anything on, and hiding is not what a caller who wrote
    // `echo … | nmts-recovery` asked for. Reading it as an ordinary line is both correct and what
    // makes the offline tests able to drive this program at all.
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("{e}"))?;
        return Ok(line);
    }

    match rpassword::read_password() {
        Ok(line) => {
            // The newline the person typed was swallowed with the echo.
            eprintln!();
            Ok(line)
        }
        Err(_) => {
            // Some terminals cannot be put into a mode where typing is invisible. Saying so is the
            // only honest option: the alternative is a person typing their master key onto a
            // screen they believed was blank.
            eprintln!();
            eprintln!("{}", msg::ECHO_WARNING.get(lang));
            eprint!("{}", msg::ASK_CODE.get(lang));
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| format!("{e}"))?;
            Ok(line)
        }
    }
}
