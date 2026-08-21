//! Everything this program says to a person, in both languages it can say it in.
//!
//! # English is what it says unless asked otherwise
//! The tool exists for the day NMTS is gone. On that day the person running it may be the account
//! holder, or it may be someone helping them — a friend, a relative, whoever ends up holding the
//! drive. Which of those two reads Korean is not something the moment of saving the list could
//! know, so the default is the one more people can read, and `--lang ko` (or the toggle in the
//! control window) switches it. Nothing is auto-detected: a program whose output changes with a
//! machine's locale is a program whose output cannot be quoted in a bug report.
//!
//! ⛔ No message here promises anything the program has not already done. "Restored 412 files" is
//!    printed after 412 files were written and their hashes checked, never before.

use crate::args::Lang;

/// One line, in both languages.
#[derive(Debug, Clone, Copy)]
pub struct Line(pub &'static str, pub &'static str);

impl Line {
    pub fn get(&self, lang: Lang) -> &'static str {
        match lang {
            Lang::En => self.0,
            Lang::Ko => self.1,
        }
    }
}

pub const ASK_CODE: Line = Line(
    "Account code (32 letters and digits, dashes optional): ",
    "계정 코드 (글자와 숫자 32개, 붙임표는 있어도 없어도 됩니다): ",
);

pub const ECHO_WARNING: Line = Line(
    "⚠ This terminal will show what you type. Make sure nobody is watching your screen.",
    "⚠ 이 창은 입력한 글자를 그대로 보여 줍니다. 화면을 보는 사람이 없는지 확인하십시오.",
);

pub const CODE_EMPTY: Line = Line(
    "No account code was entered.",
    "계정 코드가 입력되지 않았습니다.",
);

pub const CODE_MALFORMED: Line = Line(
    "That is not a valid account code. Check for a mistyped character; the last character is a \
     check symbol, so a single typo is caught here rather than later.",
    "올바른 계정 코드가 아닙니다. 잘못 입력한 글자가 있는지 확인하십시오. 마지막 글자가 검사용이라 \
     한 글자만 틀려도 여기서 걸립니다.",
);

pub const CODE_WRONG_ACCOUNT: Line = Line(
    "This account code does not belong to this recovery list. The code is valid, but it identifies \
     a different account. Check that you are using the file saved from this account.",
    "이 계정 코드는 이 복구 목록의 것이 아닙니다. 코드 자체는 올바르지만 다른 계정을 가리킵니다. \
     이 계정에서 저장한 파일이 맞는지 확인하십시오.",
);

pub const MAP_NOT_A_MAP: Line = Line(
    "This file is not an NMTS recovery list.",
    "이 파일은 NMTS 복구 목록이 아닙니다.",
);

/// Said when a recovery KIT is offered to the control page instead of a recovery list.
///
/// ⛔ A kit holds the account code in the clear. The whole design of this program says the code is
/// typed in the terminal and never goes near a browser, and a kit chosen in the page's file picker
/// walks straight past that. So the page refuses a kit before it reads one, and this sentence is
/// what it says — with the command that does work, because a person who saved only the kit has no
/// other file to offer and must not be left at a dead end.
pub const KIT_NOT_IN_THE_BROWSER: Line = Line(
    "That is a recovery kit, not a recovery list. A kit holds your account code, and your account \
     code must not go through a browser. Open a terminal and run:  nmts-recovery --map <that file>",
    "그것은 복구 키트이고 복구 목록이 아닙니다. 키트에는 계정 코드가 들어 있고, 계정 코드는 \
     브라우저를 지나가면 안 됩니다. 터미널에서 다음을 실행하십시오:  nmts-recovery --map <그 파일>",
);

pub const MAP_WILL_NOT_OPEN: Line = Line(
    "The recovery list would not open. The account code is right for this account, so the file \
     itself has been changed or damaged since it was saved.",
    "복구 목록이 열리지 않았습니다. 계정 코드는 이 계정의 것이 맞으므로, 파일 자체가 저장된 \
     뒤에 바뀌었거나 손상된 것입니다.",
);

/// Said when the list names the version it needs — the actionable half of [`MAP_TOO_NEW`].
pub const MAP_NEEDS_VERSION: Line = Line(
    "This list needs nmts-recovery {need} or newer; this is {have}. Newer builds are at \
     https://github.com/needmoretruth/nmts-recovery — nothing was read.",
    "이 복구 목록에는 nmts-recovery {need} 이상이 필요합니다. 지금 쓰고 계신 것은 {have}입니다. \
     새 판은 https://github.com/needmoretruth/nmts-recovery 에 있습니다. 아무것도 읽지 않았습니다.",
);

pub const MAP_TOO_NEW: Line = Line(
    "This list was written in a newer format than this build understands. Use a newer \
     nmts-recovery; nothing was read.",
    "이 복구 목록은 이 판이 아는 것보다 새로운 형식으로 쓰였습니다. 더 새로운 nmts-recovery를 \
     쓰십시오. 아무것도 읽지 않았습니다.",
);

pub const MAP_SEQ_DISAGREES: Line = Line(
    "This file's header and the sealed list inside it disagree about which list this is. The \
     sealed one was used; the header is the part anyone holding the file could have edited",
    "이 파일의 겉면과 그 안에 봉인된 목록이 서로 다른 번호를 말합니다. 봉인된 쪽을 썼습니다. \
     겉면은 파일을 가진 사람이면 누구나 고칠 수 있는 자리입니다",
);

pub const SUMMARY_HEAD: Line = Line("This list covers:", "이 복구 목록이 담고 있는 것:");

/// What the list says about ITSELF, printed above what it covers (owner directive, 2026-08-19).
///
/// ⭐ The half that earns its line is `{chain}`. Before it existed, a blob id from testnet and one
/// from mainnet were the same string to this program, so a list that resolved to nothing looked
/// exactly like a list whose bytes were gone.
pub const LIST_ABOUT: Line = Line(
    "Written by {product} {version} · {network}/{chain}",
    "{product} {version}이(가) 쓴 목록입니다 · {network}/{chain}",
);

/// Where the format is written down — for whoever is reading this without our code beside them.
pub const LIST_SPEC: Line = Line("Format: {url}", "형식 설명: {url}");

/// The document's own count does not match what was parsed out of it.
///
/// ⛔ Said, not enforced. The document is one authenticated envelope, so this cannot be an attack —
/// it is a reader that skipped records it did not recognise, which is exactly the case a person
/// must be told about rather than left to discover by a missing file.
pub const LIST_TOTALS_DISAGREE: Line = Line(
    "⚠ This list says it holds {claimed} files; {parsed} were read. Some records were not \
     understood by this build — a newer nmts-recovery may read them.",
    "⚠ 이 목록은 파일 {claimed}개를 담았다고 적고 있는데 읽어낸 것은 {parsed}개입니다. 이 판이 \
     이해하지 못한 기록이 있습니다. 더 새로운 nmts-recovery라면 읽을 수 있습니다.",
);

/// A file was written but its recorded date could not be put back.
pub const DATE_NOT_RESTORED: Line = Line(
    "the file is complete; its original date could not be set",
    "파일은 온전합니다. 원래 날짜만 되돌리지 못했습니다",
);

pub const NOTHING_MATCHED: Line = Line(
    "Nothing in this list matches --only.",
    "--only 에 해당하는 것이 이 복구 목록에 없습니다.",
);

/// The list named hosts to fetch from, and this run did not contact them.
///
/// ⛔ SAID OUT LOUD RATHER THAN DONE QUIETLY. Holding them back is the safe default, but a person
/// whose files will not come back needs to know that another address exists and that they may use
/// it. `{list}` is filled with the addresses, one per line.
pub const RECORDED_HELD_BACK: Line = Line(
    "This list also names storage addresses of its own. They were NOT contacted: whoever sealed \
     the list chose them, and contacting one tells its operator where and when you recovered. Add \
     --use-recorded-aggregators to use them too.\n{list}",
    "이 복구 목록에는 자체 저장망 주소도 적혀 있습니다. 접속하지 않았습니다. 그 주소는 목록을 \
     봉인한 사람이 적은 것이고, 접속하면 그 주소의 운영자에게 복구한 위치와 시각이 알려집니다. \
     함께 쓰려면 --use-recorded-aggregators 를 붙이십시오.\n{list}",
);

/// Printed after a restore that did not finish, when there were held-back addresses.
pub const RECORDED_HELD_BACK_HINT: Line = Line(
    "Some parts did not arrive. This list names storage addresses this run did not contact — \
     --use-recorded-aggregators tries those too.",
    "받지 못한 조각이 있습니다. 이 복구 목록에는 이번에 접속하지 않은 저장망 주소가 적혀 \
     있습니다. --use-recorded-aggregators 를 붙이면 그 주소도 시도합니다.",
);

pub const FETCH_PLAN_HEAD: Line = Line(
    "Fetch these, save each under the filename shown, then run again with --blobs-dir:",
    "아래를 받아 표시된 이름으로 저장한 뒤 --blobs-dir 로 다시 실행하십시오:",
);

pub const RESTORE_HEAD: Line = Line("Restoring:", "되찾는 중:");

pub const DONE_ALL: Line = Line(
    "Done. Every file in the list was restored and its contents verified.",
    "끝났습니다. 복구 목록에 있는 파일을 모두 되찾았고 내용까지 확인했습니다.",
);

pub const DONE_PARTIAL: Line = Line(
    "Finished with failures. The files listed above were NOT restored; everything else was, and \
     was verified.",
    "실패가 있는 채로 끝났습니다. 위에 적힌 파일은 되찾지 못했습니다. 나머지는 전부 되찾았고 \
     내용까지 확인했습니다.",
);

pub const NO_HASH_NOTE: Line = Line(
    "note: this file predates content hashes, so its bytes were authenticated by the encryption \
     but not compared against a recorded hash.",
    "참고: 이 파일은 내용 해시가 생기기 전의 것이라, 암호화로 위조는 걸러냈지만 기록된 해시와 \
     대조하지는 못했습니다.",
);

pub const UNKNOWN_NETWORK: Line = Line(
    "is stored on a network this build cannot read",
    "이 판이 읽을 수 없는 저장망에 있습니다",
);

// ── Looking the list up on the storage network ───────────────────────────────────────────────

pub const FIND_LOOKING: Line = Line(
    "Looking for your recovery list on the storage network. Your account code stays here; what \
     goes out is a question about these public addresses:",
    "저장망에서 복구 목록을 찾고 있습니다. 계정 코드는 이 기계 밖으로 나가지 않고, 밖으로 나가는 \
     것은 아래 공개 주소에 대한 물음뿐입니다:",
);

pub const FIND_FOUND: Line = Line("Found it in bundle", "찾았습니다 — 꾸러미");

pub const FIND_SEQ: Line = Line("list number", "목록 번호");

pub const FIND_UNDER: Line = Line("held by", "가진 주소");

pub const FIND_BUNDLES_SEEN: Line = Line("bundles were checked", "개의 꾸러미를 확인했습니다");

pub const FIND_NOTHING: Line = Line(
    "No recovery list was found on the storage network for this account code. Three things make \
     that normal rather than alarming: the account may never have turned the storage-network copy \
     on; the uploads may have been paid for by a browser-extension wallet or an imported key, \
     whose address an account code cannot derive — pass it with --owner; or the account may hold \
     only large files, which are stored on their own rather than in bundles. A recovery list file \
     you saved, or a recovery kit, still works: pass it with --map.",
    "이 계정 코드로는 저장망에서 복구 목록을 찾지 못했습니다. 놀랄 일이 아닌 경우가 셋입니다. \
     저장망 사본을 켠 적이 없거나, 확장 프로그램 지갑이나 가져온 개인 키로 저장 비용을 냈거나 \
     (그 주소는 계정 코드로 계산할 수 없습니다 — --owner 로 알려 주십시오), 큰 파일만 있어서 \
     꾸러미가 아니라 따로 올라가 있는 경우입니다. 저장해 두신 복구 목록 파일이나 복구 키트가 \
     있으면 --map 으로 그대로 쓰실 수 있습니다.",
);

pub const FIND_LIST_NAME: Line = Line(
    "the list stored on the storage network",
    "저장망에 있는 복구 목록",
);

pub const FIND_TRUNCATED: Line = Line(
    "This address holds more objects than one search walks through, so bundles may have been \
     missed. If nothing was found, say --map and use a saved file instead.",
    "이 주소가 가진 물건이 한 번의 검색이 훑는 것보다 많아서, 못 본 꾸러미가 있을 수 있습니다. \
     아무것도 못 찾았다면 --map 으로 저장해 두신 파일을 쓰십시오.",
);

pub const OWN_QUILT_UNKNOWN: Line = Line(
    "is stored in the bundle this recovery list itself came from, and this list was read from a \
     file, so there is nothing here that says which bundle that was. Run this again pointing at \
     the account code instead of the file, and the list will be found where it is stored.",
    "이 복구 목록이 실려 있던 꾸러미 안에 있습니다. 그런데 이 목록은 파일에서 읽었고, 파일에는 \
     그것이 어느 꾸러미였는지가 적혀 있지 않습니다. 파일 대신 계정 코드로 다시 실행하시면 목록을 \
     그것이 저장된 자리에서 찾습니다.",
);

pub const PART_PLACEMENT_UNVERIFIABLE: Line = Line(
    "note: this list is an older version that did not record where each piece belongs, so the \
     order of the pieces is what the list claims and could not be checked against the pieces \
     themselves.",
    "참고: 이 복구 목록은 조각의 자리를 기록하지 않던 옛 판이라, 조각의 순서는 목록의 주장일 뿐 \
     조각 자체와 대조하지 못했습니다.",
);

// ── The control window ────────────────────────────────────────────────────────────────────────

pub const GUI_HEAD: Line = Line(
    "A control window is waiting for you at this address. Open it in a browser:",
    "조작 화면이 아래 주소에서 기다리고 있습니다. 브라우저로 여십시오:",
);

pub const GUI_LOCAL_ONLY: Line = Line(
    "  Only this machine can reach it, and the address stops working when this program ends.",
    "  이 주소는 이 기계에서만 열리고, 이 프로그램이 끝나면 닫힙니다.",
);

pub const GUI_CODE_STAYS_HERE: Line = Line(
    "  Your account code is typed HERE, in this terminal — never in the browser.",
    "  계정 코드는 브라우저가 아니라 바로 이 창에 입력하십시오.",
);

pub const GUI_OPENED: Line = Line(
    "  A browser was asked to open it for you.",
    "  브라우저에 열어 달라고 부탁해 두었습니다.",
);

pub const GUI_ASK_IN_TERMINAL: Line = Line(
    "The window has handed over a recovery list. It needs your account code now, and it is asking \
     here rather than in the browser on purpose.",
    "화면에서 복구 목록을 넘겨받았습니다. 이제 계정 코드가 필요한데, 브라우저가 아니라 여기서 묻는 \
     것은 일부러 그렇게 한 것입니다.",
);

pub const GUI_MAP_OPEN: Line = Line(
    "The list is open. Go back to the browser window.",
    "복구 목록이 열렸습니다. 브라우저 화면으로 돌아가십시오.",
);

pub const GUI_CLOSED: Line = Line(
    "The control window said it was finished. Nothing is listening any more.",
    "조작 화면이 끝났다고 알려 왔습니다. 이제 아무것도 열려 있지 않습니다.",
);

pub const GUI_NO_PORT: Line = Line(
    "A door could not be opened on this machine for the control window.",
    "조작 화면을 위한 통로를 이 기계에서 열지 못했습니다.",
);

pub const GUI_NEED_DESTINATION: Line = Line(
    "Say where the files should go.",
    "파일을 놓을 자리를 적어 주십시오.",
);

pub const GUI_NEED_SELECTION: Line = Line(
    "Tick at least one file first.",
    "파일을 하나 이상 골라 주십시오.",
);

pub const GUI_ALREADY_RUNNING: Line = Line(
    "A restore is already running.",
    "되찾기가 이미 돌고 있습니다.",
);

pub const GUI_PAGE_WRITTEN: Line = Line(
    "The control page was written there. On its own it does nothing — run this program with --gui \
     and open the address it prints.",
    "조작 화면을 그 자리에 썼습니다. 그 파일만으로는 아무 일도 일어나지 않습니다. 이 프로그램을 \
     --gui 로 실행하고 거기 찍히는 주소를 여십시오.",
);

// ── The recovery kit, and what a code derives ────────────────────────────────────────────────

pub const KIT_OPENED: Line = Line(
    "This is a recovery kit, and the recovery list is inside it.",
    "복구 키트입니다. 복구 목록이 그 안에 들어 있습니다.",
);

pub const KIT_CARRIES_CODE: Line = Line(
    "⚠ This kit carries your account code in the clear, so this program is not asking for it. \
     Anyone who reads this file can do exactly what you are about to do.",
    "⚠ 이 키트에는 계정 코드가 그대로 들어 있어서 따로 묻지 않습니다. 이 파일을 읽을 수 있는 \
     사람은 지금 하시려는 일을 똑같이 할 수 있습니다.",
);

pub const KIT_NO_LIST: Line = Line(
    "This recovery kit has no recovery list inside it — it was taken before there were any files, \
     or by an older version of NMTS. Use the recovery list file instead.",
    "이 복구 키트 안에는 복구 목록이 없습니다. 파일이 하나도 없을 때 받았거나, 예전 판의 \
     NMTS에서 받은 것입니다. 복구 목록 파일을 쓰십시오.",
);

pub const KIT_DAMAGED: Line = Line(
    "This looks like a recovery kit, but the part a program reads is not readable.",
    "복구 키트로 보이는데, 프로그램이 읽는 부분을 읽을 수 없습니다.",
);

pub const KIT_TOO_NEW: Line = Line(
    "This recovery kit was written in a newer format than this build understands. Use a newer \
     nmts-recovery; nothing was read.",
    "이 복구 키트는 이 판이 아는 것보다 새로운 형식으로 쓰였습니다. 더 새로운 nmts-recovery를 \
     쓰십시오. 아무것도 읽지 않았습니다.",
);

pub const DERIVE_HEAD: Line = Line(
    "What this account code derives:",
    "이 계정 코드에서 나오는 것:",
);

pub const DERIVE_ACCOUNT_ID: Line = Line("Account id", "계정 식별자");
pub const DERIVE_FINGERPRINT: Line = Line("Fingerprint", "지문");
pub const DERIVE_PUBLIC_CODE: Line = Line("Public code", "공개 코드");
pub const DERIVE_WALLET: Line = Line("Wallet", "지갑");
pub const DERIVE_SECRET_KEY: Line = Line("Private key", "개인 키");

pub const DERIVE_PUBLIC_ONLY: Line = Line(
    "These are public. Add --secrets to also print the wallet private keys.",
    "여기까지는 공개해도 되는 값입니다. 지갑의 개인 키까지 보시려면 --secrets 를 붙이십시오.",
);

pub const DERIVE_SECRET_WARNING: Line = Line(
    "⛔ PRIVATE KEYS FOLLOW. Anyone who reads them can spend everything in those wallets. They are \
     about to be in this terminal's history — close it when you are done, and do not paste this \
     anywhere.",
    "⛔ 아래는 개인 키입니다. 이것을 읽는 사람은 그 지갑의 돈을 전부 쓸 수 있습니다. 지금부터 이 \
     창의 기록에 남으니, 끝나면 창을 닫으시고 어디에도 붙여 넣지 마십시오.",
);

pub const DERIVE_NOTHING_ELSE: Line = Line(
    "Nothing was written and nothing was sent. This is the same derivation your browser does.",
    "아무것도 저장하지 않았고 어디로도 보내지 않았습니다. 브라우저가 하는 것과 같은 계산입니다.",
);

/// Every line above, in one place.
///
/// ⛔ This exists so the both-languages check below has something to iterate. A list maintained by
///    hand would drift, which is why the test does not trust it either — it counts the declarations
///    in this file's own source and refuses to pass if the two numbers differ.
#[cfg(test)]
pub const ALL_LINES: &[Line] = &[
    ASK_CODE,
    ECHO_WARNING,
    CODE_EMPTY,
    CODE_MALFORMED,
    CODE_WRONG_ACCOUNT,
    MAP_NOT_A_MAP,
    KIT_NOT_IN_THE_BROWSER,
    MAP_WILL_NOT_OPEN,
    MAP_TOO_NEW,
    MAP_NEEDS_VERSION,
    MAP_SEQ_DISAGREES,
    SUMMARY_HEAD,
    LIST_ABOUT,
    LIST_SPEC,
    LIST_TOTALS_DISAGREE,
    DATE_NOT_RESTORED,
    NOTHING_MATCHED,
    RECORDED_HELD_BACK,
    RECORDED_HELD_BACK_HINT,
    FETCH_PLAN_HEAD,
    RESTORE_HEAD,
    DONE_ALL,
    DONE_PARTIAL,
    NO_HASH_NOTE,
    UNKNOWN_NETWORK,
    OWN_QUILT_UNKNOWN,
    FIND_LOOKING,
    FIND_FOUND,
    FIND_SEQ,
    FIND_UNDER,
    FIND_BUNDLES_SEEN,
    FIND_NOTHING,
    FIND_TRUNCATED,
    FIND_LIST_NAME,
    PART_PLACEMENT_UNVERIFIABLE,
    GUI_HEAD,
    GUI_LOCAL_ONLY,
    GUI_CODE_STAYS_HERE,
    GUI_OPENED,
    GUI_ASK_IN_TERMINAL,
    GUI_MAP_OPEN,
    GUI_CLOSED,
    GUI_NO_PORT,
    GUI_NEED_DESTINATION,
    GUI_NEED_SELECTION,
    GUI_ALREADY_RUNNING,
    GUI_PAGE_WRITTEN,
    KIT_OPENED,
    KIT_CARRIES_CODE,
    KIT_NO_LIST,
    KIT_DAMAGED,
    KIT_TOO_NEW,
    DERIVE_HEAD,
    DERIVE_ACCOUNT_ID,
    DERIVE_FINGERPRINT,
    DERIVE_PUBLIC_CODE,
    DERIVE_WALLET,
    DERIVE_SECRET_KEY,
    DERIVE_PUBLIC_ONLY,
    DERIVE_SECRET_WARNING,
    DERIVE_NOTHING_ELSE,
];

/// `n bytes` in a form a person reads. Deliberately plain: no locale-specific grouping, because
/// the number is a fact and the unit is what makes it legible.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes_read_as_sizes() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1_000), "1.0 KB");
        assert_eq!(human_bytes(1_500_000), "1.5 MB");
        assert_eq!(human_bytes(u64::MAX), "18446744.1 TB");
    }

    /// ⛔ A half-translated tool is worse than an English one: the person hits the Korean sentence,
    ///    trusts it, and then meets a blank where the next sentence should be.
    #[test]
    fn every_line_exists_in_both_languages() {
        for line in ALL_LINES {
            assert!(!line.0.trim().is_empty(), "an English line is empty");
            assert!(!line.1.trim().is_empty(), "a Korean line is empty");
        }
    }

    /// ⛔ The check above is only worth having if nothing can be declared and left out of the list
    ///    it walks. So this counts what the file actually declares, from the file itself.
    ///
    /// ⚠ The count is taken from the source with every run of whitespace flattened to one space,
    ///   NOT line by line. A declaration split over two lines — the name and its type on one, the
    ///   `Line(` on the next — was invisible to both halves of this check at once: the counter
    ///   skipped the line, and nothing pushed whoever wrote it towards the list below. The two
    ///   numbers then agreed, and a message existed that neither language check had ever read.
    ///   Flattening first means how a declaration is wrapped cannot decide whether it is counted,
    ///   so rustfmt may rewrap this file freely. What flattening must not do is let one
    ///   declaration's search run on into the next one — see the `;` stop below.
    ///
    /// ⚠ Both needles are spelled in two pieces, for the reason the network test in `args.rs`
    ///   spells its own in two pieces: written whole, the lines below would read as one more
    ///   declaration once the line breaks are gone, and this file would count a message it does
    ///   not have.
    #[test]
    fn no_message_can_be_added_without_joining_the_list_that_is_checked() {
        const DECL: &str = concat!("pub ", "const ");
        const OF_TYPE_LINE: &str = concat!(": Line = ", "Line");
        let source = include_str!("msg.rs");
        let flat = source.split_whitespace().collect::<Vec<_>>().join(" ");
        let declared = flat
            .match_indices(DECL)
            .filter(|&(at, _)| {
                let after_declaration = &flat[at + DECL.len()..];
                after_declaration
                    .split_once('(')
                    .is_some_and(|(name_and_type, _)| {
                        // ⚠ A `;` before that `(` means the declaration already ended and the
                        //   paren belongs to whatever comes next. Without this second stop, an
                        //   ordinary constant declared among the messages — say a length as a
                        //   `usize`, which ends at its own semicolon — reads on into the following
                        //   message's opening paren and is counted as a message. Measured on this
                        //   file: 62 counted where 61 exist, and the failure then told whoever
                        //   added the constant to register a message that does not exist. The
                        //   same stop is what keeps the list below out of the count wherever in
                        //   the file it sits, instead of only while it happens to be written last.
                        //   ⛔ Nothing in this comment may spell either needle: the count is taken
                        //   from this file, so a sentence about a declaration would become one.
                        !name_and_type.contains(';') && name_and_type.ends_with(OF_TYPE_LINE)
                    })
            })
            .count();
        println!("{declared} message declarations judged");
        // ⚠ A floor. A search that has stopped matching how this file is written would otherwise
        //   find nothing, and nothing would agree with an empty list without complaining.
        assert!(
            declared >= 55,
            "only {declared} declarations were found in this file — this search no longer matches \
             how the messages above are written"
        );
        // ⛔ Two numbers can be made to agree without the file being honest: list one message
        //   twice and leave another out, and the totals still match while the language checks
        //   above never read the one that was left out. Measured on this file — a message whose
        //   Korean half was an empty string, plus a second mention of an existing entry, and this
        //   check stayed green. Names are not visible here at run time, so the text stands in for
        //   the name: two entries carrying the same pair are either that trick or a copy-paste.
        let mut seen = std::collections::HashSet::new();
        for line in ALL_LINES {
            assert!(
                seen.insert((line.0, line.1)),
                "the list names the same message twice, which would let the totals below agree \
                 while another message went unlisted and unread: {}",
                line.0
            );
        }
        assert_eq!(
            declared,
            ALL_LINES.len(),
            "{declared} messages are declared but {} are in ALL_LINES — add the new one there",
            ALL_LINES.len()
        );
    }

    /// The English text is what a person quotes when something goes wrong, so it may not be a
    /// translation of nothing.
    #[test]
    fn the_two_languages_are_actually_different_text() {
        for line in ALL_LINES {
            assert_ne!(line.0, line.1, "a line was never translated: {}", line.0);
        }
    }
}
