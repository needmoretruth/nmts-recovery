//! Everything this program says to a person, in both languages it can say it in.
//!
//! # English is what it says unless asked otherwise
//! The tool exists for the day NMTS is gone. On that day the person running it may be the account
//! holder, or it may be someone helping them — a friend, a relative, whoever ends up holding the
//! drive. Which of those two reads Korean is not something the moment of saving the map could
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
    "This account code does not belong to this recovery map. The code is valid, but it identifies \
     a different account. Check that you are using the map file saved from this account.",
    "이 계정 코드는 이 복구 지도의 것이 아닙니다. 코드 자체는 올바르지만 다른 계정을 가리킵니다. \
     이 계정에서 저장한 지도 파일이 맞는지 확인하십시오.",
);

pub const MAP_NOT_A_MAP: Line = Line(
    "This file is not an NMTS recovery map.",
    "이 파일은 NMTS 복구 지도가 아닙니다.",
);

pub const MAP_WILL_NOT_OPEN: Line = Line(
    "The recovery map would not open. The account code is right for this account, so the map file \
     itself has been changed or damaged since it was saved.",
    "복구 지도가 열리지 않았습니다. 계정 코드는 이 계정의 것이 맞으므로, 지도 파일 자체가 저장된 \
     뒤에 바뀌었거나 손상된 것입니다.",
);

pub const MAP_TOO_NEW: Line = Line(
    "This map was written in a newer format than this build understands. Use a newer \
     nmts-recovery; nothing was read.",
    "이 지도는 이 판이 아는 것보다 새로운 형식으로 쓰였습니다. 더 새로운 nmts-recovery를 쓰십시오. \
     아무것도 읽지 않았습니다.",
);

pub const MAP_SEQ_DISAGREES: Line = Line(
    "This file's header and the sealed map inside it disagree about which map this is. The sealed \
     one was used; the header is the part anyone holding the file could have edited",
    "이 파일의 겉면과 그 안에 봉인된 지도가 서로 다른 번호를 말합니다. 봉인된 쪽을 썼습니다. \
     겉면은 파일을 가진 사람이면 누구나 고칠 수 있는 자리입니다",
);

pub const SUMMARY_HEAD: Line = Line("This map covers:", "이 지도가 담고 있는 것:");

pub const NOTHING_MATCHED: Line = Line(
    "Nothing in this map matches --only.",
    "--only 에 해당하는 것이 이 지도에 없습니다.",
);

pub const FETCH_PLAN_HEAD: Line = Line(
    "Fetch these, save each under the filename shown, then run again with --blobs-dir:",
    "아래를 받아 표시된 이름으로 저장한 뒤 --blobs-dir 로 다시 실행하십시오:",
);

pub const RESTORE_HEAD: Line = Line("Restoring:", "되찾는 중:");

pub const DONE_ALL: Line = Line(
    "Done. Every file in the map was restored and its contents verified.",
    "끝났습니다. 지도에 있는 파일을 모두 되찾았고 내용까지 확인했습니다.",
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

pub const PART_PLACEMENT_UNVERIFIABLE: Line = Line(
    "note: this map is an older version that did not record where each piece belongs, so the \
     order of the pieces is the map's claim and could not be checked against the pieces \
     themselves.",
    "참고: 이 지도는 조각의 자리를 기록하지 않던 옛 판이라, 조각의 순서는 지도의 주장일 뿐 조각 \
     자체와 대조하지 못했습니다.",
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
    "The window has handed over a recovery map. It needs your account code now, and it is asking \
     here rather than in the browser on purpose.",
    "화면에서 복구 지도를 넘겨받았습니다. 이제 계정 코드가 필요한데, 브라우저가 아니라 여기서 묻는 \
     것은 일부러 그렇게 한 것입니다.",
);

pub const GUI_MAP_OPEN: Line = Line(
    "The map is open. Go back to the browser window.",
    "지도가 열렸습니다. 브라우저 화면으로 돌아가십시오.",
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
    MAP_WILL_NOT_OPEN,
    MAP_TOO_NEW,
    MAP_SEQ_DISAGREES,
    SUMMARY_HEAD,
    NOTHING_MATCHED,
    FETCH_PLAN_HEAD,
    RESTORE_HEAD,
    DONE_ALL,
    DONE_PARTIAL,
    NO_HASH_NOTE,
    UNKNOWN_NETWORK,
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
    #[test]
    fn no_message_can_be_added_without_joining_the_list_that_is_checked() {
        let source = include_str!("msg.rs");
        let declared = source
            .lines()
            .filter(|l| l.starts_with("pub const ") && l.contains(": Line = Line("))
            .count();
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
