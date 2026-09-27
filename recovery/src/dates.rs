//! Putting a restored file's recorded date back on it (`docs/RECOVERY-MANIFEST.md` §2.3).
//!
//! Moved out of `restore.rs` unchanged when Filecoin parts needed the room there (`check:size`).
//! ⛔ The dates decide nothing: they are stamped after the file is complete and renamed into place,
//!    and a failure to stamp becomes a note, never a failed file.

use std::fs;
use std::path::Path;

use nmts_crypto::manifest::Item;

use crate::restore::Note;

/// Seconds since the Unix epoch for an RFC 3339 timestamp, or `None` for anything unexpected.
///
/// # Why this is written out rather than pulled in
/// It is the only date arithmetic in the program, it runs on values that decide nothing (see
/// [`Item::created_at`] in the crypto crate), and a date crate would be a dependency added to a
/// recovery tool for cosmetics. Unexpected input answers `None` — the file still comes back, it
/// just keeps today's date.
///
/// Handles the shapes NMTS writes and the ones a re-implementation is likely to: `Z`, a numeric
/// offset, and an optional fractional part, which is discarded (a modification time to the second
/// is what every filesystem here stores anyway).
fn rfc3339_seconds(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || (b[10] != b'T' && b[10] != b't') {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> { s.get(from..to)?.parse::<i64>().ok() };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, min, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    // Days from the civil calendar (Howard Hinnant's algorithm), era-based so it needs no tables
    // and is correct before 1970 as well as after.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    // The trailing zone. Anything after the seconds is skipped up to the sign or the Z.
    let rest = &s[19..];
    let rest = rest.strip_prefix('.').map_or(rest, |frac| {
        let digits = frac.len() - frac.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        &frac[digits..]
    });
    let offset = match rest.as_bytes().first() {
        None => 0,
        Some(b'Z') | Some(b'z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let (oh, om) = (
                rest.get(1..3)?.parse::<i64>().ok()?,
                rest.get(4..6)?.parse::<i64>().ok()?,
            );
            let magnitude = oh * 3600 + om * 60;
            if *sign == b'+' {
                magnitude
            } else {
                -magnitude
            }
        }
        Some(_) => return None,
    };
    Some(days * 86_400 + hour * 3600 + min * 60 + sec - offset)
}

/// Put a file's recorded date back, reporting only a real failure.
///
/// `None` for a file whose list carried no date: nothing was attempted, so there is nothing to
/// report. `updated_at` wins over `created_at` because it is what a file manager shows and what a
/// person sorts by.
pub fn restore_date(dest: &Path, item: &Item) -> Option<Note> {
    let stamp = item.updated_at.as_deref().or(item.created_at.as_deref())?;
    let secs = rfc3339_seconds(stamp)?;
    let when = if secs >= 0 {
        std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs as u64))
    } else {
        std::time::UNIX_EPOCH.checked_sub(std::time::Duration::from_secs(secs.unsigned_abs()))
    }?;
    // Opened for writing because that is what setting a time requires; the file is already
    // complete and renamed into place, so nothing here can damage it.
    match fs::File::options()
        .write(true)
        .open(dest)
        .and_then(|f| f.set_modified(when))
    {
        Ok(()) => None,
        Err(_) => Some(Note::DateNotRestored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The date arithmetic, against values worked out by hand.
    ///
    /// ⛔ Hand-computed on purpose. A test that built the expected number with the same expression
    /// the function uses would agree with the function whatever either of them did.
    #[test]
    fn rfc3339_is_read_the_way_every_writer_spells_it() {
        // 2026-03-04T05:06:07Z — see `tests/common/mod.rs::UPDATED_AT_UNIX` for the working.
        assert_eq!(rfc3339_seconds("2026-03-04T05:06:07Z"), Some(1_772_600_767));
        // The epoch itself, and the day before it: negative seconds are representable, so a file
        // dated before 1970 does not silently become 1970.
        assert_eq!(rfc3339_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_seconds("1969-12-31T00:00:00Z"), Some(-86_400));
        // A fraction is discarded rather than refused — every filesystem here stores whole seconds.
        assert_eq!(
            rfc3339_seconds("2026-03-04T05:06:07.250Z"),
            rfc3339_seconds("2026-03-04T05:06:07Z")
        );
        // An offset moves the instant, in both directions.
        assert_eq!(
            rfc3339_seconds("2026-03-04T14:06:07+09:00"),
            rfc3339_seconds("2026-03-04T05:06:07Z")
        );
        assert_eq!(
            rfc3339_seconds("2026-03-03T21:06:07-08:00"),
            rfc3339_seconds("2026-03-04T05:06:07Z")
        );
        // A leap second is accepted rather than rejecting the file's whole date.
        assert!(rfc3339_seconds("2016-12-31T23:59:60Z").is_some());
    }

    /// Anything unexpected answers `None`, and `None` costs a date rather than a file.
    #[test]
    fn a_date_that_is_not_a_date_is_simply_not_used() {
        for bad in [
            "",
            "yesterday",
            "2026-03-04",
            "2026-13-04T00:00:00Z",
            "2026-03-32T00:00:00Z",
            "2026-03-04T25:00:00Z",
            "2026-03-04T05:06:07 CET",
        ] {
            assert_eq!(rfc3339_seconds(bad), None, "{bad:?} was read as a date");
        }
    }
}
