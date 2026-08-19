//! Turning an opened recovery list into files on a disk.
//!
//! Everything a recovery has to get right lives here, and it is worth naming what "right" means,
//! because the failure this code exists to prevent is not "an error message" — it is a person
//! believing they got their files back and finding out otherwise years later:
//!
//!   1. **Placement is checked positionally, never by sorting.** Each part's SEALED header says
//!      which position it belongs at; this code compares that against the position it is about to
//!      write into. Sorting the parts by their own claimed index first would make every
//!      permutation agree with itself, which is exactly the defect
//!      `docs/RECOVERY-MANIFEST.md` §2.1 was written after finding.
//!   2. **The length is checked twice, against two different authorities.** The list says how long
//!      a part is; the part's own header says so too, under the AEAD. Both must agree before a
//!      byte is written, and the stream's own end-of-stream check runs after.
//!   3. **The whole file is hashed and compared** when the list recorded a hash. This is the only
//!      check that spans parts, so it is the only one that would catch a list whose parts are each
//!      individually perfect and collectively the wrong file.
//!   4. **Nothing half-written is left looking finished.** Every file is written under a temporary
//!      name in its own destination directory and renamed only after every check above has passed.
//!   5. **A failure costs one file, not the recovery.** One unreachable blob must not stop the
//!      other four hundred files from coming back. What failed is named, and the exit code says
//!      something did.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use nmts_crypto::framing::{Header, PartPlacement, StreamDecryptor, HEADER_LEN};
use nmts_crypto::manifest::{Item, Placement, Quilt, RecoveryManifest};
use nmts_crypto::wrap::DEK_LEN;
use sha2::{Digest, Sha256};

use crate::source::{BlobRef, BlobSource, SourceError, KNOWN_NETWORK};

/// How much ciphertext is pulled from the source per read. Small enough to keep memory flat on a
/// 1 GiB part, large enough that a syscall is not paid per kilobyte.
const READ_CHUNK: usize = 256 * 1024;

/// Why an item's parts could not be turned into things to fetch.
///
/// Two reasons, kept apart because a person can act on one of them and not the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefProblem {
    /// The list names a storage network this build cannot read.
    UnknownNetwork,
    /// The item is placed in "the quilt this document came from", and this document came from a
    /// file. Nothing about the file says which quilt that was, and guessing would fetch a
    /// stranger's bytes — so the item is reported rather than attempted.
    OwnQuiltUnknown,
}

/// One file the list describes, resolved to where it would land.
pub struct PlannedItem<'a> {
    pub item: &'a Item,
    /// Destination, already confined under the output directory.
    pub dest: PathBuf,
    /// Set when the item's own path or name had to be altered to be writable here.
    pub renamed_from: Option<String>,
    /// Blob id of the quilt this manifest was READ from, when it was read from one.
    ///
    /// It is the reader's knowledge, not the document's — the document cannot contain it (NRM-3,
    /// `Quilt::identifier`). Carried per item so `refs()` needs no extra argument and no call
    /// site can forget to supply it.
    pub own_quilt: Option<&'a str>,
}

impl<'a> PlannedItem<'a> {
    /// The parts, in list order, as source references paired with the plaintext length their
    /// SEALED stream declares.
    ///
    /// ⚠ That is [`Part::stream_plaintext_len`], not `plaintext_len`: a PADDED part was sealed
    /// larger than the bytes it contributes, so the stored object — and everything sized from it —
    /// follows the padded number. The real number stays with the part and is applied when the
    /// plaintext is written out.
    pub fn refs(&self) -> Result<Vec<(BlobRef, u64)>, RefProblem> {
        let mut out = Vec::with_capacity(self.item.parts.len());
        for part in &self.item.parts {
            if part.network_name() != KNOWN_NETWORK {
                return Err(RefProblem::UnknownNetwork);
            }
            // A quilted item is one patch inside one shared blob, so it has exactly one part and
            // the patch is what an aggregator serves it by. Reading it as a whole blob would hand
            // back the entire cohort — everyone's ciphertext, not this file's.
            let r = match (self.item.quilt.as_ref().and_then(Quilt::placement), self.item.parts.len()) {
                (Some(Placement::Absolute { patch_id, .. }), 1) => BlobRef::Patch(patch_id.to_owned()),
                (Some(Placement::OwnQuilt { identifier }), 1) => BlobRef::InQuilt {
                    quilt_id: self.own_quilt.ok_or(RefProblem::OwnQuiltUnknown)?.to_owned(),
                    identifier: identifier.to_owned(),
                },
                // Not quilted (or a shape the parse already refuses): the part names its own blob.
                _ => BlobRef::Whole(
                    part.blob_id
                        .clone()
                        .ok_or(RefProblem::OwnQuiltUnknown)?,
                ),
            };
            out.push((r, part.stream_plaintext_len()));
        }
        Ok(out)
    }
}

/// Resolve every item in the list to a destination under `out`.
///
/// `only` filters on the path and the name as the LIST spells them, not as they land on disk — a
/// person filtering for a folder they remember should not have to know what this program did to
/// make the name writable.
pub fn plan<'a>(
    manifest: &'a RecoveryManifest,
    out: &Path,
    only: Option<&str>,
    own_quilt: Option<&'a str>,
) -> Vec<PlannedItem<'a>> {
    let mut taken: HashSet<PathBuf> = HashSet::new();
    let mut planned = Vec::new();
    for item in &manifest.items {
        if let Some(needle) = only {
            let hay = format!("{}/{}", item.path, item.name);
            if !hay.contains(needle) {
                continue;
            }
        }
        let original = format!("{}/{}", item.path.trim_end_matches('/'), item.name);
        let mut dest = out.to_path_buf();
        let mut altered = false;
        for seg in item.path.split('/').filter(|s| !s.is_empty()) {
            let safe = safe_segment(seg);
            altered |= safe != seg;
            dest.push(safe);
        }
        let safe_name = safe_segment(&item.name);
        altered |= safe_name != item.name;
        dest.push(&safe_name);
        // Two files may legitimately share a name. NMTS keeps no version history — a second file
        // of the same name is numbered `(2)` rather than replacing the first — and a list written
        // across a rename can hold both. Either way, letting the second overwrite the first here
        // would lose a file silently, which is the one thing a recovery may never do.
        let dest = deduplicate(dest, &mut taken);
        planned.push(PlannedItem {
            item,
            dest,
            renamed_from: if altered { Some(original) } else { None },
            own_quilt,
        });
    }
    planned
}

/// Make one path segment safe to write on any of the three desktop platforms.
///
/// ⛔ It SANITISES rather than refuses, and that is a considered trade. Refusing would mean a
///    person loses a file because of a character in its name — in the one situation where the
///    file cannot be re-uploaded. So the bytes always land, and `renamed_from` says what the name
///    was, so nothing changes silently.
fn safe_segment(seg: &str) -> String {
    let cleaned: String = seg
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if (c as u32) < 0x20 || c == '\u{7f}' => '_',
            c => c,
        })
        .collect();
    // Trailing dots and spaces are silently dropped by Windows, which turns `a.` and `a` into the
    // same file. Leading dots are kept: a file genuinely named `.bashrc` should come back as `.bashrc`.
    let trimmed = cleaned.trim_end_matches([' ', '.']);
    // `.` and `..` are directory traversal, not names. They are the only segments that could take
    // a write outside the output directory, and they cannot survive this function.
    let out = match trimmed {
        "" | "." | ".." => "_",
        other => other,
    };
    // Windows device names are unusable as filenames whatever the extension.
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = out.split('.').next().unwrap_or(out).to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        format!("_{out}")
    } else {
        out.to_string()
    }
}

/// Give a path a `(2)`, `(3)` … suffix until it is one nothing else claimed.
fn deduplicate(dest: PathBuf, taken: &mut HashSet<PathBuf>) -> PathBuf {
    if taken.insert(dest.clone()) {
        return dest;
    }
    let parent = dest.parent().map(Path::to_path_buf).unwrap_or_default();
    let name = dest
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();
    let (stem, ext) = match name.rfind('.') {
        // A leading dot is the whole name (`.bashrc`), not an empty stem with an extension.
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name.as_str(), ""),
    };
    for n in 2..u32::MAX {
        let candidate = parent.join(format!("{stem} ({n}){ext}"));
        if taken.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("a directory cannot hold u32::MAX files of one name")
}

/// What happened to one file.
pub struct Outcome {
    /// Notes worth printing even though the file came back — an unverifiable part order, a
    /// missing content hash.
    pub notes: Vec<Note>,
    pub bytes: u64,
}

/// Something true about a restored file that the person should know.
#[derive(Debug, PartialEq, Eq)]
pub enum Note {
    /// The list is NRM-1: it never recorded where each part belongs.
    PartOrderUnverifiable,
    /// The item predates content hashes, so nothing spans the parts.
    NoContentHash,
}

/// Fetch, decrypt, verify and write one file. Returns an error message fit to show a person.
///
/// `on_bytes` is called with each run of plaintext as it is produced, so a caller that has a
/// progress bar can move it. ⛔ It is told about bytes that have been WRITTEN, not bytes that have
/// arrived — a bar that runs ahead of the disk is a bar that finishes before the file does.
pub fn restore_item(
    planned: &PlannedItem<'_>,
    source: &dyn BlobSource,
    overwrite: bool,
    lang: crate::args::Lang,
    on_bytes: &mut dyn FnMut(u64),
) -> Result<Outcome, String> {
    let item = planned.item;
    if !overwrite && planned.dest.exists() {
        return Err(format!(
            "{} is already there. Use --overwrite to replace it.",
            planned.dest.display()
        ));
    }
    let refs = planned.refs().map_err(|problem| {
        let why = match problem {
            RefProblem::UnknownNetwork => crate::msg::UNKNOWN_NETWORK.get(lang),
            RefProblem::OwnQuiltUnknown => crate::msg::OWN_QUILT_UNKNOWN.get(lang),
        };
        format!("\"{}\" {why}", item.name)
    })?;
    if refs.is_empty() {
        return Err(format!("\"{}\" has no stored parts in the list", item.name));
    }

    let dek = decode_dek(&item.dek)?;
    let mut notes = Vec::new();
    let total = u32::try_from(refs.len()).map_err(|_| "that file has more parts than a part counter can hold".to_string())?;

    let parent = planned.dest.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("{} could not be created ({e})", parent.display()))?;
    // The temporary sits in the SAME directory as the destination so the final rename is within
    // one filesystem and therefore atomic. A temp in /tmp would turn it into a copy that can fail
    // halfway with the destination already replaced.
    let tmp = parent.join(format!(".nmts-recovery-{}.part", sanitize_id(&item.id)));
    let mut written: u64 = 0;
    let mut hasher = Sha256::new();

    let result = (|| -> Result<(), String> {
        let mut file = fs::File::create(&tmp).map_err(|e| format!("{} could not be written ({e})", tmp.display()))?;
        for (index, (blob, part_len)) in refs.iter().enumerate() {
            let position = u32::try_from(index).expect("index < total, which is a u32");
            // ⛔ THE PLACEMENT THIS PART MUST CLAIM comes from the loop counter — the position
            //    being written into — and never from the part's own record. Reading it back out of
            //    the thing being checked compares a value with itself.
            let claimed = item.parts[index].part_index;
            if claimed.is_none() {
                if !notes.contains(&Note::PartOrderUnverifiable) {
                    notes.push(Note::PartOrderUnverifiable);
                }
            } else if claimed != Some(u64::from(position)) {
                return Err(format!(
                    "the list places part {} of \"{}\" at position {}",
                    claimed.unwrap_or_default(),
                    item.name,
                    position
                ));
            }

            // What this part CONTRIBUTES, which is less than what its stream holds when the part
            // was padded. Everything after this line is about the real bytes only: the padding is
            // decrypted (it is inside the AEAD, so it has to be) and then dropped — never written,
            // never hashed, never counted.
            let contributes = item.parts[index].plaintext_len;
            source
                .open(blob, *part_len, &mut |reader| {
                    let kept = decrypt_part(
                        reader,
                        &dek,
                        PartPlacement::at(position, total),
                        *part_len,
                        contributes,
                        &mut file,
                        &mut hasher,
                        on_bytes,
                    )?;
                    written += kept;
                    Ok(())
                })
                .map_err(|e: SourceError| match e {
                    SourceError::Unavailable(m) => format!("part {position} could not be fetched: {m}"),
                    SourceError::Consumer(m) => format!("part {position}: {m}"),
                })?;
        }
        file.flush().map_err(|e| format!("the file could not be finished ({e})"))?;

        if written != item.size {
            return Err(format!(
                "the list says this file is {} bytes and its parts produced {written}",
                item.size
            ));
        }
        // The only check that spans parts. Without it, a list naming the right parts in the right
        // order for the WRONG file passes everything else, because every part is internally valid.
        match &item.content_hash {
            Some(expected) => {
                let got: [u8; 32] = hasher.finalize_reset().into();
                let want = nmts_crypto::b64::decode(expected)
                    .map_err(|_| "the list's recorded content hash is not readable".to_string())?;
                if want != got {
                    return Err("the reassembled file does not match the hash the list recorded".to_string());
                }
            }
            None => notes.push(Note::NoContentHash),
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            fs::rename(&tmp, &planned.dest)
                .map_err(|e| format!("{} could not be put in place ({e})", planned.dest.display()))?;
            Ok(Outcome { notes, bytes: written })
        }
        Err(e) => {
            // Leaving the temporary behind would look like a partial file that might be usable.
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Read one NCF-3 stream from `reader`, writing its plaintext out as it decrypts.
///
/// `map_says` is what the list says the stream's header declares; `keep` is how many of those
/// bytes belong to the file. They differ only for a PADDED part, and then by exactly the padding.
/// Returns the bytes KEPT — which is what the file grew by.
///
/// ⛔ The padding is decrypted rather than skipped, and that is not an oversight. It is sealed
///    inside the same AEAD as the file's own bytes, so the chunk tags, the final-chunk flag and
///    the recovered length only add up if every byte goes through the decryptor. Reading a shorter
///    prefix would turn "this stream is intact" into "the front of this stream is intact".
#[allow(clippy::too_many_arguments)]
fn decrypt_part(
    reader: &mut dyn Read,
    dek: &[u8; DEK_LEN],
    placement: PartPlacement,
    map_says: u64,
    keep: u64,
    out: &mut dyn Write,
    hasher: &mut Sha256,
    on_bytes: &mut dyn FnMut(u64),
) -> Result<u64, String> {
    let mut header_bytes = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut header_bytes)
        .map_err(|_| "the stored bytes are too short to be an encrypted part".to_string())?;
    let header = Header::parse(&header_bytes).map_err(|e| format!("the part's header is not readable ({e})"))?;
    // Both of these compare the SEALED header against something the header did not supply.
    header
        .verify_placement(placement)
        .map_err(|_| {
            format!(
                "this is part {} of {}, where part {} of {} belongs",
                header.part_index, header.part_total, placement.index, placement.total
            )
        })?;
    if header.plaintext_len != map_says {
        return Err(format!(
            "the list says this part is {map_says} bytes and the part itself says {}",
            header.plaintext_len
        ));
    }

    // Constructing this verifies the key commitment, so a decryptor that exists is one whose
    // header names this exact key (NCF-3 §4.2).
    let mut dec = StreamDecryptor::new(dek, &header_bytes)
        .map_err(|_| "this part does not open with your account's key".to_string())?;
    let mut buf = vec![0u8; READ_CHUNK];
    let mut left_to_keep = keep;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("the stored bytes stopped arriving ({e})"))?;
        if n == 0 {
            break;
        }
        let plain = dec
            .push(&buf[..n])
            .map_err(|e| format!("the stored bytes failed their authentication check ({e})"))?;
        if !plain.is_empty() {
            let take = usize::try_from(left_to_keep).unwrap_or(usize::MAX).min(plain.len());
            if take > 0 {
                out.write_all(&plain[..take]).map_err(|e| format!("the file could not be written ({e})"))?;
                hasher.update(&plain[..take]);
                left_to_keep -= take as u64;
                on_bytes(take as u64);
            }
        }
    }
    // The anti-truncation gate: the chunk count, the final flag and the recovered length all have
    // to agree with the header before any of this counts.
    dec.finish()
        .map_err(|e| format!("the part ended before it was complete ({e})"))?;
    if left_to_keep != 0 {
        // Unreachable while `padded_len > plaintext_len` is enforced at parse time and the header
        // was just checked against the padded number — which is exactly why it is stated here
        // rather than assumed: if either of those two ever stops holding, this says so instead of
        // handing back a file that is short by `left_to_keep` bytes.
        return Err(format!(
            "this part was {left_to_keep} bytes shorter than the list said it would be"
        ));
    }
    Ok(keep)
}

/// The item's DEK, which the list carries raw because the list is itself one envelope.
fn decode_dek(b64: &str) -> Result<[u8; DEK_LEN], String> {
    let raw = nmts_crypto::b64::decode(b64).map_err(|_| "the list's stored key is not readable".to_string())?;
    raw.try_into()
        .map_err(|_| "the list's stored key is the wrong length".to_string())
}

/// An item id reduced to something safe in a temporary filename.
fn sanitize_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(40)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Component;

    #[test]
    fn traversal_cannot_survive_a_path_segment() {
        assert_eq!(safe_segment(".."), "_");
        assert_eq!(safe_segment("."), "_");
        assert_eq!(safe_segment(""), "_");
        assert_eq!(safe_segment("a/b"), "a_b");
        assert_eq!(safe_segment("a\\b"), "a_b");
        assert_eq!(safe_segment("C:"), "C_");
    }

    /// ⛔ The invariant the whole path treatment exists for: whatever the list says, the write lands
    ///    under the output directory. A list is a file somebody could have edited.
    #[test]
    fn no_planned_destination_escapes_the_output_directory() {
        let manifest = manifest_with_paths(&[
            ("/../../etc", "passwd"),
            ("/..", ".."),
            ("/a/../../b", "x"),
            ("/", "/etc/shadow"),
        ]);
        let out = Path::new("/tmp/out");
        for p in plan(&manifest, out, None, None) {
            assert!(p.dest.starts_with(out), "{} escaped", p.dest.display());
            assert!(
                !p.dest.components().any(|c| c == Component::ParentDir),
                "{} still contains ..",
                p.dest.display()
            );
        }
    }

    #[test]
    fn an_altered_name_is_reported_and_an_untouched_one_is_not() {
        let manifest = manifest_with_paths(&[("/docs", "notes.txt"), ("/docs", "a:b.txt")]);
        let planned = plan(&manifest, Path::new("/tmp/out"), None, None);
        assert_eq!(planned[0].renamed_from, None);
        assert_eq!(planned[1].renamed_from.as_deref(), Some("/docs/a:b.txt"));
    }

    #[test]
    fn two_files_of_one_name_both_land() {
        let manifest = manifest_with_paths(&[("/d", "a.txt"), ("/d", "a.txt"), ("/d", "a.txt")]);
        let planned = plan(&manifest, Path::new("/tmp/out"), None, None);
        assert!(planned[0].dest.ends_with("a.txt"));
        assert!(planned[1].dest.ends_with("a (2).txt"));
        assert!(planned[2].dest.ends_with("a (3).txt"));
    }

    #[test]
    fn a_dotfile_keeps_its_leading_dot_and_numbers_after_the_whole_name() {
        let manifest = manifest_with_paths(&[("/", ".bashrc"), ("/", ".bashrc")]);
        let planned = plan(&manifest, Path::new("/tmp/out"), None, None);
        assert!(planned[0].dest.ends_with(".bashrc"));
        assert!(planned[1].dest.ends_with(".bashrc (2)"));
    }

    #[test]
    fn windows_device_names_do_not_become_devices() {
        assert_eq!(safe_segment("nul"), "_nul");
        assert_eq!(safe_segment("CON.txt"), "_CON.txt");
        assert_eq!(safe_segment("console.txt"), "console.txt");
    }

    #[test]
    fn only_filters_on_what_the_map_says_not_on_what_lands() {
        let manifest = manifest_with_paths(&[("/photos", "a:b.jpg"), ("/docs", "c.txt")]);
        let planned = plan(&manifest, Path::new("/tmp/out"), Some("a:b"), None);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].item.name, "a:b.jpg");
    }

    /// A quilted item is served by its patch id — reading it as a whole blob would hand back the
    /// entire cohort instead of this file.
    #[test]
    fn a_quilted_item_is_fetched_by_its_patch() {
        let mut manifest = manifest_with_paths(&[("/", "a.txt")]);
        manifest.items[0].quilt = Some(nmts_crypto::manifest::Quilt {
            quilt_blob_id: Some("QUILT".into()),
            patch_id: Some("PATCH".into()),
            identifier: None,
        });
        let planned = plan(&manifest, Path::new("/tmp/out"), None, None);
        let refs = planned[0].refs().expect("a known network");
        assert_eq!(refs[0].0, BlobRef::Patch("PATCH".into()));
    }

    /// An item the list places in its OWN bundle is fetched from the bundle the list came from,
    /// by the name the writer gave it (NRM-3).
    ///
    /// This is the half of a recovery that would otherwise be lost silently: those are the files
    /// from the very upload the list rode along with, and for somebody who uploaded once and never
    /// again they are ALL of the files.
    #[test]
    fn an_item_in_the_lists_own_bundle_is_fetched_from_that_bundle() {
        let mut manifest = manifest_with_paths(&[("/", "a.txt")]);
        manifest.items[0].parts[0].blob_id = None;
        manifest.items[0].quilt = Some(nmts_crypto::manifest::Quilt {
            quilt_blob_id: None,
            patch_id: None,
            identifier: Some("NAME".into()),
        });
        let planned = plan(&manifest, Path::new("/tmp/out"), None, Some("FOUND-IN"));
        let refs = planned[0].refs().expect("a bundle is known");
        assert_eq!(
            refs[0].0,
            BlobRef::InQuilt {
                quilt_id: "FOUND-IN".into(),
                identifier: "NAME".into()
            }
        );
    }

    /// ⛔ The same item, in a list read from a FILE, is refused rather than fetched.
    ///
    /// Nothing in a file says which bundle it was stored in, so there is no bundle to resolve
    /// against. The tempting guess — any bundle the account owns — would hand back somebody
    /// else's ciphertext and fail as "damaged", which is the wrong story entirely.
    #[test]
    fn the_same_item_read_from_a_file_says_so_instead_of_guessing() {
        let mut manifest = manifest_with_paths(&[("/", "a.txt")]);
        manifest.items[0].parts[0].blob_id = None;
        manifest.items[0].quilt = Some(nmts_crypto::manifest::Quilt {
            quilt_blob_id: None,
            patch_id: None,
            identifier: Some("NAME".into()),
        });
        let planned = plan(&manifest, Path::new("/tmp/out"), None, None);
        assert_eq!(planned[0].refs(), Err(RefProblem::OwnQuiltUnknown));
    }

    #[test]
    fn a_network_this_build_does_not_know_is_refused_rather_than_guessed() {
        let mut manifest = manifest_with_paths(&[("/", "a.txt")]);
        manifest.items[0].parts[0].network = Some("something-else".into());
        let planned = plan(&manifest, Path::new("/tmp/out"), None, None);
        assert_eq!(planned[0].refs(), Err(RefProblem::UnknownNetwork));
    }

    fn manifest_with_paths(specs: &[(&str, &str)]) -> RecoveryManifest {
        RecoveryManifest {
            v: 2,
            seq: 1,
            prev_manifest_blob_id: None,
            generated_at: "2026-08-17T00:00:00Z".into(),
            account_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            items: specs
                .iter()
                .enumerate()
                .map(|(i, (path, name))| Item {
                    id: format!("item-{i}"),
                    name: (*name).into(),
                    path: (*path).into(),
                    size: 0,
                    dek: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                    kind: "file".into(),
                    content_hash: None,
                    parts: vec![nmts_crypto::manifest::Part {
                        part_index: Some(0),
                        blob_id: Some(format!("blob-{i}")),
                        plaintext_len: 0,
                        padded_len: None,
                        network: None,
                        sui_object_id: None,
                    }],
                    quilt: None,
                })
                .collect(),
        }
    }
}
