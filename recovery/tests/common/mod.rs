//! The synthesised account both end-to-end test files drive the program with.
//!
//! # Why it is shared rather than copied
//! Two test files run the same program two ways — from the terminal and through the control
//! window — and the whole point of having both is that they exercise ONE recovery. If each built
//! its own fixture, a change to how a list is written could be made in one and forgotten in the
//! other, and the pair would go on passing while agreeing about nothing.
//!
//! Everything here is real: a real account code, real NCF-3 streams under real per-file keys, and
//! a real sealed list, all produced by the same crate the browser compiles to WASM.

// Each integration test binary compiles this module separately, so whichever one does not call a
// given helper would otherwise report it as dead. The helpers are used; just not all by everyone.
#![allow(dead_code)]

use std::fs;
use std::process::Command;

use nmts_crypto::codes::AccountCode;
use nmts_crypto::framing::StreamEncryptor;
use nmts_crypto::manifest::{Item, Part, Quilt, RecoveryManifest};
use nmts_crypto::{b64, kdf, wrap};

/// One synthesised account with a list, a blob folder, and somewhere to restore into.
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub code: AccountCode,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("blobs")).expect("blobs dir");
        fs::create_dir_all(dir.path().join("out")).expect("out dir");
        let code = AccountCode::generate();
        fs::write(dir.path().join("code.txt"), code.display()).expect("code file");
        Fixture { dir, code }
    }

    pub fn path(&self, rel: &str) -> std::path::PathBuf {
        self.dir.path().join(rel)
    }

    /// Encrypt `plaintext` as `parts` NCF-3 streams, write them where a source would find them,
    /// and return the manifest item describing them.
    pub fn add_file(&self, name: &str, path: &str, plaintext: &[u8], parts: u32, quilted: bool) -> Item {
        let dek = wrap::generate_dek();
        let chunk = plaintext.len().div_ceil(parts as usize).max(1);
        let mut manifest_parts = Vec::new();
        for index in 0..parts {
            let start = (index as usize) * chunk;
            let end = ((index as usize + 1) * chunk).min(plaintext.len());
            let slice = &plaintext[start.min(plaintext.len())..end.max(start.min(plaintext.len()))];
            let mut enc = StreamEncryptor::new_part(&dek, slice.len() as u64, index, parts);
            let mut stream = enc.header().to_vec();
            stream.extend_from_slice(&enc.push(slice).expect("push"));
            stream.extend_from_slice(&enc.finish().expect("finish"));

            // The id is arbitrary here; what matters is that the FILENAME the tool looks for is
            // derived from it the same way in the test and in the tool.
            let id = format!("{name}-{index}").replace('.', "-");
            let file_name = if quilted {
                format!("patch-{id}.bin")
            } else {
                format!("blob-{id}.bin")
            };
            fs::write(self.path("blobs").join(file_name), &stream).expect("blob");
            manifest_parts.push(Part {
                part_index: Some(u64::from(index)),
                blob_id: Some(id.clone()),
                plaintext_len: slice.len() as u64,
                network: Some("walrus".into()),
                sui_object_id: None,
            });
        }
        let quilt = quilted.then(|| Quilt {
            quilt_blob_id: Some("COHORT".into()),
            patch_id: Some(format!("{name}-0").replace('.', "-")),
            identifier: None,
        });
        Item {
            id: format!("id-{name}"),
            name: name.into(),
            path: path.into(),
            size: plaintext.len() as u64,
            dek: b64::encode(&*dek),
            kind: "file".into(),
            content_hash: Some(b64::encode(&sha256(plaintext))),
            parts: manifest_parts,
            quilt,
        }
    }

    /// Seal `items` into a `.nmtsmap` beside the blobs.
    pub fn write_map(&self, items: Vec<Item>) {
        let keys = kdf::derive(&self.code).expect("derive");
        let manifest = RecoveryManifest {
            v: 2,
            seq: 4,
            prev_manifest_blob_id: None,
            generated_at: "2026-08-17T09:00:00Z".into(),
            account_id: keys.account_id_b64(),
            items,
        };
        let sealed = manifest.encrypt(&keys.data_key).expect("seal");
        let doc = format!(
            r#"{{"format":"nmts-recovery-map","version":2,"nrm":2,"seq":4,
                 "generated_at":"2026-08-17T09:00:00Z","account_id":"{}",
                 "sealed":"{}","note":["en","ko"]}}"#,
            keys.account_id_b64(),
            b64::encode(&sealed)
        );
        fs::write(self.path("map.nmtsmap"), doc).expect("list file");
    }

    /// Write a recovery KIT beside the list: the same sealed document, plus the account code, in
    /// the one-file form the product now hands people.
    ///
    /// ⛔ Built here as TEXT rather than by calling the browser's builder, because the thing under
    ///    test is the agreement between two programs that never share code — the page writes this
    ///    file and the recovery program reads it. A fixture generated by the reader would agree
    ///    with the reader no matter what the writer does.
    pub fn write_kit(&self) {
        let map = fs::read_to_string(self.path("map.nmtsmap")).expect("map first");
        let keys = kdf::derive(&self.code).expect("derive");
        let kit = format!(
            "# NMTS Recovery Kit\nCreated: 2026-08-17T09:00:00Z\n\n\
             Anyone who holds this file holds this account.\n\n\
             Account code:\n    {}\n\n\
             --- BEGIN NMTS RECOVERY KIT DATA ---\n\
             {{\"format\":\"nmts-recovery-kit\",\"version\":2,\
               \"generated_at\":\"2026-08-17T09:00:00Z\",\"account_id\":\"{}\",\
               \"account_fingerprint\":\"AAAA-BBBB-CCCC-DDDD\",\"account_code\":\"{}\",\
               \"recovery_manifest_blob\":null,\"recovery_list\":{}}}\n\
             --- END NMTS RECOVERY KIT DATA ---\n",
            self.code.display(),
            keys.account_id_b64(),
            self.code.display(),
            map.trim()
        );
        fs::write(self.path("kit.txt"), kit).expect("kit file");
    }

    pub fn run(&self, extra: &[&str]) -> std::process::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"));
        cmd.arg("--map")
            .arg(self.path("map.nmtsmap"))
            .arg("--code-file")
            .arg(self.path("code.txt"))
            .arg("--lang")
            .arg("en")
            .args(extra);
        cmd.output().expect("run nmts-recovery")
    }

    /// The ordinary restore: from the blob folder, into the output folder.
    pub fn restore(&self) -> std::process::Output {
        self.run(&[
            "--out",
            self.path("out").to_str().expect("utf8 path"),
            "--blobs-dir",
            self.path("blobs").to_str().expect("utf8 path"),
        ])
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
