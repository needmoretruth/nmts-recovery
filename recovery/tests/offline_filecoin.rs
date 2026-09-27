//! NMTS Heavy, end to end, with no network: the binary given a list whose files are on Filecoin
//! (NRM-5 · `docs/RECOVERY-MANIFEST.md` §2.4), and the EVM wallet `--derive` prints.
//!
//! # What these tests cannot do offline, and where it is done instead
//! A copy that fails followed by one that answers needs an https server this machine trusts, which
//! an offline test does not have — every address a list may name is https. That order of attempts
//! is tested against a pretend network in `src/filecoin_tests.rs`; here, every company is made to
//! fail by pointing all outbound traffic at a closed local port, so the tests prove the sentence a
//! person reads and that nothing leaves the machine.

use std::fs;
use std::net::TcpListener;
use std::process::Command;

mod common;
use common::Fixture;

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// A local port nothing listens on: bound, read, released.
fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr").port()
}

/// The claim for Heavy: a key, a list and the stored pieces give the files back — beside a Walrus
/// file in the same list, one piece or several.
#[test]
fn heavy_files_come_back_from_a_blob_folder_beside_a_walrus_one() {
    let fx = Fixture::new();
    let small = b"kept at two companies".to_vec();
    let big: Vec<u8> = (0..150_000u32).map(|i| (i % 241) as u8).collect();
    let hosts = ["https://sp-a.example", "https://sp-b.example:8443"];
    fx.write_map(vec![
        fx.add_file("walrus.txt", "/docs", b"on walrus", 1, false),
        fx.add_heavy_file("heavy.txt", "/docs", &small, 1, &hosts),
        fx.add_heavy_file("heavy.bin", "/", &big, 2, &hosts),
    ]);
    // The list is a v5 document because it holds Filecoin parts, and says so before it is opened.
    let map = fs::read_to_string(fx.path("map.nmtsmap")).expect("list");
    assert!(map.contains(r#""nrm":5"#), "{map}");

    let out = fx.restore();
    assert!(
        out.status.success(),
        "{}\n{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    let read = |rel: &str| fs::read(fx.path("out").join(rel)).expect(rel);
    assert_eq!(read("docs/walrus.txt"), b"on walrus");
    assert_eq!(read("docs/heavy.txt"), small);
    assert_eq!(read("heavy.bin"), big);
}

/// The plan names each file's network, and the hand-fetch commands for a piece try its companies
/// in order and write the file the blob folder is read for.
#[test]
fn the_plan_names_each_files_network() {
    let fx = Fixture::new();
    let hosts = ["https://sp-a.example", "https://sp-b.example"];
    let heavy = fx.add_heavy_file("heavy.txt", "/", b"piece", 1, &hosts);
    let cid = heavy.parts[0].blob_id.clone().expect("a piece id");
    fx.write_map(vec![
        fx.add_file("walrus.txt", "/", b"blob", 1, false),
        heavy,
    ]);

    let listed = stdout(&fx.run(&["--list"]));
    let line = |name: &str| {
        listed
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or("")
            .to_string()
    };
    assert!(line("walrus.txt").ends_with("Walrus"), "{listed}");
    assert!(line("heavy.txt").ends_with("Filecoin"), "{listed}");

    let plan = stdout(&fx.run(&["--print-fetch-plan"]));
    let want = format!(
        "curl -fL -o piece-{cid}.bin https://sp-a.example/piece/{cid} || \
         curl -fL -o piece-{cid}.bin https://sp-b.example/piece/{cid}  # Filecoin"
    );
    assert!(plan.contains(&want), "{plan}");
    assert!(plan.contains("/v1/blobs/walrus-txt-0  # Walrus"), "{plan}");
    assert!(fx.path(&format!("blobs/piece-{cid}.bin")).exists());
}

/// ⛔ When no company returns a part, the person is told how many were asked, the exit code says
///    something failed, and nothing half-written is left. All traffic goes to a closed local port,
///    so this also proves the attempt (recorded addresses, then the registry) leaves no machine.
#[test]
fn when_no_company_returns_a_part_the_sentence_counts_them() {
    let fx = Fixture::new();
    let dead = format!("https://127.0.0.1:{}", closed_port());
    let item = fx.add_heavy_file(
        "lost.bin",
        "/",
        b"nobody has it",
        1,
        &[dead.as_str(), "https://sp-b.example"],
    );
    fx.write_map(vec![item]);

    let proxy = format!("http://127.0.0.1:{}", closed_port());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"));
    for var in [
        "NO_PROXY",
        "no_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        cmd.env_remove(var);
    }
    // On its own line: the public-repository gate reads a line starting with the env call as
    // an environment-file reference.
    cmd.env("ALL_PROXY", &proxy);
    let out = cmd
        .arg("--map")
        .arg(fx.path("map.nmtsmap"))
        .arg("--code-file")
        .arg(fx.path("code.txt"))
        .args([
            "--lang",
            "en",
            "--out",
            fx.path("out").to_str().expect("utf8"),
        ])
        .output()
        .expect("run");
    let said = stdout(&out);
    assert_eq!(out.status.code(), Some(3), "{said}");
    assert!(
        said.contains("Filecoin: none of the 2 storage companies returned this part."),
        "{said}"
    );
    assert_eq!(
        fs::read_dir(fx.path("out")).expect("out").count(),
        0,
        "{said}"
    );
}

/// `--derive` names the EVM wallet beside each Sui one; `--export-evm-key N` prints that wallet's
/// key after its warning, and nothing prints a key unasked.
#[test]
fn derive_names_the_evm_wallets_and_exports_one_key_after_its_warning() {
    let fx = Fixture::new();
    let derive = |extra: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_nmts-recovery"))
            .args(["--derive", "--wallets", "2", "--lang", "en", "--code-file"])
            .arg(fx.path("code.txt"))
            .args(extra)
            .output()
            .expect("run");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        stdout(&out)
    };
    let keys = nmts_crypto::kdf::derive(&fx.code).expect("derive");
    let key_hex = |i: u32| -> String {
        let key = keys.evm_key_for(i);
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        format!("0x{hex}")
    };

    let plain = derive(&[]);
    assert!(
        plain.contains("EVM address (NMTS Heavy, wallet 0): 0x"),
        "{plain}"
    );
    assert!(
        plain.contains("EVM address (NMTS Heavy, wallet 1): 0x"),
        "{plain}"
    );
    assert!(
        !plain.contains(&key_hex(0)) && !plain.contains(&key_hex(1)),
        "{plain}"
    );

    let asked = derive(&["--export-evm-key", "1"]);
    let warning = asked
        .find("This is the private key of EVM wallet 1.")
        .expect("the warning");
    let key = asked.find(&key_hex(1)).expect("wallet 1's key");
    assert!(warning < key, "the warning came after the key: {asked}");
    assert!(
        !asked.contains(&key_hex(0)),
        "only the wallet asked for: {asked}"
    );
}
