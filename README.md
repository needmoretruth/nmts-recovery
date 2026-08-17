# nmts-recovery

Get your files back from Walrus storage **without NMTS**, using your account code and the
recovery map file you saved.

NMTS encrypts every file in your browser before it is uploaded, and every key comes from your
account code. That design carries an obligation: if NMTS disappears, your files must still be
recoverable, and you should not have to take anyone's word for it. This program is that
obligation, discharged.

It contacts **no NMTS server at any point**. It reads public Walrus aggregators — or a folder of
blobs you fetched yourself — and writes your files back out.

* Licence: **GNU Affero General Public License v3.0** (see `LICENSE`).
* It adds **no cryptography of its own.** Every key derivation, every envelope, every stream
  decryption is a call into `crypto/`, which is the same engine the NMTS browser code compiles to
  WebAssembly. The format is NCF-3, documented in
  [nmts-crypto](https://github.com/needmoretruth/nmts-crypto) along with the conformance vectors
  that arbitrate it.

## What you need

1. **Your account code** — 32 letters and digits, from your recovery kit.
2. **Your recovery map file** — the `.nmtsmap` file you saved from NMTS.

The map is encrypted; the code opens it. Neither is sent anywhere.

## What it cannot do

Stated plainly, because a recovery tool that oversells itself is worse than none:

* **It cannot find your files without the recovery map.** The map is the index: it holds each
  file's key and where its pieces are stored. Blob addresses on Walrus are derived from the
  content, so nothing computes them from an account code. Today the map lives in your `.nmtsmap`
  file and in NMTS's database, and nowhere else — so save the file while you can.
* **It cannot recover anything you deleted.** Deleting a file in NMTS destroys its key, and the
  key is what this program needs.
* **It cannot prove a blob is still stored.** It finds out by fetching it.
* **It cannot tell you which Walrus network a map refers to.** An NRM-2 map records the storage
  network by name (`walrus`) and does not say mainnet or testnet, so both are tried in that order.
  `--aggregator` overrides this.

## Build

Rust 1.75 or newer. No other toolchain, no build script, no code generation.

```sh
cd recovery
cargo build --release
```

The binary lands at `recovery/target/release/nmts-recovery` (`nmts-recovery.exe` on Windows).
It runs natively on Linux, macOS and Windows; nothing here needs a compatibility layer.

Run the tests, which restore real files from synthesised storage with no network at all:

```sh
cd recovery
cargo test
```

## Run it from the terminal

```sh
nmts-recovery --map ~/Downloads/nmts-recovery-map.nmtsmap --out ~/recovered
```

It will ask for your account code, show you what the map covers, then fetch, decrypt, verify and
write each file.

Useful before committing to anything:

```sh
nmts-recovery --map FILE --list               # what the map holds. No network, nothing written.
nmts-recovery --map FILE --print-fetch-plan   # the exact URLs, as curl commands
```

If you would rather this program did not open network connections at all, run
`--print-fetch-plan`, fetch the blobs yourself with the commands it prints, and then pass the
folder you filled with `--blobs-dir`. Everything after the bytes arrive is identical either way.

| Option | |
|---|---|
| `--map FILE` | the `.nmtsmap` file you saved. Required unless `--gui`. |
| `--out DIR` | where to write recovered files. Required when restoring. |
| `--code-file FILE` | read the account code from a file instead of typing it. |
| `--aggregator URL` | a Walrus aggregator to read from. Repeatable; tried in order. |
| `--blobs-dir DIR` | read blobs from a directory instead of the network. |
| `--only TEXT` | restore only files whose path or name contains TEXT. |
| `--overwrite` | replace files that already exist. Off by default. |
| `--lang en\|ko` | message language. English by default; nothing is auto-detected. |

## Run it from a browser instead

If a terminal is not where you want to pick eight files out of four hundred:

```sh
nmts-recovery --gui
```

It prints an address, opens it if it can, and serves a control window: choose your map, see what
it holds, tick what you want, say where it goes, and watch it happen.

**The program is still the program.** The page draws a list and sends back which rows you ticked.
Every key, every fetch, every decryption and every file written happens in the Rust binary. The
browser holds no key, opens no blob, and writes nothing.

### Your account code is typed in the terminal, never in the browser

This is deliberate, and it is the rule the rest of the design follows from. A browser is the
largest attack surface on a personal machine: extensions can read any page's contents, password
managers offer to remember anything that looks like a credential, and form values outlive the tab.
Your account code is the master key for your account — every other key derives from it. So when
the page has handed over a map file, the program asks for the code in the terminal window it was
started from, and the page tells you to look there.

There is no route in the control channel that accepts an account code, and a test asserts it.

### Why a page served on your own machine can be trusted at all

Four things, and none of them is sufficient alone:

1. The listener is bound to `127.0.0.1`. Nothing off your machine can connect to it.
2. A fresh 32-byte token is minted per run and printed once, in the terminal. Every request
   carries it or is refused. It exists only in memory and dies with the process.
3. The `Host` header must be the loopback address and port. This is what stops DNS rebinding: a
   hostname that resolves to `127.0.0.1` lets a page on the internet reach a local port, and the
   socket genuinely is local, so the token alone would not know the difference.
4. No response carries a cross-origin header of any kind, and any `Origin` other than the
   server's own is refused outright.

Each of those four is held by its own test, and each test was checked by removing the check and
watching it fail.

The page is at `recovery/gui/index.html` — one file, no libraries, nothing loaded from anywhere.
`nmts-recovery --write-gui FILE` writes a copy out so you can read it. Opening that copy on its
own does nothing, on purpose: a page loaded from `file://` has no origin the program could tell
apart from any other page loaded from `file://`, so admitting it would mean admitting all of them.

## What it does over the network

One kind of request, and only when you have not passed `--blobs-dir`:

```
GET https://<aggregator>/v1/blobs/<blob id>
GET https://<aggregator>/v1/blobs/by-quilt-patch-id/<patch id>
```

Public blobs, by their public ids. Your account code never reaches this code path — keys are
derived locally, and the map is opened before anything is fetched. Every response is bounded to
the exact ciphertext length the map states before it is read.

## What it checks before it says a file came back

A recovery that half worked and reported success is the failure worth designing against, so:

* **Placement is checked positionally.** Each part's sealed header says which position it belongs
  at, and that is compared against the position being written into — never against the part's own
  record, and never after sorting the parts by their own claimed index.
* **Length is checked twice, against two authorities**: what the map says, and what the part's own
  sealed header says. Both must agree before a byte is written.
* **The key is checked before decryption begins**, by the envelope's key commitment.
* **The whole file is hashed and compared** to the hash the map recorded. This is the only check
  that spans parts, so it is the only one that would catch parts that are each individually
  perfect and collectively the wrong file.
* **Nothing half-written is left looking finished.** Each file is written under a temporary name
  in its destination directory and renamed only after every check above has passed.
* **A failure costs one file, not the recovery.** What failed is named, and the exit code says
  something did.

Exit codes: `0` everything restored · `1` it could not start · `2` the arguments were wrong ·
`3` finished with failures.

## Reporting a problem

Open an issue, or write to nmts@nmts.me.

⛔ Do not include your account code in a bug report, an issue, a screenshot, or anywhere else.
Nobody needs it to help you, and anyone who has it has your files.
