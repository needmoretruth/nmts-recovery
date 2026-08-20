# nmts-recovery

Get your files back from Walrus storage **without NMTS**, using your account code and the
recovery list file you saved.

**NMTS** ([nmts.me](https://nmts.me)) is end-to-end encrypted file storage built on Walrus: every
file is encrypted in your browser before it is uploaded, and every key comes from an account code
that never leaves your device. This program is the other half of that promise — if NMTS disappears,
your files must still be recoverable, and you should not have to take anyone's word for it.

It contacts **no NMTS server at any point**. It reads public Walrus aggregators — or a folder of
blobs you fetched yourself — and writes your files back out.

* Licence: **GNU Affero General Public License v3.0** (see `LICENSE`).
* It adds **no cryptography of its own.** Every key derivation, every envelope, every stream
  decryption is a call into `crypto/`, which is the same engine the NMTS browser code compiles to
  WebAssembly. The format is NCF-3, documented in
  [nmts-crypto](https://github.com/needmoretruth/nmts-crypto) along with the conformance vectors
  that arbitrate it.

## What you need

Either of these:

* **Your recovery kit** (`nmts-recovery-kit-….txt`) — one file with everything in it: your account
  code, and the recovery list. Hand this program that file and it needs nothing else.
  ⛔ Which is also why anyone who takes that file takes your account.
* **Your recovery list** (`.nmtsmap`) **and your account code**. The list is encrypted and the code
  opens it, so keeping them apart is what makes losing one of them survivable.

Neither the code nor the list is ever sent anywhere. Things derived from your code do go out when
you use `--find` — see **What it does over the network**.

## What it cannot do

Stated plainly, because a recovery tool that oversells itself is worse than none:

* **It cannot find your files without the recovery list.** The list is the index: it holds each
  file's key and where its pieces are stored. Blob addresses on Walrus are derived from the
  content, so nothing computes them from an account code alone.
  There are two places a list can be: the `.nmtsmap` file you saved, and — if the account switched
  the storage-network copy on — a copy on Walrus that `--find` can look up from your account code
  (see below). If neither exists, nothing here can reconstruct one, so save the file while you can.
* **It cannot recover anything you deleted.** Deleting a file in NMTS destroys its key, and the
  key is what this program needs.
* **It cannot prove a blob is still stored.** It finds out by fetching it.
* **A list written before 2026-08-19 does not say which Walrus network it refers to.** It records
  the storage network by name (`walrus`), and mainnet and testnet blob ids look alike, so both
  aggregators are tried — mainnet first. Lists written from that date on carry the chain inside the
  sealed document and the right aggregator is asked first; the other is still tried, so a list that
  names its chain wrongly costs one extra request rather than the recovery. `--aggregator`
  overrides all of it.
* **It does not contact storage addresses the list itself names.** A list can record the
  aggregators the browser was reading from when it was written. Those are not contacted unless you
  ask with `--use-recorded-aggregators`: the list is sealed, but a *recovery kit* carries the
  account code, so a kit somebody hands you is a document they sealed — every field in it is
  theirs, that list of hosts included. Contacting one tells its operator the address you recovered
  from and the moment you did it, and authenticating the bytes that come back does not undo a
  request that already went out. The addresses are printed either way, so they are there for the
  day the built-in ones go dark.
* **An older copy cannot open a newer list.** The list format carries a version, and a build that
  predates it stops and says so rather than guessing at bytes it does not understand — guessing is
  how a recovery produces files that look right and are not. `nmts-recovery --version` prints the
  program's own number and the newest list version it reads; if a list is ahead of it, take a newer
  build from this repository.

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

It will ask for your account code, show you what the recovery list covers, then fetch, decrypt, verify and
write each file.

Useful before committing to anything:

```sh
nmts-recovery --map FILE --list               # what the recovery list holds. No network, nothing written.
nmts-recovery --map FILE --print-fetch-plan   # the exact URLs, as curl commands
```

If you would rather this program did not open network connections at all, run
`--print-fetch-plan`, fetch the blobs yourself with the commands it prints, and then pass the
folder you filled with `--blobs-dir`. Everything after the bytes arrive is identical either way.

| Option | |
|---|---|
| `--map FILE` | your recovery list (`.nmtsmap`) **or** your recovery kit (`.txt`), which has the list inside it. Required unless `--find`, `--gui` or `--derive`. |
| `--find` | look the list up on Walrus from your account code alone — no saved file. See below. |
| `--rpc URL` | a Sui node for `--find` to ask. Repeatable; tried in order. |
| `--owner 0xADDRESS` | with `--find`, the wallet that paid for the uploads. Needed only when that wallet is a browser extension or an imported key, because an account code cannot derive such an address. |
| `--out DIR` | where to write recovered files. Required when restoring. |
| `--code-file FILE` | read the account code from a file instead of typing it. |
| `--aggregator URL` | a Walrus aggregator to read from. Repeatable; tried in order. |
| `--use-recorded-aggregators` | also read from the storage addresses written inside the recovery list itself. Off by default — see below. |
| `--blobs-dir DIR` | read blobs from a directory instead of the network. |
| `--only TEXT` | restore only files whose path or name contains TEXT. |
| `--overwrite` | replace files that already exist. Off by default. |
| `--derive` | print what your account code derives, and stop. No list, no network. |
| `--wallets N` | how many wallets `--derive` walks, and how many `--find` looks under. Default: 1. |
| `--secrets` | with `--derive`, also print the wallet private keys. |
| `--lang en\|ko` | message language. English by default; nothing is auto-detected. |

## When you have no list file

If the account switched the storage-network copy on, a copy of the recovery list is on Walrus and
your account code is enough to find it:

```sh
nmts-recovery --find --out ~/recovered
```

A blob id on Walrus is a hash of the blob's own bytes, so nothing predicts one from an account
code. Two other things are predictable, and together they are enough: the wallet that paid for the
storage comes from the account code, and so does the name the list is stored under. So this derives
the address, asks a public Sui node which blob objects that wallet owns, asks an aggregator each of
those for a patch by that name, and opens what comes back with the same code.

⚠ **What the lookup tells other people.** A Sui node learns that somebody is interested in that
address, and an aggregator learns that somebody asked for those patches. Both are public services
being asked public questions. Neither is given your account code, which never leaves this program.

Two things it needs to be told sometimes: `--owner 0xADDRESS` if the uploads were paid for with a
browser-extension or imported wallet, because no account code derives such an address; and
`--wallets N` if the account used more than the first derived wallet.

Finding nothing is an answer, not a failure, and there are three ordinary reasons for it: the copy
was never switched on, the wallet that paid is not one this code derives, or the account uploaded
only large files — those are stored as blobs of their own rather than inside a quilt, and it is the
quilt that carries the list. In any of those cases, use your `.nmtsmap` file.

## Run it from a browser instead

If a terminal is not where you want to pick eight files out of four hundred:

```sh
nmts-recovery --gui
```

It prints an address, opens it if it can, and serves a control window: choose your recovery list or
kit, see what it holds, tick what you want, say where it goes, and watch it happen.

**The program is still the program.** The page draws a list and sends back which rows you ticked.
Every key, every fetch, every decryption and every file written happens in the Rust binary. The
browser holds no key, opens no blob, and writes nothing.

### Your account code is typed in the terminal, never in the browser

This is deliberate, and it is the rule the rest of the design follows from. A browser is the
largest attack surface on a personal machine: extensions can read any page's contents, password
managers offer to remember anything that looks like a credential, and form values outlive the tab.
Your account code is the master key for your account — every other key derives from it. So when
the page has handed over a list file, the program asks for the code in the terminal window it was
started from, and the page tells you to look there.

The page will not even read a file that is not a recovery list: a list is a JSON document, so
the page looks at the first few bytes and stops there if they are not one. That check exists
because of the **recovery kit** — the one-file form that holds the list *and* the account code.
A kit chosen in the page's file picker would otherwise be read into the browser whole. If you
saved only a kit, the page says so and gives you the command: `nmts-recovery --map <that file>`,
which asks for nothing, because the kit already carries the code.

No route in the control channel takes an account code, and a test asserts it — including a test
that offers a real kit to the route that accepts file text, because that is how a code could
actually have arrived.

### Why a page served on your own machine can be trusted at all

Five things, and none of them is sufficient alone:

1. The listener is bound to `127.0.0.1`. Nothing off your machine can connect to it.
2. A fresh 32-byte token is minted per run and printed once, in the terminal. Every request
   carries it or is refused. It exists only in memory and dies with the process.
3. The `Host` header must be the loopback address and port. This is what stops DNS rebinding: a
   hostname that resolves to `127.0.0.1` lets a page on the internet reach a local port, and the
   socket genuinely is local, so the token alone would not know the difference.
4. No response carries a cross-origin header of any kind, and any `Origin` other than the
   server's own is refused outright.

5. Your desktop is handed a **file**, not the address. Opening the address directly would put the
   token in a command line, and on Linux every account on the machine can read those. Whoever holds
   the token can ask this program for your whole file index and tell it where to write your
   decrypted files — so it is a secret in the same class as the address itself. The file is created
   with owner-only permission and an unguessable name, and it does nothing but send the browser to
   the address. It is removed shortly after. If it cannot be written, nothing is opened: the
   address is in your terminal either way, and quietly falling back would put the token in the
   process list on exactly the systems where writing a private file failed.

Each of those is held by its own test, and each test was checked by removing the check and
watching it fail.

The page is at `recovery/gui/index.html` — one file, no libraries, nothing loaded from anywhere.
`nmts-recovery --write-gui FILE` writes a copy out so you can read it. Opening that copy on its
own does nothing, on purpose: a page loaded from `file://` has no origin the program could tell
apart from any other page loaded from `file://`, so admitting it would mean admitting all of them.

## Getting your wallet back too

An account code is not a password — it is the root. Every key the account has is computed from it,
including the wallet that pays for storage. "Get my files back" is half of what somebody needs; the
other half is "get my wallet back", and nothing else can do that computation for them.

```sh
nmts-recovery --derive              # account id, fingerprint, public code, wallet addresses
nmts-recovery --derive --secrets    # the same, plus the wallet private keys
```

`--derive` prints the public half. `--secrets` adds the private keys, behind a warning, because a
person checking which account a code belongs to should not have a spendable key land in their
terminal history as a side effect.

The wallet derivation is checked against fixtures taken from the library NMTS itself uses
(`recovery/src/derive.rs`) — if this program and the browser ever disagreed about an address,
somebody would fund the wrong one.

## What it does over the network

**Your account code never goes out.** It is read, keys are derived from it locally, and it is not
part of any request this program makes. What follows is everything that *is*.

Fetching the bytes, on every restore that does not use `--blobs-dir`:

```
GET https://<aggregator>/v1/blobs/<blob id>
GET https://<aggregator>/v1/blobs/by-quilt-patch-id/<patch id>
```

Public blobs, by their public ids. The list is opened before anything is fetched, and every
response is bounded to the exact ciphertext length the recovery list states before it is read.

With `--find`, two more, because there is no saved file to read the ids out of:

```
POST https://<sui node>/           suix_getOwnedObjects for the derived wallet address
GET  https://<aggregator>/v1/blobs/by-quilt-patch-id/<derived patch id>
```

⚠ **Both of those are derived from your account code**, so asking them is telling a stranger's
server that somebody is looking for this account's files, from this address, at this moment. The
code itself is not sent, and neither server can work back to it — but the questions are not
anonymous. `--rpc` names your own node; `--map FILE` avoids the lookup entirely.

The addresses contacted are this program's built-in ones. A recovery list can name storage
addresses of its own, and those are **not** contacted unless you ask with
`--use-recorded-aggregators`.

## What it checks before it says a file came back

A recovery that half worked and reported success is the failure worth designing against, so:

* **Placement is checked positionally.** Each part's sealed header says which position it belongs
  at, and that is compared against the position being written into — never against the part's own
  record, and never after sorting the parts by their own claimed index.
* **Length is checked twice, against two authorities**: what the recovery list says, and what the part's own
  sealed header says. Both must agree before a byte is written. A part may be **padded** — sealed
  larger than the bytes it holds, so that its stored size does not give the file's size away — and
  then the list carries both numbers, the padding is decrypted and authenticated like everything
  else, and only the file's own bytes are written out and hashed.
* **The key is checked before decryption begins**, by the envelope's key commitment.
* **The whole file is hashed and compared** to the hash the recovery list recorded. This is the only check
  that spans parts, so it is the only one that would catch parts that are each individually
  perfect and collectively the wrong file.
* **Nothing half-written is left looking finished.** Each file is written under a temporary name
  in its destination directory and renamed only after every check above has passed.
* **A failure costs one file, not the recovery.** What failed is named, and the exit code says
  something did.
* **The file's own date is put back**, when the list recorded one — after the file is complete and
  in place, never before, and a filesystem that refuses timestamps costs a note rather than the
  file. A list that recorded no date leaves the file dated at the moment of the recovery, which is
  honest; stamping such a file 1 January 1970 would read as damage.

⚠ **What the program does NOT decide with:** a list's dates, its `totals`, and anything in the
`.nmtsmap` file's plaintext header. The dates come from the storage layer and are checked against
nothing, so they are written onto files and used for nothing else. A `totals` that disagrees with
what was read is reported and the recovery continues. The plaintext header is editable by anyone
holding the file, so nothing in it is shown as advice and no URL in it is ever printed as somewhere
to download software — what the program shows about a list comes out of the sealed document.

Exit codes: `0` everything restored · `1` it could not start · `2` the arguments were wrong ·
`3` finished with failures.

## Reporting a problem

Open an issue, or write to nmts@nmts.me.

⛔ Do not include your account code in a bug report, an issue, a screenshot, or anywhere else.
Nobody needs it to help you, and anyone who has it has your files.
