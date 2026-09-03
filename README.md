# nmts-recovery

Get your files back from Walrus storage **without NMTS**, using your account code and the
recovery list you saved.

[NMTS](https://nmts.me) is end-to-end encrypted file storage built on Walrus: every file is
encrypted in your browser before it is uploaded, and every key comes from an account code that
never leaves your device. This program is the other half of that promise. If NMTS disappears, your
files must still be recoverable, and you should not have to take anyone's word for it.

> **[한국어 문서](README.ko.md)** · Talk about NMTS on [Discord](https://discord.gg/pcmRkVmVZk),
> in English or Korean.

It contacts **no NMTS server at any point.** It reads public Walrus aggregators, or a folder of
blobs you fetched yourself, and writes your files back out. It adds no cryptography of its own:
every key derivation and every decryption is a call into `crypto/`, the same engine the NMTS
browser code compiles to WebAssembly. The format is NCF-3, documented in
[nmts-crypto](https://github.com/needmoretruth/nmts-crypto) with the conformance vectors that
arbitrate it.

## What you need

Either of these:

- **Your recovery kit** (`nmts-recovery-kit-….txt`): one file holding your account code and the
  recovery list. Hand this program that file and it needs nothing else. Which is also why anyone
  who takes that file takes your account.
- **Your recovery list** (`.nmtsmap`) **and your account code.** The list is encrypted and the
  code opens it, so keeping them apart is what makes losing one of them survivable.

Neither the code nor the list is ever sent anywhere. Things derived from your code do go out when
you use `--find`; see [What it does over the network](#what-it-does-over-the-network).

## What it cannot do

- **Find your files without the recovery list.** The list is the index: it holds each file's key
  and where its pieces are stored. Blob addresses on Walrus derive from content, so nothing
  computes them from an account code alone. If the account switched the storage-network copy on,
  `--find` can look a copy up from your account code; otherwise save the file while you can.
- **Recover anything you deleted.** Deleting a file in NMTS destroys its key, and the key is what
  this program needs.
- **Prove a blob is still stored.** It finds out by fetching it.
- **Tell which Walrus network a list written before 2026-08-19 refers to.** Both aggregators are
  tried, mainnet first. Lists written from that date on carry the chain inside the sealed document;
  `--aggregator` overrides all of it.
- **Contact storage addresses the list itself names**, unless you ask with
  `--use-recorded-aggregators`. A kit somebody hands you is a document they sealed, that list of
  hosts included, and contacting one tells its operator when and from where you recovered. The
  addresses are printed either way.
- **Open a list newer than itself.** The list format carries a version, and an older build stops
  and says so rather than guessing at bytes. `nmts-recovery --version` prints the newest list
  version it reads.

## Get it

The `nmts` command-line tool fetches the release for your machine and checks it against the
release's checksum file: `nmts recovery --out ~/tools`. Or build it yourself with Rust 1.75 or
newer, no other toolchain:

```sh
cd recovery
cargo build --release     # recovery/target/release/nmts-recovery (.exe on Windows)
cargo test                # restores real files from synthesised storage, no network
```

It runs natively on Linux, macOS and Windows.

## Run it from the terminal

```sh
nmts-recovery --map ~/Downloads/nmts-recovery-map.nmtsmap --out ~/recovered
```

It asks for your account code, shows what the recovery list covers, then fetches, decrypts,
verifies and writes each file. Before committing to anything:

```sh
nmts-recovery --map FILE --list               # what the list holds. No network, nothing written.
nmts-recovery --map FILE --print-fetch-plan   # the exact URLs, as curl commands
```

If you would rather this program opened no network connection at all, fetch the blobs yourself
with the commands `--print-fetch-plan` prints and pass the folder with `--blobs-dir`. Everything
after the bytes arrive is identical.

| Option | |
|---|---|
| `--map FILE` | your recovery list (`.nmtsmap`) **or** your recovery kit (`.txt`). Required unless `--find`, `--gui` or `--derive`. |
| `--find` | look the list up on Walrus from your account code alone. See below. |
| `--rpc URL` | a Sui node for `--find` to ask. Repeatable; tried in order. |
| `--owner 0xADDRESS` | with `--find`, the wallet that paid for the uploads. Needed only when that wallet is a browser extension or an imported key. |
| `--out DIR` | where to write recovered files. Required when restoring. |
| `--code-file FILE` | read the account code from a file instead of typing it. |
| `--aggregator URL` | a Walrus aggregator to read from. Repeatable; tried in order. |
| `--use-recorded-aggregators` | also read from the storage addresses written inside the list. Off by default. |
| `--blobs-dir DIR` | read blobs from a directory instead of the network. |
| `--only TEXT` | restore only files whose path or name contains TEXT. |
| `--overwrite` | replace files that already exist. Off by default. |
| `--derive` | print what your account code derives, and stop. No list, no network. |
| `--wallets N` | how many wallets `--derive` walks, and how many `--find` looks under. Default: 1. |
| `--secrets` | with `--derive`, also print the wallet private keys. |
| `--lang en\|ko` | message language. English by default; nothing is auto-detected. |

**The account code is never an argument.** It is typed when the program asks, or read from
`--code-file`. An argument would land in your shell history and be visible to other users.

## When you have no list file

If the account switched the storage-network copy on, a copy of the recovery list is on Walrus and
your account code is enough to find it:

```sh
nmts-recovery --find --out ~/recovered
```

Two things are predictable from the account code: the wallet that paid for the storage, and the
name the list is stored under. So this derives the address, asks a public Sui node which blob
objects that wallet owns, asks an aggregator for a patch by that name, and opens what comes back.
A Sui node learns that somebody is interested in that address, and an aggregator learns that
somebody asked for those patches; neither is given your account code.

Tell it `--owner 0xADDRESS` if the uploads were paid for with a browser-extension or imported
wallet, and `--wallets N` if the account used more than the first derived wallet. Finding nothing
is an answer, and there are three ordinary reasons for it: the copy was never switched on, the
wallet that paid is not one this code derives, or the account uploaded only large files, which are
stored as blobs of their own rather than inside the quilt that carries the list. Use your
`.nmtsmap` file in those cases.

## Run it from a browser instead

```sh
nmts-recovery --gui
```

It prints an address, opens it if it can, and serves a control page: choose your recovery list,
see what it holds, tick what you want, say where it goes, and watch it happen. The page draws a
list and sends back which rows you ticked; every key, every fetch, every decryption and every file
written happens in the Rust binary. The browser holds no key and writes nothing.

**Your account code is typed in the terminal, never in the browser.** A browser is the largest
attack surface on a personal machine: extensions read page contents, password managers remember
anything that looks like a credential, form values outlive the tab. So the program asks for the
code in the terminal it was started from, and the page tells you to look there. The page refuses
to read a file that is not a recovery list, which is how a **kit** (list and code in one file) is
kept out of the browser: if you saved only a kit, the page gives you the terminal command instead.
No route in the control channel takes an account code, and a test asserts it.

Why a page served on your own machine can be trusted:

1. The listener is bound to `127.0.0.1`.
2. A fresh 32-byte token is minted per run and printed once in the terminal; every request carries
   it or is refused. It lives only in memory.
3. The `Host` header must be the loopback address and port, which stops DNS rebinding.
4. No response carries a cross-origin header, and any other `Origin` is refused.
5. Your desktop is handed a file, not the address, because the token is a secret and an address on
   a command line is visible to every account on the machine. The file is owner-only, does nothing
   but send the browser to the address, and is removed shortly after. If it cannot be written,
   nothing is opened and the address stays in your terminal.

Each of those is held by its own test. The page is `recovery/gui/index.html`: one file, no
libraries, nothing loaded from anywhere. `--write-gui FILE` writes a copy out so you can read it;
opening that copy on its own does nothing, on purpose.

## Getting your wallet back too

Every key the account has is computed from the account code, including the wallet that pays for
storage. Nothing else can do that computation for you.

```sh
nmts-recovery --derive              # account id, fingerprint, public code, wallet addresses
nmts-recovery --derive --secrets    # the same, plus the wallet private keys, behind a warning
```

The derivation is checked against fixtures taken from the library NMTS itself uses
(`recovery/src/derive.rs`).

## What it does over the network

**Your account code never goes out.** Keys are derived from it locally and it is part of no
request. What is sent:

```
GET https://<aggregator>/v1/blobs/<blob id>                       every restore not using --blobs-dir
GET https://<aggregator>/v1/blobs/by-quilt-patch-id/<patch id>
POST https://<sui node>/     suix_getOwnedObjects for the derived wallet     --find only
GET https://<aggregator>/v1/blobs/by-quilt-patch-id/<derived patch id>      --find only
```

Public blobs, by their public ids; every response is bounded to the ciphertext length the list
states. The two `--find` requests are derived from your account code, so they tell a stranger's
server that somebody is looking for this account's files, at this moment, from this address. The
code itself is not sent and cannot be worked back to. `--rpc` names your own node; `--map FILE`
avoids the lookup entirely. Addresses recorded inside a list are not contacted unless you ask with
`--use-recorded-aggregators`.

## What it checks before it says a file came back

- **Placement is checked positionally**, from each part's sealed header against the position
  being written, never from the part's own record.
- **Length is checked twice**, against the list and against the part's sealed header. A padded
  part (sealed larger than the bytes it holds, so the stored size does not give the file's size
  away) is authenticated whole and only the file's own bytes are written and hashed.
- **The key is checked before decryption begins**, by the envelope's key commitment.
- **The whole file is hashed and compared** to the hash the list recorded — the only check that
  spans parts.
- **Nothing half-written is left looking finished.** Each file is written under a temporary name
  and renamed after every check has passed.
- **A failure costs one file, not the recovery.** What failed is named, and the exit code says so.
- **The file's own date is put back** when the list recorded one, after the file is complete. A
  list with no date leaves the file dated at the moment of recovery.

What the program does not decide with: a list's dates, its `totals`, and anything in the
`.nmtsmap` file's plaintext header, which anyone holding the file can edit. No URL in that header
is ever printed as somewhere to download software.

Exit codes: `0` everything restored · `1` it could not start · `2` the arguments were wrong ·
`3` finished with failures.

## Reporting a problem

Open an issue, or write to nmts@nmts.me. **Do not include your account code** in a bug report, an
issue, or a screenshot: nobody needs it to help you, and anyone who has it has your files.

## Licence

Apache-2.0 — see [LICENSE](LICENSE). It moved here from AGPL-3.0-only on 2026-08-30; copies
already held under the AGPL stay under it. If you need different terms, write to **nmts@nmts.me**
and say why. Code is welcome: [CONTRIBUTING.md](CONTRIBUTING.md) says how it reaches here.

Copyright © 2026 needmoretruth.
