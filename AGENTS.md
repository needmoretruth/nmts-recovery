# For programs and agents working in this repository

This is the NMTS recovery program: one executable that rebuilds a person's files from the storage
network with no NMTS server involved, using only the account code and the recovery list. Its
purpose is to keep working when nothing else does, so the rules below are about not adding
dependencies on things that can disappear.

## What to know before changing anything

- It must work offline against a local copy of the recovery list and the blobs. Nothing may
  require the NMTS server, the NMTS website or any account with a third party.
- The cryptography comes from the `nmts-crypto` crate; the format is NCF-3 and its document lives
  there. Do not reimplement any of it here.
- Messages are printed in English and Korean. Every sentence must be true of what the program
  did; a sentence that guesses is a bug.
- No `unsafe`. No new network endpoints beyond the storage network's public read path.

## How to check your work

Run the crate's tests and clippy over all targets; both must be clean. The `--derive` mode prints
the keys an account code yields, and `--derive --ai-accounts` the codes of the sub-accounts
derived under it; both are checked against the crypto crate's vectors.
