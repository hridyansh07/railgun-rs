# CLAUDE.md

Context for Claude Code working in this repository.

## What this is

`railgun-rs` — a native (Rust) SDK for the RAILGUN privacy protocol. It is
the **library**, not the wallet app. A separate macOS-first wallet project will
consume it. The SDK is also meant to host more than one privacy protocol over
time, so RAILGUN-specific logic stays behind clean, typed boundaries.

## Current scope (important)

Only three crates are part of this workspace/repository right now:

- `crates/types` — shared vocabulary (Alloy base primitives + RAILGUN newtypes).
- `crates/crypto` — heavy-lifting cryptography (Poseidon, BabyJubJub) over `types`.
- `crates/poseidon-rust` — vendored Poseidon engine; internal dep of `crypto`.

Four more crates exist **locally but are parked** — listed under `[workspace.exclude]`
in the root `Cargo.toml` and git-ignored: `railgun-keys`, `railgun-merkle`,
`railgun-prover`, `railgun-wallet-native`. They are WIP, do not build as part of the
workspace, and still reference the old crate names. To resume one, move it from
`exclude` back into `members` and update its references. They will be renamed and
published when ready.

Two design docs (`ARCHITECTURE.md`, `RAILGUN_WALLET_RUNTIME.md`) also live locally
but are git-ignored for now — they describe the broader, not-yet-built vision and
still use pre-rename names.

## Conventions & invariants

- **Typed domain flow.** Pass domain types, not raw `U256`/`Vec<u8>`/`String`,
  across protocol boundaries. `types` is the single source of base primitives —
  including the `uint!` macro (re-exported from `alloy-primitives`). Do not import
  `ruint` by name in app-facing code.
- **O(1) allocation on hot paths** (hashing, key derivation; later scan/merkle/
  prover). Any `.collect`/`vec!`/`Vec::new` etc. on a hot path needs a same-line
  `alloc-ok: <reason>` comment. Full rules: `CODE_INVARIANTS.md`.
- **Parity first.** Crypto output must match the TypeScript RAILGUN engine.
  Tests assert against known vectors generated from the JS SDK.

## Crate-specific notes

- **Poseidon** is exposed only through the `PoseidonInput` trait
  (`value.poseidon_hash()`), not a free function. Backed by the vendored
  `poseidon-rust` — the single Poseidon implementation (the parity-matching one).
- `crypto` depends on `ruint` *only* to enable its `ark-ff-06` feature
  (`ark BigInt <-> U256` conversions). Names still come from `types`.
- The `[patch.crates-io] ruint = git fork` in the root `Cargo.toml` must stay — it
  patches the `ruint` that `alloy-primitives` pulls in transitively.
- MiMC / Pedersen (circomlib V1 hashes) were deleted as dead code; recover from
  git/kohaku if RAILGUN V1 commitment support is ever needed.

## Build & test

```sh
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace   # pedantic = warn (repo has known pre-existing warnings)
```

## Provenance

Cryptographic source material is adapted from Ethereum Kohaku (MIT) and the
vendored TaceoLabs `poseidon-rust` (MIT OR Apache-2.0). See `README.md`
Acknowledgements and `LICENSE`.
