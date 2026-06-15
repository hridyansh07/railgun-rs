# CLAUDE.md

Context for Claude Code working in this repository.

## What this is

`railgun-rs` — a native (Rust) SDK for the RAILGUN privacy protocol. It is
the **library**, not the wallet app. A separate macOS-first wallet project will
consume it. The SDK is also meant to host more than one privacy protocol over
time, so RAILGUN-specific logic stays behind clean, typed boundaries.

## Current scope (important)

The workspace crates:

- `crates/types` — shared vocabulary (Alloy base primitives + RAILGUN newtypes,
  including BIP-32-style derivation path types).
- `crates/crypto` — heavy-lifting cryptography (Poseidon, BabyJubJub, BIP-39
  mnemonic + HMAC key derivation, merkle math incl. the `MerkleWalk` trait and
  frontier accumulator) over `types` + `database`.
- `crates/poseidon-rust` — vendored Poseidon engine; internal dep of `crypto`.
- `crates/database` — the **single owner of the open store** (redb-only; the
  `test-util` feature exposes a tempfile-backed `test_util::temp()` for tests):
  typed read views (`Database::read` → MVCC snapshot with table namespaces and
  range scans), closure-scoped write transactions (`Database::write` — commit on
  Ok, discard on Err, cross-table atomic), overlay `WriteBatch` for
  stage→validate(async)→apply flows, per-table schema version stamps, and the
  tracing choke point (every write txn emits duration + per-table counts).
  Table key layouts that pre-date the crate (commitments, decoded) are frozen.
- `crates/sync` — Subsquid event sync; each block-window commits data + folded
  merkle frontier snapshots + watermark in one transaction (roots become O(1)
  reads via the snapshot fast path in `crypto::MerkleWalk`).
- `crates/decoder` — note decryption/scan + asset-indexed balances over
  database read views.
- `crates/wallet` — the user-facing facade: active-wallet registry (in-memory
  decryptors, keys never persisted), the unlock/seal session (`crypto::Sealer`;
  decoded notes + pending POI entries are ciphertext at rest, memory-only when
  locked), and the single-lifecycle pipeline (`sync_and_scan`: sync the tree
  once → one incremental multi-wallet threaded scan via `decoder::Scanner`).
- `integration/` — whole-stack tests over real chain data (fixture-based;
  `fixture_decode` doubles as the disk-format compatibility gate).

The old `utils` (KeyValueStore/StorageBackend) and `commitments` (leaf storage)
crates were **dissolved into `database`**: engine + transactions replaced the
hand-rolled staging buffer; the byte-exact node codec and key layouts moved
verbatim (disk format unchanged).

One crate exists **locally but is parked** — listed under `[workspace.exclude]`
in the root `Cargo.toml` and git-ignored: `railgun-wallet-native`. It is WIP, does
not build as part of the workspace, and still references old crate names. To resume
it, move it from `exclude` back into `members` and update its references.

`railgun-prover` was un-parked as part of the POI milestone: it is a workspace
member providing the typed prover seam (`CircuitKind` incl.
`ProofOfInnocence { size }`, `CircuitProver`, snarkjs-shaped `Proof`). The Groth16
implementation behind the seam is still future work.

The `poi` crate hosts Private Proof of Innocence: the POI node JSON-RPC client
(`ppoi_*`), the database-backed txid tree (txid table namespaces + `TxidIndexer`,
roots validated against the POI node), per-list status caching + engine-parity
balance buckets, POI circuit witness assembly (`PoiCircuitInputs`, parity-tested
against the engine's `test-vector-poi.json`), and persisted `PendingPoiEntry`
records for the future spent-POI submission loop.

The old `railgun-keys` crate was folded into `types` (derivation path types) and
`crypto` (mnemonic + `KeyNode` derivation). The old `railgun-merkle` crate was
likewise folded in and removed.

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
