# railgun-rs

A native (Rust) SDK for interacting with the [RAILGUN](https://www.railgun.org/)
privacy protocol — the engine, not a wallet app.

It targets **native applications** (the first consumer is a macOS desktop wallet)
where real threads, native cryptography, and a native Groth16 prover unlock
performance the JavaScript stack structurally cannot reach. It is a second,
independent path to RAILGUN alongside the TypeScript
[`@railgun-community/engine`](https://github.com/Railgun-Community/engine).

The SDK is built to be a reusable library with strongly-typed protocol APIs and
clean integration points (Swift, Kotlin, desktop, CLI) — and to eventually host
more than one privacy protocol behind a shared, app-facing shape. The wallet
application that consumes this SDK is a separate project.

> [!NOTE]
> Early stage. Only the foundational crates are published here so far. The
> merkle, prover, sync, transaction, and runtime crates are in progress and will
> be added as they stabilize.

## Crates

| Crate | Description |
| --- | --- |
| [`types`](crates/types) | Shared vocabulary: Alloy base primitives, strongly-typed RAILGUN domain newtypes, and derivation-path types. |
| [`crypto`](crates/crypto) | Heavy-lifting cryptography (Poseidon, BabyJubJub, BIP-39 mnemonic + key derivation) exposed as typed APIs over `types`. |
| [`poseidon-rust`](crates/poseidon-rust) | Vendored Poseidon engine (the parity-matching implementation). Internal dependency of `crypto`. |

## Design principles

- **Typed domain flow.** Protocol concepts move through the code as domain types,
  not raw `U256` / `Vec<u8>` / `String`. `types` is the single vocabulary.
- **Predictable performance.** Hot paths (hashing, key derivation, and — as they
  land — scan, merkle updates, proving) hold to an O(1)-allocation discipline.
- **Parity first.** Cryptographic output is validated byte-for-byte against the
  TypeScript RAILGUN engine before anything depends on it.

The full engineering rules are in [`CODE_INVARIANTS.md`](CODE_INVARIANTS.md).

## Build & test

```sh
cargo build --workspace
cargo test --workspace
cargo fmt --all
```

## Acknowledgements

This SDK builds on prior open-source work:

- **[Ethereum Kohaku](https://github.com/ethereum/kohaku)** (MIT) — the
  cryptographic source material adapted into `crypto`.
- **[poseidon-rust](https://github.com/TaceoLabs/poseidon-rust)** (MIT OR
  Apache-2.0, © TaceoLabs) — vendored under `crates/poseidon-rust/`, retaining its
  upstream licence.

## License

MIT — see [LICENSE](LICENSE).
