# crypto

The heavy-lifting cryptography crate for `railgun-rs`. It implements the
crypto RAILGUN needs and exposes it as **typed APIs over the [`types`](../types)
crate** — callers work with domain types and traits, never loose byte slices or
raw field-element arrays.

## What's here

- **Poseidon** via the `PoseidonInput` trait. Types know how to feed themselves to
  Poseidon, so hashing reads naturally:

  ```rust
  use crypto::PoseidonInput;

  let mpk = (spending_public_key, nullifying_key).poseidon_hash()?;
  let nk  = U256::from_be_bytes(*viewing_key.as_bytes()).poseidon_hash()?;
  ```

  Implemented for `U256`, `FieldScalar`, `PoseidonHash`, `BabyJubJubPoint`,
  references, slices/arrays, and tuples. The raw hashing function is intentionally
  not exported.

- **BabyJubJub** key derivation via the `SpendingKeyPublicKey` trait
  (`spending_key.public_key()`). EdDSA signing lives here too, wired up as
  transaction signing lands.

- **Mnemonic & key derivation.** `RailgunMnemonic` (BIP-39) produces a seed;
  `KeyNode` runs the RAILGUN HMAC-SHA512 hardened derivation and
  `KeyNode::derive_railgun_keys` returns the full `DerivedRailgunKeys` bundle
  (spending/viewing keys, public key, nullifying + master public keys). The
  derivation-path *types* (`DerivationPath`, `RailgunAccountIndex`) live in
  [`types`](../types); the *derivation* lives here.

## Implementation notes

- Poseidon is backed by the vendored [`poseidon-rust`](../poseidon-rust) engine —
  the implementation whose output matches the TypeScript RAILGUN engine's parity
  vectors. There is exactly one Poseidon implementation in the workspace.
- BabyJubJub / MiMC / Pedersen source material is kohaku-derived and kept internal
  to this crate (see [Acknowledgements](../../README.md#acknowledgements)).
- `ruint` is a dependency only to enable its `ark-ff-06` feature (the
  `ark BigInt <-> U256` conversions). All `U256`/`uint!` *names* come from `types`.

## Invariants

Poseidon and key derivation are hot paths. Allocation in those paths must be
bounded, persistent, or justified with an `alloc-ok` comment — see
[`CODE_INVARIANTS.md`](../../CODE_INVARIANTS.md).
