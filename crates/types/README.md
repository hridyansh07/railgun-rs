# types

The shared vocabulary crate for `railgun-rs`. It owns the base data
types the rest of the workspace passes around — and nothing else. No I/O, no
crypto behavior, no protocol logic.

It re-exports EVM base primitives from
[`alloy-primitives`](https://crates.io/crates/alloy-primitives) (`U256`, `B256`,
`Bytes`, `Address`, and the `uint!` macro) and adds strongly-typed RAILGUN
newtypes on top so values that share a primitive shape can't be mixed by
accident.

## What's here

| Type | Purpose |
| --- | --- |
| `CommitmentHash`, `Nullifier`, `PoseidonHash`, `RailgunTxid` | RAILGUN protocol hash/identifier newtypes |
| `SpendingKey`, `ViewingKey`, `SharedKey` | fixed-byte key wrappers |
| `BabyJubJubPoint` | BabyJubJub curve point (x, y) |
| `FieldScalar` | a value in the scalar field |
| `RailgunBase37` | Base37 string encoding/decoding (allocation-free decode) |
| `RailgunAccountIndex`, `DerivationPath` | hardened derivation-path vocabulary (parse/render `m/44'/1984'/…`) |

`RailgunAddress` / `0zk` handling will live here later.

## Type policy

Domain types expose only **named** accessors (`as_u256`, `as_bytes`, `x`/`y`) and
**never** broad cross-domain `From` conversions — a conversion that is genuinely
needed gets a named constructor that describes the operation. See
[`CODE_INVARIANTS.md`](../../CODE_INVARIANTS.md) for the full rules.

## Usage

```rust
use types::{PoseidonHash, U256};

let h = PoseidonHash::new(U256::from(1u8));
assert_eq!(h.as_u256(), U256::from(1u8));
```
