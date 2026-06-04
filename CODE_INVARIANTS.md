# Code Invariants

This repository should bias toward domain types, explicit capabilities, and code
that can survive being read years later. These invariants are part of the
architecture, not a style preference.

## O(1) Allocation Principle

Where heap allocations cannot be avoided you MUST ENSURE that the algorithms or
functions you write at a high-level only make a constant number of allocations
relative to the input size.

This means methods such as `.collect`, `.to_vec`, etc. are **ANTI-PATTERNS** to
be avoided. If there are borrow checker conflicts first try:
- adapting functions to take specific fields rather than the entirety of `self`
- defining a reusable heap-allocated before instead of ones that are allocated &
  then freed on each call

## Hot Path Enforcement

The O(1) allocation principle is strict in scan, note decryption, merkle updates,
prover input construction, key derivation, and transaction planning code.

Any `.collect`, `.to_vec`, input-sized `Vec`, or clone of variable-sized data in
those hot-path modules requires a nearby `alloc-ok: reason` comment. The reason
must explain why the allocation is bounded, persistent, or part of an owned API
boundary.

Allowed exceptions are tests, fixtures, FFI DTO creation, serialization
boundaries, startup/config loading, artifact loading, and fixed-size protocol
outputs.

## Typed Domain Flow

Protocol concepts should move through the code as domain types. Do not pass raw
`U256`, `Vec<u8>`, or `String` across high-level protocol boundaries when a
newtype can carry the invariant.

Prefer method-oriented Rust APIs for domain behavior:

- `node.decrypt_with(...)`
- `base37.try_decode(...)`
- `tree.insert_node(...)`
- `spending_key.public_key()`

Free functions are acceptable for private mathematical primitives or where Rust
trait coherence makes a method impossible. Public protocol APIs should
hand-hold the caller through the correct operation.

## Domain Type Conversion Policy

Rust newtypes must not expose broad conversion surfaces by default. A domain type
exists to prevent accidental mixing of values that share the same primitive
shape.

Do not implement cross-domain `From` conversions such as
`PoseidonHash -> CommitmentHash`. If a semantic conversion is truly required,
use a named constructor or function that describes the operation, such as
`CommitmentHash::from_poseidon(...)`.

Prefer small internal macros for repeated wrapper boilerplate, but those macros
must generate only the minimal required API. Add conversions only when a current
call site needs them.

## Workspace Boundary

Kohaku-derived code is treated as low-level source material. It can live as
internal modules (for example the BabyJubJub primitives inside `crypto`, or the
vendored `poseidon-rust` engine), but app-facing code should depend on `types`
for shared domain vocabulary and on `crypto` (and the higher-level crates as they
land) for behavior instead of loose primitive functions.
