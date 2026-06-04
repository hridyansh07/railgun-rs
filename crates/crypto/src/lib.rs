//! Heavy-lifting cryptography for `railgun-native`.
//!
//! Domain value types live in `railgun-types`; this crate adds the cryptographic
//! behavior and exposes it as trait methods on those domain types (for example
//! [`SpendingKeyPublicKey`] on `SpendingKey`).
//!
//! Poseidon hashing is backed by the vendored `poseidon-rust` engine — the
//! implementation whose output matches the TypeScript engine's parity vectors.
//! BabyJubJub, MiMC, and Pedersen are kohaku-derived primitives kept internal to
//! this crate; callers reach them only through typed APIs.

// `public()` is wired in via `SpendingKeyPublicKey`; `sign`/`Signature` land when
// transaction EdDSA signing is implemented.
#[allow(dead_code)]
mod babyjubjub;
mod common;
mod keys;
mod poseidon;

pub use keys::SpendingKeyPublicKey;
pub use poseidon::PoseidonInput;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error(transparent)]
    Poseidon(#[from] poseidon_rust::error::Error),
}
