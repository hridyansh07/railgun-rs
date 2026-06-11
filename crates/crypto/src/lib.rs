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
mod aes;
#[allow(dead_code)]
mod babyjubjub;
pub mod commitment;
mod common;
mod derivation;
mod keys;
mod merkle;
mod mnemonic;
mod note;
mod poseidon;
mod viewing;

pub use derivation::{DerivedRailgunKeys, KeyNode};
pub use keys::SpendingKeyPublicKey;
pub use merkle::{
    ExpectedRoot, MerkleAccumulator, MerkleAccumulatorState, MerkleConfig, MerkleError, MerkleRoot,
    MerkleWalk, MerklerootValidator, RailgunMerkleConfig, TreeIntegrity, tree_frontier,
};
pub use mnemonic::{MnemonicStrength, RailgunMnemonic};
pub use note::{NodeDecrypt, NoteDecryptor};
pub use poseidon::PoseidonInput;
pub use viewing::{ViewingKeyNullifier, ViewingKeyPublicKey, ViewingKeySharedSecret};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error(transparent)]
    Poseidon(#[from] poseidon_rust::error::Error),
    #[error(transparent)]
    Bip39(#[from] bip39::Error),
    #[error("invalid seed hex")]
    InvalidSeedHex,
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Type(#[from] types::TypeError),
    #[error("AES authentication failed")]
    Aes,
    #[error("invalid curve point")]
    PointDecompression,
    #[error("commitment plaintext did not match the expected layout")]
    MalformedCommitment,
    #[error("decrypted commitment did not match expected public data")]
    CommitmentMismatch,
}
