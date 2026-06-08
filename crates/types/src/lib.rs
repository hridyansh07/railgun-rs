//! Base Alloy-backed RAILGUN domain types.
//!
//! This crate is the single vocabulary the rest of the workspace shares: EVM base
//! primitives (re-exported from `alloy-primitives`) plus RAILGUN protocol newtypes.
//!
//! `RailgunAddress` / `0zk` handling belongs in this crate later. It is not
//! implemented yet; this crate currently owns only the base types.

mod asset;
mod block;
mod commitment;
mod curve;
mod derivation;
mod macros;
mod protocol;
mod scalar;

pub use alloy_primitives::{Address as EvmAddress, B256, Bytes, U256, uint};
pub use asset::AssetId;
pub use block::BlockNumber;
pub use commitment::{
    BlindedCommitmentType, Ciphertext, DecryptedNote, NodePosition, NoteValue, Nullified,
    ShieldCommitment, TransactCommitment,
};
pub use curve::{
    BabyJubJubPoint, BlindedKey, SharedKey, SpendingKey, ViewingKey, ViewingPublicKey,
};
pub use derivation::{DerivationPath, DerivationPathError, RailgunAccountIndex};
pub use protocol::{
    Base37Error, CommitmentHash, Nullifier, PoseidonHash, RailgunBase37, RailgunBase37Decoded,
    RailgunTxid,
};
pub use scalar::FieldScalar;

/// Base error for the `types` crate. Higher-level APIs absorb this single error
/// (via `#[from]`) instead of matching each granular error by hand; the granular
/// errors stay as the precise return types of their own operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypeError {
    #[error(transparent)]
    Base37(#[from] Base37Error),
    #[error(transparent)]
    DerivationPath(#[from] DerivationPathError),
    #[error("expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid token hash")]
    InvalidTokenHash,
    #[error("invalid node position leaf index: {leaf_index}")]
    InvalidNodePosition { leaf_index: u32 },
    #[error("value does not fit in a RAILGUN note value")]
    ValueOverflow,
}
