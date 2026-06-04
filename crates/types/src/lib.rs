//! Base Alloy-backed RAILGUN domain types.
//!
//! This crate is the single vocabulary the rest of the workspace shares: EVM base
//! primitives (re-exported from `alloy-primitives`) plus RAILGUN protocol newtypes.
//!
//! `RailgunAddress` / `0zk` handling belongs in this crate later. It is not
//! implemented yet; this crate currently owns only the base types.

mod curve;
mod macros;
mod protocol;
mod scalar;

pub use alloy_primitives::{Address as EvmAddress, B256, Bytes, U256, uint};
pub use curve::{BabyJubJubPoint, SharedKey, SpendingKey, ViewingKey};
pub use protocol::{
    Base37Error, CommitmentHash, Nullifier, PoseidonHash, RailgunBase37, RailgunBase37Decoded,
    RailgunTxid,
};
pub use scalar::FieldScalar;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RailgunTypeError {
    #[error("expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
}
