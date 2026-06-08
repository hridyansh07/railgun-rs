//! The RAILGUN commitment store.
//!
//! Every on-chain commitment is recorded, keyed by `(tree, position)`, on top of
//! a buffered [`utils::KeyValueStore`]. This is the data substrate a future
//! balance scanner reads: the engine discovers a wallet's UTXOs by attempt-
//! decrypting *every* stored commitment, so they all live here regardless of
//! ownership. Spent-tracking (nullifiers) lives alongside.
//!
//! This crate stores and retrieves commitments only — it does no hashing
//! (merkle roots/proofs) and no decryption (the scanner). Both are deferred.

mod codec;
mod store;
mod tree;

pub use codec::CodecError;
pub use store::{CommitmentStore, CommitmentStoreError};
pub use tree::Tree;
