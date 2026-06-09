//! Decodes RAILGUN commitment nodes into a wallet's owned notes.
//!
//! `sync` fills the merkle forest ([`commitments::CommitmentStore`]); this crate takes
//! a read-view of that store plus a wallet's keys and decodes each node into the
//! wallet's own [`types::DecryptedNote`]s. The decoded set is exposed asset-indexed
//! ([`DecodedNotes`]) for balance and UTXO queries, and can be persisted over any
//! storage backend ([`DecodedNoteStore`]) — for redb, in its own table alongside the
//! commitment store.
//!
//! Decoding is per-tree and read-only ([`Decoder::decode_tree`]), so a caller can fan
//! trees across threads. Spent status is resolved against the commitment store's
//! nullifier set at query time, keeping the synced chain state the single source of
//! truth.

mod decode;
mod notes;
mod store;

pub use decode::Decoder;
pub use notes::{Balance, DecodedNotes};
pub use store::DecodedNoteStore;

/// Errors raised while decoding nodes or persisting the decoded set.
///
/// Per-node decryption failures (a leaf not addressed to the wallet, or malformed
/// plaintext) are *not* errors — they are skipped during a scan.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// Reading the commitment store (nodes, nullifier set) failed.
    #[error(transparent)]
    Store(#[from] commitments::CommitmentStoreError),
    /// Reading or writing the decoded-note store failed.
    #[error(transparent)]
    Storage(#[from] utils::StorageError),
    /// Encoding or decoding a persisted note record failed.
    #[error("note (de)serialization failed: {0}")]
    Serde(String),
}
