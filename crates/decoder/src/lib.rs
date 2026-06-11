//! Decodes RAILGUN commitment nodes into a wallet's owned notes.
//!
//! `sync` fills the merkle forest (the database's commitments table); this
//! crate takes any database read context plus a wallet's keys and decodes each
//! node into the wallet's own [`types::DecryptedNote`]s. The decoded set is
//! exposed asset-indexed ([`DecodedNotes`]) for balance and UTXO queries, and
//! persists through the database's `decoded` table namespace.
//!
//! Decoding is per-tree and read-only ([`Decoder::decode_tree`]), so a caller
//! can fan trees across threads (each with its own read view). Spent status is
//! resolved against the nullifier set at query time, keeping the synced chain
//! state the single source of truth.

mod decode;
mod notes;

pub use decode::Decoder;
pub use notes::{Balance, DecodedNotes};

/// Errors raised while decoding nodes.
///
/// Per-node decryption failures (a leaf not addressed to the wallet, or malformed
/// plaintext) are *not* errors — they are skipped during a scan.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// Reading the database (nodes, nullifier set) failed.
    #[error(transparent)]
    Database(#[from] database::DatabaseError),
}
