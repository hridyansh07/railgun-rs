//! Commitment + nullifier storage keyed by `(tree, position)`.

use types::{NodePosition, Nullified, Nullifier, ShieldCommitment, TransactCommitment};
use utils::{KeyValueStore, StorageBackend, StorageError};

use crate::codec::{CodecError, decode_node, encode_node};

/// A stored commitment, mirroring the engine's `Commitment` union.
#[derive(Debug)]
pub enum CommitmentNode {
    Shield(ShieldCommitment),
    Transact(TransactCommitment),
}

impl CommitmentNode {
    /// Where this commitment sits in the UTXO forest.
    #[must_use]
    pub fn position(&self) -> NodePosition {
        match self {
            Self::Shield(commitment) => commitment.position,
            Self::Transact(commitment) => commitment.position,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CommitmentStoreError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Codec(#[from] CodecError),
}

/// Stores every commitment (keyed by `(tree, position)`) and the set of observed
/// nullifiers, over a buffered [`KeyValueStore`]. Records are persisted with the
/// byte-exact [`crate::codec`] layout.
#[derive(Debug)]
pub struct CommitmentStore<B: StorageBackend> {
    kv: KeyValueStore<B>,
}

impl<B: StorageBackend> CommitmentStore<B> {
    /// Opens a store over `backend` (default flush policy).
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            kv: KeyValueStore::new(backend),
        }
    }

    /// Opens a store over a pre-configured [`KeyValueStore`] (e.g. custom flush capacity).
    #[must_use]
    pub fn with_store(kv: KeyValueStore<B>) -> Self {
        Self { kv }
    }

    /// Records a commitment at its `(tree, position)`, extending the tracked tree
    /// length and tree count as needed.
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn insert(&mut self, node: &CommitmentNode) -> Result<(), CommitmentStoreError> {
        let position = node.position();
        let tree = position.tree_number();
        let index = position.leaf_index();

        self.kv
            .put(commitment_key(tree, index), encode_node(node))?;

        if index + 1 > self.tree_length(tree)? {
            self.kv
                .put(length_key(tree), (index + 1).to_be_bytes().to_vec())?;
        }
        if tree + 1 > self.tree_count()? {
            self.kv
                .put(tree_count_key(), (tree + 1).to_be_bytes().to_vec())?;
        }
        Ok(())
    }

    /// Reads the commitment at `(tree, position)`, if present.
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn get(
        &self,
        tree: u32,
        position: u32,
    ) -> Result<Option<CommitmentNode>, CommitmentStoreError> {
        match self.kv.get(&commitment_key(tree, position))? {
            Some(bytes) => Ok(Some(decode_node(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Reads the commitments in `tree` at positions `start..=end` (inclusive),
    /// skipping any gaps. Mirrors the engine's `getCommitmentRange`.
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn range(
        &self,
        tree: u32,
        start: u32,
        end: u32,
    ) -> Result<Vec<CommitmentNode>, CommitmentStoreError> {
        // alloc-ok: range DTO bounded by the caller-chosen scan window.
        let mut out = Vec::new();
        for position in start..=end {
            if let Some(node) = self.get(tree, position)? {
                out.push(node);
            }
        }
        Ok(out)
    }

    /// Number of leaves recorded in `tree` (highest seen position + 1).
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn tree_length(&self, tree: u32) -> Result<u32, CommitmentStoreError> {
        decode_u32(self.kv.get(&length_key(tree))?.as_deref())
    }

    /// Number of trees observed (highest tree number + 1).
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn tree_count(&self) -> Result<u32, CommitmentStoreError> {
        decode_u32(self.kv.get(&tree_count_key())?.as_deref())
    }

    /// Highest tree number observed, or `None` if the store is empty.
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn latest_tree(&self) -> Result<Option<u32>, CommitmentStoreError> {
        let count = self.tree_count()?;
        Ok(if count == 0 { None } else { Some(count - 1) })
    }

    /// Records an observed nullifier (marks the matching commitment spent).
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn insert_nullifier(&mut self, nullified: Nullified) -> Result<(), CommitmentStoreError> {
        self.kv.put(
            nullifier_key(nullified.tree_number, nullified.nullifier),
            Vec::new(),
        )?;
        Ok(())
    }

    /// Whether `nullifier` has been seen in `tree`.
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn is_nullified(
        &self,
        tree: u32,
        nullifier: Nullifier,
    ) -> Result<bool, CommitmentStoreError> {
        Ok(self.kv.get(&nullifier_key(tree, nullifier))?.is_some())
    }

    /// Forces all staged writes to the backend.
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn flush(&mut self) -> Result<(), CommitmentStoreError> {
        self.kv.flush()?;
        Ok(())
    }

    /// Consumes the store and returns the backend. Call [`flush`](Self::flush)
    /// first to persist staged writes.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.kv.into_backend()
    }
}

/// Decodes a stored 4-byte big-endian counter, treating a missing key as zero.
fn decode_u32(bytes: Option<&[u8]>) -> Result<u32, CommitmentStoreError> {
    match bytes {
        Some(bytes) => {
            let array: [u8; 4] = bytes.try_into().map_err(|_| CodecError::UnexpectedEof)?;
            Ok(u32::from_be_bytes(array))
        }
        None => Ok(0),
    }
}

// Key layout (first byte = namespace):
//   commitment:  b'c' | tree (u32 BE) | position (u32 BE)
//   nullifier:   b'n' | tree (u32 BE) | nullifier (32 bytes)
//   tree length: b'm' | tree (u32 BE)
//   tree count:  b'g' (global)

fn commitment_key(tree: u32, position: u32) -> Vec<u8> {
    // alloc-ok: fixed 9-byte store key.
    let mut key = Vec::with_capacity(9);
    key.push(b'c');
    key.extend_from_slice(&tree.to_be_bytes());
    key.extend_from_slice(&position.to_be_bytes());
    key
}

fn nullifier_key(tree: u32, nullifier: Nullifier) -> Vec<u8> {
    // alloc-ok: fixed 37-byte store key.
    let mut key = Vec::with_capacity(37);
    key.push(b'n');
    key.extend_from_slice(&tree.to_be_bytes());
    key.extend_from_slice(nullifier.as_b256().as_slice());
    key
}

fn length_key(tree: u32) -> Vec<u8> {
    // alloc-ok: fixed 5-byte store key.
    let mut key = Vec::with_capacity(5);
    key.push(b'm');
    key.extend_from_slice(&tree.to_be_bytes());
    key
}

fn tree_count_key() -> Vec<u8> {
    // alloc-ok: 1-byte global store key.
    vec![b'g']
}
