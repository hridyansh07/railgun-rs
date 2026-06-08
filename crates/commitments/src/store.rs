//! Commitment + nullifier storage keyed by `(tree, position)`.

use types::{
    BlockNumber, NodePosition, Nullified, Nullifier, ShieldCommitment, TransactCommitment,
};
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

/// Stores every commitment (keyed by `(tree, position)`), the set of observed
/// nullifiers, and the sync watermark, over a [`KeyValueStore`]. Records use the
/// byte-exact [`crate::codec`] layout.
///
/// This is the single source of truth for "what leaves do I have, and as of what
/// block." [`commit`](Self::commit) is the **only** durability boundary: it stages a
/// batch of commitments + nullifiers **and** the watermark, then flushes once, so the
/// watermark can never be observed apart from the data it certifies.
#[derive(Debug)]
pub struct CommitmentStore<B: StorageBackend> {
    kv: KeyValueStore<B>,
}

impl<B: StorageBackend> CommitmentStore<B> {
    /// Opens a store over `backend`.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            kv: KeyValueStore::new(backend),
        }
    }

    /// Atomically records a batch of commitments + nullifiers and advances the sync
    /// watermark to `through`, in a single backend transaction.
    ///
    /// The watermark and the data move together: on error nothing is flushed, so the
    /// durable state never has the watermark ahead of (or behind) its commitments. An
    /// empty batch still advances the watermark (a fully-scanned block range with no
    /// events). Commitment keys are `(tree, position)`, so re-committing a range is
    /// idempotent.
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn commit(
        &mut self,
        commitments: Vec<CommitmentNode>,
        nullifiers: Vec<Nullified>,
        through: BlockNumber,
    ) -> Result<(), CommitmentStoreError> {
        for node in commitments {
            self.insert(&node)?;
        }
        for nullified in nullifiers {
            self.insert_nullifier(nullified);
        }
        self.stage_synced_block(through);
        self.kv.flush()?;
        Ok(())
    }

    /// Stages a commitment at its `(tree, position)`, extending the tracked tree
    /// length and tree count as needed. Staged only — durability is the caller's
    /// [`commit`](Self::commit).
    fn insert(&mut self, node: &CommitmentNode) -> Result<(), CommitmentStoreError> {
        let position = node.position();
        let tree = position.tree_number();
        let index = position.leaf_index();

        self.kv.put(commitment_key(tree, index), encode_node(node));

        if index + 1 > self.tree_length(tree)? {
            self.kv
                .put(length_key(tree), (index + 1).to_be_bytes().to_vec());
        }
        if tree + 1 > self.tree_count()? {
            self.kv
                .put(tree_count_key(), (tree + 1).to_be_bytes().to_vec());
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

    /// Stages an observed nullifier (marks the matching commitment spent). Staged
    /// only — durability is the caller's [`commit`](Self::commit).
    fn insert_nullifier(&mut self, nullified: Nullified) {
        self.kv.put(
            nullifier_key(nullified.tree_number, nullified.nullifier),
            Vec::new(),
        );
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

    /// The last block synced into this store, or `None` if never synced. This is the
    /// resume floor a syncer reads before fetching more.
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn synced_block(&self) -> Result<Option<BlockNumber>, CommitmentStoreError> {
        match self.kv.get(&synced_block_key())? {
            Some(bytes) => {
                let array: [u8; 8] = bytes.try_into().map_err(|_| CodecError::UnexpectedEof)?;
                Ok(Some(BlockNumber::new(u64::from_be_bytes(array))))
            }
            None => Ok(None),
        }
    }

    /// Stages the sync watermark. Staged only — flushed atomically with its data by
    /// [`commit`](Self::commit).
    fn stage_synced_block(&mut self, block: BlockNumber) {
        self.kv
            .put(synced_block_key(), block.get().to_be_bytes().to_vec());
    }

    /// Consumes the store and returns the backend. Safe to call between commits: a
    /// [`commit`](Self::commit) leaves no staged writes behind.
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
//   watermark:   b's' (global)

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

fn synced_block_key() -> Vec<u8> {
    // alloc-ok: 1-byte global store key.
    vec![b's']
}
