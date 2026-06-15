//! The UTXO merkle forest table: commitments keyed by `(tree, position)`,
//! the nullifier set, per-tree lengths, and the sync watermark.
//!
//! Key layout and the byte-exact node codec are **frozen** — they pre-date
//! this crate (moved verbatim from the old `commitments` crate) and existing
//! database files must keep reading. Key layout (first byte = namespace):
//!
//! ```text
//! commitment:  b'c' | tree (u32 BE) | position (u32 BE)
//! nullifier:   b'n' | tree (u32 BE) | nullifier (32 bytes)
//! tree length: b'm' | tree (u32 BE)
//! tree count:  b'g' (global)
//! watermark:   b's' (global)
//! rescan:      b'r' | tree (u32 BE) | position (u32 BE)   (additive, post-freeze)
//! ```
//!
//! The rescan queue records backfills: a node staged **below** its tree's
//! length landed under every wallet's scan watermark, so the decode scanner
//! must revisit that position (and clears the entry once it has).

use types::{BlockNumber, CommitmentHash, Node, Nullified, Nullifier};

use crate::DatabaseError;
use crate::read::{RangeIter, Reader};
use crate::tables::{TableId, codec};
use crate::write::Writer;

/// Read namespace over the commitments table. Construct via
/// `view.commitments()` (or any [`Reader`]'s equivalent).
pub struct Commitments<'a, R: Reader> {
    reader: &'a R,
}

impl<'a, R: Reader> Commitments<'a, R> {
    /// Opens the namespace over any [`Reader`] (snapshot, write transaction,
    /// or overlay). `view.commitments()` is the usual spelling.
    #[must_use]
    pub fn new(reader: &'a R) -> Self {
        Commitments { reader }
    }

    /// The node at `(tree, position)`, if present.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn node(&self, tree: u32, position: u32) -> Result<Option<Node>, DatabaseError> {
        match self
            .reader
            .get(TableId::Commitments, &commitment_key(tree, position))?
        {
            Some(bytes) => Ok(Some(codec::decode_node(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Only the merkle leaf hash at `(tree, position)` — without decoding the
    /// rest of the node.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn leaf_hash(
        &self,
        tree: u32,
        position: u32,
    ) -> Result<Option<CommitmentHash>, DatabaseError> {
        match self
            .reader
            .get(TableId::Commitments, &commitment_key(tree, position))?
        {
            Some(bytes) => Ok(Some(codec::decode_hash(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Every leaf hash in `tree`, in position order, as **one range scan**
    /// (one engine transaction for the whole walk). Yields the stored
    /// position alongside each hash so a walker can detect gaps.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn leaf_hashes(&self, tree: u32) -> Result<LeafHashes, DatabaseError> {
        Ok(LeafHashes(self.reader.range(
            TableId::Commitments,
            &commitment_key(tree, 0),
            &commitment_key(tree, u32::MAX),
        )?))
    }

    /// Every stored node in `tree`, in position order, as one range scan.
    /// The decoder's scan path.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn nodes(&self, tree: u32) -> Result<Nodes, DatabaseError> {
        self.nodes_range(tree, 0, u32::MAX)
    }

    /// The stored nodes of `tree` within positions `first..=last`, in
    /// position order — the bounded scan a chunked decode worker runs.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn nodes_range(&self, tree: u32, first: u32, last: u32) -> Result<Nodes, DatabaseError> {
        Ok(Nodes(self.reader.range(
            TableId::Commitments,
            &commitment_key(tree, first),
            &commitment_key(tree, last),
        )?))
    }

    /// Backfilled `(tree, position)` pairs awaiting a decode rescan, in key
    /// order.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn rescan_queue(&self) -> Result<Vec<(u32, u32)>, DatabaseError> {
        // alloc-ok: backfills are rare; the queue is normally empty.
        let mut queue = Vec::new();
        for entry in self.reader.range(
            TableId::Commitments,
            &rescan_key(0, 0),
            &rescan_key(u32::MAX, u32::MAX),
        )? {
            let (key, _) = entry?;
            queue.push(rescan_from_key(&key)?);
        }
        Ok(queue)
    }

    /// Number of leaves recorded in `tree` (highest seen position + 1).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn tree_length(&self, tree: u32) -> Result<u32, DatabaseError> {
        decode_u32(
            self.reader
                .get(TableId::Commitments, &length_key(tree))?
                .as_deref(),
        )
    }

    /// Number of trees observed (highest tree number + 1).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn tree_count(&self) -> Result<u32, DatabaseError> {
        decode_u32(
            self.reader
                .get(TableId::Commitments, &tree_count_key())?
                .as_deref(),
        )
    }

    /// Highest tree number observed, or `None` if the store is empty.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn latest_tree(&self) -> Result<Option<u32>, DatabaseError> {
        let count = self.tree_count()?;
        Ok(if count == 0 { None } else { Some(count - 1) })
    }

    /// Whether `nullifier` has been seen in `tree` (the commitment is spent).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn is_nullified(&self, tree: u32, nullifier: Nullifier) -> Result<bool, DatabaseError> {
        Ok(self
            .reader
            .get(TableId::Commitments, &nullifier_key(tree, nullifier))?
            .is_some())
    }

    /// The last block synced, or `None` if never synced — the syncer's resume
    /// floor.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn synced_block(&self) -> Result<Option<BlockNumber>, DatabaseError> {
        match self.reader.get(TableId::Commitments, &synced_block_key())? {
            Some(bytes) => {
                let array: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| DatabaseError::Engine("malformed watermark".to_owned()))?;
                Ok(Some(BlockNumber::new(u64::from_be_bytes(array))))
            }
            None => Ok(None),
        }
    }

    /// Whether this database has ever been synced (carries a watermark).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn is_synced(&self) -> Result<bool, DatabaseError> {
        Ok(self.synced_block()?.is_some())
    }
}

/// Position-ordered `(position, leaf_hash)` stream over one tree.
pub struct LeafHashes(RangeIter);

impl Iterator for LeafHashes {
    type Item = Result<(u32, CommitmentHash), DatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.0.next()?;
        Some(entry.and_then(|(key, value)| {
            let position = position_from_key(&key)?;
            let hash = codec::decode_hash(&value)?;
            Ok((position, hash))
        }))
    }
}

/// Position-ordered decoded [`Node`] stream over one tree.
pub struct Nodes(RangeIter);

impl Iterator for Nodes {
    type Item = Result<Node, DatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.0.next()?;
        Some(entry.and_then(|(_, value)| Ok(codec::decode_node(&value)?)))
    }
}

/// Write namespace over the commitments table. Staged only — durability is
/// the enclosing transaction's commit (or the batch's `apply`).
pub struct CommitmentsMut<'a, W: Reader + Writer> {
    rw: &'a mut W,
}

impl<'a, W: Reader + Writer> CommitmentsMut<'a, W> {
    pub(crate) fn new(rw: &'a mut W) -> Self {
        CommitmentsMut { rw }
    }

    /// Stages a commitment at its `(tree, position)`, extending the tracked
    /// tree length and tree count as needed (reads see staged writes, so
    /// repeated inserts within one batch keep counters correct).
    ///
    /// Incorrect commitments either mean a failure of the config/indexing layer
    /// Currently propogates and error ideally should surface the error and refetch
    /// the same node from RPC calls through the chain for a higher gurantee of correct node?
    ///
    /// # Errors
    /// [`DatabaseError::CommitmentConflict`] if a different node is already
    /// stored at this position; otherwise propagates [`DatabaseError`].
    pub fn insert_node(&mut self, node: &Node) -> Result<(), DatabaseError> {
        let tree = node.position.tree_number();
        let index = node.position.leaf_index();
        let key = commitment_key(tree, index);
        let encoded = codec::encode_node(node);

        if let Some(existing) = self.rw.get(TableId::Commitments, &key)? {
            if existing == encoded {
                return Ok(());
            }
            return Err(DatabaseError::CommitmentConflict {
                tree,
                position: index,
            });
        }

        self.rw.put(TableId::Commitments, &key, &encoded)?;

        let view = Commitments::new(&*self.rw);
        let length = view.tree_length(tree)?;
        let count = view.tree_count()?;
        if index + 1 > length {
            self.rw.put(
                TableId::Commitments,
                &length_key(tree),
                &(index + 1).to_be_bytes(),
            )?;
        } else {
            // Backfill: the node landed below the tree's length, i.e. under
            // every wallet's scan watermark — queue it for a decode rescan.
            self.rw
                .put(TableId::Commitments, &rescan_key(tree, index), &[])?;
        }
        if tree + 1 > count {
            self.rw.put(
                TableId::Commitments,
                &tree_count_key(),
                &(tree + 1).to_be_bytes(),
            )?;
        }
        Ok(())
    }

    /// Stages removal of a drained rescan-queue entry (the scanner has
    /// revisited the position).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn clear_rescan(&mut self, tree: u32, position: u32) -> Result<(), DatabaseError> {
        self.rw
            .delete(TableId::Commitments, &rescan_key(tree, position))
    }

    /// Stages an observed nullifier (marks the matching commitment spent).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn insert_nullifier(&mut self, nullified: Nullified) -> Result<(), DatabaseError> {
        self.rw.put(
            TableId::Commitments,
            &nullifier_key(nullified.tree_number, nullified.nullifier),
            &[],
        )
    }

    /// Stages the sync watermark. Always staged in the same transaction as
    /// the data it certifies — that is the whole point of the closure-scoped
    /// write.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn set_synced_block(&mut self, block: BlockNumber) -> Result<(), DatabaseError> {
        self.rw.put(
            TableId::Commitments,
            &synced_block_key(),
            &block.get().to_be_bytes(),
        )
    }
}

fn decode_u32(bytes: Option<&[u8]>) -> Result<u32, DatabaseError> {
    match bytes {
        Some(bytes) => {
            let array: [u8; 4] = bytes
                .try_into()
                .map_err(|_| DatabaseError::Engine("malformed counter".to_owned()))?;
            Ok(u32::from_be_bytes(array))
        }
        None => Ok(0),
    }
}

fn position_from_key(key: &[u8]) -> Result<u32, DatabaseError> {
    // b'c' | tree (4) | position (4)
    let bytes: [u8; 4] = key
        .get(5..9)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| DatabaseError::Engine("malformed commitment key".to_owned()))?;
    Ok(u32::from_be_bytes(bytes))
}

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

fn rescan_key(tree: u32, position: u32) -> Vec<u8> {
    // alloc-ok: fixed 9-byte store key.
    let mut key = Vec::with_capacity(9);
    key.push(b'r');
    key.extend_from_slice(&tree.to_be_bytes());
    key.extend_from_slice(&position.to_be_bytes());
    key
}

fn rescan_from_key(key: &[u8]) -> Result<(u32, u32), DatabaseError> {
    // b'r' | tree (4) | position (4)
    let malformed = || DatabaseError::Engine("malformed rescan key".to_owned());
    let tree: [u8; 4] = key
        .get(1..5)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(malformed)?;
    let position: [u8; 4] = key
        .get(5..9)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(malformed)?;
    Ok((u32::from_be_bytes(tree), u32::from_be_bytes(position)))
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
