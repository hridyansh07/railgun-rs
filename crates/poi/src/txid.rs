//! The railgun txid tree: database-backed leaf storage and the sync pump that
//! builds it from chain transaction events, gated on the POI node's view.
//!
//! The tree is strictly append-only with no gaps (one leaf per validated
//! operation), so a single global leaf count replaces per-tree lengths:
//! leaf `n` lives at `(n / 65536, n % 65536)`.
//!
//! Storage is the `txid` table of the shared [`database::Database`], read and
//! written through typed namespaces ([`Txids`]/[`TxidsMut`]) generic over the
//! [`Reader`]/[`Writer`] seams — so the same code runs over a snapshot, a
//! write transaction, or an overlay batch.
//!
//! [`TxidIndexer::sync_to_head`] mirrors kohaku's `TxidIndexer::sync_to`:
//! fetched transactions land in a durable pending FIFO immediately (one write
//! transaction per block window), but become tree leaves only up to the POI
//! node's validated txid index. The drain is staged in a [`WriteBatch`]
//! overlay, the recomputed roots are validated by the node **while no engine
//! lock is held**, and the batch is applied only on acceptance — dropping it
//! is the discard.

use crypto::{
    MerkleAccumulator, MerkleProof, MerkleRoot, RailgunMerkleConfig, UtxoTreeIndex,
    prove_from_leaves, railgun_txid_for, txid_leaf_hash,
};
use database::{Database, DatabaseError, Reader, WriteBatch, Writer, tables};
use sync::{RailgunTxSource, SyncError};
use types::{BlockNumber, RailgunTransaction, RailgunTxid, U256};

use crate::client::{PoiClientError, PoiNodeClient};

/// Leaves per txid tree (`2^16`), the stride of flat global indices.
const TREE_STRIDE: u64 = 1 << 16;

/// Default block span committed per checkpoint while pumping transactions
/// (same role as the commitment syncer's window).
const DEFAULT_BLOCK_WINDOW: u64 = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum TxidError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error("record codec error: {0}")]
    Codec(#[from] serde_json::Error),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error("txid tree leaf ({tree}, {leaf}) is missing")]
    MissingLeaf { tree: u32, leaf: u32 },
    #[error("stored record has an unexpected shape")]
    MalformedRecord,
}

/// One accepted txid-tree leaf: the operation's txid plus the UTXO positions
/// its leaf hash binds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TxidRecord {
    pub txid: RailgunTxid,
    pub utxo_tree_in: u32,
    pub utxo_tree_out: u32,
    pub utxo_batch_start_position_out: u32,
    pub block: BlockNumber,
}

/// Read namespace over the txid table. Works over any [`Reader`] — snapshot,
/// write transaction, or overlay.
pub struct Txids<'a, R: Reader> {
    reader: &'a R,
}

impl<'a, R: Reader> Txids<'a, R> {
    #[must_use]
    pub fn new(reader: &'a R) -> Self {
        Txids { reader }
    }

    /// Total leaves accepted into the tree forest.
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn total_leaves(&self) -> Result<u64, TxidError> {
        decode_u64(self.reader.get(tables::TXID, &total_key())?.as_deref())
    }

    /// Leaves in `tree` (full strides below the head tree, remainder at it).
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn tree_length(&self, tree: u32) -> Result<u32, TxidError> {
        let total = self.total_leaves()?;
        let start = u64::from(tree) * TREE_STRIDE;
        #[allow(clippy::cast_possible_truncation)]
        Ok(total.saturating_sub(start).min(TREE_STRIDE) as u32)
    }

    /// The leaf hash at `(tree, leaf)`, if present — a raw 32-byte read, no
    /// record decoding (the merkle walk fast path).
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn leaf_hash(&self, tree: u32, leaf: u32) -> Result<Option<U256>, TxidError> {
        match self.reader.get(tables::TXID, &leaf_hash_key(tree, leaf))? {
            Some(bytes) => {
                let array: [u8; 32] = bytes.try_into().map_err(|_| TxidError::MalformedRecord)?;
                Ok(Some(U256::from_be_bytes(array)))
            }
            None => Ok(None),
        }
    }

    /// The full record at `(tree, leaf)`, if present.
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn record(&self, tree: u32, leaf: u32) -> Result<Option<TxidRecord>, TxidError> {
        match self.reader.get(tables::TXID, &record_key(tree, leaf))? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Where `txid` sits in the txid tree, if accepted.
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn txid_position(&self, txid: RailgunTxid) -> Result<Option<(u32, u32)>, TxidError> {
        match self.reader.get(tables::TXID, &txid_index_key(txid))? {
            Some(bytes) => Ok(Some(decode_position(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Where `txid`'s outputs start in the UTXO tree, if accepted:
    /// `(utxo_tree_out, utxo_batch_start_position_out)`.
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn utxo_position(&self, txid: RailgunTxid) -> Result<Option<(u32, u32)>, TxidError> {
        let Some((tree, leaf)) = self.txid_position(txid)? else {
            return Ok(None);
        };
        let record = self
            .record(tree, leaf)?
            .ok_or(TxidError::MissingLeaf { tree, leaf })?;
        Ok(Some((
            record.utxo_tree_out,
            record.utxo_batch_start_position_out,
        )))
    }

    /// Recomputes `tree`'s root by streaming its leaf hashes through a
    /// frontier accumulator (O(depth) memory).
    ///
    /// # Errors
    /// [`TxidError::MissingLeaf`] on a gap (the tree is append-only, so a
    /// gap is corruption); otherwise propagates [`TxidError`].
    pub fn merkle_root(&self, tree: u32) -> Result<MerkleRoot, TxidError> {
        let mut accumulator = MerkleAccumulator::<RailgunMerkleConfig>::new();
        for leaf in 0..self.tree_length(tree)? {
            let hash = self
                .leaf_hash(tree, leaf)?
                .ok_or(TxidError::MissingLeaf { tree, leaf })?;
            accumulator.insert(hash);
        }
        Ok(accumulator.root())
    }

    /// The membership proof for `(tree, leaf)`, built by streaming the tree's
    /// leaf hashes.
    ///
    /// # Errors
    /// As [`merkle_root`](Self::merkle_root), plus a proof error if `leaf` is
    /// past the tree's length.
    pub fn merkle_proof(
        &self,
        tree: u32,
        leaf: u32,
    ) -> Result<MerkleProof<RailgunMerkleConfig>, TxidError> {
        let length = self.tree_length(tree)?;
        let leaves = (0..length).map(|index| {
            self.leaf_hash(tree, index)?
                .ok_or(TxidError::MissingLeaf { tree, leaf: index })
        });
        prove_from_leaves::<RailgunMerkleConfig, _>(leaves, leaf).map_err(|error| match error {
            crypto::MerkleProofError::Source(inner) => inner,
            other => TxidError::MissingLeaf {
                tree,
                leaf: match other {
                    crypto::MerkleProofError::TargetOutOfRange { target, .. } => target,
                    _ => leaf,
                },
            },
        })
    }

    /// The last block whose transactions were pumped into the pending FIFO.
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn synced_block(&self) -> Result<Option<BlockNumber>, TxidError> {
        match self.reader.get(tables::TXID, &synced_block_key())? {
            Some(bytes) => Ok(Some(BlockNumber::new(decode_u64(Some(&bytes))?))),
            None => Ok(None),
        }
    }

    /// Transactions waiting in the FIFO (fetched but not yet POI-validated).
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn pending_len(&self) -> Result<u64, TxidError> {
        let (head, tail) = self.fifo_cursors()?;
        Ok(tail - head)
    }

    fn fifo_cursors(&self) -> Result<(u64, u64), TxidError> {
        match self.reader.get(tables::TXID, &fifo_key())? {
            Some(bytes) if bytes.len() == 16 => {
                let head = u64::from_be_bytes(bytes[..8].try_into().expect("checked length"));
                let tail = u64::from_be_bytes(bytes[8..].try_into().expect("checked length"));
                Ok((head, tail))
            }
            Some(_) => Err(TxidError::MalformedRecord),
            None => Ok((0, 0)),
        }
    }
}

/// Write namespace over the txid table. Staged only — durability is the
/// enclosing transaction's commit (or the batch's `apply`). Reads resolve
/// through the same context, so a drain over an overlay sees its own appends.
pub struct TxidsMut<'a, W: Reader + Writer> {
    rw: &'a mut W,
}

impl<'a, W: Reader + Writer> TxidsMut<'a, W> {
    #[must_use]
    pub fn new(rw: &'a mut W) -> Self {
        TxidsMut { rw }
    }

    /// Stages `transaction` at the FIFO tail.
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn push_pending(&mut self, transaction: &RailgunTransaction) -> Result<(), TxidError> {
        let (head, tail) = Txids::new(&*self.rw).fifo_cursors()?;
        self.rw.put(
            tables::TXID,
            &pending_key(tail),
            &serde_json::to_vec(transaction)?,
        )?;
        self.put_fifo_cursors(head, tail + 1)?;
        Ok(())
    }

    /// Stages removal of the FIFO head and returns it, or `None` if empty.
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn take_pending(&mut self) -> Result<Option<RailgunTransaction>, TxidError> {
        let view = Txids::new(&*self.rw);
        let (head, tail) = view.fifo_cursors()?;
        if head == tail {
            return Ok(None);
        }
        let bytes = self
            .rw
            .get(tables::TXID, &pending_key(head))?
            .ok_or(TxidError::MalformedRecord)?;
        let transaction: RailgunTransaction = serde_json::from_slice(&bytes)?;
        self.rw.delete(tables::TXID, &pending_key(head))?;
        self.put_fifo_cursors(head + 1, tail)?;
        Ok(Some(transaction))
    }

    /// Stages acceptance of the next leaf: record, raw leaf hash, txid index,
    /// and the bumped total. The caller computes `leaf_hash` (it owns the
    /// [`UtxoTreeIndex`] policy).
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn insert_leaf(
        &mut self,
        record: &TxidRecord,
        leaf_hash: U256,
    ) -> Result<(u32, u32), TxidError> {
        let total = Txids::new(&*self.rw).total_leaves()?;
        #[allow(clippy::cast_possible_truncation)]
        let (tree, leaf) = ((total / TREE_STRIDE) as u32, (total % TREE_STRIDE) as u32);

        self.rw.put(
            tables::TXID,
            &record_key(tree, leaf),
            &serde_json::to_vec(record)?,
        )?;
        self.rw.put(
            tables::TXID,
            &leaf_hash_key(tree, leaf),
            &leaf_hash.to_be_bytes::<32>(),
        )?;
        self.rw.put(
            tables::TXID,
            &txid_index_key(record.txid),
            &encode_position(tree, leaf),
        )?;
        self.rw
            .put(tables::TXID, &total_key(), &(total + 1).to_be_bytes())?;
        Ok((tree, leaf))
    }

    /// Stages the pump watermark.
    ///
    /// # Errors
    /// Propagates [`TxidError`].
    pub fn set_synced_block(&mut self, block: BlockNumber) -> Result<(), TxidError> {
        self.rw.put(
            tables::TXID,
            &synced_block_key(),
            &block.get().to_be_bytes(),
        )?;
        Ok(())
    }

    fn put_fifo_cursors(&mut self, head: u64, tail: u64) -> Result<(), TxidError> {
        // alloc-ok: fixed 16-byte cursor record.
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&head.to_be_bytes());
        bytes.extend_from_slice(&tail.to_be_bytes());
        self.rw.put(tables::TXID, &fifo_key(), &bytes)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TxidIndexerError {
    #[error(transparent)]
    Txid(#[from] TxidError),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    PoiClient(#[from] PoiClientError),
    #[error("txid tree {tree} root rejected by the POI node")]
    RootMismatch { tree: u32 },
}

/// Outcome of one [`TxidIndexer::sync_to_head`] run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TxidSyncSummary {
    /// Transactions fetched into the pending FIFO this run.
    pub fetched: u64,
    /// Leaves accepted into the tree this run.
    pub appended: u64,
    /// Duplicate txids consumed from the FIFO without a leaf slot.
    pub duplicates: u64,
    /// Pump watermark after the run.
    pub synced_to: BlockNumber,
}

/// The pump: chain transactions → pending FIFO → validated txid-tree leaves.
pub struct TxidIndexer<S> {
    source: S,
    floor: BlockNumber,
    block_window: u64,
}

impl<S: RailgunTxSource> TxidIndexer<S> {
    /// Creates an indexer over `source`, fetching no earlier than `floor`
    /// (the chain's POI launch block).
    #[must_use]
    pub fn new(source: S, floor: BlockNumber) -> Self {
        TxidIndexer {
            source,
            floor,
            block_window: DEFAULT_BLOCK_WINDOW,
        }
    }

    /// Sets the per-checkpoint block window for the transaction pump.
    ///
    /// # Panics
    /// Panics if `block_window` is zero.
    pub fn set_block_window(&mut self, block_window: u64) {
        assert!(block_window > 0, "block_window must be non-zero");
        self.block_window = block_window;
    }

    /// One full pass: pump new transactions into the FIFO (one write
    /// transaction per block window), then drain leaves up to the POI node's
    /// validated txid index. The drain is staged in a [`WriteBatch`] overlay;
    /// the recomputed roots of every touched tree are validated by the node
    /// with no engine lock held, and the batch is applied only on acceptance.
    ///
    /// # Errors
    /// [`TxidIndexerError::RootMismatch`] drops the drain batch (the FIFO and
    /// watermark keep their pumped state); other variants propagate the
    /// failing layer.
    pub async fn sync_to_head<C: PoiNodeClient>(
        &self,
        db: &Database,
        client: &C,
    ) -> Result<TxidSyncSummary, TxidIndexerError> {
        let mut summary = TxidSyncSummary::default();

        // 1. Pump transactions into the durable pending FIFO, one write
        //    transaction per block window.
        let target = self.source.latest_block().await?;
        let watermark = Txids::new(&db.read()?).synced_block()?;
        let mut from = watermark.map_or(self.floor, |block| block.saturating_add(1));
        summary.synced_to = watermark.unwrap_or_default();

        while from <= target {
            let end = from.saturating_add(self.block_window - 1).min(target);
            // alloc-ok: one window's transactions, the per-checkpoint memory ceiling.
            let mut window = Vec::new();
            let mut cursor = None;
            loop {
                let page = self
                    .source
                    .fetch_transactions_page(from, end, cursor)
                    .await?;
                window.extend(page.transactions);
                match page.cursor {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
            summary.fetched += window.len() as u64;
            db.write(|txn| {
                let mut txids = TxidsMut::new(txn);
                for transaction in &window {
                    txids.push_pending(transaction)?;
                }
                txids.set_synced_block(end)?;
                Ok::<_, TxidIndexerError>(())
            })?;
            summary.synced_to = end;
            from = end.saturating_add(1);
        }

        // 2. Drain leaves up to the node's validated txid index, staged in an
        //    overlay batch over a snapshot — nothing durable yet.
        let validated = client.validated_txid().await?;
        let target_total = u64::from(validated.index) + 1;

        let view = db.read()?;
        let mut batch = WriteBatch::new();
        // alloc-ok: one root per touched tree (drain batches touch few trees).
        let mut roots = Vec::new();
        {
            let mut overlay = batch.overlay(&view);
            let mut total = Txids::new(&overlay).total_leaves()?;
            let first_touched_tree = total / TREE_STRIDE;

            while total < target_total {
                let Some(transaction) = TxidsMut::new(&mut overlay).take_pending()? else {
                    break;
                };
                let txid = railgun_txid_for(&transaction)?;
                if Txids::new(&overlay).txid_position(txid)?.is_some() {
                    // Duplicate operation: consume it without assigning a slot.
                    tracing::warn!(txid = %txid.as_u256(), "skipping duplicate txid");
                    summary.duplicates += 1;
                    continue;
                }

                let leaf_hash = txid_leaf_hash(
                    txid,
                    transaction.utxo_tree_in,
                    UtxoTreeIndex::included(
                        transaction.utxo_tree_out,
                        transaction.utxo_batch_start_position_out,
                    ),
                )?;
                TxidsMut::new(&mut overlay).insert_leaf(
                    &TxidRecord {
                        txid,
                        utxo_tree_in: transaction.utxo_tree_in,
                        utxo_tree_out: transaction.utxo_tree_out,
                        utxo_batch_start_position_out: transaction.utxo_batch_start_position_out,
                        block: transaction.block,
                    },
                    leaf_hash,
                )?;
                total += 1;
                summary.appended += 1;
            }

            // Recompute every touched tree's root over the overlay (base +
            // staged appends as one world).
            if summary.appended > 0 || summary.duplicates > 0 {
                let last_touched_tree = (total.saturating_sub(1)) / TREE_STRIDE;
                for tree in first_touched_tree..=last_touched_tree {
                    #[allow(clippy::cast_possible_truncation)]
                    let tree = tree as u32;
                    let txids = Txids::new(&overlay);
                    let length = txids.tree_length(tree)?;
                    if length == 0 {
                        continue;
                    }
                    roots.push((tree, length - 1, txids.merkle_root(tree)?));
                }
            }
        }
        // The overlay (and the snapshot it read through) is gone: the node
        // round-trips below hold no engine resources at all.
        drop(view);

        // 3. Root-gate the drain batch: apply only if the node accepts every
        //    recomputed root. Dropping the batch is the discard.
        for &(tree, index, root) in &roots {
            let accepted = client.validate_txid_merkleroot(tree, index, root).await?;
            if !accepted {
                return Err(TxidIndexerError::RootMismatch { tree });
            }
        }
        if !batch.is_empty() {
            db.apply(batch)?;
        }

        Ok(summary)
    }
}

fn decode_u64(bytes: Option<&[u8]>) -> Result<u64, TxidError> {
    match bytes {
        Some(bytes) => {
            let array: [u8; 8] = bytes.try_into().map_err(|_| TxidError::MalformedRecord)?;
            Ok(u64::from_be_bytes(array))
        }
        None => Ok(0),
    }
}

fn decode_position(bytes: &[u8]) -> Result<(u32, u32), TxidError> {
    if bytes.len() != 8 {
        return Err(TxidError::MalformedRecord);
    }
    let tree = u32::from_be_bytes(bytes[..4].try_into().expect("checked length"));
    let leaf = u32::from_be_bytes(bytes[4..].try_into().expect("checked length"));
    Ok((tree, leaf))
}

fn encode_position(tree: u32, leaf: u32) -> Vec<u8> {
    // alloc-ok: fixed 8-byte position record.
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&tree.to_be_bytes());
    bytes.extend_from_slice(&leaf.to_be_bytes());
    bytes
}

// Key layout (first byte = namespace), all in the dedicated `"txid"` table:
//   leaf hash:   b'h' | tree (u32 BE) | leaf (u32 BE)   -> 32 raw bytes
//   record:      b'o' | tree (u32 BE) | leaf (u32 BE)   -> TxidRecord JSON
//   txid index:  b'x' | txid (32 bytes)                 -> tree | leaf (u32 BE each)
//   pending:     b'p' | seq (u64 BE)                    -> RailgunTransaction JSON
//   fifo:        b'q'                                   -> head | tail (u64 BE each)
//   total:       b't'                                   -> u64 BE
//   watermark:   b's'                                   -> u64 BE

fn leaf_hash_key(tree: u32, leaf: u32) -> Vec<u8> {
    // alloc-ok: fixed 9-byte store key.
    let mut key = Vec::with_capacity(9);
    key.push(b'h');
    key.extend_from_slice(&tree.to_be_bytes());
    key.extend_from_slice(&leaf.to_be_bytes());
    key
}

fn record_key(tree: u32, leaf: u32) -> Vec<u8> {
    // alloc-ok: fixed 9-byte store key.
    let mut key = Vec::with_capacity(9);
    key.push(b'o');
    key.extend_from_slice(&tree.to_be_bytes());
    key.extend_from_slice(&leaf.to_be_bytes());
    key
}

fn txid_index_key(txid: RailgunTxid) -> Vec<u8> {
    // alloc-ok: fixed 33-byte store key.
    let mut key = Vec::with_capacity(33);
    key.push(b'x');
    key.extend_from_slice(&txid.as_u256().to_be_bytes::<32>());
    key
}

fn pending_key(seq: u64) -> Vec<u8> {
    // alloc-ok: fixed 9-byte store key.
    let mut key = Vec::with_capacity(9);
    key.push(b'p');
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

fn fifo_key() -> Vec<u8> {
    // alloc-ok: 1-byte global store key.
    vec![b'q']
}

fn total_key() -> Vec<u8> {
    // alloc-ok: 1-byte global store key.
    vec![b't']
}

fn synced_block_key() -> Vec<u8> {
    // alloc-ok: 1-byte global store key.
    vec![b's']
}

#[cfg(test)]
mod tests {
    use database::test_util::temp;

    use crate::test_support::{CannedTxSource, MockPoiNode};

    use super::*;

    fn transaction(block: u64, seed: u64) -> RailgunTransaction {
        RailgunTransaction {
            block: BlockNumber::new(block),
            nullifiers: vec![U256::from(seed)],
            commitments: vec![U256::from(seed + 1), U256::from(seed + 2)],
            bound_params_hash: U256::from(seed + 3),
            utxo_tree_in: 0,
            utxo_tree_out: 0,
            utxo_batch_start_position_out: 7,
        }
    }

    #[tokio::test]
    async fn drains_up_to_validated_index_and_records_positions() {
        let source = CannedTxSource {
            head: BlockNumber::new(100),
            transactions: vec![
                transaction(10, 1),
                transaction(20, 100),
                transaction(30, 200),
            ],
        };
        // Node has validated only the first two leaves (flat index 1).
        let client = MockPoiNode {
            validated_index: 1,
            ..MockPoiNode::default()
        };
        let indexer = TxidIndexer::new(source, BlockNumber::new(0));
        let db = temp();

        let summary = indexer.sync_to_head(&db, &client).await.unwrap();

        assert_eq!(summary.fetched, 3);
        assert_eq!(summary.appended, 2);
        assert_eq!(summary.synced_to, BlockNumber::new(100));

        let view = db.read().unwrap();
        let txids = Txids::new(&view);
        assert_eq!(txids.total_leaves().unwrap(), 2);
        assert_eq!(txids.pending_len().unwrap(), 1);

        // Positions and the txid index round-trip.
        let txid = railgun_txid_for(&transaction(10, 1)).unwrap();
        assert_eq!(txids.txid_position(txid).unwrap(), Some((0, 0)));
        assert_eq!(txids.utxo_position(txid).unwrap(), Some((0, 7)));
        assert!(txids.leaf_hash(0, 1).unwrap().is_some());
        assert!(txids.leaf_hash(0, 2).unwrap().is_none());

        // The root the node accepted matches a local recompute and the proof.
        let validated = client.validated_roots.lock().unwrap();
        assert_eq!(validated.len(), 1);
        let (tree, index, root) = validated[0];
        assert_eq!((tree, index), (0, 1));
        assert_eq!(txids.merkle_root(0).unwrap(), root);
        let proof = txids.merkle_proof(0, 1).unwrap();
        assert_eq!(proof.root, root);
        assert!(proof.verify());
    }

    #[tokio::test]
    async fn rejected_root_discards_the_drain_batch_but_keeps_the_pump() {
        let source = CannedTxSource {
            head: BlockNumber::new(100),
            transactions: vec![transaction(10, 1)],
        };
        let client = MockPoiNode {
            validated_index: 0,
            accept_roots: false,
            ..MockPoiNode::default()
        };
        let indexer = TxidIndexer::new(source, BlockNumber::new(0));
        let db = temp();

        let error = indexer.sync_to_head(&db, &client).await.unwrap_err();
        assert!(matches!(error, TxidIndexerError::RootMismatch { tree: 0 }));

        // Drain batch discarded; the pumped FIFO and watermark survived.
        let view = db.read().unwrap();
        let txids = Txids::new(&view);
        assert_eq!(txids.total_leaves().unwrap(), 0);
        assert_eq!(txids.pending_len().unwrap(), 1);
        assert_eq!(txids.synced_block().unwrap(), Some(BlockNumber::new(100)));
    }

    #[tokio::test]
    async fn duplicate_txids_consume_pending_without_a_leaf_slot() {
        let duplicate = transaction(10, 1);
        let source = CannedTxSource {
            head: BlockNumber::new(100),
            transactions: vec![duplicate.clone(), duplicate, transaction(20, 100)],
        };
        let client = MockPoiNode {
            validated_index: 1,
            ..MockPoiNode::default()
        };
        let indexer = TxidIndexer::new(source, BlockNumber::new(0));
        let db = temp();

        let summary = indexer.sync_to_head(&db, &client).await.unwrap();
        assert_eq!(summary.appended, 2);
        assert_eq!(summary.duplicates, 1);

        let view = db.read().unwrap();
        assert_eq!(Txids::new(&view).total_leaves().unwrap(), 2);
        assert_eq!(Txids::new(&view).pending_len().unwrap(), 0);
    }

    #[tokio::test]
    async fn resync_is_idempotent_from_the_watermark() {
        let source = CannedTxSource {
            head: BlockNumber::new(100),
            transactions: vec![transaction(10, 1)],
        };
        let client = MockPoiNode {
            validated_index: 0,
            ..MockPoiNode::default()
        };
        let indexer = TxidIndexer::new(source, BlockNumber::new(0));
        let db = temp();

        indexer.sync_to_head(&db, &client).await.unwrap();
        let second = indexer.sync_to_head(&db, &client).await.unwrap();

        // Nothing re-fetched (watermark) and nothing re-appended (validated index).
        assert_eq!(second.fetched, 0);
        assert_eq!(second.appended, 0);
        let view = db.read().unwrap();
        assert_eq!(Txids::new(&view).total_leaves().unwrap(), 1);
    }
}
