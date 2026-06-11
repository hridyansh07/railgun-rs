//! The unified wallet database: one owner of the open store.
//!
//! Everything persisted flows through one [`Database`]:
//!
//! - **Reads** ([`Database::read`]) hand out [`ReadView`]s — concurrent MVCC
//!   snapshots with typed table namespaces and range scans (one engine
//!   transaction per view, however many keys you read).
//! - **Writes** ([`Database::write`]) are closure-scoped transactions:
//!   commit on `Ok`, discard on `Err`. The closure can touch any number of
//!   tables — cross-table atomicity (data + watermark + frontier together)
//!   is the reason this crate exists.
//! - **Overlay batches** ([`WriteBatch`]/[`Overlay`]) stage writes *outside*
//!   any engine transaction, readable as one world over a snapshot — the
//!   primitive for "stage, validate against an external authority (async),
//!   then apply atomically". Dropping the batch is the discard.
//!
//! Tracing is built in at this single choke point: every write transaction
//! emits a commit event with duration and per-table mutation counts.
//!
//! The engine behind it is redb (or an in-memory test engine); see
//! [`engine`](crate::engine) — sealed enum dispatch, no generics leak out.
//! Table key layouts that pre-date this crate (commitments, decoded notes)
//! are frozen; see each `tables::*` module.

mod batch;
mod engine;
mod read;
pub mod tables;
mod version;
mod write;

use std::path::Path;
use std::time::Instant;

pub use batch::{Overlay, WriteBatch};
pub use read::{RangeIter, ReadView, Reader};
pub use tables::TableId;
pub use tables::codec::CodecError;
pub use tables::commitments::{Commitments, CommitmentsMut, LeafHashes, Nodes};
pub use tables::decoded::{Decoded, DecodedMut};
pub use tables::frontier::{Frontier, FrontierMut};
pub use write::{WriteTxn, Writer};

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("storage engine error: {0}")]
    Engine(String),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("record (de)serialization failed: {0}")]
    Serde(String),
    #[error("schema version mismatch for table {table}: found v{found}, expected v{expected}")]
    SchemaVersion {
        table: &'static str,
        found: u32,
        expected: u32,
    },
}

/// The single owner of the open store. Share it as `Arc<Database>`; reads are
/// concurrent snapshots, writes serialize on the engine's writer lock.
pub struct Database {
    engine: engine::Engine,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database").finish_non_exhaustive()
    }
}

impl Database {
    /// Opens (creating if absent) the redb database at `path`: materializes
    /// every registered table and checks/stamps schema versions, all in one
    /// transaction. Files that pre-date version stamping are stamped as v1.
    ///
    /// # Errors
    /// [`DatabaseError::SchemaVersion`] on a stamp mismatch; otherwise
    /// propagates the engine.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let db = Database {
            engine: engine::Engine::open(path.as_ref())?,
        };
        db.initialize()?;
        Ok(db)
    }

    /// An in-memory database (test engine). Same semantics, nothing durable.
    ///
    /// # Panics
    /// Panics only if initialization of the empty engine fails (it cannot).
    #[must_use]
    pub fn in_memory() -> Self {
        let db = Database {
            engine: engine::Engine::in_memory(),
        };
        db.initialize()
            .expect("in-memory initialization is infallible");
        db
    }

    /// A consistent snapshot of every table. Concurrent with writers and
    /// other readers; create per query, not per process (a long-held view
    /// pins the engine's MVCC snapshot).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`] from the engine.
    pub fn read(&self) -> Result<ReadView, DatabaseError> {
        Ok(ReadView {
            txn: self.engine.begin_read()?,
        })
    }

    /// Runs `f` inside one write transaction: **commit on `Ok`, discard on
    /// `Err`**. Everything staged in the closure lands atomically or not at
    /// all. `E` lets domain errors flow through unchanged.
    ///
    /// Never perform network calls in `f` (it is sync by design — the writer
    /// lock is held throughout); for validate-then-commit flows, stage a
    /// [`WriteBatch`] and [`apply`](Self::apply) it after validation.
    ///
    /// # Errors
    /// `f`'s error on failure, or the engine's commit error.
    pub fn write<T, E>(&self, f: impl FnOnce(&mut WriteTxn<'_>) -> Result<T, E>) -> Result<T, E>
    where
        E: From<DatabaseError>,
    {
        let span = tracing::info_span!("db.write");
        let _guard = span.enter();
        let started = Instant::now();

        let mut txn = WriteTxn::new(self.engine.begin_write()?);
        match f(&mut txn) {
            Ok(value) => {
                let (puts, deletes, touched) = (txn.puts, txn.deletes, txn.touched.clone());
                txn.inner.commit().map_err(E::from)?;
                tracing::debug!(
                    duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    puts,
                    deletes,
                    tables = ?touched,
                    "committed"
                );
                Ok(value)
            }
            Err(error) => {
                // Dropping the transaction is the rollback.
                tracing::warn!(
                    duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    puts = txn.puts,
                    deletes = txn.deletes,
                    "write transaction discarded"
                );
                Err(error)
            }
        }
    }

    /// Applies a validated [`WriteBatch`] in one fast transaction.
    ///
    /// Takes the batch by value on purpose: applying *spends* it, so a
    /// double-apply cannot compile.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    #[allow(clippy::needless_pass_by_value)]
    pub fn apply(&self, batch: WriteBatch) -> Result<(), DatabaseError> {
        let entries = batch.len();
        self.write(|txn| {
            for (table, kvs) in &batch.entries {
                for (key, value) in kvs {
                    match value {
                        Some(value) => txn.put(*table, key, value)?,
                        None => txn.delete(*table, key)?,
                    }
                }
            }
            Ok::<_, DatabaseError>(())
        })?;
        tracing::debug!(entries, "batch applied");
        Ok(())
    }

    /// Wipes every registered table, leaving an empty (re-stamped) database.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn clear_all(&self) -> Result<(), DatabaseError> {
        self.write(|txn| {
            for &table in tables::ALL_TABLES {
                txn.clear_table(table)?;
            }
            // The wipe took the version stamps with it; re-stamp in the same txn.
            version::check_and_stamp(txn)
        })
    }

    /// Materializes all registered tables and checks/stamps versions.
    fn initialize(&self) -> Result<(), DatabaseError> {
        self.write(|txn| {
            for &table in tables::ALL_TABLES {
                txn.inner.materialize(table)?;
            }
            version::check_and_stamp(txn)
        })
    }
}

#[cfg(test)]
mod tests {
    use types::{
        AssetId, BlockNumber, CommitmentHash, EvmAddress, Node, NodeBody, NodePosition, Nullified,
        Nullifier, ShieldBody, U256, ViewingPublicKey,
    };

    use super::*;

    fn shield_node(tree: u32, leaf: u32) -> Node {
        Node {
            position: NodePosition::try_new(tree, leaf).unwrap(),
            hash: CommitmentHash::new(U256::from(u64::from(leaf) + 1)),
            block: BlockNumber::new(1),
            body: NodeBody::Shield(ShieldBody {
                npk: U256::from(7u64),
                token: AssetId::erc20(EvmAddress::from([0x11; 20])),
                value: U256::from(1000u64),
                encrypted_bundle: vec![[0u8; 32]],
                shield_key: ViewingPublicKey::from_bytes([4u8; 32]),
            }),
        }
    }

    #[test]
    fn nodes_round_trip_and_counters_track() {
        let db = Database::in_memory();
        db.write(|txn| {
            let mut commitments = txn.commitments();
            commitments.insert_node(&shield_node(0, 0))?;
            commitments.insert_node(&shield_node(0, 1))?;
            commitments.insert_node(&shield_node(1, 0))?;
            commitments.set_synced_block(BlockNumber::new(100))?;
            Ok::<_, DatabaseError>(())
        })
        .unwrap();

        let view = db.read().unwrap();
        let commitments = view.commitments();
        assert_eq!(commitments.tree_count().unwrap(), 2);
        assert_eq!(commitments.tree_length(0).unwrap(), 2);
        assert_eq!(commitments.tree_length(1).unwrap(), 1);
        assert!(commitments.node(0, 1).unwrap().is_some());
        assert!(commitments.node(0, 2).unwrap().is_none());
        assert_eq!(
            commitments.synced_block().unwrap(),
            Some(BlockNumber::new(100))
        );
        assert!(commitments.is_synced().unwrap());
    }

    #[test]
    fn leaf_hashes_scan_yields_positions_in_order() {
        let db = Database::in_memory();
        db.write(|txn| {
            let mut commitments = txn.commitments();
            // Positions 0, 1, 3 — an interior gap at 2.
            for leaf in [0u32, 1, 3] {
                commitments.insert_node(&shield_node(0, leaf))?;
            }
            Ok::<_, DatabaseError>(())
        })
        .unwrap();

        let view = db.read().unwrap();
        let scanned: Vec<(u32, U256)> = view
            .commitments()
            .leaf_hashes(0)
            .unwrap()
            .map(|entry| entry.map(|(pos, hash)| (pos, hash.as_u256())))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            scanned,
            vec![
                (0, U256::from(1u8)),
                (1, U256::from(2u8)),
                (3, U256::from(4u8)),
            ]
        );
    }

    #[test]
    fn failed_write_closure_discards_everything() {
        let db = Database::in_memory();
        let result: Result<(), DatabaseError> = db.write(|txn| {
            txn.commitments().insert_node(&shield_node(0, 0))?;
            txn.frontier().set_snapshot(0, b"snapshot")?;
            txn.decoded().save(&[])?;
            Err(DatabaseError::Engine("domain failure".to_owned()))
        });
        assert!(result.is_err());

        let view = db.read().unwrap();
        assert_eq!(view.commitments().tree_count().unwrap(), 0);
        assert!(view.commitments().node(0, 0).unwrap().is_none());
        assert!(view.frontier().snapshot(0).unwrap().is_none());
    }

    #[test]
    fn nullifiers_resolve_per_tree() {
        let db = Database::in_memory();
        let nullifier = Nullifier::new(types::B256::from(U256::from(9u8).to_be_bytes::<32>()));
        db.write(|txn| {
            txn.commitments().insert_nullifier(Nullified {
                tree_number: 1,
                nullifier,
            })?;
            Ok::<_, DatabaseError>(())
        })
        .unwrap();

        let view = db.read().unwrap();
        assert!(view.commitments().is_nullified(1, nullifier).unwrap());
        assert!(!view.commitments().is_nullified(0, nullifier).unwrap());
    }

    #[test]
    fn overlay_reads_batch_over_base_and_apply_lands_it() {
        let db = Database::in_memory();
        db.write(|txn| {
            txn.commitments().insert_node(&shield_node(0, 0))?;
            Ok::<_, DatabaseError>(())
        })
        .unwrap();

        let view = db.read().unwrap();
        let mut batch = WriteBatch::new();
        let mut overlay = batch.overlay(&view);
        overlay
            .commitments()
            .insert_node(&shield_node(0, 1))
            .unwrap();

        // Overlay sees base + batch as one world.
        let merged = overlay.commitments_view();
        assert_eq!(merged.tree_length(0).unwrap(), 2);
        assert!(merged.node(0, 0).unwrap().is_some()); // from base
        assert!(merged.node(0, 1).unwrap().is_some()); // from batch
        let positions: Vec<u32> = merged
            .leaf_hashes(0)
            .unwrap()
            .map(|entry| entry.map(|(pos, _)| pos))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(positions, vec![0, 1]);

        // Nothing durable yet; the pre-apply snapshot never sees the batch.
        assert_eq!(db.read().unwrap().commitments().tree_length(0).unwrap(), 1);
        db.apply(batch).unwrap();
        assert_eq!(db.read().unwrap().commitments().tree_length(0).unwrap(), 2);
        assert_eq!(view.commitments().tree_length(0).unwrap(), 1);
    }

    #[test]
    fn overlay_tombstones_hide_base_entries() {
        let db = Database::in_memory();
        db.write(|txn| {
            txn.frontier().set_snapshot(0, b"old")?;
            Ok::<_, DatabaseError>(())
        })
        .unwrap();

        let view = db.read().unwrap();
        let mut batch = WriteBatch::new();
        let mut overlay = batch.overlay(&view);
        overlay.frontier().clear_snapshot(0).unwrap();
        assert!(overlay.frontier_snapshot_is_none());

        db.apply(batch).unwrap();
        assert!(db.read().unwrap().frontier().snapshot(0).unwrap().is_none());
    }

    #[test]
    fn dropped_batch_is_a_discard() {
        let db = Database::in_memory();
        let view = db.read().unwrap();
        let mut batch = WriteBatch::new();
        batch
            .overlay(&view)
            .commitments()
            .insert_node(&shield_node(0, 0))
            .unwrap();
        drop(batch);
        assert_eq!(db.read().unwrap().commitments().tree_count().unwrap(), 0);
    }

    #[test]
    fn clear_all_wipes_and_restamps() {
        let db = Database::in_memory();
        db.write(|txn| {
            txn.commitments().insert_node(&shield_node(0, 0))?;
            txn.commitments().set_synced_block(BlockNumber::new(5))?;
            Ok::<_, DatabaseError>(())
        })
        .unwrap();

        db.clear_all().unwrap();

        let view = db.read().unwrap();
        assert!(!view.commitments().is_synced().unwrap());
        assert_eq!(view.commitments().tree_count().unwrap(), 0);
        // Re-stamped, not left bare.
        assert_eq!(view.schema_version(tables::COMMITMENTS).unwrap(), Some(1));

        // Immediately reusable.
        db.write(|txn| {
            txn.commitments().insert_node(&shield_node(0, 0))?;
            Ok::<_, DatabaseError>(())
        })
        .unwrap();
        assert_eq!(db.read().unwrap().commitments().tree_count().unwrap(), 1);
    }

    #[test]
    fn persists_across_reopen_and_stamps_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        {
            let db = Database::open(&path).unwrap();
            db.write(|txn| {
                txn.commitments().insert_node(&shield_node(0, 0))?;
                Ok::<_, DatabaseError>(())
            })
            .unwrap();
        } // dropped, closing the file

        let db = Database::open(&path).unwrap();
        let view = db.read().unwrap();
        assert!(view.commitments().node(0, 0).unwrap().is_some());
        assert_eq!(view.schema_version(tables::COMMITMENTS).unwrap(), Some(1));
        assert_eq!(view.schema_version(tables::META).unwrap(), Some(1));
    }

    #[test]
    fn mismatched_version_stamp_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        {
            let db = Database::open(&path).unwrap();
            // Poke a bogus future version straight into meta.
            db.write(|txn| {
                txn.put(tables::META, b"vcommitments", &99u32.to_be_bytes())?;
                Ok::<_, DatabaseError>(())
            })
            .unwrap();
        }

        let error = Database::open(&path).unwrap_err();
        assert!(matches!(
            error,
            DatabaseError::SchemaVersion {
                table: "commitments",
                found: 99,
                expected: 1
            }
        ));
    }

    impl Overlay<'_> {
        /// Test helper: whether the frontier snapshot for tree 0 reads as absent.
        fn frontier_snapshot_is_none(&self) -> bool {
            self.get(tables::FRONTIER, &0u32.to_be_bytes())
                .unwrap()
                .is_none()
        }
    }
}
