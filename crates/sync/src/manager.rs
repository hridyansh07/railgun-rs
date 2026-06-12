//! [`Syncer`] — a stateless pump from an [`EventSource`] into the [`Database`].

use std::collections::BTreeMap;

use crypto::{
    MerkleAccumulator, MerkleAccumulatorState, MerkleConfig, RailgunMerkleConfig, tree_frontier,
};
use database::{Database, DatabaseError, Frontier, WriteTxn};
use types::{BlockNumber, Node, Nullified};

use crate::pump::pump_windows;
use crate::{EventSource, EventStream, SyncError, SyncEvent};

/// Default block span committed per checkpoint. Bounds peak memory (one window's
/// events) and the re-fetch interval on crash; also the watermark granularity.
// Need to check and update what kind of memory does this require before writing to a file
const DEFAULT_BLOCK_WINDOW: u64 = 100_000;

/// Outcome of a sync run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncSummary {
    pub commitments: u64,
    pub nullifiers: u64,
    pub synced_to: BlockNumber,
}

/// Drives an [`EventSource`] into the [`Database`], one block-window at a time.
///
/// Holds no durable state: it reads the resume point from the database, fetches
/// the next batch, and commits it in **one write transaction per window** —
/// commitments, nullifiers, the folded frontier snapshots, and the watermark
/// land atomically or not at all. The database is the single source of truth —
/// a syncer is just a pump, triggered on demand or by a scheduler.
///
/// Writes serialize on the database's writer lock; overlapping runs against one
/// database are a usage error.
pub struct Syncer<S> {
    source: S,
    floor: BlockNumber,
    block_window: u64,
}

impl<S: EventSource> Syncer<S> {
    /// Creates a syncer over `source`, syncing no earlier than `floor` (typically the
    /// chain's contract deployment block).
    #[must_use]
    pub fn new(source: S, floor: BlockNumber) -> Self {
        Self {
            source,
            floor,
            block_window: DEFAULT_BLOCK_WINDOW,
        }
    }

    /// Sets the per-checkpoint block window.
    ///
    /// # Panics
    /// Panics if `block_window` is zero.
    pub fn set_block_window(&mut self, block_window: u64) {
        assert!(block_window > 0, "block_window must be non-zero");
        self.block_window = block_window;
    }

    /// Syncs `db` up to the source's latest block.
    ///
    /// # Errors
    /// Propagates [`SyncError`].
    pub async fn run_to_head(&self, db: &Database) -> Result<SyncSummary, SyncError> {
        let target = self.source.latest_block().await?;
        self.run(db, target).await
    }

    /// Syncs `db` to the source's head **only if it has never been synced**.
    ///
    /// If the database already carries a watermark, returns immediately with a
    /// zero-delta summary and **without any network call** —
    /// the hatch for reusing a populated database (e.g. a committed fixture) offline.
    /// To force a re-sync, [`clear_all`](Database::clear_all) first.
    ///
    /// # Errors
    /// Propagates [`SyncError`].
    pub async fn run_to_head_if_unsynced(&self, db: &Database) -> Result<SyncSummary, SyncError> {
        let view = db.read()?;
        if view.commitments().is_synced()? {
            return Ok(SyncSummary {
                synced_to: view.commitments().synced_block()?.unwrap_or_default(),
                ..SyncSummary::default()
            });
        }
        drop(view);
        self.run_to_head(db).await
    }

    /// Syncs `db` from its watermark (or `floor` if never synced) up to `target`,
    /// committing one block-window at a time.
    ///
    /// # Errors
    /// Propagates [`SyncError`].
    pub async fn run(&self, db: &Database, target: BlockNumber) -> Result<SyncSummary, SyncError> {
        let watermark = db.read()?.commitments().synced_block()?;
        let from = watermark.map_or(self.floor, |block| block.saturating_add(1));

        let mut summary = SyncSummary {
            synced_to: watermark.unwrap_or_default(),
            ..SyncSummary::default()
        };

        pump_windows(from, target, self.block_window, async |from, end| {
            // alloc-ok: one window's events, the deliberate per-checkpoint memory
            // ceiling (HTTP responses stay page-sized underneath).
            let mut commitments = Vec::new();
            let mut nullifiers = Vec::new();

            for stream in [EventStream::Commitments, EventStream::Nullifiers] {
                let mut cursor = None;
                loop {
                    let page = self.source.fetch_page(stream, from, end, cursor).await?;
                    for event in page.events {
                        match event {
                            SyncEvent::Commitment(node) => commitments.push(node),
                            SyncEvent::Nullified(nullified) => nullifiers.push(nullified),
                        }
                    }
                    match page.cursor {
                        Some(next) => cursor = Some(next),
                        None => break,
                    }
                }
            }

            summary.commitments += commitments.len() as u64;
            summary.nullifiers += nullifiers.len() as u64;
            commit_window(db, &commitments, &nullifiers, end)?;
            summary.synced_to = end;
            Ok::<_, SyncError>(())
        })
        .await?;

        Ok(summary)
    }
}

/// Commits one window in **one write transaction**: the commitments and
/// nullifiers, the per-tree frontier snapshots advanced over the new leaves,
/// and the watermark — atomically, so durable state never has the watermark
/// (or a frontier) ahead of or behind its data.
fn commit_window(
    db: &Database,
    commitments: &[Node],
    nullifiers: &[Nullified],
    through: BlockNumber,
) -> Result<(), SyncError> {
    db.write(|txn| {
        for node in commitments {
            txn.commitments().insert_node(node)?;
        }
        for nullified in nullifiers {
            txn.commitments().insert_nullifier(*nullified)?;
        }
        advance_frontiers(txn, commitments)?;
        txn.commitments().set_synced_block(through)?;
        Ok::<_, SyncError>(())
    })
}

/// Advances each touched tree's frontier snapshot over this window's new
/// leaves (O(depth) hashes per leaf — the appended leaf's root path).
///
/// Leaves normally arrive append-only, so the persisted accumulator just
/// extends (zero-filling any interior gap, mirroring the full walk's
/// semantics). A leaf landing **below** the frontier (a backfilled gap)
/// invalidates the incremental state — that tree is rebuilt from a full
/// in-transaction scan instead, so the snapshot is never silently wrong.
fn advance_frontiers(txn: &mut WriteTxn, commitments: &[Node]) -> Result<(), SyncError> {
    // Group the window's leaf hashes by tree, ordered by position.
    // alloc-ok: one window's leaves, regrouped.
    let mut by_tree: BTreeMap<u32, BTreeMap<u32, types::U256>> = BTreeMap::new();
    for node in commitments {
        by_tree
            .entry(node.position.tree_number())
            .or_default()
            .insert(node.position.leaf_index(), node.hash.as_u256());
    }

    for (tree, leaves) in by_tree {
        let mut accumulator = match Frontier::new(&*txn).snapshot(tree)? {
            Some(bytes) => {
                let state: MerkleAccumulatorState = serde_json::from_slice(&bytes)
                    .map_err(|error| DatabaseError::Serde(error.to_string()))?;
                MerkleAccumulator::<RailgunMerkleConfig>::from_state(state)?
            }
            None => MerkleAccumulator::new(),
        };

        let backfill = leaves
            .keys()
            .next()
            .is_some_and(|first| u64::from(*first) < accumulator.len());
        if backfill {
            // The nodes are already staged in this transaction, so a full
            // rescan (read-your-writes) sees them.
            tracing::debug!(tree, "backfill below frontier; rebuilding snapshot");
            accumulator = tree_frontier(&*txn, tree)?.0;
        } else {
            for (position, hash) in leaves {
                while accumulator.len() < u64::from(position) {
                    accumulator.insert(RailgunMerkleConfig::zero());
                }
                accumulator.insert(hash);
            }
        }

        let bytes = serde_json::to_vec(&accumulator.state())
            .map_err(|error| DatabaseError::Serde(error.to_string()))?;
        txn.frontier().set_snapshot(tree, &bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{SyncSummary, Syncer};
    use crate::{EventSource, EventStream, Page, SyncError};
    use types::BlockNumber;

    /// An [`EventSource`] that serves empty pages and counts every network call, so a
    /// test can assert whether the source was touched at all.
    #[derive(Default)]
    struct CountingSource {
        latest_calls: AtomicUsize,
        page_calls: AtomicUsize,
        head: u64,
    }

    #[async_trait::async_trait]
    impl EventSource for CountingSource {
        async fn latest_block(&self) -> Result<BlockNumber, SyncError> {
            self.latest_calls.fetch_add(1, Ordering::SeqCst);
            Ok(BlockNumber::new(self.head))
        }

        async fn fetch_page(
            &self,
            _stream: EventStream,
            _from: BlockNumber,
            _to: BlockNumber,
            _cursor: Option<String>,
        ) -> Result<Page, SyncError> {
            self.page_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Page {
                events: Vec::new(),
                cursor: None,
            })
        }
    }

    #[tokio::test]
    async fn run_to_head_if_unsynced_skips_a_populated_store_without_touching_the_source() {
        let source = CountingSource {
            head: 1_000,
            ..CountingSource::default()
        };
        let syncer = Syncer::new(source, BlockNumber::new(0));

        let db = database::test_util::temp();
        // Pre-populate the watermark (an event-free scanned range).
        db.write(|txn| {
            txn.commitments().set_synced_block(BlockNumber::new(42))?;
            Ok::<_, database::DatabaseError>(())
        })
        .unwrap();

        let summary = syncer.run_to_head_if_unsynced(&db).await.unwrap();

        assert_eq!(
            summary,
            SyncSummary {
                synced_to: BlockNumber::new(42),
                ..SyncSummary::default()
            }
        );
        // The whole point: not a single network call.
        assert_eq!(syncer.source.latest_calls.load(Ordering::SeqCst), 0);
        assert_eq!(syncer.source.page_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn run_to_head_if_unsynced_syncs_an_empty_store() {
        let source = CountingSource {
            head: 1_000,
            ..CountingSource::default()
        };
        let syncer = Syncer::new(source, BlockNumber::new(0));

        let db = database::test_util::temp();
        let summary = syncer.run_to_head_if_unsynced(&db).await.unwrap();

        // Reached head, and the source *was* consulted this time.
        assert_eq!(summary.synced_to, BlockNumber::new(1_000));
        assert_eq!(syncer.source.latest_calls.load(Ordering::SeqCst), 1);
        assert!(db.read().unwrap().commitments().is_synced().unwrap());
    }
}
