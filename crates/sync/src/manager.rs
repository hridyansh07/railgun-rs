//! [`Syncer`] — a stateless pump from an [`EventSource`] into a [`CommitmentStore`].

use commitments::CommitmentStore;
use types::BlockNumber;
use utils::StorageBackend;

use crate::{EventSource, EventStream, SyncError, SyncEvent};

/// Default block span committed per checkpoint. Bounds peak memory (one window's
/// events) and the re-fetch interval on crash; also the watermark granularity.
const DEFAULT_BLOCK_WINDOW: u64 = 100_000;

/// Outcome of a sync run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncSummary {
    pub commitments: u64,
    pub nullifiers: u64,
    pub synced_to: BlockNumber,
}

/// Drives an [`EventSource`] into a [`CommitmentStore`], one block-window at a time.
///
/// Holds no durable state: it reads the resume point from the store, fetches the
/// next batch, and asks the store to [`commit`](CommitmentStore::commit) it
/// atomically. The store is the single source of truth — a syncer is just a pump,
/// triggered on demand or by a scheduler.
///
/// The store must have a single writer at a time; overlapping runs against one store
/// are a usage error.
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

    /// Syncs `store` up to the source's latest block.
    ///
    /// # Errors
    /// Propagates [`SyncError`].
    pub async fn run_to_head<B: StorageBackend>(
        &self,
        store: &mut CommitmentStore<B>,
    ) -> Result<SyncSummary, SyncError> {
        let target = self.source.latest_block().await?;
        self.run(store, target).await
    }

    /// Syncs `store` from its watermark (or `floor` if never synced) up to `target`,
    /// committing one block-window at a time.
    ///
    /// # Errors
    /// Propagates [`SyncError`].
    pub async fn run<B: StorageBackend>(
        &self,
        store: &mut CommitmentStore<B>,
        target: BlockNumber,
    ) -> Result<SyncSummary, SyncError> {
        let watermark = store.synced_block()?;
        let mut from = watermark.map_or(self.floor, |block| block.saturating_add(1));

        let mut summary = SyncSummary {
            synced_to: watermark.unwrap_or_default(),
            ..SyncSummary::default()
        };

        while from <= target {
            let end = from.saturating_add(self.block_window - 1).min(target);

            // alloc-ok: one window's events, the deliberate per-checkpoint memory
            // ceiling (HTTP responses stay page-sized underneath).
            let mut commitments = Vec::new();
            let mut nullifiers = Vec::new();

            for stream in [EventStream::Commitments, EventStream::Nullifiers] {
                let mut cursor = None;
                loop {
                    // Keeping this async/await might be avoided if the fetch is made earlier and the value is fetched from memory here?  
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
            store.commit(commitments, nullifiers, end)?;
            summary.synced_to = end;
            from = end.saturating_add(1);
        }

        Ok(summary)
    }
}
