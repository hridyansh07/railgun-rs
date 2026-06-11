//! [`WriteBatch`] — staged writes that live *outside* any engine transaction —
//! and [`Overlay`], the batch read/written over a base snapshot.
//!
//! This is the validate-between-stage-and-commit primitive: stage a batch,
//! read store+batch as one world through the overlay (e.g. recompute a merkle
//! root), `await` an external validation **holding no engine lock**, then
//! [`Database::apply`](crate::Database::apply) the batch in one fast
//! transaction — or simply drop it, which *is* the discard.

use std::collections::BTreeMap;

use crate::DatabaseError;
use crate::read::{RangeInner, RangeIter, ReadView, Reader};
use crate::tables::{
    TableId, commitments::CommitmentsMut, decoded::DecodedMut, frontier::FrontierMut,
};
use crate::write::Writer;

/// An in-memory, ordered, table-aware batch of staged writes
/// (`None` = delete/tombstone).
#[derive(Debug, Default)]
pub struct WriteBatch {
    // alloc-ok: the staged batch is the deliberate memory ceiling of the
    // stage→validate→apply pattern.
    pub(crate) entries: BTreeMap<TableId, BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
}

impl WriteBatch {
    #[must_use]
    pub fn new() -> Self {
        WriteBatch::default()
    }

    /// Staged entries across all tables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.values().map(BTreeMap::len).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.values().all(BTreeMap::is_empty)
    }

    /// Reads and writes this batch over `base`: gets hit the batch first,
    /// range scans merge batch + base (batch wins, tombstones hide), and
    /// mutations land in the batch.
    pub fn overlay<'a>(&'a mut self, base: &'a ReadView) -> Overlay<'a> {
        Overlay { batch: self, base }
    }
}

/// A [`WriteBatch`] composed over a base [`ReadView`]: one coherent world for
/// both reads and staged writes, with no engine write lock held.
pub struct Overlay<'a> {
    batch: &'a mut WriteBatch,
    base: &'a ReadView,
}

impl Overlay<'_> {
    /// The UTXO merkle forest mutators, staging into the batch.
    pub fn commitments(&mut self) -> CommitmentsMut<'_, Self> {
        CommitmentsMut::new(self)
    }

    /// The decoded-notes mutators, staging into the batch.
    pub fn decoded(&mut self) -> DecodedMut<'_, Self> {
        DecodedMut::new(self)
    }

    /// The frontier-snapshot mutators, staging into the batch.
    pub fn frontier(&mut self) -> FrontierMut<'_, Self> {
        FrontierMut::new(self)
    }

    /// The read-only commitments namespace over store+batch.
    #[must_use]
    pub fn commitments_view(&self) -> crate::tables::commitments::Commitments<'_, Self> {
        crate::tables::commitments::Commitments::new(self)
    }
}

impl Reader for Overlay<'_> {
    fn get(&self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        if let Some(staged) = self.batch.entries.get(&table).and_then(|map| map.get(key)) {
            // alloc-ok: owned copy at the read boundary.
            return Ok(staged.clone());
        }
        self.base.get(table, key)
    }

    fn range(&self, table: TableId, start: &[u8], end: &[u8]) -> Result<RangeIter, DatabaseError> {
        let overlay: Vec<(Vec<u8>, Option<Vec<u8>>)> = self
            .batch
            .entries
            .get(&table)
            .map(|map| {
                map.range::<[u8], _>((
                    std::ops::Bound::Included(start),
                    std::ops::Bound::Included(end),
                ))
                // alloc-ok: the batch's staged entries for one scan window.
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
            })
            .unwrap_or_default();

        Ok(RangeIter(RangeInner::Merged {
            base: Box::new(self.base.range(table, start, end)?),
            overlay: overlay.into_iter(),
            base_peek: None,
            overlay_peek: None,
        }))
    }
}

impl Writer for Overlay<'_> {
    fn put(&mut self, table: TableId, key: &[u8], value: &[u8]) -> Result<(), DatabaseError> {
        self.batch
            .entries
            .entry(table)
            .or_default()
            .insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&mut self, table: TableId, key: &[u8]) -> Result<(), DatabaseError> {
        self.batch
            .entries
            .entry(table)
            .or_default()
            .insert(key.to_vec(), None);
        Ok(())
    }
}
