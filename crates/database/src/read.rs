//! The read side: [`Reader`] (the point-read + range-scan seam) and
//! [`ReadView`] (an MVCC snapshot of the whole database).

use crate::DatabaseError;
use crate::engine::{RawRange, ReadTxnInner};
use crate::tables::{TableId, commitments::Commitments, decoded::Decoded, frontier::Frontier};

/// A point-read + ordered-range source over the database's tables.
///
/// Implemented by [`ReadView`] (snapshot), [`WriteTxn`](crate::WriteTxn)
/// (read-your-writes), and [`Overlay`](crate::Overlay) (batch-over-snapshot).
/// Typed table namespaces are written once, generic over this — as is
/// higher-level logic like the merkle walk in `crypto`.
pub trait Reader {
    /// The value at `key` in `table`, if any.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`] from the engine.
    fn get(&self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError>;

    /// Ordered `(key, value)` scan over `start..=end` (both inclusive).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`] from the engine.
    fn range(&self, table: TableId, start: &[u8], end: &[u8]) -> Result<RangeIter, DatabaseError>;
}

/// An owned, ordered `(key, value)` iterator from a [`Reader::range`] scan.
pub struct RangeIter(pub(crate) RangeInner);

pub(crate) enum RangeInner {
    /// Streaming engine scan (one open transaction for the whole walk).
    Raw(RawRange),
    /// Eagerly collected (write transactions; bounded in-txn scans).
    Collected(std::vec::IntoIter<(Vec<u8>, Vec<u8>)>),
    /// Merge of a batch overlay over a base scan; overlay wins on key
    /// collision, `None` overlay entries (tombstones) suppress base keys.
    Merged {
        base: Box<RangeIter>,
        // alloc-ok: the overlay's staged entries for one scan window.
        overlay: std::vec::IntoIter<(Vec<u8>, Option<Vec<u8>>)>,
        base_peek: Option<(Vec<u8>, Vec<u8>)>,
        overlay_peek: Option<(Vec<u8>, Option<Vec<u8>>)>,
    },
}

impl Iterator for RangeIter {
    type Item = Result<(Vec<u8>, Vec<u8>), DatabaseError>;

    // The merge loop's explicit `continue`s mark tombstone-skips; `{}` arms
    // would hide the control flow they document.
    #[allow(clippy::needless_continue)]
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            RangeInner::Raw(range) => range.next(),
            RangeInner::Collected(iter) => iter.next().map(Ok),
            RangeInner::Merged {
                base,
                overlay,
                base_peek,
                overlay_peek,
            } => loop {
                if base_peek.is_none() {
                    match base.next() {
                        Some(Ok(entry)) => *base_peek = Some(entry),
                        Some(Err(error)) => return Some(Err(error)),
                        None => {}
                    }
                }
                if overlay_peek.is_none() {
                    *overlay_peek = overlay.next();
                }

                match (base_peek.as_ref(), overlay_peek.as_ref()) {
                    (None, None) => return None,
                    // Only base left.
                    (Some(_), None) => return base_peek.take().map(Ok),
                    // Only overlay left: skip tombstones.
                    (None, Some(_)) => {
                        let (key, value) = overlay_peek.take().expect("peeked");
                        match value {
                            Some(value) => return Some(Ok((key, value))),
                            None => continue,
                        }
                    }
                    (Some((base_key, _)), Some((overlay_key, _))) => {
                        match base_key.cmp(overlay_key) {
                            std::cmp::Ordering::Less => return base_peek.take().map(Ok),
                            std::cmp::Ordering::Equal => {
                                // Overlay wins; consume both.
                                *base_peek = None;
                                let (key, value) = overlay_peek.take().expect("peeked");
                                match value {
                                    Some(value) => return Some(Ok((key, value))),
                                    None => continue, // tombstone hides the base entry
                                }
                            }
                            std::cmp::Ordering::Greater => {
                                let (key, value) = overlay_peek.take().expect("peeked");
                                match value {
                                    Some(value) => return Some(Ok((key, value))),
                                    None => continue,
                                }
                            }
                        }
                    }
                }
            },
        }
    }
}

/// A consistent MVCC snapshot of every table. Cheap to create, any number may
/// exist concurrently, and writers are never blocked by one.
///
/// Holding a view for a long time pins the engine's snapshot (redb defers
/// page reclamation, it does not block writers) — create views per query, not
/// per process.
pub struct ReadView {
    pub(crate) txn: ReadTxnInner,
}

impl Reader for ReadView {
    fn get(&self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        self.txn.get(table, key)
    }

    fn range(&self, table: TableId, start: &[u8], end: &[u8]) -> Result<RangeIter, DatabaseError> {
        Ok(RangeIter(RangeInner::Raw(
            self.txn.range(table, start, end)?,
        )))
    }
}

impl ReadView {
    /// The UTXO merkle forest namespace.
    #[must_use]
    pub fn commitments(&self) -> Commitments<'_, Self> {
        Commitments::new(self)
    }

    /// The decoded-notes namespace.
    #[must_use]
    pub fn decoded(&self) -> Decoded<'_, Self> {
        Decoded::new(self)
    }

    /// The frontier-snapshot namespace.
    #[must_use]
    pub fn frontier(&self) -> Frontier<'_, Self> {
        Frontier::new(self)
    }

    /// The schema version stamped for `table` (`None` = pre-stamp data, v1).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn schema_version(&self, table: TableId) -> Result<Option<u32>, DatabaseError> {
        crate::version::read_version(self, table)
    }
}
