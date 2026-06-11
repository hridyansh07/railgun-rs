//! The write side: [`Writer`] (the staged-mutation seam) and [`WriteTxn`]
//! (one engine write transaction, the durability boundary).

use crate::DatabaseError;
use crate::engine::WriteTxnInner;
use crate::read::{RangeInner, RangeIter, Reader};
use crate::tables::{
    TableId, commitments::CommitmentsMut, decoded::DecodedMut, frontier::FrontierMut,
};

/// A staged-mutation sink. Implemented by [`WriteTxn`] (writes land in the
/// engine transaction) and [`Overlay`](crate::Overlay) (writes land in a
/// [`WriteBatch`](crate::WriteBatch)). Typed mutator namespaces are written
/// once, generic over `Reader + Writer`.
pub trait Writer {
    /// Stages a put.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`] from the engine.
    fn put(&mut self, table: TableId, key: &[u8], value: &[u8]) -> Result<(), DatabaseError>;

    /// Stages a delete.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`] from the engine.
    fn delete(&mut self, table: TableId, key: &[u8]) -> Result<(), DatabaseError>;
}

/// One write transaction over the whole database — the **only** durability
/// boundary. Created by [`Database::write`](crate::Database::write), which
/// commits on `Ok` and discards on `Err`; cross-table atomicity is the point.
///
/// Reads through a `WriteTxn` see its own staged writes. Mutation counters
/// feed the commit-time tracing event — the single metrics choke point.
pub struct WriteTxn<'db> {
    pub(crate) inner: WriteTxnInner<'db>,
    pub(crate) puts: u64,
    pub(crate) deletes: u64,
    // alloc-ok: at most one entry per registered table.
    pub(crate) touched: std::collections::BTreeSet<&'static str>,
}

impl<'db> WriteTxn<'db> {
    pub(crate) fn new(inner: WriteTxnInner<'db>) -> Self {
        WriteTxn {
            inner,
            puts: 0,
            deletes: 0,
            touched: std::collections::BTreeSet::new(),
        }
    }

    /// The UTXO merkle forest mutators.
    pub fn commitments(&mut self) -> CommitmentsMut<'_, Self> {
        CommitmentsMut::new(self)
    }

    /// The decoded-notes mutators.
    pub fn decoded(&mut self) -> DecodedMut<'_, Self> {
        DecodedMut::new(self)
    }

    /// The frontier-snapshot mutators.
    pub fn frontier(&mut self) -> FrontierMut<'_, Self> {
        FrontierMut::new(self)
    }

    /// Drops and recreates `table`, leaving it empty.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn clear_table(&mut self, table: TableId) -> Result<(), DatabaseError> {
        self.touched.insert(table.name());
        self.inner.clear_table(table)
    }
}

impl Reader for WriteTxn<'_> {
    fn get(&self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        self.inner.get(table, key)
    }

    fn range(&self, table: TableId, start: &[u8], end: &[u8]) -> Result<RangeIter, DatabaseError> {
        // Write-side engine iterators borrow the transaction, so in-txn scans
        // are collected eagerly; they are rare and bounded (frontier rebuilds).
        Ok(RangeIter(RangeInner::Collected(
            self.inner.range(table, start, end)?.into_iter(),
        )))
    }
}

impl Writer for WriteTxn<'_> {
    fn put(&mut self, table: TableId, key: &[u8], value: &[u8]) -> Result<(), DatabaseError> {
        self.puts += 1;
        self.touched.insert(table.name());
        self.inner.put(table, key, value)
    }

    fn delete(&mut self, table: TableId, key: &[u8]) -> Result<(), DatabaseError> {
        self.deletes += 1;
        self.touched.insert(table.name());
        self.inner.delete(table, key)
    }
}
