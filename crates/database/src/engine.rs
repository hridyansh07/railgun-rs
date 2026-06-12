//! The redb adapter behind [`Database`](crate::Database) — the one module
//! that touches `redb` types. Everything above it works with these wrappers,
//! so a second engine, if one is ever needed, would reintroduce dispatch here
//! designed around that backend's real semantics.
//!
//! redb borrow facts this design is built on (redb 2.x):
//! - `ReadTransaction::open_table` returns an **owned, `'static`**
//!   `ReadOnlyTable` (it holds the transaction guard via `Arc`), and
//!   `ReadOnlyTable::range` returns an owned `'static` iterator — so read
//!   views and long-lived range scans need no self-referential structs.
//! - Write-side `Table<'txn>` **borrows** the `WriteTransaction`, and
//!   `commit()` takes `self` — so [`WriteTxnInner`] opens tables per
//!   operation and never caches handles.

use std::ops::Bound;
use std::path::Path;

use redb::{ReadableTable, TableDefinition};

use crate::DatabaseError;
use crate::tables::TableId;

fn definition(table: TableId) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
    TableDefinition::new(table.name())
}

fn engine_error<E: std::fmt::Display>(error: E) -> DatabaseError {
    DatabaseError::Engine(error.to_string())
}

pub(crate) struct Engine(redb::Database);

impl Engine {
    pub(crate) fn open(path: &Path) -> Result<Self, DatabaseError> {
        Ok(Engine(redb::Database::create(path).map_err(engine_error)?))
    }

    pub(crate) fn begin_read(&self) -> Result<ReadTxnInner, DatabaseError> {
        Ok(ReadTxnInner(self.0.begin_read().map_err(engine_error)?))
    }

    pub(crate) fn begin_write(&self) -> Result<WriteTxnInner, DatabaseError> {
        Ok(WriteTxnInner(self.0.begin_write().map_err(engine_error)?))
    }
}

// ---- read side -----------------------------------------------------------------

pub(crate) struct ReadTxnInner(redb::ReadTransaction);

impl ReadTxnInner {
    pub(crate) fn get(&self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        let table = self.0.open_table(definition(table)).map_err(engine_error)?;
        // alloc-ok: owned copy at the persistence boundary.
        Ok(table
            .get(key)
            .map_err(engine_error)?
            .map(|guard| guard.value().to_vec()))
    }

    /// An ordered scan over `start..=end` (both inclusive).
    pub(crate) fn range(
        &self,
        table: TableId,
        start: &[u8],
        end: &[u8],
    ) -> Result<RawRange, DatabaseError> {
        let table = self.0.open_table(definition(table)).map_err(engine_error)?;
        // `ReadOnlyTable::range` yields an owned `'static` iterator —
        // the table handle itself can drop here.
        let range = table
            .range::<&[u8]>((Bound::Included(start), Bound::Included(end)))
            .map_err(engine_error)?;
        Ok(RawRange(range))
    }
}

/// An owned, ordered `(key, value)` scan over one table.
pub(crate) struct RawRange(redb::Range<'static, &'static [u8], &'static [u8]>);

impl Iterator for RawRange {
    type Item = Result<(Vec<u8>, Vec<u8>), DatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|entry| {
            entry
                .map(|(key, value)| {
                    // alloc-ok: owned copies at the persistence boundary.
                    (key.value().to_vec(), value.value().to_vec())
                })
                .map_err(engine_error)
        })
    }
}

// ---- write side ----------------------------------------------------------------

/// An ordered scan result from a write transaction (collected eagerly).
pub(crate) type ScannedEntries = Vec<(Vec<u8>, Vec<u8>)>;

pub(crate) struct WriteTxnInner(redb::WriteTransaction);

impl WriteTxnInner {
    /// Point read that sees this transaction's own staged writes.
    pub(crate) fn get(&self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        let table = self.0.open_table(definition(table)).map_err(engine_error)?;
        // alloc-ok: owned copy at the persistence boundary.
        Ok(table
            .get(key)
            .map_err(engine_error)?
            .map(|guard| guard.value().to_vec()))
    }

    /// Ordered scan (`start..=end`) seeing this transaction's staged writes.
    /// Collected eagerly — write-side redb iterators borrow the transaction,
    /// and in-transaction scans are rare and bounded (frontier rebuilds).
    pub(crate) fn range(
        &self,
        table: TableId,
        start: &[u8],
        end: &[u8],
    ) -> Result<ScannedEntries, DatabaseError> {
        let table = self.0.open_table(definition(table)).map_err(engine_error)?;
        let mut out = Vec::new(); // alloc-ok: bounded in-transaction scan.
        for entry in table
            .range::<&[u8]>((Bound::Included(start), Bound::Included(end)))
            .map_err(engine_error)?
        {
            let (key, value) = entry.map_err(engine_error)?;
            out.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(out)
    }

    pub(crate) fn put(
        &mut self,
        table: TableId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), DatabaseError> {
        let mut table = self.0.open_table(definition(table)).map_err(engine_error)?;
        table.insert(key, value).map_err(engine_error)?;
        Ok(())
    }

    pub(crate) fn delete(&mut self, table: TableId, key: &[u8]) -> Result<(), DatabaseError> {
        let mut table = self.0.open_table(definition(table)).map_err(engine_error)?;
        table.remove(key).map_err(engine_error)?;
        Ok(())
    }

    /// Drops and recreates `table`, leaving it empty.
    pub(crate) fn clear_table(&mut self, table: TableId) -> Result<(), DatabaseError> {
        self.0
            .delete_table(definition(table))
            .map_err(engine_error)?;
        self.0.open_table(definition(table)).map_err(engine_error)?;
        Ok(())
    }

    /// Materializes `table` so later reads never hit "table does not exist".
    pub(crate) fn materialize(&mut self, table: TableId) -> Result<(), DatabaseError> {
        self.0.open_table(definition(table)).map_err(engine_error)?;
        Ok(())
    }

    pub(crate) fn commit(self) -> Result<(), DatabaseError> {
        self.0.commit().map_err(engine_error)
    }
}
