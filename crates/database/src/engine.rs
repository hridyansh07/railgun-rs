//! Storage engines behind [`Database`](crate::Database), enum-dispatched.
//!
//! Two engines: redb (durable, primary) and an in-memory `BTreeMap` engine
//! (tests; the variant a future wasm/IndexedDB engine would join). Enum
//! dispatch — not a public trait — keeps `Database`/`ReadView`/`WriteTxn`
//! concrete types everywhere, so no `B: StorageBackend` generics leak through
//! consumer crates.
//!
//! redb borrow facts this design is built on (redb 2.x):
//! - `ReadTransaction::open_table` returns an **owned, `'static`**
//!   `ReadOnlyTable` (it holds the transaction guard via `Arc`), and
//!   `ReadOnlyTable::range` returns an owned `'static` iterator — so read
//!   views and long-lived range scans need no self-referential structs.
//! - Write-side `Table<'txn>` **borrows** the `WriteTransaction`, and
//!   `commit()` takes `self` — so [`WriteTxnInner`] opens tables per
//!   operation and never caches handles.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use redb::{ReadableTable, TableDefinition};

use crate::DatabaseError;
use crate::tables::TableId;

/// One logical table's contents in the memory engine.
type MemTable = BTreeMap<Vec<u8>, Vec<u8>>;
/// The memory engine's whole world, keyed by table name.
type MemTables = HashMap<&'static str, MemTable>;

fn definition(table: TableId) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
    TableDefinition::new(table.name())
}

fn engine_error<E: std::fmt::Display>(error: E) -> DatabaseError {
    DatabaseError::Engine(error.to_string())
}

pub(crate) enum Engine {
    Redb(redb::Database),
    Memory(MemoryEngine),
}

/// In-memory engine: a mutex'd table map. Write transactions clone the world,
/// mutate the clone, and swap it back on commit — drop-without-commit is a
/// rollback, matching redb's semantics. Test-grade by design.
pub(crate) struct MemoryEngine {
    tables: Mutex<MemTables>,
}

impl Engine {
    pub(crate) fn open(path: &Path) -> Result<Self, DatabaseError> {
        Ok(Engine::Redb(
            redb::Database::create(path).map_err(engine_error)?,
        ))
    }

    pub(crate) fn in_memory() -> Self {
        Engine::Memory(MemoryEngine {
            tables: Mutex::new(MemTables::new()),
        })
    }

    pub(crate) fn begin_read(&self) -> Result<ReadTxnInner, DatabaseError> {
        match self {
            Engine::Redb(db) => Ok(ReadTxnInner::Redb(db.begin_read().map_err(engine_error)?)),
            Engine::Memory(engine) => {
                // alloc-ok: snapshot clone — the memory engine is test-grade.
                let snapshot = engine
                    .tables
                    .lock()
                    .expect("memory engine poisoned")
                    .clone();
                Ok(ReadTxnInner::Memory(snapshot))
            }
        }
    }

    pub(crate) fn begin_write(&self) -> Result<WriteTxnInner<'_>, DatabaseError> {
        match self {
            Engine::Redb(db) => Ok(WriteTxnInner::Redb(db.begin_write().map_err(engine_error)?)),
            Engine::Memory(engine) => {
                // Holding the guard for the transaction's lifetime is the
                // single-writer lock (redb's begin_write blocks the same way).
                let guard = engine.tables.lock().expect("memory engine poisoned");
                // alloc-ok: clone-on-write world copy — test-grade engine.
                let staged = guard.clone();
                Ok(WriteTxnInner::Memory { guard, staged })
            }
        }
    }
}

// ---- read side -----------------------------------------------------------------

pub(crate) enum ReadTxnInner {
    Redb(redb::ReadTransaction),
    Memory(MemTables),
}

impl ReadTxnInner {
    pub(crate) fn get(&self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        match self {
            ReadTxnInner::Redb(txn) => {
                let table = txn.open_table(definition(table)).map_err(engine_error)?;
                // alloc-ok: owned copy at the persistence boundary.
                Ok(table
                    .get(key)
                    .map_err(engine_error)?
                    .map(|guard| guard.value().to_vec()))
            }
            ReadTxnInner::Memory(tables) => Ok(tables
                .get(table.name())
                .and_then(|map| map.get(key))
                // alloc-ok: owned copy at the persistence boundary.
                .cloned()),
        }
    }

    /// An ordered scan over `start..=end` (both inclusive).
    pub(crate) fn range(
        &self,
        table: TableId,
        start: &[u8],
        end: &[u8],
    ) -> Result<RawRange, DatabaseError> {
        match self {
            ReadTxnInner::Redb(txn) => {
                let table = txn.open_table(definition(table)).map_err(engine_error)?;
                // `ReadOnlyTable::range` yields an owned `'static` iterator —
                // the table handle itself can drop here.
                let range = table
                    .range::<&[u8]>((Bound::Included(start), Bound::Included(end)))
                    .map_err(engine_error)?;
                Ok(RawRange::Redb(range))
            }
            ReadTxnInner::Memory(tables) => Ok(RawRange::Memory(
                tables
                    .get(table.name())
                    .map(|map| {
                        map.range::<[u8], _>((Bound::Included(start), Bound::Included(end)))
                            // alloc-ok: snapshot copy — test-grade engine.
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
                    .into_iter(),
            )),
        }
    }
}

/// An owned, ordered `(key, value)` scan over one table.
pub(crate) enum RawRange {
    Redb(redb::Range<'static, &'static [u8], &'static [u8]>),
    Memory(std::vec::IntoIter<(Vec<u8>, Vec<u8>)>),
}

impl Iterator for RawRange {
    type Item = Result<(Vec<u8>, Vec<u8>), DatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RawRange::Redb(range) => range.next().map(|entry| {
                entry
                    .map(|(key, value)| {
                        // alloc-ok: owned copies at the persistence boundary.
                        (key.value().to_vec(), value.value().to_vec())
                    })
                    .map_err(engine_error)
            }),
            RawRange::Memory(iter) => iter.next().map(Ok),
        }
    }
}

// ---- write side ----------------------------------------------------------------

/// An ordered scan result from a write transaction (collected eagerly).
pub(crate) type ScannedEntries = Vec<(Vec<u8>, Vec<u8>)>;

// The variant size gap (boxed-pointer redb txn vs. inline guard + table map)
// is irrelevant: exactly one write transaction exists at a time.
#[allow(clippy::large_enum_variant)]
pub(crate) enum WriteTxnInner<'db> {
    Redb(redb::WriteTransaction),
    Memory {
        guard: MutexGuard<'db, MemTables>,
        staged: MemTables,
    },
}

impl WriteTxnInner<'_> {
    /// Point read that sees this transaction's own staged writes.
    pub(crate) fn get(&self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        match self {
            WriteTxnInner::Redb(txn) => {
                let table = txn.open_table(definition(table)).map_err(engine_error)?;
                // alloc-ok: owned copy at the persistence boundary.
                Ok(table
                    .get(key)
                    .map_err(engine_error)?
                    .map(|guard| guard.value().to_vec()))
            }
            WriteTxnInner::Memory { staged, .. } => Ok(staged
                .get(table.name())
                .and_then(|map| map.get(key))
                // alloc-ok: owned copy at the persistence boundary.
                .cloned()),
        }
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
        match self {
            WriteTxnInner::Redb(txn) => {
                let table = txn.open_table(definition(table)).map_err(engine_error)?;
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
            WriteTxnInner::Memory { staged, .. } => Ok(staged
                .get(table.name())
                .map(|map| {
                    map.range::<[u8], _>((Bound::Included(start), Bound::Included(end)))
                        // alloc-ok: snapshot copy — test-grade engine.
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default()),
        }
    }

    pub(crate) fn put(
        &mut self,
        table: TableId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), DatabaseError> {
        match self {
            WriteTxnInner::Redb(txn) => {
                let mut table = txn.open_table(definition(table)).map_err(engine_error)?;
                table.insert(key, value).map_err(engine_error)?;
                Ok(())
            }
            WriteTxnInner::Memory { staged, .. } => {
                staged
                    .entry(table.name())
                    .or_default()
                    .insert(key.to_vec(), value.to_vec());
                Ok(())
            }
        }
    }

    pub(crate) fn delete(&mut self, table: TableId, key: &[u8]) -> Result<(), DatabaseError> {
        match self {
            WriteTxnInner::Redb(txn) => {
                let mut table = txn.open_table(definition(table)).map_err(engine_error)?;
                table.remove(key).map_err(engine_error)?;
                Ok(())
            }
            WriteTxnInner::Memory { staged, .. } => {
                if let Some(map) = staged.get_mut(table.name()) {
                    map.remove(key);
                }
                Ok(())
            }
        }
    }

    /// Drops and recreates `table`, leaving it empty.
    pub(crate) fn clear_table(&mut self, table: TableId) -> Result<(), DatabaseError> {
        match self {
            WriteTxnInner::Redb(txn) => {
                txn.delete_table(definition(table)).map_err(engine_error)?;
                txn.open_table(definition(table)).map_err(engine_error)?;
                Ok(())
            }
            WriteTxnInner::Memory { staged, .. } => {
                staged.insert(table.name(), MemTable::new());
                Ok(())
            }
        }
    }

    /// Materializes `table` so later reads never hit "table does not exist".
    pub(crate) fn materialize(&mut self, table: TableId) -> Result<(), DatabaseError> {
        match self {
            WriteTxnInner::Redb(txn) => {
                txn.open_table(definition(table)).map_err(engine_error)?;
                Ok(())
            }
            WriteTxnInner::Memory { staged, .. } => {
                staged.entry(table.name()).or_default();
                Ok(())
            }
        }
    }

    pub(crate) fn commit(self) -> Result<(), DatabaseError> {
        match self {
            WriteTxnInner::Redb(txn) => txn.commit().map_err(engine_error),
            WriteTxnInner::Memory { mut guard, staged } => {
                *guard = staged;
                Ok(())
            }
        }
    }
}
