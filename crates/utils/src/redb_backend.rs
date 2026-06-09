//! A durable [`StorageBackend`] backed by [redb](https://docs.rs/redb).
//!
//! redb is synchronous and transactional, so it slots straight into our sync
//! `StorageBackend` trait: each `write_batch` (one per `KeyValueStore` flush)
//! becomes a single atomic commit.
//!
//! One redb file can host several logical stores: open the database once and call
//! [`RedbBackend::table`] for a second backend scoped to a different table (for
//! example a `"commitments"` table and a `"decoded"` table sharing one file). redb
//! allows only one `Database` per file, so the table-scoped backends share it via
//! `Arc`.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, TableDefinition};

use crate::storage::{StorageBackend, StorageError};

/// A redb-backed key-value store scoped to a single named table.
///
/// [`table`](Self::table) returns another backend over the **same** database file
/// under a different table name, sharing the underlying [`Database`].
pub struct RedbBackend {
    db: Arc<Database>,
    table: &'static str,
}

impl RedbBackend {
    /// Opens (creating if absent) a redb database at `path`, scoped to `table`.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if the database cannot be opened or the
    /// table cannot be initialized.
    pub fn open(path: impl AsRef<Path>, table: &'static str) -> Result<Self, StorageError> {
        let db = Arc::new(Database::create(path).map_err(backend_error)?);
        let backend = Self { db, table };
        backend.materialize()?;
        Ok(backend)
    }

    /// Returns another backend over the **same database file**, scoped to `table`.
    ///
    /// Lets several stores (e.g. merkle commitments and decoded notes) share one
    /// file under distinct tables.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if the table cannot be initialized.
    pub fn table(&self, table: &'static str) -> Result<Self, StorageError> {
        let backend = Self {
            db: Arc::clone(&self.db),
            table,
        };
        backend.materialize()?;
        Ok(backend)
    }

    /// Materializes the table up front so reads never hit `TableDoesNotExist`.
    fn materialize(&self) -> Result<(), StorageError> {
        let definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new(self.table);
        let txn = self.db.begin_write().map_err(backend_error)?;
        txn.open_table(definition).map_err(backend_error)?;
        txn.commit().map_err(backend_error)?;
        Ok(())
    }
}

impl std::fmt::Debug for RedbBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbBackend")
            .field("table", &self.table)
            .finish_non_exhaustive()
    }
}

impl StorageBackend for RedbBackend {
    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new(self.table);
        let txn = self.db.begin_read().map_err(backend_error)?;
        let table = txn.open_table(definition).map_err(backend_error)?;
        // alloc-ok: owned copy at the persistence boundary.
        let value = table
            .get(key)
            .map_err(backend_error)?
            .map(|guard| guard.value().to_vec());
        Ok(value)
    }

    fn write_batch(
        &mut self,
        entries: &mut dyn Iterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), StorageError> {
        let definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new(self.table);
        let txn = self.db.begin_write().map_err(backend_error)?;
        {
            let mut table = txn.open_table(definition).map_err(backend_error)?;
            for (key, value) in entries {
                match value {
                    Some(value) => {
                        table
                            .insert(key.as_slice(), value.as_slice())
                            .map_err(backend_error)?;
                    }
                    None => {
                        table.remove(key.as_slice()).map_err(backend_error)?;
                    }
                }
            }
        }
        txn.commit().map_err(backend_error)?;
        Ok(())
    }
}

fn backend_error<E: std::fmt::Display>(error: E) -> StorageError {
    StorageError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyValueStore;

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        {
            let mut store = KeyValueStore::new(RedbBackend::open(&path, "kv").unwrap());
            store.put(b"a".to_vec(), b"1".to_vec());
            store.put(b"b".to_vec(), b"2".to_vec());
            store.flush().unwrap();
        } // store + backend dropped, closing the database file.

        let reopened = KeyValueStore::new(RedbBackend::open(&path, "kv").unwrap());
        assert_eq!(reopened.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(reopened.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(reopened.get(b"missing").unwrap(), None);
    }

    #[test]
    fn staged_delete_persists_after_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        let mut store = KeyValueStore::new(RedbBackend::open(&path, "kv").unwrap());
        store.put(b"k".to_vec(), b"v".to_vec());
        store.flush().unwrap();
        store.remove(b"k".to_vec());
        store.flush().unwrap();

        assert_eq!(store.get(b"k").unwrap(), None);
    }

    #[test]
    fn tables_share_one_file_independently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        {
            let backend_a = RedbBackend::open(&path, "a").unwrap();
            let backend_b = backend_a.table("b").unwrap();
            let mut store_a = KeyValueStore::new(backend_a);
            let mut store_b = KeyValueStore::new(backend_b);

            store_a.put(b"k".to_vec(), b"from_a".to_vec());
            store_b.put(b"k".to_vec(), b"from_b".to_vec());
            store_a.flush().unwrap();
            store_b.flush().unwrap();

            // Same key, different tables — no collision.
            assert_eq!(store_a.get(b"k").unwrap(), Some(b"from_a".to_vec()));
            assert_eq!(store_b.get(b"k").unwrap(), Some(b"from_b".to_vec()));
        } // both backends (sharing the Arc<Database>) dropped, closing the file.

        // Reopen the shared file once, then reach the second table via `table()` —
        // redb allows only one `Database` per file (the lock that makes this API
        // necessary in the first place).
        let backend_a = RedbBackend::open(&path, "a").unwrap();
        let backend_b = backend_a.table("b").unwrap();
        let reopened_a = KeyValueStore::new(backend_a);
        let reopened_b = KeyValueStore::new(backend_b);
        assert_eq!(reopened_a.get(b"k").unwrap(), Some(b"from_a".to_vec()));
        assert_eq!(reopened_b.get(b"k").unwrap(), Some(b"from_b".to_vec()));
    }
}
