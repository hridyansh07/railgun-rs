//! A durable [`StorageBackend`] backed by [redb](https://docs.rs/redb).
//!
//! redb is synchronous and transactional, so it slots straight into our sync
//! `StorageBackend` trait: each `write_batch` (one per `KeyValueStore` flush)
//! becomes a single atomic commit.

use std::path::Path;

use redb::{Database, TableDefinition};

use crate::storage::{StorageBackend, StorageError};

/// The single key-value table; both key and value are opaque bytes.
const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("railgun_kv");

/// A redb-backed key-value store.
pub struct RedbBackend {
    db: Database,
}

impl RedbBackend {
    /// Opens (creating if absent) a redb database at `path`.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if the database cannot be opened or the
    /// table cannot be initialized.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = Database::create(path).map_err(backend_error)?;
        // Materialize the table up front so reads never hit `TableDoesNotExist`.
        let txn = db.begin_write().map_err(backend_error)?;
        txn.open_table(KV).map_err(backend_error)?;
        txn.commit().map_err(backend_error)?;
        Ok(Self { db })
    }
}

impl std::fmt::Debug for RedbBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbBackend").finish_non_exhaustive()
    }
}

impl StorageBackend for RedbBackend {
    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let txn = self.db.begin_read().map_err(backend_error)?;
        let table = txn.open_table(KV).map_err(backend_error)?;
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
        let txn = self.db.begin_write().map_err(backend_error)?;
        {
            let mut table = txn.open_table(KV).map_err(backend_error)?;
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
            let mut store = KeyValueStore::new(RedbBackend::open(&path).unwrap());
            store.put(b"a".to_vec(), b"1".to_vec());
            store.put(b"b".to_vec(), b"2".to_vec());
            store.flush().unwrap();
        } // store + backend dropped, closing the database file.

        let reopened = KeyValueStore::new(RedbBackend::open(&path).unwrap());
        assert_eq!(reopened.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(reopened.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(reopened.get(b"missing").unwrap(), None);
    }

    #[test]
    fn staged_delete_persists_after_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        let mut store = KeyValueStore::new(RedbBackend::open(&path).unwrap());
        store.put(b"k".to_vec(), b"v".to_vec());
        store.flush().unwrap();
        store.remove(b"k".to_vec());
        store.flush().unwrap();

        assert_eq!(store.get(b"k").unwrap(), None);
    }
}
