//! A byte key-value store with explicit-flush staging over a swappable backend.
//!
//! The store deals only in opaque bytes — all structural encoding lives in the
//! caller's codec, so an arbitrarily complex record flows through the same
//! `(key, value)` pipe as a scalar.

use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// A swappable durable sink behind [`KeyValueStore`].
///
/// Implementations only need point reads and batched writes; [`KeyValueStore`]
/// layers staging and the flush boundary on top. `write_batch` takes an iterator
/// (not a materialized batch) so the store can drain its staging buffer straight
/// into the backend with no intermediate allocation. The `&mut dyn` form keeps the
/// trait object-safe for a future `Arc<dyn StorageBackend>`.
pub trait StorageBackend {
    /// Reads the value stored at `key`, if any.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if the underlying store fails.
    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Applies a batch of writes. Each item is `(key, value)`; a `None` value
    /// deletes the key.
    ///
    /// # Errors
    /// Returns [`StorageError::Backend`] if the underlying store fails.
    fn write_batch(
        &mut self,
        entries: &mut dyn Iterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), StorageError>;
}

/// An in-memory [`StorageBackend`] backed by a hash map.
#[derive(Debug, Default, Clone)]
pub struct InMemoryBackend {
    map: HashMap<Vec<u8>, Vec<u8>>,
}

impl InMemoryBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of keys currently persisted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl StorageBackend for InMemoryBackend {
    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        // alloc-ok: returns an owned copy at the persistence boundary.
        Ok(self.map.get(key).cloned())
    }

    fn write_batch(
        &mut self,
        entries: &mut dyn Iterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), StorageError> {
        for (key, value) in entries {
            match value {
                Some(value) => {
                    self.map.insert(key, value);
                }
                None => {
                    self.map.remove(&key);
                }
            }
        }
        Ok(())
    }
}

/// A write-through byte key-value store with explicit-flush staging.
///
/// Writes are staged in a buffer (coalesced per key) and reach the backend only on
/// an explicit [`flush`] — the caller owns the durability boundary, so a batch
/// commits as a single backend transaction (no mid-batch escape). Reads resolve
/// staged writes first, then the backend.
///
/// [`flush`]: KeyValueStore::flush
#[derive(Debug)]
pub struct KeyValueStore<B: StorageBackend> {
    backend: B,
    // Staged writes: `Some(value)` = pending put, `None` = pending delete.
    pending: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<B: StorageBackend> KeyValueStore<B> {
    /// Wraps `backend` with an empty staging buffer.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            pending: HashMap::new(),
        }
    }

    /// Reads `key`, resolving any staged write before falling through to the backend.
    ///
    /// # Errors
    /// Propagates [`StorageError`] from the backend.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if let Some(staged) = self.pending.get(key) {
            // alloc-ok: owned copy of a staged value at the read boundary.
            return Ok(staged.clone());
        }
        self.backend.read(key)
    }

    /// Stages a put. Durable only after the next [`flush`](Self::flush).
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.pending.insert(key, Some(value));
    }

    /// Stages a delete. Durable only after the next [`flush`](Self::flush).
    pub fn remove(&mut self, key: Vec<u8>) {
        self.pending.insert(key, None);
    }

    /// Drains all staged writes into the backend in a single `write_batch`.
    ///
    /// Drains directly into the backend (no intermediate collection); the staging
    /// map keeps its allocated capacity for reuse on the next cycle.
    ///
    /// # Errors
    /// Propagates [`StorageError`] from the backend.
    pub fn flush(&mut self) -> Result<(), StorageError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.backend.write_batch(&mut self.pending.drain())
    }

    /// Number of staged (not yet flushed) writes.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Borrows the backend (does not include staged writes).
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Consumes the store and returns the backend. Staged writes are dropped;
    /// call [`flush`](KeyValueStore::flush) first to persist them.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }
}
