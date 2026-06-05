//! A buffered byte key-value store over a swappable backend.
//!
//! The store deals only in opaque bytes — all structural encoding lives in the
//! caller's codec, so an arbitrarily complex record flows through the same
//! `(key, value)` pipe as a scalar.

use std::collections::HashMap;

/// Default number of staged writes that triggers an automatic flush.
const DEFAULT_FLUSH_CAPACITY: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// A swappable durable sink behind [`KeyValueStore`].
///
/// Implementations only need point reads and batched writes; [`KeyValueStore`]
/// layers staging, coalescing, and flush policy on top. `write_batch` takes an
/// iterator (not a materialized batch) so the store can drain its staging buffer
/// straight into the backend with no intermediate allocation. The `&mut dyn`
/// form keeps the trait object-safe for a future `Arc<dyn StorageBackend>`.
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

/// A buffered, write-through byte key-value store.
///
/// Writes are staged in a bounded buffer (coalesced per key) that auto-flushes to
/// the backend once it reaches `flush_capacity`, plus an explicit [`flush`] for
/// end-of-batch durability. Reads resolve staged writes first, then the backend.
///
/// [`flush`]: KeyValueStore::flush
#[derive(Debug)]
pub struct KeyValueStore<B: StorageBackend> {
    backend: B,
    // Staged writes: `Some(value)` = pending put, `None` = pending delete.
    pending: HashMap<Vec<u8>, Option<Vec<u8>>>,
    flush_capacity: usize,
}

impl<B: StorageBackend> KeyValueStore<B> {
    /// Wraps `backend` with the default flush capacity.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self::with_flush_capacity(backend, DEFAULT_FLUSH_CAPACITY)
    }

    /// Wraps `backend`, auto-flushing once `flush_capacity` distinct keys are staged.
    ///
    /// # Panics
    /// Panics if `flush_capacity` is zero.
    #[must_use]
    pub fn with_flush_capacity(backend: B, flush_capacity: usize) -> Self {
        assert!(flush_capacity > 0, "flush_capacity must be non-zero");
        Self {
            backend,
            pending: HashMap::new(),
            flush_capacity,
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

    /// Stages a put. May trigger an automatic flush.
    ///
    /// # Errors
    /// Propagates [`StorageError`] if an auto-flush occurs and fails.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError> {
        self.stage(key, Some(value))
    }

    /// Stages a delete. May trigger an automatic flush.
    ///
    /// # Errors
    /// Propagates [`StorageError`] if an auto-flush occurs and fails.
    pub fn remove(&mut self, key: Vec<u8>) -> Result<(), StorageError> {
        self.stage(key, None)
    }

    fn stage(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<(), StorageError> {
        self.pending.insert(key, value);
        if self.pending.len() >= self.flush_capacity {
            self.flush()?;
        }
        Ok(())
    }

    /// Drains all staged writes into the backend.
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
