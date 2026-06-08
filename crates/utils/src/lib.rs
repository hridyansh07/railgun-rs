//! Shared utilities for `railgun-native`.
//!
//! Currently a single persistence primitive: [`KeyValueStore`], a buffered byte
//! key-value store over a swappable [`StorageBackend`]. Writes accumulate in a
//! fixed-capacity buffer that auto-flushes once full (bounding in-memory growth)
//! and can be force-persisted with [`KeyValueStore::flush`]. The store deals only
//! in opaque bytes — record encoding belongs to the caller's codec — and the
//! backend is pluggable: [`InMemoryBackend`] now, a real database later, with no
//! churn to callers.

mod redb_backend;
mod storage;

pub use redb_backend::RedbBackend;
pub use storage::{InMemoryBackend, KeyValueStore, StorageBackend, StorageError};
