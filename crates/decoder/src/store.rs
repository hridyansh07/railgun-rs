//! [`DecodedNoteStore`] — persists a wallet's decoded notes over a storage backend.

use types::DecryptedNote;
use utils::{KeyValueStore, StorageBackend};

use crate::DecodeError;

/// The single key the flat note list is stored under.
const NOTES_KEY: &[u8] = b"decoded_notes";

/// Persists a wallet's decoded notes over a [`StorageBackend`].
///
/// The flat note list is stored as one `serde_json` record (the asset grouping is a
/// query-time concern — see [`DecodedNotes`](crate::DecodedNotes) — and `serde_json`
/// cannot key a map by a struct anyway). Point a redb backend at its own table (via
/// [`RedbBackend::table`]) to share a database file with the commitment store.
///
/// [`RedbBackend::table`]: utils::RedbBackend::table
#[derive(Debug)]
pub struct DecodedNoteStore<B: StorageBackend> {
    kv: KeyValueStore<B>,
}

impl<B: StorageBackend> DecodedNoteStore<B> {
    /// Opens a note store over `backend`.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            kv: KeyValueStore::new(backend),
        }
    }

    /// Replaces the stored note set with `notes`, flushing atomically.
    ///
    /// # Errors
    /// [`DecodeError::Serde`] if serialization fails; [`DecodeError::Storage`] if the
    /// flush fails.
    pub fn save(&mut self, notes: &[DecryptedNote]) -> Result<(), DecodeError> {
        let encoded =
            serde_json::to_vec(notes).map_err(|error| DecodeError::Serde(error.to_string()))?;
        self.kv.put(NOTES_KEY.to_vec(), encoded);
        self.kv.flush()?;
        Ok(())
    }

    /// Loads the stored note set, or an empty list if nothing has been saved.
    ///
    /// # Errors
    /// [`DecodeError::Storage`] if the read fails; [`DecodeError::Serde`] if the stored
    /// record cannot be decoded.
    pub fn load(&self) -> Result<Vec<DecryptedNote>, DecodeError> {
        match self.kv.get(NOTES_KEY)? {
            // alloc-ok: owned note list at the persistence boundary.
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| DecodeError::Serde(error.to_string())),
            None => Ok(Vec::new()),
        }
    }

    /// Consumes the store and returns the backend.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.kv.into_backend()
    }
}
