//! The decoded-notes table: a wallet's owned notes as one flat serde record.
//!
//! Layout is **frozen** (pre-dates this crate): the single key
//! `b"decoded_notes"` holding the `serde_json` note list. Asset grouping is a
//! query-time concern (`decoder::DecodedNotes`).

use types::DecryptedNote;

use crate::DatabaseError;
use crate::read::Reader;
use crate::tables::TableId;
use crate::write::Writer;

const NOTES_KEY: &[u8] = b"decoded_notes";

/// Read namespace over the decoded-notes table.
pub struct Decoded<'a, R: Reader> {
    reader: &'a R,
}

impl<'a, R: Reader> Decoded<'a, R> {
    /// Opens the namespace over any [`Reader`].
    #[must_use]
    pub fn new(reader: &'a R) -> Self {
        Decoded { reader }
    }

    /// The stored note set, or an empty list if nothing has been saved.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn load(&self) -> Result<Vec<DecryptedNote>, DatabaseError> {
        match self.reader.get(TableId::Decoded, NOTES_KEY)? {
            // alloc-ok: owned note list at the persistence boundary.
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| DatabaseError::Serde(error.to_string())),
            None => Ok(Vec::new()),
        }
    }
}

/// Write namespace over the decoded-notes table.
pub struct DecodedMut<'a, W: Writer> {
    writer: &'a mut W,
}

impl<'a, W: Writer> DecodedMut<'a, W> {
    pub(crate) fn new(writer: &'a mut W) -> Self {
        DecodedMut { writer }
    }

    /// Stages a replacement of the stored note set.
    ///
    /// # Errors
    /// [`DatabaseError::Serde`] if serialization fails.
    pub fn save(&mut self, notes: &[DecryptedNote]) -> Result<(), DatabaseError> {
        let encoded =
            serde_json::to_vec(notes).map_err(|error| DatabaseError::Serde(error.to_string()))?;
        self.writer.put(TableId::Decoded, NOTES_KEY, &encoded)
    }
}
