//! The decoded-notes table: per-wallet **sealed** note records and scan
//! watermarks, plus the legacy single-wallet plaintext record.
//!
//! Key layout (legacy key frozen — pre-dates this crate):
//!
//! ```text
//! legacy notes:     b"decoded_notes"                      -> plaintext serde_json note list
//! sealed notes:     b'w' | wallet id (32 bytes)           -> opaque sealed bytes
//! scan watermark:   b'm' | wallet id (32 bytes) | tree    -> scanned length (u32 BE)
//! ```
//!
//! Sealed bytes are ciphertext produced *above* this crate (the decoder's
//! scan seals through `crypto::Sealer`); the database never sees plaintext
//! notes on the per-wallet path. Watermarks are plain — "scanned up to N"
//! leaks nothing useful.

use types::DecryptedNote;

use crate::DatabaseError;
use crate::read::Reader;
use crate::tables::TableId;
use crate::write::Writer;

const NOTES_KEY: &[u8] = b"decoded_notes";

fn sealed_key(wallet: &[u8; 32]) -> Vec<u8> {
    // alloc-ok: fixed 33-byte store key.
    let mut key = Vec::with_capacity(33);
    key.push(b'w');
    key.extend_from_slice(wallet);
    key
}

fn watermark_key(wallet: &[u8; 32], tree: u32) -> Vec<u8> {
    // alloc-ok: fixed 37-byte store key.
    let mut key = Vec::with_capacity(37);
    key.push(b'm');
    key.extend_from_slice(wallet);
    key.extend_from_slice(&tree.to_be_bytes());
    key
}

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

    /// The wallet's sealed note record, if any — opaque ciphertext, unsealed
    /// by the caller.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn sealed_notes(&self, wallet: &[u8; 32]) -> Result<Option<Vec<u8>>, DatabaseError> {
        self.reader.get(TableId::Decoded, &sealed_key(wallet))
    }

    /// How far `wallet` has scanned `tree` (leaves below this are attempted;
    /// `0` = never scanned).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn watermark(&self, wallet: &[u8; 32], tree: u32) -> Result<u32, DatabaseError> {
        match self
            .reader
            .get(TableId::Decoded, &watermark_key(wallet, tree))?
        {
            Some(bytes) => {
                let array: [u8; 4] = bytes
                    .try_into()
                    .map_err(|_| DatabaseError::Engine("malformed scan watermark".to_owned()))?;
                Ok(u32::from_be_bytes(array))
            }
            None => Ok(0),
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

    /// Stages a replacement of the wallet's sealed note record (ciphertext
    /// produced by the caller's `Sealer`).
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn save_sealed_notes(
        &mut self,
        wallet: &[u8; 32],
        sealed: &[u8],
    ) -> Result<(), DatabaseError> {
        self.writer
            .put(TableId::Decoded, &sealed_key(wallet), sealed)
    }

    /// Stages the wallet's scan watermark for `tree`.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn set_watermark(
        &mut self,
        wallet: &[u8; 32],
        tree: u32,
        scanned: u32,
    ) -> Result<(), DatabaseError> {
        self.writer.put(
            TableId::Decoded,
            &watermark_key(wallet, tree),
            &scanned.to_be_bytes(),
        )
    }
}
