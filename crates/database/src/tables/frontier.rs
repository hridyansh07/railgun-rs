//! The frontier table: merkle accumulator snapshots, one opaque record per
//! tree.
//!
//! The bytes are opaque *here* on purpose: this crate stays crypto-free (the
//! merkle math lives in `crypto`, which depends on this crate — storing
//! decoded state would invert the dependency). The producer (the syncer's
//! commit path) serializes `crypto::MerkleAccumulatorState`; consumers (the
//! merkle walk) deserialize it back. Key: `tree (u32 BE)`.

use crate::DatabaseError;
use crate::read::Reader;
use crate::tables::TableId;
use crate::write::Writer;

/// Read namespace over the frontier table.
pub struct Frontier<'a, R: Reader> {
    reader: &'a R,
}

impl<'a, R: Reader> Frontier<'a, R> {
    /// Opens the namespace over any [`Reader`].
    #[must_use]
    pub fn new(reader: &'a R) -> Self {
        Frontier { reader }
    }

    /// The stored snapshot bytes for `tree`, if any.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn snapshot(&self, tree: u32) -> Result<Option<Vec<u8>>, DatabaseError> {
        self.reader.get(TableId::Frontier, &tree.to_be_bytes())
    }
}

/// Write namespace over the frontier table.
pub struct FrontierMut<'a, W: Writer> {
    writer: &'a mut W,
}

impl<'a, W: Writer> FrontierMut<'a, W> {
    pub(crate) fn new(writer: &'a mut W) -> Self {
        FrontierMut { writer }
    }

    /// Stages a snapshot for `tree`. Stage it in the same transaction as the
    /// leaves it summarizes.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn set_snapshot(&mut self, tree: u32, bytes: &[u8]) -> Result<(), DatabaseError> {
        self.writer
            .put(TableId::Frontier, &tree.to_be_bytes(), bytes)
    }

    /// Stages removal of `tree`'s snapshot (e.g. after a backfill invalidates
    /// it), forcing the next root query down the full-walk path.
    ///
    /// # Errors
    /// Propagates [`DatabaseError`].
    pub fn clear_snapshot(&mut self, tree: u32) -> Result<(), DatabaseError> {
        self.writer.delete(TableId::Frontier, &tree.to_be_bytes())
    }
}
