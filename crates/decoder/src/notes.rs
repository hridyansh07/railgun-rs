//! [`DecodedNotes`] — a wallet's decoded notes, grouped by asset.

use std::collections::HashMap;

use commitments::CommitmentStore;
use types::{AssetId, DecryptedNote, U256};
use utils::StorageBackend;

use crate::DecodeError;

/// The spendable position for one asset: total unspent value, plus the unspent notes
/// themselves so a caller can select spend inputs without re-deriving them.
#[derive(Debug, Clone)]
pub struct Balance {
    /// Total value of the unspent notes for this asset.
    pub value: U256,
    /// The unspent notes (spendable UTXOs) for this asset.
    // alloc-ok: owned spendable set — having the UTXOs ready to hand is the point.
    pub unspent_utxos: Vec<DecryptedNote>,
}

/// A wallet's decoded notes, grouped by [`AssetId`].
///
/// Built from [`Decoder`](crate::Decoder) output; the per-asset grouping makes balance
/// and UTXO-selection queries trivial. Spent status is not stored — it is resolved
/// against the commitment store's nullifier set at query time, so the synced chain
/// state stays the single source of truth.
#[derive(Debug, Default, Clone)]
pub struct DecodedNotes {
    by_asset: HashMap<AssetId, Vec<DecryptedNote>>,
}

impl DecodedNotes {
    /// Groups a flat list of decoded notes by asset.
    #[must_use]
    pub fn from_notes(notes: Vec<DecryptedNote>) -> Self {
        // alloc-ok: one bucket per held asset, built once from a decode pass.
        let mut by_asset: HashMap<AssetId, Vec<DecryptedNote>> = HashMap::new();
        for note in notes {
            by_asset.entry(note.asset).or_default().push(note);
        }
        Self { by_asset }
    }

    /// The assets this wallet holds notes for.
    pub fn assets(&self) -> impl Iterator<Item = &AssetId> {
        self.by_asset.keys()
    }

    /// All decoded notes for `asset` (spent and unspent), or an empty slice.
    #[must_use]
    pub fn utxos(&self, asset: &AssetId) -> &[DecryptedNote] {
        self.by_asset.get(asset).map_or(&[], Vec::as_slice)
    }

    /// The raw per-asset view: every decoded note (spent and unspent), grouped by
    /// asset. The companion to [`balances`](Self::balances), which filters this down to
    /// the unspent, spendable set.
    #[must_use]
    pub fn notes_by_asset(&self) -> &HashMap<AssetId, Vec<DecryptedNote>> {
        &self.by_asset
    }

    /// A flat copy of every decoded note, for persistence via [`DecodedNoteStore`].
    ///
    /// [`DecodedNoteStore`]: crate::DecodedNoteStore
    #[must_use]
    pub fn to_notes(&self) -> Vec<DecryptedNote> {
        // alloc-ok: flat snapshot for serialization, not a hot path.
        self.by_asset.values().flatten().cloned().collect()
    }

    /// The spendable [`Balance`] per asset — total unspent value and the unspent notes.
    ///
    /// A note is unspent unless its nullifier has been observed in `store` (i.e. spent
    /// on-chain). Assets with no unspent notes are omitted, so every returned
    /// [`Balance`] holds at least one UTXO.
    ///
    /// # Errors
    /// Propagates [`DecodeError::Store`] if the nullifier set cannot be read.
    pub fn balances<B: StorageBackend>(
        &self,
        store: &CommitmentStore<B>,
    ) -> Result<HashMap<AssetId, Balance>, DecodeError> {
        // alloc-ok: one entry per held asset.
        let mut balances: HashMap<AssetId, Balance> = HashMap::new();
        for (asset, notes) in &self.by_asset {
            let mut value = U256::ZERO;
            // alloc-ok: the unspent (spendable) subset for one asset.
            let mut unspent_utxos = Vec::new();
            for note in notes {
                if store.is_nullified(note.position.tree_number(), note.nullifier)? {
                    continue;
                }
                value = value.saturating_add(note.value.as_u256());
                unspent_utxos.push(note.clone());
            }
            if !unspent_utxos.is_empty() {
                balances.insert(
                    *asset,
                    Balance {
                        value,
                        unspent_utxos,
                    },
                );
            }
        }
        Ok(balances)
    }
}
