//! Persisted records for post-transaction (spent) POI proofs.
//!
//! When a transaction is broadcast, everything needed to later prove the spent
//! POI is captured as a [`PendingPoiEntry`] in the database's `poi_pending`
//! table. A future submission loop drains the table once the operation's txid
//! is indexed: build [`crate::inputs::PoiCircuitInputs`] with
//! `UtxoTreeIndex::included(..)`, prove through the `CircuitProver` seam, and
//! `ppoi_submit_transact_proof`.
//!
//! Writes go through `db.write` at the call site — a pending proof obligation
//! must commit before the broadcast is considered done.
//!
//! Entries carry the wallet's `nullifying_key` and note randoms, so they
//! persist **sealed only** ([`crypto::Sealer`]) — the database holds
//! ciphertext. Follow-up: the DEK itself becomes hardware/biometric-gated in
//! the platform layer (same trait, no change here).

use crypto::Sealer;
use database::{DatabaseError, Reader, TableId, Writer};
use types::{BabyJubJubPoint, DecryptedNote, PoseidonHash, RailgunTxid, U256};

use types::ListKey;

#[derive(Debug, thiserror::Error)]
pub enum PendingPoiError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error("entry codec error: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("sealed entry: {0}")]
    Seal(crypto::CryptoError),
}

/// Everything needed to generate and submit one operation's spent POI proofs
/// after its txid lands in the txid tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingPoiEntry {
    pub txid: RailgunTxid,
    pub spending_public_key: BabyJubJubPoint,
    pub nullifying_key: PoseidonHash,
    pub utxo_tree_in: u32,
    pub bound_params_hash: U256,
    pub in_notes: Vec<DecryptedNote>,
    pub out_commitments: Vec<U256>,
    pub out_npks: Vec<U256>,
    pub out_values: Vec<U256>,
    pub token_hash: U256,
    pub has_unshield: bool,
    /// Lists this operation still owes a spent proof.
    pub list_keys: Vec<ListKey>,
}

/// Read namespace over the pending-POI table. Works over any [`Reader`].
pub struct PendingPois<'a, R: Reader> {
    reader: &'a R,
}

impl<'a, R: Reader> PendingPois<'a, R> {
    #[must_use]
    pub fn new(reader: &'a R) -> Self {
        PendingPois { reader }
    }

    /// The entry for `txid`, if still pending — unsealed with the caller's
    /// session key.
    ///
    /// # Errors
    /// [`PendingPoiError::Seal`] on the wrong key or a corrupt record;
    /// otherwise propagates [`PendingPoiError`].
    pub fn get(
        &self,
        txid: RailgunTxid,
        sealer: &dyn Sealer,
    ) -> Result<Option<PendingPoiEntry>, PendingPoiError> {
        match self.reader.get(TableId::PoiPending, &entry_key(txid))? {
            Some(ciphertext) => {
                let plain = sealer.unseal(&ciphertext).map_err(PendingPoiError::Seal)?;
                Ok(Some(serde_json::from_slice(&plain)?))
            }
            None => Ok(None),
        }
    }
}

/// Write namespace over the pending-POI table. Staged only — durability is
/// the enclosing transaction's commit.
pub struct PendingPoisMut<'a, W: Writer> {
    writer: &'a mut W,
}

impl<'a, W: Writer> PendingPoisMut<'a, W> {
    #[must_use]
    pub fn new(writer: &'a mut W) -> Self {
        PendingPoisMut { writer }
    }

    /// Stages `entry` (insert or replace), sealed under the caller's session
    /// key.
    ///
    /// # Errors
    /// Propagates [`PendingPoiError`].
    pub fn put(
        &mut self,
        entry: &PendingPoiEntry,
        sealer: &dyn Sealer,
    ) -> Result<(), PendingPoiError> {
        let ciphertext = sealer
            .seal(&serde_json::to_vec(entry)?)
            .map_err(PendingPoiError::Seal)?;
        self.writer
            .put(TableId::PoiPending, &entry_key(entry.txid), &ciphertext)?;
        Ok(())
    }

    /// Stages removal of the entry for `txid` (all its lists are proven).
    ///
    /// # Errors
    /// Propagates [`PendingPoiError`].
    pub fn remove(&mut self, txid: RailgunTxid) -> Result<(), PendingPoiError> {
        self.writer.delete(TableId::PoiPending, &entry_key(txid))?;
        Ok(())
    }
}

// Key layout: b'e' | txid (32 bytes)
fn entry_key(txid: RailgunTxid) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(b'e');
    key.extend_from_slice(&txid.as_u256().to_be_bytes::<32>());
    key
}

#[cfg(test)]
mod tests {
    use crypto::AesGcmSealer;
    use database::test_util::temp;

    use super::*;

    #[test]
    fn entries_round_trip_and_remove() {
        let db = temp();
        let entry = PendingPoiEntry {
            txid: RailgunTxid::new(U256::from(42u64)),
            spending_public_key: BabyJubJubPoint::new(U256::from(1u8), U256::from(2u8)),
            nullifying_key: PoseidonHash::new(U256::from(3u8)),
            utxo_tree_in: 0,
            bound_params_hash: U256::from(4u8),
            in_notes: vec![],
            out_commitments: vec![U256::from(5u8)],
            out_npks: vec![],
            out_values: vec![],
            token_hash: U256::from(6u8),
            has_unshield: true,
            list_keys: vec![ListKey::from("test_list")],
        };

        let sealer = AesGcmSealer::new([7u8; 32]);
        db.write(|txn| PendingPoisMut::new(txn).put(&entry, &sealer))
            .unwrap();
        let view = db.read().unwrap();
        let loaded = PendingPois::new(&view)
            .get(entry.txid, &sealer)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.bound_params_hash, entry.bound_params_hash);
        assert_eq!(loaded.list_keys, entry.list_keys);

        // The wrong session key fails closed.
        let wrong = AesGcmSealer::new([9u8; 32]);
        assert!(matches!(
            PendingPois::new(&view).get(entry.txid, &wrong),
            Err(PendingPoiError::Seal(_))
        ));
        drop(view);

        db.write(|txn| PendingPoisMut::new(txn).remove(entry.txid))
            .unwrap();
        let view = db.read().unwrap();
        assert!(
            PendingPois::new(&view)
                .get(entry.txid, &sealer)
                .unwrap()
                .is_none()
        );
    }
}
