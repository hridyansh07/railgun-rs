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
//! ⚠️ Entries persist the wallet's `nullifying_key` and note randoms on disk
//! (kohaku carries the same caveat). Encrypting this table — or re-deriving
//! the keys at submission time — is a follow-up before production use.

use database::{DatabaseError, Reader, TableId, Writer};
use types::{BabyJubJubPoint, DecryptedNote, PoseidonHash, RailgunTxid, U256};

use types::ListKey;

#[derive(Debug, thiserror::Error)]
pub enum PendingPoiError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error("entry codec error: {0}")]
    Codec(#[from] serde_json::Error),
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

    /// The entry for `txid`, if still pending.
    ///
    /// # Errors
    /// Propagates [`PendingPoiError`].
    pub fn get(&self, txid: RailgunTxid) -> Result<Option<PendingPoiEntry>, PendingPoiError> {
        match self.reader.get(TableId::PoiPending, &entry_key(txid))? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
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

    /// Stages `entry` (insert or replace).
    ///
    /// # Errors
    /// Propagates [`PendingPoiError`].
    pub fn put(&mut self, entry: &PendingPoiEntry) -> Result<(), PendingPoiError> {
        self.writer.put(
            TableId::PoiPending,
            &entry_key(entry.txid),
            &serde_json::to_vec(entry)?,
        )?;
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

        db.write(|txn| PendingPoisMut::new(txn).put(&entry))
            .unwrap();
        let view = db.read().unwrap();
        let loaded = PendingPois::new(&view).get(entry.txid).unwrap().unwrap();
        assert_eq!(loaded.bound_params_hash, entry.bound_params_hash);
        assert_eq!(loaded.list_keys, entry.list_keys);

        db.write(|txn| PendingPoisMut::new(txn).remove(entry.txid))
            .unwrap();
        let view = db.read().unwrap();
        assert!(PendingPois::new(&view).get(entry.txid).unwrap().is_none());
    }
}
