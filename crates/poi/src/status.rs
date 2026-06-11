//! POI status cache and the balance-bucket spendability model.
//!
//! Statuses come from `ppoi_pois_per_list`, cached per
//! `(blinded commitment, list key)` in the database's `poi_status` table.
//! `Valid` is terminal and never re-fetched; everything else is re-queried on
//! refresh (the engine's semantics). Bucketing follows the engine's
//! `POI.getBalanceBucket` decision tree, reading nullifiers and statuses off
//! one shared read view.

use std::collections::HashMap;

use database::{Commitments, Database, DatabaseError, Reader, Writer, tables};
use decoder::{Balance, DecodedNotes};
use types::{AssetId, BlindedCommitmentType, DecryptedNote, U256};

use crate::client::{PoiClientError, PoiNodeClient};
use crate::types::{BlindedCommitment, BlindedCommitmentData, ListKey, PoiStatus};

#[derive(Debug, thiserror::Error)]
pub enum PoiStatusError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error("status codec error: {0}")]
    Codec(#[from] serde_json::Error),
    #[error(transparent)]
    Client(#[from] PoiClientError),
}

/// A cached POI status and when it was fetched (unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StatusRecord {
    pub status: PoiStatus,
    pub fetched_at_unix: u64,
}

/// Read namespace over the POI status cache. Works over any [`Reader`].
pub struct PoiStatuses<'a, R: Reader> {
    reader: &'a R,
}

impl<'a, R: Reader> PoiStatuses<'a, R> {
    #[must_use]
    pub fn new(reader: &'a R) -> Self {
        PoiStatuses { reader }
    }

    /// The cached status for `(blinded_commitment, list_key)`, if any.
    ///
    /// # Errors
    /// Propagates [`PoiStatusError`].
    pub fn get(
        &self,
        blinded_commitment: BlindedCommitment,
        list_key: &ListKey,
    ) -> Result<Option<StatusRecord>, PoiStatusError> {
        match self.reader.get(
            tables::POI_STATUS,
            &status_key(blinded_commitment, list_key),
        )? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }
}

/// Write namespace over the POI status cache. Staged only — durability is the
/// enclosing transaction's commit.
pub struct PoiStatusesMut<'a, W: Writer> {
    writer: &'a mut W,
}

impl<'a, W: Writer> PoiStatusesMut<'a, W> {
    #[must_use]
    pub fn new(writer: &'a mut W) -> Self {
        PoiStatusesMut { writer }
    }

    /// Stages a status record.
    ///
    /// # Errors
    /// Propagates [`PoiStatusError`].
    pub fn put(
        &mut self,
        blinded_commitment: BlindedCommitment,
        list_key: &ListKey,
        record: StatusRecord,
    ) -> Result<(), PoiStatusError> {
        self.writer.put(
            tables::POI_STATUS,
            &status_key(blinded_commitment, list_key),
            &serde_json::to_vec(&record)?,
        )?;
        Ok(())
    }
}

/// Outcome of one status refresh pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RefreshSummary {
    /// (note, list key) pairs queried.
    pub queried: u64,
    /// Records written (the node answered for the pair).
    pub updated: u64,
}

/// Batch-refreshes cached statuses from a [`PoiNodeClient`].
pub struct PoiStatusRefresher<'a, C: PoiNodeClient> {
    client: &'a C,
    now_unix: u64,
}

impl<'a, C: PoiNodeClient> PoiStatusRefresher<'a, C> {
    /// # Panics
    /// Panics if the system clock is before the unix epoch.
    #[must_use]
    pub fn new(client: &'a C) -> Self {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs();
        PoiStatusRefresher { client, now_unix }
    }

    /// Refreshes every `(note, list key)` pair whose cached status is absent
    /// or non-`Valid` (`Valid` is terminal). One chunked node round-trip
    /// (holding no engine lock), then one write transaction.
    ///
    /// # Errors
    /// Propagates [`PoiStatusError`]; on error nothing is written.
    pub async fn refresh<'n>(
        &self,
        notes: impl Iterator<Item = &'n DecryptedNote>,
        db: &Database,
    ) -> Result<RefreshSummary, PoiStatusError> {
        let list_keys = self.client.list_keys();

        // alloc-ok: one refresh batch (bounded by the wallet's note count).
        let mut stale = Vec::new();
        {
            let view = db.read()?;
            let cache = PoiStatuses::new(&view);
            for note in notes {
                let blinded = BlindedCommitment::from_note(note);
                let mut needs_fetch = false;
                for list_key in list_keys {
                    let cached = cache.get(blinded, list_key)?;
                    if !matches!(
                        cached,
                        Some(StatusRecord {
                            status: PoiStatus::Valid,
                            ..
                        })
                    ) {
                        needs_fetch = true;
                    }
                }
                if needs_fetch {
                    stale.push(BlindedCommitmentData::from_note(note));
                }
            }
        }

        let mut summary = RefreshSummary {
            queried: (stale.len() * list_keys.len()) as u64,
            ..RefreshSummary::default()
        };
        if stale.is_empty() {
            return Ok(summary);
        }

        let statuses = self.client.pois_per_list(list_keys, &stale).await?;
        db.write(|txn| {
            let mut cache = PoiStatusesMut::new(txn);
            for (blinded, per_list) in &statuses {
                for (list_key, status) in per_list {
                    cache.put(
                        *blinded,
                        list_key,
                        StatusRecord {
                            status: *status,
                            fetched_at_unix: self.now_unix,
                        },
                    )?;
                    summary.updated += 1;
                }
            }
            Ok::<_, PoiStatusError>(())
        })?;
        Ok(summary)
    }
}

/// The engine's `WalletBalanceBucket`: where a UTXO sits in the POI lifecycle.
///
/// `MissingInternalPOI` (change outputs) requires sender-side output-type
/// decoding that [`DecryptedNote`] does not carry yet, so change collapses
/// into [`BalanceBucket::MissingExternalPOI`] for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BalanceBucket {
    Spendable,
    ShieldBlocked,
    ShieldPending,
    ProofSubmitted,
    MissingInternalPOI,
    MissingExternalPOI,
    Spent,
}

/// The engine's `POI.getBalanceBucket` decision tree:
/// spent (nullified) → `Spent`; any active list uncached → `ShieldPending`
/// (shield) / `MissingExternalPOI`; all `Valid` → `Spendable`; any
/// `ShieldBlocked` → `ShieldBlocked`; shield → `ShieldPending`; any
/// `ProofSubmitted` → `ProofSubmitted`; else `MissingExternalPOI`.
///
/// Nullifiers and cached statuses are read off the same `view`, so the
/// answer is one consistent snapshot.
///
/// # Errors
/// Propagates [`PoiStatusError`].
pub fn balance_bucket<R: Reader>(
    note: &DecryptedNote,
    view: &R,
    active_list_keys: &[ListKey],
) -> Result<BalanceBucket, PoiStatusError> {
    if Commitments::new(view).is_nullified(note.position.tree_number(), note.nullifier)? {
        return Ok(BalanceBucket::Spent);
    }

    let is_shield = matches!(note.commitment_type, BlindedCommitmentType::Shield);
    let blinded = BlindedCommitment::from_note(note);
    let statuses = PoiStatuses::new(view);

    // alloc-ok: fixed-size per-list status row (one entry per active list).
    let mut per_list = Vec::with_capacity(active_list_keys.len());
    for list_key in active_list_keys {
        match statuses.get(blinded, list_key)? {
            Some(record) => per_list.push(record.status),
            None => {
                return Ok(if is_shield {
                    BalanceBucket::ShieldPending
                } else {
                    BalanceBucket::MissingExternalPOI
                });
            }
        }
    }

    if per_list.iter().all(|status| *status == PoiStatus::Valid) {
        return Ok(BalanceBucket::Spendable);
    }
    if per_list.contains(&PoiStatus::ShieldBlocked) {
        return Ok(BalanceBucket::ShieldBlocked);
    }
    if is_shield {
        return Ok(BalanceBucket::ShieldPending);
    }
    if per_list.contains(&PoiStatus::ProofSubmitted) {
        return Ok(BalanceBucket::ProofSubmitted);
    }
    Ok(BalanceBucket::MissingExternalPOI)
}

/// Per-asset balances split by [`BalanceBucket`]. The POI-aware companion to
/// `decoder::DecodedNotes::balances` (which is POI-blind by design).
#[derive(Debug, Default)]
pub struct BucketedBalances {
    by_asset: HashMap<AssetId, HashMap<BalanceBucket, Balance>>,
}

impl BucketedBalances {
    /// The balance for `asset` in `bucket`, if any notes landed there.
    #[must_use]
    pub fn get(&self, asset: &AssetId, bucket: BalanceBucket) -> Option<&Balance> {
        self.by_asset.get(asset)?.get(&bucket)
    }

    /// The spendable balance for `asset`: unspent **and** `Valid` on every
    /// active list.
    #[must_use]
    pub fn spendable(&self, asset: &AssetId) -> Option<&Balance> {
        self.get(asset, BalanceBucket::Spendable)
    }

    /// All buckets for `asset`.
    #[must_use]
    pub fn buckets(&self, asset: &AssetId) -> Option<&HashMap<BalanceBucket, Balance>> {
        self.by_asset.get(asset)
    }
}

/// Buckets every decoded note by POI status, reading off one `view`. Notes in
/// a bucket carry their UTXOs so spend-input selection can run straight off
/// the `Spendable` set.
///
/// # Errors
/// Propagates [`PoiStatusError`].
pub fn bucket_balances<R: Reader>(
    notes: &DecodedNotes,
    view: &R,
    active_list_keys: &[ListKey],
) -> Result<BucketedBalances, PoiStatusError> {
    let mut by_asset: HashMap<AssetId, HashMap<BalanceBucket, Balance>> = HashMap::new();
    for (asset, asset_notes) in notes.notes_by_asset() {
        for note in asset_notes {
            let bucket = balance_bucket(note, view, active_list_keys)?;
            let balance = by_asset
                .entry(*asset)
                .or_default()
                .entry(bucket)
                .or_insert_with(|| Balance {
                    value: U256::ZERO,
                    // alloc-ok: per-bucket UTXO set, the query's product.
                    unspent_utxos: Vec::new(),
                });
            balance.value = balance.value.saturating_add(note.value.as_u256());
            balance.unspent_utxos.push(note.clone());
        }
    }
    Ok(BucketedBalances { by_asset })
}

// Key layout: b'v' | blinded commitment (32 bytes) | list key (utf-8)
fn status_key(blinded_commitment: BlindedCommitment, list_key: &ListKey) -> Vec<u8> {
    let key_bytes = list_key.as_str().as_bytes();
    // alloc-ok: fixed-prefix store key.
    let mut key = Vec::with_capacity(33 + key_bytes.len());
    key.push(b'v');
    key.extend_from_slice(&blinded_commitment.as_u256().to_be_bytes::<32>());
    key.extend_from_slice(key_bytes);
    key
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use database::test_util::{TempDatabase, temp};
    use types::{
        AssetId, B256, BlockNumber, CommitmentHash, EvmAddress, NodePosition, NoteValue, Nullified,
        Nullifier,
    };

    use crate::test_support::MockPoiNode;

    use super::*;

    fn note(leaf: u32, kind: BlindedCommitmentType) -> DecryptedNote {
        DecryptedNote {
            position: NodePosition::try_new(0, leaf).unwrap(),
            value: NoteValue::new(1_000),
            asset: AssetId::erc20(EvmAddress::from([0x11; 20])),
            random: [0u8; 16],
            memo: String::new(),
            commitment_hash: CommitmentHash::new(U256::from(leaf + 1)),
            note_public_key: U256::from(7u8),
            nullifier: Nullifier::new(B256::from(U256::from(leaf + 100).to_be_bytes::<32>())),
            blinded_commitment: U256::from(leaf + 1_000),
            commitment_type: kind,
        }
    }

    fn db_with(statuses: &[(DecryptedNote, &str, PoiStatus)]) -> TempDatabase {
        let db = temp();
        db.write(|txn| {
            let mut cache = PoiStatusesMut::new(txn);
            for (note, list_key, status) in statuses {
                cache.put(
                    BlindedCommitment::from_note(note),
                    &ListKey::from(*list_key),
                    StatusRecord {
                        status: *status,
                        fetched_at_unix: 0,
                    },
                )?;
            }
            Ok::<_, PoiStatusError>(())
        })
        .unwrap();
        db
    }

    fn lists(keys: &[&str]) -> Vec<ListKey> {
        keys.iter().map(|key| ListKey::from(*key)).collect()
    }

    // One test per branch of the engine's getBalanceBucket decision tree.
    #[test]
    fn bucket_decision_table_matches_engine() {
        let active = lists(&["a", "b"]);

        let shield = note(0, BlindedCommitmentType::Shield);
        let transact = note(1, BlindedCommitmentType::Transact);

        let cases: Vec<(&DecryptedNote, Vec<(PoiStatus, PoiStatus)>, BalanceBucket)> = vec![
            // All Valid → Spendable.
            (
                &shield,
                vec![(PoiStatus::Valid, PoiStatus::Valid)],
                BalanceBucket::Spendable,
            ),
            // Any ShieldBlocked → ShieldBlocked (beats everything but Spent).
            (
                &transact,
                vec![(PoiStatus::Valid, PoiStatus::ShieldBlocked)],
                BalanceBucket::ShieldBlocked,
            ),
            // Shield with non-valid, non-blocked statuses → ShieldPending.
            (
                &shield,
                vec![(PoiStatus::Missing, PoiStatus::Valid)],
                BalanceBucket::ShieldPending,
            ),
            // Transact with a submitted proof → ProofSubmitted.
            (
                &transact,
                vec![(PoiStatus::ProofSubmitted, PoiStatus::Valid)],
                BalanceBucket::ProofSubmitted,
            ),
            // Transact with Missing everywhere else → MissingExternalPOI.
            (
                &transact,
                vec![(PoiStatus::Missing, PoiStatus::Valid)],
                BalanceBucket::MissingExternalPOI,
            ),
        ];

        for (note, statuses, expected) in cases {
            let rows: Vec<_> = statuses
                .iter()
                .flat_map(|(a, b)| [(note.clone(), "a", *a), (note.clone(), "b", *b)])
                .collect();
            let db = db_with(&rows);
            let view = db.read().unwrap();
            assert_eq!(
                balance_bucket(note, &view, &active).unwrap(),
                expected,
                "wrong bucket for {statuses:?}"
            );
        }
    }

    #[test]
    fn uncached_status_is_pending_for_shield_and_missing_for_transact() {
        let db = temp();
        let view = db.read().unwrap();
        let active = lists(&["a"]);

        assert_eq!(
            balance_bucket(&note(0, BlindedCommitmentType::Shield), &view, &active).unwrap(),
            BalanceBucket::ShieldPending
        );
        assert_eq!(
            balance_bucket(&note(1, BlindedCommitmentType::Transact), &view, &active).unwrap(),
            BalanceBucket::MissingExternalPOI
        );
    }

    #[test]
    fn nullified_note_is_spent_regardless_of_poi() {
        let spent = note(0, BlindedCommitmentType::Shield);
        let db = db_with(&[(spent.clone(), "a", PoiStatus::Valid)]);
        db.write(|txn| {
            txn.commitments().insert_nullifier(Nullified {
                tree_number: 0,
                nullifier: spent.nullifier,
            })?;
            txn.commitments().set_synced_block(BlockNumber::new(1))?;
            Ok::<_, DatabaseError>(())
        })
        .unwrap();

        let view = db.read().unwrap();
        assert_eq!(
            balance_bucket(&spent, &view, &lists(&["a"])).unwrap(),
            BalanceBucket::Spent
        );
    }

    #[tokio::test]
    async fn refresh_skips_valid_and_writes_node_statuses() {
        let valid = note(0, BlindedCommitmentType::Shield);
        let missing = note(1, BlindedCommitmentType::Transact);

        let mut node_statuses = PoisPerListMapHelper::new();
        node_statuses.set(&missing, "test_list", PoiStatus::ProofSubmitted);
        // The mock would also answer for `valid`, proving refresh never asked.
        node_statuses.set(&valid, "test_list", PoiStatus::ShieldBlocked);

        let client = MockPoiNode {
            statuses: node_statuses.0,
            ..MockPoiNode::default()
        };

        let db = db_with(&[(valid.clone(), "test_list", PoiStatus::Valid)]);
        let summary = PoiStatusRefresher::new(&client)
            .refresh([&valid, &missing].into_iter(), &db)
            .await
            .unwrap();

        assert_eq!(summary.queried, 1);
        assert_eq!(summary.updated, 1);
        // Valid stayed terminal; missing picked up the node's answer.
        let key = ListKey::from("test_list");
        let view = db.read().unwrap();
        let cache = PoiStatuses::new(&view);
        assert_eq!(
            cache
                .get(BlindedCommitment::from_note(&valid), &key)
                .unwrap()
                .unwrap()
                .status,
            PoiStatus::Valid
        );
        assert_eq!(
            cache
                .get(BlindedCommitment::from_note(&missing), &key)
                .unwrap()
                .unwrap()
                .status,
            PoiStatus::ProofSubmitted
        );
    }

    #[test]
    fn bucket_balances_groups_by_asset_and_bucket() {
        let active = lists(&["a"]);

        let spendable = note(0, BlindedCommitmentType::Shield);
        let pending = note(1, BlindedCommitmentType::Shield);
        let db = db_with(&[(spendable.clone(), "a", PoiStatus::Valid)]);

        let decoded = DecodedNotes::from_notes(vec![spendable.clone(), pending.clone()]);
        let view = db.read().unwrap();
        let bucketed = bucket_balances(&decoded, &view, &active).unwrap();

        let asset = spendable.asset;
        let spendable_balance = bucketed.spendable(&asset).unwrap();
        assert_eq!(spendable_balance.value, U256::from(1_000u64));
        assert_eq!(spendable_balance.unspent_utxos.len(), 1);

        let pending_balance = bucketed.get(&asset, BalanceBucket::ShieldPending).unwrap();
        assert_eq!(pending_balance.unspent_utxos.len(), 1);
    }

    /// Builder for the nested PoisPerListMap literal.
    struct PoisPerListMapHelper(crate::types::PoisPerListMap);

    impl PoisPerListMapHelper {
        fn new() -> Self {
            PoisPerListMapHelper(HashMap::new())
        }

        fn set(&mut self, note: &DecryptedNote, list_key: &str, status: PoiStatus) {
            self.0
                .entry(BlindedCommitment::from_note(note))
                .or_default()
                .insert(ListKey::from(list_key), status);
        }
    }
}
