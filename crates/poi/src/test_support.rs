//! In-crate test doubles: a scripted POI node and a canned transaction source.

use std::collections::HashMap;
use std::sync::Mutex;

use crypto::{MerkleProof, MerkleRoot, RailgunMerkleConfig};
use sync::{RailgunTxSource, SyncError, TransactionPage};
use types::{BlockNumber, RailgunTransaction};

use crate::client::{PoiClientError, PoiNodeClient};
use crate::types::{
    BlindedCommitment, BlindedCommitmentData, ListKey, PoisPerListMap, TransactProofData,
    ValidatedRailgunTxidStatus,
};

/// A scripted [`PoiNodeClient`].
pub struct MockPoiNode {
    pub list_keys: Vec<ListKey>,
    /// Returned by `pois_per_list`, filtered to the requested commitments.
    pub statuses: PoisPerListMap,
    /// Returned by `validated_txid`.
    pub validated_index: u32,
    /// `validate_txid_merkleroot` returns this; `true` accepts every root.
    pub accept_roots: bool,
    /// Roots the indexer asked us to validate, in order.
    pub validated_roots: Mutex<Vec<(u32, u32, MerkleRoot)>>,
    /// Proofs served by `merkle_proof`, keyed by blinded commitment.
    pub proofs: HashMap<BlindedCommitment, MerkleProof<RailgunMerkleConfig>>,
}

impl Default for MockPoiNode {
    fn default() -> Self {
        MockPoiNode {
            list_keys: vec![ListKey::from("test_list")],
            statuses: PoisPerListMap::new(),
            validated_index: 0,
            accept_roots: true,
            validated_roots: Mutex::new(Vec::new()),
            proofs: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl PoiNodeClient for MockPoiNode {
    fn list_keys(&self) -> &[ListKey] {
        &self.list_keys
    }

    async fn pois_per_list(
        &self,
        _list_keys: &[ListKey],
        datas: &[BlindedCommitmentData],
    ) -> Result<PoisPerListMap, PoiClientError> {
        Ok(datas
            .iter()
            .filter_map(|data| {
                self.statuses
                    .get(&data.blinded_commitment)
                    .map(|statuses| (data.blinded_commitment, statuses.clone()))
            })
            .collect())
    }

    async fn merkle_proof(
        &self,
        list_key: &ListKey,
        blinded_commitment: BlindedCommitment,
    ) -> Result<MerkleProof<RailgunMerkleConfig>, PoiClientError> {
        self.proofs
            .get(&blinded_commitment)
            .cloned()
            .ok_or_else(|| PoiClientError::ProofNotFound {
                list_key: list_key.clone(),
                blinded_commitment,
            })
    }

    async fn submit_transact_proof(
        &self,
        _list_key: &ListKey,
        _data: TransactProofData,
    ) -> Result<(), PoiClientError> {
        Ok(())
    }

    async fn validated_txid(&self) -> Result<ValidatedRailgunTxidStatus, PoiClientError> {
        Ok(ValidatedRailgunTxidStatus {
            index: self.validated_index,
            merkleroot: MerkleRoot::new(types::U256::ZERO),
        })
    }

    async fn validate_txid_merkleroot(
        &self,
        tree: u32,
        index: u32,
        merkleroot: MerkleRoot,
    ) -> Result<bool, PoiClientError> {
        self.validated_roots
            .lock()
            .expect("mock lock")
            .push((tree, index, merkleroot));
        Ok(self.accept_roots)
    }
}

/// A [`RailgunTxSource`] serving a fixed transaction list in one page.
pub struct CannedTxSource {
    pub head: BlockNumber,
    pub transactions: Vec<RailgunTransaction>,
}

#[async_trait::async_trait]
impl RailgunTxSource for CannedTxSource {
    async fn latest_block(&self) -> Result<BlockNumber, SyncError> {
        Ok(self.head)
    }

    async fn fetch_transactions_page(
        &self,
        from: BlockNumber,
        to: BlockNumber,
        _cursor: Option<String>,
    ) -> Result<TransactionPage, SyncError> {
        Ok(TransactionPage {
            // alloc-ok: test double.
            transactions: self
                .transactions
                .iter()
                .filter(|tx| tx.block >= from && tx.block <= to)
                .cloned()
                .collect(),
            cursor: None,
        })
    }
}
