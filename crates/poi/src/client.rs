//! JSON-RPC 2.0 client for POI aggregator nodes.
//!
//! Methods and envelopes mirror kohaku's `poi/client.rs` against the official
//! POI node API. The network sits behind [`PoiNodeClient`] so stores and
//! refreshers test against a mock.

use std::sync::atomic::{AtomicU64, Ordering};

use crypto::{MerkleProof, MerkleRoot, RailgunMerkleConfig};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::types::{
    BlindedCommitment, BlindedCommitmentData, ChainParams, GetMerkleProofsParams,
    GetPoisPerListParams, ListKey, PoisPerListMap, SubmitTransactProofParams, TransactProofData,
    ValidateTxidMerklerootParams, ValidatedRailgunTxidStatus,
};

/// Blinded commitments per `ppoi_pois_per_list` request; larger queries are
/// chunked so one bad page can't take down a whole refresh.
const POIS_PER_LIST_CHUNK: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum PoiClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON-RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("null result from RPC")]
    NullResult,
    #[error("no merkle proof returned for {blinded_commitment} on list {list_key}")]
    ProofNotFound {
        list_key: ListKey,
        blinded_commitment: BlindedCommitment,
    },
}

/// The POI node operations the wallet depends on.
#[async_trait::async_trait]
pub trait PoiNodeClient: Send + Sync {
    /// The active list keys a UTXO must be `Valid` on to be spendable.
    fn list_keys(&self) -> &[ListKey];

    /// POI status per (blinded commitment, list key). Chunked internally.
    async fn pois_per_list(
        &self,
        list_keys: &[ListKey],
        datas: &[BlindedCommitmentData],
    ) -> Result<PoisPerListMap, PoiClientError>;

    /// The POI tree membership proof for one blinded commitment on one list.
    /// Note: the node returns *dummy* proofs (constant filler elements) for
    /// commitments it has no entry for — these do not verify as a zero ladder.
    async fn merkle_proof(
        &self,
        list_key: &ListKey,
        blinded_commitment: BlindedCommitment,
    ) -> Result<MerkleProof<RailgunMerkleConfig>, PoiClientError>;

    /// Submits one operation's POI proof for one list. The node replies with a
    /// null result on success.
    async fn submit_transact_proof(
        &self,
        list_key: &ListKey,
        data: TransactProofData,
    ) -> Result<(), PoiClientError>;

    /// The node's latest validated txid-tree position and root.
    async fn validated_txid(&self) -> Result<ValidatedRailgunTxidStatus, PoiClientError>;

    /// Whether `root` is the node's root for `tree` at `index` (last leaf).
    async fn validate_txid_merkleroot(
        &self,
        tree: u32,
        index: u32,
        merkleroot: MerkleRoot,
    ) -> Result<bool, PoiClientError>;
}

/// HTTP JSON-RPC implementation of [`PoiNodeClient`], pinned to V2.
pub struct PoiClient {
    http: reqwest::Client,
    url: String,
    next_id: AtomicU64,
    chain_id: u64,
    // alloc-ok: configuration held for the client's lifetime.
    list_keys: Vec<ListKey>,
}

impl PoiClient {
    #[must_use]
    pub fn new(chain_id: u64, url: impl Into<String>, list_keys: Vec<ListKey>) -> Self {
        PoiClient {
            http: reqwest::Client::new(),
            url: url.into(),
            next_id: AtomicU64::new(1),
            chain_id,
            list_keys,
        }
    }

    fn chain(&self) -> ChainParams {
        ChainParams::evm_v2(self.chain_id)
    }

    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<R, PoiClientError> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            params,
        };

        let response: JsonRpcResponse<R> = self
            .http
            .post(&self.url)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            return Err(PoiClientError::Rpc {
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(PoiClientError::NullResult)
    }
}

#[async_trait::async_trait]
impl PoiNodeClient for PoiClient {
    fn list_keys(&self) -> &[ListKey] {
        &self.list_keys
    }

    async fn pois_per_list(
        &self,
        list_keys: &[ListKey],
        datas: &[BlindedCommitmentData],
    ) -> Result<PoisPerListMap, PoiClientError> {
        let mut merged = PoisPerListMap::new();
        for chunk in datas.chunks(POIS_PER_LIST_CHUNK) {
            let page: PoisPerListMap = self
                .call(
                    "ppoi_pois_per_list",
                    GetPoisPerListParams {
                        chain: self.chain(),
                        // alloc-ok: request DTO boundary.
                        list_keys: list_keys.to_vec(),
                        // alloc-ok: request DTO boundary.
                        blinded_commitment_datas: chunk.to_vec(),
                    },
                )
                .await?;
            merged.extend(page);
        }
        Ok(merged)
    }

    async fn merkle_proof(
        &self,
        list_key: &ListKey,
        blinded_commitment: BlindedCommitment,
    ) -> Result<MerkleProof<RailgunMerkleConfig>, PoiClientError> {
        let proofs: Vec<MerkleProof<RailgunMerkleConfig>> = self
            .call(
                "ppoi_merkle_proofs",
                GetMerkleProofsParams {
                    chain: self.chain(),
                    list_key: list_key.clone(),
                    // alloc-ok: request DTO boundary.
                    blinded_commitments: vec![blinded_commitment],
                },
            )
            .await?;

        proofs
            .into_iter()
            .next()
            .ok_or_else(|| PoiClientError::ProofNotFound {
                list_key: list_key.clone(),
                blinded_commitment,
            })
    }

    async fn submit_transact_proof(
        &self,
        list_key: &ListKey,
        data: TransactProofData,
    ) -> Result<(), PoiClientError> {
        let result: Result<serde_json::Value, PoiClientError> = self
            .call(
                "ppoi_submit_transact_proof",
                SubmitTransactProofParams {
                    chain: self.chain(),
                    list_key: list_key.clone(),
                    transact_proof_data: data,
                },
            )
            .await;

        match result {
            // The node acknowledges with a null result.
            Ok(_) | Err(PoiClientError::NullResult) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn validated_txid(&self) -> Result<ValidatedRailgunTxidStatus, PoiClientError> {
        self.call("ppoi_validated_txid", self.chain()).await
    }

    async fn validate_txid_merkleroot(
        &self,
        tree: u32,
        index: u32,
        merkleroot: MerkleRoot,
    ) -> Result<bool, PoiClientError> {
        self.call(
            "ppoi_validate_txid_merkleroot",
            ValidateTxidMerklerootParams {
                chain: self.chain(),
                tree,
                index,
                merkleroot,
            },
        )
        .await
    }
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<P: Serialize> {
    jsonrpc: &'static str,
    method: &'static str,
    id: u64,
    params: P,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<R> {
    result: Option<R>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[cfg(test)]
mod tests {
    use types::{BlindedCommitmentType, U256};

    use super::*;

    #[test]
    fn pois_per_list_params_serialize_in_node_wire_shape() {
        let params = GetPoisPerListParams {
            chain: ChainParams::evm_v2(1),
            list_keys: vec![ListKey::from("test_list")],
            blinded_commitment_datas: vec![BlindedCommitmentData {
                commitment_type: BlindedCommitmentType::Shield,
                blinded_commitment: BlindedCommitment::from(U256::from(1u8)),
            }],
        };

        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "chainType": "0",
                "chainID": "1",
                "txidVersion": "V2_PoseidonMerkle",
                "listKeys": ["test_list"],
                "blindedCommitmentDatas": [{
                    "type": "Shield",
                    "blindedCommitment":
                        "0x0000000000000000000000000000000000000000000000000000000000000001",
                }],
            })
        );
    }

    #[test]
    fn rpc_error_response_is_surfaced() {
        let response: JsonRpcResponse<bool> = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"bad"}}"#,
        )
        .unwrap();
        assert!(response.result.is_none());
        assert_eq!(response.error.unwrap().code, -32000);
    }
}
