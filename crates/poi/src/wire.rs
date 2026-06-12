//! Wire vocabulary for the POI node JSON-RPC API: request/response DTOs only.
//!
//! Shapes and field names track the POI node API:
//! <https://github.com/Railgun-Community/private-proof-of-innocence>.
//! Domain types ([`BlindedCommitment`], [`ListKey`], [`PoiStatus`]) live in
//! `types`; this module is the serde skin around them and migrates to the
//! broadcaster crate with the client.

use std::collections::HashMap;

use crypto::MerkleRoot;
use types::{
    BlindedCommitment, BlindedCommitmentType, DecryptedNote, ListKey, PoiStatus, RailgunTxid,
};

/// Txid tree flavor. Everything here is pinned to V2; V3 changes bound-params
/// hashing and event shapes and is additive later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TxidVersion {
    #[serde(rename = "V2_PoseidonMerkle")]
    V2PoseidonMerkle,
    #[serde(rename = "V3_PoseidonMerkle")]
    V3PoseidonMerkle,
}

/// The chain/version scope every POI request carries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainParams {
    /// `"0"` = EVM.
    pub chain_type: String,
    #[serde(rename = "chainID")]
    pub chain_id: String,
    pub txid_version: TxidVersion,
}

impl ChainParams {
    /// V2 params for an EVM chain.
    #[must_use]
    pub fn evm_v2(chain_id: u64) -> Self {
        ChainParams {
            chain_type: "0".to_owned(),
            chain_id: chain_id.to_string(),
            txid_version: TxidVersion::V2PoseidonMerkle,
        }
    }
}

/// One commitment in a status query: its blinded form plus origin kind.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlindedCommitmentData {
    #[serde(rename = "type")]
    pub commitment_type: BlindedCommitmentType,
    pub blinded_commitment: BlindedCommitment,
}

impl BlindedCommitmentData {
    #[must_use]
    pub fn from_note(note: &DecryptedNote) -> Self {
        BlindedCommitmentData {
            commitment_type: note.commitment_type,
            blinded_commitment: BlindedCommitment::from_note(note),
        }
    }
}

/// `ppoi_pois_per_list` params.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPoisPerListParams {
    #[serde(flatten)]
    pub chain: ChainParams,
    pub list_keys: Vec<ListKey>,
    pub blinded_commitment_datas: Vec<BlindedCommitmentData>,
}

/// `ppoi_merkle_proofs` params.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetMerkleProofsParams {
    #[serde(flatten)]
    pub chain: ChainParams,
    pub list_key: ListKey,
    pub blinded_commitments: Vec<BlindedCommitment>,
}

/// `ppoi_validated_txid` response: the POI node's latest validated txid-tree
/// position (a flat `tree * 65536 + leaf` index) and the root at it.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ValidatedRailgunTxidStatus {
    #[serde(rename = "validatedTxidIndex")]
    pub index: u32,
    #[serde(rename = "validatedMerkleroot")]
    pub merkleroot: MerkleRoot,
}

impl ValidatedRailgunTxidStatus {
    #[must_use]
    pub fn tree(&self) -> u32 {
        self.index >> 16
    }

    #[must_use]
    pub fn leaf_index(&self) -> u32 {
        self.index & 0xFFFF
    }
}

/// `ppoi_validate_txid_merkleroot` params.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateTxidMerklerootParams {
    #[serde(flatten)]
    pub chain: ChainParams,
    pub tree: u32,
    pub index: u32,
    pub merkleroot: MerkleRoot,
}

/// `ppoi_pois_per_list` response: status per (blinded commitment, list key).
pub type PoisPerListMap = HashMap<BlindedCommitment, HashMap<ListKey, PoiStatus>>;

/// `ppoi_submit_transact_proof` params.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitTransactProofParams {
    #[serde(flatten)]
    pub chain: ChainParams,
    pub list_key: ListKey,
    pub transact_proof_data: TransactProofData,
}

/// A POI proof package for one operation on one list.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactProofData {
    #[serde(rename = "snarkProof")]
    pub snark_proof: railgun_prover::Proof,
    /// POI tree roots the input membership proofs were generated against.
    pub poi_merkleroots: Vec<MerkleRoot>,
    /// Txid tree root the inclusion proof was generated against.
    pub txid_merkleroot: MerkleRoot,
    /// Flat global index (`tree * 65536 + leaf`) of the txid-tree snapshot the
    /// root corresponds to — not the leaf index of this operation's txid.
    pub txid_merkleroot_index: u64,
    pub blinded_commitments_out: Vec<BlindedCommitment>,
    /// The operation's railgun txid if it has an unshield, else zero.
    #[serde(with = "txid_hex")]
    pub railgun_txid_if_has_unshield: RailgunTxid,
}

/// Bare 64-digit hex for [`RailgunTxid`] (kohaku's `Txid` wire format; accepts
/// `0x` prefixes on input).
mod txid_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    use types::{RailgunTxid, U256};

    pub fn serialize<S: Serializer>(value: &RailgunTxid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:064x}", value.as_u256()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<RailgunTxid, D::Error> {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let value = U256::from_str_radix(s, 16).map_err(serde::de::Error::custom)?;
        Ok(RailgunTxid::new(value))
    }
}

#[cfg(test)]
mod tests {
    use types::U256;

    use super::*;

    #[test]
    fn chain_params_serialize_in_node_wire_shape() {
        let params = ChainParams::evm_v2(11_155_111);
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "chainType": "0",
                "chainID": "11155111",
                "txidVersion": "V2_PoseidonMerkle",
            })
        );
    }

    #[test]
    fn pois_per_list_deserializes_from_node_response() {
        let json = r#"{
            "0x000000000000000000000000000000000000000000000000000000000000abcd": {
                "test_list": "Valid",
                "other_list": "ShieldBlocked"
            }
        }"#;
        let map: PoisPerListMap = serde_json::from_str(json).unwrap();
        let statuses = &map[&BlindedCommitment::from(U256::from(0xabcdu64))];
        assert_eq!(statuses[&ListKey::from("test_list")], PoiStatus::Valid);
        assert_eq!(
            statuses[&ListKey::from("other_list")],
            PoiStatus::ShieldBlocked
        );
    }

    #[test]
    fn validated_txid_status_splits_flat_index() {
        let status: ValidatedRailgunTxidStatus = serde_json::from_str(
            r#"{"validatedTxidIndex": 131074, "validatedMerkleroot": "0123"}"#,
        )
        .unwrap();
        assert_eq!(status.tree(), 2);
        assert_eq!(status.leaf_index(), 2);
    }
}
