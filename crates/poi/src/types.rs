//! Wire vocabulary for the POI node JSON-RPC API.
//!
//! Shapes and field names follow kohaku's `poi/types.rs`, which tracks the POI
//! node API: <https://github.com/Railgun-Community/private-proof-of-innocence>.

use std::collections::HashMap;

use crypto::MerkleRoot;
use types::{BlindedCommitmentType, DecryptedNote, RailgunTxid, U256};

/// Identifier of a POI list (a curated innocence list a wallet proves against).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ListKey(String);

impl ListKey {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ListKey {
    fn from(value: &str) -> Self {
        ListKey(value.to_owned())
    }
}

impl From<String> for ListKey {
    fn from(value: String) -> Self {
        ListKey(value)
    }
}

impl std::fmt::Display for ListKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A blinded UTXO commitment — `poseidon(hash, npk, global_position)` — the
/// anonymous handle POI lists track. Serializes as `0x`-prefixed 64-digit hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
pub struct BlindedCommitment(U256);

impl BlindedCommitment {
    /// The blinded commitment a note carries from decryption.
    #[must_use]
    pub fn from_note(note: &DecryptedNote) -> Self {
        BlindedCommitment(note.blinded_commitment)
    }

    /// An unshield's blinded commitment: the railgun txid itself.
    #[must_use]
    pub fn from_unshield(txid: RailgunTxid) -> Self {
        BlindedCommitment(crypto::unshield_blinded_commitment(txid))
    }

    #[must_use]
    pub fn as_u256(self) -> U256 {
        self.0
    }
}

impl From<U256> for BlindedCommitment {
    fn from(value: U256) -> Self {
        BlindedCommitment(value)
    }
}

impl serde::Serialize for BlindedCommitment {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{:064x}", self.0))
    }
}

impl std::fmt::Display for BlindedCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:064x}", self.0)
    }
}

/// Txid tree flavor. Everything here is pinned to V2; V3 changes bound-params
/// hashing and event shapes and is additive later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TxidVersion {
    #[serde(rename = "V2_PoseidonMerkle")]
    V2PoseidonMerkle,
    #[serde(rename = "V3_PoseidonMerkle")]
    V3PoseidonMerkle,
}

/// A UTXO's standing on one POI list. `Ord` ranks best→worst, so `max` across
/// lists is the binding (worst-case) status.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum PoiStatus {
    Valid,
    ProofSubmitted,
    Missing,
    ShieldBlocked,
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
    fn blinded_commitment_serializes_prefixed_and_padded() {
        let bc = BlindedCommitment::from(U256::from(0xabcdu64));
        let json = serde_json::to_string(&bc).unwrap();
        assert_eq!(
            json,
            "\"0x000000000000000000000000000000000000000000000000000000000000abcd\""
        );
    }

    #[test]
    fn poi_status_orders_best_to_worst() {
        assert!(PoiStatus::Valid < PoiStatus::ProofSubmitted);
        assert!(PoiStatus::ProofSubmitted < PoiStatus::Missing);
        assert!(PoiStatus::Missing < PoiStatus::ShieldBlocked);
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
