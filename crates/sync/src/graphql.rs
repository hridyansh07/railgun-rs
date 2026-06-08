//! Subsquid GraphQL request/response shapes and the mapping to our domain types.
//!
//! Schema + field interpretation mirror kohaku's `subsquid_types.rs` (a working
//! reference), retargeted onto our `types`/`commitments`.

use alloy_primitives::{Address, FixedBytes};
use serde::{Deserialize, Serialize};
use tracing::warn;

use types::{
    AssetId, B256, BlindedKey, BlockNumber, Bytes, Ciphertext, CommitmentHash, Node, NodeBody,
    NodePosition, Nullified, Nullifier, ShieldBody, TransactBody, U256, ViewingPublicKey,
};

use crate::SyncEvent;

#[derive(Serialize)]
pub(crate) struct GraphqlRequest<V: Serialize> {
    pub query: &'static str,
    pub variables: V,
}

#[derive(Deserialize)]
pub(crate) struct GraphqlResponse<T> {
    pub data: Option<T>,
    pub errors: Option<Vec<GraphQlError>>,
}

#[derive(Deserialize)]
pub(crate) struct GraphQlError {
    pub message: String,
}

/// Shared pagination/range variables for the commitment and nullifier queries.
#[derive(Serialize)]
pub(crate) struct QueryVars {
    pub id_gt: String,
    #[serde(rename = "blockNumber_gte")]
    pub block_number_gte: u64,
    #[serde(rename = "blockNumber_lte")]
    pub block_number_lte: u64,
    pub limit: u64,
}

#[derive(Deserialize)]
pub(crate) struct CommitmentsResponse {
    pub commitments: Vec<Commitment>,
}

#[derive(Deserialize)]
pub(crate) struct Commitment {
    pub id: String,
    #[serde(rename = "blockNumber", deserialize_with = "de_string_u64")]
    pub block_number: u64,
    #[serde(deserialize_with = "de_decimal_u256")]
    pub hash: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: u32,
    #[serde(rename = "treePosition")]
    pub tree_position: u32,
    #[serde(flatten)]
    pub kind: CommitmentKind,
}

#[derive(Deserialize)]
#[serde(tag = "__typename")]
pub(crate) enum CommitmentKind {
    ShieldCommitment {
        preimage: ShieldPreimage,
        #[serde(rename = "shieldKey")]
        shield_key: FixedBytes<32>,
        #[serde(rename = "encryptedBundle")]
        encrypted_bundle: Vec<FixedBytes<32>>,
    },
    TransactCommitment {
        ciphertext: TransactCiphertextOuter,
    },
    #[serde(other)]
    Legacy,
}

#[derive(Deserialize)]
pub(crate) struct ShieldPreimage {
    pub npk: FixedBytes<32>,
    #[serde(deserialize_with = "de_decimal_u256")]
    pub value: U256,
    pub token: TokenInfo,
}

#[derive(Deserialize)]
pub(crate) struct TokenInfo {
    #[serde(rename = "tokenAddress")]
    pub token_address: Address,
    #[serde(rename = "tokenType")]
    pub token_type: TokenType,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum TokenType {
    Erc20,
    Erc721,
    Erc1155,
}

#[derive(Deserialize)]
pub(crate) struct TransactCiphertextOuter {
    pub ciphertext: TransactCiphertextInner,
    pub memo: Bytes,
    #[serde(rename = "blindedSenderViewingKey")]
    pub blinded_sender_viewing_key: FixedBytes<32>,
    #[serde(rename = "blindedReceiverViewingKey")]
    pub blinded_receiver_viewing_key: FixedBytes<32>,
    #[serde(rename = "annotationData")]
    pub annotation_data: Bytes,
}

#[derive(Deserialize)]
pub(crate) struct TransactCiphertextInner {
    pub iv: FixedBytes<16>,
    pub tag: FixedBytes<16>,
    pub data: Vec<FixedBytes<32>>,
}

#[derive(Deserialize)]
pub(crate) struct NullifiersResponse {
    pub nullifiers: Vec<NullifierRow>,
}

#[derive(Deserialize)]
pub(crate) struct NullifierRow {
    pub id: String,
    pub nullifier: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: u32,
}

#[derive(Deserialize)]
pub(crate) struct BlockNumberResponse {
    pub transactions: Vec<BlockRow>,
}

#[derive(Deserialize)]
pub(crate) struct BlockRow {
    #[serde(rename = "blockNumber", deserialize_with = "de_string_u64")]
    pub block_number: u64,
}

fn de_string_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let s = String::deserialize(d)?;
    s.parse().map_err(serde::de::Error::custom)
}

fn de_decimal_u256<'de, D: serde::Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
    let s = String::deserialize(d)?;
    U256::from_str_radix(&s, 10).map_err(serde::de::Error::custom)
}

/// Maps a GraphQL commitment to a [`SyncEvent`], or `None` for rows we can't (yet)
/// represent: non-ERC20 shields (our `AssetId` is ERC20-only) and legacy commitments.
pub(crate) fn map_commitment(commitment: Commitment) -> Option<SyncEvent> {
    let position = NodePosition::normalized(commitment.tree_number, commitment.tree_position);
    let hash = CommitmentHash::new(commitment.hash);
    let block = BlockNumber::new(commitment.block_number);

    let body = match commitment.kind {
        CommitmentKind::Legacy => return None,
        CommitmentKind::TransactCommitment { ciphertext } => {
            // alloc-ok: per-block ciphertext data words from a chain event boundary.
            let data = ciphertext
                .ciphertext
                .data
                .iter()
                .map(|chunk| Bytes::copy_from_slice(chunk.as_slice()))
                .collect();
            NodeBody::Transact(TransactBody {
                ciphertext: Ciphertext {
                    iv: ciphertext.ciphertext.iv.0,
                    tag: ciphertext.ciphertext.tag.0,
                    data,
                },
                memo: ciphertext.memo,
                blinded_sender_key: BlindedKey::from_bytes(ciphertext.blinded_sender_viewing_key.0),
                blinded_receiver_key: BlindedKey::from_bytes(
                    ciphertext.blinded_receiver_viewing_key.0,
                ),
                annotation: ciphertext.annotation_data,
            })
        }
        CommitmentKind::ShieldCommitment {
            preimage,
            shield_key,
            encrypted_bundle,
        } => {
            if preimage.token.token_type != TokenType::Erc20 {
                warn!(
                    tree = position.tree_number(),
                    leaf = position.leaf_index(),
                    "skipping non-ERC20 shield commitment"
                );
                return None;
            }
            // alloc-ok: full shield ciphertext bundle kept verbatim.
            let encrypted_bundle = encrypted_bundle.iter().map(|word| word.0).collect();
            NodeBody::Shield(ShieldBody {
                npk: U256::from_be_bytes(preimage.npk.0),
                token: AssetId::erc20(preimage.token.token_address),
                value: preimage.value,
                encrypted_bundle,
                shield_key: ViewingPublicKey::from_bytes(shield_key.0),
            })
        }
    };

    Some(SyncEvent::Commitment(Node {
        position,
        hash,
        block,
        body,
    }))
}

/// Maps a GraphQL nullifier row to a [`SyncEvent`].
pub(crate) fn map_nullifier(row: &NullifierRow) -> SyncEvent {
    SyncEvent::Nullified(Nullified {
        tree_number: row.tree_number,
        nullifier: Nullifier::new(B256::from(row.nullifier.to_be_bytes::<32>())),
    })
}
