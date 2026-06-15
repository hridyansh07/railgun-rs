use core::fmt;

use alloy_primitives::Bytes;

use crate::{
    AssetId, BlindedKey, BlockNumber, CommitmentHash, Nullifier, TypeError, U256, ViewingPublicKey,
};

const TREE_LEAF_CAPACITY: u32 = 65_536;

/// Where a commitment sits in the UTXO Merkle forest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodePosition {
    tree_number: u32,
    leaf_index: u32,
}

impl NodePosition {
    pub fn try_new(tree_number: u32, leaf_index: u32) -> Result<Self, TypeError> {
        if leaf_index >= TREE_LEAF_CAPACITY {
            return Err(TypeError::InvalidNodePosition { leaf_index });
        }

        Ok(Self {
            tree_number,
            leaf_index,
        })
    }

    /// Builds a position, normalizing a `leaf_index` that overflows a tree into the
    /// next tree(s). On-chain indexers can report positions past `TREE_LEAF_CAPACITY`;
    /// this re-splits the global index so the result always satisfies the invariant.
    ///
    /// # Panics
    /// Panics only if the normalized tree number exceeds `u32::MAX` (unreachable for
    /// real chain positions).
    #[must_use]
    pub fn normalized(tree_number: u32, leaf_index: u32) -> Self {
        let global = u64::from(tree_number) * u64::from(TREE_LEAF_CAPACITY) + u64::from(leaf_index);
        let tree_number = u32::try_from(global / u64::from(TREE_LEAF_CAPACITY))
            .expect("normalized tree fits u32");
        let leaf_index =
            u32::try_from(global % u64::from(TREE_LEAF_CAPACITY)).expect("modulo is < 2^32");
        Self {
            tree_number,
            leaf_index,
        }
    }

    pub fn tree_number(self) -> u32 {
        self.tree_number
    }

    pub fn leaf_index(self) -> u32 {
        self.leaf_index
    }
}

/// A note amount that fits the current RAILGUN plaintext value layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NoteValue(u128);

impl NoteValue {
    pub fn new(value: u128) -> Self {
        Self(value)
    }

    pub fn try_from_u256(value: U256) -> Result<Self, TypeError> {
        let bytes = value.to_be_bytes::<32>();
        if bytes[..16].iter().any(|byte| *byte != 0) {
            return Err(TypeError::ValueOverflow);
        }

        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes[16..]);
        Ok(Self(u128::from_be_bytes(out)))
    }

    pub fn as_u128(self) -> u128 {
        self.0
    }

    pub fn as_u256(self) -> U256 {
        U256::from(self.0)
    }
}

/// AES-256-GCM ciphertext as carried by an on-chain commitment event.
#[derive(Debug)]
pub struct Ciphertext {
    pub iv: [u8; 16],
    pub tag: [u8; 16],
    // alloc-ok: per-block ciphertext DTO decoded from a chain event boundary.
    pub data: Vec<Bytes>,
}

/// Whether a commitment originated from a shield, a transact, or an unshield.
///
/// `Unshield` never appears on a [`DecryptedNote`] (unshields produce no UTXO);
/// it exists for POI status queries, where an unshield's blinded commitment is
/// the railgun txid itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlindedCommitmentType {
    Shield,
    Transact,
    Unshield,
}

/// A shield commitment's payload (depositing funds into RAILGUN). ERC20 only.
#[derive(Debug)]
pub struct ShieldBody {
    pub npk: U256,
    pub token: AssetId,
    pub value: U256,
    /// The on-chain shield ciphertext bundle, kept verbatim (each entry a 32-byte word).
    // alloc-ok: full shield ciphertext bundle from a chain event boundary.
    pub encrypted_bundle: Vec<[u8; 32]>,
    pub shield_key: ViewingPublicKey,
}

/// A transact commitment's payload (a private transfer output).
#[derive(Debug)]
pub struct TransactBody {
    pub ciphertext: Ciphertext,
    // alloc-ok: variable-length memo from a chain event boundary.
    pub memo: Bytes,
    pub blinded_sender_key: BlindedKey,
    pub blinded_receiver_key: BlindedKey,
    // alloc-ok: variable-length annotation from a chain event boundary.
    pub annotation: Bytes,
}

/// The kind-specific payload of a leaf.
#[derive(Debug)]
pub enum NodeBody {
    Shield(ShieldBody),
    Transact(TransactBody),
}

/// The smallest complete leaf in the UTXO Merkle forest: where it sits, its Poseidon
/// hash (the merkle leaf value), the block it landed in, and its kind-specific payload.
#[derive(Debug)]
pub struct Node {
    pub position: NodePosition,
    pub hash: CommitmentHash,
    pub block: BlockNumber,
    pub body: NodeBody,
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}:{}] block={} hash={} ",
            self.position.tree_number(),
            self.position.leaf_index(),
            self.block.get(),
            self.hash.as_u256(),
        )?;
        match &self.body {
            NodeBody::Shield(body) => write!(
                f,
                "shield value={} token={:?} bundle_words={}",
                body.value,
                body.token,
                body.encrypted_bundle.len(),
            ),
            NodeBody::Transact(body) => write!(
                f,
                "transact memo={}B annotation={}B data_words={}",
                body.memo.len(),
                body.annotation.len(),
                body.ciphertext.data.len(),
            ),
        }
    }
}

/// An on-chain nullifier event, marking a commitment in `tree_number` as spent.
#[derive(Debug, Clone, Copy)]
pub struct Nullified {
    pub tree_number: u32,
    pub nullifier: Nullifier,
}

/// A note successfully decrypted from a commitment event — one of the wallet's UTXOs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecryptedNote {
    pub position: NodePosition,
    pub value: NoteValue,
    pub asset: AssetId,
    pub random: [u8; 16],
    // alloc-ok: owned memo string carried on the decrypted note DTO.
    pub memo: String,
    pub commitment_hash: CommitmentHash,
    pub note_public_key: U256,
    pub nullifier: Nullifier,
    pub blinded_commitment: U256,
    pub commitment_type: BlindedCommitmentType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_position_exposes_named_accessors() {
        let position = NodePosition::try_new(2, 7).unwrap();
        assert_eq!(position.tree_number(), 2);
        assert_eq!(position.leaf_index(), 7);
    }

    #[test]
    fn node_position_rejects_out_of_range_leaf_index() {
        assert_eq!(
            NodePosition::try_new(0, TREE_LEAF_CAPACITY).unwrap_err(),
            TypeError::InvalidNodePosition {
                leaf_index: TREE_LEAF_CAPACITY
            }
        );
    }

    #[test]
    fn note_value_roundtrips() {
        let value = NoteValue::new(100);
        assert_eq!(value.as_u128(), 100);
        assert_eq!(NoteValue::try_from_u256(value.as_u256()).unwrap(), value);
    }

    #[test]
    fn note_value_rejects_overflow() {
        let overflow = U256::from(u128::MAX) + U256::from(1u8);
        assert_eq!(
            NoteValue::try_from_u256(overflow).unwrap_err(),
            TypeError::ValueOverflow
        );
    }
}
