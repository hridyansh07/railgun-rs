//! Railgun txid math: the txid identifying one on-chain RAILGUN operation, and
//! the leaf hash anchoring that txid in the txid Merkle tree.
//!
//! The txid tree is a parallel forest to the UTXO tree, with the same shape
//! ([`crate::RailgunMerkleConfig`]): one leaf per `RailgunSmartWallet`
//! Transaction event. POI proofs are anchored against its roots.

use types::{RailgunTransaction, RailgunTxid, U256};

use crate::{CryptoError, PoseidonInput, merkle::MerkleConfig, merkle::RailgunMerkleConfig};

/// Maximum circuit inputs/outputs; txid hashing always pads to this width.
const TXID_PAD_WIDTH: usize = 13;

/// Leaves per UTXO tree (`2^16`), the stride of global UTXO positions.
const UTXO_TREE_STRIDE: u64 = 1 << RailgunMerkleConfig::DEPTH;

/// Sentinel tree/position for unshield-only operations (no UTXO outputs).
const UNSHIELD_ONLY_SENTINEL: u64 = 99_999;

/// Sentinel tree/position for pre-transaction POI proofs (operation not yet
/// included on-chain).
const PRE_INCLUSION_SENTINEL: u64 = 199_999;

/// Where an operation's outputs sit in the UTXO forest, for txid leaf hashing.
///
/// `PreInclusion` is used when generating a pre-transaction POI proof (the
/// operation is not on-chain yet); `UnshieldOnly` when the operation created no
/// UTXO outputs; `Included` once the outputs have on-chain positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtxoTreeIndex {
    PreInclusion,
    Included { tree_number: u32, start_index: u32 },
    UnshieldOnly,
}

impl UtxoTreeIndex {
    #[must_use]
    pub fn included(tree_number: u32, start_index: u32) -> Self {
        UtxoTreeIndex::Included {
            tree_number,
            start_index,
        }
    }

    /// The global UTXO position encoded as `tree * 65536 + index` (sentinel
    /// values for the non-included variants).
    #[must_use]
    pub fn global_index(self) -> u64 {
        let (tree_number, start_index) = match self {
            UtxoTreeIndex::Included {
                tree_number,
                start_index,
            } => (u64::from(tree_number), u64::from(start_index)),
            UtxoTreeIndex::PreInclusion => (PRE_INCLUSION_SENTINEL, PRE_INCLUSION_SENTINEL),
            UtxoTreeIndex::UnshieldOnly => (UNSHIELD_ONLY_SENTINEL, UNSHIELD_ONLY_SENTINEL),
        };

        tree_number * UTXO_TREE_STRIDE + start_index
    }
}

/// The railgun txid of one operation:
/// `poseidon(poseidon(nullifiers ⧺ pad), poseidon(commitments ⧺ pad), boundParamsHash)`,
/// each list zero-padded to 13 with the Merkle zero value. Entries beyond 13
/// are ignored, matching the circuit width.
///
/// # Errors
/// Propagates [`CryptoError::Poseidon`].
pub fn railgun_txid(
    nullifiers: &[U256],
    commitments: &[U256],
    bound_params_hash: U256,
) -> Result<RailgunTxid, CryptoError> {
    let nullifiers_hash = padded_hash(nullifiers)?;
    let commitments_hash = padded_hash(commitments)?;
    let txid = (nullifiers_hash, commitments_hash, bound_params_hash).poseidon_hash()?;
    Ok(RailgunTxid::new(txid.as_u256()))
}

/// [`railgun_txid`] over a sync-layer transaction event.
///
/// # Errors
/// Propagates [`CryptoError::Poseidon`].
pub fn railgun_txid_for(transaction: &RailgunTransaction) -> Result<RailgunTxid, CryptoError> {
    railgun_txid(
        &transaction.nullifiers,
        &transaction.commitments,
        transaction.bound_params_hash,
    )
}

/// A txid-tree leaf: `poseidon(txid, utxo_tree_in, global_out_position)`.
///
/// # Errors
/// Propagates [`CryptoError::Poseidon`].
pub fn txid_leaf_hash(
    txid: RailgunTxid,
    utxo_tree_in: u32,
    utxo_out: UtxoTreeIndex,
) -> Result<U256, CryptoError> {
    let leaf = (
        txid.as_u256(),
        U256::from(utxo_tree_in),
        U256::from(utxo_out.global_index()),
    )
        .poseidon_hash()?;
    Ok(leaf.as_u256())
}

/// An unshield's blinded commitment for POI status queries: the railgun txid
/// itself (unshields produce no UTXO commitment to blind).
#[must_use]
pub fn unshield_blinded_commitment(txid: RailgunTxid) -> U256 {
    txid.as_u256()
}

/// Poseidon over `values` zero-padded to the 13-wide circuit shape.
fn padded_hash(values: &[U256]) -> Result<U256, CryptoError> {
    let mut padded = [RailgunMerkleConfig::zero(); TXID_PAD_WIDTH];
    for (slot, value) in padded.iter_mut().zip(values.iter()) {
        *slot = *value;
    }
    Ok(padded.poseidon_hash()?.as_u256())
}

#[cfg(test)]
mod tests {
    use types::uint;

    use super::*;

    // Parity vector from kohaku `crypto::railgun_txid::tests::test_txid`
    // (snapshot `railgun__crypto__railgun_txid__tests__txid.snap`).
    #[test]
    fn railgun_txid_matches_kohaku_vector() {
        let txid = railgun_txid(
            &[
                uint!(
                    13715694855377408371089601959277332264580227086500088662374474180290571297793_U256
                ),
                uint!(
                    4879960293526035536337105771650901564439892825648159183025591237708347140334_U256
                ),
            ],
            &[
                uint!(
                    12207157656628265423438060380057846656543786903997769688185483156243865679225_U256
                ),
                uint!(
                    21704732194337337773381894542943230082317724786316223111256657768939470463625_U256
                ),
                uint!(
                    3419899127455500147715903774774198308673930432280940502846714726325919416502_U256
                ),
            ],
            uint!(
                20104295272660775597730850404771326812479727572119535488383037433725311268740_U256
            ),
        )
        .unwrap();

        assert_eq!(
            txid.as_u256().to_string(),
            "16377560740762083297602124407587012236402803616921752695154194813882621728488"
        );
    }

    #[test]
    fn global_index_encodes_tree_and_position() {
        assert_eq!(UtxoTreeIndex::included(2, 7).global_index(), 2 * 65_536 + 7);
        assert_eq!(
            UtxoTreeIndex::UnshieldOnly.global_index(),
            99_999 * 65_536 + 99_999
        );
        assert_eq!(
            UtxoTreeIndex::PreInclusion.global_index(),
            199_999 * 65_536 + 199_999
        );
    }

    #[test]
    fn txid_leaf_hash_binds_positions() {
        let txid = RailgunTxid::new(U256::from(42u64));
        let included = txid_leaf_hash(txid, 0, UtxoTreeIndex::included(0, 0)).unwrap();
        let pre = txid_leaf_hash(txid, 0, UtxoTreeIndex::PreInclusion).unwrap();
        assert_ne!(included, pre);
    }
}
