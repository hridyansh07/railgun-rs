//! POI circuit witness assembly, ending at the [`railgun_prover::CircuitProver`]
//! seam.
//!
//! Field set, signal names, and padding rules are kohaku's `PoiCircuitInputs`
//! / the engine's `formatPOIInputs`, bit-for-bit: nullifiers, commitments,
//! npks, randoms, positions, and POI roots pad with the Railgun merkle zero;
//! values and POI proof indices pad with plain `0`; absent POI proof paths pad
//! with depth-16 merkle-zero columns.
//!
//! The txid-tree proof depends on where the operation stands:
//! - **Pre-transaction** ([`UtxoTreeIndex::PreInclusion`] / `UnshieldOnly`):
//!   the operation is not on-chain, so the engine's *dummy* proof is used —
//!   all-zero path elements folded over the leaf (not a zero-subtree ladder).
//! - **Spent POI** ([`UtxoTreeIndex::Included`]): a real membership proof from
//!   the local txid tree ([`Txids`]).

use std::collections::HashMap;

use crypto::{
    MerkleConfig, MerkleProof, MerkleRoot, RailgunMerkleConfig, UtxoTreeIndex, railgun_txid,
    txid_leaf_hash,
};
use database::Reader;
use railgun_prover::{ArtifactId, CircuitKind, CircuitProver, ProveRequest, ProverError};
use types::{BabyJubJubPoint, DecryptedNote, PoseidonHash, RailgunTxid, U256};

use crate::txid::{TxidError, Txids};

const DEPTH: usize = RailgunMerkleConfig::DEPTH;

#[derive(Debug, thiserror::Error)]
pub enum PoiInputsError {
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error(transparent)]
    Txid(#[from] TxidError),
    #[error("txid {0} is not indexed in the txid tree")]
    TxidNotIndexed(U256),
    #[error("witness serialization failed: {0}")]
    Witness(#[from] serde_json::Error),
    #[error(transparent)]
    Prover(#[from] ProverError),
}

/// A spend input with the POI tree membership proof fetched from the node
/// (`ppoi_merkle_proofs`) for the list being proven.
#[derive(Debug, Clone)]
pub struct PoiNote {
    pub note: DecryptedNote,
    pub poi_proof: MerkleProof<RailgunMerkleConfig>,
}

/// Assembled POI circuit witness for one operation on one list.
#[derive(Debug)]
pub struct PoiCircuitInputs {
    // Public inputs.
    pub railgun_txid_merkleroot_after_transaction: MerkleRoot,
    /// Unpadded POI roots (the wire value for `TransactProofData`).
    pub poi_merkleroots: Vec<MerkleRoot>,
    poi_merkleroots_padded: Vec<U256>,

    // Private inputs (padded to the circuit size at construction).
    bound_params_hash: U256,
    /// Padded; exposed for circuit-size selection and txid recomputation.
    pub nullifiers: Vec<U256>,
    pub commitments: Vec<U256>,
    spending_public_key: [U256; 2],
    nullifying_key: U256,
    token: U256,
    randoms_in: Vec<U256>,
    values_in: Vec<U256>,
    utxo_positions_in: Vec<U256>,
    utxo_tree_in: U256,
    npks_out: Vec<U256>,
    values_out: Vec<U256>,
    utxo_batch_global_start_position_out: U256,
    pub railgun_txid_if_has_unshield: RailgunTxid,
    railgun_txid_merkle_proof_indices: U256,
    railgun_txid_merkle_proof_path_elements: Vec<U256>,
    poi_in_merkle_proof_indices: Vec<U256>,
    poi_in_merkle_proof_path_elements: Vec<Vec<U256>>,

    size: u8,
}

impl PoiCircuitInputs {
    /// Assembles the witness. POI proofs ride in on `in_notes`; the txid proof
    /// is built locally — a dummy proof for pre-inclusion operations, a real
    /// txid-tree proof (read off `view`) for included ones.
    ///
    /// `out_commitments` carries every output commitment (including an
    /// unshield's); `out_npks`/`out_values` carry note outputs only.
    ///
    /// # Errors
    /// [`PoiInputsError::TxidNotIndexed`] if `utxo_tree_out` is `Included` but
    /// the operation's txid is not in the tree; otherwise propagates the
    /// failing layer.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts<R: Reader>(
        spending_public_key: BabyJubJubPoint,
        nullifying_key: PoseidonHash,
        utxo_tree_in: u32,
        bound_params_hash: U256,
        in_notes: &[PoiNote],
        out_commitments: &[U256],
        out_npks: &[U256],
        out_values: &[U256],
        token_hash: U256,
        has_unshield: bool,
        utxo_tree_out: UtxoTreeIndex,
        view: &R,
    ) -> Result<Self, PoiInputsError> {
        // alloc-ok: witness assembly is a per-proof DTO boundary throughout.
        let nullifiers: Vec<U256> = in_notes
            .iter()
            .map(|poi_note| U256::from_be_bytes(poi_note.note.nullifier.as_b256().0))
            .collect();

        let txid = railgun_txid(&nullifiers, out_commitments, bound_params_hash)?;
        let leaf_hash = txid_leaf_hash(txid, utxo_tree_in, utxo_tree_out)?;

        let txid_proof = match utxo_tree_out {
            UtxoTreeIndex::Included { .. } => {
                let txids = Txids::new(view);
                let (tree, leaf) = txids
                    .txid_position(txid)?
                    .ok_or(PoiInputsError::TxidNotIndexed(txid.as_u256()))?;
                txids.merkle_proof(tree, leaf)?
            }
            UtxoTreeIndex::PreInclusion | UtxoTreeIndex::UnshieldOnly => {
                dummy_merkle_proof(leaf_hash)
            }
        };

        let poi_merkleroots: Vec<MerkleRoot> =
            in_notes.iter().map(|note| note.poi_proof.root).collect();
        let poi_in_merkle_proof_indices: Vec<U256> =
            in_notes.iter().map(|note| note.poi_proof.indices).collect();
        let poi_in_merkle_proof_path_elements: Vec<Vec<U256>> = in_notes
            .iter()
            .map(|note| note.poi_proof.elements.clone())
            .collect();

        let randoms_in: Vec<U256> = in_notes
            .iter()
            .map(|note| U256::from_be_slice(&note.note.random))
            .collect();
        let values_in: Vec<U256> = in_notes
            .iter()
            .map(|note| note.note.value.as_u256())
            .collect();
        let utxo_positions_in: Vec<U256> = in_notes
            .iter()
            .map(|note| U256::from(note.note.position.leaf_index()))
            .collect();

        let size = circuit_size(nullifiers.len(), out_commitments.len());
        let max = usize::from(size);
        let zero = RailgunMerkleConfig::zero();

        Ok(PoiCircuitInputs {
            railgun_txid_merkleroot_after_transaction: txid_proof.root,
            poi_merkleroots: poi_merkleroots.clone(),
            poi_merkleroots_padded: pad(
                poi_merkleroots.iter().map(|root| root.as_u256()).collect(),
                max,
                zero,
            ),
            bound_params_hash,
            nullifiers: pad(nullifiers, max, zero),
            commitments: pad(out_commitments.to_vec(), max, zero),
            spending_public_key: [spending_public_key.x(), spending_public_key.y()],
            nullifying_key: nullifying_key.as_u256(),
            token: token_hash,
            randoms_in: pad(randoms_in, max, zero),
            values_in: pad(values_in, max, U256::ZERO),
            utxo_positions_in: pad(utxo_positions_in, max, zero),
            utxo_tree_in: U256::from(utxo_tree_in),
            npks_out: pad(out_npks.to_vec(), max, zero),
            values_out: pad(out_values.to_vec(), max, U256::ZERO),
            utxo_batch_global_start_position_out: U256::from(utxo_tree_out.global_index()),
            railgun_txid_if_has_unshield: if has_unshield {
                txid
            } else {
                RailgunTxid::new(U256::ZERO)
            },
            railgun_txid_merkle_proof_indices: txid_proof.indices,
            railgun_txid_merkle_proof_path_elements: txid_proof.elements,
            poi_in_merkle_proof_indices: pad(poi_in_merkle_proof_indices, max, U256::ZERO),
            poi_in_merkle_proof_path_elements: pad_paths(poi_in_merkle_proof_path_elements, max),
            size,
        })
    }

    /// The circuit variant this witness fits: 3 (mini) or 13 (full).
    #[must_use]
    pub fn circuit_size(&self) -> u8 {
        self.size
    }

    /// The 20 circuit signals under their circom names (kohaku-exact),
    /// 2D paths flattened row-major.
    #[must_use]
    pub fn to_circuit_signals(&self) -> HashMap<String, Vec<U256>> {
        // alloc-ok: per-proof witness DTO.
        let mut signals = HashMap::with_capacity(20);
        signals.insert(
            "anyRailgunTxidMerklerootAfterTransaction".to_owned(),
            vec![self.railgun_txid_merkleroot_after_transaction.as_u256()],
        );
        signals.insert("boundParamsHash".to_owned(), vec![self.bound_params_hash]);
        signals.insert("nullifiers".to_owned(), self.nullifiers.clone());
        signals.insert("commitmentsOut".to_owned(), self.commitments.clone());
        signals.insert(
            "spendingPublicKey".to_owned(),
            self.spending_public_key.to_vec(),
        );
        signals.insert("nullifyingKey".to_owned(), vec![self.nullifying_key]);
        signals.insert("token".to_owned(), vec![self.token]);
        signals.insert("randomsIn".to_owned(), self.randoms_in.clone());
        signals.insert("valuesIn".to_owned(), self.values_in.clone());
        signals.insert("utxoPositionsIn".to_owned(), self.utxo_positions_in.clone());
        signals.insert("utxoTreeIn".to_owned(), vec![self.utxo_tree_in]);
        signals.insert("npksOut".to_owned(), self.npks_out.clone());
        signals.insert("valuesOut".to_owned(), self.values_out.clone());
        signals.insert(
            "utxoBatchGlobalStartPositionOut".to_owned(),
            vec![self.utxo_batch_global_start_position_out],
        );
        signals.insert(
            "railgunTxidIfHasUnshield".to_owned(),
            vec![self.railgun_txid_if_has_unshield.as_u256()],
        );
        signals.insert(
            "railgunTxidMerkleProofIndices".to_owned(),
            vec![self.railgun_txid_merkle_proof_indices],
        );
        signals.insert(
            "railgunTxidMerkleProofPathElements".to_owned(),
            self.railgun_txid_merkle_proof_path_elements.clone(),
        );
        signals.insert(
            "poiMerkleroots".to_owned(),
            self.poi_merkleroots_padded.clone(),
        );
        signals.insert(
            "poiInMerkleProofIndices".to_owned(),
            self.poi_in_merkle_proof_indices.clone(),
        );
        signals.insert(
            "poiInMerkleProofPathElements".to_owned(),
            self.poi_in_merkle_proof_path_elements
                .iter()
                .flatten()
                .copied()
                .collect(),
        );
        signals
    }

    /// The witness as snarkjs-style JSON (decimal strings), the encoding
    /// handed across the prover seam.
    ///
    /// # Errors
    /// Propagates [`PoiInputsError::Witness`].
    pub fn witness_json(&self) -> Result<Vec<u8>, PoiInputsError> {
        let signals = self.to_circuit_signals();
        // alloc-ok: per-proof witness DTO.
        let decimal: HashMap<&str, Vec<String>> = signals
            .iter()
            .map(|(name, values)| {
                (
                    name.as_str(),
                    values.iter().map(ToString::to_string).collect(),
                )
            })
            .collect();
        Ok(serde_json::to_vec(&decimal)?)
    }

    /// Generates the Groth16 POI proof through the [`CircuitProver`] seam.
    ///
    /// # Errors
    /// Propagates [`PoiInputsError`].
    pub fn prove(
        &self,
        prover: &dyn CircuitProver,
    ) -> Result<railgun_prover::Proof, PoiInputsError> {
        let witness = self.witness_json()?;
        let proof = prover.prove(ProveRequest {
            artifact: ArtifactId {
                circuit: CircuitKind::ProofOfInnocence { size: self.size },
            },
            witness_inputs: &witness,
        })?;
        Ok(proof)
    }
}

/// 3 (mini) if the operation fits 3×3, else 13 (full).
fn circuit_size(nullifiers: usize, commitments: usize) -> u8 {
    if nullifiers <= 3 && commitments <= 3 {
        3
    } else {
        13
    }
}

fn pad(mut values: Vec<U256>, target: usize, fill: U256) -> Vec<U256> {
    while values.len() < target {
        values.push(fill);
    }
    values
}

fn pad_paths(mut paths: Vec<Vec<U256>>, target: usize) -> Vec<Vec<U256>> {
    while paths.len() < target {
        // alloc-ok: fixed depth-16 zero column, only for absent inputs.
        paths.push(vec![RailgunMerkleConfig::zero(); DEPTH]);
    }
    paths
}

/// The engine's `createDummyMerkleProof`: all-zero path elements folded over
/// the leaf (`root = H(...H(H(leaf, 0), 0)..., 0)`), indices `0`. Used for
/// pre-transaction POIs, whose operation has no on-chain txid position yet.
#[must_use]
pub fn dummy_merkle_proof(leaf: U256) -> MerkleProof<RailgunMerkleConfig> {
    // alloc-ok: fixed depth-16 dummy path.
    let elements = vec![U256::ZERO; DEPTH];
    let mut root = leaf;
    for element in &elements {
        root = RailgunMerkleConfig::hash(root, *element);
    }
    MerkleProof::new(leaf, elements, U256::ZERO, MerkleRoot::new(root))
}
