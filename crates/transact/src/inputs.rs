//! Transact circuit witness assembly, ending at the [`railgun_prover::CircuitProver`]
//! seam. Field set + signal names mirror kohaku's `TransactCircuitInputs`
//! (`circuit/inputs/transact_inputs.rs`) bit-for-bit.
//!
//! Unlike POI, transact circuits are sized per-`(inputs, outputs)`, so the witness
//! uses exact counts — no padding. The spend-authorization signature signs
//! `poseidon([merkleRoot, boundParamsHash, ...nullifiers, ...commitmentsOut])`; that
//! arity (`2 + nullifiers + commitments`) is bounded by the Poseidon engine to 13,
//! so a transact here carries at most `nullifiers + commitments <= 11`.

use std::collections::HashMap;

use crypto::{
    MAX_POSEIDON_INPUTS, MerkleConfig, MerkleProof, MerkleRoot, PoseidonInput, RailgunMerkleConfig,
    SpendingKeyPublicKey, SpendingKeySign, commitment,
};
use railgun_prover::{ArtifactId, CircuitKind, CircuitProver, Proof, ProveRequest};
use types::{AssetId, DecryptedNote, NoteValue, PoseidonHash, SpendingKey, U256};

use crate::error::TransactInputsError;

/// A spend input: the decrypted note plus its UTXO-tree membership proof.
#[derive(Debug, Clone)]
pub struct TransactInputNote {
    pub note: DecryptedNote,
    pub proof: MerkleProof<RailgunMerkleConfig>,
}

/// An output note's witness facet — its note public key and value. The encrypted
/// ciphertext that rides on-chain is handled separately (see
/// [`crate::bound_params_hash`]).
#[derive(Debug, Clone, Copy)]
pub struct TransactOutputNote {
    pub npk: U256,
    pub value: NoteValue,
}

/// Assembled transact circuit witness for one operation.
#[derive(Debug)]
pub struct TransactCircuitInputs {
    // Public inputs.
    pub merkleroot: MerkleRoot,
    pub bound_params_hash: U256,
    pub nullifiers: Vec<U256>,
    pub commitments_out: Vec<U256>,

    // Private inputs.
    token: U256,
    public_key: [U256; 2],
    signature: [U256; 3],
    random_in: Vec<U256>,
    value_in: Vec<U256>,
    path_elements: Vec<Vec<U256>>,
    leaves_indices: Vec<U256>,
    nullifying_key: U256,
    npk_out: Vec<U256>,
    value_out: Vec<U256>,
}

impl TransactCircuitInputs {
    /// Assembles the witness from pre-selected inputs/outputs. `bound_params_hash` is
    /// computed up front (it is part of the signed message); UTXO membership proofs
    /// ride in on `inputs`, all against the same tree root.
    ///
    /// # Errors
    /// [`TransactInputsError::Empty`] if `inputs` or `outputs` is empty;
    /// [`TransactInputsError::InconsistentRoot`] if the input proofs disagree on the
    /// tree root; [`TransactInputsError::AssetMismatch`] if an input note's asset is
    /// not `asset`; [`TransactInputsError::ProofShape`] if an input proof does not
    /// have exactly [`RailgunMerkleConfig::DEPTH`] siblings;
    /// [`TransactInputsError::TooManyNotes`] if the signed-message arity exceeds the
    /// circuit/poseidon limit; propagates [`crypto::CryptoError`] from note hashing /
    /// signing.
    pub fn from_parts(
        asset: AssetId,
        spending_key: &SpendingKey,
        nullifying_key: PoseidonHash,
        bound_params_hash: U256,
        inputs: &[TransactInputNote],
        outputs: &[TransactOutputNote],
    ) -> Result<Self, TransactInputsError> {
        let Some(first) = inputs.first() else {
            return Err(TransactInputsError::Empty);
        };
        if outputs.is_empty() {
            return Err(TransactInputsError::Empty);
        }
        let merkleroot = first.proof.root;
        if inputs.iter().any(|input| input.proof.root != merkleroot) {
            return Err(TransactInputsError::InconsistentRoot);
        }
        // Every input must spend the transact's asset; the token signal and all output
        // commitments are built from that single `asset`, so a mismatched input would
        // bind a note to the wrong token.
        if inputs.iter().any(|input| input.note.asset != asset) {
            return Err(TransactInputsError::AssetMismatch);
        }
        // Each proof must carry exactly DEPTH siblings, or the flattened `pathElements`
        // signal would be silently mis-shaped.
        if let Some(input) = inputs
            .iter()
            .find(|input| input.proof.elements.len() != RailgunMerkleConfig::DEPTH)
        {
            return Err(TransactInputsError::ProofShape {
                got: input.proof.elements.len(),
                expected: RailgunMerkleConfig::DEPTH,
            });
        }

        // Witness assembly is a per-note DTO boundary throughout; allocation is fine here.
        let nullifiers: Vec<U256> = inputs
            .iter()
            .map(|input| U256::from_be_bytes(input.note.nullifier.as_b256().0))
            .collect();
        let commitments_out: Vec<U256> = outputs
            .iter()
            .map(|out| Ok(commitment::note_hash(out.npk, asset, out.value)?.as_u256()))
            .collect::<Result<_, crypto::CryptoError>>()?;

        // The signed message is poseidon([merkleRoot, boundParamsHash, ..nullifiers,
        // ..commitments]); its arity must stay within the engine's Poseidon cap, so
        // reject oversize here with a typed error instead of an opaque hashing failure.
        if 2 + nullifiers.len() + commitments_out.len() > MAX_POSEIDON_INPUTS {
            return Err(TransactInputsError::TooManyNotes {
                inputs: nullifiers.len(),
                outputs: commitments_out.len(),
            });
        }

        let public = spending_key.public_key();

        // Spend authorization signs poseidon([merkleRoot, boundParamsHash, ..nullifiers, ..commitments]).
        let mut unsigned = Vec::with_capacity(2 + nullifiers.len() + commitments_out.len());
        unsigned.push(merkleroot.as_u256());
        unsigned.push(bound_params_hash);
        unsigned.extend_from_slice(&nullifiers);
        unsigned.extend_from_slice(&commitments_out);
        let message = unsigned.as_slice().poseidon_hash()?.as_u256();
        let signature = spending_key.sign(message)?;

        let random_in = inputs
            .iter()
            .map(|input| U256::from_be_slice(&input.note.random))
            .collect();
        let value_in = inputs
            .iter()
            .map(|input| input.note.value.as_u256())
            .collect();
        let path_elements = inputs
            .iter()
            .map(|input| input.proof.elements.clone())
            .collect();
        let leaves_indices = inputs.iter().map(|input| input.proof.indices).collect();
        let npk_out = outputs.iter().map(|out| out.npk).collect();
        let value_out = outputs.iter().map(|out| out.value.as_u256()).collect();

        Ok(TransactCircuitInputs {
            merkleroot,
            bound_params_hash,
            nullifiers,
            commitments_out,
            token: asset.token_hash(),
            public_key: [public.x(), public.y()],
            signature: [signature.r8_x, signature.r8_y, signature.s],
            random_in,
            value_in,
            path_elements,
            leaves_indices,
            nullifying_key: nullifying_key.as_u256(),
            npk_out,
            value_out,
        })
    }

    /// The 14 circuit signals under their circom names (kohaku-exact); the 2D
    /// `pathElements` is flattened row-major.
    #[must_use]
    pub fn to_circuit_signals(&self) -> HashMap<String, Vec<U256>> {
        let mut signals = HashMap::with_capacity(14);
        signals.insert("merkleRoot".to_owned(), vec![self.merkleroot.as_u256()]);
        signals.insert("boundParamsHash".to_owned(), vec![self.bound_params_hash]);
        signals.insert("nullifiers".to_owned(), self.nullifiers.clone());
        signals.insert("commitmentsOut".to_owned(), self.commitments_out.clone());
        signals.insert("token".to_owned(), vec![self.token]);
        signals.insert("publicKey".to_owned(), self.public_key.to_vec());
        signals.insert("signature".to_owned(), self.signature.to_vec());
        signals.insert("randomIn".to_owned(), self.random_in.clone());
        signals.insert("valueIn".to_owned(), self.value_in.clone());
        signals.insert(
            "pathElements".to_owned(),
            self.path_elements.iter().flatten().copied().collect(),
        );
        signals.insert("leavesIndices".to_owned(), self.leaves_indices.clone());
        signals.insert("nullifyingKey".to_owned(), vec![self.nullifying_key]);
        signals.insert("npkOut".to_owned(), self.npk_out.clone());
        signals.insert("valueOut".to_owned(), self.value_out.clone());
        signals
    }

    /// The witness as snarkjs-style JSON (decimal strings) — the encoding handed
    /// across the prover seam.
    ///
    /// # Errors
    /// Propagates [`TransactInputsError::Witness`].
    pub fn witness_json(&self) -> Result<Vec<u8>, TransactInputsError> {
        let signals = self.to_circuit_signals();
        // alloc-ok: per-signal decimal strings at the prover-seam DTO boundary.
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

    /// Generates the Groth16 transact proof through the [`CircuitProver`] seam,
    /// selecting the `inputs × outputs` circuit from the witness counts.
    ///
    /// # Errors
    /// Propagates [`TransactInputsError`].
    ///
    /// # Panics
    /// Never in practice: `from_parts` is the only constructor and caps the note
    /// counts at `MAX_POSEIDON_INPUTS` (13), so they always fit in the circuit
    /// selector's `u8` fields.
    pub fn prove(&self, prover: &dyn CircuitProver) -> Result<Proof, TransactInputsError> {
        let witness = self.witness_json()?;
        let proof = prover.prove(ProveRequest {
            artifact: ArtifactId {
                // `from_parts` is the only constructor and caps the counts at
                // MAX_POSEIDON_INPUTS (13), so both always fit in a u8.
                circuit: CircuitKind::Transact {
                    inputs: u8::try_from(self.nullifiers.len())
                        .expect("note count bounded by MAX_POSEIDON_INPUTS"),
                    outputs: u8::try_from(self.commitments_out.len())
                        .expect("note count bounded by MAX_POSEIDON_INPUTS"),
                },
            },
            witness_inputs: &witness,
        })?;
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use crypto::PoseidonInput;
    use railgun_prover::ProverError;
    use types::{B256, BlindedCommitmentType, CommitmentHash, NodePosition, Nullifier};

    use super::*;

    fn test_asset() -> AssetId {
        AssetId::erc20(
            "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
        )
    }

    fn input_note(
        nullifier_byte: u8,
        random: [u8; 16],
        value: u128,
        root: U256,
    ) -> TransactInputNote {
        let note = DecryptedNote {
            position: NodePosition::try_new(0, 0).unwrap(),
            value: NoteValue::new(value),
            asset: test_asset(),
            random,
            memo: String::new(),
            commitment_hash: CommitmentHash::new(U256::ZERO),
            note_public_key: U256::ZERO,
            nullifier: Nullifier::new(B256::from([nullifier_byte; 32])),
            blinded_commitment: U256::ZERO,
            commitment_type: BlindedCommitmentType::Transact,
        };
        TransactInputNote {
            note,
            proof: test_proof(root),
        }
    }

    // A full-depth membership proof (DEPTH siblings) so it passes the proof-shape
    // check; the first two siblings stay `7, 8` (the rest zero) so the `pathElements`
    // assertion stays legible.
    fn test_proof(root: U256) -> MerkleProof<RailgunMerkleConfig> {
        let mut elements = vec![U256::ZERO; RailgunMerkleConfig::DEPTH];
        elements[0] = U256::from(7u8);
        elements[1] = U256::from(8u8);
        MerkleProof::<RailgunMerkleConfig>::new(
            U256::ZERO,
            elements,
            U256::from(3u8),
            MerkleRoot::new(root),
        )
    }

    fn sample_witness() -> TransactCircuitInputs {
        let spending_key = SpendingKey::from_bytes([1u8; 32]);
        let nullifying = PoseidonHash::new(U256::from(7u64));
        let inputs = vec![input_note(9, [3u8; 16], 500, U256::from(42u8))];
        let outputs = vec![
            TransactOutputNote {
                npk: U256::from(111u64),
                value: NoteValue::new(300),
            },
            TransactOutputNote {
                npk: U256::from(222u64),
                value: NoteValue::new(200),
            },
        ];
        TransactCircuitInputs::from_parts(
            test_asset(),
            &spending_key,
            nullifying,
            U256::from(12345u64),
            &inputs,
            &outputs,
        )
        .unwrap()
    }

    // The witness must assemble the signed message in kohaku's exact order and shape
    // each signal correctly. The signature reuses the parity-locked `SpendingKeySign`.
    #[test]
    fn assembles_signed_message_and_signals() {
        let asset = test_asset();
        let spending_key = SpendingKey::from_bytes([1u8; 32]);
        let nullifying = PoseidonHash::new(U256::from(7u64));
        let root = U256::from(42u8);
        let bphash = U256::from(12345u64);

        let witness = sample_witness();
        let signals = witness.to_circuit_signals();

        // Independently recompute nullifiers, commitments, signed message, signature.
        let n0 = U256::from_be_bytes([9u8; 32]);
        let c0 = commitment::note_hash(U256::from(111u64), asset, NoteValue::new(300))
            .unwrap()
            .as_u256();
        let c1 = commitment::note_hash(U256::from(222u64), asset, NoteValue::new(200))
            .unwrap()
            .as_u256();
        let unsigned = vec![root, bphash, n0, c0, c1];
        let message = unsigned.as_slice().poseidon_hash().unwrap().as_u256();
        let sig = spending_key.sign(message).unwrap();
        let public = spending_key.public_key();

        assert_eq!(signals["signature"], vec![sig.r8_x, sig.r8_y, sig.s]);
        assert_eq!(signals["merkleRoot"], vec![root]);
        assert_eq!(signals["boundParamsHash"], vec![bphash]);
        assert_eq!(signals["nullifiers"], vec![n0]);
        assert_eq!(signals["commitmentsOut"], vec![c0, c1]);
        assert_eq!(signals["token"], vec![asset.token_hash()]);
        assert_eq!(signals["publicKey"], vec![public.x(), public.y()]);
        assert_eq!(signals["nullifyingKey"], vec![nullifying.as_u256()]);
        assert_eq!(signals["randomIn"], vec![U256::from_be_slice(&[3u8; 16])]);
        assert_eq!(signals["valueIn"], vec![U256::from(500u64)]);
        let mut expected_path = vec![U256::ZERO; RailgunMerkleConfig::DEPTH];
        expected_path[0] = U256::from(7u8);
        expected_path[1] = U256::from(8u8);
        assert_eq!(signals["pathElements"], expected_path);
        assert_eq!(signals["leavesIndices"], vec![U256::from(3u8)]);
        assert_eq!(
            signals["npkOut"],
            vec![U256::from(111u64), U256::from(222u64)]
        );
        assert_eq!(
            signals["valueOut"],
            vec![U256::from(300u64), U256::from(200u64)]
        );
        assert_eq!(signals.len(), 14);
    }

    #[test]
    fn empty_inputs_or_outputs_rejected() {
        let err = TransactCircuitInputs::from_parts(
            test_asset(),
            &SpendingKey::from_bytes([1u8; 32]),
            PoseidonHash::new(U256::ZERO),
            U256::ZERO,
            &[],
            &[TransactOutputNote {
                npk: U256::from(1u8),
                value: NoteValue::new(1),
            }],
        )
        .unwrap_err();
        assert!(matches!(err, TransactInputsError::Empty));
    }

    // An input note spending a different asset than the transact `asset` is rejected
    // rather than silently bound to the wrong token signal.
    #[test]
    fn input_asset_mismatch_rejected() {
        let other_asset = AssetId::erc20(
            "0x00000000000000000000000000000000000000ff"
                .parse()
                .unwrap(),
        );
        let mut input = input_note(9, [3u8; 16], 500, U256::from(42u8));
        input.note.asset = other_asset;

        let err = TransactCircuitInputs::from_parts(
            test_asset(),
            &SpendingKey::from_bytes([1u8; 32]),
            PoseidonHash::new(U256::from(7u64)),
            U256::from(12345u64),
            &[input],
            &[TransactOutputNote {
                npk: U256::from(1u8),
                value: NoteValue::new(1),
            }],
        )
        .unwrap_err();
        assert!(matches!(err, TransactInputsError::AssetMismatch));
    }

    // A proof whose sibling count is not DEPTH is rejected before it can flatten into
    // a mis-shaped `pathElements` signal.
    #[test]
    fn short_merkle_proof_rejected() {
        let mut input = input_note(9, [3u8; 16], 500, U256::from(42u8));
        input.proof = MerkleProof::<RailgunMerkleConfig>::new(
            U256::ZERO,
            vec![U256::from(7u8), U256::from(8u8)],
            U256::from(3u8),
            MerkleRoot::new(U256::from(42u8)),
        );

        let err = TransactCircuitInputs::from_parts(
            test_asset(),
            &SpendingKey::from_bytes([1u8; 32]),
            PoseidonHash::new(U256::from(7u64)),
            U256::from(12345u64),
            &[input],
            &[TransactOutputNote {
                npk: U256::from(1u8),
                value: NoteValue::new(1),
            }],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TransactInputsError::ProofShape {
                got: 2,
                expected: 16
            }
        ));
    }

    // The signed-message arity (`2 + inputs + outputs`) is capped at the engine's
    // Poseidon limit; an oversize transact fails with a typed error, not the opaque
    // crypto hashing error.
    #[test]
    fn too_many_notes_rejected() {
        let root = U256::from(42u8);
        // alloc-ok: test fixture, not a hot path.
        let inputs: Vec<TransactInputNote> = (0..6)
            .map(|i| input_note(i, [3u8; 16], 500, root))
            .collect();
        // alloc-ok: test fixture, not a hot path.
        let outputs: Vec<TransactOutputNote> = (0u64..6)
            .map(|i| TransactOutputNote {
                npk: U256::from(i + 1),
                value: NoteValue::new(1),
            })
            .collect();

        let err = TransactCircuitInputs::from_parts(
            test_asset(),
            &SpendingKey::from_bytes([1u8; 32]),
            PoseidonHash::new(U256::from(7u64)),
            U256::from(12345u64),
            &inputs,
            &outputs,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TransactInputsError::TooManyNotes {
                inputs: 6,
                outputs: 6
            }
        ));
    }

    // `prove` selects the inputs×outputs circuit from the witness counts and hands a
    // non-empty witness across the seam.
    #[test]
    fn prove_selects_transact_circuit_by_size() {
        struct ExpectProver;
        impl CircuitProver for ExpectProver {
            fn prove(&self, request: ProveRequest<'_>) -> Result<Proof, ProverError> {
                assert_eq!(
                    request.artifact.circuit,
                    CircuitKind::Transact {
                        inputs: 1,
                        outputs: 2
                    }
                );
                assert!(!request.witness_inputs.is_empty());
                Err(ProverError::ArtifactNotFound)
            }
        }

        let err = sample_witness().prove(&ExpectProver).unwrap_err();
        assert!(matches!(
            err,
            TransactInputsError::Prover(ProverError::ArtifactNotFound)
        ));
    }
}
