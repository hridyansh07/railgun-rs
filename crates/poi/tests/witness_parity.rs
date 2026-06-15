//! End-to-end witness parity against the TypeScript engine's POI test vector
//! (`engine/src/test/test-vector-poi.json`, copied into `fixtures/`).
//!
//! The vector is a real unshield operation: one nullifier, one (unshield)
//! commitment, no note outputs. Rebuilding `PoiCircuitInputs` from its
//! constituent fields and comparing every signal exercises the txid hash, the
//! txid-tree proof, padding rules, and signal naming in one shot.

use crypto::{MerkleProof, MerkleRoot, RailgunMerkleConfig, UtxoTreeIndex, railgun_txid};
use poi::inputs::{PoiCircuitInputs, PoiNote};
use poi::txid::{TxidError, TxidRecord, TxidsMut};
use types::{
    AssetId, B256, BabyJubJubPoint, BlindedCommitmentType, BlockNumber, CommitmentHash,
    DecryptedNote, EvmAddress, NodePosition, NoteValue, Nullifier, PoseidonHash, U256,
};

const VECTOR: &str = include_str!("fixtures/test-vector-poi.json");

fn hex(value: &serde_json::Value) -> U256 {
    let s = value.as_str().expect("hex string");
    U256::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex u256")
}

fn dec(value: &serde_json::Value) -> U256 {
    let s = value.as_str().expect("decimal string");
    U256::from_str_radix(s, 10).expect("decimal u256")
}

fn hex_vec(value: &serde_json::Value) -> Vec<U256> {
    value.as_array().expect("array").iter().map(hex).collect()
}

#[test]
fn witness_signals_match_engine_test_vector() {
    let vector: serde_json::Value = serde_json::from_str(VECTOR).unwrap();

    let nullifiers = hex_vec(&vector["nullifiers"]);
    let commitments_out = hex_vec(&vector["commitmentsOut"]);
    let bound_params_hash = hex(&vector["boundParamsHash"]);

    // The operation has an unshield, so its txid is the vector's
    // railgunTxidIfHasUnshield — recompute it from scratch.
    let txid = railgun_txid(&nullifiers, &commitments_out, bound_params_hash).unwrap();
    assert_eq!(
        txid.as_u256(),
        hex(&vector["railgunTxidIfHasUnshield"]),
        "recomputed railgun txid diverges from the engine vector"
    );

    // Index the operation as the only leaf of the txid tree; the vector's
    // proof indices (0) say it sits at leaf 0.
    let utxo_tree_in = u32::try_from(vector["utxoTreeIn"].as_u64().unwrap()).unwrap();
    let global_out: u64 = vector["utxoBatchGlobalStartPositionOut"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let utxo_tree_out = UtxoTreeIndex::included(
        u32::try_from(global_out >> 16).unwrap(),
        u32::try_from(global_out & 0xFFFF).unwrap(),
    );
    assert_eq!(utxo_tree_out.global_index(), global_out);

    let leaf_hash = crypto::txid_leaf_hash(txid, utxo_tree_in, utxo_tree_out).unwrap();
    let db = database::test_util::temp();
    db.write(|txn| {
        TxidsMut::new(txn)
            .insert_leaf(
                &TxidRecord {
                    txid,
                    utxo_tree_in,
                    utxo_tree_out: u32::try_from(global_out >> 16).unwrap(),
                    utxo_batch_start_position_out: u32::try_from(global_out & 0xFFFF).unwrap(),
                    block: BlockNumber::new(0),
                },
                leaf_hash,
            )
            .map(|_| ())
    })
    .map_err(|error: TxidError| error)
    .unwrap();

    // The spend input note, reassembled from the vector's private inputs.
    let note = DecryptedNote {
        position: NodePosition::try_new(
            utxo_tree_in,
            u32::try_from(vector["utxoPositionsIn"][0].as_u64().unwrap()).unwrap(),
        )
        .unwrap(),
        value: NoteValue::try_from_u256(dec(&vector["valuesIn"][0])).unwrap(),
        asset: AssetId::erc20(EvmAddress::ZERO), // token hash is passed separately
        random: hex(&vector["randomsIn"][0]).to_be_bytes::<32>()[16..]
            .try_into()
            .unwrap(),
        memo: String::new(),
        commitment_hash: CommitmentHash::new(U256::ZERO),
        note_public_key: U256::ZERO,
        nullifier: Nullifier::new(B256::from(nullifiers[0].to_be_bytes::<32>())),
        blinded_commitment: hex(&vector["blindedCommitmentsIn"][0]),
        commitment_type: BlindedCommitmentType::Transact,
    };

    // The POI tree proof as the node served it.
    let poi_proof = MerkleProof::<RailgunMerkleConfig>::new(
        note.blinded_commitment,
        hex_vec(&vector["poiInMerkleProofPathElements"][0]),
        hex(&vector["poiInMerkleProofIndices"][0]),
        MerkleRoot::new(hex(&vector["poiMerkleroots"][0])),
    );

    let spending_public_key = BabyJubJubPoint::new(
        dec(&vector["spendingPublicKey"][0]),
        dec(&vector["spendingPublicKey"][1]),
    );
    let nullifying_key = PoseidonHash::new(dec(&vector["nullifyingKey"]));

    let inputs = PoiCircuitInputs::from_parts(
        spending_public_key,
        nullifying_key,
        utxo_tree_in,
        bound_params_hash,
        &[PoiNote {
            note: note.clone(),
            poi_proof,
        }],
        &commitments_out,
        &[], // npksOut is empty: the only output is the unshield
        &[],
        hex(&vector["token"]),
        true,
        utxo_tree_out,
        &db.read().unwrap(),
    )
    .unwrap();

    assert_eq!(inputs.circuit_size(), 3);
    let signals = inputs.to_circuit_signals();
    let zero = <RailgunMerkleConfig as crypto::MerkleConfig>::zero();

    // Public inputs: the locally rebuilt txid-tree proof must land on the
    // engine's root and path.
    assert_eq!(
        signals["anyRailgunTxidMerklerootAfterTransaction"],
        vec![hex(&vector["anyRailgunTxidMerklerootAfterTransaction"])]
    );
    assert_eq!(
        signals["railgunTxidMerkleProofIndices"],
        vec![hex(&vector["railgunTxidMerkleProofIndices"])]
    );
    assert_eq!(
        signals["railgunTxidMerkleProofPathElements"],
        hex_vec(&vector["railgunTxidMerkleProofPathElements"])
    );

    // Scalars.
    assert_eq!(signals["boundParamsHash"], vec![bound_params_hash]);
    assert_eq!(signals["token"], vec![hex(&vector["token"])]);
    assert_eq!(signals["utxoTreeIn"], vec![U256::from(utxo_tree_in)]);
    assert_eq!(
        signals["utxoBatchGlobalStartPositionOut"],
        vec![U256::from(global_out)]
    );
    assert_eq!(
        signals["railgunTxidIfHasUnshield"],
        vec![hex(&vector["railgunTxidIfHasUnshield"])]
    );
    assert_eq!(
        signals["spendingPublicKey"],
        vec![spending_public_key.x(), spending_public_key.y()]
    );
    assert_eq!(signals["nullifyingKey"], vec![nullifying_key.as_u256()]);

    // Vectors padded with the merkle zero (engine padWithZerosToMax default).
    assert_eq!(signals["nullifiers"], vec![nullifiers[0], zero, zero]);
    assert_eq!(
        signals["commitmentsOut"],
        vec![commitments_out[0], zero, zero]
    );
    assert_eq!(
        signals["randomsIn"],
        vec![hex(&vector["randomsIn"][0]), zero, zero]
    );
    assert_eq!(signals["utxoPositionsIn"], vec![U256::ZERO, zero, zero]);
    assert_eq!(signals["npksOut"], vec![zero, zero, zero]);
    assert_eq!(
        signals["poiMerkleroots"],
        vec![hex(&vector["poiMerkleroots"][0]), zero, zero]
    );

    // Vectors padded with plain zero.
    assert_eq!(
        signals["valuesIn"],
        vec![dec(&vector["valuesIn"][0]), U256::ZERO, U256::ZERO]
    );
    assert_eq!(signals["valuesOut"], vec![U256::ZERO; 3]);
    assert_eq!(signals["poiInMerkleProofIndices"], vec![U256::ZERO; 3]);

    // POI proof paths: the real path then two depth-16 merkle-zero columns,
    // flattened row-major.
    let mut expected_paths = hex_vec(&vector["poiInMerkleProofPathElements"][0]);
    expected_paths.extend(std::iter::repeat_n(zero, 32));
    assert_eq!(signals["poiInMerkleProofPathElements"], expected_paths);

    assert_eq!(signals.len(), 20);
}

#[test]
fn dummy_txid_proof_is_used_pre_inclusion() {
    let vector: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    let nullifiers = hex_vec(&vector["nullifiers"]);
    let commitments_out = hex_vec(&vector["commitmentsOut"]);
    let bound_params_hash = hex(&vector["boundParamsHash"]);

    let txid = railgun_txid(&nullifiers, &commitments_out, bound_params_hash).unwrap();
    let leaf = crypto::txid_leaf_hash(txid, 0, UtxoTreeIndex::PreInclusion).unwrap();
    let dummy = poi::inputs::dummy_merkle_proof(leaf);

    // Engine createDummyMerkleProof: 16 zero elements folded over the leaf.
    assert_eq!(dummy.elements, vec![U256::ZERO; 16]);
    assert_eq!(dummy.indices, U256::ZERO);
    let mut expected_root = leaf;
    for _ in 0..16 {
        expected_root =
            <RailgunMerkleConfig as crypto::MerkleConfig>::hash(expected_root, U256::ZERO);
    }
    assert_eq!(dummy.root.as_u256(), expected_root);
}
