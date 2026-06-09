//! Offline tests for the decoder: scan loop, asset-indexed balances (with the spent
//! filter), persistence round-trip, and parallel per-tree decoding.
//!
//! The decode *match* path (a node that actually decrypts to a note) needs a
//! ciphertext encrypted to the wallet — there is no encryption path yet — so it is
//! exercised by the ignored `live_decode` test instead.

use commitments::CommitmentStore;
use crypto::{KeyNode, RailgunMnemonic};
use decoder::{DecodedNoteStore, DecodedNotes, Decoder};
use types::{
    AssetId, B256, BlindedCommitmentType, BlockNumber, CommitmentHash, DecryptedNote, EvmAddress,
    Node, NodeBody, NodePosition, NoteValue, Nullified, Nullifier, RailgunAccountIndex, ShieldBody,
    U256, ViewingPublicKey,
};
use utils::InMemoryBackend;

fn test_decoder() -> Decoder {
    let mnemonic =
        RailgunMnemonic::parse("test test test test test test test test test test test junk")
            .unwrap();
    let keys = KeyNode::derive_railgun_keys(&mnemonic, RailgunAccountIndex::new(0)).unwrap();
    Decoder::from_keys(&keys)
}

fn erc20(byte: u8) -> AssetId {
    AssetId::erc20(EvmAddress::from([byte; 20]))
}

/// A shield node with arbitrary ciphertext — never addressed to `test_decoder`.
fn shield_node(tree: u32, leaf: u32) -> Node {
    Node {
        position: NodePosition::try_new(tree, leaf).unwrap(),
        hash: CommitmentHash::new(U256::from(u64::from(leaf) + 1)),
        block: BlockNumber::new(1),
        body: NodeBody::Shield(ShieldBody {
            npk: U256::from(7u64),
            token: erc20(0x11),
            value: U256::from(1000u64),
            encrypted_bundle: vec![[0u8; 32], [1u8; 32], [2u8; 32]],
            shield_key: ViewingPublicKey::from_bytes([4u8; 32]),
        }),
    }
}

/// A hand-built owned note (bypasses decryption) for balance/persistence tests.
fn owned_note(
    asset: AssetId,
    value: u128,
    tree: u32,
    leaf: u32,
    nullifier: Nullifier,
) -> DecryptedNote {
    DecryptedNote {
        position: NodePosition::try_new(tree, leaf).unwrap(),
        value: NoteValue::new(value),
        asset,
        random: [0u8; 16],
        memo: String::new(),
        commitment_hash: CommitmentHash::new(U256::from(value)),
        note_public_key: U256::from(1u64),
        nullifier,
        blinded_commitment: U256::from(1u64),
        commitment_type: BlindedCommitmentType::Transact,
    }
}

#[test]
fn decode_skips_nodes_not_addressed_to_the_wallet() {
    let mut store = CommitmentStore::new(InMemoryBackend::new());
    store
        .commit(
            vec![shield_node(0, 0), shield_node(0, 1)],
            vec![],
            BlockNumber::new(1),
        )
        .unwrap();

    let notes = test_decoder().decode_all(&store).unwrap();
    assert!(notes.is_empty());
}

#[test]
fn decode_tree_runs_across_threads() {
    let mut store = CommitmentStore::new(InMemoryBackend::new());
    store
        .commit(
            vec![shield_node(0, 0), shield_node(1, 0)],
            vec![],
            BlockNumber::new(1),
        )
        .unwrap();

    let decoder = test_decoder();
    let tree_count = store.tree_count().unwrap();
    assert_eq!(tree_count, 2);

    // One tree per thread over a shared read-view of the store. `store_ref` and
    // `decoder` are `Copy`, so each `move` closure copies them rather than moving.
    let store_ref = &store;
    let mut owned = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..tree_count)
            .map(|tree| scope.spawn(move || decoder.decode_tree(store_ref, tree)))
            .collect();
        for handle in handles {
            owned.extend(handle.join().unwrap().unwrap());
        }
    });

    assert!(owned.is_empty());
}

#[test]
fn balances_group_by_asset_and_exclude_spent() {
    let weth = erc20(0xAA);
    let dai = erc20(0xBB);

    let spent = Nullifier::new(B256::repeat_byte(9));
    let unspent = Nullifier::new(B256::repeat_byte(8));
    let dai_nullifier = Nullifier::new(B256::repeat_byte(7));

    let notes = vec![
        owned_note(weth, 100, 0, 0, spent),
        owned_note(weth, 250, 0, 1, unspent),
        owned_note(dai, 1000, 0, 2, dai_nullifier),
    ];

    // Only `spent` has been observed on-chain.
    let mut store = CommitmentStore::new(InMemoryBackend::new());
    store
        .commit(
            vec![],
            vec![Nullified {
                tree_number: 0,
                nullifier: spent,
            }],
            BlockNumber::new(1),
        )
        .unwrap();

    let balances = DecodedNotes::from_notes(notes).balances(&store).unwrap();

    assert_eq!(balances.len(), 2);
    let weth_balance = balances.get(&weth).unwrap();
    assert_eq!(weth_balance.value, U256::from(250u64)); // 100 spent, 250 unspent
    assert_eq!(weth_balance.unspent_utxos.len(), 1);
    assert_eq!(balances.get(&dai).unwrap().value, U256::from(1000u64));
}

#[test]
fn note_store_round_trips_through_serde() {
    let weth = erc20(0xAA);
    let notes = vec![
        owned_note(weth, 100, 0, 0, Nullifier::new(B256::repeat_byte(1))),
        owned_note(weth, 200, 0, 1, Nullifier::new(B256::repeat_byte(2))),
    ];

    let mut store = DecodedNoteStore::new(InMemoryBackend::new());
    assert!(store.load().unwrap().is_empty());

    store.save(&notes).unwrap();
    let loaded = store.load().unwrap();

    assert_eq!(
        serde_json::to_vec(&notes).unwrap(),
        serde_json::to_vec(&loaded).unwrap()
    );
}
