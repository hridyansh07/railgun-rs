//! End-to-end tests for the Merkle walk-up over a real commitment store: leaves are
//! committed through the store (codec + backend round-trip), then the root is recomputed
//! from them and validated.
//!
//! The `shield_node` helper stores `hash = leaf_index + 1`, so committing positions
//! `0..=9` yields leaf hashes `1..=10` — the exact vector the engine/kohaku tests assert,
//! letting us check the whole store -> decode -> walk-up path against a known root.

use commitments::CommitmentStore;
use crypto::{ExpectedRoot, MerkleRoot, MerkleWalk};
use types::{
    AssetId, BlockNumber, CommitmentHash, EvmAddress, Node, NodeBody, NodePosition, ShieldBody,
    U256, ViewingPublicKey,
};
use utils::{InMemoryBackend, RedbBackend, StorageBackend};

/// Root of leaves `[1..=10]` in a depth-16 RAILGUN tree (TypeScript-engine vector).
const TEN_LEAF_ROOT: &str =
    "13360826432759445967430837006844965422592495092152969583910134058984357610665";
/// Root of an empty depth-16 RAILGUN tree (TypeScript-engine vector).
const EMPTY_ROOT: &str =
    "9493149700940509817378043077993653487291699154667385859234945399563579865744";

/// A shield node whose merkle leaf hash is `leaf + 1`. Body is arbitrary — the walk-up
/// only reads `hash`.
fn shield_node(tree: u32, leaf: u32) -> Node {
    Node {
        position: NodePosition::try_new(tree, leaf).unwrap(),
        hash: CommitmentHash::new(U256::from(u64::from(leaf) + 1)),
        block: BlockNumber::new(1),
        body: NodeBody::Shield(ShieldBody {
            npk: U256::from(7u64),
            token: AssetId::erc20(EvmAddress::from([0x11; 20])),
            value: U256::from(1000u64),
            // alloc-ok: test fixture.
            encrypted_bundle: vec![[0u8; 32], [1u8; 32], [2u8; 32]],
            shield_key: ViewingPublicKey::from_bytes([4u8; 32]),
        }),
    }
}

/// Commits `shield_node(0, 0..=9)` into a fresh in-memory store.
fn store_with_ten_leaves() -> CommitmentStore<InMemoryBackend> {
    let mut store = CommitmentStore::new(InMemoryBackend::new());
    // alloc-ok: test fixture.
    let nodes: Vec<Node> = (0..10u32).map(|leaf| shield_node(0, leaf)).collect();
    store.commit(nodes, vec![], BlockNumber::new(1)).unwrap();
    store
}

fn assert_ten_leaf_root<B: StorageBackend>(store: &CommitmentStore<B>) {
    let root = store.tree(0).merkle_root().unwrap();
    assert_eq!(root.as_u256().to_string(), TEN_LEAF_ROOT);
}

#[test]
fn walk_up_matches_engine_vector_in_memory() {
    assert_ten_leaf_root(&store_with_ten_leaves());
}

#[test]
fn walk_up_matches_engine_vector_on_redb() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("commitments.redb");

    let mut store = CommitmentStore::new(RedbBackend::open(&path, "commitments").unwrap());
    // alloc-ok: test fixture.
    let nodes: Vec<Node> = (0..10u32).map(|leaf| shield_node(0, leaf)).collect();
    store.commit(nodes, vec![], BlockNumber::new(1)).unwrap();

    // The walk-up reads back every leaf from the durable backend through the codec.
    assert_ten_leaf_root(&store);
}

#[test]
fn empty_tree_returns_engine_empty_root() {
    let store = CommitmentStore::new(InMemoryBackend::new());
    let root = store.tree(0).merkle_root().unwrap();
    assert_eq!(root.as_u256().to_string(), EMPTY_ROOT);
}

#[test]
fn validate_accepts_correct_root_and_rejects_a_wrong_one() {
    let store = store_with_ten_leaves();
    let correct = store.tree(0).merkle_root().unwrap();

    let ok = store.tree(0).validate(&ExpectedRoot(correct)).unwrap();
    assert!(ok.valid);
    assert_eq!(ok.leaf_count, 10);
    assert_eq!(ok.missing, 0);
    assert_eq!(ok.root, correct);

    let wrong = ExpectedRoot(MerkleRoot::new(U256::from(1u8)));
    let report = store.tree(0).validate(&wrong).unwrap();
    assert!(!report.valid);
}

#[test]
fn validate_detects_an_interior_gap() {
    // Positions 0, 1, 3, 4 — position 2 is missing, but tree_length becomes 5.
    let mut store = CommitmentStore::new(InMemoryBackend::new());
    store
        .commit(
            vec![
                shield_node(0, 0),
                shield_node(0, 1),
                shield_node(0, 3),
                shield_node(0, 4),
            ],
            vec![],
            BlockNumber::new(1),
        )
        .unwrap();

    let report = store
        .tree(0)
        .validate(&ExpectedRoot(MerkleRoot::new(U256::from(0u8))))
        .unwrap();

    assert_eq!(report.leaf_count, 5);
    assert_eq!(report.missing, 1);
}
