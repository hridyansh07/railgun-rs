//! End-to-end tests for the Merkle walk over a real database: leaves are
//! committed through a write transaction (codec + engine round-trip), then the
//! root is recomputed from them and validated — including the frontier
//! snapshot fast path and its equivalence with the full recompute.
//!
//! The `shield_node` helper stores `hash = leaf_index + 1`, so committing positions
//! `0..=9` yields leaf hashes `1..=10` — the exact vector the engine/kohaku tests assert,
//! letting us check the whole store -> decode -> walk-up path against a known root.

use crypto::{ExpectedRoot, MerkleAccumulator, MerkleRoot, MerkleWalk, RailgunMerkleConfig};
use database::{Database, DatabaseError};
use types::{
    AssetId, BlockNumber, CommitmentHash, EvmAddress, Node, NodeBody, NodePosition, ShieldBody,
    U256, ViewingPublicKey,
};

/// Root of leaves `[1..=10]` in a depth-16 RAILGUN tree (TypeScript-engine vector).
const TEN_LEAF_ROOT: &str =
    "13360826432759445967430837006844965422592495092152969583910134058984357610665";
/// Root of an empty depth-16 RAILGUN tree (TypeScript-engine vector).
const EMPTY_ROOT: &str =
    "9493149700940509817378043077993653487291699154667385859234945399563579865744";

/// A shield node whose merkle leaf hash is `leaf + 1`. Body is arbitrary — the walk
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

/// Commits the given leaf positions of tree 0 in one write transaction.
fn commit_leaves(db: &Database, leaves: &[u32]) {
    db.write(|txn| {
        let mut commitments = txn.commitments();
        for &leaf in leaves {
            commitments.insert_node(&shield_node(0, leaf))?;
        }
        commitments.set_synced_block(BlockNumber::new(1))?;
        Ok::<_, DatabaseError>(())
    })
    .unwrap();
}

fn db_with_ten_leaves() -> database::test_util::TempDatabase {
    let db = database::test_util::temp();
    // alloc-ok: test fixture.
    let leaves: Vec<u32> = (0..10).collect();
    commit_leaves(&db, &leaves);
    db
}

#[test]
fn walk_up_matches_engine_vector() {
    let db = db_with_ten_leaves();
    let root = db.read().unwrap().merkle_root(0).unwrap();
    assert_eq!(root.as_u256().to_string(), TEN_LEAF_ROOT);
}

#[test]
fn walk_up_matches_engine_vector_on_redb() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("commitments.redb");

    let db = Database::open(&path).unwrap();
    // alloc-ok: test fixture.
    let leaves: Vec<u32> = (0..10).collect();
    commit_leaves(&db, &leaves);

    // The walk reads back every leaf from the durable engine through the codec.
    let root = db.read().unwrap().merkle_root(0).unwrap();
    assert_eq!(root.as_u256().to_string(), TEN_LEAF_ROOT);
}

#[test]
fn empty_tree_returns_engine_empty_root() {
    let db = database::test_util::temp();
    let root = db.read().unwrap().merkle_root(0).unwrap();
    assert_eq!(root.as_u256().to_string(), EMPTY_ROOT);
}

#[test]
fn validate_accepts_correct_root_and_rejects_a_wrong_one() {
    let db = db_with_ten_leaves();
    let view = db.read().unwrap();
    let correct = view.merkle_root(0).unwrap();

    let ok = view.validate(0, &ExpectedRoot(correct)).unwrap();
    assert!(ok.valid);
    assert_eq!(ok.leaf_count, 10);
    assert_eq!(ok.missing, 0);
    assert_eq!(ok.root, correct);

    let wrong = ExpectedRoot(MerkleRoot::new(U256::from(1u8)));
    let report = view.validate(0, &wrong).unwrap();
    assert!(!report.valid);
}

#[test]
fn validate_detects_an_interior_gap() {
    // Positions 0, 1, 3, 4 — position 2 is missing, but tree_length becomes 5.
    let db = database::test_util::temp();
    commit_leaves(&db, &[0, 1, 3, 4]);

    let report = db
        .read()
        .unwrap()
        .validate(0, &ExpectedRoot(MerkleRoot::new(U256::from(0u8))))
        .unwrap();

    assert_eq!(report.leaf_count, 5);
    assert_eq!(report.missing, 1);
}

#[test]
fn current_frontier_snapshot_short_circuits_to_the_same_root() {
    let db = db_with_ten_leaves();

    // Persist the frontier of the same ten leaves, as the syncer would.
    let mut accumulator = MerkleAccumulator::<RailgunMerkleConfig>::new();
    for leaf in 1..=10u64 {
        accumulator.insert(U256::from(leaf));
    }
    db.write(|txn| {
        let bytes = serde_json::to_vec(&accumulator.state())
            .map_err(|error| DatabaseError::Serde(error.to_string()))?;
        txn.frontier().set_snapshot(0, &bytes)?;
        Ok::<_, DatabaseError>(())
    })
    .unwrap();

    // Fast path (snapshot) == full recompute == engine vector.
    let with_snapshot = db.read().unwrap().merkle_root(0).unwrap();
    assert_eq!(with_snapshot.as_u256().to_string(), TEN_LEAF_ROOT);

    db.write(|txn| {
        txn.frontier().clear_snapshot(0)?;
        Ok::<_, DatabaseError>(())
    })
    .unwrap();
    let recomputed = db.read().unwrap().merkle_root(0).unwrap();
    assert_eq!(with_snapshot, recomputed);
}

#[test]
fn stale_frontier_snapshot_falls_back_to_recompute() {
    let db = db_with_ten_leaves();

    // A snapshot of only five leaves, with a deliberately bogus root: if the
    // stale fast path were taken, the bogus root would leak out.
    let mut accumulator = MerkleAccumulator::<RailgunMerkleConfig>::new();
    for leaf in 1..=5u64 {
        accumulator.insert(U256::from(leaf));
    }
    let mut stale = accumulator.state();
    stale.root = U256::from(0xdead_beefu64);
    db.write(|txn| {
        let bytes =
            serde_json::to_vec(&stale).map_err(|error| DatabaseError::Serde(error.to_string()))?;
        txn.frontier().set_snapshot(0, &bytes)?;
        Ok::<_, DatabaseError>(())
    })
    .unwrap();

    // next_index (5) != tree_length (10) → full walk, correct root.
    let root = db.read().unwrap().merkle_root(0).unwrap();
    assert_eq!(root.as_u256().to_string(), TEN_LEAF_ROOT);
}
