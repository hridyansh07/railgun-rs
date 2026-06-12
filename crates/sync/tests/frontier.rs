//! Frontier-snapshot equivalence through the real [`Syncer`] commit path:
//! after every synced window — including one that leaves an interior gap and
//! one that backfills it — the persisted snapshot's fast-path root must equal
//! a forced full recompute.

use crypto::{ExpectedRoot, MerkleWalk};
use database::{Database, DatabaseError};
use sync::{EventSource, EventStream, Page, SyncError, SyncEvent, Syncer};
use types::{
    AssetId, BlockNumber, CommitmentHash, EvmAddress, Node, NodeBody, NodePosition, ShieldBody,
    U256, ViewingPublicKey,
};

/// A shield node whose merkle leaf hash is `leaf + 1`, landing at `block`.
fn shield_node(tree: u32, leaf: u32, block: u64) -> Node {
    Node {
        position: NodePosition::try_new(tree, leaf).unwrap(),
        hash: CommitmentHash::new(U256::from(u64::from(leaf) + 1)),
        block: BlockNumber::new(block),
        body: NodeBody::Shield(ShieldBody {
            npk: U256::from(7u64),
            token: AssetId::erc20(EvmAddress::from([0x11; 20])),
            value: U256::from(1000u64),
            encrypted_bundle: vec![[0u8; 32]],
            shield_key: ViewingPublicKey::from_bytes([4u8; 32]),
        }),
    }
}

/// Serves a fixed node list, filtered per requested block window.
struct CannedSource {
    head: u64,
    nodes: Vec<Node>,
}

#[async_trait::async_trait]
impl EventSource for CannedSource {
    async fn latest_block(&self) -> Result<BlockNumber, SyncError> {
        Ok(BlockNumber::new(self.head))
    }

    async fn fetch_page(
        &self,
        stream: EventStream,
        from: BlockNumber,
        to: BlockNumber,
        _cursor: Option<String>,
    ) -> Result<Page, SyncError> {
        let events = match stream {
            EventStream::Commitments => self
                .nodes
                .iter()
                .filter(|node| node.block >= from && node.block <= to)
                .map(|node| SyncEvent::Commitment(clone_node(node)))
                .collect(),
            EventStream::Nullifiers => Vec::new(),
        };
        Ok(Page {
            events,
            cursor: None,
        })
    }
}

/// `Node` is deliberately not `Clone` in `types`; rebuild it for the test double.
fn clone_node(node: &Node) -> Node {
    shield_node(
        node.position.tree_number(),
        node.position.leaf_index(),
        node.block.get(),
    )
}

/// The frontier fast path agrees with a forced full recompute for `tree`.
fn assert_frontier_matches_recompute(db: &Database, tree: u32) {
    let view = db.read().unwrap();
    assert!(
        view.frontier().snapshot(tree).unwrap().is_some(),
        "syncer should have persisted a frontier snapshot for tree {tree}"
    );
    // merkle_root takes the snapshot fast path; validate always recomputes.
    let fast = view.merkle_root(tree).unwrap();
    let report = view.validate(tree, &ExpectedRoot(fast)).unwrap();
    assert!(
        report.valid,
        "fast-path root diverged from recompute for tree {tree}"
    );
}

#[tokio::test]
async fn frontier_tracks_recompute_across_windows_gaps_and_backfill() {
    // Window 1 (blocks 0..=99): leaves 0, 1.
    // Window 2 (blocks 100..=199): leaves 3, 4 — leaf 2 missing (interior gap).
    // Window 3 (blocks 200..=299): leaf 2 arrives late (backfill below the
    // frontier → snapshot rebuild) plus leaf 5 appends; second tree starts.
    let source = CannedSource {
        head: 299,
        nodes: vec![
            shield_node(0, 0, 10),
            shield_node(0, 1, 20),
            shield_node(0, 3, 110),
            shield_node(0, 4, 120),
            shield_node(0, 2, 210),
            shield_node(0, 5, 220),
            shield_node(1, 0, 230),
        ],
    };

    let mut syncer = Syncer::new(source, BlockNumber::new(0));
    syncer.set_block_window(100);
    let db = database::test_util::temp();

    // Window 1: dense append.
    syncer.run(&db, BlockNumber::new(99)).await.unwrap();
    assert_frontier_matches_recompute(&db, 0);

    // Window 2: append past a gap (zero-filled in both paths).
    syncer.run(&db, BlockNumber::new(199)).await.unwrap();
    {
        let view = db.read().unwrap();
        assert_eq!(view.commitments().tree_length(0).unwrap(), 5);
        let report = view
            .validate(0, &ExpectedRoot(view.merkle_root(0).unwrap()))
            .unwrap();
        assert_eq!(report.missing, 1, "gap at position 2 should be counted");
    }
    assert_frontier_matches_recompute(&db, 0);
    let gap_root = db.read().unwrap().merkle_root(0).unwrap();

    // Window 3: the backfill must change the root (no longer zero-filled at 2)
    // and the rebuilt snapshot must agree with the recompute; tree 1 starts.
    syncer.run_to_head(&db).await.unwrap();
    {
        let view = db.read().unwrap();
        assert_eq!(view.commitments().tree_length(0).unwrap(), 6);
        let report = view
            .validate(0, &ExpectedRoot(view.merkle_root(0).unwrap()))
            .unwrap();
        assert_eq!(report.missing, 0, "backfill should have closed the gap");
        assert_ne!(view.merkle_root(0).unwrap(), gap_root);
    }
    assert_frontier_matches_recompute(&db, 0);
    assert_frontier_matches_recompute(&db, 1);

    // And the whole run is idempotent from the watermark.
    let again = syncer.run_to_head(&db).await.unwrap();
    assert_eq!(again.commitments, 0);
    assert_frontier_matches_recompute(&db, 0);
}

#[tokio::test]
async fn ten_leaf_frontier_matches_engine_vector() {
    // The canonical engine vector, but arriving through the full sync path.
    let source = CannedSource {
        head: 9,
        nodes: (0..10u32)
            .map(|leaf| shield_node(0, leaf, u64::from(leaf)))
            .collect(),
    };
    let db = database::test_util::temp();
    Syncer::new(source, BlockNumber::new(0))
        .run_to_head(&db)
        .await
        .unwrap();

    // Snapshot fast path lands exactly on the engine vector.
    let view = db.read().unwrap();
    assert!(view.frontier().snapshot(0).unwrap().is_some());
    assert_eq!(
        view.merkle_root(0).unwrap().as_u256().to_string(),
        "13360826432759445967430837006844965422592495092152969583910134058984357610665"
    );

    // Clearing the snapshot and recomputing gives the same root.
    db.write(|txn| {
        txn.frontier().clear_snapshot(0)?;
        Ok::<_, DatabaseError>(())
    })
    .unwrap();
    assert_eq!(
        db.read()
            .unwrap()
            .merkle_root(0)
            .unwrap()
            .as_u256()
            .to_string(),
        "13360826432759445967430837006844965422592495092152969583910134058984357610665"
    );
}
