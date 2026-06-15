//! Txid-tree integrity over the local Sepolia txid fixture.
//!
//! Offline part (always runs when the fixture exists): every tree's root
//! recomputes from the stored leaf hashes, and a sampled membership proof
//! verifies against that root. Live part (only with `RAILGUN_POI_LIVE` set):
//! the recomputed head root is validated by the public POI node.
//!
//! One test on purpose — redb locks the fixture file exclusively.

use database::Database;
use poi::{PoiClient, PoiNodeClient, Txids};
use sync::ChainConfig;

#[tokio::test]
async fn txid_fixture_roots_recompute_and_validate() {
    let path = integration_tests::txid_fixture_path();
    if !path.exists() {
        eprintln!(
            "skipping: no txid fixture at {} (run `build_txid_fixture` to create it)",
            path.display()
        );
        return;
    }

    let db = Database::open(&path).expect("open fixture");
    let view = db.read().expect("read view");
    let txids = Txids::new(&view);
    let total = txids.total_leaves().expect("total_leaves");
    if total == 0 {
        eprintln!("skipping: txid fixture at {} is empty", path.display());
        return;
    }
    println!("txid fixture holds {total} leaves");

    // Offline: every tree's root recomputes, and a sampled proof verifies.
    #[allow(clippy::cast_possible_truncation)]
    let head_tree = ((total - 1) >> 16) as u32;
    let mut head_root = None;
    for tree in 0..=head_tree {
        let length = txids.tree_length(tree).expect("tree_length");
        let root = txids.merkle_root(tree).expect("merkle_root");
        let proof = txids.merkle_proof(tree, length / 2).expect("merkle_proof");
        assert_eq!(proof.root, root, "proof root diverges for tree {tree}");
        assert!(proof.verify(), "membership proof failed for tree {tree}");
        head_root = Some((tree, length - 1, root));
    }

    // Live: the node accepts the recomputed head root.
    if !integration_tests::poi_live_enabled() {
        eprintln!("offline only: set RAILGUN_POI_LIVE in .env to validate against the POI node");
        return;
    }
    let chain = ChainConfig::sepolia();
    let client = PoiClient::new(
        chain.id,
        chain.poi_node.expect("sepolia has a POI node"),
        chain
            .poi_list_keys
            .iter()
            .map(|key| (*key).into())
            .collect(),
    );

    let (tree, index, root) = head_root.expect("at least one tree");
    let accepted = client
        .validate_txid_merkleroot(tree, index, root)
        .await
        .expect("validate_txid_merkleroot");
    // The node may have validated further leaves since the fixture was built,
    // in which case our root is a stale-but-correct historical root the node
    // no longer reports for this index — only assert on a fresh fixture.
    let validated = client.validated_txid().await.expect("validated_txid");
    if u64::from(validated.index) + 1 == total {
        assert!(accepted, "node rejected the recomputed head root");
    } else {
        println!(
            "node has advanced past the fixture (validated index {} vs {} local leaves); accepted={accepted}",
            validated.index, total
        );
    }
}
