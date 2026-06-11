//! Live Sepolia txid-tree fixture builder — **ignored by default** (hits the
//! Subsquid index *and* the public POI node, and rewrites a local fixture).
//! Regenerates `tests/fixtures/sepolia-txid.redb`:
//!
//! ```sh
//! cargo test -p integration-tests --test build_txid_fixture -- --ignored --nocapture
//! ```
//!
//! The txid tree must start at the chain's POI launch block and run to the
//! node's validated head — unlike the commitment fixture, the window cannot be
//! narrowed, or the recomputed roots would not match the node's.

use database::Database;
use poi::{PoiClient, TxidIndexer, Txids};
use sync::{ChainConfig, SubsquidSource};

#[tokio::test]
#[ignore = "hits live Sepolia Subsquid + the public POI node, and (re)writes a local fixture"]
async fn build_sepolia_txid_fixture() {
    let chain = ChainConfig::sepolia();
    let Some(poi_node) = chain.poi_node else {
        panic!("Sepolia chain config carries no POI node endpoint");
    };

    let path = integration_tests::txid_fixture_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixtures dir");
    }

    let db = Database::open(&path).expect("open database");

    let client = PoiClient::new(
        chain.id,
        poi_node,
        chain
            .poi_list_keys
            .iter()
            .map(|key| (*key).into())
            .collect(),
    );
    let indexer = TxidIndexer::new(
        SubsquidSource::new(chain.subsquid_endpoint),
        chain.poi_launch_block,
    );

    println!(
        "building txid tree from block {} -> {}",
        chain.poi_launch_block.get(),
        path.display()
    );
    let summary = indexer.sync_to_head(&db, &client).await.expect("sync");
    println!(
        "fetched {} transactions, appended {} leaves ({} duplicates), synced to block {}",
        summary.fetched,
        summary.appended,
        summary.duplicates,
        summary.synced_to.get()
    );
    let view = db.read().expect("read view");
    println!(
        "total leaves: {} — fixture written: {}",
        Txids::new(&view).total_leaves().expect("total_leaves"),
        path.display()
    );
}
