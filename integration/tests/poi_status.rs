//! Live POI status smoke over the committed commitment fixture's decoded
//! notes: refresh statuses from the public POI node, then bucket balances.
//!
//! Runs only with `RAILGUN_POI_LIVE` set — POI list data drifts over time, so
//! assertions are shape-level (statuses cached, every note lands in a bucket),
//! never value-level.

use database::Database;
use decoder::DecodedNotes;
use poi::{PoiClient, PoiStatusRefresher, bucket_balances};
use sync::ChainConfig;

#[tokio::test]
async fn live_poi_statuses_bucket_fixture_notes() {
    if !integration_tests::poi_live_enabled() {
        eprintln!("skipping: set RAILGUN_POI_LIVE in .env to run live POI status tests");
        return;
    }
    let path = integration_tests::fixture_path();
    if !path.exists() {
        eprintln!("skipping: no fixture at {}", path.display());
        return;
    }

    // One database: commitments and decoded notes come from the fixture, and
    // the refreshed statuses land in its (gitignored-rebuildable) status table.
    let db = Database::open(&path).expect("open fixture");
    let notes = db
        .read()
        .expect("read view")
        .decoded()
        .load()
        .expect("load decoded notes");
    if notes.is_empty() {
        eprintln!("skipping: fixture has no decoded notes");
        return;
    }
    println!("checking POI status for {} note(s)", notes.len());

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

    let summary = PoiStatusRefresher::new(&client)
        .refresh(notes.iter(), &db)
        .await
        .expect("refresh statuses");
    println!(
        "queried {} (note, list) pairs, cached {} statuses",
        summary.queried, summary.updated
    );
    assert!(summary.queried > 0, "expected at least one stale pair");

    // Every note lands in some bucket; shape only — live statuses drift.
    let list_keys: Vec<poi::ListKey> = chain
        .poi_list_keys
        .iter()
        .map(|key| (*key).into())
        .collect();
    let decoded = DecodedNotes::from_notes(notes);
    let view = db.read().expect("read view");
    let bucketed = bucket_balances(&decoded, &view, &list_keys).expect("bucket balances");
    for asset in decoded.assets() {
        let buckets = bucketed.buckets(asset).expect("asset has buckets");
        assert!(!buckets.is_empty());
        for (bucket, balance) in buckets {
            println!(
                "asset {asset:?} {bucket:?}: {} across {} note(s)",
                balance.value,
                balance.notes.len()
            );
        }
    }
}
