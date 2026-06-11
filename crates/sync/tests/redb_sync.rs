//! Live, network-gated sync runner backed by a durable redb database — also
//! checks the synced state (watermark, trees, frontier-backed roots) survives
//! a reopen.
//!
//! Ignored by default (it hits the real Subsquid endpoint). Run on demand:
//!
//! ```sh
//! cargo test -p sync --test redb_sync -- --ignored --nocapture
//! ```
//!
//! Overridable via env: `RAILGUN_SYNC_SPAN`, `RAILGUN_SYNC_WINDOW`,
//! `RAILGUN_PAGE_LIMIT`, `RAILGUN_SYNC_FROM`, `RAILGUN_REDB_PATH`.

use database::Database;
use sync::{ChainConfig, SubsquidSource, Syncer};
use types::BlockNumber;

/// Blocks fetched + committed per checkpoint.
const DEFAULT_WINDOW: u64 = 100_000;
/// Block span from the deployment block to sync (kept small for a bounded run).
const DEFAULT_SPAN: u64 = 5_000_000;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[tokio::test]
#[ignore = "hits the live Subsquid endpoint and writes a redb database"]
async fn live_sync_mainnet_to_redb() {
    let chain = ChainConfig::mainnet();
    let window = env_u64("RAILGUN_SYNC_WINDOW", DEFAULT_WINDOW);
    let span = env_u64("RAILGUN_SYNC_SPAN", DEFAULT_SPAN);
    let page_limit = env_u64("RAILGUN_PAGE_LIMIT", 0);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = std::env::var_os("RAILGUN_REDB_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dir.path().join("railgun-sync.redb"));

    let mut source = SubsquidSource::new(chain.subsquid_endpoint);
    if page_limit > 0 {
        source.set_page_limit(page_limit);
    }

    // Sync floor: deployment block by default, overridable to jump to a later range
    // (e.g. to reach V2 Shield/Transact commitments past the legacy migration).
    let floor = std::env::var("RAILGUN_SYNC_FROM")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(chain.deployment_block, BlockNumber::new);

    let mut syncer = Syncer::new(source, floor);
    syncer.set_block_window(window);

    let target = floor.saturating_add(span);

    println!(
        "syncing mainnet [{}, {}] into {} (window {window}, page_limit {page_limit}) ...",
        floor.get(),
        target.get(),
        path.display(),
    );

    let summary = {
        let db = Database::open(&path).expect("open database");
        let summary = syncer
            .run(&db, target)
            .await
            .expect("live redb sync failed");

        println!("\n=== summary ===");
        println!("commitments: {}", summary.commitments);
        println!("nullifiers:  {}", summary.nullifiers);
        println!("synced_to:   {}", summary.synced_to.get());

        let view = db.read().expect("read view");
        assert_eq!(
            view.commitments().synced_block().expect("synced_block"),
            Some(target)
        );
        if summary.commitments > 0 {
            assert!(
                view.commitments().tree_count().expect("tree_count") >= 1,
                "commitments present but no trees recorded"
            );
        }
        summary
    }; // database dropped, closing the file

    assert!(path.exists(), "redb database file should be created");

    let reopened = Database::open(&path).expect("reopen database");
    let view = reopened.read().expect("read view");
    assert_eq!(
        view.commitments().synced_block().expect("synced_block"),
        Some(target)
    );
    if summary.commitments > 0 {
        use crypto::MerkleWalk;
        let trees = view.commitments().tree_count().expect("tree_count");
        assert!(trees >= 1, "reopened database lost tree metadata");

        // The frontier snapshots persisted with the data: the fast-path root
        // must agree with a full recompute on the reopened file.
        for tree in 0..trees {
            let fast = view.merkle_root(tree).expect("fast root");
            let report = view
                .validate(tree, &crypto::ExpectedRoot(fast))
                .expect("validate");
            assert!(report.valid, "frontier root diverged for tree {tree}");
            println!(
                "tree {tree}: {} leaves, {} gaps, root {}",
                report.leaf_count,
                report.missing,
                report.root.as_u256()
            );
        }
    }
}
