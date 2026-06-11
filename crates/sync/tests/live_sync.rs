//! Live, network-gated sync runner (in-memory database).
//!
//! Ignored by default (it hits the real Subsquid endpoint). Run on demand:
//!
//! ```sh
//! cargo test -p sync --test live_sync -- --ignored --nocapture
//! ```
//!
//! Overridable via env: `RAILGUN_SYNC_SPAN`, `RAILGUN_SYNC_WINDOW`,
//! `RAILGUN_PAGE_LIMIT`, `RAILGUN_SYNC_FROM`.

use database::{Database, Reader};
use sync::{ChainConfig, SubsquidSource, Syncer};
use types::{BlockNumber, NodeBody};

/// Blocks fetched + committed per checkpoint.
const DEFAULT_WINDOW: u64 = 100_000;
/// Block span from the deployment block to sync (kept small for a bounded run).
const DEFAULT_SPAN: u64 = 5_000_000;
/// Positions sampled from each end of a tree when printing the layout.
const SAMPLE: u32 = 5;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[tokio::test]
#[ignore = "hits the live Subsquid endpoint; run with --ignored"]
async fn live_sync_mainnet_from_deployment() {
    let chain = ChainConfig::mainnet();
    let window = env_u64("RAILGUN_SYNC_WINDOW", DEFAULT_WINDOW);
    let span = env_u64("RAILGUN_SYNC_SPAN", DEFAULT_SPAN);
    let page_limit = env_u64("RAILGUN_PAGE_LIMIT", 0);

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
    let db = Database::in_memory();

    println!(
        "syncing mainnet [{}, {}] (window {window}, page_limit {page_limit}) ...",
        floor.get(),
        target.get(),
    );

    let summary = syncer.run(&db, target).await.expect("live sync failed");

    println!("\n=== summary ===");
    println!("commitments: {}", summary.commitments);
    println!("nullifiers:  {}", summary.nullifiers);
    println!("synced_to:   {}", summary.synced_to.get());

    let view = db.read().expect("read view");
    inspect(&view);

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
}

fn inspect<R: Reader>(view: &R) {
    let commitments = database::Commitments::new(view);
    let tree_count = commitments.tree_count().expect("tree_count");
    println!("\n=== tree layout ({tree_count} tree(s)) ===");

    let mut total_shield = 0u64;
    let mut total_transact = 0u64;
    let mut total_gaps = 0u64;

    for number in 0..tree_count {
        let len = commitments.tree_length(number).expect("tree_length");
        let mut shield = 0u32;
        let mut transact = 0u32;
        let mut stored_positions = Vec::new();

        for node in commitments.nodes(number).expect("nodes") {
            let node = node.expect("node");
            stored_positions.push(node.position.leaf_index());
            match node.body {
                NodeBody::Shield(_) => shield += 1,
                NodeBody::Transact(_) => transact += 1,
            }
        }

        let stored = shield + transact;
        let gaps = len - stored;
        total_shield += u64::from(shield);
        total_transact += u64::from(transact);
        total_gaps += u64::from(gaps);

        println!(
            "\ntree {number}: length {len}, stored {stored} (shield {shield}, transact {transact}), gaps {gaps}"
        );
        for pos in stored_positions.iter().take(SAMPLE as usize) {
            if let Some(node) = commitments.node(number, *pos).expect("node") {
                println!("  head {node}");
            }
        }
    }

    println!("\ntotals: shield {total_shield}, transact {total_transact}, gaps {total_gaps}");
}
