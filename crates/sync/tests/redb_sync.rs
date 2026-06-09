//! Live, network-gated sync runner backed by redb.
//!
//! Ignored by default (it hits the real Subsquid endpoint). Run on demand:
//!
//! ```sh
//! cargo test -p sync --test redb_sync -- --ignored --nocapture
//! ```
//!
//! Overridable via env: `RAILGUN_SYNC_SPAN`, `RAILGUN_SYNC_WINDOW`,
//! `RAILGUN_PAGE_LIMIT`, `RAILGUN_SYNC_FROM`, `RAILGUN_REDB_PATH`.

use commitments::{CommitmentStore, Tree};
use sync::{ChainConfig, SubsquidSource, Syncer};
use types::{BlockNumber, NodeBody};
use utils::{RedbBackend, StorageBackend};

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
        let mut store = CommitmentStore::new(
            RedbBackend::open(&path, "commitments").expect("open redb database"),
        );

        let summary = syncer
            .run(&mut store, target)
            .await
            .expect("live redb sync failed");

        println!("\n=== summary ===");
        println!("commitments: {}", summary.commitments);
        println!("nullifiers:  {}", summary.nullifiers);
        println!("synced_to:   {}", summary.synced_to.get());

        inspect_store(&store);

        assert_eq!(store.synced_block().expect("synced_block"), Some(target));
        if summary.commitments > 0 {
            assert!(
                store.tree_count().expect("tree_count") >= 1,
                "commitments present but no trees recorded"
            );
        }

        summary
    };

    assert!(path.exists(), "redb database file should be created");

    let reopened = CommitmentStore::new(
        RedbBackend::open(&path, "commitments").expect("reopen redb database"),
    );
    assert_eq!(reopened.synced_block().expect("synced_block"), Some(target));
    if summary.commitments > 0 {
        assert!(
            reopened.tree_count().expect("tree_count") >= 1,
            "reopened database lost tree metadata"
        );
    }

    println!("\n=== reopened redb ===");
    inspect_store(&reopened);
}

fn inspect_store<B: StorageBackend>(store: &CommitmentStore<B>) {
    let tree_count = store.tree_count().expect("tree_count");
    println!("\n=== tree layout ({tree_count} tree(s)) ===");

    let mut total_shield = 0u64;
    let mut total_transact = 0u64;
    let mut total_gaps = 0u64;

    for number in 0..tree_count {
        let tree = store.tree(number);
        let len = tree.leaf_count().expect("leaf_count");
        let mut shield = 0u32;
        let mut transact = 0u32;
        let mut gaps: Vec<u32> = Vec::new();

        for pos in 0..len {
            match tree.get(pos).expect("get") {
                Some(node) => match node.body {
                    NodeBody::Shield(_) => shield += 1,
                    NodeBody::Transact(_) => transact += 1,
                },
                None => gaps.push(pos),
            }
        }

        let stored = shield + transact;
        total_shield += u64::from(shield);
        total_transact += u64::from(transact);
        total_gaps += gaps.len() as u64;

        println!(
            "\ntree {number}: length {len}, stored {stored} (shield {shield}, transact {transact}), gaps {}",
            gaps.len()
        );
        print_positions(&tree, 0..len.min(SAMPLE), "head");
        if len > SAMPLE * 2 {
            print_positions(&tree, len.saturating_sub(SAMPLE)..len, "tail");
        }
        if !gaps.is_empty() {
            let preview: Vec<u32> = gaps.iter().copied().take(10).collect();
            println!(
                "  gaps (first {} of {}): {preview:?}",
                preview.len(),
                gaps.len()
            );
        }
    }

    println!("\ntotals: shield {total_shield}, transact {total_transact}, gaps {total_gaps}");
}

fn print_positions<B: StorageBackend>(
    tree: &Tree<'_, B>,
    positions: std::ops::Range<u32>,
    label: &str,
) {
    for pos in positions {
        match tree.get(pos).expect("get") {
            // `Node`'s Display prints position, block, hash, and kind in one line.
            Some(node) => println!("  {label} {node}"),
            None => println!("  {label} [{}:{pos}] <gap>", tree.number()),
        }
    }
}
