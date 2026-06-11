//! Live Sepolia fixture builder — **ignored by default** (hits the network and rewrites
//! a committed file). This is the regeneration step for `tests/fixtures/sepolia.redb`.
//!
//! After putting `RAILGUN_TEST_MNEMONIC` in `.env` and your transactions on Sepolia:
//!
//! ```sh
//! RAILGUN_SYNC_FROM=<block-before-your-txns> RAILGUN_SYNC_SPAN=<tight span> \
//!   cargo test -p integration-tests --test build_fixture -- --ignored --nocapture
//! ```
//!
//! Keep the window TIGHT so the committed fixture stays small.

use database::{Database, DatabaseError};
use decoder::Decoder;
use integration_tests::{fixture_path, test_var, test_wallet};
use sync::{ChainConfig, SubsquidSource, Syncer};
use types::BlockNumber;

fn env_u64(key: &str, default: u64) -> u64 {
    test_var(key)
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

#[tokio::test]
#[ignore = "hits live Sepolia Subsquid and (re)writes the committed redb fixture"]
async fn build_sepolia_fixture() {
    let Some(keys) = test_wallet() else {
        eprintln!("skipping: set RAILGUN_TEST_MNEMONIC in .env to build the fixture");
        return;
    };

    let chain = ChainConfig::sepolia();
    let floor = BlockNumber::new(env_u64("RAILGUN_SYNC_FROM", chain.deployment_block.get()));
    let span = env_u64("RAILGUN_SYNC_SPAN", 200_000);
    let window = env_u64("RAILGUN_SYNC_WINDOW", 100_000);
    let target = floor.saturating_add(span);

    let path = fixture_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixtures dir");
    }

    // One database file; commitments and decoded notes are tables inside it.
    let db = Database::open(&path).expect("open database");

    // Clean rebuild so the committed fixture holds exactly this window.
    db.clear_all().expect("clear_all");

    let mut syncer = Syncer::new(SubsquidSource::new(chain.subsquid_endpoint), floor);
    syncer.set_block_window(window);

    println!(
        "syncing Sepolia [{}, {}] -> {}",
        floor.get(),
        target.get(),
        path.display()
    );
    let summary = syncer.run(&db, target).await.expect("sync");
    let view = db.read().expect("read view");
    println!(
        "commitments: {}, nullifiers: {}, trees: {}",
        summary.commitments,
        summary.nullifiers,
        view.commitments().tree_count().expect("tree_count")
    );

    let notes = Decoder::from_keys(&keys).decode_all(&view).expect("decode");
    println!("decoded {} owned note(s)", notes.len());
    drop(view);

    db.write(|txn| {
        txn.decoded().save(&notes)?;
        Ok::<_, DatabaseError>(())
    })
    .expect("save decoded notes");

    println!("fixture written: {}", path.display());
}
