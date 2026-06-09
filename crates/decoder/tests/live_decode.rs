//! Live, network-gated decode runner.
//!
//! Ignored by default (it hits the real Subsquid endpoint and needs a mnemonic). Run:
//!
//! ```sh
//! RAILGUN_MNEMONIC="word word ... word" \
//!   cargo test -p decoder --test live_decode -- --ignored --nocapture
//! ```
//!
//! Overridable via env: `RAILGUN_SYNC_WINDOW`, `RAILGUN_SYNC_SPAN`, `RAILGUN_SYNC_FROM`.

use commitments::CommitmentStore;
use crypto::{KeyNode, RailgunMnemonic};
use decoder::{DecodedNoteStore, DecodedNotes, Decoder};
use sync::{ChainConfig, SubsquidSource, Syncer};
use types::{BlockNumber, RailgunAccountIndex};
use utils::RedbBackend;

const DEFAULT_WINDOW: u64 = 100_000;
const DEFAULT_SPAN: u64 = 5_000_000;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[tokio::test]
#[ignore = "hits the live Subsquid endpoint; requires RAILGUN_MNEMONIC"]
async fn live_decode_mainnet() {
    let Ok(phrase) = std::env::var("RAILGUN_MNEMONIC") else {
        eprintln!("set RAILGUN_MNEMONIC to run this test");
        return;
    };
    let mnemonic = RailgunMnemonic::parse(phrase).expect("valid mnemonic");
    let keys =
        KeyNode::derive_railgun_keys(&mnemonic, RailgunAccountIndex::new(0)).expect("derive keys");

    let chain = ChainConfig::mainnet();
    let window = env_u64("RAILGUN_SYNC_WINDOW", DEFAULT_WINDOW);
    let span = env_u64("RAILGUN_SYNC_SPAN", DEFAULT_SPAN);
    let floor = std::env::var("RAILGUN_SYNC_FROM")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(chain.deployment_block, BlockNumber::new);
    let target = floor.saturating_add(span);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("railgun.redb");

    // One redb file, two tables: merkle commitments and decoded notes.
    let commitments_backend = RedbBackend::open(&path, "commitments").expect("open redb");
    let decoded_backend = commitments_backend.table("decoded").expect("decoded table");
    let mut cstore = CommitmentStore::new(commitments_backend);

    let mut syncer = Syncer::new(SubsquidSource::new(chain.subsquid_endpoint), floor);
    syncer.set_block_window(window);

    println!("syncing mainnet [{}, {}] ...", floor.get(), target.get());
    let summary = syncer.run(&mut cstore, target).await.expect("sync");
    println!(
        "commitments: {}, nullifiers: {}",
        summary.commitments, summary.nullifiers
    );

    let decoder = Decoder::from_keys(&keys);
    let notes = decoder.decode_all(&cstore).expect("decode");
    println!("decoded {} owned note(s)", notes.len());

    // Persist into the "decoded" table, then reload and report balances.
    let mut nstore = DecodedNoteStore::new(decoded_backend);
    nstore.save(&notes).expect("persist notes");
    let owned = DecodedNotes::from_notes(nstore.load().expect("reload notes"));
    let balances = owned.balances(&cstore).expect("balances");

    println!("\n=== balances ({} asset(s)) ===", balances.len());
    for (asset, balance) in &balances {
        println!(
            "  {asset:?}: value={} unspent={}",
            balance.value,
            balance.unspent_utxos.len()
        );
    }
}
