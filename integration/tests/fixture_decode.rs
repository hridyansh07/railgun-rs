//! Offline end-to-end test over the committed Sepolia fixture: merkle-root
//! recomputation + note decode/balances on real chain data — no network.
//!
//! This is also the **disk-format compatibility gate** for the unified
//! database crate: the fixture file was written by the pre-`database` stores,
//! so opening it here and reading every table proves the key layouts, codec,
//! and table names survived the migration byte-for-byte. (The first open adds
//! the new `meta`/`frontier` tables and stamps versions — a benign write to a
//! gitignored local file.)
//!
//! It is a **single** test on purpose: redb takes an exclusive lock per file, so opening
//! the same fixture from two tests running on parallel threads would race. Everything
//! that touches the fixture lives here, behind one open. Skips cleanly when the fixture
//! is missing or empty, so a clean checkout stays green; regenerate the fixture with the
//! `build_fixture` test.

use crypto::MerkleWalk;
use database::Database;
use decoder::{DecodedNotes, Decoder};
use integration_tests::{fixture_path, init_tracing, test_wallet};

#[test]
fn fixture_recomputes_roots_and_decodes_balances() {
    init_tracing();
    let path = fixture_path();
    if !path.exists() {
        eprintln!(
            "skipping: no fixture at {} (run `build_fixture` to create it)",
            path.display()
        );
        return;
    }
    let db = Database::open(&path).expect("open fixture");
    let view = db.read().expect("read view");
    if !view.commitments().is_synced().expect("is_synced") {
        eprintln!("skipping: fixture at {} is empty", path.display());
        return;
    }

    // 1) Merkle integrity over the real, Subsquid-sourced leaves: every tree's root
    //    recomputes, exercising the codec + redb round-trip + merkle walk on real data.
    let trees = view.commitments().tree_count().expect("tree_count");
    assert!(trees >= 1, "a synced fixture must hold at least one tree");
    for tree in 0..trees {
        let leaves = view.commitments().tree_length(tree).expect("tree_length");
        let root = view
            .merkle_root(tree)
            .expect("merkle root computes over real leaves");
        println!("tree {tree}: {leaves} leaves, root {root:?}");
        assert!(leaves > 0, "tree {tree} unexpectedly has no leaves");
    }

    // 2) Decode parity: the fixture's notes were encrypted (by the real RAILGUN client)
    //    to keys derived from this mnemonic, so decrypting them proves our derivation
    //    matches that client end-to-end — the strongest parity signal we have.
    let Some(keys) = test_wallet() else {
        eprintln!("skipping balances: set RAILGUN_TEST_MNEMONIC to decode the fixture");
        return;
    };
    let notes = Decoder::from_keys(&keys).decode_all(&view).expect("decode");
    assert!(
        !notes.is_empty(),
        "expected the wallet to own at least one note in the fixture"
    );

    let owned = DecodedNotes::from_notes(notes);
    let balances = owned.balances(&view).expect("balances");
    println!("decoded {} asset balance(s):", balances.len());
    for (asset, balance) in &balances {
        println!(
            "  {asset:?}: value={} unspent={}",
            balance.value,
            balance.unspent_utxos.len()
        );
    }
    // TODO(user): pin the exact expected asset / value / unspent here to lock the fixture
    // as a regression guard (e.g. the Sepolia WETH note seen in the current fixture).
}
