//! Manual decode benchmark over a synthetic full tree — ignored by default.
//!
//! The committed Sepolia fixture is deliberately sparse (6 stored nodes), so
//! decode timing needs a synthetic load: one full 65,536-leaf tree of
//! realistic *non-matching* shield nodes (each costs the real per-leaf work —
//! ECDH + AES attempt that fails as not-ours). Run with:
//!
//! ```sh
//! cargo test -p decoder --release --test scan_bench -- --ignored --nocapture
//! ```

use std::time::Instant;

use crypto::{KeyNode, RailgunMnemonic};
use database::DatabaseError;
use decoder::Decoder;
use types::{
    AssetId, BlockNumber, CommitmentHash, EvmAddress, Node, NodeBody, NodePosition,
    RailgunAccountIndex, ShieldBody, U256, ViewingPublicKey,
};

const TREE_LEAVES: u32 = 65_536;

/// A deterministic "random-looking" 32-byte block per (position, salt).
fn bytes32(position: u32, salt: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut state = (u64::from(position) << 8) ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for chunk in out.chunks_mut(8) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        chunk.copy_from_slice(&state.to_be_bytes());
    }
    out
}

fn synthetic_node(position: u32) -> Node {
    Node {
        position: NodePosition::try_new(0, position).unwrap(),
        hash: CommitmentHash::new(U256::from_be_bytes(bytes32(position, 1))),
        block: BlockNumber::new(u64::from(position)),
        body: NodeBody::Shield(ShieldBody {
            npk: U256::from_be_bytes(bytes32(position, 2)),
            token: AssetId::erc20(EvmAddress::from([0x11; 20])),
            value: U256::from(1_000u64),
            encrypted_bundle: vec![bytes32(position, 3), bytes32(position, 4)],
            shield_key: ViewingPublicKey::from_bytes(bytes32(position, 5)),
        }),
    }
}

fn bench_wallet() -> crypto::DerivedRailgunKeys {
    let mnemonic =
        RailgunMnemonic::parse("test test test test test test test test test test test junk")
            .unwrap();
    KeyNode::derive_railgun_keys(&mnemonic, RailgunAccountIndex::new(0)).unwrap()
}

#[test]
#[ignore = "manual benchmark: fills a full synthetic tree (slow in debug; run --release)"]
fn bench_threaded_scan_full_tree() {
    use crypto::AesGcmSealer;
    use decoder::{ScanWallet, Scanner};

    let db = database::test_util::temp();
    for window in 0..(TREE_LEAVES / 8192) {
        db.write(|txn| {
            let mut commitments = txn.commitments();
            for leaf in (window * 8192)..((window + 1) * 8192) {
                commitments.insert_node(&synthetic_node(leaf))?;
            }
            Ok::<_, DatabaseError>(())
        })
        .unwrap();
    }

    let keys = bench_wallet();
    let sealer = AesGcmSealer::new([7u8; 32]);

    for threads in [1usize, 2, 4, 8] {
        // Fresh wallet id per run won't help (same watermark row), so wipe it.
        db.write(|txn| {
            let id = decoder::WalletId::from_keys(&keys);
            txn.decoded().set_watermark(id.as_bytes(), 0, 0)?;
            Ok::<_, DatabaseError>(())
        })
        .unwrap();

        let mut scanner = Scanner::new(vec![ScanWallet::from_keys(&keys)]);
        scanner.set_threads(threads);

        let started = Instant::now();
        let summary = scanner.scan(&db, &sealer).unwrap();
        let elapsed = started.elapsed();
        #[allow(clippy::cast_precision_loss)]
        let leaves_per_sec = summary.leaves_scanned as f64 / elapsed.as_secs_f64();
        println!(
            "scan x{threads}: {} leaves in {elapsed:?} ({leaves_per_sec:.0} leaves/sec)",
            summary.leaves_scanned
        );
    }
}

#[test]
#[ignore = "manual benchmark: fills a full synthetic tree (slow in debug; run --release)"]
fn bench_decode_full_tree() {
    let db = database::test_util::temp();

    let fill_started = Instant::now();
    // Commit in windows mirroring real sync batches.
    for window in 0..(TREE_LEAVES / 8192) {
        db.write(|txn| {
            let mut commitments = txn.commitments();
            for leaf in (window * 8192)..((window + 1) * 8192) {
                commitments.insert_node(&synthetic_node(leaf))?;
            }
            Ok::<_, DatabaseError>(())
        })
        .unwrap();
    }
    println!(
        "filled {TREE_LEAVES} leaves in {:?}",
        fill_started.elapsed()
    );

    let decoder = Decoder::from_keys(&bench_wallet());
    let view = db.read().unwrap();

    let started = Instant::now();
    let notes = decoder.decode_tree(&view, 0).unwrap();
    let elapsed = started.elapsed();

    #[allow(clippy::cast_precision_loss)]
    let leaves_per_sec = f64::from(TREE_LEAVES) / elapsed.as_secs_f64();
    println!(
        "decode_tree: {TREE_LEAVES} leaves in {elapsed:?} ({leaves_per_sec:.0} leaves/sec), {} notes",
        notes.len()
    );
}
