//! Offline tests for the incremental multi-wallet scanner: watermark
//! advancement, segment planning, the backfill rescan queue, and sealed
//! persistence. (The decode *match* path needs ciphertext encrypted to the
//! wallet — no encryption path exists yet — so notes enter via seeded sealed
//! records and `notes_found` stays 0 here, as in the plain decoder tests.)

use crypto::{AesGcmSealer, KeyNode, RailgunMnemonic, Sealer};
use database::DatabaseError;
use decoder::{DecodeError, ScanWallet, Scanner, WalletId};
use types::{
    AssetId, B256, BlindedCommitmentType, BlockNumber, CommitmentHash, DecryptedNote, EvmAddress,
    Node, NodeBody, NodePosition, NoteValue, Nullifier, RailgunAccountIndex, ShieldBody, U256,
    ViewingPublicKey,
};

fn wallet(account: u32) -> (WalletId, ScanWallet, ScanWallet) {
    let mnemonic =
        RailgunMnemonic::parse("test test test test test test test test test test test junk")
            .unwrap();
    let keys = KeyNode::derive_railgun_keys(&mnemonic, RailgunAccountIndex::new(account)).unwrap();
    (
        WalletId::from_keys(&keys),
        ScanWallet::from_keys(&keys),
        ScanWallet::from_keys(&keys),
    )
}

fn shield_node(tree: u32, leaf: u32) -> Node {
    Node {
        position: NodePosition::try_new(tree, leaf).unwrap(),
        hash: CommitmentHash::new(U256::from(u64::from(leaf) + 1)),
        block: BlockNumber::new(1),
        body: NodeBody::Shield(ShieldBody {
            npk: U256::from(7u64),
            token: AssetId::erc20(EvmAddress::from([0x11; 20])),
            value: U256::from(1000u64),
            encrypted_bundle: vec![[0u8; 32], [1u8; 32], [2u8; 32]],
            shield_key: ViewingPublicKey::from_bytes([4u8; 32]),
        }),
    }
}

fn owned_note(leaf: u32) -> DecryptedNote {
    DecryptedNote {
        position: NodePosition::try_new(0, leaf).unwrap(),
        value: NoteValue::new(100),
        asset: AssetId::erc20(EvmAddress::from([0xAA; 20])),
        random: [0u8; 16],
        memo: String::new(),
        commitment_hash: CommitmentHash::new(U256::from(leaf)),
        note_public_key: U256::from(1u64),
        nullifier: Nullifier::new(B256::repeat_byte(u8::try_from(leaf % 255).unwrap())),
        blinded_commitment: U256::from(1u64),
        commitment_type: BlindedCommitmentType::Transact,
    }
}

fn insert_leaves(db: &database::Database, tree: u32, leaves: impl Iterator<Item = u32>) {
    db.write(|txn| {
        let mut commitments = txn.commitments();
        for leaf in leaves {
            commitments.insert_node(&shield_node(tree, leaf))?;
        }
        Ok::<_, DatabaseError>(())
    })
    .unwrap();
}

fn sealer() -> AesGcmSealer {
    AesGcmSealer::new([7u8; 32])
}

#[test]
fn scan_advances_watermarks_and_is_incremental() {
    let db = database::test_util::temp();
    insert_leaves(&db, 0, 0..100);

    let (id, scan_wallet, _) = wallet(0);
    let scanner = Scanner::new(vec![scan_wallet]);
    let sealer = sealer();

    let first = scanner.scan(&db, &sealer).unwrap();
    assert_eq!(first.leaves_scanned, 100);
    assert_eq!(first.attempts, 100);
    assert_eq!(first.notes_found, 0);
    assert_eq!(
        db.read()
            .unwrap()
            .decoded()
            .watermark(id.as_bytes(), 0)
            .unwrap(),
        100
    );

    // Nothing new: the second pass visits nothing.
    let second = scanner.scan(&db, &sealer).unwrap();
    assert_eq!(second.leaves_scanned, 0);

    // Twenty more leaves: only those are visited.
    insert_leaves(&db, 0, 100..120);
    let third = scanner.scan(&db, &sealer).unwrap();
    assert_eq!(third.leaves_scanned, 20);
    assert_eq!(
        db.read()
            .unwrap()
            .decoded()
            .watermark(id.as_bytes(), 0)
            .unwrap(),
        120
    );
}

#[test]
fn late_wallet_backfills_and_overlap_is_read_once() {
    let db = database::test_util::temp();
    insert_leaves(&db, 0, 0..60);

    let (_, wallet_a, wallet_a_again) = wallet(0);
    let sealer = sealer();

    // Wallet A catches up alone.
    let scanner_a = Scanner::new(vec![wallet_a]);
    scanner_a.scan(&db, &sealer).unwrap();

    // Wallet B arrives; 40 more leaves land.
    insert_leaves(&db, 0, 60..100);
    let (_, wallet_b, _) = wallet(1);
    let scanner_ab = Scanner::new(vec![wallet_a_again, wallet_b]);
    let summary = scanner_ab.scan(&db, &sealer).unwrap();

    // Segments: [0,60) B alone (60 leaves, 60 attempts) + [60,100) both
    // (40 leaves read once, 80 attempts).
    assert_eq!(summary.leaves_scanned, 100);
    assert_eq!(summary.attempts, 140);
}

#[test]
fn backfill_enters_rescan_queue_and_scan_drains_it() {
    let db = database::test_util::temp();
    // Positions 0..10 with a gap at 5 (insert order: skip then backfill).
    insert_leaves(&db, 0, (0..10).filter(|&l| l != 5));

    let (_, scan_wallet, scan_wallet_again) = wallet(0);
    let sealer = sealer();
    let scanner = Scanner::new(vec![scan_wallet]);
    scanner.scan(&db, &sealer).unwrap();

    // The backfill lands below the watermark (10) → queued.
    insert_leaves(&db, 0, std::iter::once(5));
    assert_eq!(
        db.read().unwrap().commitments().rescan_queue().unwrap(),
        vec![(0, 5)]
    );

    let summary = Scanner::new(vec![scan_wallet_again])
        .scan(&db, &sealer)
        .unwrap();
    assert_eq!(summary.rescans, 1);
    assert_eq!(summary.leaves_scanned, 1, "only the backfilled position");
    assert!(
        db.read()
            .unwrap()
            .commitments()
            .rescan_queue()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn sealed_records_round_trip_and_wrong_dek_fails() {
    let db = database::test_util::temp();
    insert_leaves(&db, 0, 0..10);

    let (id, scan_wallet, scan_wallet_again) = wallet(0);
    let sealer = sealer();

    // Seed an existing sealed record (as if an earlier scan had found notes).
    let seeded = vec![owned_note(3), owned_note(1)];
    db.write(|txn| {
        let ciphertext = sealer.seal(&serde_json::to_vec(&seeded).unwrap()).unwrap();
        txn.decoded()
            .save_sealed_notes(id.as_bytes(), &ciphertext)?;
        Ok::<_, DatabaseError>(())
    })
    .unwrap();

    Scanner::new(vec![scan_wallet]).scan(&db, &sealer).unwrap();

    // The record survived the scan (merged, sorted by position), still sealed.
    let ciphertext = db
        .read()
        .unwrap()
        .decoded()
        .sealed_notes(id.as_bytes())
        .unwrap()
        .expect("sealed record present");
    let notes: Vec<DecryptedNote> =
        serde_json::from_slice(&sealer.unseal(&ciphertext).unwrap()).unwrap();
    let positions: Vec<u32> = notes.iter().map(|n| n.position.leaf_index()).collect();
    assert_eq!(positions, vec![1, 3]);

    // A scanner with the wrong DEK must fail closed, not wipe the record.
    let wrong = AesGcmSealer::new([9u8; 32]);
    let error = Scanner::new(vec![scan_wallet_again])
        .scan(&db, &wrong)
        .unwrap_err();
    assert!(matches!(error, DecodeError::Seal(_)));
}

#[test]
fn memory_only_scan_persists_nothing_and_carries_cursors() {
    let db = database::test_util::temp();
    insert_leaves(&db, 0, 0..50);

    let (id, scan_wallet, _) = wallet(0);
    let scanner = Scanner::new(vec![scan_wallet]);

    let (notes, cursors, summary) = scanner
        .scan_in_memory(&db, &decoder::ScanCursors::default())
        .unwrap();
    assert_eq!(summary.leaves_scanned, 50);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].1.is_empty());
    assert_eq!(cursors[&(id, 0)], 50);

    // Nothing landed on disk: no sealed record, watermark still zero.
    let view = db.read().unwrap();
    assert!(
        view.decoded()
            .sealed_notes(id.as_bytes())
            .unwrap()
            .is_none()
    );
    assert_eq!(view.decoded().watermark(id.as_bytes(), 0).unwrap(), 0);

    // Carried cursors make the next pass incremental.
    insert_leaves(&db, 0, 50..60);
    let (_, _, summary2) = scanner.scan_in_memory(&db, &cursors).unwrap();
    assert_eq!(summary2.leaves_scanned, 10);
}
