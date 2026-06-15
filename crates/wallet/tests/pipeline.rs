//! Facade pipeline tests: sync → scan over a scripted event source, sealed
//! vs memory-only behavior, and the late-wallet flow.

use async_trait::async_trait;
use sync::{EventSource, EventStream, Page, SyncError, SyncEvent, Syncer};
use types::{
    AssetId, BlockNumber, CommitmentHash, EvmAddress, Node, NodeBody, NodePosition,
    RailgunAccountIndex, ShieldBody, U256, ViewingPublicKey,
};
use wallet::Wallets;

/// Serves `leaves` synthetic commitments (all at `block`) in one page.
struct CannedSource {
    head: BlockNumber,
    block: u64,
    leaves: u32,
}

#[async_trait]
impl EventSource for CannedSource {
    async fn latest_block(&self) -> Result<BlockNumber, SyncError> {
        Ok(self.head)
    }

    async fn fetch_page(
        &self,
        stream: EventStream,
        from: BlockNumber,
        to: BlockNumber,
        _cursor: Option<String>,
    ) -> Result<Page, SyncError> {
        let block = BlockNumber::new(self.block);
        let events = match stream {
            EventStream::Commitments if block >= from && block <= to => (0..self.leaves)
                .map(|leaf| SyncEvent::Commitment(shield_node(leaf, self.block)))
                .collect(),
            _ => Vec::new(),
        };
        Ok(Page {
            events,
            cursor: None,
        })
    }
}

fn shield_node(leaf: u32, block: u64) -> Node {
    Node {
        position: NodePosition::try_new(0, leaf).unwrap(),
        hash: CommitmentHash::new(U256::from(u64::from(leaf) + 1)),
        block: BlockNumber::new(block),
        body: NodeBody::Shield(ShieldBody {
            npk: U256::from(7u64),
            token: AssetId::erc20(EvmAddress::from([0x11; 20])),
            value: U256::from(1000u64),
            encrypted_bundle: vec![[0u8; 32], [1u8; 32], [2u8; 32]],
            shield_key: ViewingPublicKey::from_bytes([4u8; 32]),
        }),
    }
}

fn keys(account: u32) -> crypto::DerivedRailgunKeys {
    let mnemonic = crypto::RailgunMnemonic::parse(
        "test test test test test test test test test test test junk",
    )
    .unwrap();
    crypto::KeyNode::derive_railgun_keys(&mnemonic, RailgunAccountIndex::new(account)).unwrap()
}

#[tokio::test]
async fn sync_and_scan_seals_when_unlocked() {
    let db = database::test_util::temp();
    let source = CannedSource {
        head: BlockNumber::new(50),
        block: 10,
        leaves: 30,
    };
    let syncer = Syncer::new(source, BlockNumber::new(0));

    let mut wallets = Wallets::new();
    let id = wallets.register(&keys(0));
    wallets.unlock([7u8; 32]);

    let summary = wallets.sync_and_scan(&db, &syncer).await.unwrap();
    assert_eq!(summary.sync.commitments, 30);
    assert_eq!(summary.scan.leaves_scanned, 30);

    // Sealed record + watermark landed; pipeline is incremental.
    let view = db.read().unwrap();
    assert!(
        view.decoded()
            .sealed_notes(id.as_bytes())
            .unwrap()
            .is_some()
    );
    assert_eq!(view.decoded().watermark(id.as_bytes(), 0).unwrap(), 30);
    drop(view);

    let again = wallets.sync_and_scan(&db, &syncer).await.unwrap();
    assert_eq!(again.sync.commitments, 0);
    assert_eq!(again.scan.leaves_scanned, 0);

    // The wallet owns nothing in this synthetic tree, but the query path works.
    assert!(wallets.notes(&db, id).unwrap().notes_by_asset().is_empty());
}

#[tokio::test]
async fn locked_pipeline_persists_nothing() {
    let db = database::test_util::temp();
    let source = CannedSource {
        head: BlockNumber::new(50),
        block: 10,
        leaves: 10,
    };
    let syncer = Syncer::new(source, BlockNumber::new(0));

    let mut wallets = Wallets::new();
    let id = wallets.register(&keys(0));
    assert!(!wallets.is_unlocked());

    let summary = wallets.sync_and_scan(&db, &syncer).await.unwrap();
    assert_eq!(summary.scan.leaves_scanned, 10);

    // Chain data is durable; nothing wallet-derived is.
    let view = db.read().unwrap();
    assert_eq!(view.commitments().tree_length(0).unwrap(), 10);
    assert!(
        view.decoded()
            .sealed_notes(id.as_bytes())
            .unwrap()
            .is_none()
    );
    assert_eq!(view.decoded().watermark(id.as_bytes(), 0).unwrap(), 0);
    drop(view);

    // In-memory cursors still make the session incremental.
    let again = wallets.sync_and_scan(&db, &syncer).await.unwrap();
    assert_eq!(again.scan.leaves_scanned, 0);
}

#[tokio::test]
async fn late_wallet_backfills_on_next_scan() {
    let db = database::test_util::temp();
    let source = CannedSource {
        head: BlockNumber::new(50),
        block: 10,
        leaves: 20,
    };
    let syncer = Syncer::new(source, BlockNumber::new(0));

    let mut wallets = Wallets::new();
    wallets.register(&keys(0));
    wallets.unlock([7u8; 32]);
    wallets.sync_and_scan(&db, &syncer).await.unwrap();

    // A second wallet arrives: next scan backfills exactly its 20 leaves.
    let late = wallets.register(&keys(1));
    let summary = wallets.scan(&db).unwrap();
    assert_eq!(summary.leaves_scanned, 20);
    assert_eq!(summary.attempts, 20, "only the late wallet attempts");
    assert_eq!(
        db.read()
            .unwrap()
            .decoded()
            .watermark(late.as_bytes(), 0)
            .unwrap(),
        20
    );

    let error = wallets.notes(&db, decoder::WalletId::from_keys(&keys(9)));
    assert!(matches!(error, Err(wallet::WalletError::UnknownWallet(_))));
}
