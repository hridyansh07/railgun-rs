use types::{BlockNumber, RailgunTransaction};

use crate::{SyncError, SyncEvent};

/// Which on-chain event stream a page is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStream {
    Commitments,
    Nullifiers,
}

/// One bounded page of events plus the cursor to resume after it.
///
/// `cursor: None` means the stream is exhausted for the requested range; otherwise
/// pass it back as the next `fetch_page` cursor.
#[derive(Debug)]
pub struct Page {
    pub events: Vec<SyncEvent>,
    pub cursor: Option<String>,
}

/// A swappable source of chain events.
///
/// The syncer pulls one bounded page at a time and drains it into the store, so peak
/// memory is one page (HTTP response) regardless of the range. A future RPC source
/// implements this same trait; reconnection/retry policy lives inside each
/// implementation.
///
/// Prefering Single Page Fetches Here for Pagination
///
// Could look into Substreams to parallize the sink from different block ranges that are reconciled
// on the Sink Level?
#[async_trait::async_trait]
pub trait EventSource: Send + Sync {
    /// The highest block the source can currently serve.
    async fn latest_block(&self) -> Result<BlockNumber, SyncError>;

    /// One page of `stream` events within the inclusive block range `[from, to]`,
    /// resuming after `cursor` (`None` = from the start of the range).
    async fn fetch_page(
        &self,
        stream: EventStream,
        from: BlockNumber,
        to: BlockNumber,
        cursor: Option<String>,
    ) -> Result<Page, SyncError>;
}

/// One bounded page of RAILGUN transaction events plus the resume cursor
/// (same contract as [`Page`]).
#[derive(Debug)]
pub struct TransactionPage {
    pub transactions: Vec<RailgunTransaction>,
    pub cursor: Option<String>,
}

/// A swappable source of `RailgunSmartWallet` Transaction events — the leaves
/// of the txid tree, consumed by the POI txid indexer. Kept as a sibling of
/// [`EventSource`] so the commitment/nullifier pump stays untouched.
#[async_trait::async_trait]
pub trait RailgunTxSource: Send + Sync {
    /// The highest block the source can currently serve.
    async fn latest_block(&self) -> Result<BlockNumber, SyncError>;

    /// One page of transaction events within the inclusive block range
    /// `[from, to]`, resuming after `cursor` (`None` = start of the range).
    async fn fetch_transactions_page(
        &self,
        from: BlockNumber,
        to: BlockNumber,
        cursor: Option<String>,
    ) -> Result<TransactionPage, SyncError>;
}
