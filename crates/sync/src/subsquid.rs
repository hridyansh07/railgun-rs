//! Subsquid GraphQL [`EventSource`].

use std::time::Duration;

use reqwest::Client;
use serde::{Serialize, de::DeserializeOwned};
use tracing::warn;
use types::BlockNumber;

use crate::{
    EventSource, EventStream, Page, RailgunTxSource, SyncError, TransactionPage,
    graphql::{
        BlockNumberResponse, CommitmentsResponse, GraphqlRequest, GraphqlResponse,
        NullifiersResponse, QueryVars, TransactionsResponse, map_commitment, map_nullifier,
        map_transaction,
    },
};

const COMMITMENTS_QUERY: &str = include_str!("graphql/commitments.graphql");
const NULLIFIERS_QUERY: &str = include_str!("graphql/nullifiers.graphql");
const BLOCK_NUMBER_QUERY: &str = include_str!("graphql/block_number.graphql");
const TRANSACTIONS_QUERY: &str = include_str!("graphql/transactions.graphql");

/// Default rows per GraphQL page
/// NOTE: TEST AND CHANGE
const DEFAULT_PAGE_LIMIT: u64 = 20_000;
/// Default GraphQL request retry budget.
const DEFAULT_MAX_RETRIES: usize = 3;
/// Default delay between retries.
const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Reads RAILGUN events from a Subsquid GraphQL endpoint, with bounded retries.
pub struct SubsquidSource {
    client: Client,
    url: String,
    page_limit: u64,
    max_retries: usize,
    retry_delay: Duration,
}

impl SubsquidSource {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            url: url.into(),
            page_limit: DEFAULT_PAGE_LIMIT,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_delay: DEFAULT_RETRY_DELAY,
        }
    }

    /// Sets the rows fetched per page.
    ///
    /// # Panics
    /// Panics if `page_limit` is zero.
    pub fn set_page_limit(&mut self, page_limit: u64) {
        assert!(page_limit > 0, "page_limit must be non-zero");
        self.page_limit = page_limit;
    }

    /// Sets the retry budget and the delay between attempts.
    pub fn set_retries(&mut self, max_retries: usize, retry_delay: Duration) {
        self.max_retries = max_retries;
        self.retry_delay = retry_delay;
    }

    async fn post_retry<V: Serialize, R: DeserializeOwned>(
        &self,
        query: &'static str,
        variables: V,
    ) -> Result<R, SyncError> {
        let body = GraphqlRequest { query, variables };
        let mut attempt = 0usize;
        loop {
            match self.post_once(&body).await {
                Ok(data) => return Ok(data),
                Err(error) => {
                    attempt += 1;
                    if attempt > self.max_retries {
                        return Err(error);
                    }
                    warn!(
                        attempt,
                        max = self.max_retries,
                        %error,
                        "graphql request failed; retrying"
                    );
                    futures_timer::Delay::new(self.retry_delay).await;
                }
            }
        }
    }

    async fn post_once<V: Serialize, R: DeserializeOwned>(
        &self,
        body: &GraphqlRequest<V>,
    ) -> Result<R, SyncError> {
        let resp = self.client.post(&self.url).json(body).send().await?;

        if !resp.status().is_success() {
            return Err(SyncError::Request {
                status: resp.status(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let parsed: GraphqlResponse<R> = resp.json().await?;
        if let Some(errors) = parsed.errors {
            return Err(SyncError::GraphQl(
                errors
                    .into_iter()
                    .map(|e| e.message)
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
        parsed
            .data
            .ok_or_else(|| SyncError::GraphQl("no data in response".to_string()))
    }

    fn vars(&self, cursor: Option<String>, from: BlockNumber, to: BlockNumber) -> QueryVars {
        QueryVars {
            id_gt: cursor.unwrap_or_default(),
            block_number_gte: from.get(),
            block_number_lte: to.get(),
            limit: self.page_limit,
        }
    }
}

#[async_trait::async_trait]
impl EventSource for SubsquidSource {
    async fn latest_block(&self) -> Result<BlockNumber, SyncError> {
        let resp: BlockNumberResponse = self.post_retry(BLOCK_NUMBER_QUERY, ()).await?;
        Ok(BlockNumber::new(
            resp.transactions.first().map_or(0, |t| t.block_number),
        ))
    }

    async fn fetch_page(
        &self,
        stream: EventStream,
        from: BlockNumber,
        to: BlockNumber,
        cursor: Option<String>,
    ) -> Result<Page, SyncError> {
        let vars = self.vars(cursor, from, to);
        match stream {
            EventStream::Commitments => {
                let resp: CommitmentsResponse = self.post_retry(COMMITMENTS_QUERY, vars).await?;
                // Cursor comes from the raw rows, not the mapped events: a page made
                // entirely of skipped (e.g. NFT) commitments must still advance.
                let cursor = resp.commitments.last().map(|c| c.id.clone());
                // alloc-ok: one bounded page of events handed to the syncer.
                let events = resp
                    .commitments
                    .into_iter()
                    .filter_map(map_commitment)
                    .collect();
                Ok(Page { events, cursor })
            }
            EventStream::Nullifiers => {
                let resp: NullifiersResponse = self.post_retry(NULLIFIERS_QUERY, vars).await?;
                let cursor = resp.nullifiers.last().map(|n| n.id.clone());
                // alloc-ok: one bounded page of events handed to the syncer.
                let events = resp.nullifiers.iter().map(map_nullifier).collect();
                Ok(Page { events, cursor })
            }
        }
    }
}

#[async_trait::async_trait]
impl RailgunTxSource for SubsquidSource {
    async fn latest_block(&self) -> Result<BlockNumber, SyncError> {
        EventSource::latest_block(self).await
    }

    async fn fetch_transactions_page(
        &self,
        from: BlockNumber,
        to: BlockNumber,
        cursor: Option<String>,
    ) -> Result<TransactionPage, SyncError> {
        let vars = self.vars(cursor, from, to);
        let resp: TransactionsResponse = self.post_retry(TRANSACTIONS_QUERY, vars).await?;
        let cursor = resp.transactions.last().map(|t| t.id.clone());
        // alloc-ok: one bounded page of events handed to the indexer.
        let transactions = resp.transactions.into_iter().map(map_transaction).collect();
        Ok(TransactionPage {
            transactions,
            cursor,
        })
    }
}
