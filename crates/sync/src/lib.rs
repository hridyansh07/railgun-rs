//! Chain event sync into the RAILGUN database.
//!
//! Pulls commitments + nullifiers from Railgun's official Subsquid GraphQL index and
//! commits them into the [`database::Database`]: each block-window lands as **one
//! write transaction** carrying the data, the folded merkle frontier snapshots, and
//! the resumable block watermark — atomically.
//!
//! The network is hidden behind the [`EventSource`] trait (a future RPC source is a
//! drop-in). [`Syncer`] is a stateless pump: it reads the resume point from the
//! database, fetches one bounded page at a time, and commits window by window. The
//! database is the single source of truth.

mod chain;
mod error;
mod event;
mod graphql;
mod manager;
mod source;
mod subsquid;

pub use chain::ChainConfig;
pub use error::SyncError;
pub use event::SyncEvent;
pub use manager::{SyncSummary, Syncer};
pub use source::{EventSource, EventStream, Page, RailgunTxSource, TransactionPage};
pub use subsquid::SubsquidSource;
