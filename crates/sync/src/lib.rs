//! Chain event sync into the RAILGUN commitment store.
//!
//! Pulls commitments + nullifiers from Railgun's official Subsquid GraphQL index and
//! commits them into a [`commitments::CommitmentStore`], which owns both the data and
//! the resumable block watermark and advances them atomically.
//!
//! The network is hidden behind the [`EventSource`] trait (a future RPC source is a
//! drop-in). [`Syncer`] is a stateless pump: it reads the resume point from the
//! store, fetches one bounded page at a time, and hands each block-window to the
//! store's atomic `commit`. The store is the single source of truth.

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
pub use source::{EventSource, EventStream, Page};
pub use subsquid::SubsquidSource;
