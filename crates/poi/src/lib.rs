//! Private Proof of Innocence (POI) for RAILGUN.
//!
//! Everything a wallet needs on the POI spend path, up to (but not including)
//! Groth16 proving:
//!
//! - [`client`]: JSON-RPC client for POI aggregator nodes (`ppoi_*` methods).
//! - [`txid`]: the railgun txid merkle tree — table namespaces over the shared
//!   `database` + sync pump, validated against the POI node's view.
//! - [`status`]: per-(blinded commitment, list key) POI status cache and the
//!   balance-bucket spendability model.
//! - [`inputs`]: POI circuit witness assembly, ending at the
//!   [`railgun_prover::CircuitProver`] seam.
//! - [`pending`]: persisted records for post-transaction (spent) POI proofs,
//!   drained by a future submission loop.

pub mod client;
pub mod inputs;
pub mod pending;
pub mod status;
#[cfg(test)]
pub(crate) mod test_support;
pub mod txid;
pub mod types;

pub use client::{PoiClient, PoiClientError, PoiNodeClient};
pub use inputs::{PoiCircuitInputs, PoiInputsError, PoiNote, dummy_merkle_proof};
pub use pending::{PendingPoiEntry, PendingPoiError, PendingPois, PendingPoisMut};
pub use status::{
    BalanceBucket, BucketedBalances, PoiStatusError, PoiStatusRefresher, PoiStatuses,
    PoiStatusesMut, RefreshSummary, StatusRecord, balance_bucket, bucket_balances,
};
pub use txid::{
    TxidError, TxidIndexer, TxidIndexerError, TxidRecord, TxidSyncSummary, Txids, TxidsMut,
};
pub use types::{
    BlindedCommitment, BlindedCommitmentData, ChainParams, GetMerkleProofsParams,
    GetPoisPerListParams, ListKey, PoiStatus, PoisPerListMap, SubmitTransactProofParams,
    TransactProofData, TxidVersion, ValidateTxidMerklerootParams, ValidatedRailgunTxidStatus,
};
