//! On-chain RAILGUN transaction events (the txid-tree vocabulary).

use crate::{BlockNumber, U256};

/// One `RailgunSmartWallet` Transaction event — a single private operation.
///
/// These are the leaves of the railgun txid tree: the txid is derived from
/// `nullifiers`/`commitments`/`bound_params_hash`, and the leaf hash binds it
/// to the UTXO-tree positions the operation consumed and produced. Produced by
/// the sync layer, consumed by the POI txid indexer.
///
/// Unshield-only operations carry the protocol sentinel positions
/// (`99999 * 65536 + 99999`) in `utxo_tree_out`/`utxo_batch_start_position_out`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RailgunTransaction {
    pub block: BlockNumber,
    // alloc-ok: ≤13 entries, chain-event DTO boundary.
    pub nullifiers: Vec<U256>,
    // alloc-ok: ≤13 entries, chain-event DTO boundary.
    pub commitments: Vec<U256>,
    pub bound_params_hash: U256,
    pub utxo_tree_in: u32,
    pub utxo_tree_out: u32,
    pub utxo_batch_start_position_out: u32,
}
