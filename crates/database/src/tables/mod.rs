//! The table registry: every logical table the database hosts, by typed id.
//!
//! `TableId`'s constructor is private to this module, so a table that isn't
//! registered here cannot be named — no stringly-typed table escapes. All
//! registered tables are materialized and version-checked on [`Database::open`].
//!
//! [`Database::open`]: crate::Database::open

pub mod codec;
pub mod commitments;
pub mod decoded;
pub mod frontier;

/// A registered logical table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TableId(&'static str);

impl TableId {
    pub(crate) const fn name(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for TableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// UTXO merkle forest: commitments, nullifiers, counters, sync watermark.
/// Pre-dates this crate — name and key layout are frozen (fixture compat).
pub const COMMITMENTS: TableId = TableId("commitments");
/// A wallet's decoded notes. Pre-dates this crate — name and layout frozen.
pub const DECODED: TableId = TableId("decoded");
/// Merkle frontier snapshots (opaque bytes per tree), for O(1) roots.
pub const FRONTIER: TableId = TableId("frontier");
/// Database metadata: per-table schema version stamps.
pub const META: TableId = TableId("meta");
/// Railgun txid tree: leaf hashes, records, txid index, pending FIFO, and the
/// pump watermark. Pre-dates this registry — name and key layout frozen.
pub const TXID: TableId = TableId("txid");
/// POI status cache per (blinded commitment, list key).
pub const POI_STATUS: TableId = TableId("poi_status");
/// Pending spent-POI proof obligations, keyed by txid.
pub const POI_PENDING: TableId = TableId("poi_pending");

/// Every table materialized and version-checked on open. Append-only; new
/// subsystems register here.
pub(crate) const ALL_TABLES: &[TableId] = &[
    COMMITMENTS,
    DECODED,
    FRONTIER,
    META,
    TXID,
    POI_STATUS,
    POI_PENDING,
];
