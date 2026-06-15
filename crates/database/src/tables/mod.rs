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

/// A registered logical table. Adding a table = adding a variant; the
/// exhaustive matches in [`name`](Self::name) and
/// [`schema_version`](Self::schema_version) make the compiler walk you
/// through the registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TableId {
    /// UTXO merkle forest: commitments, nullifiers, counters, sync watermark.
    /// Pre-dates this crate — name and key layout are frozen (fixture compat).
    Commitments,
    /// A wallet's decoded notes. Pre-dates this crate — name and layout frozen.
    Decoded,
    /// Merkle frontier snapshots (opaque bytes per tree), for O(1) roots.
    Frontier,
    /// Database metadata: per-table schema version stamps.
    Meta,
    /// Railgun txid tree: leaf hashes, records, txid index, pending FIFO, and
    /// the pump watermark. Pre-dates this registry — name and layout frozen.
    Txid,
    /// POI status cache per (blinded commitment, list key).
    PoiStatus,
    /// Pending spent-POI proof obligations, keyed by txid.
    PoiPending,
}

impl TableId {
    /// Every table, materialized and version-checked on open.
    pub(crate) const ALL: &[TableId] = &[
        TableId::Commitments,
        TableId::Decoded,
        TableId::Frontier,
        TableId::Meta,
        TableId::Txid,
        TableId::PoiStatus,
        TableId::PoiPending,
    ];

    /// The engine-level table name. **Frozen** — existing database files are
    /// read by these strings.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            TableId::Commitments => "commitments",
            TableId::Decoded => "decoded",
            TableId::Frontier => "frontier",
            TableId::Meta => "meta",
            TableId::Txid => "txid",
            TableId::PoiStatus => "poi_status",
            TableId::PoiPending => "poi_pending",
        }
    }

    /// The current schema version stamped/checked for this table.
    pub(crate) const fn schema_version(self) -> u32 {
        match self {
            TableId::Commitments
            | TableId::Decoded
            | TableId::Frontier
            | TableId::Meta
            | TableId::Txid
            | TableId::PoiStatus
            | TableId::PoiPending => 1,
        }
    }
}

impl std::fmt::Display for TableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
