//! Per-table schema version stamps in the `meta` table.
//!
//! Stamps are checked on every [`Database::open`](crate::Database::open):
//! a missing stamp means the data pre-dates stamping (the original fixture
//! format) and is treated as the current v1 — it gets stamped on first open.
//! A mismatched stamp fails the open before any consumer can misread records.

use crate::DatabaseError;
use crate::read::Reader;
use crate::tables::{self, TableId};
use crate::write::{WriteTxn, Writer};

/// Current schema version of every registered table.
const SCHEMA_VERSIONS: &[(TableId, u32)] = &[
    (tables::COMMITMENTS, 1),
    (tables::DECODED, 1),
    (tables::FRONTIER, 1),
    (tables::META, 1),
    (tables::TXID, 1),
    (tables::POI_STATUS, 1),
    (tables::POI_PENDING, 1),
];

fn version_key(table: TableId) -> Vec<u8> {
    // alloc-ok: small fixed meta key.
    let mut key = Vec::with_capacity(1 + table.name().len());
    key.push(b'v');
    key.extend_from_slice(table.name().as_bytes());
    key
}

/// The stamped version for `table`, or `None` if never stamped.
pub(crate) fn read_version<R: Reader>(
    reader: &R,
    table: TableId,
) -> Result<Option<u32>, DatabaseError> {
    match reader.get(tables::META, &version_key(table))? {
        Some(bytes) => {
            let array: [u8; 4] = bytes
                .try_into()
                .map_err(|_| DatabaseError::Engine("malformed version stamp".to_owned()))?;
            Ok(Some(u32::from_be_bytes(array)))
        }
        None => Ok(None),
    }
}

/// Checks every registered table's stamp against [`SCHEMA_VERSIONS`],
/// stamping any missing ones (pre-stamp data = current version). Called from
/// the open transaction, and again after a [`clear_all`] wipes `meta`.
///
/// [`clear_all`]: crate::Database::clear_all
pub(crate) fn check_and_stamp(txn: &mut WriteTxn) -> Result<(), DatabaseError> {
    for &(table, expected) in SCHEMA_VERSIONS {
        match read_version(txn, table)? {
            Some(found) if found != expected => {
                return Err(DatabaseError::SchemaVersion {
                    table: table.name(),
                    found,
                    expected,
                });
            }
            Some(_) => {}
            None => {
                txn.put(tables::META, &version_key(table), &expected.to_be_bytes())?;
            }
        }
    }
    Ok(())
}
