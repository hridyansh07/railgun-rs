//! Test support (behind the `test-util` feature): a tempfile-backed
//! [`Database`] that lives as long as the value.

use std::ops::Deref;

use crate::Database;

/// A [`Database`] on a temporary file, deleted on drop.
pub struct TempDatabase {
    db: Database,
    _dir: tempfile::TempDir,
}

impl Deref for TempDatabase {
    type Target = Database;

    fn deref(&self) -> &Database {
        &self.db
    }
}

/// Opens a fresh database on a tempfile.
///
/// # Panics
/// Panics if the temp directory or database cannot be created — test-only.
#[must_use]
pub fn temp() -> TempDatabase {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db = Database::open(dir.path().join("test.redb")).expect("open temp database");
    TempDatabase { db, _dir: dir }
}
