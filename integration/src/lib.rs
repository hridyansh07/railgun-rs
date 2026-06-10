//! Shared helpers for the whole-stack integration tests.
//!
//! This crate ships no product code — only the wiring the cross-crate tests in
//! `tests/` share: loading the git-ignored `.env`, building the test wallet from it,
//! and locating the committed redb fixture. Keeping it here (rather than inside any
//! single product crate) means no crate has to dev-depend on the entire graph just to
//! host end-to-end tests.
//!
//! Tests opt in with `use integration_tests::*;`. Anything that needs a secret reads
//! it from the environment and **returns `None` when unset**, so the default
//! `cargo test` stays green on a clean checkout — secrets and fixtures are opt-in.

use std::path::PathBuf;
use std::sync::Once;

use crypto::{DerivedRailgunKeys, KeyNode, RailgunMnemonic};
use types::RailgunAccountIndex;

/// Loads the repo-root `.env` into the process environment, at most once.
///
/// `dotenvy::dotenv()` searches the current dir and its parents, so the workspace-root
/// `.env` is found from any crate's test cwd. Missing `.env` is not an error (the
/// helpers below just see unset vars and signal "skip").
pub fn load_env() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = dotenvy::dotenv();
    });
}

/// A test-configured env var, or `None` if unset/empty (the "not configured → skip"
/// signal). Calls [`load_env`] first.
#[must_use]
pub fn test_var(key: &str) -> Option<String> {
    load_env();
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

/// The RAILGUN account index for the test wallet (`RAILGUN_TEST_ACCOUNT_INDEX`, default 0).
///
/// # Panics
/// Panics if the variable is set but not a valid `u32` (a misconfigured `.env`).
#[must_use]
pub fn account_index() -> RailgunAccountIndex {
    let index = test_var("RAILGUN_TEST_ACCOUNT_INDEX").map_or(0, |raw| {
        raw.parse::<u32>()
            .expect("RAILGUN_TEST_ACCOUNT_INDEX must be a u32")
    });
    RailgunAccountIndex::new(index)
}

/// The derived test wallet from `RAILGUN_TEST_MNEMONIC`, or `None` if that var is
/// unset — in which case the caller should print a note and return (skip).
///
/// # Panics
/// Panics if the mnemonic is set but invalid, or derivation fails (a misconfigured
/// `.env`, which should fail loudly rather than silently skip).
#[must_use]
pub fn test_wallet() -> Option<DerivedRailgunKeys> {
    let phrase = test_var("RAILGUN_TEST_MNEMONIC")?;
    let mnemonic =
        RailgunMnemonic::parse(phrase).expect("RAILGUN_TEST_MNEMONIC is not a valid mnemonic");
    let keys = KeyNode::derive_railgun_keys(&mnemonic, account_index())
        .expect("failed to derive keys from RAILGUN_TEST_MNEMONIC");
    Some(keys)
}

/// Path to the committed Sepolia redb fixture.
///
/// Defaults to `<this crate>/tests/fixtures/sepolia.redb` (resolved from
/// `CARGO_MANIFEST_DIR`, so it is independent of the test's working directory) and is
/// overridable with `RAILGUN_REDB_FIXTURE` for ad-hoc runs.
#[must_use]
pub fn fixture_path() -> PathBuf {
    if let Some(path) = test_var("RAILGUN_REDB_FIXTURE") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sepolia.redb")
}
