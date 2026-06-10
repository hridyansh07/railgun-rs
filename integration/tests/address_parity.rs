//! External `0zk` address parity: does our derivation reproduce the address a real
//! RAILGUN client shows for the same mnemonic?
//!
//! This is the only address check worth doing *here*. The deterministic "test…junk"
//! path is already covered by `crypto`'s `derives_zk_address_for_account` and `types`'s
//! `address.rs` encode vectors, so it isn't repeated. And the strongest parity signal is
//! actually `fixture_decode`: decrypting real notes proves our keys match the client
//! that created them, end-to-end — a stronger statement than comparing address strings.
//!
//! Set `RAILGUN_TEST_MNEMONIC` to derive and print the wallet's address; add the
//! authoritative `RAILGUN_TEST_0ZK` (copied from a real RAILGUN client) to turn the
//! print into a hard assertion.

use crypto::ViewingKeyPublicKey;
use integration_tests::{test_var, test_wallet};
use types::{ChainId, RailgunAddress};

#[test]
fn derived_0zk_matches_the_authoritative_address() {
    let Some(keys) = test_wallet() else {
        eprintln!("skipping: set RAILGUN_TEST_MNEMONIC in .env to derive an address");
        return;
    };

    let Some(expected) = test_var("RAILGUN_TEST_0ZK") else {
        // Mnemonic only → derive and print, so you can eyeball the address and paste one
        // back as RAILGUN_TEST_0ZK to lock parity. Useful output, not yet an assertion.
        eprintln!("RAILGUN_TEST_0ZK unset — derived addresses for RAILGUN_TEST_MNEMONIC:");
        eprintln!(
            "  mainnet (chain 1):        {}",
            keys.address(ChainId::evm(1))
        );
        eprintln!(
            "  sepolia (chain 11155111): {}",
            keys.address(ChainId::evm(11_155_111))
        );
        eprintln!(
            "  all chains:               {}",
            keys.address(ChainId::all())
        );
        eprintln!("set RAILGUN_TEST_0ZK (from a real client) to assert parity");
        return;
    };

    // The authoritative address carries its own chain hint; re-derive with it and assert
    // our derivation reproduces the exact string.
    let expected_address: RailgunAddress = expected
        .parse()
        .expect("RAILGUN_TEST_0ZK is a valid 0zk address");
    let derived = keys.address(expected_address.chain());

    assert_eq!(
        derived.to_string(),
        expected,
        "derived 0zk does not match the authoritative RAILGUN_TEST_0ZK"
    );
    // ...and that authoritative address must encode exactly the keys we derived.
    assert_eq!(expected_address.master_key(), keys.master_public_key);
    assert_eq!(
        expected_address.viewing_pubkey().as_bytes(),
        keys.viewing_key.public_key().as_bytes()
    );
}
