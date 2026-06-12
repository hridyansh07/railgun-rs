//! Domain vocabulary for Private Proof of Innocence: the anonymous commitment
//! handle POI lists track, list identifiers, and per-list statuses.
//!
//! These are protocol-level types (the sibling of
//! [`BlindedCommitmentType`](crate::BlindedCommitmentType)); the POI node's
//! JSON-RPC request/response shapes live with the client that speaks them.

use crate::U256;
use crate::commitment::DecryptedNote;
use crate::protocol::RailgunTxid;

/// Identifier of a POI list (a curated innocence list a wallet proves against).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ListKey(String);

impl ListKey {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ListKey {
    fn from(value: &str) -> Self {
        ListKey(value.to_owned())
    }
}

impl From<String> for ListKey {
    fn from(value: String) -> Self {
        ListKey(value)
    }
}

impl std::fmt::Display for ListKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A blinded UTXO commitment — `poseidon(hash, npk, global_position)` — the
/// anonymous handle POI lists track. Serializes as `0x`-prefixed 64-digit hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
pub struct BlindedCommitment(U256);

impl BlindedCommitment {
    /// The blinded commitment a note carries from decryption.
    #[must_use]
    pub fn from_note(note: &DecryptedNote) -> Self {
        BlindedCommitment(note.blinded_commitment)
    }

    /// An unshield's blinded commitment: the railgun txid itself (unshields
    /// produce no UTXO commitment to blind).
    #[must_use]
    pub fn from_unshield(txid: RailgunTxid) -> Self {
        BlindedCommitment(txid.as_u256())
    }

    #[must_use]
    pub fn as_u256(self) -> U256 {
        self.0
    }
}

impl From<U256> for BlindedCommitment {
    fn from(value: U256) -> Self {
        BlindedCommitment(value)
    }
}

impl serde::Serialize for BlindedCommitment {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{:064x}", self.0))
    }
}

impl std::fmt::Display for BlindedCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:064x}", self.0)
    }
}

/// A UTXO's standing on one POI list.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum PoiStatus {
    Valid,
    ProofSubmitted,
    Missing,
    ShieldBlocked,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blinded_commitment_serializes_prefixed_and_padded() {
        let bc = BlindedCommitment::from(U256::from(0xabcdu64));
        let json = serde_json::to_string(&bc).unwrap();
        assert_eq!(
            json,
            "\"0x000000000000000000000000000000000000000000000000000000000000abcd\""
        );
    }

    #[test]
    fn unshield_blinded_commitment_is_the_txid() {
        let txid = RailgunTxid::new(U256::from(42u64));
        assert_eq!(
            BlindedCommitment::from_unshield(txid).as_u256(),
            txid.as_u256()
        );
    }
}
