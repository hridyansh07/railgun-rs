//! The `0zk` RAILGUN address — the bech32m string a wallet shows and shares.
//!
//! An address is a public envelope around already-derived key material: the account's
//! [`master public key`](crate::PoseidonHash), its [`viewing public key`](crate::ViewingPublicKey),
//! and an advisory [`ChainId`]. It carries no secret material and does no hashing — building
//! the master key from private keys lives in `crypto`.
//!
//! byte-exact with the TypeScript RAILGUN engine
//! (`engine/src/key-derivation/bech32.ts`): a fixed 73-byte payload, bech32m-encoded under the
//! `0zk` human-readable prefix.
//!
//! Payload layout (73 bytes): `version(1) | master_public_key(32, BE) | network_id(8) | viewing_public_key(32)`.
//! The 8-byte network id is `chain_type(1) | chain_id(7, BE)` XOR'd with `b"railgun\0"`

use core::fmt;
use core::str::FromStr;

use bech32::{Bech32m, Hrp};

use crate::{PoseidonHash, U256, ViewingPublicKey};

/// Address format version. The only version this crate encodes or accepts.
const VERSION: u8 = 1;

/// Human-readable prefix for the bech32m encoding.
const PREFIX: Hrp = Hrp::parse_unchecked("0zk");

/// Cosmetic mask applied to the 8-byte network id (matches the engine's `'railgun'` key, which
/// XORs the 8th byte against an implicit `0`).
const NETWORK_ID_XOR_KEY: [u8; 8] = *b"railgun\0";

/// The 8-byte all-ones network id, meaning "no specific chain" / valid on all chains.
const ALL_CHAINS_NETWORK_ID: [u8; 8] = [0xff; 8];

/// Chain type byte for EVM chains (the high byte of the network id).
const CHAIN_TYPE_EVM: u8 = 0x00;

/// Advisory chain hint encoded in a [`RailgunAddress`].
///
/// This is a *display-layer* hint about where the owner expects to transact; it has no
/// protocol-level enforcement. It is deliberately distinct from the bare `alloy_primitives::ChainId`
/// (`u64`) the `sync` crate uses for RPC — that one identifies an actual chain to talk to; this one
/// is an opt-in advisory baked into a shareable address (and may be [`All`](ChainId::All)).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ChainId {
    /// No specific chain — the address is advertised as valid everywhere.
    All,
    /// An EVM chain identified by its EIP-155 id (low 7 bytes; the high byte is the EVM type tag).
    Evm { id: u64 },
}

impl ChainId {
    #[must_use]
    pub fn evm(id: u64) -> Self {
        ChainId::Evm { id }
    }

    #[must_use]
    pub fn all() -> Self {
        ChainId::All
    }

    /// The 8-byte network id (pre-XOR): `chain_type(1) | chain_id(7, BE)`.
    fn to_network_id(self) -> [u8; 8] {
        match self {
            ChainId::All => ALL_CHAINS_NETWORK_ID,
            // Mask to 7 bytes so the high byte stays the EVM type tag (0x00).
            ChainId::Evm { id } => (id & 0x00ff_ffff_ffff_ffff).to_be_bytes(),
        }
    }

    /// Interprets an 8-byte network id (post-XOR-removal) back into a chain hint.
    fn from_network_id(bytes: [u8; 8]) -> Result<Self, RailgunAddressError> {
        if bytes == ALL_CHAINS_NETWORK_ID {
            return Ok(ChainId::All);
        }
        let value = u64::from_be_bytes(bytes);
        let chain_type = (value >> 56) as u8;
        let id = value & 0x00ff_ffff_ffff_ffff;
        match chain_type {
            CHAIN_TYPE_EVM => Ok(ChainId::Evm { id }),
            other => Err(RailgunAddressError::UnknownChainType(other)),
        }
    }
}

/// XORs the 8 network-id bytes with the cosmetic `railgun\0` mask. Its own inverse.
fn xor_network_id(mut bytes: [u8; 8]) -> [u8; 8] {
    for (b, key) in bytes.iter_mut().zip(NETWORK_ID_XOR_KEY.iter()) {
        *b ^= key;
    }
    bytes
}

/// A RAILGUN `0zk` address: the public identifier used to send a note to an account.
///
/// Encode with [`Display`]/`to_string`, decode with [`FromStr`]/`parse`. Construct from already-
/// derived public keys via [`from_public_keys`](Self::from_public_keys) (or, ergonomically, from a
/// derived account via `crypto`).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RailgunAddress {
    master_key: PoseidonHash,
    viewing_pubkey: ViewingPublicKey,
    chain: ChainId,
}

impl RailgunAddress {
    #[must_use]
    pub fn from_public_keys(
        master_key: PoseidonHash,
        viewing_pubkey: ViewingPublicKey,
        chain: ChainId,
    ) -> Self {
        Self {
            master_key,
            viewing_pubkey,
            chain,
        }
    }

    #[must_use]
    pub fn master_key(&self) -> PoseidonHash {
        self.master_key
    }

    #[must_use]
    pub fn viewing_pubkey(&self) -> ViewingPublicKey {
        self.viewing_pubkey
    }

    #[must_use]
    pub fn chain(&self) -> ChainId {
        self.chain
    }
}

impl fmt::Display for RailgunAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Fixed-size payload — no allocation here; bech32 allocates the output string at the
        // display boundary.
        let mut payload = [0u8; 73];
        payload[0] = VERSION;
        payload[1..33].copy_from_slice(&self.master_key.as_u256().to_be_bytes::<32>());
        payload[33..41].copy_from_slice(&xor_network_id(self.chain.to_network_id()));
        payload[41..73].copy_from_slice(self.viewing_pubkey.as_bytes());

        let encoded = bech32::encode::<Bech32m>(PREFIX, &payload)
            .expect("fixed 73-byte payload and a valid HRP always encode");
        f.write_str(&encoded)
    }
}

impl FromStr for RailgunAddress {
    type Err = RailgunAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, payload) = bech32::decode(s)?;
        if hrp != PREFIX {
            return Err(RailgunAddressError::InvalidPrefix(hrp.to_string()));
        }
        if payload.len() != 73 {
            return Err(RailgunAddressError::BadLength(payload.len()));
        }
        let version = payload[0];
        if version != VERSION {
            return Err(RailgunAddressError::InvalidVersion(version));
        }

        let master_key = PoseidonHash::new(U256::from_be_slice(&payload[1..33]));
        let network_id = xor_network_id(
            payload[33..41]
                .try_into()
                .expect("slice is exactly 8 bytes"),
        );
        let chain = ChainId::from_network_id(network_id)?;
        let viewing_pubkey =
            ViewingPublicKey::try_from_slice(&payload[41..73]).expect("slice is exactly 32 bytes");

        Ok(Self {
            master_key,
            viewing_pubkey,
            chain,
        })
    }
}

// Required by `#[serde(try_from = "String", into = "String")]` — addresses (de)serialize as their
// canonical bech32m string.
impl TryFrom<String> for RailgunAddress {
    type Error = RailgunAddressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<RailgunAddress> for String {
    fn from(address: RailgunAddress) -> Self {
        address.to_string()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RailgunAddressError {
    #[error(transparent)]
    Bech32Decode(#[from] bech32::DecodeError),
    #[error("invalid address prefix: expected `0zk`, got `{0}`")]
    InvalidPrefix(String),
    #[error("invalid address length: expected 73 payload bytes, got {0}")]
    BadLength(usize),
    #[error("unsupported address version: {0}")]
    InvalidVersion(u8),
    #[error("unknown chain type: {0}")]
    UnknownChainType(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-exact parity vector (kohaku `account::address` test): master key = [1; 32],
    // viewing key = [2; 32], EVM chain id 1.
    const VECTOR_EVM_1: &str = "0zk1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszunpd9kxwatwqypqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqy3t4umn";

    // Byte-exact parity vector (kohaku) for an "all chains" address (chain hint absent).
    const VECTOR_ALL_CHAINS: &str = "0zk1qykqj8ed50tfm8a4ezl2qekk3aqxuq37pgv88pv6s9phk0vj3lv7erv7j6fe3z53la8hh9taj9xq34y835wrscryymjf8qqrasmm2vxrm68y0qsxtcvzj6paxpy";

    fn address_evm_1() -> RailgunAddress {
        RailgunAddress::from_public_keys(
            PoseidonHash::new(U256::from_be_bytes([1u8; 32])),
            ViewingPublicKey::from_bytes([2u8; 32]),
            ChainId::evm(1),
        )
    }

    #[test]
    fn encodes_evm_address_to_engine_vector() {
        assert_eq!(address_evm_1().to_string(), VECTOR_EVM_1);
    }

    #[test]
    fn decodes_engine_vector_to_expected_fields() {
        let parsed: RailgunAddress = VECTOR_EVM_1.parse().unwrap();
        assert_eq!(parsed, address_evm_1());
        assert_eq!(
            parsed.master_key().as_u256(),
            U256::from_be_bytes([1u8; 32])
        );
        assert_eq!(parsed.viewing_pubkey().as_bytes(), &[2u8; 32]);
        assert_eq!(parsed.chain(), ChainId::evm(1));
    }

    #[test]
    fn all_chains_vector_round_trips() {
        let parsed: RailgunAddress = VECTOR_ALL_CHAINS.parse().unwrap();
        assert_eq!(parsed.chain(), ChainId::All);
        assert_eq!(parsed.to_string(), VECTOR_ALL_CHAINS);
    }

    #[test]
    fn round_trips_through_string() {
        let address = address_evm_1();
        let restored: RailgunAddress = address.to_string().parse().unwrap();
        assert_eq!(address, restored);
    }

    #[test]
    fn network_id_xor_is_its_own_inverse() {
        let id = ChainId::evm(11_155_111).to_network_id();
        assert_eq!(xor_network_id(xor_network_id(id)), id);
    }

    #[test]
    fn rejects_wrong_prefix() {
        // Re-encode the same payload under a different HRP and confirm it's rejected.
        let (_, payload) = bech32::decode(VECTOR_EVM_1).unwrap();
        let wrong = bech32::encode::<Bech32m>(Hrp::parse_unchecked("0zktest"), &payload).unwrap();
        assert!(matches!(
            wrong.parse::<RailgunAddress>(),
            Err(RailgunAddressError::InvalidPrefix(_))
        ));
    }

    #[test]
    fn rejects_unsupported_version() {
        let (_, mut payload) = bech32::decode(VECTOR_EVM_1).unwrap();
        payload[0] = 2; // bump the version byte
        let reencoded = bech32::encode::<Bech32m>(PREFIX, &payload).unwrap();
        assert!(matches!(
            reencoded.parse::<RailgunAddress>(),
            Err(RailgunAddressError::InvalidVersion(2))
        ));
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let mut chars: Vec<char> = VECTOR_EVM_1.chars().collect();
        // Flip a character in the data part (not the `0zk1` prefix) to break the checksum.
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let corrupted: String = chars.into_iter().collect();
        assert!(corrupted.parse::<RailgunAddress>().is_err());
    }
}
