//! Static per-chain configuration: Subsquid endpoint, RAILGUN contracts, and the
//! deployment block used as the sync floor.
//!
//! Ported from kohaku's `chain_config.rs`, including the POI operational facts
//! (aggregator endpoint, launch block, active list keys) the `poi` crate consumes.

use alloy_primitives::{Address, ChainId, address};
use types::BlockNumber;

/// Static facts about a supported chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainConfig {
    /// EIP-155 chain id.
    pub id: ChainId,
    /// Subsquid GraphQL endpoint for fast syncing.
    pub subsquid_endpoint: &'static str,
    /// RAILGUN Smart Wallet contract.
    pub railgun_smart_wallet: Address,
    /// `RelayAdapt` contract (native base-token shielding via `multicall`).
    pub relay_adapt_contract: Address,
    /// Wrapped base token (e.g. WETH) used in native-shield note preimages.
    pub wrapped_base_token: Address,
    /// Block the Smart Wallet was deployed at
    pub deployment_block: BlockNumber,
    /// POI aggregator node endpoint, if POI is supported on this chain.
    pub poi_node: Option<&'static str>,
    /// Block POI launched at: the txid-tree sync floor; UTXOs before it follow
    /// the legacy POI path (not implemented here).
    pub poi_launch_block: BlockNumber,
    /// Active POI list keys a UTXO must be `Valid` on to be spendable.
    pub poi_list_keys: &'static [&'static str],
}

/// The shared RAILGUN POI list key active on mainnet and Sepolia (kohaku's
/// `chain_config.rs`).
const RAILGUN_POI_LIST_KEY: &str =
    "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

/// The public POI aggregator endpoint used by kohaku for mainnet and Sepolia.
const RAILGUN_POI_NODE: &str = "https://ppoi.fdi.network/";

impl ChainConfig {
    /// Ethereum mainnet.
    #[must_use]
    pub const fn mainnet() -> Self {
        Self {
            id: 1,
            subsquid_endpoint: "https://rail-squid.squids.live/squid-railgun-ethereum-v2/v/v1/graphql",
            railgun_smart_wallet: address!("0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9"),
            relay_adapt_contract: address!("0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405"),
            wrapped_base_token: address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            deployment_block: BlockNumber::new(14_693_013),
            poi_node: Some(RAILGUN_POI_NODE),
            poi_launch_block: BlockNumber::new(18_514_200),
            poi_list_keys: &[RAILGUN_POI_LIST_KEY],
        }
    }

    /// Ethereum Sepolia testnet.
    #[must_use]
    pub const fn sepolia() -> Self {
        Self {
            id: 11_155_111,
            subsquid_endpoint: "https://rail-squid.squids.live/squid-railgun-eth-sepolia-v2/v/v1/graphql",
            railgun_smart_wallet: address!("0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea"),
            relay_adapt_contract: address!("0x7e3d929EbD5bDC84d02Bd3205c777578f33A214D"),
            wrapped_base_token: address!("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"),
            deployment_block: BlockNumber::new(5_784_774),
            poi_node: Some(RAILGUN_POI_NODE),
            poi_launch_block: BlockNumber::new(5_944_700),
            poi_list_keys: &[RAILGUN_POI_LIST_KEY],
        }
    }

    /// Looks up a built-in config by chain id.
    #[must_use]
    pub fn from_chain_id(id: ChainId) -> Option<Self> {
        match id {
            1 => Some(Self::mainnet()),
            11_155_111 => Some(Self::sepolia()),
            _ => None,
        }
    }
}
