use crate::{EvmAddress, TypeError, U256};

/// A token identity. ERC-20 only for now; ERC-721/1155 are reserved (their token
/// hashing needs keccak and is added when those assets are supported).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AssetId {
    Erc20(EvmAddress),
}

impl AssetId {
    pub fn erc20(address: EvmAddress) -> Self {
        Self::Erc20(address)
    }

    /// RAILGUN token hash used as a Poseidon input. For ERC-20 this is simply the
    /// 20-byte address right-aligned into a 32-byte field element (no hashing).
    pub fn token_hash(self) -> U256 {
        match self {
            Self::Erc20(address) => {
                let mut bytes = [0u8; 32];
                bytes[12..].copy_from_slice(address.as_slice());
                U256::from_be_bytes(bytes)
            }
        }
    }

    /// Parses a 32-byte ERC-20 token hash back into an [`AssetId`].
    ///
    /// # Errors
    /// Returns [`TypeError::InvalidLength`] if `hash` is not exactly 32 bytes,
    /// or [`TypeError::InvalidTokenHash`] if the ERC-20 padding bytes are non-zero.
    pub fn from_token_hash(hash: &[u8]) -> Result<Self, TypeError> {
        if hash.len() != 32 {
            return Err(TypeError::InvalidLength {
                expected: 32,
                actual: hash.len(),
            });
        }
        if hash[..12].iter().any(|byte| *byte != 0) {
            return Err(TypeError::InvalidTokenHash);
        }

        Ok(Self::Erc20(EvmAddress::from_slice(&hash[12..32])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erc20_token_hash_roundtrips() {
        let address = EvmAddress::from([0x11u8; 20]);
        let asset = AssetId::erc20(address);

        let hash = asset.token_hash();
        assert_eq!(
            AssetId::from_token_hash(&hash.to_be_bytes::<32>()).unwrap(),
            asset
        );
    }

    #[test]
    fn from_token_hash_rejects_wrong_length() {
        assert_eq!(
            AssetId::from_token_hash(&[0u8; 31]).unwrap_err(),
            TypeError::InvalidLength {
                expected: 32,
                actual: 31
            }
        );
    }

    #[test]
    fn from_token_hash_rejects_non_zero_erc20_padding() {
        let mut hash = [0u8; 32];
        hash[11] = 1;

        assert_eq!(
            AssetId::from_token_hash(&hash).unwrap_err(),
            TypeError::InvalidTokenHash
        );
    }
}
