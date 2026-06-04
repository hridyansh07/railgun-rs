use std::{fmt, str::FromStr};

use crate::macros::{b256_domain_type, u256_domain_type};

b256_domain_type!(Nullifier);
u256_domain_type!(PoseidonHash);
u256_domain_type!(CommitmentHash);
u256_domain_type!(RailgunTxid);

const CHARSET: &[u8; 37] = b" 0123456789abcdefghijklmnopqrstuvwxyz";
const BASE: u128 = 37;
const MAX_DECODED_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RailgunBase37([u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Base37Error {
    #[error("invalid base37 character: {0}")]
    InvalidCharacter(char),
    #[error("base37 output exceeds {0} bytes")]
    OutputTooLong(usize),
}

impl RailgunBase37 {
    pub fn encode(text: &str) -> Result<Self, Base37Error> {
        let mut value: u128 = 0;

        for c in text.chars() {
            let idx = charset_index(c).ok_or(Base37Error::InvalidCharacter(c))?;

            value = value
                .checked_mul(BASE)
                .and_then(|v| v.checked_add(u128::from(idx)))
                .ok_or(Base37Error::OutputTooLong(16))?;
        }

        Ok(Self(value.to_be_bytes()))
    }

    pub fn from_encoded_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn encoded_bytes(self) -> [u8; 16] {
        self.0
    }

    pub fn try_decode(self) -> RailgunBase37Decoded {
        let mut value = u128::from_be_bytes(self.0);
        let mut bytes = [0u8; MAX_DECODED_LEN];
        let mut len = 0usize;

        while value > 0 {
            let remainder = (value % BASE) as usize;
            bytes[MAX_DECODED_LEN - 1 - len] = CHARSET[remainder];
            value /= BASE;
            len += 1;
        }

        RailgunBase37Decoded { bytes, len }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RailgunBase37Decoded {
    bytes: [u8; MAX_DECODED_LEN],
    len: usize,
}

impl RailgunBase37Decoded {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[MAX_DECODED_LEN - self.len..]
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("base37 charset is valid UTF-8")
    }
}

impl AsRef<[u8; 16]> for RailgunBase37 {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl TryFrom<&str> for RailgunBase37 {
    type Error = Base37Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::encode(value)
    }
}

impl FromStr for RailgunBase37 {
    type Err = Base37Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::encode(s)
    }
}

impl fmt::Display for RailgunBase37 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.try_decode().as_str())
    }
}

fn charset_index(c: char) -> Option<u8> {
    match c {
        ' ' => Some(0),
        '0'..='9' => Some((c as u8 - b'0') + 1),
        'a'..='z' => Some((c as u8 - b'a') + 11),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{B256, U256};

    #[test]
    fn nullifier_exposes_only_named_inner_access() {
        let bytes = [7u8; 32];
        let inner = B256::new(bytes);
        let nullifier = Nullifier::new(inner);

        assert_eq!(nullifier.as_b256(), inner);
    }

    #[test]
    fn u256_wrappers_expose_only_named_inner_access() {
        let value = U256::from(1984u64);

        assert_eq!(PoseidonHash::new(value).as_u256(), value);
        assert_eq!(CommitmentHash::new(value).as_u256(), value);
        assert_eq!(RailgunTxid::new(value).as_u256(), value);
    }

    #[test]
    fn base37_encodes_expected_sdk_value() {
        let encoded = RailgunBase37::encode("hello world").unwrap();
        assert_eq!(
            encoded.encoded_bytes(),
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 58, 182, 27, 136, 104, 32, 128]
        );
    }

    #[test]
    fn base37_roundtrips_without_heap_decoding() {
        let samples = ["", "hello", "railgun", "0x1234", "test 123"];

        for sample in samples {
            let encoded = RailgunBase37::encode(sample).unwrap();
            assert_eq!(encoded.to_string(), sample);
        }
    }

    #[test]
    fn base37_rejects_uppercase() {
        assert_eq!(
            RailgunBase37::encode("HELLO").unwrap_err(),
            Base37Error::InvalidCharacter('H')
        );
    }
}
