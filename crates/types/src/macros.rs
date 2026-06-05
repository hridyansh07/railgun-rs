macro_rules! u256_domain_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        pub struct $name(crate::U256);

        impl $name {
            pub fn new(value: crate::U256) -> Self {
                Self(value)
            }

            pub fn as_u256(self) -> crate::U256 {
                self.0
            }
        }
    };
}

macro_rules! b256_domain_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        pub struct $name(crate::B256);

        impl $name {
            pub fn new(value: crate::B256) -> Self {
                Self(value)
            }

            pub fn as_b256(self) -> crate::B256 {
                self.0
            }
        }
    };
}

macro_rules! fixed_bytes_domain_type {
    ($name:ident, $len:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        pub struct $name([u8; $len]);

        impl $name {
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub fn try_from_slice(bytes: &[u8]) -> Result<Self, crate::TypeError> {
                if bytes.len() != $len {
                    return Err(crate::TypeError::InvalidLength {
                        expected: $len,
                        actual: bytes.len(),
                    });
                }

                let mut out = [0u8; $len];
                out.copy_from_slice(bytes);
                Ok(Self(out))
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        // Cast-in conversions so callers who already hold a key value can
        // `.into()` / `.try_into()` it. Ingestion from the wrapped primitive only;
        // cross-domain conversions remain forbidden (see CODE_INVARIANTS.md).
        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self::from_bytes(bytes)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = crate::TypeError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::try_from_slice(bytes)
            }
        }
    };
}

pub(crate) use {b256_domain_type, fixed_bytes_domain_type, u256_domain_type};
