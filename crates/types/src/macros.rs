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

            pub fn try_from_slice(bytes: &[u8]) -> Result<Self, crate::RailgunTypeError> {
                if bytes.len() != $len {
                    return Err(crate::RailgunTypeError::InvalidLength {
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
    };
}

pub(crate) use {b256_domain_type, fixed_bytes_domain_type, u256_domain_type};
