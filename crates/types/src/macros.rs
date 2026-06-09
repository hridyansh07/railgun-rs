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

/// Generates a fixed-size **secret** key newtype: opaque bytes that never render
/// implicitly. `Debug`/`Display` redact; the raw bytes are reachable only through the
/// named `expose_secret` gate, with a `0x`-hex `reveal_hex` escape hatch for explicit
/// export. No serde, `Hash`, or equality — secret material is not persisted, hashed,
/// or compared here.
macro_rules! secret_key_type {
    ($name:ident, $len:literal) => {
        #[derive(Clone, Copy)]
        pub struct $name([u8; $len]);

        impl $name {
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// # Errors
            /// Returns a `TypeError::InvalidLength` if `bytes` is not `$len` bytes long.
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

            /// Gated raw access to the secret bytes. Every read of secret key material
            /// flows through this named method, so call sites stay greppable/auditable.
            pub fn expose_secret(&self) -> &[u8; $len] {
                &self.0
            }

            /// Escape hatch: a `0x`-prefixed hex string for explicit, user-initiated
            /// export or inspection (e.g. a "copy private key" action). Never logged
            /// implicitly — `Debug`/`Display` redact.
            #[must_use]
            pub fn reveal_hex(&self) -> String {
                // alloc-ok: explicit, user-initiated key export, not a hot path.
                ::alloy_primitives::hex::encode_prefixed(self.0)
            }
        }

        // Cast-in only (ingest a key value you already hold); cross-domain conversions
        // remain forbidden (see CODE_INVARIANTS.md).
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

        // Redacting Debug + Display: secret key material is never rendered implicitly.
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

/// Generates a fixed-size **public** key newtype: on-chain/shareable bytes that are
/// freely viewable. `Debug`/`Display` render as `0x`-hex. Keeps the harmless std
/// derives (`Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`) but no serde — the byte-exact
/// codec, not serde, persists these.
macro_rules! public_key_type {
    ($name:ident, $len:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// # Errors
            /// Returns a `TypeError::InvalidLength` if `bytes` is not `$len` bytes long.
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

            /// `0x`-prefixed hex rendering of this public key.
            #[must_use]
            pub fn to_hex(&self) -> String {
                // alloc-ok: human-facing hex rendering, not a hot path.
                ::alloy_primitives::hex::encode_prefixed(self.0)
            }
        }

        // Cast-in only (ingest a key value you already hold); cross-domain conversions
        // remain forbidden (see CODE_INVARIANTS.md).
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

        // Public key material — render as readable hex for logs and `Display`.
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(
                    f,
                    "{}({})",
                    stringify!($name),
                    ::alloy_primitives::hex::encode_prefixed(self.0)
                )
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&::alloy_primitives::hex::encode_prefixed(self.0))
            }
        }
    };
}

pub(crate) use {b256_domain_type, public_key_type, secret_key_type, u256_domain_type};
