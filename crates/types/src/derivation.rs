use std::{fmt, str::FromStr};

const MAX_DERIVATION_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DerivationPathError {
    #[error("invalid derivation path")]
    InvalidDerivationPath,
    #[error("derivation path is too deep")]
    DerivationPathTooDeep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RailgunAccountIndex(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DerivationPath {
    segments: [u32; MAX_DERIVATION_DEPTH],
    len: usize,
}

impl RailgunAccountIndex {
    pub fn new(index: u32) -> Self {
        Self(index)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn spending_path(self) -> DerivationPath {
        DerivationPath::from_segments([44, 1984, 0, 0, self.0])
    }

    pub fn viewing_path(self) -> DerivationPath {
        DerivationPath::from_segments([420, 1984, 0, 0, self.0])
    }
}

impl DerivationPath {
    pub fn from_segments<const N: usize>(segments: [u32; N]) -> Self {
        debug_assert!(N <= MAX_DERIVATION_DEPTH);

        let mut out = [0u32; MAX_DERIVATION_DEPTH];
        out[..N].copy_from_slice(&segments);
        Self {
            segments: out,
            len: N,
        }
    }

    pub fn len(self) -> usize {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn segments(&self) -> &[u32] {
        &self.segments[..self.len]
    }
}

impl FromStr for DerivationPath {
    type Err = DerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        if path == "m" {
            return Ok(Self {
                segments: [0u32; MAX_DERIVATION_DEPTH],
                len: 0,
            });
        }

        let bytes = path.as_bytes();
        if bytes.len() < 4 || bytes[0] != b'm' || bytes[1] != b'/' {
            return Err(DerivationPathError::InvalidDerivationPath);
        }

        let mut segments = [0u32; MAX_DERIVATION_DEPTH];
        let mut len = 0usize;
        let mut idx = 2usize;

        while idx < bytes.len() {
            if len == MAX_DERIVATION_DEPTH {
                return Err(DerivationPathError::DerivationPathTooDeep);
            }

            let mut value = 0u32;
            let mut saw_digit = false;

            while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                saw_digit = true;
                value = value
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((bytes[idx] - b'0') as u32))
                    .ok_or(DerivationPathError::InvalidDerivationPath)?;
                idx += 1;
            }

            if !saw_digit || idx >= bytes.len() || bytes[idx] != b'\'' {
                return Err(DerivationPathError::InvalidDerivationPath);
            }
            idx += 1;

            segments[len] = value;
            len += 1;

            if idx == bytes.len() {
                break;
            }
            if bytes[idx] != b'/' {
                return Err(DerivationPathError::InvalidDerivationPath);
            }
            idx += 1;
        }

        Ok(Self { segments, len })
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for segment in self.segments() {
            write!(f, "/{segment}'")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_railgun_paths() {
        let index = RailgunAccountIndex::new(7);
        assert_eq!(index.spending_path().to_string(), "m/44'/1984'/0'/0'/7'");
        assert_eq!(index.viewing_path().to_string(), "m/420'/1984'/0'/0'/7'");
    }

    #[test]
    fn parses_hardened_path_without_allocating_segments() {
        let path: DerivationPath = "m/0'/1'/12'".parse().unwrap();
        assert_eq!(path.segments(), &[0, 1, 12]);
        assert!("m/0/1".parse::<DerivationPath>().is_err());
        assert!("railgun".parse::<DerivationPath>().is_err());
        assert!("m/0'/x'".parse::<DerivationPath>().is_err());
    }
}
