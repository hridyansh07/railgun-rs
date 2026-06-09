use bip39::{Language, Mnemonic};

use crate::CryptoError;

#[derive(Clone, PartialEq, Eq)]
pub struct RailgunMnemonic {
    phrase: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicStrength {
    Words12,
    Words18,
    Words24,
}

impl RailgunMnemonic {
    pub fn generate(strength: MnemonicStrength) -> Result<Self, CryptoError> {
        let mnemonic = Mnemonic::generate_in(Language::English, strength.word_count())?;
        Ok(Self {
            phrase: mnemonic.to_string(),
        })
    }

    pub fn parse(phrase: impl Into<String>) -> Result<Self, CryptoError> {
        let phrase = phrase.into();
        Mnemonic::parse_in_normalized(Language::English, &phrase)?;
        Ok(Self { phrase })
    }

    pub fn validate(phrase: &str) -> bool {
        Mnemonic::parse_in_normalized(Language::English, phrase).is_ok()
    }

    pub fn as_phrase(&self) -> &str {
        &self.phrase
    }

    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &self.phrase)
            .expect("RailgunMnemonic validates at construction");
        mnemonic.to_seed_normalized(passphrase)
    }

    pub fn to_entropy(&self) -> Vec<u8> {
        // alloc-ok: owned return value for backup/export UI, not a hot derivation loop.
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &self.phrase)
            .expect("RailgunMnemonic validates at construction");
        mnemonic.to_entropy()
    }
}

impl MnemonicStrength {
    fn word_count(self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words18 => 18,
            Self::Words24 => 24,
        }
    }
}

// The phrase is the root secret — never render it implicitly. `as_phrase()` is the
// explicit reveal/export hatch.
impl std::fmt::Debug for RailgunMnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RailgunMnemonic(<redacted>)")
    }
}

impl std::fmt::Display for RailgunMnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RailgunMnemonic(<redacted>)")
    }
}

impl std::str::FromStr for RailgunMnemonic {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_abandon_mnemonic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = RailgunMnemonic::parse(phrase).unwrap();

        assert!(RailgunMnemonic::validate(phrase));
        assert_eq!(
            hex::encode(mnemonic.to_seed("")),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn mnemonic_redacts_in_debug_and_display() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = RailgunMnemonic::parse(phrase).unwrap();

        assert_eq!(format!("{mnemonic:?}"), "RailgunMnemonic(<redacted>)");
        assert_eq!(format!("{mnemonic}"), "RailgunMnemonic(<redacted>)");
        assert!(!format!("{mnemonic:?}").contains("abandon"));
        // The phrase stays reachable through the explicit accessor.
        assert_eq!(mnemonic.as_phrase(), phrase);
    }
}
