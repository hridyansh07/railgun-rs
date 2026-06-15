//! [`Sealer`] — encryption-at-rest for records the database must never hold
//! in plaintext (decoded notes, pending POI entries).
//!
//! The database stores opaque ciphertext; this seam decides what that means.
//! [`AesGcmSealer`] is the production implementation: AES-256-GCM under a
//! caller-provided 32-byte data-encryption key (DEK), fresh random nonce per
//! seal, nonce prepended to the ciphertext. *Where the DEK comes from* is the
//! caller's concern — the wallet facade today, a platform keystore
//! (Secure Enclave + biometric gate) behind the same trait later.

use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce, aead::OsRng};

use crate::CryptoError;

/// 96-bit AES-GCM nonce, prepended to every sealed record.
const NONCE_LEN: usize = 12;

/// Seals and unseals at-rest records. Implementations must be safe to share
/// across scan worker threads.
pub trait Sealer: Send + Sync {
    /// Encrypts `plaintext` into a self-contained sealed record.
    ///
    /// # Errors
    /// Propagates [`CryptoError`] from the cipher.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Recovers the plaintext of a sealed record. Fails (authenticated
    /// encryption) on the wrong key or a tampered record.
    ///
    /// # Errors
    /// [`CryptoError::Sealed`] on authentication failure or a malformed record.
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// AES-256-GCM [`Sealer`] over a 32-byte DEK.
pub struct AesGcmSealer {
    cipher: Aes256Gcm,
}

impl AesGcmSealer {
    #[must_use]
    pub fn new(dek: [u8; 32]) -> Self {
        AesGcmSealer {
            cipher: Aes256Gcm::new(&dek.into()),
        }
    }
}

impl Sealer for AesGcmSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::Sealed)?;
        // alloc-ok: sealed record at the persistence boundary.
        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < NONCE_LEN {
            return Err(CryptoError::Sealed);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        self.cipher
            .decrypt(Nonce::<_>::from_slice(nonce), ciphertext)
            .map_err(|_| CryptoError::Sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trips_and_randomizes_nonces() {
        let sealer = AesGcmSealer::new([7u8; 32]);
        let first = sealer.seal(b"the notes").unwrap();
        let second = sealer.seal(b"the notes").unwrap();
        assert_ne!(first, second, "nonce must be fresh per seal");
        assert_eq!(sealer.unseal(&first).unwrap(), b"the notes");
        assert_eq!(sealer.unseal(&second).unwrap(), b"the notes");
    }

    #[test]
    fn wrong_key_and_tampering_fail_closed() {
        let sealer = AesGcmSealer::new([7u8; 32]);
        let mut record = sealer.seal(b"secret").unwrap();

        let wrong = AesGcmSealer::new([8u8; 32]);
        assert!(matches!(wrong.unseal(&record), Err(CryptoError::Sealed)));

        let last = record.len() - 1;
        record[last] ^= 1;
        assert!(matches!(sealer.unseal(&record), Err(CryptoError::Sealed)));
        assert!(matches!(sealer.unseal(b"short"), Err(CryptoError::Sealed)));
    }
}
