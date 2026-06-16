//! Viewing-key behavior: the ed25519 public key and the curve25519 ECDH used to
//! derive the shared secret that decrypts notes. Implemented as traits on the
//! `types` `ViewingKey`, mirroring [`crate::SpendingKeyPublicKey`].

use curve25519_dalek::{EdwardsPoint, Scalar, edwards::CompressedEdwardsY};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256, Sha512};
use types::{BlindedKey, PoseidonHash, SharedKey, ViewingKey, ViewingPublicKey};

use crate::{CryptoError, PoseidonInput};

/// Derives the ed25519 public viewing key (used in RAILGUN addresses).
pub trait ViewingKeyPublicKey {
    fn public_key(&self) -> ViewingPublicKey;
}

impl ViewingKeyPublicKey for ViewingKey {
    fn public_key(&self) -> ViewingPublicKey {
        let signing_key = SigningKey::from_bytes(self.expose_secret());
        ViewingPublicKey::from_bytes(signing_key.verifying_key().to_bytes())
    }
}

/// Derives the Poseidon nullifying key for this viewing key.
pub trait ViewingKeyNullifier {
    /// Derives the nullifying key used to compute note nullifiers.
    ///
    /// # Errors
    /// Propagates [`CryptoError::Poseidon`].
    fn nullifying_key(&self) -> Result<PoseidonHash, CryptoError>;
}

impl ViewingKeyNullifier for ViewingKey {
    fn nullifying_key(&self) -> Result<PoseidonHash, CryptoError> {
        self.poseidon_hash()
    }
}

/// Derives the AES shared key for decrypting a note, via curve25519 ECDH.
pub trait ViewingKeySharedSecret {
    /// ECDH against a counterparty's raw viewing public key (shield path).
    ///
    /// # Errors
    /// Returns [`CryptoError::PointDecompression`] if the public key is not a
    /// valid curve point.
    fn derive_shared_key(&self, their_public: ViewingPublicKey) -> Result<SharedKey, CryptoError>;

    /// ECDH against a blinded sender viewing key (transact path).
    ///
    /// # Errors
    /// Returns [`CryptoError::PointDecompression`] if the blinded key is not a
    /// valid curve point.
    fn derive_shared_key_blinded(&self, blinded: BlindedKey) -> Result<SharedKey, CryptoError>;
}

impl ViewingKeySharedSecret for ViewingKey {
    fn derive_shared_key(&self, their_public: ViewingPublicKey) -> Result<SharedKey, CryptoError> {
        let point = their_public.edwards_point()?;
        Ok(shared_key(self, point))
    }

    fn derive_shared_key_blinded(&self, blinded: BlindedKey) -> Result<SharedKey, CryptoError> {
        let point = blinded.edwards_point()?;
        Ok(shared_key(self, point))
    }
}

/// Clamps the viewing key into a curve25519 scalar (Ed25519 key-expansion rules).
fn to_curve25519_scalar(viewing_key: &ViewingKey) -> Scalar {
    let hash = Sha512::digest(viewing_key.expose_secret());
    let mut head = [0u8; 32];
    head.copy_from_slice(&hash[..32]);
    head[0] &= 248;
    head[31] &= 63;
    head[31] |= 64;
    Scalar::from_bytes_mod_order(head)
}

/// A 32-byte public key that is a compressed curve25519 Edwards point. Both
/// [`ViewingPublicKey`] and [`BlindedKey`] are points; decompressing them is the
/// shared first step of every ECDH and blinding operation in the crate.
pub(crate) trait EdwardsCompressed {
    /// Decompresses this key into its curve25519 [`EdwardsPoint`].
    ///
    /// # Errors
    /// [`CryptoError::PointDecompression`] if the bytes are not a valid point.
    fn edwards_point(&self) -> Result<EdwardsPoint, CryptoError>;
}

impl EdwardsCompressed for ViewingPublicKey {
    fn edwards_point(&self) -> Result<EdwardsPoint, CryptoError> {
        decompress(self.as_bytes())
    }
}

impl EdwardsCompressed for BlindedKey {
    fn edwards_point(&self) -> Result<EdwardsPoint, CryptoError> {
        decompress(self.as_bytes())
    }
}

fn decompress(bytes: &[u8; 32]) -> Result<EdwardsPoint, CryptoError> {
    CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(CryptoError::PointDecompression)
}

fn shared_key(viewing_key: &ViewingKey, their_point: EdwardsPoint) -> SharedKey {
    let scalar = to_curve25519_scalar(viewing_key);
    let shared = their_point * scalar;
    let digest = Sha256::digest(shared.compress().to_bytes());
    SharedKey::from_bytes(digest.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors from kohaku (generated against the RAILGUN JS SDK).
    #[test]
    fn derives_ed25519_viewing_public_key() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        assert_eq!(
            hex::encode(viewing_key.public_key().as_bytes()),
            "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
        );
    }

    #[test]
    fn derives_nullifying_key() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        assert_eq!(
            viewing_key.nullifying_key().unwrap().as_u256().to_string(),
            "11044075259344817595544633535096475825354771420816801683721629142825992460598"
        );
    }

    #[test]
    fn derives_shared_key_via_ecdh() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        let their_viewing = ViewingKey::from_bytes([3u8; 32]);

        let shared = viewing_key
            .derive_shared_key(their_viewing.public_key())
            .unwrap();
        assert_eq!(
            hex::encode(shared.expose_secret()),
            "b8d9b27ccb6161ba969a646553ad1b7221b4113ac83bdd603985ce44923456f1"
        );
    }

    #[test]
    fn derives_shared_key_from_blinded_sender() {
        // `blinded` is the sender (viewing [2;32]) blinded key from kohaku's
        // `test_blinded_key`; viewing [3;32] recovers the same shared secret.
        let their_viewing = ViewingKey::from_bytes([3u8; 32]);
        let blinded = BlindedKey::try_from(
            hex::decode("2ed993356db2b8b5e573da394c2317942c9a1a72eb9a8dfd02705cc56cb1423b")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let shared = their_viewing.derive_shared_key_blinded(blinded).unwrap();
        assert_eq!(
            hex::encode(shared.expose_secret()),
            "2d33b7ea38413dfd631149f00dd0745f06dc06cd8112a6a174c73fa97af8d5a0"
        );
    }
}
