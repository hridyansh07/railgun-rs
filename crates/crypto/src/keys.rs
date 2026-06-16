use types::{BabyJubJubPoint, SpendingKey, SpendingSignature, U256};

use crate::CryptoError;
use crate::common::{fr_to_u256, u256_to_num_bigint};

pub trait SpendingKeyPublicKey {
    fn public_key(&self) -> BabyJubJubPoint;
}

impl SpendingKeyPublicKey for SpendingKey {
    fn public_key(&self) -> BabyJubJubPoint {
        crate::babyjubjub::public_key(self)
    }
}

/// Spend authorization: sign a field-element message with the spending key.
pub trait SpendingKeySign {
    /// Produces the EdDSA-Poseidon (`BabyJubJub`) signature the transact circuit
    /// verifies against the spending public key.
    ///
    /// # Errors
    /// [`CryptoError::MessageOutOfField`] if `message` is not a valid field
    /// element; propagates [`CryptoError::Poseidon`] from the challenge hash.
    fn sign(&self, message: U256) -> Result<SpendingSignature, CryptoError>;
}

impl SpendingKeySign for SpendingKey {
    fn sign(&self, message: U256) -> Result<SpendingSignature, CryptoError> {
        let signature = crate::babyjubjub::sign(self, u256_to_num_bigint(message))?;
        Ok(SpendingSignature {
            r8_x: fr_to_u256(signature.r_b8.x),
            r8_y: fr_to_u256(signature.r_b8.y),
            s: U256::from_le_slice(&signature.s.to_bytes_le().1),
        })
    }
}

#[cfg(test)]
mod tests {
    use types::uint;

    use super::*;

    #[test]
    fn derives_babyjubjub_public_key() {
        let key = SpendingKey::from_bytes([1u8; 32]);
        let public = key.public_key();

        assert_eq!(
            public.x(),
            uint!(
                15944627324083773346390189001500210680939402028015651549526524193195473201952_U256
            )
        );
        assert_eq!(
            public.y(),
            uint!(
                17251889856797524237981285661279357764562574766148660962999867467495459148286_U256
            )
        );
    }

    // Known-answer vector from kohaku's `test_sign`: spending [1;32], message 42.
    #[test]
    fn signs_message_matches_vector() {
        let key = SpendingKey::from_bytes([1u8; 32]);
        let signature = key.sign(U256::from(42u8)).unwrap();

        assert_eq!(
            signature.r8_x,
            uint!(
                14021219264176114698656285200925183015004950119566700345808626607587007258652_U256
            )
        );
        assert_eq!(
            signature.r8_y,
            uint!(722845713210012403245093368934831287436133400350912012728600696178479669333_U256)
        );
        assert_eq!(
            signature.s,
            uint!(719423466960100536815219984091461547618047721989819848960065284130969424009_U256)
        );
    }
}
