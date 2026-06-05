//! Poseidon commitment math: recompute a note's public key, leaf hash, nullifier,
//! and blinded commitment from its fields. Used to fill in a [`types::DecryptedNote`]
//! after the ciphertext is opened.

use types::{
    AssetId, B256, BabyJubJubPoint, CommitmentHash, NoteValue, Nullifier, PoseidonHash, U256,
};

use crate::{CryptoError, PoseidonInput};

/// Master public key (wallet identifier): `poseidon(spend.x, spend.y, nullifying)`.
///
/// # Errors
/// Propagates [`CryptoError::Poseidon`].
pub fn master_public_key(
    spend: BabyJubJubPoint,
    nullifying: PoseidonHash,
) -> Result<PoseidonHash, CryptoError> {
    (spend, nullifying).poseidon_hash()
}

/// Note public key: `poseidon(master_public_key, random)`.
///
/// # Errors
/// Propagates [`CryptoError::Poseidon`].
pub fn note_public_key(master: PoseidonHash, random: &[u8; 16]) -> Result<U256, CryptoError> {
    Ok((master, U256::from_be_slice(random))
        .poseidon_hash()?
        .as_u256())
}

/// Note (leaf) hash: `poseidon(npk, token_hash, value)`.
///
/// # Errors
/// Propagates [`CryptoError::Poseidon`].
pub fn note_hash(
    npk: U256,
    asset: AssetId,
    value: NoteValue,
) -> Result<CommitmentHash, CryptoError> {
    let hash = (npk, asset.token_hash(), value.as_u256()).poseidon_hash()?;
    Ok(CommitmentHash::new(hash.as_u256()))
}

/// Nullifier: `poseidon(nullifying, leaf_index)`.
///
/// # Errors
/// Propagates [`CryptoError::Poseidon`].
pub fn nullifier(nullifying: PoseidonHash, leaf_index: u32) -> Result<Nullifier, CryptoError> {
    let hash = (nullifying, U256::from(leaf_index)).poseidon_hash()?;
    Ok(Nullifier::new(B256::new(
        hash.as_u256().to_be_bytes::<32>(),
    )))
}

/// Blinded commitment: `poseidon(hash, npk, tree_number * 65536 + leaf_index)`.
///
/// # Errors
/// Propagates [`CryptoError::Poseidon`].
pub fn blinded_commitment(
    hash: CommitmentHash,
    npk: U256,
    tree_number: u32,
    leaf_index: u32,
) -> Result<U256, CryptoError> {
    let position = U256::from(u128::from(tree_number) * 65536 + u128::from(leaf_index));
    Ok((hash.as_u256(), npk, position).poseidon_hash()?.as_u256())
}

#[cfg(test)]
mod tests {
    use types::SpendingKey;

    use super::*;
    use crate::SpendingKeyPublicKey;

    // Known-answer vectors from kohaku's `test_note` (RAILGUN JS SDK): spending
    // [1;32], viewing [2;32], asset 0x1234..7890, value 100, random [3;16], leaf 0.
    fn fixture() -> (BabyJubJubPoint, PoseidonHash) {
        let spend = SpendingKey::from_bytes([1u8; 32]).public_key();
        let nullifying = U256::from_be_bytes([2u8; 32]).poseidon_hash().unwrap();
        (spend, nullifying)
    }

    #[test]
    fn note_public_key_matches_vector() {
        let (spend, nullifying) = fixture();
        let master = master_public_key(spend, nullifying).unwrap();
        let npk = note_public_key(master, &[3u8; 16]).unwrap();
        assert_eq!(
            npk.to_string(),
            "6115421394727733128036252006164802934954447834850133641440670552529040512894"
        );
    }

    #[test]
    fn note_hash_matches_vector() {
        let (spend, nullifying) = fixture();
        let master = master_public_key(spend, nullifying).unwrap();
        let npk = note_public_key(master, &[3u8; 16]).unwrap();
        let asset = AssetId::erc20(
            "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
        );

        let hash = note_hash(npk, asset, NoteValue::new(100)).unwrap();
        assert_eq!(
            hash.as_u256().to_string(),
            "15652703063364460311785063361754318622468586649506025149049958389572383217849"
        );
    }

    #[test]
    fn nullifier_matches_vector() {
        let (_, nullifying) = fixture();
        let nullifier = nullifier(nullifying, 0).unwrap();
        assert_eq!(
            U256::from_be_bytes(nullifier.as_b256().0).to_string(),
            "411278121737418487137709121143672807193871730335727382674438428088849704048"
        );
    }
}
