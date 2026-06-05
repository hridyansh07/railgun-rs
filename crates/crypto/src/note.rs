//! Tree-node (commitment) decryption: open a shield/transact event with the
//! wallet's viewing key and reconstruct the [`DecryptedNote`].
//!
//! An AES failure means the commitment was not addressed to this viewing key —
//! during scanning the caller simply skips it.

use types::{
    AssetId, BabyJubJubPoint, BlindedCommitmentType, DecryptedNote, NodePosition, NoteValue,
    PoseidonHash, ShieldCommitment, TransactCommitment, U256, ViewingKey,
};

use crate::{
    CryptoError, DerivedRailgunKeys, aes::decrypt_gcm, commitment, viewing::ViewingKeySharedSecret,
};

/// Holds the keys needed to detect and decrypt a wallet's own commitments.
#[derive(Debug, Clone, Copy)]
pub struct NoteDecryptor {
    viewing_key: ViewingKey,
    spending_public_key: BabyJubJubPoint,
    nullifying_key: PoseidonHash,
}

impl NoteDecryptor {
    pub fn new(
        viewing_key: ViewingKey,
        spending_public_key: BabyJubJubPoint,
        nullifying_key: PoseidonHash,
    ) -> Self {
        Self {
            viewing_key,
            spending_public_key,
            nullifying_key,
        }
    }

    /// Builds a decryptor from a derived RAILGUN account.
    pub fn from_keys(keys: &DerivedRailgunKeys) -> Self {
        Self::new(
            keys.viewing_key,
            keys.spending_public_key,
            keys.nullifying_key,
        )
    }

    /// Decrypts a transact commitment addressed to this wallet.
    ///
    /// # Errors
    /// [`CryptoError::Aes`] if the note is not ours; [`CryptoError::MalformedCommitment`]
    /// if the opened plaintext does not match the expected layout.
    pub fn decrypt_transact(
        &self,
        commitment_event: &TransactCommitment,
    ) -> Result<DecryptedNote, CryptoError> {
        let shared = self
            .viewing_key
            .derive_shared_key_blinded(commitment_event.blinded_sender_viewing_key)?;
        // bundle: [master_public_key, token_hash, random(16)|value(16), memo?]
        let bundle = decrypt_gcm(&commitment_event.ciphertext, shared.as_bytes())?;

        if !(bundle.len() == 3 || bundle.len() == 4) {
            return Err(CryptoError::MalformedCommitment);
        }

        let decrypted_master =
            PoseidonHash::new(U256::from_be_bytes(copy_exact::<32>(&bundle[0])?));
        let master = self.master_public_key()?;
        if decrypted_master != master {
            return Err(CryptoError::CommitmentMismatch);
        }

        let token_hash = copy_exact::<32>(&bundle[1])?;
        let asset = AssetId::from_token_hash(&token_hash)?;

        let random_value = copy_exact::<32>(&bundle[2])?;
        let mut random = [0u8; 16];
        random.copy_from_slice(&random_value[..16]);
        let mut value_bytes = [0u8; 16];
        value_bytes.copy_from_slice(&random_value[16..32]);
        let value = NoteValue::new(u128::from_be_bytes(value_bytes));

        let memo = if let Some(block) = bundle.get(3) {
            // alloc-ok: owned memo string for the decrypted-note DTO.
            String::from_utf8_lossy(block).into_owned()
        } else {
            String::new()
        };

        let note = self.assemble(
            master,
            commitment_event.position,
            asset,
            value,
            random,
            memo,
            BlindedCommitmentType::Transact,
        )?;
        if note.commitment_hash != commitment_event.hash {
            return Err(CryptoError::CommitmentMismatch);
        }

        Ok(note)
    }

    /// Decrypts a shield commitment addressed to this wallet.
    ///
    /// # Errors
    /// [`CryptoError::Aes`] if the note is not ours; [`CryptoError::MalformedCommitment`]
    /// if the opened plaintext does not match the expected layout.
    pub fn decrypt_shield(&self, shield: &ShieldCommitment) -> Result<DecryptedNote, CryptoError> {
        let shared = self.viewing_key.derive_shared_key(shield.shield_key)?;
        let decrypted = decrypt_gcm(&shield.ciphertext, shared.as_bytes())?;

        if decrypted.len() != 1 {
            return Err(CryptoError::MalformedCommitment);
        }
        let random = copy_exact::<16>(&decrypted[0])?;
        let value = NoteValue::try_from_u256(shield.value)?;
        let master = self.master_public_key()?;

        let note = self.assemble(
            master,
            shield.position,
            shield.token,
            value,
            random,
            String::new(),
            BlindedCommitmentType::Shield,
        )?;
        if note.note_public_key != shield.npk {
            return Err(CryptoError::CommitmentMismatch);
        }

        Ok(note)
    }

    fn master_public_key(&self) -> Result<PoseidonHash, CryptoError> {
        commitment::master_public_key(self.spending_public_key, self.nullifying_key)
    }

    fn assemble(
        &self,
        master: PoseidonHash,
        position: NodePosition,
        asset: AssetId,
        value: NoteValue,
        random: [u8; 16],
        memo: String,
        commitment_type: BlindedCommitmentType,
    ) -> Result<DecryptedNote, CryptoError> {
        let note_public_key = commitment::note_public_key(master, &random)?;
        let commitment_hash = commitment::note_hash(note_public_key, asset, value)?;
        let nullifier = commitment::nullifier(self.nullifying_key, position.leaf_index())?;
        let blinded_commitment = commitment::blinded_commitment(
            commitment_hash,
            note_public_key,
            position.tree_number(),
            position.leaf_index(),
        )?;

        Ok(DecryptedNote {
            position,
            value,
            asset,
            random,
            memo,
            commitment_hash,
            note_public_key,
            nullifier,
            blinded_commitment,
            commitment_type,
        })
    }
}

fn copy_exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CryptoError> {
    if bytes.len() != N {
        return Err(CryptoError::MalformedCommitment);
    }

    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}
