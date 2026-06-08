//! Tree-node (commitment) decryption: open a shield/transact leaf with the wallet's
//! viewing key and reconstruct the [`DecryptedNote`].
//!
//! An AES failure means the leaf was not addressed to this viewing key — during
//! scanning the caller simply skips it.

// NOTE Ideally this file is not strictly required since the decryption should be a function built on the node
// iteslf the current logical boudaries dicate that crypto functions live in this crate. Revisit and Fix

use types::{
    AssetId, BabyJubJubPoint, BlindedCommitmentType, Bytes, Ciphertext, CommitmentHash,
    DecryptedNote, Node, NodeBody, NodePosition, NoteValue, PoseidonHash, ShieldBody, TransactBody,
    U256, ViewingKey,
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

    /// Attempts to open `node` as a note addressed to this wallet, dispatching on its
    /// kind.
    ///
    /// # Errors
    /// [`CryptoError::Aes`] if the leaf is not ours; [`CryptoError::MalformedCommitment`]
    /// if the opened plaintext does not match the expected layout;
    /// [`CryptoError::CommitmentMismatch`] if it decodes but does not reproduce the
    /// stored commitment.
    pub fn decrypt(&self, node: &Node) -> Result<DecryptedNote, CryptoError> {
        match &node.body {
            NodeBody::Transact(body) => self.decrypt_transact(node.position, node.hash, body),
            NodeBody::Shield(body) => self.decrypt_shield(node.position, body),
        }
    }

    fn decrypt_transact(
        &self,
        position: NodePosition,
        hash: CommitmentHash,
        body: &TransactBody,
    ) -> Result<DecryptedNote, CryptoError> {
        let shared = self
            .viewing_key
            .derive_shared_key_blinded(body.blinded_sender_key)?;
        // The on-chain memo is the trailing encrypted block of the note ciphertext.
        let ciphertext = with_memo(&body.ciphertext, &body.memo);
        // bundle: [master_public_key, token_hash, random(16)|value(16), memo?]
        let bundle = decrypt_gcm(&ciphertext, shared.as_bytes())?;

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
            position,
            asset,
            value,
            random,
            memo,
            BlindedCommitmentType::Transact,
        )?;
        if note.commitment_hash != hash {
            return Err(CryptoError::CommitmentMismatch);
        }

        Ok(note)
    }

    fn decrypt_shield(
        &self,
        position: NodePosition,
        body: &ShieldBody,
    ) -> Result<DecryptedNote, CryptoError> {
        let ciphertext = shield_ciphertext(&body.encrypted_bundle)?;
        let shared = self.viewing_key.derive_shared_key(body.shield_key)?;
        let decrypted = decrypt_gcm(&ciphertext, shared.as_bytes())?;

        if decrypted.len() != 1 {
            return Err(CryptoError::MalformedCommitment);
        }
        let random = copy_exact::<16>(&decrypted[0])?;
        let value = NoteValue::try_from_u256(body.value)?;
        let master = self.master_public_key()?;

        let note = self.assemble(
            master,
            position,
            body.token,
            value,
            random,
            String::new(),
            BlindedCommitmentType::Shield,
        )?;
        if note.note_public_key != body.npk {
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

/// Reconstructs the full note ciphertext: the fixed data blocks plus the on-chain
/// memo, which is encrypted as the trailing block.
fn with_memo(ciphertext: &Ciphertext, memo: &Bytes) -> Ciphertext {
    // alloc-ok: per-leaf reconstruction of the full ciphertext for decryption.
    let mut data = ciphertext.data.clone();
    data.push(memo.clone());
    Ciphertext {
        iv: ciphertext.iv,
        tag: ciphertext.tag,
        data,
    }
}

/// Reconstructs the shield ciphertext from the stored bundle:
/// `iv = bundle[0][..16]`, `tag = bundle[0][16..]`, ciphertext = `bundle[1][..16]`.
fn shield_ciphertext(bundle: &[[u8; 32]]) -> Result<Ciphertext, CryptoError> {
    if bundle.len() < 2 {
        return Err(CryptoError::MalformedCommitment);
    }
    let iv = copy_exact::<16>(&bundle[0][..16])?;
    let tag = copy_exact::<16>(&bundle[0][16..])?;
    // alloc-ok: single-block shield ciphertext reconstructed from the stored bundle.
    let data = vec![Bytes::copy_from_slice(&bundle[1][..16])];
    Ok(Ciphertext { iv, tag, data })
}

fn copy_exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CryptoError> {
    if bytes.len() != N {
        return Err(CryptoError::MalformedCommitment);
    }

    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}
