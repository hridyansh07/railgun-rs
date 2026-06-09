//! AES-256-GCM note decryption.
//!
//! RAILGUN uses a 16-byte IV/tag (not the 12-byte AES-GCM default), so this wires
//! up `AesGcm<Aes256, U16>` explicitly. Only decryption is implemented; the
//! encryption (sending) side lands with transaction building.

use aes::Aes256;
use aes_gcm::{
    AesGcm, KeyInit, Nonce,
    aead::{Aead, Payload, consts::U16},
};
use types::{Bytes, Ciphertext, SharedKey};

use crate::CryptoError;

type Aes256GcmU16 = AesGcm<Aes256, U16>;

pub(crate) fn decrypt_with_shared_key(
    ciphertext: &Ciphertext,
    key: &SharedKey,
) -> Result<Vec<Bytes>, CryptoError> {
    decrypt_gcm(ciphertext, key.expose_secret())
}

/// Decrypts a RAILGUN GCM ciphertext, returning the original per-block plaintext.
///
/// # Errors
/// Returns [`CryptoError::Aes`] if authentication fails — which, during scanning,
/// simply means the commitment was not addressed to this key.
pub(crate) fn decrypt_gcm(
    ciphertext: &Ciphertext,
    key: &[u8; 32],
) -> Result<Vec<Bytes>, CryptoError> {
    let cipher = Aes256GcmU16::new_from_slice(key).expect("AES-256 key is always 32 bytes");
    let nonce = Nonce::<U16>::from_slice(&ciphertext.iv);

    // alloc-ok: combined ciphertext buffer bounded by the event's block lengths (DTO boundary).
    let mut data_len = 0usize;
    for block in &ciphertext.data {
        data_len = data_len
            .checked_add(block.len())
            .ok_or(CryptoError::MalformedCommitment)?;
    }
    let combined_len = data_len
        .checked_add(ciphertext.tag.len())
        .ok_or(CryptoError::MalformedCommitment)?;
    let mut combined = Vec::with_capacity(combined_len);
    for block in &ciphertext.data {
        combined.extend_from_slice(block);
    }
    combined.extend_from_slice(&ciphertext.tag);

    let decrypted = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: &[],
            },
        )
        .map_err(|_| CryptoError::Aes)?;

    // alloc-ok: per-block plaintext DTO bounded by the ciphertext block count.
    let mut data = Vec::with_capacity(ciphertext.data.len());
    let mut offset = 0usize;
    for block in &ciphertext.data {
        let len = block.len();
        let end = offset
            .checked_add(len)
            .ok_or(CryptoError::MalformedCommitment)?;
        let chunk = decrypted
            .get(offset..end)
            .ok_or(CryptoError::MalformedCommitment)?;
        data.push(Bytes::copy_from_slice(chunk));
        offset = end;
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round-trips through the same AesGcm<Aes256, U16> primitive to prove our
    // block framing (concatenate blocks + append tag) reconstructs the inputs.
    #[test]
    fn decrypt_gcm_recovers_block_framed_plaintext() {
        let key = [7u8; 32];
        let iv = [9u8; 16];
        let blocks: [&[u8]; 3] = [b"hello world ok!", b"second block...", b"third"];

        let cipher = Aes256GcmU16::new_from_slice(&key).unwrap();
        let mut combined = Vec::new();
        for block in &blocks {
            combined.extend_from_slice(block);
        }
        let mut sealed = cipher
            .encrypt(
                Nonce::<U16>::from_slice(&iv),
                Payload {
                    msg: &combined,
                    aad: &[],
                },
            )
            .unwrap();
        let tag: [u8; 16] = sealed.split_off(sealed.len() - 16).try_into().unwrap();

        let mut offset = 0;
        let data: Vec<Bytes> = blocks
            .iter()
            .map(|b| {
                let chunk = Bytes::copy_from_slice(&sealed[offset..offset + b.len()]);
                offset += b.len();
                chunk
            })
            .collect();

        let ciphertext = Ciphertext { iv, tag, data };
        let recovered = decrypt_with_shared_key(&ciphertext, &SharedKey::from_bytes(key)).unwrap();

        let recovered: Vec<&[u8]> = recovered.iter().map(|b| b.as_ref()).collect();
        assert_eq!(recovered, blocks);
    }

    #[test]
    fn decrypt_gcm_rejects_wrong_key() {
        let ciphertext = Ciphertext {
            iv: [0u8; 16],
            tag: [0u8; 16],
            data: vec![Bytes::copy_from_slice(&[0u8; 16])],
        };
        assert!(matches!(
            decrypt_with_shared_key(&ciphertext, &SharedKey::from_bytes([1u8; 32])),
            Err(CryptoError::Aes)
        ));
    }
}
