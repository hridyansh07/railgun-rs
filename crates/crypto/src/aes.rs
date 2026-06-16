//! AES note encryption and decryption.
//!
//! RAILGUN uses a 16-byte IV/tag (not the 12-byte AES-GCM default), so this wires
//! up `AesGcm<Aes256, U16>` explicitly. The capabilities hang off the key types as
//! traits (matching the rest of `crypto`): [`SharedKeyGcm`] seals and opens the note
//! plaintext bundle (scanning opens commitments, transaction building seals
//! outputs); [`ViewingKeyCtr`] carries the sender-only transact annotation. Each
//! method owns the per-block framing, so callers hand it only the blocks and an IV.
//!
//! A cipher is rebuilt per call rather than cached, because RAILGUN derives a unique
//! key per note (per-note blinded ECDH) — there is never key reuse to amortize.

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, AesGcm, KeyInit, Nonce};
use types::{Bytes, Ciphertext, SharedKey, ViewingKey};

use crate::CryptoError;

type Aes256GcmU16 = AesGcm<Aes256, U16>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// AES-256-CTR ciphertext: an IV plus per-block keystream-XORed data. RAILGUN
/// encrypts the transact annotation (sender-decryptable note metadata) in CTR
/// rather than GCM, so it carries no authentication tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CiphertextCtr {
    pub iv: [u8; 16],
    // alloc-ok: per-block CTR data, bounded by the annotation block count (3).
    pub data: Vec<Bytes>,
}

/// AES-256-GCM note encryption keyed by a derived [`SharedKey`] (16-byte IV/tag).
///
/// Owns the on-chain block framing: a note's blocks are sealed as one GCM message
/// under a single shared tag, then split back into the per-block [`Ciphertext`]
/// `data` the commitment carries. The same key opens that ciphertext, so both
/// directions of the framing live together.
pub(crate) trait SharedKeyGcm {
    /// Returns an Aes256GcmU16 cipher object using the underlying key's secret
    fn cipher(&self) -> Aes256GcmU16;

    /// Seals `blocks` as one GCM message under `iv`, returning the per-block framing
    /// (one shared 16-byte tag) the on-chain commitment ciphertext uses.
    ///
    /// # Errors
    /// [`CryptoError::Aes`] if the primitive rejects the inputs;
    /// [`CryptoError::MalformedCommitment`] if a block length overflows the buffer.
    fn gcm_encrypt(&self, blocks: &[&[u8]], iv: &[u8; 16]) -> Result<Ciphertext, CryptoError>;

    /// Opens a RAILGUN GCM ciphertext, returning the original per-block plaintext.
    ///
    /// # Errors
    /// [`CryptoError::Aes`] if authentication fails — which, during scanning, simply
    /// means the commitment was not addressed to this key;
    /// [`CryptoError::MalformedCommitment`] if a block length overflows the buffer.
    fn gcm_decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<Bytes>, CryptoError>;
}

impl SharedKeyGcm for SharedKey {
    fn cipher(&self) -> Aes256GcmU16 {
        Aes256GcmU16::new_from_slice(self.expose_secret()).expect("AES-256 key is always 32 bytes")
    }

    fn gcm_encrypt(&self, blocks: &[&[u8]], iv: &[u8; 16]) -> Result<Ciphertext, CryptoError> {
        let nonce = Nonce::<U16>::from_slice(iv);

        // alloc-ok: combined plaintext buffer bounded by the note's block lengths (DTO boundary).
        let mut buffer = Vec::with_capacity(blocks.iter().map(|b| b.len()).sum());
        for block in blocks {
            buffer.extend_from_slice(block);
        }

        let tag = self
            .cipher()
            .encrypt_in_place_detached(nonce, &[], &mut buffer)
            .map_err(|_| CryptoError::Aes)?;
        
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_slice());

        let data = split_blocks(&buffer, blocks.iter().map(|b| b.len()))?;
        Ok(Ciphertext {
            iv: *iv,
            tag: tag_bytes,
            data,
        })
    }

    fn gcm_decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<Bytes>, CryptoError> {
        let nonce = Nonce::<U16>::from_slice(&ciphertext.iv);

        // alloc-ok: combined ciphertext buffer bounded by the event's block lengths (DTO boundary).
        let mut buffer = Vec::with_capacity(ciphertext.data.iter().map(|b| b.len()).sum());
        for block in &ciphertext.data {
            buffer.extend_from_slice(block);
        }

        let tag = GenericArray::<u8, U16>::from_slice(&ciphertext.tag);
        self.cipher()
            .decrypt_in_place_detached(nonce, &[], &mut buffer, tag)
            .map_err(|_| CryptoError::Aes)?;

        split_blocks(&buffer, ciphertext.data.iter().map(|b| b.len()))
    }
}

/// AES-256-CTR annotation cipher keyed by the sender's [`ViewingKey`]. CTR is its
/// own inverse, so [`ctr_apply`](Self::ctr_apply) both encrypts and decrypts.
pub(crate) trait ViewingKeyCtr {

    /// AES-256-CTR annotation cipher object based on sender's [`ViewingKey`] and `iv`
    fn cipher(&self, iv: &[u8; 16]) -> Aes256Ctr;

    /// Applies the AES-256-CTR keystream to each block under `iv`. Calling it again
    /// with the resulting blocks (and the same `iv`) recovers the input.
    fn ctr_apply(&self, blocks: &[&[u8]], iv: &[u8; 16]) -> CiphertextCtr;
}

impl ViewingKeyCtr for ViewingKey {
    fn cipher(&self, iv: &[u8; 16]) -> Aes256Ctr {
        Aes256Ctr::new(self.expose_secret().into(), iv.into())
    }

    fn ctr_apply(&self, blocks: &[&[u8]], iv: &[u8; 16]) -> CiphertextCtr {
        // alloc-ok: per-block CTR output bounded by the annotation block count.
        let mut data = Vec::with_capacity(blocks.len());
        for block in blocks {
            // alloc-ok: mutable per-block buffer for in-place keystream XOR.
            let mut buffer = block.to_vec();
            self.cipher(iv).apply_keystream(&mut buffer);
            data.push(Bytes::from(buffer));
        }
        CiphertextCtr { iv: *iv, data }
    }
}

/// Splits a flat `buffer` back into per-block [`Bytes`] using the original block
/// `lengths` — the inverse of concatenating the blocks before a single GCM op.
fn split_blocks(
    buffer: &[u8],
    lengths: impl ExactSizeIterator<Item = usize>,
) -> Result<Vec<Bytes>, CryptoError> {
    // alloc-ok: per-block DTO bounded by the ciphertext block count.
    let mut data = Vec::with_capacity(lengths.len());
    let mut offset = 0usize;
    for len in lengths {
        let end = offset
            .checked_add(len)
            .ok_or(CryptoError::MalformedCommitment)?;
        let chunk = buffer
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

    // Independently seals with the raw primitive (detached tag) and frames it the way
    // the on-chain commitment ciphertext does, then proves gcm_decrypt rebuilds the
    // inputs from that framing.
    #[test]
    fn decrypt_recovers_block_framed_plaintext() {
        let key = SharedKey::from_bytes([7u8; 32]);
        let iv = [9u8; 16];
        let blocks: [&[u8]; 3] = [b"hello world ok!", b"second block...", b"third"];

        let cipher = Aes256GcmU16::new_from_slice(key.expose_secret()).unwrap();
        let mut buffer = Vec::new();
        for block in &blocks {
            buffer.extend_from_slice(block);
        }
        let tag = cipher
            .encrypt_in_place_detached(Nonce::<U16>::from_slice(&iv), &[], &mut buffer)
            .unwrap();
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_slice());

        let mut offset = 0;
        let data: Vec<Bytes> = blocks
            .iter()
            .map(|b| {
                let chunk = Bytes::copy_from_slice(&buffer[offset..offset + b.len()]);
                offset += b.len();
                chunk
            })
            .collect();

        let ciphertext = Ciphertext {
            iv,
            tag: tag_bytes,
            data,
        };
        let recovered = key.gcm_decrypt(&ciphertext).unwrap();

        let recovered: Vec<&[u8]> = recovered.iter().map(|b| b.as_ref()).collect();
        assert_eq!(recovered, blocks);
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let ciphertext = Ciphertext {
            iv: [0u8; 16],
            tag: [0u8; 16],
            data: vec![Bytes::copy_from_slice(&[0u8; 16])],
        };
        assert!(matches!(
            SharedKey::from_bytes([1u8; 32]).gcm_decrypt(&ciphertext),
            Err(CryptoError::Aes)
        ));
    }

    // Our own encrypt direction must round-trip through the parity-locked decrypt.
    #[test]
    fn encrypt_round_trips_through_decrypt() {
        let key = SharedKey::from_bytes([3u8; 32]);
        let iv = [9u8; 16];
        let blocks: [&[u8]; 3] = [b"first block 32by", b"second block xx", b"third"];

        let ciphertext = key.gcm_encrypt(&blocks, &iv).unwrap();
        assert_eq!(ciphertext.iv, iv);
        assert_eq!(ciphertext.data.len(), 3);

        let recovered = key.gcm_decrypt(&ciphertext).unwrap();
        let recovered: Vec<&[u8]> = recovered.iter().map(AsRef::as_ref).collect();
        assert_eq!(recovered, blocks);
    }

    // CTR keystream XOR is its own inverse: re-applying recovers the plaintext.
    #[test]
    fn ctr_is_symmetric() {
        let key = ViewingKey::from_bytes([5u8; 32]);
        let iv = [1u8; 16];
        let blocks: [&[u8]; 3] = [b"output|sender..", b"padding00000000", b"app-identifier."];

        let ciphertext = key.ctr_apply(&blocks, &iv);
        assert_eq!(ciphertext.iv, iv);
        let cipher_blocks: Vec<&[u8]> = ciphertext.data.iter().map(AsRef::as_ref).collect();

        let recovered = key.ctr_apply(&cipher_blocks, &ciphertext.iv);
        let recovered: Vec<&[u8]> = recovered.data.iter().map(AsRef::as_ref).collect();
        assert_eq!(recovered, blocks);
    }
}
