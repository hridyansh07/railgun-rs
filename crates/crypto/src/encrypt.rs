//! Output-note encryption: the sending side of [`note`](crate::note).
//!
//! Given a recipient [`RailgunAddress`] and the note plaintext, [`encrypt_note`]
//! produces the [`EncryptedNote`] that rides on a transact's on-chain
//! `CommitmentCiphertext`. Two halves:
//! - the **GCM bundle** (`[master_public_key, token_hash, random|value, memo]`)
//!   under a *blinded* ECDH shared key — what the receiver decrypts;
//! - the **CTR annotation** (`output_type | sender_random | app_identifier`) under
//!   the sender's own viewing key — what the *sender* later decrypts to recognize
//!   their own outgoing notes.
//!
//! The blinding keys ([`blind_viewing_keys`]) randomize both parties' viewing
//! public keys with a per-note scalar so the shared key — and thus the link
//! between sender and receiver — is unrecoverable without a viewing key. Layout
//! and scalar derivation are kohaku's `note::encrypt`, byte-for-byte.

use std::sync::LazyLock;

use curve25519_dalek::Scalar;
use sha2::{Digest, Sha512};
use types::{
    AssetId, BlindedKey, Bytes, Ciphertext, NoteValue, RailgunAddress, RailgunBase37, ViewingKey,
    ViewingPublicKey,
};

use crate::CryptoError;
use crate::aes::{SharedKeyGcm, ViewingKeyCtr};
use crate::viewing::{EdwardsCompressed, ViewingKeyPublicKey, ViewingKeySharedSecret};

/// The application-identifier tag embedded (CTR-encrypted) in every output note's
/// annotation. Arbitrary sender metadata; this value matches the kohaku reference.
static APP_IDENTIFIER: LazyLock<[u8; 16]> = LazyLock::new(|| {
    RailgunBase37::encode("railgun rs")
        .expect("\"railgun rs\" is valid base-37")
        .encoded_bytes()
});

/// The randomness one output note consumes.
///
/// `shared_random` becomes the note's on-chain `random`; `sender_random` is
/// `[0; 15]` for an unblinded note. The two IVs nonce the GCM note ciphertext and
/// the CTR annotation respectively. Supplied explicitly so encryption is
/// deterministic and testable — a caller wires these from a CSPRNG.
#[derive(Debug, Clone, Copy)]
pub struct OutputRandomness {
    pub shared_random: [u8; 16],
    pub sender_random: [u8; 15],
    pub gcm_iv: [u8; 16],
    pub ctr_iv: [u8; 16],
}

/// One encrypted output commitment, ready to ride on a transact's
/// `CommitmentCiphertext`. Mirrors the fields a [`types::TransactBody`] carries, so
/// the receiver's [`NodeDecrypt`](crate::NodeDecrypt) opens it straight back to the
/// note.
#[derive(Debug)]
pub struct EncryptedNote {
    /// IV/tag plus the three fixed GCM blocks
    /// `[master_public_key, token_hash, random|value]`.
    pub ciphertext: Ciphertext,
    /// The trailing GCM block: the (possibly empty) memo, carried separately.
    pub memo: Bytes,
    pub blinded_sender_key: BlindedKey,
    pub blinded_receiver_key: BlindedKey,
    /// CTR annotation blob: `ctr_iv | E(output_type|sender_random) | E(pad) | E(app_id)`.
    pub annotation_data: Bytes,
}

/// Encrypts a note addressed to `receiver` into an [`EncryptedNote`].
///
/// `value`/`asset`/`memo` are the note plaintext; `sender_viewing_key` keys both
/// the blinding and the sender annotation; `rand` supplies the per-note randomness.
///
/// # Errors
/// [`CryptoError::PointDecompression`] if a viewing key is not a valid curve point;
/// propagates [`CryptoError::Aes`] from the underlying encryption.
pub fn encrypt_note(
    receiver: &RailgunAddress,
    sender_viewing_key: &ViewingKey,
    asset: AssetId,
    value: NoteValue,
    memo: &str,
    rand: &OutputRandomness,
) -> Result<EncryptedNote, CryptoError> {
    let mut shared_random32 = [0u8; 32];
    shared_random32[..16].copy_from_slice(&rand.shared_random);
    let mut sender_random32 = [0u8; 32];
    sender_random32[..15].copy_from_slice(&rand.sender_random);

    let (blinded_sender_key, blinded_receiver_key) = blind_viewing_keys(
        sender_viewing_key.public_key(),
        receiver.viewing_pubkey(),
        &shared_random32,
        &sender_random32,
    )?;

    // Symmetric with decrypt's blinded-sender path: the sender derives the same
    // shared key from its own viewing key against the blinded receiver key.
    let shared_key = sender_viewing_key.derive_shared_key_blinded(blinded_receiver_key)?;

    let master = receiver.master_key().as_u256().to_be_bytes::<32>();
    let token = asset.token_hash().to_be_bytes::<32>();
    let mut random_value = [0u8; 32];
    random_value[..16].copy_from_slice(&rand.shared_random);
    random_value[16..].copy_from_slice(&value.as_u128().to_be_bytes());

    let mut gcm = shared_key.gcm_encrypt(
        &[&master, &token, &random_value, memo.as_bytes()],
        &rand.gcm_iv,
    )?;

    // The trailing GCM block (the memo) rides separately on the commitment, matching
    // the on-chain TransactBody layout the decryptor reconstructs.
    let memo_block = gcm.data.pop().unwrap_or_default();
    let ciphertext = Ciphertext {
        iv: gcm.iv,
        tag: gcm.tag,
        data: gcm.data,
    };

    let annotation_data = encrypt_annotation(sender_viewing_key, &rand.sender_random, &rand.ctr_iv);

    Ok(EncryptedNote {
        ciphertext,
        memo: memo_block,
        blinded_sender_key,
        blinded_receiver_key,
        annotation_data,
    })
}

/// Blinds both viewing public keys by a shared per-note scalar
/// (`scalar = reverse(Sha512(shared_random XOR sender_random))`), so neither the
/// shared key nor the sender/receiver link is recoverable without a viewing key.
///
/// # Errors
/// [`CryptoError::PointDecompression`] if either key is not a valid curve point.
pub fn blind_viewing_keys(
    sender: ViewingPublicKey,
    receiver: ViewingPublicKey,
    shared_random: &[u8; 32],
    sender_random: &[u8; 32],
) -> Result<(BlindedKey, BlindedKey), CryptoError> {
    let mut final_random = [0u8; 32];
    for (out, (a, b)) in final_random
        .iter_mut()
        .zip(shared_random.iter().zip(sender_random))
    {
        *out = a ^ b;
    }

    let mut hash: [u8; 64] = Sha512::digest(final_random).into();
    hash.reverse();
    let scalar = Scalar::from_bytes_mod_order_wide(&hash);

    Ok((
        BlindedKey::from_bytes((sender.edwards_point()? * scalar).compress().to_bytes()),
        BlindedKey::from_bytes((receiver.edwards_point()? * scalar).compress().to_bytes()),
    ))
}

/// Builds the 64-byte CTR annotation: `ctr_iv | E(ctr0) | E(ctr1) | E(ctr2)`, where
/// `ctr0 = output_type | sender_random`, `ctr1` is padding, and `ctr2` is the
/// base-37 application identifier. CTR-keyed by the sender's own viewing key, so
/// only the sender can read it back.
fn encrypt_annotation(
    sender_viewing_key: &ViewingKey,
    sender_random: &[u8; 15],
    ctr_iv: &[u8; 16],
) -> Bytes {
    const OUTPUT_TYPE: u8 = 0;

    let mut ctr0 = [0u8; 16];
    ctr0[0] = OUTPUT_TYPE;
    ctr0[1..].copy_from_slice(sender_random);
    let ctr1 = [0u8; 16];
    let ctr2 = *APP_IDENTIFIER;

    let ctr = sender_viewing_key.ctr_apply(&[&ctr0, &ctr1, &ctr2], ctr_iv);

    // alloc-ok: fixed 64-byte annotation blob assembled at a per-output DTO boundary.
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&ctr.iv);
    for block in &ctr.data {
        out.extend_from_slice(block);
    }
    Bytes::from(out)
}

#[cfg(test)]
mod tests {
    use types::{
        BlockNumber, ChainId, CommitmentHash, Node, NodeBody, NodePosition, SpendingKey,
        TransactBody,
    };

    use super::*;
    use crate::{
        NodeDecrypt, NoteDecryptor, SpendingKeyPublicKey, ViewingKeyNullifier, commitment,
    };

    // Known-answer vector from kohaku's `test_blinded_key`.
    #[test]
    fn blind_viewing_keys_matches_vector() {
        let sender = ViewingKey::from_bytes([2u8; 32]).public_key();
        let receiver = ViewingKey::from_bytes([3u8; 32]).public_key();

        let (blinded, their_blinded) =
            blind_viewing_keys(sender, receiver, &[4u8; 32], &[5u8; 32]).unwrap();

        assert_eq!(
            hex::encode(blinded.as_bytes()),
            "2ed993356db2b8b5e573da394c2317942c9a1a72eb9a8dfd02705cc56cb1423b"
        );
        assert_eq!(
            hex::encode(their_blinded.as_bytes()),
            "90878634485e306dc7f31840362fc43532313cea73c9006a19b0718e298ffcce"
        );
    }

    // Strongest parity check: an output we encrypt must decrypt cleanly through the
    // engine-parity NoteDecryptor, recovering the original plaintext.
    #[test]
    fn encrypt_note_round_trips_through_decrypt() {
        // Receiver keys.
        let receiver_spend = SpendingKey::from_bytes([3u8; 32]).public_key();
        let receiver_viewing = ViewingKey::from_bytes([4u8; 32]);
        let nullifying = receiver_viewing.nullifying_key().unwrap();
        let master = commitment::master_public_key(receiver_spend, nullifying).unwrap();
        let receiver = RailgunAddress::from_public_keys(
            master,
            receiver_viewing.public_key(),
            ChainId::evm(1),
        );
        let decryptor = NoteDecryptor::new(receiver_viewing, receiver_spend, nullifying);

        let sender_viewing = ViewingKey::from_bytes([2u8; 32]);
        let asset = AssetId::erc20(
            "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
        );
        let value = NoteValue::new(1000);
        let memo = "test memo";
        let rand = OutputRandomness {
            shared_random: [5u8; 16],
            sender_random: [0u8; 15],
            gcm_iv: [9u8; 16],
            ctr_iv: [1u8; 16],
        };

        let encrypted =
            encrypt_note(&receiver, &sender_viewing, asset, value, memo, &rand).unwrap();

        // The leaf hash binds the note; the decryptor checks it.
        let npk = commitment::note_public_key(master, &rand.shared_random).unwrap();
        let hash: CommitmentHash = commitment::note_hash(npk, asset, value).unwrap();

        let EncryptedNote {
            ciphertext,
            memo: memo_ct,
            blinded_sender_key,
            blinded_receiver_key,
            annotation_data,
        } = encrypted;
        let node = Node {
            position: NodePosition::try_new(0, 0).unwrap(),
            hash,
            block: BlockNumber::new(1),
            body: NodeBody::Transact(TransactBody {
                ciphertext,
                memo: memo_ct,
                blinded_sender_key,
                blinded_receiver_key,
                annotation: annotation_data,
            }),
        };

        let recovered = node.decrypt_with(&decryptor).unwrap();
        assert_eq!(recovered.value.as_u128(), 1000);
        assert_eq!(recovered.asset, asset);
        assert_eq!(recovered.random, rand.shared_random);
        assert_eq!(recovered.memo, memo);
        assert_eq!(recovered.commitment_hash, hash);
    }

    // The sender-facing annotation must round-trip back to its inputs (CTR is its
    // own inverse, keyed by the sender's viewing key).
    #[test]
    fn annotation_round_trips() {
        let sender_viewing = ViewingKey::from_bytes([2u8; 32]);
        let sender_random = [7u8; 15];
        let ctr_iv = [3u8; 16];

        let annotation = encrypt_annotation(&sender_viewing, &sender_random, &ctr_iv);
        assert_eq!(annotation.len(), 64);

        let iv: [u8; 16] = annotation[..16].try_into().unwrap();
        assert_eq!(iv, ctr_iv);

        let decrypted = sender_viewing.ctr_apply(
            &[
                &annotation[16..32],
                &annotation[32..48],
                &annotation[48..64],
            ],
            &iv,
        );

        assert_eq!(decrypted.data[0][0], 0); // output type
        assert_eq!(&decrypted.data[0][1..], &sender_random);
        assert_eq!(&decrypted.data[1][..], &[0u8; 16]); // padding
        let expected_app = RailgunBase37::encode("railgun rs").unwrap().encoded_bytes();
        assert_eq!(&decrypted.data[2][..], &expected_app);
    }
}
