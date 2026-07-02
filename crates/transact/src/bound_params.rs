//! `boundParamsHash`: keccak256 of the ABI-encoded on-chain `BoundParams`, reduced
//! into the BN254 scalar field. The transact witness's signed message commits to it,
//! and the on-chain transaction carries the same `BoundParams`.
//!
//! The `sol!` structs mirror the RAILGUN smart-wallet ABI (kohaku `abis/railgun.rs`)
//! byte-for-byte — declaration order is load-bearing for `abi_encode`. The four
//! `ciphertext` words map 1:1 from a [`crypto::EncryptedNote`]
//! (`[iv|tag, E(master), E(token), E(random|value)]`); the misleading Solidity
//! comment notwithstanding, that is the native `Ciphertext.data` order exactly.

use alloy_primitives::{Address, B256, U256, aliases::U72, keccak256};
use alloy_sol_types::{SolValue, sol};
use crypto::{EncryptedNote, Q};

use crate::error::TransactInputsError;

sol! {
    #[derive(Debug)]
    struct CommitmentCiphertext {
        bytes32[4] ciphertext;
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
        bytes annotationData;
        bytes memo;
    }

    #[derive(Debug)]
    enum UnshieldType {
        NONE,
        NORMAL,
        REDIRECT,
    }

    #[derive(Debug)]
    struct BoundParams {
        uint16 treeNumber;
        uint72 minGasPrice;
        UnshieldType unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        CommitmentCiphertext[] commitmentCiphertext;
    }
}

impl BoundParams {
    /// `keccak256(abi_encode(self)) mod Q` — the field-reduced bound-params digest.
    fn hash(&self) -> U256 {
        // alloc-ok: ABI-encoded byte buffer at the hashing DTO boundary.
        let encoded = self.abi_encode();
        U256::from_be_bytes(keccak256(&encoded).0) % Q
    }
}

/// Maps a [`crypto::EncryptedNote`] onto the on-chain `CommitmentCiphertext` it rides
/// as: `ciphertext = [iv|tag, data[0], data[1], data[2]]`, plus the blinded keys,
/// annotation, and memo verbatim.
///
/// # Errors
/// [`TransactInputsError::MalformedCiphertext`] if the note's GCM ciphertext is not
/// exactly three 32-byte blocks (the on-chain `bytes32[4]` layout the digest commits
/// to expects `[iv|tag, E(master), E(token), E(random|value)]`).
fn to_commitment_ciphertext(
    note: &EncryptedNote,
) -> Result<CommitmentCiphertext, TransactInputsError> {
    let ct = &note.ciphertext;
    let mut iv_tag = [0u8; 32];
    iv_tag[..16].copy_from_slice(&ct.iv);
    iv_tag[16..].copy_from_slice(&ct.tag);

    // The three GCM blocks are fixed 32-byte words on-chain; reject anything else
    // instead of panicking in `B256::from_slice`.
    if ct.data.len() != 3 {
        return Err(TransactInputsError::MalformedCiphertext);
    }
    let block = |i: usize| -> Result<B256, TransactInputsError> {
        let bytes = ct
            .data
            .get(i)
            .ok_or(TransactInputsError::MalformedCiphertext)?;
        if bytes.len() != 32 {
            return Err(TransactInputsError::MalformedCiphertext);
        }
        Ok(B256::from_slice(bytes))
    };

    Ok(CommitmentCiphertext {
        ciphertext: [B256::from(iv_tag), block(0)?, block(1)?, block(2)?],
        blindedSenderViewingKey: B256::from_slice(note.blinded_sender_key.as_bytes()),
        blindedReceiverViewingKey: B256::from_slice(note.blinded_receiver_key.as_bytes()),
        annotationData: note.annotation_data.clone(),
        memo: note.memo.clone(),
    })
}

/// Computes `boundParamsHash` for a transact: the keccak256 of the ABI-encoded
/// `BoundParams`, reduced into the scalar field.
///
/// `notes` must be exactly the encrypted (non-unshield) output notes: an unshield
/// output carries no `CommitmentCiphertext` and so is not an [`EncryptedNote`] — the
/// caller omits it, making `notes.len()` equal `(commitments - unshields)`.
///
/// `min_gas_price` is fixed at 0 (vestigial for relayers); `adapt_contract`/
/// `adapt_params` default to zero for a plain transfer.
///
/// # Errors
/// [`TransactInputsError::MalformedCiphertext`] if any note's GCM ciphertext is not
/// the three fixed 32-byte blocks the on-chain `bytes32[4]` layout requires.
pub fn bound_params_hash(
    tree_number: u16,
    unshield: UnshieldType,
    chain_id: u64,
    adapt_contract: Address,
    adapt_params: &[u8; 32],
    notes: &[EncryptedNote],
) -> Result<U256, TransactInputsError> {
    // alloc-ok: one CommitmentCiphertext per output note at the ABI DTO boundary.
    let commitment_ciphertext = notes
        .iter()
        .map(to_commitment_ciphertext)
        .collect::<Result<_, _>>()?;
    Ok(BoundParams {
        treeNumber: tree_number,
        minGasPrice: U72::ZERO,
        unshield,
        chainID: chain_id,
        adaptContract: adapt_contract,
        adaptParams: B256::from(*adapt_params),
        commitmentCiphertext: commitment_ciphertext,
    }
    .hash())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Bytes, address};
    use crypto::{
        OutputRandomness, SpendingKeyPublicKey, ViewingKeyNullifier, ViewingKeyPublicKey,
        commitment, encrypt_note,
    };
    use types::{AssetId, ChainId, NoteValue, RailgunAddress, SpendingKey, ViewingKey, uint};

    use super::*;

    // Known-answer vector ported verbatim from kohaku `test_hash_bound_params`.
    #[test]
    fn bound_params_hash_matches_kohaku_vector() {
        let bound_params = BoundParams {
            treeNumber: 1,
            minGasPrice: U72::from(10),
            unshield: UnshieldType::NONE,
            chainID: 1,
            adaptContract: address!("0x1234567890123456789012345678901234567890"),
            adaptParams: B256::from([5u8; 32]),
            commitmentCiphertext: vec![CommitmentCiphertext {
                ciphertext: [
                    B256::from([1u8; 32]),
                    B256::from([1u8; 32]),
                    B256::from([1u8; 32]),
                    B256::from([1u8; 32]),
                ],
                blindedSenderViewingKey: B256::from([2u8; 32]),
                blindedReceiverViewingKey: B256::from([3u8; 32]),
                annotationData: Bytes::from(vec![4u8; 50]),
                memo: Bytes::from(vec![5u8; 50]),
            }],
        };

        assert_eq!(
            bound_params.hash(),
            uint!(653354349844558206886319240777917397850034746873378410801880094244109558523_U256)
        );
    }

    // Builds a real encrypted output note (three fixed 32-byte GCM blocks) for the
    // mapping tests.
    fn sample_note() -> EncryptedNote {
        let receiver_spend = SpendingKey::from_bytes([3u8; 32]).public_key();
        let receiver_viewing = ViewingKey::from_bytes([4u8; 32]);
        let nullifying = receiver_viewing.nullifying_key().unwrap();
        let master = commitment::master_public_key(receiver_spend, nullifying).unwrap();
        let receiver = RailgunAddress::from_public_keys(
            master,
            receiver_viewing.public_key(),
            ChainId::evm(1),
        );
        let sender_viewing = ViewingKey::from_bytes([2u8; 32]);
        let asset = AssetId::erc20(
            "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
        );
        let rand = OutputRandomness {
            shared_random: [5u8; 16],
            sender_random: [0u8; 15],
            gcm_iv: [9u8; 16],
            ctr_iv: [1u8; 16],
        };
        encrypt_note(
            &receiver,
            &sender_viewing,
            asset,
            NoteValue::new(1000),
            "memo",
            &rand,
        )
        .unwrap()
    }

    // A ciphertext that is not exactly three 32-byte GCM blocks is rejected instead of
    // panicking in `B256::from_slice` / out-of-bounds indexing.
    #[test]
    fn malformed_ciphertext_rejected() {
        let mut short = sample_note();
        short.ciphertext.data.truncate(2);
        assert!(matches!(
            to_commitment_ciphertext(&short),
            Err(TransactInputsError::MalformedCiphertext)
        ));

        let mut bad_block = sample_note();
        bad_block.ciphertext.data[1] = Bytes::from(vec![0u8; 31]);
        assert!(matches!(
            to_commitment_ciphertext(&bad_block),
            Err(TransactInputsError::MalformedCiphertext)
        ));

        // bound_params_hash propagates the same failure.
        let mut short = sample_note();
        short.ciphertext.data.truncate(2);
        assert!(matches!(
            bound_params_hash(
                1,
                UnshieldType::NONE,
                1,
                Address::ZERO,
                &[0u8; 32],
                &[short],
            ),
            Err(TransactInputsError::MalformedCiphertext)
        ));
    }

    // The EncryptedNote → CommitmentCiphertext mapping is a direct 1:1 field copy.
    #[test]
    fn commitment_ciphertext_maps_encrypted_note() {
        let receiver_spend = SpendingKey::from_bytes([3u8; 32]).public_key();
        let receiver_viewing = ViewingKey::from_bytes([4u8; 32]);
        let nullifying = receiver_viewing.nullifying_key().unwrap();
        let master = commitment::master_public_key(receiver_spend, nullifying).unwrap();
        let receiver = RailgunAddress::from_public_keys(
            master,
            receiver_viewing.public_key(),
            ChainId::evm(1),
        );
        let sender_viewing = ViewingKey::from_bytes([2u8; 32]);
        let asset = AssetId::erc20(
            "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
        );
        let rand = OutputRandomness {
            shared_random: [5u8; 16],
            sender_random: [0u8; 15],
            gcm_iv: [9u8; 16],
            ctr_iv: [1u8; 16],
        };
        let note = encrypt_note(
            &receiver,
            &sender_viewing,
            asset,
            NoteValue::new(1000),
            "memo",
            &rand,
        )
        .unwrap();

        let cc = to_commitment_ciphertext(&note).unwrap();

        let mut iv_tag = [0u8; 32];
        iv_tag[..16].copy_from_slice(&note.ciphertext.iv);
        iv_tag[16..].copy_from_slice(&note.ciphertext.tag);
        assert_eq!(cc.ciphertext[0], B256::from(iv_tag));
        assert_eq!(cc.ciphertext[1], B256::from_slice(&note.ciphertext.data[0]));
        assert_eq!(cc.ciphertext[2], B256::from_slice(&note.ciphertext.data[1]));
        assert_eq!(cc.ciphertext[3], B256::from_slice(&note.ciphertext.data[2]));
        assert_eq!(
            cc.blindedSenderViewingKey,
            B256::from_slice(note.blinded_sender_key.as_bytes())
        );
        assert_eq!(
            cc.blindedReceiverViewingKey,
            B256::from_slice(note.blinded_receiver_key.as_bytes())
        );
        assert_eq!(cc.annotationData, note.annotation_data);
        assert_eq!(cc.memo, note.memo);
    }
}
