//! [`Decoder`] — opens commitment nodes against one wallet's keys.

use commitments::CommitmentStore;
use crypto::{CryptoError, DerivedRailgunKeys, NodeDecrypt, NoteDecryptor};
use types::DecryptedNote;
use utils::StorageBackend;

use crate::DecodeError;

/// Decodes commitment nodes against a single wallet's keys.
///
/// Holds only the wallet's [`NoteDecryptor`]; the commitment store is passed in per
/// call as a read-only view, so one [`Decoder`] can decode different trees on
/// different threads.
#[derive(Debug, Clone, Copy)]
pub struct Decoder {
    decryptor: NoteDecryptor,
}

impl Decoder {
    /// Builds a decoder from a derived RAILGUN account.
    #[must_use]
    pub fn from_keys(keys: &DerivedRailgunKeys) -> Self {
        Self {
            decryptor: NoteDecryptor::from_keys(keys),
        }
    }

    /// Builds a decoder from an existing [`NoteDecryptor`].
    #[must_use]
    pub fn new(decryptor: NoteDecryptor) -> Self {
        Self { decryptor }
    }

    /// Decodes every leaf of `tree`, returning the notes addressed to this wallet.
    ///
    /// Reads `store` immutably, so callers may decode different trees concurrently. A
    /// leaf that is not ours (or whose plaintext fails validation) is skipped.
    ///
    /// # Errors
    /// Propagates [`DecodeError::Store`] if the commitment store cannot be read.
    pub fn decode_tree<B: StorageBackend>(
        &self,
        store: &CommitmentStore<B>,
        tree: u32,
    ) -> Result<Vec<DecryptedNote>, DecodeError> {
        let view = store.tree(tree);
        let leaf_count = view.leaf_count()?;
        // alloc-ok: owned notes for one tree, bounded by its leaf count.
        let mut found = Vec::new();
        for position in 0..leaf_count {
            if let Some(node) = view.get(position)? {
                match node.decrypt_with(&self.decryptor) {
                    Ok(note) => found.push(note),
                    // The overwhelming common case: the leaf is not addressed to us.
                    // No Error just move forward
                    Err(CryptoError::Aes) => {}
                    // Decrypted but failed validation, or malformed data — unexpected,
                    // so surface it rather than swallowing it like a non-match.
                    Err(error) => tracing::debug!(
                        tree,
                        position,
                        %error,
                        "skipped commitment that decrypted but did not validate"
                    ),
                }
            }
        }
        Ok(found)
    }

    /// Decodes every tree in `store`, sequentially.
    ///
    /// A convenience over [`decode_tree`](Self::decode_tree); for large stores a caller
    /// can instead fan `decode_tree` calls across threads and merge the results.
    ///
    /// # Errors
    /// Propagates [`DecodeError::Store`].
    pub fn decode_all<B: StorageBackend>(
        &self,
        store: &CommitmentStore<B>,
    ) -> Result<Vec<DecryptedNote>, DecodeError> {
        let tree_count = store.tree_count()?;
        // alloc-ok: owned notes across the forest, bounded by total decoded leaves.
        let mut found = Vec::new();
        for tree in 0..tree_count {
            found.extend(self.decode_tree(store, tree)?);
        }
        Ok(found)
    }
}
