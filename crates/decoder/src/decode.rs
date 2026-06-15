//! [`Decoder`] — opens commitment nodes against one wallet's keys.

use crypto::{CryptoError, DerivedRailgunKeys, NodeDecrypt, NoteDecryptor};
use database::{Commitments, Reader};
use types::DecryptedNote;

use crate::DecodeError;

/// Decodes commitment nodes against a single wallet's keys.
///
/// Holds only the wallet's [`NoteDecryptor`]; the database read context is
/// passed in per call, so one [`Decoder`] can decode different trees on
/// different threads (each with its own read view).
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

    /// Decodes every stored leaf of `tree` — one range scan — returning the
    /// notes addressed to this wallet. A leaf that is not ours (or whose
    /// plaintext fails validation) is skipped.
    ///
    /// # Errors
    /// Propagates [`DecodeError::Database`] if the database cannot be read.
    pub fn decode_tree<R: Reader>(
        &self,
        view: &R,
        tree: u32,
    ) -> Result<Vec<DecryptedNote>, DecodeError> {
        let span = tracing::info_span!("decode.tree", tree);
        let _guard = span.enter();
        let started = std::time::Instant::now();

        // alloc-ok: owned notes for one tree, bounded by its leaf count.
        let mut found = Vec::new();
        let mut leaves: u64 = 0;
        for stored in Commitments::new(view).nodes(tree)? {
            let stored = stored?;
            leaves += 1;
            let position = stored.position;
            match stored.decrypt_with(&self.decryptor) {
                Ok(note) => found.push(note),
                // The overwhelming common case: the leaf is not addressed to us.
                Err(CryptoError::Aes) => {}
                // Decrypted but failed validation, or malformed data — unexpected,
                // so surface it rather than swallowing it like a non-match.
                Err(error) => tracing::debug!(
                    tree,
                    position = position.leaf_index(),
                    %error,
                    "skipped commitment that decrypted but did not validate"
                ),
            }
        }

        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        tracing::info!(
            tree,
            leaves,
            notes_found = found.len(),
            duration_ms,
            leaves_per_sec = per_second(leaves, started.elapsed()),
            "tree decoded"
        );
        Ok(found)
    }

    /// Decodes every tree, sequentially.
    ///
    /// A convenience over [`decode_tree`](Self::decode_tree); for large stores a caller
    /// can instead fan `decode_tree` calls across threads and merge the results.
    ///
    /// # Errors
    /// Propagates [`DecodeError::Database`].
    pub fn decode_all<R: Reader>(&self, view: &R) -> Result<Vec<DecryptedNote>, DecodeError> {
        let span = tracing::info_span!("decode.all");
        let _guard = span.enter();
        let started = std::time::Instant::now();

        let tree_count = Commitments::new(view).tree_count()?;
        // alloc-ok: owned notes across the forest, bounded by total decoded leaves.
        let mut found = Vec::new();
        for tree in 0..tree_count {
            found.extend(self.decode_tree(view, tree)?);
        }

        tracing::info!(
            trees = tree_count,
            notes_found = found.len(),
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "forest decoded"
        );
        Ok(found)
    }
}

/// Whole-unit rate for tracing fields (0 when the window is too small to be
/// meaningful).
pub(crate) fn per_second(count: u64, elapsed: std::time::Duration) -> u64 {
    let secs = elapsed.as_secs_f64();
    if secs <= f64::EPSILON {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (count as f64 / secs) as u64
    }
}
