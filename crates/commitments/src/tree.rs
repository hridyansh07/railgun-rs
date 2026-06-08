//! A per-tree view over a [`CommitmentStore`].

use types::Node;
use utils::StorageBackend;

use crate::{CommitmentStore, CommitmentStoreError};

/// A borrow of a [`CommitmentStore`] scoped to a single tree.
///
/// This is the unit of work for scanning — each tree is independent and can be owned by
/// one thread — and, later, the home for the merkle walk-up (`root`/`proof`). It holds
/// no state of its own; every read goes through the store.
pub struct Tree<'a, B: StorageBackend> {
    store: &'a CommitmentStore<B>,
    number: u32,
}

impl<'a, B: StorageBackend> Tree<'a, B> {
    pub(crate) fn new(store: &'a CommitmentStore<B>, number: u32) -> Self {
        Self { store, number }
    }

    /// This tree's number in the forest.
    #[must_use]
    pub fn number(&self) -> u32 {
        self.number
    }

    /// Number of leaves recorded in this tree (highest seen position + 1).
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn leaf_count(&self) -> Result<u32, CommitmentStoreError> {
        self.store.tree_length(self.number)
    }

    /// The node at `position` in this tree, if present.
    ///
    /// # Errors
    /// Propagates [`CommitmentStoreError`].
    pub fn get(&self, position: u32) -> Result<Option<Node>, CommitmentStoreError> {
        self.store.get(self.number, position)
    }
}
