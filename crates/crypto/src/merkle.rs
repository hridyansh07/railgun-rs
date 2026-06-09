//! Merkle tree walk-up: recompute a UTXO tree's root from its stored leaves and
//! validate that root against a trusted source.
//!
//! `commitments` persists leaves only (keyed by `(tree, position)`); it does no
//! hashing. Those leaves arrive from a secondary indexer rather than the chain, so
//! recomputing the root is how we check that the leaves we stored actually
//! reconstruct the tree the contract committed to — and, along the way, that our
//! codec + storage round-trip is sound.
//!
//! The walk-up is exposed as [`MerkleWalk`], a trait on [`commitments::Tree`] — the
//! same shape as [`crate::NodeDecrypt`] on a node. The behaviour lives here in
//! `crypto` (the home of Poseidon) while `commitments` stays storage-only.
//!
//! It **streams**: leaves are read in index order straight from the backing store
//! (only each leaf's hash, never the whole node) and folded through a frontier
//! [`MerkleAccumulator`], so memory is O(depth) — a handful of hashes — not O(leaves).
//! This is the same incremental algorithm the on-chain RAILGUN accumulator uses.
//!
//! Validation mirrors the TypeScript engine: compute the root, hand it to a pluggable
//! [`MerklerootValidator`] (the seam a chain/indexer validator plugs into), and report
//! the outcome. Membership proofs need the sibling hashes this stream discards, so they
//! are deferred.

use std::fmt::Debug;

use commitments::{CommitmentStoreError, Tree};
use types::{U256, uint};
use utils::StorageBackend;

use crate::PoseidonInput;

/// RAILGUN UTXO Merkle tree depth: `2^16 = 65_536` leaves per tree.
const RAILGUN_TREE_DEPTH: usize = 16;

/// The empty-leaf value, `keccak256("Railgun") % SNARK_SCALAR_FIELD`
/// (hex `0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc`). Hard-coded
/// as the protocol constant it is; `railgun_zero_matches_engine_vector` guards the value.
const RAILGUN_MERKLE_ZERO: U256 =
    uint!(2051258411002736885948763699317990061539314419500486054347250703186609807356_U256);

/// A computed Merkle tree root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MerkleRoot(U256);

impl MerkleRoot {
    #[must_use]
    pub fn new(value: U256) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn as_u256(self) -> U256 {
        self.0
    }
}

impl From<U256> for MerkleRoot {
    fn from(value: U256) -> Self {
        Self(value)
    }
}

/// Fixed-shape parameters of a Merkle tree: depth, the pairwise hash, and the empty-leaf
/// value. One impl per protocol keeps the walk-up generic.
pub trait MerkleConfig: Debug + Clone + PartialEq + Eq {
    const DEPTH: usize;

    fn hash(left: U256, right: U256) -> U256;
    fn zero() -> U256;
}

/// RAILGUN's UTXO tree: depth 16, `poseidon([left, right])`, and the `keccak256("Railgun")`
/// zero value. Matches the TypeScript engine and the kohaku port bit-for-bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailgunMerkleConfig;

impl MerkleConfig for RailgunMerkleConfig {
    const DEPTH: usize = RAILGUN_TREE_DEPTH;

    fn hash(left: U256, right: U256) -> U256 {
        // Two inputs are always within Poseidon's arity, so this never errors.
        (left, right)
            .poseidon_hash()
            .expect("poseidon over two field elements is within arity")
            .as_u256()
    }

    fn zero() -> U256 {
        RAILGUN_MERKLE_ZERO
    }
}

/// Streaming Merkle root accumulator — the incremental, append-only algorithm the on-chain
/// RAILGUN accumulator uses.
///
/// Leaves are inserted in index order. Between inserts it holds only the per-level
/// **frontier** (`filled_subtrees`: one pending left child per level) plus the
/// zero-subtree cache, so memory is O(depth) regardless of leaf count. After the final
/// insert, [`root`](Self::root) is the root of the depth-`DEPTH` tree with the remaining
/// positions zero-filled. Sibling hashes are discarded as soon as they fold into a parent,
/// so this computes the root but not membership proofs.
#[derive(Debug, Clone)]
pub struct MerkleAccumulator<C: MerkleConfig> {
    zeros: Vec<U256>,           // alloc-ok: fixed-depth (DEPTH+1) zero-subtree cache.
    filled_subtrees: Vec<U256>, // alloc-ok: fixed-depth (DEPTH) frontier of pending left children.
    next_index: u64,
    root: U256,
    marker: std::marker::PhantomData<C>,
}

impl<C: MerkleConfig> MerkleAccumulator<C> {
    #[must_use]
    pub fn new() -> Self {
        let zeros = zero_value_levels::<C>();
        // alloc-ok: fixed-depth frontier, seeded with the per-level empty values.
        let filled_subtrees = zeros[..C::DEPTH].to_vec();
        let root = zeros[C::DEPTH];

        Self {
            zeros,
            filled_subtrees,
            next_index: 0,
            root,
            marker: std::marker::PhantomData,
        }
    }

    /// Appends `leaf` at the next index, folding it up the frontier (O(depth) hashes). The
    /// caller must not insert more than `2^DEPTH` leaves.
    pub fn insert(&mut self, leaf: U256) {
        let mut index = self.next_index;
        let mut current = leaf;

        for level in 0..C::DEPTH {
            if index & 1 == 0 {
                // Left child: cache it; its right sibling is still empty (a zero subtree).
                self.filled_subtrees[level] = current;
                current = C::hash(current, self.zeros[level]);
            } else {
                // Right child: combine with the cached left sibling.
                current = C::hash(self.filled_subtrees[level], current);
            }
            index >>= 1;
        }

        self.root = current;
        self.next_index += 1;
    }

    /// The root of the tree built so far. Before any insert this is the empty-tree root.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        MerkleRoot(self.root)
    }

    /// Number of leaves inserted.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.next_index
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }
}

impl<C: MerkleConfig> Default for MerkleAccumulator<C> {
    fn default() -> Self {
        Self::new()
    }
}

/// The empty-subtree hash at each level: `zeros[0] = C::zero()`, `zeros[i+1] =
/// hash(zeros[i], zeros[i])`. Length `DEPTH + 1` (`zeros[DEPTH]` is the empty-tree root).
fn zero_value_levels<C: MerkleConfig>() -> Vec<U256> {
    // alloc-ok: fixed-depth (DEPTH+1) zero cache built once per accumulator.
    let mut levels = Vec::with_capacity(C::DEPTH + 1);
    let mut current = C::zero();
    for _ in 0..=C::DEPTH {
        levels.push(current);
        current = C::hash(current, current);
    }
    levels
}

/// Error from a Merkle walk-up over the commitment store.
#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    #[error(transparent)]
    Store(#[from] CommitmentStoreError),
    #[error("tree {tree} has {count} leaves, exceeding capacity {capacity}")]
    TreeOverfull {
        tree: u32,
        count: u32,
        capacity: u32,
    },
}

/// Decides whether a recomputed root is the one the protocol actually committed to.
///
/// This is the decoupling seam (mirroring the TypeScript engine's `merklerootValidator`):
/// the walk-up never reaches for the chain itself. A chain- or indexer-backed validator
/// plugs in here; [`ExpectedRoot`] is the trivial constant-root validator.
pub trait MerklerootValidator {
    /// `true` if `root` is the accepted root for `tree` at `last_leaf_index`.
    fn is_valid(&self, tree: u32, last_leaf_index: u32, root: MerkleRoot) -> bool;
}

/// Validates against a single known-good root (e.g. one fetched from chain).
#[derive(Debug, Clone, Copy)]
pub struct ExpectedRoot(pub MerkleRoot);

impl MerklerootValidator for ExpectedRoot {
    fn is_valid(&self, _tree: u32, _last_leaf_index: u32, root: MerkleRoot) -> bool {
        self.0 == root
    }
}

/// Outcome of validating a tree's recomputed root.
#[derive(Debug, Clone, Copy)]
pub struct TreeIntegrity {
    /// Tree number that was walked.
    pub tree: u32,
    /// Leaves considered (`0..leaf_count`).
    pub leaf_count: u32,
    /// The recomputed root.
    pub root: MerkleRoot,
    /// Positions in `0..leaf_count` that had no stored commitment (filled with the zero
    /// value for hashing). A non-zero count means the local tree is not densely filled —
    /// an ingestion/storage gap, independent of whether `root` was accepted.
    pub missing: u32,
    /// Whether the validator accepted `root`.
    pub valid: bool,
}

/// The Merkle walk-up, exposed as a method on a per-tree store view.
pub trait MerkleWalk {
    /// Recomputes this tree's root from its stored leaves (`0..leaf_count`), filling any
    /// missing position with the zero value.
    ///
    /// # Errors
    /// [`MerkleError::Store`] on a backend/codec failure; [`MerkleError::TreeOverfull`] if
    /// the tree holds more leaves than its depth allows.
    fn merkle_root(&self) -> Result<MerkleRoot, MerkleError>;

    /// Recomputes the root and checks it with `validator`, also reporting any gaps.
    ///
    /// # Errors
    /// As [`merkle_root`](MerkleWalk::merkle_root).
    fn validate<V: MerklerootValidator>(&self, validator: &V)
    -> Result<TreeIntegrity, MerkleError>;
}

impl<B: StorageBackend> MerkleWalk for Tree<'_, B> {
    fn merkle_root(&self) -> Result<MerkleRoot, MerkleError> {
        Ok(walk_up(self)?.0)
    }

    fn validate<V: MerklerootValidator>(
        &self,
        validator: &V,
    ) -> Result<TreeIntegrity, MerkleError> {
        let (root, leaf_count, missing) = walk_up(self)?;
        let last_leaf_index = leaf_count.saturating_sub(1);
        let valid = validator.is_valid(self.number(), last_leaf_index, root);
        Ok(TreeIntegrity {
            tree: self.number(),
            leaf_count,
            root,
            missing,
            valid,
        })
    }
}

/// Streams every leaf in `0..leaf_count` by index into a frontier accumulator (O(depth)
/// memory), reading only each leaf's hash — not the whole node. Reading by index (rather
/// than a gap-skipping range read) is what lets an interior gap be detected and counted.
/// Returns `(root, leaf_count, missing)`.
fn walk_up<B: StorageBackend>(tree: &Tree<'_, B>) -> Result<(MerkleRoot, u32, u32), MerkleError> {
    let leaf_count = tree.leaf_count()?;
    let capacity = 1u32 << RailgunMerkleConfig::DEPTH;
    if leaf_count > capacity {
        return Err(MerkleError::TreeOverfull {
            tree: tree.number(),
            count: leaf_count,
            capacity,
        });
    }

    let mut accumulator = MerkleAccumulator::<RailgunMerkleConfig>::new();
    let mut missing = 0u32;
    for position in 0..leaf_count {
        let leaf = if let Some(hash) = tree.leaf_hash(position)? {
            hash.as_u256()
        } else {
            missing += 1;
            RailgunMerkleConfig::zero()
        };
        accumulator.insert(leaf);
    }

    Ok((accumulator.root(), leaf_count, missing))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parity vectors from the TypeScript engine / kohaku `RailgunMerkleConfig` tests.

    #[test]
    fn railgun_zero_matches_engine_vector() {
        assert_eq!(
            RailgunMerkleConfig::zero().to_string(),
            "2051258411002736885948763699317990061539314419500486054347250703186609807356"
        );
    }

    #[test]
    fn empty_accumulator_root_matches_engine_vector() {
        let accumulator = MerkleAccumulator::<RailgunMerkleConfig>::new();
        assert!(accumulator.is_empty());
        assert_eq!(
            accumulator.root().as_u256().to_string(),
            "9493149700940509817378043077993653487291699154667385859234945399563579865744"
        );
    }

    #[test]
    fn root_of_first_ten_leaves_matches_engine_vector() {
        let mut accumulator = MerkleAccumulator::<RailgunMerkleConfig>::new();
        for leaf in 1..=10u64 {
            accumulator.insert(U256::from(leaf));
        }

        assert_eq!(
            accumulator.root().as_u256().to_string(),
            "13360826432759445967430837006844965422592495092152969583910134058984357610665"
        );
        assert_eq!(accumulator.len(), 10);
    }
}
