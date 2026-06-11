//! Merkle tree math over the database's read views: recompute a UTXO tree's
//! root from its stored leaves, validate it against a trusted source, and
//! keep an O(depth) frontier snapshot so the common root query is one read.
//!
//! The database persists leaves only (keyed by `(tree, position)`); it does no
//! hashing. Those leaves arrive from a secondary indexer rather than the chain,
//! so recomputing the root is how we check that the leaves we stored actually
//! reconstruct the tree the contract committed to — and, along the way, that
//! our codec + storage round-trip is sound.
//!
//! The walk-up is exposed as [`MerkleWalk`], implemented for **every**
//! [`database::Reader`] (snapshot views, write transactions, overlay batches)
//! — the same shape as [`crate::NodeDecrypt`] on a node. The behaviour lives
//! here in `crypto` (the home of Poseidon) while `database` stays storage-only.
//!
//! Two paths to a root:
//! - **Fast**: a persisted [`MerkleAccumulatorState`] (written by the syncer's
//!   commit transaction) whose `next_index` matches the tree length is the
//!   root, one read, zero hashing.
//! - **Full**: stream the tree's leaf hashes — **one range scan** — through a
//!   frontier [`MerkleAccumulator`] (O(depth) memory), zero-filling gaps.
//!   [`MerkleWalk::validate`] always takes this path: recomputation is the
//!   point of an integrity check.

use std::fmt::Debug;

use database::{Commitments, DatabaseError, Frontier, Reader};
use types::{U256, uint};

use crate::PoseidonInput;

/// RAILGUN UTXO Merkle tree depth: `2^16 = 65_536` leaves per tree.
const RAILGUN_TREE_DEPTH: usize = 16;

/// The empty-leaf value, `keccak256("Railgun") % SNARK_SCALAR_FIELD`
/// (hex `0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc`). Hard-coded
/// as the protocol constant it is; `railgun_zero_matches_engine_vector` guards the value.
const RAILGUN_MERKLE_ZERO: U256 =
    uint!(2051258411002736885948763699317990061539314419500486054347250703186609807356_U256);

/// A computed Merkle tree root. Serializes as bare 64-digit hex (the
/// kohaku/POI-node wire format).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MerkleRoot(#[serde(with = "crate::merkle_proof::u256_hex")] U256);

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
///
/// The frontier is exactly what [`state`](Self::state) persists: resume from a
/// snapshot with [`from_state`](Self::from_state) and keep appending.
#[derive(Debug, Clone)]
pub struct MerkleAccumulator<C: MerkleConfig> {
    zeros: Vec<U256>,           // alloc-ok: fixed-depth (DEPTH+1) zero-subtree cache.
    filled_subtrees: Vec<U256>, // alloc-ok: fixed-depth (DEPTH) frontier of pending left children.
    next_index: u64,
    root: U256,
    marker: std::marker::PhantomData<C>,
}

/// A serializable [`MerkleAccumulator`] frontier — everything needed to resume
/// appending (the zero cache is rederived from the config). This is the record
/// the syncer persists per tree so root queries skip the full walk.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleAccumulatorState {
    // alloc-ok: fixed-depth frontier snapshot DTO.
    pub filled_subtrees: Vec<U256>,
    pub next_index: u64,
    pub root: U256,
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

    /// The persistable frontier snapshot of this accumulator.
    #[must_use]
    pub fn state(&self) -> MerkleAccumulatorState {
        MerkleAccumulatorState {
            filled_subtrees: self.filled_subtrees.clone(), // alloc-ok: fixed-depth snapshot DTO.
            next_index: self.next_index,
            root: self.root,
        }
    }

    /// Resumes an accumulator from a persisted snapshot.
    ///
    /// # Errors
    /// [`MerkleError::MalformedFrontier`] if the snapshot's frontier depth
    /// does not match this config.
    pub fn from_state(state: MerkleAccumulatorState) -> Result<Self, MerkleError> {
        if state.filled_subtrees.len() != C::DEPTH {
            return Err(MerkleError::MalformedFrontier {
                expected_depth: C::DEPTH,
                found_depth: state.filled_subtrees.len(),
            });
        }
        Ok(Self {
            zeros: zero_value_levels::<C>(),
            filled_subtrees: state.filled_subtrees,
            next_index: state.next_index,
            root: state.root,
            marker: std::marker::PhantomData,
        })
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

/// Error from a Merkle walk over the database.
#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error("tree {tree} has {count} leaves, exceeding capacity {capacity}")]
    TreeOverfull {
        tree: u32,
        count: u32,
        capacity: u32,
    },
    #[error("frontier snapshot could not be decoded: {0}")]
    FrontierCodec(String),
    #[error("frontier snapshot depth {found_depth} does not match config depth {expected_depth}")]
    MalformedFrontier {
        expected_depth: usize,
        found_depth: usize,
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

/// The Merkle walk, available on every database read context
/// (`use crypto::MerkleWalk;` then `view.merkle_root(tree)`).
pub trait MerkleWalk {
    /// This tree's root: the persisted frontier snapshot when it is current
    /// (one read), else a full recomputation from the stored leaves (one
    /// range scan), filling any missing position with the zero value.
    ///
    /// # Errors
    /// Propagates [`MerkleError`].
    fn merkle_root(&self, tree: u32) -> Result<MerkleRoot, MerkleError>;

    /// Recomputes the root from scratch (never the snapshot — recomputation
    /// is the point of an integrity check), checks it with `validator`, and
    /// reports any gaps.
    ///
    /// # Errors
    /// Propagates [`MerkleError`].
    fn validate<V: MerklerootValidator>(
        &self,
        tree: u32,
        validator: &V,
    ) -> Result<TreeIntegrity, MerkleError>;
}

impl<R: Reader> MerkleWalk for R {
    fn merkle_root(&self, tree: u32) -> Result<MerkleRoot, MerkleError> {
        let leaf_count = Commitments::new(self).tree_length(tree)?;

        // Fast path: a current frontier snapshot is the root.
        if let Some(bytes) = Frontier::new(self).snapshot(tree)? {
            let state: MerkleAccumulatorState = serde_json::from_slice(&bytes)
                .map_err(|error| MerkleError::FrontierCodec(error.to_string()))?;
            if state.next_index == u64::from(leaf_count) {
                return Ok(MerkleRoot::new(state.root));
            }
            // Stale snapshot (e.g. a backfill landed): fall through to the
            // full walk rather than ever returning a wrong root.
        }

        Ok(walk_up(self, tree)?.0)
    }

    fn validate<V: MerklerootValidator>(
        &self,
        tree: u32,
        validator: &V,
    ) -> Result<TreeIntegrity, MerkleError> {
        let (root, leaf_count, missing) = walk_up(self, tree)?;
        let last_leaf_index = leaf_count.saturating_sub(1);
        let valid = validator.is_valid(tree, last_leaf_index, root);
        Ok(TreeIntegrity {
            tree,
            leaf_count,
            root,
            missing,
            valid,
        })
    }
}

/// Streams every leaf in `0..leaf_count` — **one range scan, one engine
/// transaction** — into a frontier accumulator (O(depth) memory). Returns
/// `(root, leaf_count, missing)`.
fn walk_up<R: Reader>(reader: &R, tree: u32) -> Result<(MerkleRoot, u32, u32), MerkleError> {
    let (accumulator, leaf_count, missing) = tree_frontier(reader, tree)?;
    Ok((accumulator.root(), leaf_count, missing))
}

/// Folds every stored leaf of `tree` into a fresh frontier accumulator — one
/// range scan, O(depth) memory. The scan yields stored positions, so interior
/// gaps are detected against the expected index and zero-filled (and counted).
///
/// Returns `(accumulator, leaf_count, missing)`. This is both the full-walk
/// root path and the syncer's rebuild-on-backfill: the returned accumulator's
/// [`state`](MerkleAccumulator::state) is what gets persisted as the frontier
/// snapshot.
///
/// # Errors
/// Propagates [`MerkleError`].
pub fn tree_frontier<R: Reader>(
    reader: &R,
    tree: u32,
) -> Result<(MerkleAccumulator<RailgunMerkleConfig>, u32, u32), MerkleError> {
    let commitments = Commitments::new(reader);
    let leaf_count = commitments.tree_length(tree)?;
    let capacity = 1u32 << RailgunMerkleConfig::DEPTH;
    if leaf_count > capacity {
        return Err(MerkleError::TreeOverfull {
            tree,
            count: leaf_count,
            capacity,
        });
    }

    let mut accumulator = MerkleAccumulator::<RailgunMerkleConfig>::new();
    let mut missing = 0u32;
    let mut expected = 0u32;
    for entry in commitments.leaf_hashes(tree)? {
        let (position, hash) = entry?;
        // Zero-fill the gap up to this stored position.
        while expected < position {
            accumulator.insert(RailgunMerkleConfig::zero());
            missing += 1;
            expected += 1;
        }
        accumulator.insert(hash.as_u256());
        expected += 1;
    }
    // Trailing gap: positions past the last stored leaf but within the
    // recorded length (cannot happen when length tracks max position, but the
    // walk should not silently trust that invariant).
    while expected < leaf_count {
        accumulator.insert(RailgunMerkleConfig::zero());
        missing += 1;
        expected += 1;
    }

    Ok((accumulator, leaf_count, missing))
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

    #[test]
    fn state_round_trips_and_resumes_appending() {
        let mut original = MerkleAccumulator::<RailgunMerkleConfig>::new();
        for leaf in 1..=5u64 {
            original.insert(U256::from(leaf));
        }

        let json = serde_json::to_vec(&original.state()).unwrap();
        let state: MerkleAccumulatorState = serde_json::from_slice(&json).unwrap();
        let mut resumed = MerkleAccumulator::<RailgunMerkleConfig>::from_state(state).unwrap();
        assert_eq!(resumed.root(), original.root());
        assert_eq!(resumed.len(), 5);

        // Appending to the resumed accumulator matches appending straight through.
        for leaf in 6..=10u64 {
            original.insert(U256::from(leaf));
            resumed.insert(U256::from(leaf));
        }
        assert_eq!(resumed.root(), original.root());
        assert_eq!(
            resumed.root().as_u256().to_string(),
            "13360826432759445967430837006844965422592495092152969583910134058984357610665"
        );
    }

    #[test]
    fn from_state_rejects_wrong_depth() {
        let state = MerkleAccumulatorState {
            filled_subtrees: vec![U256::ZERO; 3],
            next_index: 0,
            root: U256::ZERO,
        };
        assert!(matches!(
            MerkleAccumulator::<RailgunMerkleConfig>::from_state(state),
            Err(MerkleError::MalformedFrontier {
                expected_depth: 16,
                found_depth: 3
            })
        ));
    }
}
