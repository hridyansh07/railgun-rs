//! Merkle membership proofs: a single leaf's sibling path, built by streaming
//! the leaves once (O(depth) memory), and verification.
//!
//! The wire shape (field names, bare-hex encoding) matches kohaku's
//! `MerkleProof`, which is also the JSON the POI node's `ppoi_merkle_proofs`
//! returns — the same type deserializes node responses.

use serde::{Deserialize, Serialize};
use types::U256;

use crate::merkle::{MerkleConfig, MerkleRoot};

/// A leaf's membership proof: the leaf value, its `DEPTH` sibling hashes from
/// bottom to top, the bit-packed path (the leaf index), and the root it
/// resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof<C: MerkleConfig> {
    #[serde(rename = "leaf", with = "u256_hex")]
    pub element: U256,
    // alloc-ok: fixed DEPTH sibling hashes.
    #[serde(with = "vec_u256_hex")]
    pub elements: Vec<U256>,
    #[serde(with = "u256_hex")]
    pub indices: U256,
    pub root: MerkleRoot,
    #[serde(skip)]
    marker: std::marker::PhantomData<C>,
}

impl<C: MerkleConfig> MerkleProof<C> {
    #[must_use]
    pub fn new(element: U256, elements: Vec<U256>, indices: U256, root: MerkleRoot) -> Self {
        Self {
            element,
            elements,
            indices,
            root,
            marker: std::marker::PhantomData,
        }
    }

    /// Recomputes the root from the leaf and sibling path and compares it to
    /// [`Self::root`].
    #[must_use]
    pub fn verify(&self) -> bool {
        let mut index: u64 = self.indices.saturating_to();
        let mut current = self.element;
        for &sibling in &self.elements {
            current = if index & 1 == 0 {
                C::hash(current, sibling)
            } else {
                C::hash(sibling, current)
            };
            index >>= 1;
        }
        MerkleRoot::new(current) == self.root
    }
}

/// Error from [`prove_from_leaves`]. `E` is the leaf source's error type.
#[derive(Debug, thiserror::Error)]
pub enum MerkleProofError<E> {
    #[error("leaf source failed: {0}")]
    Source(#[source] E),
    #[error("target leaf {target} not in streamed range of {leaf_count} leaves")]
    TargetOutOfRange { target: u32, leaf_count: u64 },
    #[error("stream of {leaf_count} leaves exceeds tree capacity {capacity}")]
    Overfull { leaf_count: u64, capacity: u64 },
}

/// Builds the membership proof for leaf `target` by streaming `leaves` (index
/// order, missing positions already zero-filled by the caller) through a
/// frontier fold — O(depth) memory, O(n·depth) hashes.
///
/// During the fold for leaf `j`, the running value at level `L` is the current
/// value of tree node `j >> L`; whenever that node is the target ancestor's
/// sibling (`(target >> L) ^ 1`) the value is recorded, and the last overwrite
/// is the node's final value because leaves arrive in index order. Siblings
/// never touched by the stream keep their empty-subtree value.
///
/// # Errors
/// [`MerkleProofError::Source`] if the iterator yields an error;
/// [`MerkleProofError::TargetOutOfRange`] if `target` is past the streamed
/// leaves; [`MerkleProofError::Overfull`] if more than `2^DEPTH` leaves stream.
pub fn prove_from_leaves<C: MerkleConfig, E>(
    leaves: impl Iterator<Item = Result<U256, E>>,
    target: u32,
) -> Result<MerkleProof<C>, MerkleProofError<E>> {
    let capacity = 1u64 << C::DEPTH;
    let zeros = zero_levels::<C>();

    // alloc-ok: fixed-depth frontier of pending left children.
    let mut filled_subtrees = zeros[..C::DEPTH].to_vec();
    // alloc-ok: fixed-depth sibling path, seeded with empty-subtree values.
    let mut siblings = zeros[..C::DEPTH].to_vec();
    let mut element = None;
    let mut root = zeros[C::DEPTH];
    let mut leaf_count: u64 = 0;

    for (j, leaf) in leaves.enumerate() {
        let leaf = leaf.map_err(MerkleProofError::Source)?;
        let j = j as u64;
        if j >= capacity {
            return Err(MerkleProofError::Overfull {
                leaf_count: j + 1,
                capacity,
            });
        }
        if j == u64::from(target) {
            element = Some(leaf);
        }

        let mut index = j;
        let mut current = leaf;
        for level in 0..C::DEPTH {
            if index == (u64::from(target) >> level) ^ 1 {
                siblings[level] = current;
            }
            if index & 1 == 0 {
                filled_subtrees[level] = current;
                current = C::hash(current, zeros[level]);
            } else {
                current = C::hash(filled_subtrees[level], current);
            }
            index >>= 1;
        }
        root = current;
        leaf_count = j + 1;
    }

    let Some(element) = element else {
        return Err(MerkleProofError::TargetOutOfRange { target, leaf_count });
    };

    Ok(MerkleProof::new(
        element,
        siblings,
        U256::from(target),
        MerkleRoot::new(root),
    ))
}

/// Empty-subtree hash per level; `levels[DEPTH]` is the empty-tree root.
fn zero_levels<C: MerkleConfig>() -> Vec<U256> {
    // alloc-ok: fixed-depth (DEPTH+1) zero cache built once per proof.
    let mut levels = Vec::with_capacity(C::DEPTH + 1);
    let mut current = C::zero();
    for _ in 0..=C::DEPTH {
        levels.push(current);
        current = C::hash(current, current);
    }
    levels
}

/// Bare 64-digit hex serde (kohaku/POI-node wire format; accepts `0x` prefixes).
pub(crate) mod u256_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    use types::U256;

    pub fn serialize<S: Serializer>(value: &U256, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:064x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        U256::from_str_radix(s, 16).map_err(serde::de::Error::custom)
    }
}

pub(crate) mod vec_u256_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use types::U256;

    pub fn serialize<S: Serializer>(values: &[U256], serializer: S) -> Result<S::Ok, S::Error> {
        // alloc-ok: serde DTO boundary.
        let strings: Vec<String> = values.iter().map(|v| format!("{v:064x}")).collect();
        strings.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<U256>, D::Error> {
        let strings = Vec::<String>::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                U256::from_str_radix(s, 16).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use crate::merkle::{MerkleAccumulator, RailgunMerkleConfig};

    use super::*;

    fn leaves(n: u64) -> impl Iterator<Item = Result<U256, Infallible>> {
        (1..=n).map(|v| Ok(U256::from(v)))
    }

    // Same ten leaves as the engine-parity root vector in `merkle.rs`.
    #[test]
    fn proofs_for_all_ten_leaves_verify_against_engine_root() {
        for target in 0..10u32 {
            let proof = prove_from_leaves::<RailgunMerkleConfig, _>(leaves(10), target).unwrap();
            assert_eq!(
                proof.root.as_u256().to_string(),
                "13360826432759445967430837006844965422592495092152969583910134058984357610665",
                "root mismatch for leaf {target}"
            );
            assert_eq!(proof.element, U256::from(target + 1));
            assert_eq!(proof.elements.len(), RailgunMerkleConfig::DEPTH);
            assert!(proof.verify(), "proof for leaf {target} did not verify");
        }
    }

    #[test]
    fn proof_root_matches_accumulator_for_partial_tree() {
        let mut accumulator = MerkleAccumulator::<RailgunMerkleConfig>::new();
        for leaf in 1..=100u64 {
            accumulator.insert(U256::from(leaf));
        }

        let proof = prove_from_leaves::<RailgunMerkleConfig, _>(leaves(100), 57).unwrap();
        assert_eq!(proof.root, accumulator.root());
        assert!(proof.verify());
    }

    #[test]
    fn tampered_proof_fails_verification() {
        let mut proof = prove_from_leaves::<RailgunMerkleConfig, _>(leaves(10), 3).unwrap();
        assert!(proof.verify());
        proof.elements[4] += U256::from(1u8);
        assert!(!proof.verify());
    }

    #[test]
    fn target_past_stream_is_rejected() {
        let err = prove_from_leaves::<RailgunMerkleConfig, _>(leaves(10), 10).unwrap_err();
        assert!(matches!(
            err,
            MerkleProofError::TargetOutOfRange {
                target: 10,
                leaf_count: 10
            }
        ));
    }

    #[test]
    fn serde_round_trips_in_kohaku_wire_shape() {
        let proof = prove_from_leaves::<RailgunMerkleConfig, _>(leaves(10), 3).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"leaf\""));
        assert!(json.contains("\"indices\""));

        let back: MerkleProof<RailgunMerkleConfig> = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, back);
        assert!(back.verify());
    }
}
