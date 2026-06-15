//! Typed prover interfaces.
//!
//! The proof serialization shape is adapted from Kohaku's circuit module. The
//! heavy Groth16 witness/artifact implementation should sit behind
//! `CircuitProver` instead of leaking artifact loading into wallet code.

mod proof;

pub use proof::{G1Affine, G2Affine, Proof};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitKind {
    Transact {
        inputs: u8,
        outputs: u8,
    },
    /// POI circuits ship in two sizes: 3 (mini, ≤3 inputs and ≤3 outputs)
    /// and 13 (full).
    ProofOfInnocence {
        size: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactId {
    pub circuit: CircuitKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProveRequest<'a> {
    pub artifact: ArtifactId,
    pub witness_inputs: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProverError {
    #[error("artifact not found")]
    ArtifactNotFound,
    #[error("witness generation failed: {0}")]
    Witness(String),
    #[error("proof generation failed: {0}")]
    Proof(String),
}

pub trait ArtifactLocator {
    /// Resolves the on-disk artifact paths for `artifact`.
    ///
    /// # Errors
    /// [`ProverError::ArtifactNotFound`] if the artifact is not available.
    fn locate(&self, artifact: ArtifactId) -> Result<ArtifactLocation<'_>, ProverError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactLocation<'a> {
    pub wasm: &'a std::path::Path,
    pub proving_key: &'a std::path::Path,
    pub verification_key: &'a std::path::Path,
}

pub trait CircuitProver {
    /// Generates a Groth16 proof for the request's circuit and witness.
    ///
    /// # Errors
    /// Propagates [`ProverError`] from artifact loading, witness generation,
    /// or proving.
    fn prove(&self, request: ProveRequest<'_>) -> Result<Proof, ProverError>;
}
