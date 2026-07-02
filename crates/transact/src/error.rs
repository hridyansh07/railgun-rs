use railgun_prover::ProverError;

/// Failure assembling or proving a transact circuit witness.
#[derive(Debug, thiserror::Error)]
pub enum TransactInputsError {
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error("a transact needs at least one input and one output")]
    Empty,
    #[error("input merkle proofs disagree on the tree root")]
    InconsistentRoot,
    #[error("input note asset does not match the transact asset")]
    AssetMismatch,
    #[error("merkle proof has {got} siblings, expected {expected}")]
    ProofShape { got: usize, expected: usize },
    #[error(
        "transact has too many notes: {inputs} inputs + {outputs} outputs exceed the circuit/poseidon limit"
    )]
    TooManyNotes { inputs: usize, outputs: usize },
    #[error("output note ciphertext is not 3 x 32-byte GCM blocks")]
    MalformedCiphertext,
    #[error("witness serialization failed: {0}")]
    Witness(#[from] serde_json::Error),
    #[error(transparent)]
    Prover(#[from] ProverError),
}
