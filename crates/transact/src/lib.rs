//! Transaction building: `boundParamsHash` + transact circuit witness assembly to
//! the [`railgun_prover::CircuitProver`] seam.
//!
//! The outbound mirror of the inbound `poi` crate — same witness →
//! [`TransactCircuitInputs::to_circuit_signals`] → [`TransactCircuitInputs::witness_json`]
//! → [`TransactCircuitInputs::prove`] shape, ported from kohaku's transaction circuit
//! (`circuit/inputs/transact_inputs.rs`). Stops at the prover seam; the Groth16
//! implementation and on-chain calldata/broadcast live elsewhere.

mod bound_params;
mod error;
mod inputs;

pub use bound_params::{UnshieldType, bound_params_hash};
pub use error::TransactInputsError;
pub use inputs::{TransactCircuitInputs, TransactInputNote, TransactOutputNote};
