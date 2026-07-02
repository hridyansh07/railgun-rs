use ark_bn254::Fr;
use ark_ff::PrimeField;
use types::{BabyJubJubPoint, FieldScalar, PoseidonHash, U256, ViewingKey};

use crate::CryptoError;

/// Maximum number of field elements a single Poseidon hash can absorb. The vendored
/// `poseidon-rust` ships constants for widths `t2..=t14`, so the arity (inputs + 1
/// capacity element) caps at 14 — i.e. 13 inputs.
pub const MAX_POSEIDON_INPUTS: usize = 13;

/// A value that can be hashed with Poseidon by contributing its field elements.
///
/// Domain types implement this so upper layers never hand-build raw field-element
/// slices — they call [`PoseidonInput::poseidon_hash`] directly, e.g.
/// `(spend_pub, nullifying_key).poseidon_hash()`.
pub trait PoseidonInput {
    /// Appends this value's field elements (big-endian `U256`) to `buffer`.
    fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>);

    /// Hashes this value with Poseidon.
    ///
    /// # Errors
    /// Returns [`CryptoError::Poseidon`] if the value expands to more than
    /// `MAX_POSEIDON_INPUTS` (13) field elements.
    fn poseidon_hash(&self) -> Result<PoseidonHash, CryptoError> {
        let mut buffer = Vec::new(); // alloc-ok: bounded by Poseidon arity (<= MAX_POSEIDON_INPUTS); fixed-capacity buffer is a deferred optimization
        self.append_poseidon_inputs(&mut buffer);
        hash_field_inputs(&buffer)
    }
}

/// Poseidon over `values` padded with `fill` to a fixed `WIDTH` (entries
/// beyond `WIDTH` are ignored). Circuit-shaped hashing — e.g. the railgun
/// txid pads its nullifier/commitment lists to the 13-wide circuit arity with
/// the merkle zero — lives here so padding policy and hashing stay one step.
///
/// # Errors
/// Returns [`CryptoError::Poseidon`] if `WIDTH` exceeds the Poseidon arity (13).
pub fn poseidon_hash_padded<const WIDTH: usize>(
    values: &[U256],
    fill: U256,
) -> Result<U256, CryptoError> {
    let mut padded = [fill; WIDTH];
    for (slot, value) in padded.iter_mut().zip(values.iter()) {
        *slot = *value;
    }
    Ok(padded.poseidon_hash()?.as_u256())
}

/// Drives the vendored `poseidon-rust` engine over a collected input buffer.
fn hash_field_inputs(inputs: &[U256]) -> Result<PoseidonHash, CryptoError> {
    if inputs.len() > MAX_POSEIDON_INPUTS {
        return Err(poseidon_rust::error::Error::UnsupportedInputLength(inputs.len() + 1).into());
    }

    let mut field_inputs = [Fr::from(0u64); MAX_POSEIDON_INPUTS];
    for (slot, input) in field_inputs.iter_mut().zip(inputs.iter()) {
        *slot = Fr::from_be_bytes_mod_order(&input.to_be_bytes::<32>());
    }

    let hash = poseidon_rust::poseidon_hash(&field_inputs[..inputs.len()])?;
    Ok(PoseidonHash::new(hash.into_bigint().into()))
}

impl PoseidonInput for U256 {
    fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>) {
        buffer.push(*self);
    }
}

impl PoseidonInput for FieldScalar {
    fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>) {
        buffer.push(self.as_u256());
    }
}

impl PoseidonInput for PoseidonHash {
    fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>) {
        buffer.push(self.as_u256());
    }
}

impl PoseidonInput for ViewingKey {
    fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>) {
        buffer.push(U256::from_be_bytes(*self.expose_secret()));
    }
}

impl PoseidonInput for BabyJubJubPoint {
    fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>) {
        buffer.push(self.x());
        buffer.push(self.y());
    }
}

impl<T: PoseidonInput + ?Sized> PoseidonInput for &T {
    fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>) {
        (**self).append_poseidon_inputs(buffer);
    }
}

impl<T: PoseidonInput> PoseidonInput for [T] {
    fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>) {
        for item in self {
            item.append_poseidon_inputs(buffer);
        }
    }
}

impl<T: PoseidonInput, const N: usize> PoseidonInput for [T; N] {
    fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>) {
        self.as_slice().append_poseidon_inputs(buffer);
    }
}

/// Implements [`PoseidonInput`] for tuples so several values hash together as one
/// input sequence: `(a, b, c).poseidon_hash()`.
macro_rules! tuple_poseidon_input {
    ($($name:ident),+) => {
        impl<$($name: PoseidonInput),+> PoseidonInput for ($($name,)+) {
            fn append_poseidon_inputs(&self, buffer: &mut Vec<U256>) {
                #[allow(non_snake_case)]
                let ($($name,)+) = self;
                $($name.append_poseidon_inputs(buffer);)+
            }
        }
    };
}

tuple_poseidon_input!(A, B);
tuple_poseidon_input!(A, B, C);
tuple_poseidon_input!(A, B, C, D);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_poseidon_vector() {
        let hash = U256::from(0u8).poseidon_hash().unwrap();
        assert_eq!(
            hash.as_u256().to_string(),
            "19014214495641488759237505126948346942972912379615652741039992445865937985820"
        );
    }

    #[test]
    fn tuple_and_slice_inputs_match_a_flat_slice() {
        let a = U256::from(1u8);
        let b = U256::from(2u8);
        let c = U256::from(3u8);

        let via_tuple = (a, b, c).poseidon_hash().unwrap();
        let via_array = [a, b, c].poseidon_hash().unwrap();

        assert_eq!(via_tuple, via_array);
    }
}
