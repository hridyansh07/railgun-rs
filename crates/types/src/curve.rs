use crate::U256;
use crate::macros::{public_key_type, secret_key_type};

secret_key_type!(SpendingKey, 32);
secret_key_type!(ViewingKey, 32);
secret_key_type!(SharedKey, 32);
public_key_type!(ViewingPublicKey, 32);
public_key_type!(BlindedKey, 32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BabyJubJubPoint {
    x: U256,
    y: U256,
}

impl BabyJubJubPoint {
    pub fn new(x: U256, y: U256) -> Self {
        Self { x, y }
    }

    pub fn x(self) -> U256 {
        self.x
    }

    pub fn y(self) -> U256 {
        self.y
    }
}

/// An EdDSA-Poseidon (`BabyJubJub`) signature over a field-element message.
///
/// This is the spend-authorization signature: the spending key signs the
/// transaction's signed message and the transact circuit verifies it against the
/// spending public key. `r8` is the commitment point `R8` and `s` the scalar, both
/// reduced into the field — the circuit-signal shape the engine uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpendingSignature {
    pub r8_x: U256,
    pub r8_y: U256,
    pub s: U256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TypeError;

    #[test]
    fn point_exposes_named_coordinates() {
        let x = U256::from(1u8);
        let y = U256::from(2u8);
        let point = BabyJubJubPoint::new(x, y);

        assert_eq!(point.x(), x);
        assert_eq!(point.y(), y);
    }

    #[test]
    fn keys_expose_only_gated_byte_access() {
        let bytes = [7u8; 32];

        assert_eq!(SpendingKey::from_bytes(bytes).expose_secret(), &bytes);
        assert_eq!(ViewingKey::from_bytes(bytes).expose_secret(), &bytes);
        assert_eq!(SharedKey::from_bytes(bytes).expose_secret(), &bytes);
    }

    #[test]
    fn keys_validate_slice_length() {
        assert_eq!(
            SpendingKey::try_from_slice(&[1u8; 31]).unwrap_err(),
            TypeError::InvalidLength {
                expected: 32,
                actual: 31
            }
        );

        let bytes = [3u8; 32];
        assert_eq!(
            ViewingKey::try_from_slice(&bytes).unwrap().expose_secret(),
            &bytes
        );
    }

    #[test]
    fn keys_cast_in_from_existing_values() {
        let bytes = [7u8; 32];

        // From<[u8; 32]> and TryFrom<&[u8]> round-trip an existing key value.
        assert_eq!(SpendingKey::from(bytes).expose_secret(), &bytes);
        let key: ViewingKey = bytes.into();
        assert_eq!(key.expose_secret(), &bytes);

        let from_slice: SharedKey = bytes[..].try_into().unwrap();
        assert_eq!(from_slice.expose_secret(), &bytes);

        // A wrong-length slice surfaces the unified TypeError.
        assert_eq!(
            SpendingKey::try_from(&bytes[..31]).unwrap_err(),
            TypeError::InvalidLength {
                expected: 32,
                actual: 31
            }
        );
    }

    #[test]
    fn secret_keys_redact_in_debug_and_display() {
        let key = SpendingKey::from_bytes([7u8; 32]);

        assert_eq!(format!("{key:?}"), "SpendingKey(<redacted>)");
        assert_eq!(format!("{key}"), "SpendingKey(<redacted>)");
        assert!(!format!("{key:?}").contains('7'));

        // The escape hatch still reveals the bytes on explicit request.
        assert_eq!(key.reveal_hex(), format!("0x{}", "07".repeat(32)));
    }

    #[test]
    fn public_keys_render_as_hex() {
        let key = ViewingPublicKey::from_bytes([0x9fu8; 32]);
        let hex = format!("0x{}", "9f".repeat(32));

        assert_eq!(key.to_hex(), hex);
        assert_eq!(format!("{key}"), hex);
        assert_eq!(format!("{key:?}"), format!("ViewingPublicKey({hex})"));
    }
}
