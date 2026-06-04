use crate::U256;
use crate::macros::fixed_bytes_domain_type;

fixed_bytes_domain_type!(SpendingKey, 32);
fixed_bytes_domain_type!(ViewingKey, 32);
fixed_bytes_domain_type!(SharedKey, 32);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RailgunTypeError;

    #[test]
    fn point_exposes_named_coordinates() {
        let x = U256::from(1u8);
        let y = U256::from(2u8);
        let point = BabyJubJubPoint::new(x, y);

        assert_eq!(point.x(), x);
        assert_eq!(point.y(), y);
    }

    #[test]
    fn keys_expose_only_named_byte_access() {
        let bytes = [7u8; 32];

        assert_eq!(SpendingKey::from_bytes(bytes).as_bytes(), &bytes);
        assert_eq!(ViewingKey::from_bytes(bytes).as_bytes(), &bytes);
        assert_eq!(SharedKey::from_bytes(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn keys_validate_slice_length() {
        assert_eq!(
            SpendingKey::try_from_slice(&[1u8; 31]).unwrap_err(),
            RailgunTypeError::InvalidLength {
                expected: 32,
                actual: 31
            }
        );

        let bytes = [3u8; 32];
        assert_eq!(
            ViewingKey::try_from_slice(&bytes).unwrap().as_bytes(),
            &bytes
        );
    }
}
