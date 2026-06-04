use crate::macros::u256_domain_type;

u256_domain_type!(FieldScalar);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::U256;

    #[test]
    fn field_scalar_exposes_only_named_inner_access() {
        let value = U256::from(42u8);
        assert_eq!(FieldScalar::new(value).as_u256(), value);
    }
}
