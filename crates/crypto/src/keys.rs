use ark_ff::PrimeField;
use types::{BabyJubJubPoint, SpendingKey};

pub trait SpendingKeyPublicKey {
    fn public_key(&self) -> BabyJubJubPoint;
}

impl SpendingKeyPublicKey for SpendingKey {
    fn public_key(&self) -> BabyJubJubPoint {
        let public = crate::babyjubjub::PrivateKey::new(*self.as_bytes()).public();
        BabyJubJubPoint::new(public.x.into_bigint().into(), public.y.into_bigint().into())
    }
}

#[cfg(test)]
mod tests {
    use types::uint;

    use super::*;

    #[test]
    fn derives_babyjubjub_public_key() {
        let key = SpendingKey::from_bytes([1u8; 32]);
        let public = key.public_key();

        assert_eq!(
            public.x(),
            uint!(
                15944627324083773346390189001500210680939402028015651549526524193195473201952_U256
            )
        );
        assert_eq!(
            public.y(),
            uint!(
                17251889856797524237981285661279357764562574766148660962999867467495459148286_U256
            )
        );
    }
}
