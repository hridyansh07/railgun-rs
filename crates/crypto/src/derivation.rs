use hmac::{Hmac, Mac};
use sha2::Sha512;
use types::{
    BabyJubJubPoint, DerivationPath, PoseidonHash, RailgunAccountIndex, SpendingKey, U256,
    ViewingKey,
};

use crate::{CryptoError, PoseidonInput, RailgunMnemonic, SpendingKeyPublicKey};

type HmacSha512 = Hmac<Sha512>;

const CURVE_SEED: &[u8] = b"babyjubjub seed";
const HARDENED_OFFSET: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyNode {
    chain_key: [u8; 32],
    chain_code: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedRailgunKeys {
    pub spending_key: SpendingKey,
    pub viewing_key: ViewingKey,
    pub spending_public_key: BabyJubJubPoint,
    pub nullifying_key: PoseidonHash,
    pub master_public_key: PoseidonHash,
}

impl KeyNode {
    pub fn from_seed(seed: &[u8]) -> Self {
        let digest = hmac_sha512(CURVE_SEED, seed);
        Self::from_digest(digest)
    }

    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, CryptoError> {
        if seed_hex.len() != 128 {
            return Err(CryptoError::InvalidSeedHex);
        }

        let mut seed = [0u8; 64];
        hex::decode_to_slice(seed_hex, &mut seed)?;
        Ok(Self::from_seed(&seed))
    }

    pub fn chain_key(self) -> [u8; 32] {
        self.chain_key
    }

    pub fn chain_code(self) -> [u8; 32] {
        self.chain_code
    }

    pub fn derive_hardened(self, index: u32) -> Self {
        let index = index.wrapping_add(HARDENED_OFFSET).to_be_bytes();
        let mut preimage = [0u8; 37];
        preimage[1..33].copy_from_slice(&self.chain_key);
        preimage[33..].copy_from_slice(&index);

        let digest = hmac_sha512(&self.chain_code, &preimage);
        Self::from_digest(digest)
    }

    pub fn derive_path(self, path: &DerivationPath) -> Self {
        let mut node = self;
        for segment in path.segments() {
            node = node.derive_hardened(*segment);
        }
        node
    }

    pub fn spending_key(self) -> SpendingKey {
        SpendingKey::from_bytes(self.chain_key)
    }

    pub fn viewing_key(self) -> ViewingKey {
        ViewingKey::from_bytes(self.chain_key)
    }

    pub fn derive_railgun_keys(
        mnemonic: &RailgunMnemonic,
        index: RailgunAccountIndex,
    ) -> Result<DerivedRailgunKeys, CryptoError> {
        let seed = mnemonic.to_seed("");
        let master = Self::from_seed(&seed);
        let spending_node = master.derive_path(&index.spending_path());
        let viewing_node = master.derive_path(&index.viewing_path());

        let spending_key = spending_node.spending_key();
        let viewing_key = viewing_node.viewing_key();
        let spending_public_key = spending_key.public_key();
        let nullifying_key = U256::from_be_bytes(*viewing_key.as_bytes()).poseidon_hash()?;
        let master_public_key = (spending_public_key, nullifying_key).poseidon_hash()?;

        Ok(DerivedRailgunKeys {
            spending_key,
            viewing_key,
            spending_public_key,
            nullifying_key,
            master_public_key,
        })
    }

    fn from_digest(digest: [u8; 64]) -> Self {
        let mut chain_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        chain_key.copy_from_slice(&digest[..32]);
        chain_code.copy_from_slice(&digest[32..]);
        Self {
            chain_key,
            chain_code,
        }
    }
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::uint;

    #[test]
    fn derives_master_key_from_ts_engine_vector() {
        let node = KeyNode::from_seed_hex(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .unwrap();

        assert_eq!(
            hex::encode(node.chain_code()),
            "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc"
        );
        assert_eq!(
            hex::encode(node.chain_key()),
            "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411"
        );
    }

    #[test]
    fn derives_child_key_from_ts_engine_vector() {
        let parent = KeyNode {
            chain_code: hex_literal_32(
                "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc",
            ),
            chain_key: hex_literal_32(
                "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411",
            ),
        };

        let child = parent.derive_hardened(0);
        assert_eq!(
            hex::encode(child.chain_code()),
            "e8e6a1bbce8bab145fe8225435dc98d20d53bd32318ce3ede560b8feef3394a5"
        );
        assert_eq!(
            hex::encode(child.chain_key()),
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef"
        );
    }

    // Full RAILGUN account derivation: mnemonic -> spending/viewing nodes at the
    // RAILGUN paths -> spending public key + nullifying key -> master public key.
    // Vector generated by the RAILGUN JS SDK (engine `railgun-wallet` test:
    // mnemonic "test ... junk", account index 0).
    #[test]
    fn derives_full_railgun_account_from_js_sdk_vector() {
        let mnemonic =
            RailgunMnemonic::parse("test test test test test test test test test test test junk")
                .unwrap();

        let keys = KeyNode::derive_railgun_keys(&mnemonic, RailgunAccountIndex::new(0)).unwrap();

        // Spending private key at m/44'/1984'/0'/0'/0'.
        assert_eq!(
            keys.spending_key.as_bytes(),
            &[
                176, 149, 143, 139, 194, 134, 174, 8, 50, 250, 131, 176, 27, 113, 154, 34, 90, 7,
                206, 123, 134, 31, 243, 17, 50, 63, 34, 22, 103, 179, 189, 80,
            ]
        );

        // BabyJubJub spending public key.
        assert_eq!(
            keys.spending_public_key.x(),
            uint!(
                15684838006997671713939066069845237677934334329285343229142447933587909549584_U256
            )
        );
        assert_eq!(
            keys.spending_public_key.y(),
            uint!(
                11878614856120328179849762231924033298788609151532558727282528569229552954628_U256
            )
        );

        // Master public key = poseidon(spend.x, spend.y, nullifying_key) — the
        // wallet identifier. Asserting it transitively validates the nullifying key.
        assert_eq!(
            keys.master_public_key.as_u256(),
            uint!(
                20060431504059690749153982049210720252589378133547582826474262520121417617087_U256
            )
        );
    }

    // Spending public key + nullifying key at an arbitrary path, against the
    // engine `key-derivation` test vectors (abandon mnemonic seed, path m/0').
    #[test]
    fn derives_public_and_nullifying_keys_from_js_sdk_vector() {
        let master = KeyNode::from_seed_hex(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .unwrap();
        let path: DerivationPath = "m/0'".parse().unwrap();
        let node = master.derive_path(&path);

        let spending_public_key = node.spending_key().public_key();
        assert_eq!(
            spending_public_key.x(),
            uint!(
                1700559105542139805112168139351320601853033442476682590258553412078471731431_U256
            )
        );
        assert_eq!(
            spending_public_key.y(),
            uint!(
                20772987336827599306927277921643441679141423747083423413320022373456048866305_U256
            )
        );

        let viewing_key = node.viewing_key();
        let nullifying_key = U256::from_be_bytes(*viewing_key.as_bytes())
            .poseidon_hash()
            .unwrap();
        assert_eq!(
            nullifying_key.as_u256(),
            uint!(
                12835268173099116305231859677177501123414588269721547120001227054861606950622_U256
            )
        );
    }

    fn hex_literal_32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex, &mut out).unwrap();
        out
    }
}
