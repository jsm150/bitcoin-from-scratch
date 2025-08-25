use derive_more::Deref;
use rand::Rng;
use ruint::aliases::U256;

use crate::encrypt::key::secret_address::SecretAddress;

use super::{Fp, N};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Deref)]
pub struct SecretKey(Fp<N>);

impl SecretKey {
    pub fn random() -> Self {
        let random: U256 = rand::thread_rng().r#gen();
        let fp = Fp::new(random);
        SecretKey(fp)
    }

    pub fn new(fp: Fp<N>) -> Self {
        Self(fp)
    }
}

impl From<SecretAddress> for SecretKey {
    fn from(wif: SecretAddress) -> Self {
        let decoded = bs58::decode(wif.as_ref())
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_vec()
            .unwrap();

        Self::new(Fp::new(U256::from_be_slice(&decoded[1..33])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruint::aliases::U256;
    use crate::encrypt::{PublicAddress, key::public_key_lib::PublicKeySerialize};

    #[test]
    fn test_from_secret_address_mainnet_uncompressed() {
        // 알려진 테스트 벡터를 사용하여 테스트
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::MainNet("test".to_string());
        let sec_type = PublicKeySerialize::Uncompress([0x04u8; 65]);
        
        let secret_address = SecretAddress::build(&secret_key, &public_address, &sec_type);
        let recovered_secret_key = SecretKey::from(secret_address);
        
        assert_eq!(secret_key, recovered_secret_key);
    }

    #[test]
    fn test_from_secret_address_mainnet_compressed() {
        // 압축된 공개키 형태의 WIF 테스트
        let secret_key = SecretKey::new(Fp::new(U256::from(123456789u64)));
        let public_address = PublicAddress::MainNet("test".to_string());
        let sec_type = PublicKeySerialize::Compress([0x02u8; 33]);
        
        let secret_address = SecretAddress::build(&secret_key, &public_address, &sec_type);
        let recovered_secret_key = SecretKey::from(secret_address);
        
        assert_eq!(secret_key, recovered_secret_key);
    }
}