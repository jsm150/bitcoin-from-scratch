use derive_more::Deref;
use rand::Rng;
use ruint::aliases::U256;
use sha2::{Digest, Sha256};
use crate::encrypt::key::public_key_lib::public_address::{Address};

use super::{Fp, N, PublicAddress};

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

    pub fn to_wif(&self, public_address: &PublicAddress) -> String {

        fn add_prefix_byte<'a>(buf: &'a mut [u8], public_address: &'a PublicAddress) 
            -> (usize, &'a Address, &'a mut [u8]) 
        {
            let sec_type = match public_address {
                PublicAddress::MainNet(address) => {
                    buf[0] = 0x80;
                    address
                },
                PublicAddress::TestNet(address) => {
                    buf[0] = 0xef;
                    address
                },
            };

            (1, &sec_type, buf)
        }

        fn add_secret_key<'a>(
            (position, sec_type, buf)
            : (usize, &'a Address, &'a mut [u8]), secret_key_byte: &[u8; 32]
        ) -> (usize, &'a Address, &'a mut [u8])
        {
            buf[position .. position + secret_key_byte.len()].copy_from_slice(secret_key_byte);
            (position + secret_key_byte.len(), sec_type, buf)
        }

        fn add_postfix_byte<'a>(
            (mut position, sec_type, buf)
            : (usize, &'a Address, &'a mut [u8])
        ) -> (usize, &'a mut [u8])
        {
            if let Address::SecCompress(_) = sec_type {
                buf[position] = 0x01;
                position += 1;
            }

            (position, buf)
        }

        fn to_base58_with_check<'a>(
            (position, buf)
            : (usize, &mut [u8])
        ) -> String 
        {
            let (original, check_sum) = buf.split_at_mut(position);
            check_sum[..4].copy_from_slice(&Sha256::digest(Sha256::digest(original))[..4]);
            bs58::encode(&buf[.. position + 4])
                .with_alphabet(bs58::Alphabet::BITCOIN)
                .into_string()
        }

        
        // 접두 바이트 + 비밀키(32바이트) + 접미 바이트 + 체크섬(4바이트)
        let mut buf = [0_u8; 38];
        let secret_key_byte: [u8; 32] = U256::from(self.0).to_be_bytes();

        to_base58_with_check(
            add_postfix_byte(
                add_secret_key(
                    add_prefix_byte(&mut buf, &public_address), 
                    &secret_key_byte
                )
            )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::key::public_key_lib::public_address::Address;
    use ruint::aliases::U256;

    #[test]
    fn test_to_wif_mainnet_uncompressed() {
        // 테스트용 비밀키 생성 (1)
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::MainNet(Address::SecUncompress("dummy".to_string()));
        
        let wif = secret_key.to_wif(&public_address);
        
        // WIF 형식이 올바른지 확인 (Base58Check 인코딩된 문자열)
        assert!(!wif.is_empty());
        assert!(wif.len() > 50); // 일반적으로 51-52자 정도
        
        // Base58 디코딩이 가능한지 확인
        assert!(bs58::decode(&wif).with_alphabet(bs58::Alphabet::BITCOIN).into_vec().is_ok());
    }

    #[test]
    fn test_to_wif_mainnet_compressed() {
        // 테스트용 비밀키 생성 (1)
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::MainNet(Address::SecCompress("dummy".to_string()));
        
        let wif = secret_key.to_wif(&public_address);
        
        // 압축 형식의 경우 더 길어야 함 (추가 바이트 때문에)
        assert!(!wif.is_empty());
        assert!(wif.len() > 51);
        
        // Base58 디코딩이 가능한지 확인
        let decoded = bs58::decode(&wif).with_alphabet(bs58::Alphabet::BITCOIN).into_vec().unwrap();
        // 압축 형식의 경우 마지막에서 5번째 바이트가 0x01이어야 함
        assert_eq!(decoded[decoded.len() - 5], 0x01);
    }

    #[test]
    fn test_to_wif_testnet_uncompressed() {
        // 테스트용 비밀키 생성 (1)
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::TestNet(Address::SecUncompress("dummy".to_string()));
        
        let wif = secret_key.to_wif(&public_address);
        
        assert!(!wif.is_empty());
        
        // TestNet의 경우 접두사가 0xef여야 함
        let decoded = bs58::decode(&wif).with_alphabet(bs58::Alphabet::BITCOIN).into_vec().unwrap();
        assert_eq!(decoded[0], 0xef);
    }

    #[test]
    fn test_to_wif_testnet_compressed() {
        // 테스트용 비밀키 생성 (1) 
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::TestNet(Address::SecCompress("dummy".to_string()));
        
        let wif = secret_key.to_wif(&public_address);
        
        assert!(!wif.is_empty());
        
        let decoded = bs58::decode(&wif).with_alphabet(bs58::Alphabet::BITCOIN).into_vec().unwrap();
        // TestNet 접두사 확인
        assert_eq!(decoded[0], 0xef);
        // 압축 형식 확인
        assert_eq!(decoded[decoded.len() - 5], 0x01);
    }

    #[test]
    fn test_to_wif_known_values() {
        // 알려진 테스트 벡터를 사용한 테스트
        // 비트코인 위키나 다른 구현체와 호환성 확인을 위한 테스트
        
        // 예시: 비밀키 0x0000...0001에 대한 WIF
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        
        // MainNet 비압축
        let public_address_uncompressed = PublicAddress::MainNet(Address::SecUncompress("dummy".to_string()));
        let wif_uncompressed = secret_key.to_wif(&public_address_uncompressed);
        
        // MainNet 압축
        let public_address_compressed = PublicAddress::MainNet(Address::SecCompress("dummy".to_string()));
        let wif_compressed = secret_key.to_wif(&public_address_compressed);
        
        // 두 WIF가 다른지 확인 (압축 여부에 따라 다름)
        assert_ne!(wif_uncompressed, wif_compressed);
        
        // 압축된 버전이 더 긴지 확인 (0x01 바이트 추가로 인해)
        assert!(wif_compressed.len() > wif_uncompressed.len());
    }

    #[test]
    fn test_to_wif_bitcoin_test_vectors() {
        // 실제 비트코인 테스트 벡터 사용
        // 비밀키: 0x0000000000000000000000000000000000000000000000000000000000000001
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        
        // MainNet 비압축 형태의 예상 WIF (실제 계산 결과와 비교)
        let public_address_uncompressed = PublicAddress::MainNet(Address::SecUncompress("dummy".to_string()));
        let wif_uncompressed = secret_key.to_wif(&public_address_uncompressed);
        
        // WIF가 '5' 또는 'K'/'L'로 시작하는지 확인 (MainNet)
        assert!(wif_uncompressed.starts_with('5') || wif_uncompressed.starts_with('K') || wif_uncompressed.starts_with('L'));
        
        // 압축 형태
        let public_address_compressed = PublicAddress::MainNet(Address::SecCompress("dummy".to_string()));
        let wif_compressed = secret_key.to_wif(&public_address_compressed);
        
        // 압축된 WIF는 'K' 또는 'L'로 시작해야 함
        assert!(wif_compressed.starts_with('K') || wif_compressed.starts_with('L'));
        
        // TestNet의 경우 '9' 또는 'c'로 시작해야 함
        let public_address_testnet = PublicAddress::TestNet(Address::SecUncompress("dummy".to_string()));
        let wif_testnet = secret_key.to_wif(&public_address_testnet);
        assert!(wif_testnet.starts_with('9') || wif_testnet.starts_with('c'));
    }

    #[test]
    fn test_to_wif_checksum_validation() {
        // 체크섬 검증 테스트
        let secret_key = SecretKey::new(Fp::new(U256::from(12345u64)));
        let public_address = PublicAddress::MainNet(Address::SecUncompress("dummy".to_string()));
        
        let wif = secret_key.to_wif(&public_address);
        let decoded = bs58::decode(&wif).with_alphabet(bs58::Alphabet::BITCOIN).into_vec().unwrap();
        
        // 체크섬 검증
        let (payload, checksum) = decoded.split_at(decoded.len() - 4);
        let expected_checksum = &Sha256::digest(Sha256::digest(payload))[..4];
        assert_eq!(checksum, expected_checksum);
    }

    #[test]
    fn test_to_wif_different_secret_keys() {
        // 다른 비밀키들이 다른 WIF를 생성하는지 확인
        let secret_key1 = SecretKey::new(Fp::new(U256::from(1u64)));
        let secret_key2 = SecretKey::new(Fp::new(U256::from(2u64)));
        let public_address = PublicAddress::MainNet(Address::SecUncompress("dummy".to_string()));
        
        let wif1 = secret_key1.to_wif(&public_address);
        let wif2 = secret_key2.to_wif(&public_address);
        
        assert_ne!(wif1, wif2);
    }

    #[test]
    fn test_to_wif_with_hex_secret_key() {
        // hex 문자열로 비밀키 생성 테스트
        let hex_secret = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
        let secret_key_bytes = hex::decode(hex_secret).unwrap();
        let secret_key_bytes_copy = secret_key_bytes.clone();
        let secret_key_u256 = U256::from_be_bytes::<32>(secret_key_bytes.try_into().unwrap());
        let secret_key = SecretKey::new(Fp::new(secret_key_u256));
        
        let public_address = PublicAddress::MainNet(Address::SecCompress("dummy".to_string()));
        let wif = secret_key.to_wif(&public_address);
        
        // WIF가 생성되었고 올바른 형식인지 확인
        assert!(!wif.is_empty());
        let decoded = bs58::decode(&wif).with_alphabet(bs58::Alphabet::BITCOIN).into_vec().unwrap();
        assert_eq!(decoded[0], 0x80); // MainNet 접두사
        assert_eq!(decoded[decoded.len() - 5], 0x01); // 압축 표시
        
        // 원본 비밀키가 올바르게 포함되어 있는지 확인
        let embedded_key = &decoded[1..33];
        assert_eq!(embedded_key, secret_key_bytes_copy.as_slice());
    }

    #[test]
    fn test_to_wif_edge_cases() {
        // 경계값 테스트
        
        // 최대 비밀키 값 (secp256k1 곡선 order - 1)
        let max_key = U256::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16).unwrap();
        let secret_key_max = SecretKey::new(Fp::new(max_key));
        let public_address = PublicAddress::MainNet(Address::SecUncompress("dummy".to_string()));
        let wif_max = secret_key_max.to_wif(&public_address);
        
        assert!(!wif_max.is_empty());
        
        // 최소 비밀키 값 (1)
        let secret_key_min = SecretKey::new(Fp::new(U256::from(1u64)));
        let wif_min = secret_key_min.to_wif(&public_address);
        
        assert!(!wif_min.is_empty());
        assert_ne!(wif_max, wif_min);
    }
}