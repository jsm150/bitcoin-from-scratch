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

    pub fn from_wif(wif: &String) -> Result<Self, WifDeserializeErr> {
        let original = bs58::decode(wif)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_vec()
            .map_err(|e| WifDeserializeErr::FailDecode(e))?;

        // 접두 바이트(1) + 비밀키(32) 접미 바이트(0 or 1) + 체크섬(4)
        if original.len() < 37 {
            return Err(WifDeserializeErr::WifToSmall);
        }   

        let (data, saved_check_sum) = original.split_at(original.len() - 4);

        let check_sum= &Sha256::digest(Sha256::digest(data))[..4];


        if check_sum != saved_check_sum {
            return Err(
                WifDeserializeErr::InvalidChecksum(
                    hex::encode(check_sum), hex::encode(saved_check_sum)
                )
            );
        }

        Ok(Self::new(Fp::new(U256::from_be_slice(&data[1..33]))))
    }
}

#[derive(Debug)]
pub enum WifDeserializeErr {
    WifToSmall,
    FailDecode(bs58::decode::Error),
    InvalidChecksum(String, String)
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

    // === from_wif 테스트 코드 ===

    #[test]
    fn test_from_wif_round_trip() {
        // WIF 생성 후 다시 파싱해서 원본과 같은지 확인하는 라운드트립 테스트
        let original_secret = SecretKey::new(Fp::new(U256::from(12345u64)));
        
        // MainNet 비압축
        let public_address_uncompressed = PublicAddress::MainNet(Address::SecUncompress("dummy".to_string()));
        let wif_uncompressed = original_secret.to_wif(&public_address_uncompressed);
        let parsed_secret_uncompressed = SecretKey::from_wif(&wif_uncompressed).unwrap();
        assert_eq!(original_secret, parsed_secret_uncompressed);
        
        // MainNet 압축
        let public_address_compressed = PublicAddress::MainNet(Address::SecCompress("dummy".to_string()));
        let wif_compressed = original_secret.to_wif(&public_address_compressed);
        let parsed_secret_compressed = SecretKey::from_wif(&wif_compressed).unwrap();
        assert_eq!(original_secret, parsed_secret_compressed);
        
        // TestNet 비압축
        let public_address_testnet = PublicAddress::TestNet(Address::SecUncompress("dummy".to_string()));
        let wif_testnet = original_secret.to_wif(&public_address_testnet);
        let parsed_secret_testnet = SecretKey::from_wif(&wif_testnet).unwrap();
        assert_eq!(original_secret, parsed_secret_testnet);
        
        // TestNet 압축
        let public_address_testnet_compressed = PublicAddress::TestNet(Address::SecCompress("dummy".to_string()));
        let wif_testnet_compressed = original_secret.to_wif(&public_address_testnet_compressed);
        let parsed_secret_testnet_compressed = SecretKey::from_wif(&wif_testnet_compressed).unwrap();
        assert_eq!(original_secret, parsed_secret_testnet_compressed);
    }

    #[test]
    fn test_from_wif_various_secret_keys() {
        // 다양한 비밀키 값에 대한 라운드트립 테스트
        let test_values = vec![
            1u64,
            255u64,
            65536u64,
            16777216u64,
            u64::MAX,
        ];
        
        for value in test_values {
            let original_secret = SecretKey::new(Fp::new(U256::from(value)));
            let public_address = PublicAddress::MainNet(Address::SecCompress("dummy".to_string()));
            
            let wif = original_secret.to_wif(&public_address);
            let parsed_secret = SecretKey::from_wif(&wif).unwrap();
            
            assert_eq!(original_secret, parsed_secret, "Failed for value: {}", value);
        }
    }

    #[test]
    fn test_from_wif_hex_secret_key() {
        // hex로 된 비밀키에 대한 라운드트립 테스트
        let hex_secret = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
        let secret_key_bytes = hex::decode(hex_secret).unwrap();
        let secret_key_u256 = U256::from_be_bytes::<32>(secret_key_bytes.try_into().unwrap());
        let original_secret = SecretKey::new(Fp::new(secret_key_u256));
        
        let public_address = PublicAddress::MainNet(Address::SecCompress("dummy".to_string()));
        let wif = original_secret.to_wif(&public_address);
        let parsed_secret = SecretKey::from_wif(&wif).unwrap();
        
        assert_eq!(original_secret, parsed_secret);
    }

    #[test]
    fn test_from_wif_error_cases() {
        // 잘못된 WIF 형식에 대한 에러 테스트
        
        // 빈 문자열
        let result = SecretKey::from_wif(&"".to_string());
        assert!(result.is_err());
        
        // 잘못된 Base58 문자열
        let result = SecretKey::from_wif(&"invalid_base58_0OIl".to_string());
        assert!(result.is_err());
        
        // 너무 짧은 WIF
        let result = SecretKey::from_wif(&"5".to_string());
        assert!(result.is_err());
        
        // 올바른 Base58이지만 너무 짧은 데이터
        let short_data = bs58::encode(&[0u8; 10])
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string();
        let result = SecretKey::from_wif(&short_data);
        assert!(matches!(result, Err(WifDeserializeErr::WifToSmall)));
    }

    #[test]
    fn test_from_wif_invalid_checksum() {
        // 잘못된 체크섬을 가진 WIF 테스트
        let original_secret = SecretKey::new(Fp::new(U256::from(12345u64)));
        let public_address = PublicAddress::MainNet(Address::SecUncompress("dummy".to_string()));
        let wif = original_secret.to_wif(&public_address);
        
        // WIF 문자열의 마지막 문자를 변경하여 체크섬을 망침
        let mut chars: Vec<char> = wif.chars().collect();
        let last_char = chars.last_mut().unwrap();
        *last_char = if *last_char == '1' { '2' } else { '1' };
        let corrupted_wif: String = chars.into_iter().collect();
        
        let result = SecretKey::from_wif(&corrupted_wif);
        assert!(matches!(result, Err(WifDeserializeErr::InvalidChecksum(_, _))));
    }

    #[test]
    fn test_from_wif_edge_cases() {
        // 경계값 테스트
        
        // 최소값 (1)
        let min_secret = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::MainNet(Address::SecUncompress("dummy".to_string()));
        let wif_min = min_secret.to_wif(&public_address);
        let parsed_min = SecretKey::from_wif(&wif_min).unwrap();
        assert_eq!(min_secret, parsed_min);
        
        // 큰 값
        let big_value = U256::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16).unwrap();
        let big_secret = SecretKey::new(Fp::new(big_value));
        let wif_big = big_secret.to_wif(&public_address);
        let parsed_big = SecretKey::from_wif(&wif_big).unwrap();
        assert_eq!(big_secret, parsed_big);
    }

    #[test]
    fn test_from_wif_all_network_types() {
        // 모든 네트워크 타입에 대한 테스트
        let original_secret = SecretKey::new(Fp::new(U256::from(54321u64)));
        
        let test_cases = vec![
            PublicAddress::MainNet(Address::SecUncompress("dummy".to_string())),
            PublicAddress::MainNet(Address::SecCompress("dummy".to_string())),
            PublicAddress::TestNet(Address::SecUncompress("dummy".to_string())),
            PublicAddress::TestNet(Address::SecCompress("dummy".to_string())),
        ];
        
        for public_address in test_cases {
            let wif = original_secret.to_wif(&public_address);
            let parsed_secret = SecretKey::from_wif(&wif).unwrap();
            assert_eq!(original_secret, parsed_secret);
        }
    }

    #[test] 
    fn test_from_wif_random_keys() {
        // 랜덤 키에 대한 라운드트립 테스트
        for _ in 0..10 {
            let random_secret = SecretKey::random();
            let public_address = PublicAddress::MainNet(Address::SecCompress("dummy".to_string()));
            
            let wif = random_secret.to_wif(&public_address);
            let parsed_secret = SecretKey::from_wif(&wif).unwrap();
            
            assert_eq!(random_secret, parsed_secret);
        }
    }
}