use ruint::aliases::U256;
use sha2::{Digest, Sha256};

use crate::encrypt::{key::public_key_lib::PublicKeySerialize, PublicAddress, SecretKey};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PublicNet {
    Main,
    Test
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Compress {
    On,
    Off
}

#[derive(Debug, PartialEq, Clone)]
pub struct SecretAddress {
    pub net: PublicNet,
    pub comp: Compress,
    address: String
}

impl AsRef<String> for SecretAddress {
    fn as_ref(&self) -> &String {
        &self.address
    }
}

impl SecretAddress {
    pub fn build(secret_key: &SecretKey, public_address: &PublicAddress, sec: &PublicKeySerialize) -> Self {
        fn add_prefix_byte<'a>(buf: &'a mut [u8], public_address: &'a PublicAddress) 
            -> (usize, &'a mut [u8]) 
        {
            match public_address {
                PublicAddress::MainNet(_) => buf[0] = 0x80,
                PublicAddress::TestNet(_) => buf[0] = 0xef
            }

            (1, buf)
        }

        fn add_secret_key<'a>(
            (position, buf): (usize, &'a mut [u8]), 
            secret_key_byte: &[u8; 32]
        ) -> (usize, &'a mut [u8])
        {
            buf[position .. position + secret_key_byte.len()].copy_from_slice(secret_key_byte);
            (position + secret_key_byte.len(), buf)
        }

        fn add_postfix_byte<'a>(
            (mut position, buf): (usize, &'a mut [u8]),
            sec_type: &PublicKeySerialize
        ) -> (usize, &'a mut [u8])
        {
            if let PublicKeySerialize::Compress(_) = sec_type {
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
        let secret_key_byte: [u8; 32] = U256::from(**secret_key).to_be_bytes();

        let address = to_base58_with_check
        (
            add_postfix_byte(
                add_secret_key(
                    add_prefix_byte(&mut buf, &public_address), 
                    &secret_key_byte
                ),
                &sec
            )
        );


        Self {
            address,
            net: match public_address {
                PublicAddress::MainNet(_) => PublicNet::Main,
                PublicAddress::TestNet(_) => PublicNet::Test,
            },
            comp: match sec {
                PublicKeySerialize::Compress(_) => Compress::On,
                PublicKeySerialize::Uncompress(_) => Compress::Off,
            },
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum WifError {
    InvalidBase58,
    InvalidLength,
    InvalidChecksum,
    InvalidPrefix,
}

impl std::fmt::Display for WifError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WifError::InvalidBase58 => write!(f, "Invalid base58 encoding"),
            WifError::InvalidLength => write!(f, "Invalid WIF length"),
            WifError::InvalidChecksum => write!(f, "Invalid checksum"),
            WifError::InvalidPrefix => write!(f, "Invalid network prefix"),
        }
    }
}

impl std::error::Error for WifError {}

impl TryFrom<String> for SecretAddress {
    type Error = WifError;

    fn try_from(address: String) -> Result<Self, Self::Error> {
        // Base58 디코딩
        let decoded = bs58::decode(&address)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_vec()
            .map_err(|_| WifError::InvalidBase58)?;

        // 길이 검증: 접두사(1) + 비밀키(32) + 선택적 압축 플래그(1) + 체크섬(4))
        if decoded.len() < 37 || decoded.len() > 38 {
            return Err(WifError::InvalidLength);
        }

        let (data, checksum) = decoded.split_at(decoded.len() - 4);
        
        // 체크섬 검증
        let calculated_checksum = &Sha256::digest(Sha256::digest(data))[..4];
        if checksum != calculated_checksum {
            return Err(WifError::InvalidChecksum);
        }

        // 네트워크 접두사 검증
        let prefix = data[0];
        let net =  match prefix {
            0x80 => PublicNet::Main, // 메인넷
            0xef => PublicNet::Test, // 테스트넷
            _ => return Err(WifError::InvalidPrefix),
        };

        // WIF가 유효하면 SecretAddress로 변환
        Ok(Self {
            address,
            net,
            comp: if decoded.len() == 38 {
                Compress::On
            }
            else {
                Compress::Off
            }
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::key::Fp;
    use ruint::aliases::U256;

    #[test]
    fn test_build_and_validate_structure() {
        // 기본적인 SecretAddress 구조 검증
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::MainNet("dummy".to_string());
        let sec = PublicKeySerialize::Compress([0; 33]);

        let secret_address = SecretAddress::build(&secret_key, &public_address, &sec);

        // 구조체 필드 검증
        assert_eq!(secret_address.net, PublicNet::Main);
        assert_eq!(secret_address.comp, Compress::On);
        assert!(!secret_address.as_ref().is_empty());
        
        println!("✓ SecretAddress structure validation passed");
    }

    #[test]
    fn test_build_mainnet_compressed() {
        // 메인넷 압축 WIF 테스트
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::MainNet("dummy".to_string());
        let sec = PublicKeySerialize::Compress([0; 33]);

        let secret_address = SecretAddress::build(&secret_key, &public_address, &sec);
        let wif = secret_address.as_ref();

        // WIF 기본 검증
        assert!(!wif.is_empty());
        assert!(wif.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)));
        
        // 메인넷 압축 키는 'K' 또는 'L'로 시작해야 함
        assert!(wif.starts_with('K') || wif.starts_with('L'), "MainNet compressed WIF should start with K or L, got: {}", wif);
        
        // 구조체 필드 검증
        assert_eq!(secret_address.net, PublicNet::Main);
        assert_eq!(secret_address.comp, Compress::On);
        
        println!("✓ MainNet compressed WIF: {}", wif);
    }

    #[test]
    fn test_build_mainnet_uncompressed() {
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::MainNet("dummy".to_string());
        let sec = PublicKeySerialize::Uncompress([0; 65]);

        let secret_address = SecretAddress::build(&secret_key, &public_address, &sec);
        let wif = secret_address.as_ref();

        // 메인넷 비압축 키는 '5'로 시작해야 함
        assert!(wif.starts_with('5'), "MainNet uncompressed WIF should start with 5, got: {}", wif);
        
        // 구조체 필드 검증
        assert_eq!(secret_address.net, PublicNet::Main);
        assert_eq!(secret_address.comp, Compress::Off);
        
        println!("✓ MainNet uncompressed WIF: {}", wif);
    }

    #[test]
    fn test_build_testnet_compressed() {
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::TestNet("dummy".to_string());
        let sec = PublicKeySerialize::Compress([0; 33]);

        let secret_address = SecretAddress::build(&secret_key, &public_address, &sec);
        let wif = secret_address.as_ref();

        // 테스트넷 압축 키는 'c'로 시작해야 함
        assert!(wif.starts_with('c'), "TestNet compressed WIF should start with c, got: {}", wif);
        
        // 구조체 필드 검증
        assert_eq!(secret_address.net, PublicNet::Test);
        assert_eq!(secret_address.comp, Compress::On);
        
        println!("✓ TestNet compressed WIF: {}", wif);
    }

    #[test]
    fn test_build_testnet_uncompressed() {
        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        let public_address = PublicAddress::TestNet("dummy".to_string());
        let sec = PublicKeySerialize::Uncompress([0; 65]);

        let secret_address = SecretAddress::build(&secret_key, &public_address, &sec);
        let wif = secret_address.as_ref();

        // 테스트넷 비압축 키는 '9'로 시작해야 함
        assert!(wif.starts_with('9'), "TestNet uncompressed WIF should start with 9, got: {}", wif);
        
        // 구조체 필드 검증
        assert_eq!(secret_address.net, PublicNet::Test);
        assert_eq!(secret_address.comp, Compress::Off);
        
        println!("✓ TestNet uncompressed WIF: {}", wif);
    }

    #[test]
    fn test_try_from_valid_wif() {
        // 올바른 WIF에서 SecretAddress 생성 테스트
        let secret_key = SecretKey::new(Fp::new(U256::from(12345u64)));
        let public_address = PublicAddress::MainNet("dummy".to_string());
        let sec = PublicKeySerialize::Compress([0; 33]);

        let original_secret_address = SecretAddress::build(&secret_key, &public_address, &sec);
        let wif_string = original_secret_address.as_ref().clone();

        // String에서 SecretAddress 생성
        let parsed_secret_address = SecretAddress::try_from(wif_string.clone()).unwrap();

        // 원본과 파싱된 것이 같은지 확인
        assert_eq!(parsed_secret_address.net, original_secret_address.net);
        assert_eq!(parsed_secret_address.comp, original_secret_address.comp);
        assert_eq!(parsed_secret_address.as_ref(), original_secret_address.as_ref());

        println!("✓ Valid WIF parsed successfully: {}", wif_string);
    }

    #[test]
    fn test_try_from_invalid_wif() {
        // 잘못된 WIF 테스트
        
        // 잘못된 Base58 (0, O, I, l 문자는 Base58에서 사용되지 않음)
        let result = SecretAddress::try_from("invalid0OIl".to_string());
        println!("Result for invalid0OIl: {:?}", result);
        match result {
            Err(WifError::InvalidBase58) => println!("✓ InvalidBase58 caught correctly"),
            other => panic!("Expected InvalidBase58, got: {:?}", other),
        }
        
        // 너무 짧은 길이
        let result = SecretAddress::try_from("5".to_string());
        match result {
            Err(WifError::InvalidBase58) | Err(WifError::InvalidLength) => println!("✓ Short string rejected"),
            other => panic!("Expected InvalidBase58 or InvalidLength, got: {:?}", other),
        }
        
        // 빈 문자열 (bs58 라이브러리가 이를 길이 오류로 처리할 수 있음)
        let result = SecretAddress::try_from("".to_string());
        match result {
            Err(WifError::InvalidBase58) | Err(WifError::InvalidLength) => println!("✓ Empty string rejected"),
            other => panic!("Expected InvalidBase58 or InvalidLength, got: {:?}", other),
        }
        
        // 올바른 Base58이지만 잘못된 길이 (너무 짧음)
        let result = SecretAddress::try_from("111111111111111111111111111111111111".to_string());
        match result {
            Err(WifError::InvalidLength) => println!("✓ Wrong length rejected"),
            other => panic!("Expected InvalidLength, got: {:?}", other),
        }
        
        println!("✓ Invalid WIF properly rejected");
    }

    #[test]
    fn test_round_trip_conversion() {
        // 다양한 시나리오에서의 라운드트립 테스트
        let test_cases = [
            (U256::from(1u64), PublicNet::Main, Compress::On),
            (U256::from(1u64), PublicNet::Main, Compress::Off),
            (U256::from(1u64), PublicNet::Test, Compress::On),
            (U256::from(1u64), PublicNet::Test, Compress::Off),
            (U256::from(0xdeadbeefdeadbeefdeadbeefdeadbeefu128), PublicNet::Main, Compress::On),
            (U256::from(0x1234567890abcdefu64), PublicNet::Test, Compress::Off),
        ];

        for (private_key, expected_net, expected_comp) in test_cases {
            let secret_key = SecretKey::new(Fp::new(private_key));
            let public_address = match expected_net {
                PublicNet::Main => PublicAddress::MainNet("dummy".to_string()),
                PublicNet::Test => PublicAddress::TestNet("dummy".to_string()),
            };
            let sec = match expected_comp {
                Compress::On => PublicKeySerialize::Compress([0; 33]),
                Compress::Off => PublicKeySerialize::Uncompress([0; 65]),
            };

            // SecretKey -> SecretAddress -> String -> SecretAddress -> SecretKey
            let secret_address = SecretAddress::build(&secret_key, &public_address, &sec);
            let wif_string = secret_address.as_ref().clone();
            let parsed_address = SecretAddress::try_from(wif_string.clone()).unwrap();
            let recovered_key = SecretKey::from(&parsed_address);

            // 모든 값이 일치하는지 확인
            assert_eq!(U256::from(*secret_key), U256::from(*recovered_key));
            assert_eq!(secret_address.net, expected_net);
            assert_eq!(secret_address.comp, expected_comp);

            println!("✓ Round-trip successful for {:?}/{:?}: {}", expected_net, expected_comp, wif_string);
        }
    }

    #[test]
    fn test_different_secret_keys_different_wif() {
        // 다른 비밀키는 다른 WIF를 생성해야 함
        let keys = [1u64, 2, 100, 12345, 0xdeadbeef];
        let mut wifs = Vec::new();

        for &key_value in &keys {
            let secret_key = SecretKey::new(Fp::new(U256::from(key_value)));
            let public_address = PublicAddress::MainNet("dummy".to_string());
            let sec = PublicKeySerialize::Compress([0; 33]);

            let wif = SecretAddress::build(&secret_key, &public_address, &sec).as_ref().to_string();
            wifs.push(wif);
        }

        // 모든 WIF가 서로 달라야 함
        for i in 0..wifs.len() {
            for j in (i + 1)..wifs.len() {
                assert_ne!(wifs[i], wifs[j], "Different secret keys should produce different WIFs");
            }
        }

        println!("✓ All different secret keys produced unique WIFs");
    }

    #[test]
    fn test_wif_format_validation() {
        // WIF 포맷이 올바른지 상세히 확인
        let secret_key = SecretKey::new(Fp::new(U256::from(0x123456789abcdefu64)));
        
        // 압축/비압축 각각에 대해 테스트
        let test_cases = [
            (PublicAddress::MainNet("dummy".to_string()), PublicKeySerialize::Compress([0; 33]), true),
            (PublicAddress::MainNet("dummy".to_string()), PublicKeySerialize::Uncompress([0; 65]), false),
            (PublicAddress::TestNet("dummy".to_string()), PublicKeySerialize::Compress([0; 33]), true),
            (PublicAddress::TestNet("dummy".to_string()), PublicKeySerialize::Uncompress([0; 65]), false),
        ];

        for (addr, sec, is_compressed) in test_cases {
            let secret_address = SecretAddress::build(&secret_key, &addr, &sec);
            let wif = secret_address.as_ref();

            // Base58 문자 집합 검증
            let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            assert!(wif.chars().all(|c| base58_alphabet.contains(c)), 
                "WIF contains invalid base58 characters: {}", wif);

            // 길이 검증
            if is_compressed {
                assert!(wif.len() >= 51 && wif.len() <= 52, "Compressed WIF length should be 51-52 chars, got: {}", wif.len());
            } else {
                assert!(wif.len() >= 50 && wif.len() <= 52, "Uncompressed WIF length should be 50-52 chars, got: {}", wif.len());
            }

            println!("✓ WIF format valid: {} (length: {})", wif, wif.len());
        }
    }

    #[test]
    fn test_checksum_validation() {
        // 체크섬 검증이 올바르게 작동하는지 테스트
        let secret_key = SecretKey::new(Fp::new(U256::from(42u64)));
        let public_address = PublicAddress::MainNet("dummy".to_string());
        let sec = PublicKeySerialize::Compress([0; 33]);

        let secret_address = SecretAddress::build(&secret_key, &public_address, &sec);
        let mut wif_string = secret_address.as_ref().clone();

        // 마지막 문자를 변경해서 체크섬을 깨트림
        let mut chars: Vec<char> = wif_string.chars().collect();
        let last_char = chars.last_mut().unwrap();
        *last_char = if *last_char == 'A' { 'B' } else { 'A' };
        wif_string = chars.into_iter().collect();

        // 깨진 체크섬으로 파싱 시도
        let result = SecretAddress::try_from(wif_string);
        assert!(matches!(result, Err(WifError::InvalidChecksum)), 
            "Should reject WIF with invalid checksum");

        println!("✓ Checksum validation works correctly");
    }

    #[test]
    fn test_network_prefix_validation() {
        // 올바른 네트워크 접두사에 대한 테스트는 이미 다른 테스트에서 커버됨
        // 여기서는 잘못된 접두사로 구성된 가상의 WIF를 테스트할 수는 없지만,
        // 최소한 올바른 접두사가 올바른 네트워크로 인식되는지 확인

        let secret_key = SecretKey::new(Fp::new(U256::from(1u64)));
        
        // 메인넷 테스트
        let mainnet_addr = PublicAddress::MainNet("dummy".to_string());
        let mainnet_wif = SecretAddress::build(&secret_key, &mainnet_addr, &PublicKeySerialize::Compress([0; 33]));
        let parsed_mainnet = SecretAddress::try_from(mainnet_wif.as_ref().clone()).unwrap();
        assert_eq!(parsed_mainnet.net, PublicNet::Main);

        // 테스트넷 테스트
        let testnet_addr = PublicAddress::TestNet("dummy".to_string());
        let testnet_wif = SecretAddress::build(&secret_key, &testnet_addr, &PublicKeySerialize::Compress([0; 33]));
        let parsed_testnet = SecretAddress::try_from(testnet_wif.as_ref().clone()).unwrap();
        assert_eq!(parsed_testnet.net, PublicNet::Test);

        println!("✓ Network prefix validation passed");
    }
}
