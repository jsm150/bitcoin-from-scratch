use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use super::PublicKeySerialize;



pub struct AddressEncoder(Vec<u8>);

impl AddressEncoder {
    fn to_base58_check(&mut self) -> String {
        self.0.extend_from_slice(&Sha256::digest(Sha256::digest(&self.0))[..4]);
        bs58::encode(&self.0)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string()
    }

    pub fn into_main_net(mut self) -> PublicAddress {
        self.0[0] = 0x00;
        let addr = self.to_base58_check();

        PublicAddress::MainNet(addr)
    }

    pub fn into_test_net(mut self) -> PublicAddress {
        self.0[0] = 0x6f;
        let addr = self.to_base58_check();

        PublicAddress::TestNet(addr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicAddress {
    MainNet(String),
    TestNet(String)
}

impl PublicAddress {
    fn to_hash(public_serialize: &PublicKeySerialize) -> Vec<u8> {
        let mut vec = vec![0];
        let hash160 = Ripemd160::digest(Sha256::digest(public_serialize));
        vec.extend_from_slice(hash160.as_slice());
        vec
    }

    pub fn build(public_serialize: &PublicKeySerialize) -> AddressEncoder {
        AddressEncoder(Self::to_hash(public_serialize))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressParseError {
    InvalidBase58,
    InvalidChecksum,
    InvalidLength,
    UnsupportedVersion,
}

impl std::fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressParseError::InvalidBase58 => write!(f, "Invalid base58 encoding"),
            AddressParseError::InvalidChecksum => write!(f, "Invalid checksum"),
            AddressParseError::InvalidLength => write!(f, "Invalid address length"),
            AddressParseError::UnsupportedVersion => write!(f, "Unsupported address version"),
        }
    }
}

impl std::error::Error for AddressParseError {}

impl TryFrom<String> for PublicAddress {
    type Error = AddressParseError;

    fn try_from(address: String) -> Result<Self, Self::Error> {
        // Base58 디코딩
        let decoded = bs58::decode(&address)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_vec()
            .map_err(|_| AddressParseError::InvalidBase58)?;

        // 최소 길이 확인 (version byte + 20 bytes hash + 4 bytes checksum)
        if decoded.len() != 25 {
            return Err(AddressParseError::InvalidLength);
        }

        // 체크섬 검증
        let (payload, checksum) = decoded.split_at(21);
        let expected_checksum = &Sha256::digest(Sha256::digest(payload))[..4];
        
        if checksum != expected_checksum {
            return Err(AddressParseError::InvalidChecksum);
        }

        // 버전 바이트에 따라 MainNet/TestNet 구분
        let version = payload[0];
        match version {
            0x00 => {
                // MainNet P2PKH 주소
                Ok(PublicAddress::MainNet(address))
            },
            0x6f => {
                // TestNet P2PKH 주소
                Ok(PublicAddress::TestNet(address))
            },
            _ => Err(AddressParseError::UnsupportedVersion),
        }
    }
}


impl PartialEq<PublicKeySerialize> for PublicAddress {
    fn eq(&self, sec: &PublicKeySerialize) -> bool {
        let arr = match sec {
            PublicKeySerialize::Compress(arr) => &arr[..],
            PublicKeySerialize::Uncompress(arr) => &arr[..],
        };
        
        let hash160 = Ripemd160::digest(Sha256::digest(arr));
        
        let address = match self {
            PublicAddress::MainNet(address) => address,
            PublicAddress::TestNet(address) => address,
        };
        
        let decoded = bs58::decode(address)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_vec()
            .unwrap();

        decoded[1..21] == hash160[..]
    }
}

#[cfg(test)]
mod tests {
    use ruint::aliases::U256;

    use crate::encrypt::PublicKey;

    use super::*;
    use super::super::Secp256k1;

    #[test]
    fn test_address_builder_basic_functionality() {
        // 기본적인 Address builder 기능 테스트
        let g = Secp256k1::default();
        let point = g * U256::from(42u64);
        let public_key = PublicKey::from_point(point).unwrap();
        
        // PublicKeySerialize 생성
        let compressed_sec = public_key.to_compress_sec();
        let uncompressed_sec = public_key.to_uncompress_sec();
        
        // 압축된 형식 주소 생성
        let compressed_mainnet = PublicAddress::build(&compressed_sec).into_main_net();
        let compressed_testnet = PublicAddress::build(&compressed_sec).into_test_net();
        
        // 비압축 형식 주소 생성  
        let uncompressed_mainnet = PublicAddress::build(&uncompressed_sec).into_main_net();
        let uncompressed_testnet = PublicAddress::build(&uncompressed_sec).into_test_net();
        
        // 생성된 주소들이 올바른 타입인지 확인
        match compressed_mainnet {
            PublicAddress::MainNet(_) => println!("Compressed MainNet address created successfully"),
            PublicAddress::TestNet(_) => panic!("Expected MainNet address"),
        }
        
        match compressed_testnet {
            PublicAddress::MainNet(_) => panic!("Expected TestNet address"),  // 버그: into_test_net에서 MainNet을 반환하고 있음
            PublicAddress::TestNet(_) => println!("Compressed TestNet address created successfully"),
        }
        
        match uncompressed_mainnet {
            PublicAddress::MainNet(_) => println!("Uncompressed MainNet address created successfully"),
            PublicAddress::TestNet(_) => panic!("Expected MainNet address"),
        }
        
        match uncompressed_testnet {
            PublicAddress::MainNet(_) => panic!("Expected TestNet address"),  // 버그: into_test_net에서 MainNet을 반환하고 있음
            PublicAddress::TestNet(_) => println!("Uncompressed TestNet address created successfully"),
        }
    }

    #[test]
    fn test_address_builder_consistency() {
        // 동일한 공개키로 여러 번 주소를 생성했을 때 일관성 테스트
        let g = Secp256k1::default();
        let point = g * U256::from(314159u64);
        let public_key = PublicKey::from_point(point).unwrap();
        
        // 압축된 PublicKeySerialize 생성
        let compressed_sec = public_key.to_compress_sec();
        
        // 같은 공개키로 여러 번 주소 생성
        let addr1 = PublicAddress::build(&compressed_sec).into_main_net();
        let addr2 = PublicAddress::build(&compressed_sec).into_main_net();
        let addr3 = PublicAddress::build(&compressed_sec).into_main_net();
        
        // 모든 주소가 동일해야 함
        let addr1_str = match &addr1 {
            PublicAddress::MainNet(s) => s,
            _ => panic!("Expected MainNet"),
        };
        
        let addr2_str = match &addr2 {
            PublicAddress::MainNet(s) => s,
            _ => panic!("Expected MainNet"),
        };
        
        let addr3_str = match &addr3 {
            PublicAddress::MainNet(s) => s,
            _ => panic!("Expected MainNet"),
        };
        
        assert_eq!(addr1_str, addr2_str, "Multiple calls should return identical addresses");
        assert_eq!(addr2_str, addr3_str, "Multiple calls should return identical addresses");
        
        println!("Address consistency test passed");
    }

    #[test]
    fn test_address_builder_known_test_vector() {
        // 알려진 개인키 1에 대한 공개키 주소 검증
        let private_key = U256::from(1u64);
        let g = Secp256k1::default();
        let point = g * private_key;
        
        // 개인키가 1인지 확인
        assert_eq!(private_key, U256::from(1u64), "Private key should be 1");
        
        let public_key = PublicKey::from_point(point).unwrap();
        
        // 압축된 PublicKeySerialize 생성
        let compressed_sec = public_key.to_compress_sec();
        
        // 압축된 MainNet 주소 생성 및 검증
        let compressed_mainnet = PublicAddress::build(&compressed_sec).into_main_net();
        let compressed_addr = match compressed_mainnet {
            PublicAddress::MainNet(s) => s,
            _ => panic!("Expected MainNet"),
        };
        
        // 개인키 1의 압축된 공개키 주소는 비트코인에서 잘 알려진 값
        // 실제 예상 주소: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        let expected_compressed = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        assert_eq!(compressed_addr, expected_compressed, 
            "Compressed address should match the known value for private key 1");
        
        println!("✓ Private key 1 compressed MainNet address: {}", compressed_addr);
        
        // 비압축 PublicKeySerialize 생성
        let uncompressed_sec = public_key.to_uncompress_sec();
        
        // 비압축 MainNet 주소 생성 및 검증
        let uncompressed_mainnet = PublicAddress::build(&uncompressed_sec).into_main_net();
        let uncompressed_addr = match uncompressed_mainnet {
            PublicAddress::MainNet(s) => s,
            _ => panic!("Expected MainNet"),
        };
        
        // 개인키 1의 비압축 공개키 주소는 비트코인에서 잘 알려진 값
        // 실제 예상 주소: "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
        let expected_uncompressed = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm";
        assert_eq!(uncompressed_addr, expected_uncompressed,
            "Uncompressed address should match the known value for private key 1");
        
        println!("✓ Private key 1 uncompressed MainNet address: {}", uncompressed_addr);
        
        // 압축/비압축 주소가 서로 다른지 확인
        assert_ne!(compressed_addr, uncompressed_addr, 
            "Compressed and uncompressed addresses should be different");
        
        println!("✓ All known address values verified for private key 1");
    }

    #[test]
    fn test_string_to_public_address_conversion() {
        // 유효한 MainNet 주소 테스트
        let mainnet_address = String::from("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        let parsed_mainnet = PublicAddress::try_from(mainnet_address.clone()).unwrap();
        
        match parsed_mainnet {
            PublicAddress::MainNet(addr) => {
                assert_eq!(addr, mainnet_address);
                println!("✓ MainNet address parsed successfully: {}", addr);
            },
            _ => panic!("Expected MainNet address"),
        }

        // 유효한 TestNet 주소 테스트 (버전 바이트 0x6f)
        // TestNet 주소 예시를 만들어보자
        let g = Secp256k1::default();
        let point = g * U256::from(1u64);
        let public_key = PublicKey::from_point(point).unwrap();
        let compressed_sec = public_key.to_compress_sec();
        let testnet_address_obj = PublicAddress::build(&compressed_sec).into_test_net();
        
        let testnet_address_str = match &testnet_address_obj {
            PublicAddress::TestNet(s) => s.clone(),
            _ => panic!("Expected TestNet address"),
        };

        let parsed_testnet = PublicAddress::try_from(testnet_address_str.clone()).unwrap();
        match parsed_testnet {
            PublicAddress::TestNet(addr) => {
                assert_eq!(addr, testnet_address_str);
                println!("✓ TestNet address parsed successfully: {}", addr);
            },
            _ => panic!("Expected TestNet address"),
        }

        // 잘못된 Base58 문자열 테스트
        let invalid_base58 = String::from("invalid0OIl");
        let result = PublicAddress::try_from(invalid_base58);
        assert!(matches!(result, Err(AddressParseError::InvalidBase58)));
        println!("✓ Invalid base58 correctly rejected");

        // 잘못된 체크섬 테스트
        let invalid_checksum = String::from("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMX"); // 마지막 문자 변경
        let result = PublicAddress::try_from(invalid_checksum);
        assert!(matches!(result, Err(AddressParseError::InvalidChecksum)));
        println!("✓ Invalid checksum correctly rejected");

        // 잘못된 길이 테스트
        let too_short = String::from("1A1");
        let result = PublicAddress::try_from(too_short);
        assert!(matches!(result, Err(AddressParseError::InvalidLength)));
        println!("✓ Invalid length correctly rejected");

        // 지원하지 않는 버전 테스트 (P2SH 주소는 0x05로 시작)
        // P2SH 주소 예시: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
        let p2sh_address = String::from("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
        let result = PublicAddress::try_from(p2sh_address);
        assert!(matches!(result, Err(AddressParseError::UnsupportedVersion)));
        println!("✓ Unsupported version correctly rejected");

        println!("✓ All string to PublicAddress conversion tests passed");
    }

    #[test]
    fn test_public_address_equals_public_key_serialize() {
        // 테스트용 공개키 생성
        let g = Secp256k1::default();
        let point = g * U256::from(42u64);
        let public_key = PublicKey::from_point(point).unwrap();

        // 압축된 형태의 PublicKeySerialize와 PublicAddress 생성
        let compressed_sec = public_key.to_compress_sec();
        let compressed_address = PublicAddress::build(&compressed_sec).into_main_net();

        // 압축된 주소와 압축된 SEC가 같은지 테스트
        assert_eq!(compressed_address, compressed_sec);
        println!("✓ Compressed PublicAddress equals compressed PublicKeySerialize");

        // 비압축 형태의 PublicKeySerialize와 PublicAddress 생성
        let uncompressed_sec = public_key.to_uncompress_sec();
        let uncompressed_address = PublicAddress::build(&uncompressed_sec).into_main_net();

        // 비압축 주소와 비압축 SEC가 같은지 테스트
        assert_eq!(uncompressed_address, uncompressed_sec);
        println!("✓ Uncompressed PublicAddress equals uncompressed PublicKeySerialize");

        // TestNet 주소도 동일하게 동작하는지 테스트
        let compressed_testnet = PublicAddress::build(&compressed_sec).into_test_net();
        assert_eq!(compressed_testnet, compressed_sec);
        println!("✓ Compressed TestNet PublicAddress equals compressed PublicKeySerialize");

        let uncompressed_testnet = PublicAddress::build(&uncompressed_sec).into_test_net();
        assert_eq!(uncompressed_testnet, uncompressed_sec);
        println!("✓ Uncompressed TestNet PublicAddress equals uncompressed PublicKeySerialize");

        // 다른 형태끼리는 같지 않아야 함
        assert_ne!(compressed_address, uncompressed_sec);
        assert_ne!(uncompressed_address, compressed_sec);
        println!("✓ Different compression formats correctly identified as not equal");
    }

    #[test]
    fn test_public_address_equals_different_keys() {
        // 서로 다른 공개키로 생성한 주소와 SEC는 같지 않아야 함
        let g = Secp256k1::default();
        
        let point1 = g * U256::from(123u64);
        let public_key1 = PublicKey::from_point(point1).unwrap();
        
        let point2 = g * U256::from(456u64);
        let public_key2 = PublicKey::from_point(point2).unwrap();

        // 첫 번째 키로 주소와 SEC 생성
        let compressed_sec1 = public_key1.to_compress_sec();
        let address1 = PublicAddress::build(&compressed_sec1).into_main_net();
        let sec1 = public_key1.to_compress_sec();

        // 두 번째 키로 SEC 생성
        let sec2 = public_key2.to_compress_sec();

        // 같은 키로 생성한 것은 같아야 함
        assert_eq!(address1, sec1);
        
        // 다른 키로 생성한 것은 다르게 나와야 함
        assert_ne!(address1, sec2);
        println!("✓ Different keys produce different addresses as expected");
    }

    #[test]
    fn test_public_address_equals_known_vector() {
        // 알려진 테스트 벡터로 검증
        let private_key = U256::from(1u64);
        let g = Secp256k1::default();
        let point = g * private_key;
        let public_key = PublicKey::from_point(point).unwrap();

        // 압축된 형태
        let compressed_sec = public_key.to_compress_sec();
        let compressed_address = PublicAddress::build(&compressed_sec).into_main_net();

        assert_eq!(compressed_address, compressed_sec);
        
        // 실제 주소 확인
        let address_str = match &compressed_address {
            PublicAddress::MainNet(s) => s,
            _ => panic!("Expected MainNet address"),
        };
        assert_eq!(address_str, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        
        // 비압축 형태
        let uncompressed_sec = public_key.to_uncompress_sec();
        let uncompressed_address = PublicAddress::build(&uncompressed_sec).into_main_net();

        assert_eq!(uncompressed_address, uncompressed_sec);
        
        // 실제 주소 확인
        let address_str = match &uncompressed_address {
            PublicAddress::MainNet(s) => s,
            _ => panic!("Expected MainNet address"),
        };
        assert_eq!(address_str, "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
        
        println!("✓ Known test vector verification passed");
    }

    #[test]
    fn test_public_address_equals_parse_from_string() {
        // 문자열로 파싱한 주소와 PublicKeySerialize 비교
        let g = Secp256k1::default();
        let point = g * U256::from(1u64);
        let public_key = PublicKey::from_point(point).unwrap();

        // 압축된 형태로 주소 생성
        let compressed_sec = public_key.to_compress_sec();
        let compressed_address = PublicAddress::build(&compressed_sec).into_main_net();

        // 주소 문자열 추출
        let address_string = match &compressed_address {
            PublicAddress::MainNet(s) => s.clone(),
            _ => panic!("Expected MainNet address"),
        };

        // 문자열에서 파싱한 주소
        let parsed_address = PublicAddress::try_from(address_string).unwrap();

        // 파싱한 주소는 UnknownCompress 타입이지만, 동일한 SEC와 비교했을 때는 같아야 함
        assert_eq!(parsed_address, compressed_sec);
        println!("✓ Parsed address equals original PublicKeySerialize");

        // TestNet 주소도 테스트
        let testnet_address = PublicAddress::build(&compressed_sec).into_test_net();
        
        let testnet_string = match &testnet_address {
            PublicAddress::TestNet(s) => s.clone(),
            _ => panic!("Expected TestNet address"),
        };

        let parsed_testnet = PublicAddress::try_from(testnet_string).unwrap();
        assert_eq!(parsed_testnet, compressed_sec);
        println!("✓ Parsed TestNet address equals original PublicKeySerialize");
    }
}