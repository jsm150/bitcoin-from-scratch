use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use super::{PublicKeySerialize, PublicKey};



pub struct AddressEncoder(PublicKeySerialize);

impl AddressEncoder {
    fn to_base58_check(vec: &mut Vec<u8>) -> String {
        vec.extend_from_slice(&Sha256::digest(Sha256::digest(&vec))[..4]);
        bs58::encode(&vec)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string()
    }

    fn to_hash(&self, sec: &PublicKeySerialize) -> Vec<u8> {
        let mut vec = vec![0];
        let hash160 = Ripemd160::digest(Sha256::digest(sec));
        vec.extend_from_slice(hash160.as_slice());
        vec
    }

    pub fn into_main_net(self) -> PublicAddress {
        let mut vec = self.to_hash(&self.0);
        vec[0] = 0x00;
        let addr = Self::to_base58_check(&mut vec);

        match self.0 {
            PublicKeySerialize::Compress(_) => PublicAddress::MainNet(Address::Compress(addr)),
            PublicKeySerialize::Uncompress(_) => PublicAddress::MainNet(Address::Uncompress(addr)),
        }
    }

    pub fn into_test_net(self) -> PublicAddress {
        let mut vec = self.to_hash(&self.0);
        vec[0] = 0x6f;
        let addr = Self::to_base58_check(&mut vec);

        match self.0 {
            PublicKeySerialize::Compress(_) => PublicAddress::TestNet(Address::Compress(addr)),
            PublicKeySerialize::Uncompress(_) => PublicAddress::TestNet(Address::Uncompress(addr)),
        }
    }
}

pub struct AddressBuilder(PublicKey);

impl AddressBuilder {
    pub fn from_compress(self) -> AddressEncoder {
        AddressEncoder(self.0.to_compress_sec())
    }

    pub fn from_uncompress(self) -> AddressEncoder {
        AddressEncoder(self.0.to_uncompress_sec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Address {
    Compress(String),
    Uncompress(String),
    UnknownCompress(String)
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Compress(s) => write!(f, "{}", s),
            Address::Uncompress(s) => write!(f, "{}", s),
            Address::UnknownCompress(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicAddress {
    MainNet(Address),
    TestNet(Address)
}

impl PublicAddress {
    pub fn build_with_public_key(public_key: PublicKey) -> AddressBuilder {
        AddressBuilder(public_key)
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
                Ok(PublicAddress::MainNet(Address::UnknownCompress(address)))
            },
            0x6f => {
                // TestNet P2PKH 주소
                Ok(PublicAddress::TestNet(Address::UnknownCompress(address)))
            },
            _ => Err(AddressParseError::UnsupportedVersion),
        }
    }
}


#[cfg(test)]
mod tests {
    use ruint::aliases::U256;

    use super::*;
    use super::super::Secp256k1;

    #[test]
    fn test_address_builder_basic_functionality() {
        // 기본적인 Address builder 기능 테스트
        let g = Secp256k1::default();
        let point = g * U256::from(42u64);
        let public_key = PublicKey::from_point(point).unwrap();
        
        // Builder 인스턴스 생성 테스트
        let builder = PublicAddress::build_with_public_key(public_key);
        
        // from_compress를 통한 압축된 형식 주소 생성
        let compressed_mainnet = builder.from_compress().into_main_net();
        let compressed_testnet = PublicAddress::build_with_public_key(public_key).from_compress().into_test_net();
        
        // from_uncompress를 통한 비압축 형식 주소 생성  
        let uncompressed_mainnet = PublicAddress::build_with_public_key(public_key).from_uncompress().into_main_net();
        let uncompressed_testnet = PublicAddress::build_with_public_key(public_key).from_uncompress().into_test_net();
        
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
        
        // 같은 공개키로 여러 번 주소 생성
        let addr1 = PublicAddress::build_with_public_key(public_key).from_compress().into_main_net();
        let addr2 = PublicAddress::build_with_public_key(public_key).from_compress().into_main_net();
        let addr3 = PublicAddress::build_with_public_key(public_key).from_compress().into_main_net();
        
        // 모든 주소가 동일해야 함
        let addr1_str = match &addr1 {
            PublicAddress::MainNet(Address::Compress(s)) => s,
            PublicAddress::MainNet(Address::Uncompress(s)) => s,
            _ => panic!("Expected MainNet"),
        };
        
        let addr2_str = match &addr2 {
            PublicAddress::MainNet(Address::Compress(s)) => s,
            PublicAddress::MainNet(Address::Uncompress(s)) => s,
            _ => panic!("Expected MainNet"),
        };
        
        let addr3_str = match &addr3 {
            PublicAddress::MainNet(Address::Compress(s)) => s,
            PublicAddress::MainNet(Address::Uncompress(s)) => s,
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
        
        // 압축된 MainNet 주소 생성 및 검증
        let compressed_mainnet = PublicAddress::build_with_public_key(public_key).from_compress().into_main_net();
        let compressed_addr = match compressed_mainnet {
            PublicAddress::MainNet(Address::Compress(s)) => s,
            PublicAddress::MainNet(Address::Uncompress(_)) => panic!("Expected compressed address"),
            _ => panic!("Expected MainNet"),
        };
        
        // 개인키 1의 압축된 공개키 주소는 비트코인에서 잘 알려진 값
        // 실제 예상 주소: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        let expected_compressed = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        assert_eq!(compressed_addr, expected_compressed, 
            "Compressed address should match the known value for private key 1");
        
        println!("✓ Private key 1 compressed MainNet address: {}", compressed_addr);
        
        // 비압축 MainNet 주소 생성 및 검증
        let uncompressed_mainnet = PublicAddress::build_with_public_key(public_key).from_uncompress().into_main_net();
        let uncompressed_addr = match uncompressed_mainnet {
            PublicAddress::MainNet(Address::Uncompress(s)) => s,
            PublicAddress::MainNet(Address::Compress(_)) => panic!("Expected uncompressed address"),
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
            PublicAddress::MainNet(Address::UnknownCompress(addr)) => {
                assert_eq!(addr, mainnet_address);
                println!("✓ MainNet address parsed successfully: {}", addr);
            },
            _ => panic!("Expected MainNet UnknownCompress address"),
        }

        // 유효한 TestNet 주소 테스트 (버전 바이트 0x6f)
        // TestNet 주소 예시를 만들어보자
        let g = Secp256k1::default();
        let point = g * U256::from(1u64);
        let public_key = PublicKey::from_point(point).unwrap();
        let testnet_address_obj = PublicAddress::build_with_public_key(public_key)
            .from_compress()
            .into_test_net();
        
        let testnet_address_str = match &testnet_address_obj {
            PublicAddress::TestNet(Address::Compress(s)) => s.clone(),
            _ => panic!("Expected TestNet Compress address"),
        };

        let parsed_testnet = PublicAddress::try_from(testnet_address_str.clone()).unwrap();
        match parsed_testnet {
            PublicAddress::TestNet(Address::UnknownCompress(addr)) => {
                assert_eq!(addr, testnet_address_str);
                println!("✓ TestNet address parsed successfully: {}", addr);
            },
            _ => panic!("Expected TestNet UnknownCompress address"),
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
}