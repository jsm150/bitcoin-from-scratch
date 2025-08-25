
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeySerialize {
    Compress([u8; 33]),
    Uncompress([u8; 65])
}

impl AsRef<[u8]> for PublicKeySerialize {
    fn as_ref(&self) -> &[u8] {
        match self {
            PublicKeySerialize::Compress(a) => &a[..],
            PublicKeySerialize::Uncompress(a) => &a[..],
        }
    }
}

impl TryFrom<[u8; 33]> for PublicKeySerialize {
    type Error = PublicKeyDeserializationErr;

    fn try_from(sec: [u8; 33]) -> Result<Self, Self::Error> {
        if sec[0] != 0x03 && sec[0] != 0x02 {
            return Err(PublicKeyDeserializationErr::NotCompressSec);
        }

        Ok(Self::Compress(sec))
    }
}

impl TryFrom<[u8; 65]> for PublicKeySerialize {
    type Error = PublicKeyDeserializationErr;

    fn try_from(sec: [u8; 65]) -> Result<Self, Self::Error> {
        if sec[0] != 0x04 {
            return Err(PublicKeyDeserializationErr::NotUncompressSec);
        }

        Ok(Self::Uncompress(sec))
    }
}

#[derive(Debug)]
pub enum PublicKeyDeserializationErr {
    NotUncompressSec,
    NotCompressSec
}

impl std::ops::Index<usize> for PublicKeySerialize {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_ref()[index]
    }
}

impl std::ops::Index<std::ops::Range<usize>> for PublicKeySerialize {
    type Output = [u8];

    fn index(&self, range: std::ops::Range<usize>) -> &Self::Output {
        &self.as_ref()[range]
    }
}

impl std::ops::Index<std::ops::RangeFrom<usize>> for PublicKeySerialize {
    type Output = [u8];

    fn index(&self, range: std::ops::RangeFrom<usize>) -> &Self::Output {
        &self.as_ref()[range]
    }
}

impl std::ops::Index<std::ops::RangeTo<usize>> for PublicKeySerialize {
    type Output = [u8];

    fn index(&self, range: std::ops::RangeTo<usize>) -> &Self::Output {
        &self.as_ref()[range]
    }
}

impl PublicKeySerialize {
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_compressed_public_key() {
        // 0x02로 시작하는 압축된 공개키 테스트
        let compressed_key_02 = [0x02; 33];
        let result = PublicKeySerialize::try_from(compressed_key_02);
        assert!(result.is_ok());
        match result.unwrap() {
            PublicKeySerialize::Compress(key) => assert_eq!(key[0], 0x02),
            _ => panic!("Expected compressed key"),
        }

        // 0x03로 시작하는 압축된 공개키 테스트
        let compressed_key_03 = [0x03; 33];
        let result = PublicKeySerialize::try_from(compressed_key_03);
        assert!(result.is_ok());
        match result.unwrap() {
            PublicKeySerialize::Compress(key) => assert_eq!(key[0], 0x03),
            _ => panic!("Expected compressed key"),
        }
    }

    #[test]
    fn test_try_from_uncompressed_public_key() {
        // 0x04로 시작하는 비압축된 공개키 테스트
        let uncompressed_key = [0x04; 65];
        let result = PublicKeySerialize::try_from(uncompressed_key);
        assert!(result.is_ok());
        match result.unwrap() {
            PublicKeySerialize::Uncompress(key) => assert_eq!(key[0], 0x04),
            _ => panic!("Expected uncompressed key"),
        }
    }

    #[test]
    fn test_try_from_invalid_compressed_key() {
        // 잘못된 압축 키 (0x01로 시작)
        let invalid_compressed = [0x01; 33];
        let result = PublicKeySerialize::try_from(invalid_compressed);
        assert!(result.is_err());
        match result.unwrap_err() {
            PublicKeyDeserializationErr::NotCompressSec => {},
            _ => panic!("Expected NotCompressSec error"),
        }

        // 잘못된 압축 키 (0x05로 시작)
        let invalid_compressed = [0x05; 33];
        let result = PublicKeySerialize::try_from(invalid_compressed);
        assert!(result.is_err());
        match result.unwrap_err() {
            PublicKeyDeserializationErr::NotCompressSec => {},
            _ => panic!("Expected NotCompressSec error"),
        }
    }

    #[test]
    fn test_try_from_invalid_uncompressed_key() {
        // 잘못된 비압축 키 (0x03로 시작)
        let invalid_uncompressed = [0x03; 65];
        let result = PublicKeySerialize::try_from(invalid_uncompressed);
        assert!(result.is_err());
        match result.unwrap_err() {
            PublicKeyDeserializationErr::NotUncompressSec => {},
            _ => panic!("Expected NotUncompressSec error"),
        }

        // 잘못된 비압축 키 (0x01로 시작)
        let invalid_uncompressed = [0x01; 65];
        let result = PublicKeySerialize::try_from(invalid_uncompressed);
        assert!(result.is_err());
        match result.unwrap_err() {
            PublicKeyDeserializationErr::NotUncompressSec => {},
            _ => panic!("Expected NotUncompressSec error"),
        }
    }
}