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