use rand::Rng;
use ruint::aliases::U256;


use super::{Fp, N, P, Secp256k1, CurvePoint, U256Wrapper, PublicKey, SecretKey};

pub struct Signature {
    r: Fp<N>,
    s: Fp<N>,
}

impl Signature {
    fn new(r: Fp<N>, s: Fp<N>) -> Self {
        Self { r, s }
    }

    pub fn build(z: Fp<N>, secret_key: SecretKey) -> Self {
        let (k, r) = (0..).find_map(|_| {
            let k = Fp::new(rand::thread_rng().r#gen::<U256>() % N::NUM);

            match Secp256k1::default() * k {
                CurvePoint::Point { 
                    x, .. 
                } => Some((k, Fp::<N>::from(x))),
                _ => None,
            }
            
        }).unwrap();

        let mut s = (z + r * *secret_key) / k;
        if U256::from(s) > N::NUM / U256::from(2) {
            s = Fp::new(U256::ZERO) - s;
        }
        Self::new(r, s)
    }

    pub fn verify(&self, z: Fp<N>, public_key: PublicKey) -> bool {
        // uG + vP = R
        // u = z / s, v = r / s

        let u = z / self.s;
        let v = self.r / self.s;
        let r = (Secp256k1::default() * u) + (*public_key * v);

        if let CurvePoint::Point { x: rx, .. } = r {
            let rx = Fp::<N>::from(rx);
            rx == self.r
        }
        else {
            false
        }
    }

    pub fn to_der(&self) -> [u8; 72] {
        
        fn parse(byte: &[u8; 32]) -> (u8, [u8; 35]) {

            let mut buf = [0; 35];
            buf[0] = 0x2;

            // r_byte + 길이 바이트 + 시작 바이트
            let mut buf_len = (byte.len() + 2) as u8;

            if byte[0] >= 0x80 {
                buf_len += 1;
                buf[1] = (byte.len() + 1) as u8;
                buf[2] = 0;
                buf[3..].copy_from_slice(byte);
            }
            else {
                buf[1] = byte.len() as u8;
                buf[2.. 2 + byte.len()].copy_from_slice(byte);
            }

            (buf_len, buf)
        }

        let r_byte: [u8; 32] = U256::from(self.r).to_be_bytes();
        let s_byte: [u8; 32] = U256::from(self.s).to_be_bytes();
        let (r_len, r_buf) = parse(&r_byte);
        let (s_len, s_buf) = parse(&s_byte);
        
        let mut der = [0; 72];
        der[0] = 0x30;
        der[1] = r_len + s_len;

        let (r_len, s_len) = (r_len as usize, s_len as usize);
        
        der[2 .. 2 + r_len].copy_from_slice(&r_buf[..r_len]);
        der[2 + r_len .. 2 + r_len + s_len].copy_from_slice(&s_buf[..s_len]);

        der
    }
}


impl From<Fp<P>> for Fp<N> {
    fn from(value: Fp<P>) -> Self {
        let p = U256::from(value);
        if p >= N::NUM {
            Self::new(p % N::NUM )
        }
        else {
            Self::new(p)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::encrypt::k256::B;
    use crate::encrypt::k256::A;

    use super::*;

    #[test]
    fn test_signature_validation_multiple_cases() {
        // 첫 번째 이미지 데이터
        let z_hex = "0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423";
        let r_hex = "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6";
        let s_hex = "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        let px_hex = "0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574";
        let py_hex = "0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4";

        // 16진수 문자열을 U256으로 변환
        let z = U256::from_str_radix(&z_hex[2..], 16).unwrap();
        let r = U256::from_str_radix(&r_hex[2..], 16).unwrap();
        let s = U256::from_str_radix(&s_hex[2..], 16).unwrap();
        let px = U256::from_str_radix(&px_hex[2..], 16).unwrap();
        let py = U256::from_str_radix(&py_hex[2..], 16).unwrap();

        // 공개키 포인트 생성
        let pk = CurvePoint::Point { 
            x: Fp::new(px), 
            y: Fp::new(py),
            a: Fp::new(A::NUM),
            b: Fp::new(B::NUM),
            _phantom: std::marker::PhantomData
        };
        
        // 서명 생성
        let signature = Signature::new(Fp::new(r), Fp::new(s));
        
        // 서명 검증 - 유효한 서명이므로 true여야 함
        assert!(signature.verify(Fp::new(z), PublicKey::from_point(pk).unwrap()), "First signature should be valid");

        // 두 번째 이미지의 첫 번째 서명
        let px_hex = "0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c";
        let py_hex = "0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34";
        
        let z1_hex = "0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60";
        let r1_hex = "0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395";
        let s1_hex = "0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4";
        
        let px = U256::from_str_radix(&px_hex[2..], 16).unwrap();
        let py = U256::from_str_radix(&py_hex[2..], 16).unwrap();
        let z1 = U256::from_str_radix(&z1_hex[2..], 16).unwrap();
        let r1 = U256::from_str_radix(&r1_hex[2..], 16).unwrap();
        let s1 = U256::from_str_radix(&s1_hex[2..], 16).unwrap();
        
        let pk = CurvePoint::Point { 
            x: Fp::new(px), 
            y: Fp::new(py),
            a: Fp::new(A::NUM),
            b: Fp::new(B::NUM),
            _phantom: std::marker::PhantomData
        };
        let signature1 = Signature::new(Fp::new(r1), Fp::new(s1));
        
        assert!(signature1.verify(Fp::new(z1), PublicKey::from_point(pk).unwrap()), "Second image first signature should be valid");
        
        // 두 번째 이미지의 두 번째 서명
        let z2_hex = "0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d";
        let r2_hex = "0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c";
        let s2_hex = "0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
        
        let z2 = U256::from_str_radix(&z2_hex[2..], 16).unwrap();
        let r2 = U256::from_str_radix(&r2_hex[2..], 16).unwrap();
        let s2 = U256::from_str_radix(&s2_hex[2..], 16).unwrap();
        
        let signature2 = Signature::new(Fp::new(r2), Fp::new(s2));
        
        assert!(signature2.verify(Fp::new(z2), PublicKey::from_point(pk).unwrap()), "Second image second signature should be valid");

        // 잘못된 서명 검증
        let z_invalid_hex = "0xdeadbeef";
        let z_invalid = U256::from_str_radix(&z_invalid_hex[2..], 16).unwrap();
        let signature_invalid = Signature::new(Fp::new(r2), Fp::new(s2));

        assert!(!signature_invalid.verify(Fp::new(z_invalid), PublicKey::from_point(pk).unwrap()), "Invalid signature should fail validation");
    }

    #[test]
    fn test_signature_build() {
        // 테스트용 개인키와 메시지 해시
        let secret_key = Fp::new(U256::from(12345u64));
        let z = Fp::new(U256::from(67890u64));
        
        // 서명 생성
        let signature = Signature::build(z, SecretKey::new(secret_key));
        
        // 공개키 계산 (G * secret_key)
        let g = Secp256k1::default();
        let public_key = g * U256::from(secret_key);
        
        // 생성된 서명이 유효한지 검증
        assert!(signature.verify(z, PublicKey::from_point(public_key).unwrap()), "Generated signature should be valid");
    }

    #[test]
    fn test_signature_build_multiple_messages() {
        // 동일한 개인키로 여러 메시지에 대한 서명 테스트
        let secret_key = Fp::new(U256::from(98765u64));
        let messages = [
            U256::from(11111u64),
            U256::from(22222u64),
            U256::from(33333u64),
        ];
        
        let g = Secp256k1::default();
        let public_key = g * U256::from(secret_key);
        
        for &msg in &messages {
            let z = Fp::new(msg);
            let signature = Signature::build(z, SecretKey::new(secret_key));
            
            assert!(signature.verify(z, PublicKey::from_point(public_key).unwrap()), 
                "Signature should be valid for message: {}", msg);
        }
    }

    #[test]
    fn test_signature_build_deterministic_verification() {
        // 서명이 deterministic하지 않더라도 항상 검증이 성공해야 함
        let secret_key = Fp::new(U256::from(54321u64));
        let z = Fp::new(U256::from(13579u64));
        
        let g = Secp256k1::default();
        let public_key = g * U256::from(secret_key);
        
        // 같은 메시지와 키로 여러 번 서명 생성 (k가 랜덤이므로 다른 서명이 생성됨)
        for _ in 0..5 {
            let signature = Signature::build(z, SecretKey::new(secret_key));
            assert!(signature.verify(z, PublicKey::from_point(public_key).unwrap()), 
                "Each generated signature should be valid");
        }
    }

    #[test]
    fn test_to_der_encoding() {
        // 테스트용 r, s 값 생성 (0x80보다 작은 첫 바이트)
        let r = Fp::new(U256::from_str_radix("37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6", 16).unwrap());
        let s = Fp::new(U256::from_str_radix("8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec", 16).unwrap());
        
        let signature = Signature::new(r, s);
        let der = signature.to_der();
        
        // DER 형식 검증
        assert_eq!(der[0], 0x30, "DER should start with 0x30 (SEQUENCE tag)");
        
        // 첫 번째 정수 (r)
        let r_start_index = 2;
        assert_eq!(der[r_start_index], 0x02, "r should start with 0x02 (INTEGER tag)");
        let r_len = der[r_start_index + 1] as usize;
        
        // r 값이 0x80 이상이면 패딩이 있어야 함
        let r_bytes: [u8; 32] = U256::from(r).to_be_bytes();
        if r_bytes[0] >= 0x80 {
            assert_eq!(der[r_start_index + 2], 0x00, "r should have 0x00 padding when first byte >= 0x80");
            assert_eq!(r_len, 33, "r length should be 33 when padded");
        } else {
            assert_eq!(r_len, 32, "r length should be 32 when not padded");
        }
        
        // 두 번째 정수 (s)
        let s_start_index = r_start_index + 2 + r_len;
        assert_eq!(der[s_start_index], 0x02, "s should start with 0x02 (INTEGER tag)");
        let s_len = der[s_start_index + 1] as usize;
        
        // s 값이 0x80 이상이면 패딩이 있어야 함
        let s_bytes: [u8; 32] = U256::from(s).to_be_bytes();
        if s_bytes[0] >= 0x80 {
            assert_eq!(der[s_start_index + 2], 0x00, "s should have 0x00 padding when first byte >= 0x80");
            assert_eq!(s_len, 33, "s length should be 33 when padded");
        } else {
            assert_eq!(s_len, 32, "s length should be 32 when not padded");
        }
        
        // 전체 길이 검증
        let total_length = der[1] as usize;
        assert_eq!(total_length, (r_len + s_len + 4), "Total length should match r_len + s_len + 4");
    }

    #[test]
    fn test_to_der_with_high_bit_values() {
        // 첫 바이트가 0x80 이상인 r, s 값으로 테스트 (패딩 필요)
        let r = Fp::new(U256::from_str_radix("ff206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6", 16).unwrap());
        let s = Fp::new(U256::from_str_radix("80a63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec", 16).unwrap());
        
        let signature = Signature::new(r, s);
        let der = signature.to_der();
        
        // DER 기본 구조 검증
        assert_eq!(der[0], 0x30, "DER should start with 0x30");
        
        // r 값 검증 (0xff로 시작하므로 패딩 필요)
        assert_eq!(der[2], 0x02, "r INTEGER tag");
        assert_eq!(der[3], 33, "r length should be 33 (with padding)");
        assert_eq!(der[4], 0x00, "r should have 0x00 padding");
        assert_eq!(der[5], 0xff, "r first data byte should be 0xff");
        
        // s 값 검증 (0x80으로 시작하므로 패딩 필요)
        let s_start = 2 + 2 + 33; // SEQUENCE header + r INTEGER header + r data
        assert_eq!(der[s_start], 0x02, "s INTEGER tag");
        assert_eq!(der[s_start + 1], 33, "s length should be 33 (with padding)");
        assert_eq!(der[s_start + 2], 0x00, "s should have 0x00 padding");
        assert_eq!(der[s_start + 3], 0x80, "s first data byte should be 0x80");
        
        // 전체 길이 검증
        assert_eq!(der[1], 33 + 33 + 4, "Total length should be 70");
    }

    #[test]
    fn test_to_der_with_low_bit_values() {
        // 첫 바이트가 0x80 미만인 r, s 값으로 테스트 (패딩 불필요)
        let r = Fp::new(U256::from_str_radix("37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6", 16).unwrap());
        let s = Fp::new(U256::from_str_radix("1ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec", 16).unwrap());
        
        let signature = Signature::new(r, s);
        let der = signature.to_der();
        
        // DER 기본 구조 검증
        assert_eq!(der[0], 0x30, "DER should start with 0x30");
        
        // r 값 검증 (0x37로 시작하므로 패딩 불필요)
        assert_eq!(der[2], 0x02, "r INTEGER tag");
        assert_eq!(der[3], 32, "r length should be 32 (no padding)");
        assert_eq!(der[4], 0x37, "r first data byte should be 0x37");
        
        // s 값 검증 (0x1c로 시작하므로 패딩 불필요)
        let s_start = 2 + 2 + 32; // SEQUENCE header + r INTEGER header + r data
        assert_eq!(der[s_start], 0x02, "s INTEGER tag");
        assert_eq!(der[s_start + 1], 32, "s length should be 32 (no padding)");
        assert_eq!(der[s_start + 2], 0x1c, "s first data byte should be 0x1c");
        
        // 전체 길이 검증
        assert_eq!(der[1], 32 + 32 + 4, "Total length should be 68");
    }

    #[test]
    fn test_to_der_mixed_padding() {
        // r은 패딩 필요, s는 패딩 불필요한 경우
        let r = Fp::new(U256::from_str_radix("ff206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6", 16).unwrap());
        let s = Fp::new(U256::from_str_radix("1ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec", 16).unwrap());
        
        let signature = Signature::new(r, s);
        let der = signature.to_der();
        
        // DER 기본 구조 검증
        assert_eq!(der[0], 0x30, "DER should start with 0x30");
        
        // r 값 검증 (패딩 필요)
        assert_eq!(der[2], 0x02, "r INTEGER tag");
        assert_eq!(der[3], 33, "r length should be 33 (with padding)");
        assert_eq!(der[4], 0x00, "r should have 0x00 padding");
        
        // s 값 검증 (패딩 불필요)
        let s_start = 2 + 2 + 33;
        assert_eq!(der[s_start], 0x02, "s INTEGER tag");
        assert_eq!(der[s_start + 1], 32, "s length should be 32 (no padding)");
        assert_eq!(der[s_start + 2], 0x1c, "s first data byte should be 0x1c");
        
        // 전체 길이 검증
        assert_eq!(der[1], 33 + 32 + 4, "Total length should be 69");
    }

    #[test]
    fn test_to_der_zero_values() {
        // r, s 모두 0인 경우 (극단적인 경우)
        let r = Fp::new(U256::ZERO);
        let s = Fp::new(U256::from(1u64)); // s는 0이면 안되므로 1로 설정
        
        let signature = Signature::new(r, s);
        let der = signature.to_der();
        
        // DER 기본 구조 검증
        assert_eq!(der[0], 0x30, "DER should start with 0x30");
        
        // r 값 검증 (모든 바이트가 0)
        assert_eq!(der[2], 0x02, "r INTEGER tag");
        assert_eq!(der[3], 32, "r length should be 32");
        assert_eq!(der[4], 0x00, "r first data byte should be 0x00");
        
        // s 값 검증
        let s_start = 2 + 2 + 32;
        assert_eq!(der[s_start], 0x02, "s INTEGER tag");
        assert_eq!(der[s_start + 1], 32, "s length should be 32");
        
        // s의 마지막 바이트가 1이어야 함
        let s_data_start = s_start + 2;
        for i in 0..31 {
            assert_eq!(der[s_data_start + i], 0x00, "s bytes except last should be 0x00");
        }
        assert_eq!(der[s_data_start + 31], 0x01, "s last byte should be 0x01");
    }

    #[test]
    fn test_to_der_with_specific_values() {
        // 사진에서 제공된 r, s 값을 사용한 테스트
        let r_hex = "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6";
        let s_hex = "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        
        let r = Fp::new(U256::from_str_radix(r_hex, 16).unwrap());
        let s = Fp::new(U256::from_str_radix(s_hex, 16).unwrap());
        
        let signature = Signature::new(r, s);
        let der = signature.to_der();
        
        // DER 형식의 기본 구조 검증
        assert_eq!(der[0], 0x30, "DER should start with 0x30 (SEQUENCE tag)");
        
        // r 값 검증 (0x37로 시작하므로 패딩 불필요)
        assert_eq!(der[2], 0x02, "r should start with 0x02 (INTEGER tag)");
        assert_eq!(der[3], 32, "r length should be 32 (no padding needed)");
        assert_eq!(der[4], 0x37, "r first byte should be 0x37");
        
        // s 값 검증 (0x8c로 시작하므로 패딩 필요)
        let s_start = 2 + 2 + 32; // SEQUENCE header + r header + r data
        assert_eq!(der[s_start], 0x02, "s should start with 0x02 (INTEGER tag)");
        assert_eq!(der[s_start + 1], 33, "s length should be 33 (padding needed)");
        assert_eq!(der[s_start + 2], 0x00, "s should have 0x00 padding");
        assert_eq!(der[s_start + 3], 0x8c, "s first data byte should be 0x8c");
        
        // 전체 길이 검증
        assert_eq!(der[1], 32 + 33 + 4, "Total length should be 69");
        
        // Python에서 출력한 예상 DER 인코딩 결과와 비교
        // 3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
        let expected = [
            0x30, 0x45, // SEQUENCE, length 69
            0x02, 0x20, // INTEGER, length 32 (r)
            0x37, 0x20, 0x6a, 0x06, 0x10, 0x99, 0x5c, 0x58,
            0x07, 0x49, 0x99, 0xcb, 0x97, 0x67, 0xb8, 0x7a,
            0xf4, 0xc4, 0x97, 0x8d, 0xb6, 0x8c, 0x06, 0xe8,
            0xe6, 0xe8, 0x1d, 0x28, 0x20, 0x47, 0xa7, 0xc6,
            0x02, 0x21, // INTEGER, length 33 (s with padding)
            0x00, 0x8c, 0xa6, 0x37, 0x59, 0xc1, 0x15, 0x7e,
            0xbe, 0xae, 0xc0, 0xd0, 0x3c, 0xec, 0xca, 0x11,
            0x9f, 0xc9, 0xa7, 0x5b, 0xf8, 0xe6, 0xd0, 0xfa,
            0x65, 0xc8, 0x41, 0xc8, 0xe2, 0x73, 0x8c, 0xda, 0xec
        ];
        
        // 실제 생성된 DER과 예상 결과 비교 (첫 71바이트만)
        let der_len = der[1] as usize + 2;
        assert_eq!(der_len, expected.len(), "DER length should match expected");
        
        for i in 0..expected.len() {
            assert_eq!(der[i], expected[i], 
                "Byte {} should be 0x{:02x}, but was 0x{:02x}", i, expected[i], der[i]);
        }
        
        println!("DER encoding test passed! Generated DER matches expected result.");
    }
}