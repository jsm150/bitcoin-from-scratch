mod elliptic_curve;

use std::ops::Deref;

use rand::Rng;
use ruint::aliases::U256;

use crate::{U256Type, U256Wrapper};

pub use elliptic_curve::{CurvePoint, Fp};

type P = U256Type<0xFFFFFFFF_FFFFFFFF, 
    0xFFFFFFFF_FFFFFFFF, 
    0xFFFFFFFF_FFFFFFFF, 
    0xFFFFFFFE_FFFFFC2F>;

type N = U256Type<0xFFFFFFFF_FFFFFFFF, 
    0xFFFFFFFF_FFFFFFFE, 
    0xBAAEDCE6_AF48A03B, 
    0xBFD25E8C_D0364141>;

type GX = U256Type<0x79BE667E_F9DCBBAC, 
    0x55A06295_CE870B07, 
    0x029BFCDB_2DCE28D9, 
    0x59F2815B_16F81798>;

type GY = U256Type<0x483ADA77_26A3C465, 
    0x5DA4FBFC_0E1108A8, 
    0xFD17B448_A6855419, 
    0x9C47D08F_FB10D4B8>;

type A = U256Type<0, 0, 0, 0>;
type B = U256Type<0, 0, 0, 7>;

pub type Secp256k1 = CurvePoint<P, A, B>;

impl Default for Secp256k1 {
    fn default() -> Self {
        Self::new(Fp::new(GX::NUM), Fp::new(GY::NUM))
    }
}

pub struct Signature {
    r: Fp<N>,
    s: Fp<N>,
}

impl Signature {
    fn new(r: Fp<N>, s: Fp<N>) -> Self {
        Self { r, s }
    }

    pub fn build(z: Fp<N>, secret_key: Fp<N>) -> Self {
        let (k, r) = (0..).find_map(|_| {
            let k = Fp::new(rand::thread_rng().r#gen::<U256>() % N::NUM);

            match Secp256k1::default() * k {
                elliptic_curve::CurvePoint::Point { 
                    x, .. 
                } => Some((k, Fp::<N>::from(x))),
                _ => None,
            }
            
        }).unwrap();

        let mut s = (z + r * secret_key) / k;
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

#[derive(Debug)]
pub enum PublicKeyBuildErr {
    NotAllowInfinity
}

#[derive(Debug)]
pub enum PublicKeyDeserializationErr {
    NotUncompressSec,
    NotCompressSec
}

pub struct PublicKey(Secp256k1);

impl PublicKey {

    pub fn build(key: Secp256k1) -> Result<Self, PublicKeyBuildErr> {
        if let Secp256k1::Infinity = key {
            Err(PublicKeyBuildErr::NotAllowInfinity)
        }
        else {
            Ok(PublicKey(key))
        }
    }

    pub fn to_uncompress_sec(&self) -> [u8; 65] {
        let mut sec = [0_u8; 65];
        sec[..1].copy_from_slice(&[4]);

        if let Secp256k1::Point { x, y, .. } = self.0 {
            let x_bytes: [u8; 32] = U256::from(x).to_be_bytes();
            sec[1..33].clone_from_slice(&x_bytes);

            let y_bytes: [u8; 32] = U256::from(y).to_be_bytes();
            sec[33..].clone_from_slice(&y_bytes);
        }
        
        sec
    }

    pub fn to_compress_sec(&self) -> [u8; 33] {
        let mut sec = [0_u8; 33];
        
        if let Secp256k1::Point { x, y, .. } = self.0 {
            if U256::from(y) % U256::from(2) == 0 {
                sec[..1].copy_from_slice(&[2]);
            }
            else {
                sec[..1].copy_from_slice(&[3]);
            }

            let x_bytes: [u8; 32] = U256::from(x).to_be_bytes();
            sec[1..].clone_from_slice(&x_bytes);

        }

        sec
    }
}

impl TryFrom<[u8; 65]> for PublicKey {
    type Error = PublicKeyDeserializationErr;

    fn try_from(sec: [u8; 65]) -> Result<Self, Self::Error> {
        if sec[..1] != [4] {
            return Err(PublicKeyDeserializationErr::NotUncompressSec)
        }

        let x = U256::from_be_slice(&sec[1..33]);
        let y = U256::from_be_slice(&sec[33..]);

        Ok(Self::build(Secp256k1::new(Fp::new(x), Fp::new(y))).unwrap())
    }
}

impl TryFrom<[u8; 33]> for PublicKey {
    type Error = PublicKeyDeserializationErr;

    fn try_from(sec: [u8; 33]) -> Result<Self, Self::Error> {
        if sec[..1] != [3] && sec[..1] != [2] {
            return Err(PublicKeyDeserializationErr::NotCompressSec);
        }

        let x = U256::from_be_slice(&sec[1..]);
        let fp_x = Fp::<P>::new(x);
        let mut y = 
            (fp_x.pow(U256::from(3)) + Fp::new(B::NUM)).pow((P::NUM + U256::from(1)) / U256::from(4));

        let is_even = U256::from(y) % U256::from(2) == U256::ZERO;
        

        if !is_even && sec[..1] == [2] || is_even && sec[..1] == [3] {
            y = Fp::new(U256::ZERO) - y;
        }
        
        Ok(Self::build(Secp256k1::new(fp_x, y)).unwrap())
    }
}


impl Deref for PublicKey {
    type Target = Secp256k1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_curve_equation() {
        // Secp256k1 곡선 방정식 검증: y² = x³ + 7 (mod p)
        let p = P::NUM;
        let gx = GX::NUM;
        let gy = GY::NUM;
        
        // 직접 모듈러 연산으로 확인
        let y_squared = gy.mul_mod(gy, p);
        let x_cubed = gx.mul_mod(gx, p).mul_mod(gx, p);
        let right_side = x_cubed.add_mod(U256::from(7), p);
        
        assert_eq!(y_squared, right_side, "Generator point should be on the curve");
    }

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
        assert!(signature.verify(Fp::new(z), PublicKey::build(pk).unwrap()), "First signature should be valid");

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
        
        assert!(signature1.verify(Fp::new(z1), PublicKey::build(pk).unwrap()), "Second image first signature should be valid");
        
        // 두 번째 이미지의 두 번째 서명
        let z2_hex = "0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d";
        let r2_hex = "0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c";
        let s2_hex = "0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
        
        let z2 = U256::from_str_radix(&z2_hex[2..], 16).unwrap();
        let r2 = U256::from_str_radix(&r2_hex[2..], 16).unwrap();
        let s2 = U256::from_str_radix(&s2_hex[2..], 16).unwrap();
        
        let signature2 = Signature::new(Fp::new(r2), Fp::new(s2));
        
        assert!(signature2.verify(Fp::new(z2), PublicKey::build(pk).unwrap()), "Second image second signature should be valid");

        // 잘못된 서명 검증
        let z_invalid_hex = "0xdeadbeef";
        let z_invalid = U256::from_str_radix(&z_invalid_hex[2..], 16).unwrap();
        let signature_invalid = Signature::new(Fp::new(r2), Fp::new(s2));

        assert!(!signature_invalid.verify(Fp::new(z_invalid), PublicKey::build(pk).unwrap()), "Invalid signature should fail validation");
    }

    #[test]
    fn test_signature_build() {
        // 테스트용 개인키와 메시지 해시
        let secret_key = Fp::new(U256::from(12345u64));
        let z = Fp::new(U256::from(67890u64));
        
        // 서명 생성
        let signature = Signature::build(z, secret_key);
        
        // 공개키 계산 (G * secret_key)
        let g = Secp256k1::default();
        let public_key = g * U256::from(secret_key);
        
        // 생성된 서명이 유효한지 검증
        assert!(signature.verify(z, PublicKey::build(public_key).unwrap()), "Generated signature should be valid");
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
            let signature = Signature::build(z, secret_key);
            
            assert!(signature.verify(z, PublicKey::build(public_key).unwrap()), 
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
            let signature = Signature::build(z, secret_key);
            assert!(signature.verify(z, PublicKey::build(public_key).unwrap()), 
                "Each generated signature should be valid");
        }
    }

    #[test]
    fn test_signature_build_with_large_values() {
        // 큰 값들로 테스트
        let secret_key = Fp::new(U256::from_str_radix("129797975587483456789abcdef", 16).unwrap());
        let z = Fp::new(U256::from_str_radix("fedcba987645486748654554321", 16).unwrap());
        
        let signature = Signature::build(z, secret_key);
        
        let g = Secp256k1::default();
        let public_key = g * U256::from(secret_key);
        
        assert!(signature.verify(z, PublicKey::build(public_key).unwrap()), 
            "Signature with large values should be valid");
    }

    #[test]
    fn test_publickey_uncompress_sec() {
        // 알려진 Generator 포인트로 테스트
        let px_hex = "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let py_hex = "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
        
        let px = U256::from_str_radix(&px_hex[2..], 16).unwrap();
        let py = U256::from_str_radix(&py_hex[2..], 16).unwrap();
        
        let point = Secp256k1::new(Fp::new(px), Fp::new(py));
        let public_key = PublicKey::build(point).unwrap();
        
        let uncompressed = public_key.to_uncompress_sec();
        
        // 첫 번째 바이트는 0x04여야 함 (비압축 형식)
        assert_eq!(uncompressed[0], 0x04);
        
        // 전체 길이는 65바이트여야 함
        assert_eq!(uncompressed.len(), 65);
        
        // x 좌표 확인 (바이트 1-32)
        let x_bytes_expected: [u8; 32] = px.to_be_bytes();
        assert_eq!(&uncompressed[1..33], &x_bytes_expected);
        
        // y 좌표 확인 (바이트 33-64)
        let y_bytes_expected: [u8; 32] = py.to_be_bytes();
        assert_eq!(&uncompressed[33..65], &y_bytes_expected);
    }

    #[test]
    fn test_publickey_uncompress_sec_multiple_keys() {
        // 여러 개인키로 생성된 공개키의 SEC 형식 테스트
        let test_private_keys = [1u64, 2, 123, 999, 123456789];
        
        let g = Secp256k1::default();
        
        for &private_key in &test_private_keys {
            let secret_key = U256::from(private_key);
            let point = g * secret_key;
            
            if let Secp256k1::Point { x, y, .. } = point {
                let public_key = PublicKey::build(point).unwrap();
                let uncompressed = public_key.to_uncompress_sec();
                
                // 기본 형식 검증
                assert_eq!(uncompressed[0], 0x04);
                assert_eq!(uncompressed.len(), 65);
                
                // x, y 좌표가 올바르게 인코딩되었는지 확인
                let x_bytes_expected: [u8; 32] = U256::from(x).to_be_bytes();
                let y_bytes_expected: [u8; 32] = U256::from(y).to_be_bytes();
                
                assert_eq!(&uncompressed[1..33], &x_bytes_expected);
                assert_eq!(&uncompressed[33..65], &y_bytes_expected);
                
                println!("Private key {}: SEC format valid", private_key);
            } else {
                panic!("Expected a valid point for private key {}", private_key);
            }
        }
    }

    #[test]
    fn test_publickey_uncompress_sec_format_structure() {
        // SEC 비압축 형식의 구조적 특성 테스트
        let secret_key = U256::from(42u64);
        let g = Secp256k1::default();
        let point = g * secret_key;
        
        if let Secp256k1::Point { x, y, .. } = point {
            let public_key = PublicKey::build(point).unwrap();
            let uncompressed = public_key.to_uncompress_sec();
            
            // 1. Prefix 검증 (첫 번째 바이트는 0x04)
            assert_eq!(uncompressed[0], 0x04, "Prefix should be 0x04 for uncompressed format");
            
            // 2. 총 길이 검증 (1 + 32 + 32 = 65바이트)
            assert_eq!(uncompressed.len(), 65, "Total length should be 65 bytes");
            
            // 3. x 좌표 부분 검증 (바이트 1-32)
            let x_part = &uncompressed[1..33];
            let x_array: [u8; 32] = x_part.try_into().unwrap();
            let x_reconstructed = U256::from_be_bytes(x_array);
            assert_eq!(x_reconstructed, U256::from(x), "X coordinate should match");
            
            // 4. y 좌표 부분 검증 (바이트 33-64)
            let y_part = &uncompressed[33..65];
            let y_array: [u8; 32] = y_part.try_into().unwrap();
            let y_reconstructed = U256::from_be_bytes(y_array);
            assert_eq!(y_reconstructed, U256::from(y), "Y coordinate should match");
            
            // 5. 곡선 방정식 검증 (재구성된 좌표가 곡선 위에 있는지)
            let p = P::NUM;
            let y_squared = y_reconstructed.mul_mod(y_reconstructed, p);
            let x_cubed = x_reconstructed.mul_mod(x_reconstructed, p).mul_mod(x_reconstructed, p);
            let right_side = x_cubed.add_mod(U256::from(7), p);
            
            assert_eq!(y_squared, right_side, "Reconstructed point should be on the curve");
        } else {
            panic!("Expected a valid point");
        }
    }

    #[test]
    fn test_publickey_uncompress_sec_edge_cases() {
        // 경계 케이스들에 대한 테스트
        
        // 1. 매우 작은 개인키
        let small_key = U256::from(1u64);
        let g = Secp256k1::default();
        let point = g * small_key;
        
        if let Secp256k1::Point { .. } = point {
            let public_key = PublicKey::build(point).unwrap();
            let uncompressed = public_key.to_uncompress_sec();
            
            assert_eq!(uncompressed[0], 0x04);
            assert_eq!(uncompressed.len(), 65);
            
            // Generator 포인트와 같아야 함 (개인키가 1이므로)
            assert_eq!(point, g);
        }
        
        // 2. 큰 개인키
        let large_key = U256::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16).unwrap();
        let point = g * large_key;
        
        if let Secp256k1::Point { .. } = point {
            let public_key = PublicKey::build(point).unwrap();
            let uncompressed = public_key.to_uncompress_sec();
            
            assert_eq!(uncompressed[0], 0x04);
            assert_eq!(uncompressed.len(), 65);
        }
    }

    #[test]
    fn test_publickey_uncompress_sec_consistency() {
        // 동일한 공개키에 대해 여러 번 호출했을 때 일관된 결과를 반환하는지 테스트
        let secret_key = U256::from(314159u64);
        let g = Secp256k1::default();
        let point = g * secret_key;
        
        if let Secp256k1::Point { .. } = point {
            let public_key = PublicKey::build(point).unwrap();
            
            // 여러 번 호출하여 결과가 동일한지 확인
            let result1 = public_key.to_uncompress_sec();
            let result2 = public_key.to_uncompress_sec();
            let result3 = public_key.to_uncompress_sec();
            
            assert_eq!(result1, result2, "Multiple calls should return identical results");
            assert_eq!(result2, result3, "Multiple calls should return identical results");
            
            // 모든 결과가 올바른 형식인지 확인
            for result in [&result1, &result2, &result3] {
                assert_eq!(result[0], 0x04);
                assert_eq!(result.len(), 65);
            }
        }
    }

    #[test]
    fn test_publickey_compress_sec() {
        // 알려진 Generator 포인트로 테스트
        let px_hex = "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let py_hex = "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
        
        let px = U256::from_str_radix(&px_hex[2..], 16).unwrap();
        let py = U256::from_str_radix(&py_hex[2..], 16).unwrap();
        
        let point = Secp256k1::new(Fp::new(px), Fp::new(py));
        let public_key = PublicKey::build(point).unwrap();
        
        let compressed = public_key.to_compress_sec();
        
        // 총 길이는 33바이트여야 함
        assert_eq!(compressed.len(), 33);
        
        // y가 짝수인지 홀수인지 확인하여 prefix 검증
        let is_y_even = py % U256::from(2) == U256::ZERO;
        if is_y_even {
            assert_eq!(compressed[0], 0x02, "Y is even, prefix should be 0x02");
        } else {
            assert_eq!(compressed[0], 0x03, "Y is odd, prefix should be 0x03");
        }
        
        // x 좌표 확인 (바이트 1-32)
        let x_bytes_expected: [u8; 32] = px.to_be_bytes();
        assert_eq!(&compressed[1..33], &x_bytes_expected);
    }

    #[test]
    fn test_publickey_compress_sec_multiple_keys() {
        // 여러 개인키로 생성된 공개키의 압축 SEC 형식 테스트
        let test_private_keys = [1u64, 2, 123, 999, 123456789];
        
        let g = Secp256k1::default();
        
        for &private_key in &test_private_keys {
            let secret_key = U256::from(private_key);
            let point = g * secret_key;
            
            if let Secp256k1::Point { x, y, .. } = point {
                let public_key = PublicKey::build(point).unwrap();
                let compressed = public_key.to_compress_sec();
                
                // 기본 형식 검증
                assert_eq!(compressed.len(), 33);
                
                // prefix가 0x02 또는 0x03이어야 함
                assert!(compressed[0] == 0x02 || compressed[0] == 0x03, 
                    "Prefix should be 0x02 or 0x03");
                
                // y의 패리티와 prefix가 일치하는지 확인
                let is_y_even = U256::from(y) % U256::from(2) == U256::ZERO;
                if is_y_even {
                    assert_eq!(compressed[0], 0x02, "Even Y should have prefix 0x02");
                } else {
                    assert_eq!(compressed[0], 0x03, "Odd Y should have prefix 0x03");
                }
                
                // x 좌표가 올바르게 인코딩되었는지 확인
                let x_bytes_expected: [u8; 32] = U256::from(x).to_be_bytes();
                assert_eq!(&compressed[1..33], &x_bytes_expected);
                
                println!("Private key {}: Compressed SEC format valid", private_key);
            } else {
                panic!("Expected a valid point for private key {}", private_key);
            }
        }
    }

    #[test]
    fn test_publickey_compress_sec_consistency() {
        // 동일한 공개키에 대해 여러 번 호출했을 때 일관된 결과를 반환하는지 테스트
        let secret_key = U256::from(271828u64);
        let g = Secp256k1::default();
        let point = g * secret_key;
        
        if let Secp256k1::Point { .. } = point {
            let public_key = PublicKey::build(point).unwrap();
            
            // 여러 번 호출하여 결과가 동일한지 확인
            let result1 = public_key.to_compress_sec();
            let result2 = public_key.to_compress_sec();
            let result3 = public_key.to_compress_sec();
            
            assert_eq!(result1, result2, "Multiple calls should return identical results");
            assert_eq!(result2, result3, "Multiple calls should return identical results");
            
            // 모든 결과가 올바른 형식인지 확인
            for result in [&result1, &result2, &result3] {
                assert!(result[0] == 0x02 || result[0] == 0x03);
                assert_eq!(result.len(), 33);
            }
        }
    }

    #[test]
    fn test_publickey_from_compressed_sec() {
        // 압축된 SEC 형식에서 공개키 복원 테스트
        let test_cases = [
            (1u64, "Private key 1"),
            (2u64, "Private key 2"),
            (123u64, "Private key 123"),
            (999u64, "Private key 999"),
            (123456789u64, "Private key 123456789"),
        ];
        
        let g = Secp256k1::default();
        
        for &(private_key, desc) in &test_cases {
            let secret_key = U256::from(private_key);
            let original_point = g * secret_key;
            
            if let Secp256k1::Point { x: orig_x, y: orig_y, .. } = original_point {
                let original_public_key = PublicKey::build(original_point).unwrap();
                
                // 압축 형식으로 변환
                let compressed_sec = original_public_key.to_compress_sec();
                
                // 압축된 SEC에서 공개키 복원
                let restored_public_key = PublicKey::try_from(compressed_sec).unwrap();
                
                // 복원된 공개키가 원본과 동일한지 확인
                if let Secp256k1::Point { x: rest_x, y: rest_y, .. } = restored_public_key.0 {
                    assert_eq!(U256::from(orig_x), U256::from(rest_x), 
                        "{}: X coordinates should match", desc);
                    assert_eq!(U256::from(orig_y), U256::from(rest_y), 
                        "{}: Y coordinates should match", desc);
                } else {
                    panic!("{}: Restored public key should be a valid point", desc);
                }
                
                println!("{}: Compression and decompression successful", desc);
            } else {
                panic!("{}: Original point should be valid", desc);
            }
        }
    }

    #[test]
    fn test_publickey_from_compressed_sec_invalid_prefix() {
        // 잘못된 prefix로 압축 SEC 파싱 테스트
        let mut invalid_sec = [0u8; 33];
        
        // 유효하지 않은 prefix들 테스트
        let invalid_prefixes = [0x00, 0x01, 0x04, 0x05, 0xFF];
        
        for &prefix in &invalid_prefixes {
            invalid_sec[0] = prefix;
            // 나머지 바이트는 임의의 값으로 채움
            for i in 1..33 {
                invalid_sec[i] = (i as u8).wrapping_mul(17);
            }
            
            let result = PublicKey::try_from(invalid_sec);
            assert!(result.is_err(), "Should fail for invalid prefix: 0x{:02x}", prefix);
            
            if let Err(PublicKeyDeserializationErr::NotCompressSec) = result {
                // 예상된 에러
            } else {
                panic!("Should return NotCompressSec error for prefix: 0x{:02x}", prefix);
            }
        }
    }

    #[test]
    fn test_publickey_from_compressed_sec_valid_prefixes() {
        // 유효한 prefix (0x02, 0x03)로 테스트
        let g = Secp256k1::default();
        let original_point = g * U256::from(42u64);
        
        if let Secp256k1::Point { x, y, .. } = original_point {
            let x_bytes: [u8; 32] = U256::from(x).to_be_bytes();
            
            // 0x02 prefix 테스트 (짝수 y 가정)
            let mut compressed_sec_02 = [0u8; 33];
            compressed_sec_02[0] = 0x02;
            compressed_sec_02[1..].copy_from_slice(&x_bytes);
            
            let result_02 = PublicKey::try_from(compressed_sec_02);
            assert!(result_02.is_ok(), "Should succeed with 0x02 prefix");
            
            // 0x03 prefix 테스트 (홀수 y 가정)
            let mut compressed_sec_03 = [0u8; 33];
            compressed_sec_03[0] = 0x03;
            compressed_sec_03[1..].copy_from_slice(&x_bytes);
            
            let result_03 = PublicKey::try_from(compressed_sec_03);
            assert!(result_03.is_ok(), "Should succeed with 0x03 prefix");
            
            // 두 결과 중 하나는 원본 포인트와 일치해야 함
            let is_y_even = U256::from(y) % U256::from(2) == U256::ZERO;
            
            if is_y_even {
                if let Ok(pk_02) = result_02 {
                    if let Secp256k1::Point { y: restored_y, .. } = pk_02.0 {
                        assert_eq!(U256::from(y), U256::from(restored_y), 
                            "0x02 prefix should restore even Y correctly");
                    }
                }
            } else {
                if let Ok(pk_03) = result_03 {
                    if let Secp256k1::Point { y: restored_y, .. } = pk_03.0 {
                        assert_eq!(U256::from(y), U256::from(restored_y), 
                            "0x03 prefix should restore odd Y correctly");
                    }
                }
            }
        }
    }

    #[test]
    fn test_publickey_compress_decompress_roundtrip() {
        // 압축 -> 압축해제 라운드트립 테스트
        let test_private_keys = [
            1u64, 2, 7, 42, 123, 999, 12345, 123456789,
            0xDEADBEEFu64, 0xCAFEBABEu64
        ];
        
        let g = Secp256k1::default();
        
        for &private_key in &test_private_keys {
            let secret_key = U256::from(private_key);
            let original_point = g * secret_key;
            
            if let Secp256k1::Point { .. } = original_point {
                let original_public_key = PublicKey::build(original_point).unwrap();
                
                // 압축
                let compressed_sec = original_public_key.to_compress_sec();
                
                // 압축해제
                let restored_public_key = PublicKey::try_from(compressed_sec).unwrap();
                
                // 원본과 복원된 공개키가 동일한지 확인
                assert_eq!(original_public_key.0, restored_public_key.0,
                    "Roundtrip should preserve the public key for private key: {}", private_key);
                
                println!("Private key {}: Roundtrip test passed", private_key);
            } else {
                panic!("Expected valid point for private key: {}", private_key);
            }
        }
    }

    #[test]
    fn test_publickey_compress_vs_uncompress_length() {
        // 압축과 비압축 형식의 길이 차이 테스트
        let secret_key = U256::from(87654321u64);
        let g = Secp256k1::default();
        let point = g * secret_key;
        
        if let Secp256k1::Point { .. } = point {
            let public_key = PublicKey::build(point).unwrap();
            
            let uncompressed = public_key.to_uncompress_sec();
            let compressed = public_key.to_compress_sec();
            
            assert_eq!(uncompressed.len(), 65, "Uncompressed should be 65 bytes");
            assert_eq!(compressed.len(), 33, "Compressed should be 33 bytes");
            
            // 압축된 형식이 더 작아야 함
            assert!(compressed.len() < uncompressed.len(), 
                "Compressed format should be smaller than uncompressed");
            
            // prefix 차이 확인
            assert_eq!(uncompressed[0], 0x04, "Uncompressed prefix should be 0x04");
            assert!(compressed[0] == 0x02 || compressed[0] == 0x03, 
                "Compressed prefix should be 0x02 or 0x03");
            
            // x 좌표는 동일해야 함
            assert_eq!(&uncompressed[1..33], &compressed[1..33], 
                "X coordinates should be identical in both formats");
        }
    }

    #[test]
    fn test_publickey_from_uncompressed_sec() {
        // 비압축 SEC 형식에서 공개키 복원 테스트
        let test_private_keys = [1u64, 42u64, 12345u64];
        let g = Secp256k1::default();
        
        for &private_key in &test_private_keys {
            let secret_key = U256::from(private_key);
            let original_point = g * secret_key;
            
            if let Secp256k1::Point { .. } = original_point {
                let original_public_key = PublicKey::build(original_point).unwrap();
                
                // 비압축 형식으로 변환
                let uncompressed_sec = original_public_key.to_uncompress_sec();
                
                // 비압축 SEC에서 공개키 복원
                let restored_public_key = PublicKey::try_from(uncompressed_sec).unwrap();
                
                // 원본과 복원된 공개키가 동일한지 확인
                assert_eq!(original_public_key.0, restored_public_key.0,
                    "Uncompressed roundtrip should preserve the public key for private key: {}", private_key);
            }
        }
    }

    #[test]
    fn test_publickey_from_uncompressed_sec_invalid_prefix() {
        // 잘못된 prefix로 비압축 SEC 파싱 테스트
        let mut invalid_sec = [0u8; 65];
        
        // 유효하지 않은 prefix들 테스트 (0x04가 아닌 값들)
        let invalid_prefixes = [0x00, 0x01, 0x02, 0x03, 0x05, 0xFF];
        
        for &prefix in &invalid_prefixes {
            invalid_sec[0] = prefix;
            
            let result = PublicKey::try_from(invalid_sec);
            assert!(result.is_err(), "Should fail for invalid prefix: 0x{:02x}", prefix);
            
            if let Err(PublicKeyDeserializationErr::NotUncompressSec) = result {
                // 예상된 에러
            } else {
                panic!("Should return NotUncompressSec error for prefix: 0x{:02x}", prefix);
            }
        }
    }

    #[test]
    fn test_publickey_from_uncompressed_sec_valid_prefix() {
        // 유효한 prefix (0x04)로 비압축 SEC 테스트
        let g = Secp256k1::default();
        let point = g * U256::from(123u64);
        
        if let Secp256k1::Point { x, y, .. } = point {
            let mut valid_sec = [0u8; 65];
            valid_sec[0] = 0x04;
            
            let x_bytes: [u8; 32] = U256::from(x).to_be_bytes();
            let y_bytes: [u8; 32] = U256::from(y).to_be_bytes();
            
            valid_sec[1..33].copy_from_slice(&x_bytes);
            valid_sec[33..65].copy_from_slice(&y_bytes);
            
            let result = PublicKey::try_from(valid_sec);
            assert!(result.is_ok(), "Should succeed with valid 0x04 prefix and valid coordinates");
            
            if let Ok(restored_key) = result {
                assert_eq!(restored_key.0, point, "Restored key should match original point");
            }
        }
    }
}
