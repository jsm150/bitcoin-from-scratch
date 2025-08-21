mod elliptic_curve;

use ruint::aliases::U256;

use crate::{U256Type, U256Wrapper};

pub use elliptic_curve::{Curve, Fp};

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

pub type Secp256k1 = Curve<P, A, B>;

impl Secp256k1 {
    pub const P: U256 = P::NUM;
    pub const N: U256 = N::NUM;
    
    pub const A: U256 = A::NUM;
    pub const B: U256 = B::NUM;

    pub const GX: Fp<P> = Fp::new(GX::NUM);
    pub const GY: Fp<P> = Fp::new(GY::NUM);
}

impl Default for Secp256k1 {
    fn default() -> Self {
        Self::new(Self::GX, Self::GY)
    }
}

pub struct Signature {
    z: Fp<N>,
    r: Fp<N>,
    s: Fp<N>,
    pk: Secp256k1
}

impl Signature {
    pub fn new(z: Fp<N>, rx: Fp<N>, s: Fp<N>, pk: Secp256k1) -> Self {
        Self { z, r: rx, s, pk }
    }
}

impl Signature {
    pub fn validate(&self) -> bool {
        // uG + vP = R
        // u = z / s, v = r / s
        
        let u = self.z / self.s;
        let v = self.r / self.s;
        let g = Secp256k1::default();
        let r = (g * U256::from(u)) + (self.pk * U256::from(v));

        if let Curve::Point { x: rx, .. } = r {
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


#[doc(hidden)]
pub mod doc_test_utils {
    pub use crate::encrypt::elliptic_curve::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_curve_equation() {
        // Secp256k1 곡선 방정식 검증: y² = x³ + 7 (mod p)
        let p = Secp256k1::P;
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

        // Fp 타입으로 변환
        
        // 공개키 포인트 생성
        let pk = Curve::Point { x: Fp::new(px), y: Fp::new(py) };
        
        // 서명 생성
        let signature = Signature::new(Fp::new(z), Fp::new(r), Fp::new(s), pk);
        
        // 서명 검증 - 유효한 서명이므로 true여야 함
        assert!(signature.validate(), "First signature should be valid");

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
        
        let pk = Curve::Point { x: Fp::new(px), y: Fp::new(py) };
        let signature1 = Signature::new(Fp::new(z1), Fp::new(r1), Fp::new(s1), pk);
        
        assert!(signature1.validate(), "Second image first signature should be valid");
        
        // 두 번째 이미지의 두 번째 서명
        let z2_hex = "0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d";
        let r2_hex = "0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c";
        let s2_hex = "0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
        
        let z2 = U256::from_str_radix(&z2_hex[2..], 16).unwrap();
        let r2 = U256::from_str_radix(&r2_hex[2..], 16).unwrap();
        let s2 = U256::from_str_radix(&s2_hex[2..], 16).unwrap();
        
        let signature2 = Signature::new(Fp::new(z2), Fp::new(r2), Fp::new(s2), pk);
        
        assert!(signature2.validate(), "Second image second signature should be valid");
    }
}
