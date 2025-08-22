mod elliptic_curve;
mod public_key;
mod signature;

use crate::{U256Type, U256Wrapper};

pub use elliptic_curve::{CurvePoint, Fp};
pub use public_key::PublicKey;
pub use signature::Signature;

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



#[cfg(test)]
mod tests {
    use ruint::aliases::U256;

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
}
