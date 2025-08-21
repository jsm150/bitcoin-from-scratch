pub mod encrypt;

use std::{fmt::Debug};

use ruint::aliases::U256;

pub trait U256Wrapper:
    Debug + Clone + Copy + PartialEq + Eq
{
    const NUM: U256;
}


/// U256을 const generic 파라미터로 사용하기 위한 래퍼 구조체
/// 
/// 4개의 u64 limbs를 Little Endian 순서로 저장합니다.
/// 
/// # 값 생성과 비교 예시
/// 
/// ```rust
/// # use bitcoin_practice::{U256Type, U256Wrapper};
/// # use ruint::aliases::U256;
/// 
/// // 작은 수 생성
/// type P23 = U256Type<0, 0, 0, 23>;  // 23을 표현
/// assert_eq!(P23::NUM, U256::from(23));
/// 
/// // 다른 수들과 비교
/// type P17 = U256Type<0, 0, 0, 17>;
/// type A5 = U256Type<0, 0, 0, 5>;
/// 
/// assert_eq!(P17::NUM, U256::from(17));
/// assert_eq!(A5::NUM, U256::from(5));
/// assert_ne!(P23::NUM, P17::NUM);  // 23 ≠ 17
/// 
/// // 큰 수 생성 (주의: 실제로는 매우 큰 값이 됨)
/// type BigNum = U256Type<1, 0, 0, 0>;
/// // BigNum::NUM은 2^192와 같은 매우 큰 수
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256Type<const B1: u64, const B2: u64, const B3: u64, const B4: u64>;
impl<const B1: u64, const B2: u64, const B3: u64, const B4: u64> U256Wrapper for U256Type<B1, B2, B3, B4> {
    const NUM: U256 = U256::from_limbs([B4, B3, B2, B1]);
}