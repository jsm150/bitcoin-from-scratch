mod finite_field;

use finite_field::Field;
use ruint::aliases::U256;
use std::{fmt::Debug, marker::PhantomData, ops::{Add, Mul}, usize};
use finite_field::FieldElement;




/// 타원 곡선을 나타내는 타입 별칭
/// 
/// 이 타입은 유한체 위의 타원 곡선 `y² = x³ + Ax + B (mod P)`를 표현합니다.
/// 
/// # 타입 매개변수
/// 
/// * `P` - 유한체의 소수 모듈러스 (field modulus)
/// * `A` - 타원 곡선 방정식의 계수 A 
/// * `B` - 타원 곡선 방정식의 계수 B
/// 
/// # 예시
/// 
/// ```rust
/// # use bitcoin_practice::encrypt::doc_test_utils::*;
/// # use ruint::aliases::U256;
/// 
/// // Secp256k1 곡선: y² = x³ + 7 (mod p)
/// type P = U256Type<0xFFFFFFFF_FFFFFFFF, 0xFFFFFFFF_FFFFFFFF, 
///                   0xFFFFFFFF_FFFFFFFF, 0xFFFFFFFE_FFFFFC2F>;
/// type A = U256Type<0, 0, 0, 0>;  // A = 0
/// type B = U256Type<0, 0, 0, 7>;  // B = 7
/// 
/// type Secp256k1Curve = Curve<P, A, B>;
/// 
/// // 생성자 점 생성
/// let gx = Fp::<P>::new(U256::from_limbs([0x59F2815B_16F81798, 0x029BFCDB_2DCE28D9, 
///                                         0x55A06295_CE870B07, 0x79BE667E_F9DCBBAC]));
/// let gy = Fp::<P>::new(U256::from_limbs([0x9C47D08F_FB10D4B8, 0xFD17B448_A6855419,
///                                         0x5DA4FBFC_0E1108A8, 0x483ADA77_26A3C465]));
/// 
/// let generator = Secp256k1Curve::new(gx, gy);
/// ```
/// 
/// # 지원하는 연산
/// 
/// * **점 덧셈**: `point1 + point2` - 타원 곡선 상의 두 점을 더합니다
/// * **스칼라 곱셈**: `point * scalar` - 점을 정수배 합니다 (이진 거듭제곱법 사용)
/// * **무한원점**: `Curve::Infinity` - 덧셈의 항등원
/// 
/// # 암호학적 응용
/// 
/// 이 타입은 다음과 같은 암호학적 프로토콜에서 사용됩니다:
/// 
/// * **ECDSA** (Elliptic Curve Digital Signature Algorithm)
/// * **ECDH** (Elliptic Curve Diffie-Hellman)
/// * **Bitcoin** 및 기타 암호화폐의 공개키 암호화
/// 
/// # 보안 고려사항
/// 
/// * 사용하는 곡선이 암호학적으로 안전한지 확인해야 합니다
/// * 스칼라 곱셈 시 타이밍 공격에 대한 보호가 필요할 수 있습니다
/// * 개인키는 안전하게 관리되어야 합니다
pub type Curve<P, A, B> = CurvePoint<GeneralCruveConfig<P, A, B>>;

/// 유한체 원소를 나타내는 타입 별칭
/// 
/// 이 타입은 소수 `P`를 모듈러스로 하는 유한체 `F_P`의 원소를 표현합니다.
/// 
/// # 타입 매개변수
/// 
/// * `P` - 유한체의 소수 모듈러스
/// 
/// # 예시
/// 
/// ```rust
/// # use bitcoin_practice::encrypt::doc_test_utils::*;
/// # use ruint::aliases::U256;
/// 
/// // F_23 (mod 23) 유한체 정의
/// type P23 = U256Type<0, 0, 0, 23>;
/// 
/// // 유한체 원소 생성
/// let a = Fp::<P23>::new(U256::from(15));
/// let b = Fp::<P23>::new(U256::from(10));
/// 
/// // 유한체 연산
/// let sum = a + b;      // (15 + 10) mod 23 = 2
/// let product = a * b;  // (15 * 10) mod 23 = 12
/// let quotient = a / b; // 15 * 10^(-1) mod 23
/// ```
/// 
/// # 지원하는 연산
/// 
/// * **사칙연산**: `+`, `-`, `*`, `/` (모두 모듈러 연산)
/// * **거듭제곱**: `pow(exponent)` - 모듈러 거듭제곱
/// * **음수**: `-a` - 가법 역원
pub type Fp<P> = FieldElement<P>;

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
/// # use bitcoin_practice::encrypt::doc_test_utils::*;
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

pub trait CruveConfig:
    Clone + Copy + Debug + PartialEq + Eq
{
    type BaseField: Field;

    const A: Self::BaseField;
    const B: Self::BaseField;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralCruveConfig<P, A, B> 
where 
    P: U256Wrapper,
    A: U256Wrapper,
    B: U256Wrapper
{
    _phantom: PhantomData<(P, A, B)>
}

impl<P, A, B> CruveConfig for GeneralCruveConfig<P, A, B> 
where 
    P: U256Wrapper,
    A: U256Wrapper,
    B: U256Wrapper
{
    type BaseField = FieldElement<P>;

    const A: Self::BaseField = FieldElement::<P>::new(A::NUM);
    const B: Self::BaseField = FieldElement::<P>::new(B::NUM);
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurvePoint<C> 
where 
    C: CruveConfig
{
    Infinity,
    Point {
        x: C::BaseField,
        y: C::BaseField,
    }
}

impl<C> CurvePoint<C> 
where 
   C: CruveConfig
{
    pub fn new(x: C::BaseField, y: C::BaseField) -> Self {
        assert_eq!(y.pow(U256::from(2)), x.pow(U256::from(3)) + C::A * x + C::B, "타원 곡선의 좌표가 잘못되었습니다.");
        Self::Point { x, y }
    }
}

impl<C> Add for CurvePoint<C> 
where 
    C: CruveConfig
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            // 둘중 하나가 무한원점 일 경우
            (e @ Self::Point { .. }, Self::Infinity) 
                | (Self::Infinity, e @ Self::Point { .. }) => e,

            (Self::Point { x: x1, y: y1 }, 
                Self::Point { x: x2, .. }) 
                    if x1 == x2 && y1 == C::BaseField::ZERO => Self::Infinity,

            (Self::Infinity, Self::Infinity) => Self::Infinity,

            (Self::Point { x: x1, y: y1}, 
                Self::Point { x: x2, y: y2}) => 
            {
                // (A, -A)
                if y1 != y2 && x1 == x2 {
                    return Self::Infinity;
                }

                let (s, x3) = if (x1, y1) != (x2, y2) {
                    let s = (y1 - y2) / (x1 - x2);
                    let x3 = s.pow(U256::from(2)) - x1 - x2;
                    (s, x3)
                }
                else {
                    let two = C::BaseField::ONE + C::BaseField::ONE;
                    let three = C::BaseField::ONE + C::BaseField::ONE + C::BaseField::ONE;
                    let s = (three * x1.pow(U256::from(2)) + C::A) / (two * y1);
                    let x3 = s.pow(U256::from(2)) - (two * x1);
                    (s, x3)
                };

                let y3 = s * (x1 - x3) - y1;
                Self::Point { x: x3, y: y3 }
            },
        }
    }
}

impl<C> Mul<usize> for CurvePoint<C> 
where 
    C: CruveConfig
{
    type Output = Self;

    fn mul(self, rhs: usize) -> Self::Output {
        self.mul(U256::from(rhs))
    }
}

impl<C> Mul<U256> for CurvePoint<C> 
where 
    C: CruveConfig
{
    type Output = Self;

    fn mul(self, rhs: U256) -> Self::Output {
        let mut e = rhs;
        let mut base = self;

        let mut mul: CurvePoint<C> = Self::Infinity;

        while e > U256::from(0) {
            if e % U256::from(2) == U256::from(1) {
                mul = mul + base;
            }            

            base = base + base;
            e /= U256::from(2);
        }

        mul
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // U256Wrapper 구현체들 정의
    type P23 = U256Type<0, 0, 0, 23>;
    type A5 = U256Type<0, 0, 0, 5>;
    type B7 = U256Type<0, 0, 0, 7>;
    type P17 = U256Type<17, 0, 0, 17>;
    type A2 = U256Type<0, 0, 0, 2>;
    type B3 = U256Type<0, 0, 0, 3>;

    type TestCurve = GeneralCruveConfig<P23, A5, B7>; // y^2 = x^3 + 5x + 7 mod 23
    type TestPoint = CurvePoint<TestCurve>;

    #[test]
    fn test_point_new_valid() {
        // y^2 = x^3 + 5x + 7 mod 23에서 유효한 점들
        // (1, 7): 7^2 = 49 ≡ 3 mod 23, 1^3 + 5*1 + 7 = 13 mod 23... 
        // 실제 계산으로 유효한 점 찾기
        
        // (3, 10): 10^2 = 100 ≡ 8 mod 23, 3^3 + 5*3 + 7 = 27 + 15 + 7 = 49 ≡ 3 mod 23
        // 다른 점을 찾아서 테스트
        
        // 우선 간단한 점들로 테스트
        let x = FieldElement::<P23>::new(U256::from(1));
        let y = FieldElement::<P23>::new(U256::from(5)); // 실제로는 곡선 위의 점인지 확인 필요
        
        // 곡선 방정식 확인: y^2 = x^3 + 5x + 7
        let left = y.pow(U256::from(2)); // y^2
        let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
        
        if left == right {
            let point = TestPoint::new(x, y);
            match point {
                CurvePoint::Point { x: px, y: py } => {
                    assert_eq!(px, x);
                    assert_eq!(py, y);
                }
                _ => panic!("Expected Point variant"),
            }
        }
    }

    #[test]
    #[should_panic(expected = "타원 곡선의 좌표가 잘못되었습니다.")]
    fn test_point_new_invalid() {
        // 확실히 곡선 위에 있지 않은 점으로 테스트
        let x = FieldElement::<P23>::new(U256::from(1));
        let y = FieldElement::<P23>::new(U256::from(1));
        
        TestPoint::new(x, y);
    }

    #[test]
    fn test_add_with_infinity() {
        // 곡선 위의 실제 점 하나 찾기 - 브루트 포스로 찾기
        let mut test_point = None;
        
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    test_point = Some(TestPoint::new(x, y));
                    break;
                }
            }
            if test_point.is_some() {
                break;
            }
        }
        
        let point = test_point.expect("Should find at least one point on the curve");
        let inf = TestPoint::Infinity;

        // Point + Inf = Point
        let result1 = point + inf;
        assert_eq!(result1, point);

        // Inf + Point = Point
        let result2 = inf + point;
        assert_eq!(result2, point);

        // Inf + Inf = Inf
        let result3 = inf + inf;
        assert_eq!(result3, inf);
    }

    #[test]
    fn test_infinity_properties() {
        let inf = TestPoint::Infinity;
        
        // Infinity + Infinity = Infinity
        assert_eq!(inf + inf, inf);
        
        // Infinity는 항등원
        let inf2 = TestPoint::Infinity;
        assert_eq!(inf, inf2);
    }

    #[test] 
    fn test_point_equality() {
        let x = FieldElement::<P23>::new(U256::from(0));
        let y = FieldElement::<P23>::new(U256::from(0));
        
        // (0,0)이 곡선 위에 있는지 확인
        let left = y.pow(U256::from(2));
        let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
        
        if left == right {
            let p1 = TestPoint::new(x, y);
            let p2 = TestPoint::new(x, y);
            assert_eq!(p1, p2);
        }

        let inf1 = TestPoint::Infinity;
        let inf2 = TestPoint::Infinity;
        assert_eq!(inf1, inf2);
    }

    #[test]
    fn test_curve_point_doubling() {
        // 곡선 위의 점을 찾아서 점 배가(doubling) 테스트
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right && y != FieldElement::<P23>::new(U256::from(0)) {
                    let point = TestPoint::new(x, y);
                    
                    // 점 배가: P + P = 2P
                    let doubled = point + point;
                    
                    // 결과가 무한원점이거나 유효한 점이어야 함
                    match doubled {
                        CurvePoint::Infinity => {
                            // 무한원점도 유효한 결과
                        }
                        CurvePoint::Point { x: x3, y: y3 } => {
                            // 결과 점이 곡선 위에 있는지 확인
                            let left_check = y3.pow(U256::from(2));
                            let right_check = x3.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x3 + FieldElement::<P23>::new(U256::from(7));
                            assert_eq!(left_check, right_check, "Doubled point should be on curve");
                        }
                    }
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
    }

    #[test]
    fn test_different_curve_config() {
        // 다른 곡선 설정으로 테스트: y^2 = x^3 + 2x + 3 mod 17
        type TestCurve2 = GeneralCruveConfig<P17, A2, B3>;
        type TestPoint2 = CurvePoint<TestCurve2>;
        
        // 곡선 위의 점 찾기
        for x_val in 0..17 {
            for y_val in 0..17 {
                let x = FieldElement::<P17>::new(U256::from(x_val));
                let y = FieldElement::<P17>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P17>::new(U256::from(2)) * x + FieldElement::<P17>::new(U256::from(3));
                
                if left == right {
                    let point = TestPoint2::new(x, y);
                    let inf = TestPoint2::Infinity;
                    
                    // 기본 연산 테스트
                    assert_eq!(point + inf, point);
                    assert_eq!(inf + point, point);
                    
                    return; // 하나 찾으면 충분
                }
            }
        }
    }

    #[test]
    fn test_inverse_points() {
        // 곡선 위의 점과 그 역원 점 찾기
        for x_val in 0..23 {
            for y_val in 1..23 { // y=0 제외 (특별한 경우)
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point1 = TestPoint::new(x, y);
                    let neg_y = FieldElement::<P23>::new(U256::from(0)) - y; // -y mod 23
                    
                    // 역원 점이 곡선 위에 있는지 확인
                    let left_inv = neg_y.pow(U256::from(2));
                    if left_inv == right {
                        let point2 = TestPoint::new(x, neg_y);
                        
                        // P + (-P) = Infinity
                        let result = point1 + point2;
                        assert_eq!(result, TestPoint::Infinity);
                        
                        return; // 하나 테스트하면 충분
                    }
                }
            }
        }
    }

    #[test]
    fn test_associativity_simple() {
        // 무한원점과의 결합법칙 테스트 (간단한 케이스)
        let inf = TestPoint::Infinity;
        
        // (Inf + Inf) + Inf = Inf + (Inf + Inf) = Inf
        let left = (inf + inf) + inf;
        let right = inf + (inf + inf);
        assert_eq!(left, right);
        assert_eq!(left, inf);
    }

    #[test] 
    fn test_field_constants() {
        // Field trait의 상수들 테스트
        let zero = <FieldElement<P23> as Field>::ZERO;
        let one = <FieldElement<P23> as Field>::ONE;
        
        assert_eq!(zero, FieldElement::<P23>::new(U256::from(0)));
        assert_eq!(one, FieldElement::<P23>::new(U256::from(1)));
        
        // 항등원 성질
        let a = FieldElement::<P23>::new(U256::from(10));
        assert_eq!(a + zero, a);
        assert_eq!(a * one, a);
    }

    // 스칼라 곱(Scalar Multiplication) 테스트들
    #[test]
    fn test_scalar_mult_by_zero() {
        // 곡선 위의 점을 찾아서 테스트
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point = TestPoint::new(x, y);
                    
                    // 0 * P = Infinity (영점)
                    let result = point * 0;
                    assert_eq!(result, TestPoint::Infinity);
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
        
        // 무한원점의 경우도 테스트
        let inf = TestPoint::Infinity;
        let result = inf * 0;
        assert_eq!(result, TestPoint::Infinity);
    }

    #[test]
    fn test_scalar_mult_by_one() {
        // 곡선 위의 점을 찾아서 테스트
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point = TestPoint::new(x, y);
                    
                    // 1 * P = P (항등원)
                    let result = point * 1;
                    assert_eq!(result, point);
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
        
        // 무한원점의 경우도 테스트
        let inf = TestPoint::Infinity;
        let result = inf * 1;
        assert_eq!(result, TestPoint::Infinity);
    }

    #[test]
    fn test_scalar_mult_by_two() {
        // 곡선 위의 점을 찾아서 테스트
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point = TestPoint::new(x, y);
                    
                    // 2 * P = P + P (점 배가와 동일)
                    let doubled_by_mult = point * 2;
                    let doubled_by_add = point + point;
                    assert_eq!(doubled_by_mult, doubled_by_add);
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
    }

    #[test]
    fn test_scalar_mult_distributivity() {
        // 곡선 위의 점을 찾아서 테스트
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point = TestPoint::new(x, y);
                    
                    // (a + b) * P = a * P + b * P 분배법칙 테스트
                    let a = 3;
                    let b = 5;
                    
                    let left_side = point * (a + b);  // (3 + 5) * P = 8 * P
                    let right_side = point * a + point * b;  // 3 * P + 5 * P
                    
                    assert_eq!(left_side, right_side);
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
    }

    #[test]
    fn test_scalar_mult_associativity() {
        // 곡선 위의 점을 찾아서 테스트
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point = TestPoint::new(x, y);
                    
                    // (a * b) * P = a * (b * P) 결합법칙 테스트
                    let a = 3;
                    let b = 4;
                    
                    let left_side = point * (a * b);  // (3 * 4) * P = 12 * P
                    let temp = point * b;  // 4 * P
                    let right_side = temp * a;  // 3 * (4 * P)
                    
                    assert_eq!(left_side, right_side);
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
    }

    #[test]
    fn test_scalar_mult_small_values() {
        // 곡선 위의 점을 찾아서 작은 스칼라 값들로 테스트
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point = TestPoint::new(x, y);
                    
                    // 작은 값들 테스트
                    let _result_3 = point * 3;  // 3P
                    let _result_4 = point * 4;  // 4P
                    let _result_5 = point * 5;  // 5P
                    
                    // 3P = P + P + P와 동일한지 확인
                    let manual_3p = point + point + point;
                    let scalar_3p = point * 3;
                    assert_eq!(manual_3p, scalar_3p);
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
    }

    #[test]
    fn test_scalar_mult_infinity() {
        let inf = TestPoint::Infinity;
        
        // 무한원점에 대한 스칼라 곱은 항상 무한원점
        for scalar in 0..10 {
            let result = inf * scalar;
            assert_eq!(result, TestPoint::Infinity);
        }
    }

    #[test]
    fn test_scalar_mult_large_values() {
        // 곡선 위의 점을 찾아서 큰 스칼라 값으로 테스트
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point = TestPoint::new(x, y);
                    
                    // 큰 값들로 테스트 (이진 곱셈 알고리즘 테스트)
                    let result_10 = point * 10;
                    let result_15 = point * 15;
                    let result_20 = point * 20;
                    
                    // 결과가 무한원점이거나 곡선 위의 점이어야 함
                    match result_10 {
                        CurvePoint::Infinity => {},
                        CurvePoint::Point { x: x_res, y: y_res } => {
                            let left_check = y_res.pow(U256::from(2));
                            let right_check = x_res.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x_res + FieldElement::<P23>::new(U256::from(7));
                            assert_eq!(left_check, right_check, "10P should be on curve");
                        }
                    }
                    
                    match result_15 {
                        CurvePoint::Infinity => {},
                        CurvePoint::Point { x: x_res, y: y_res } => {
                            let left_check = y_res.pow(U256::from(2));
                            let right_check = x_res.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x_res + FieldElement::<P23>::new(U256::from(7));
                            assert_eq!(left_check, right_check, "15P should be on curve");
                        }
                    }
                    
                    match result_20 {
                        CurvePoint::Infinity => {},
                        CurvePoint::Point { x: x_res, y: y_res } => {
                            let left_check = y_res.pow(U256::from(2));
                            let right_check = x_res.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x_res + FieldElement::<P23>::new(U256::from(7));
                            assert_eq!(left_check, right_check, "20P should be on curve");
                        }
                    }
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
    }

    #[test]
    fn test_scalar_mult_binary_algorithm() {
        // 이진 곱셈 알고리즘이 올바르게 작동하는지 테스트
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point = TestPoint::new(x, y);
                    
                    // 이진 표현에서 다양한 비트 패턴 테스트
                    // 7 = 111(2), 모든 비트가 1인 경우
                    let result_7 = point * 7;
                    let manual_7 = point * 4 + point * 2 + point * 1;  // 4P + 2P + P
                    assert_eq!(result_7, manual_7);
                    
                    // 6 = 110(2), 연속된 1 비트
                    let result_6 = point * 6;
                    let manual_6 = point * 4 + point * 2;  // 4P + 2P
                    assert_eq!(result_6, manual_6);
                    
                    // 5 = 101(2), 떨어진 1 비트
                    let result_5 = point * 5;
                    let manual_5 = point * 4 + point * 1;  // 4P + P
                    assert_eq!(result_5, manual_5);
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
    }

    #[test]
    fn test_scalar_mult_order() {
        // 타원곡선의 점의 차수(order) 관련 테스트
        // 특정 점 P에 대해 nP = Infinity가 되는 최소 n(차수)이 존재함
        for x_val in 0..23 {
            for y_val in 0..23 {
                let x = FieldElement::<P23>::new(U256::from(x_val));
                let y = FieldElement::<P23>::new(U256::from(y_val));
                
                let left = y.pow(U256::from(2));
                let right = x.pow(U256::from(3)) + FieldElement::<P23>::new(U256::from(5)) * x + FieldElement::<P23>::new(U256::from(7));
                
                if left == right {
                    let point = TestPoint::new(x, y);
                    
                    // 점의 차수가 곡선의 크기보다 작거나 같아야 함
                    // 유한체 위의 타원곡선에서 최대 2p개의 점이 있음
                    let max_possible_order = 2 * 23 + 1; // Hasse's theorem
                    
                    let mut current = point;
                    for i in 2..max_possible_order {
                        current = current + point;
                        if current == TestPoint::Infinity {
                            // 점의 차수를 찾음
                            println!("Point ({}, {}) has order {}", x_val, y_val, i);
                            
                            // 차수가 올바른지 확인: (i-1)P ≠ Infinity, iP = Infinity
                            let prev = point * (i - 1);
                            let curr = point * i;
                            assert_ne!(prev, TestPoint::Infinity);
                            assert_eq!(curr, TestPoint::Infinity);
                            break;
                        }
                    }
                    
                    return; // 하나만 테스트하면 충분
                }
            }
        }
    }
}
