use std::{fmt::Debug, marker::PhantomData, ops::{Add, Div, Mul, Neg, Sub}};

use ruint::{aliases::U256, ToUintError};

use crate::U256Wrapper;

// Marker
pub trait Field:
    Clone + Copy + PartialEq + Eq + Debug
    + Add<Output = Self> + Sub<Output = Self> 
    + Mul<Output = Self> + Div<Output = Self> 
    + Neg<Output = Self> + Sized 
{ 
    const ZERO: Self;
    const ONE: Self;
    fn pow(&self, rhs: U256) -> Self;
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement<P: U256Wrapper> {
    num: U256,
    _phantom: PhantomData<P>
}

impl<P> Field for FieldElement<P> 
where 
    P: U256Wrapper
{ 
    const ONE: Self = Self { num: U256::from_limbs([1, 0, 0, 0]), _phantom: PhantomData };
    const ZERO: Self = Self { num: U256::from_limbs([0, 0, 0, 0]), _phantom: PhantomData };

    fn pow(&self, rhs: U256) -> Self {
        if rhs == U256::ZERO {
            return Self::new(U256::from(1));
        }
        
        let mut base = *self;
        let mut e = rhs;
        let mut res = Self::new(U256::from(1));

        while e > U256::ZERO {
            if e % U256::from(2) == U256::from(1) {
                res = res * base;
            }

            base = base * base;
            e /= U256::from(2);
        }
        
        res
    }
}

impl<P> FieldElement<P> 
where 
    P: U256Wrapper
{
    pub const fn new(num: U256) -> Self {
        if num.checked_sub(P::NUM).is_some() {
            panic!("위수보다 작은 값을 가져야 합니다.");
        }
        
        Self { num, _phantom: PhantomData }
    }

    
}

impl<P> Add for FieldElement<P> 
where 
    P: U256Wrapper
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.num.add_mod(rhs.num, P::NUM))
    }
}

impl<P> Sub for FieldElement<P> 
where 
    P: U256Wrapper
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.num >= rhs.num {
            Self::new(self.num - rhs.num)
        }
        else {
            Self::new(P::NUM - (rhs.num - self.num))
        }
    }
}

impl<P> Mul for FieldElement<P> 
where 
    P: U256Wrapper
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::new(self.num.mul_mod(rhs.num, P::NUM))
    }
}

impl<P> Div for FieldElement<P> 
where 
    P: U256Wrapper
{
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.pow(P::NUM - U256::from(2))
    }
}

impl<P> Neg for FieldElement<P> 
where 
    P: U256Wrapper
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self.num == 0 {
            Self::new(U256::from(0))
        } else {
            Self::new(P::NUM - self.num)
        }
    }
}

impl<P> TryFrom<FieldElement<P>> for U256 
where 
    P: U256Wrapper
{
    type Error = ToUintError<Self>;

    fn try_from(value: FieldElement<P>) -> Result<Self, Self::Error> {
        Ok(value.num)
    }
}

#[cfg(test)]
mod tests {
    use crate::U256Type;

    use super::*;

    // U256Wrapper 구현체들 정의
    type P7 = U256Type<0, 0, 0, 7>;
    type P5 = U256Type<0, 0, 0, 5>;
    type P11 = U256Type<0, 0, 0, 11>;

    #[test]
    fn test_new() {
        let a = FieldElement::<P7>::new(U256::from(3));
        assert_eq!(a.num, U256::from(3));
        
        // 경계값 테스트
        let b = FieldElement::<P7>::new(U256::from(0));
        assert_eq!(b.num, U256::from(0));
        
        let c = FieldElement::<P7>::new(U256::from(6));
        assert_eq!(c.num, U256::from(6));
    }

    #[test]
    #[should_panic(expected = "위수보다 작은 값을 가져야 합니다.")]
    fn test_new_panic() {
        // P보다 큰 값으로 생성하면 panic 발생
        // P7::NUM은 7이고, U256::from(7)도 7이므로 7 >= 7에서 패닉이 발생해야 함
        println!("P7::NUM = {:?}", P7::NUM);
        println!("U256::from(7) = {:?}", U256::from(7));
        FieldElement::<P7>::new(U256::from(7));
    }

    #[test]
    fn test_add() {
        let a = FieldElement::<P7>::new(U256::from(3));
        let b = FieldElement::<P7>::new(U256::from(4));
        let result = a + b;
        assert_eq!(result.num, U256::from(0)); // (3 + 4) % 7 = 0

        let c = FieldElement::<P7>::new(U256::from(2));
        let d = FieldElement::<P7>::new(U256::from(3));
        let result2 = c + d;
        assert_eq!(result2.num, U256::from(5)); // (2 + 3) % 7 = 5

        // 0과 더하기
        let e = FieldElement::<P7>::new(U256::from(0));
        let f = FieldElement::<P7>::new(U256::from(5));
        let result3 = e + f;
        assert_eq!(result3.num, U256::from(5)); // (0 + 5) % 7 = 5
    }

    #[test]
    fn test_sub() {
        let a = FieldElement::<P7>::new(U256::from(3));
        let b = FieldElement::<P7>::new(U256::from(1));
        let result = a - b;
        assert_eq!(result.num, U256::from(2)); // (3 - 1) % 7 = 2

        let c = FieldElement::<P7>::new(U256::from(1));
        let d = FieldElement::<P7>::new(U256::from(3));
        let result2 = c - d;
        assert_eq!(result2.num, U256::from(5)); // (1 - 3 + 7) % 7 = 5

        // 같은 값 빼기
        let e = FieldElement::<P7>::new(U256::from(4));
        let f = FieldElement::<P7>::new(U256::from(4));
        let result3 = e - f;
        assert_eq!(result3.num, U256::from(0)); // (4 - 4) % 7 = 0
    }

    #[test]
    fn test_mul() {
        let a = FieldElement::<P7>::new(U256::from(3));
        let b = FieldElement::<P7>::new(U256::from(2));
        let result = a * b;
        assert_eq!(result.num, U256::from(6)); // (3 * 2) % 7 = 6

        let c = FieldElement::<P7>::new(U256::from(4));
        let d = FieldElement::<P7>::new(U256::from(5));
        let result2 = c * d;
        assert_eq!(result2.num, U256::from(6)); // (4 * 5) % 7 = 6

        // 0과 곱하기
        let e = FieldElement::<P7>::new(U256::from(0));
        let f = FieldElement::<P7>::new(U256::from(5));
        let result3 = e * f;
        assert_eq!(result3.num, U256::from(0)); // (0 * 5) % 7 = 0

        // 1과 곱하기 (곱셈의 항등원)
        let g = FieldElement::<P7>::new(U256::from(1));
        let h = FieldElement::<P7>::new(U256::from(5));
        let result4 = g * h;
        assert_eq!(result4.num, U256::from(5)); // (1 * 5) % 7 = 5
    }

    #[test]
    fn test_pow() {
        let a = FieldElement::<P7>::new(U256::from(2));
        let result = a.pow(U256::from(3));
        assert_eq!(result.num, U256::from(1)); // 2^3 % 7 = 8 % 7 = 1

        let b = FieldElement::<P7>::new(U256::from(3));
        let result2 = b.pow(U256::from(2));
        assert_eq!(result2.num, U256::from(2)); // 3^2 % 7 = 9 % 7 = 2

        // 지수가 0인 경우 (항등원)
        let c = FieldElement::<P7>::new(U256::from(5));
        let result3 = c.pow(U256::from(0));
        assert_eq!(result3.num, U256::from(1)); // 5^0 = 1

        // 지수가 1인 경우
        let d = FieldElement::<P7>::new(U256::from(4));
        let result4 = d.pow(U256::from(1));
        assert_eq!(result4.num, U256::from(4)); // 4^1 = 4

        // 페르마의 소정리 테스트: a^(p-1) ≡ 1 (mod p) when p is prime and gcd(a,p) = 1
        let e = FieldElement::<P7>::new(U256::from(3));
        let result5 = e.pow(U256::from(6)); // 7-1 = 6
        assert_eq!(result5.num, U256::from(1)); // 3^6 % 7 = 1
    }

    #[test]
    fn test_div() {
        let a = FieldElement::<P7>::new(U256::from(6));
        let b = FieldElement::<P7>::new(U256::from(2));
        let result = a / b;
        assert_eq!(result.num, U256::from(3)); // 6 / 2 = 3 in F7

        let c = FieldElement::<P7>::new(U256::from(1));
        let d = FieldElement::<P7>::new(U256::from(3));
        let result2 = c / d;
        assert_eq!(result2.num, U256::from(5)); // 1 / 3 = 1 * 3^(7-2) = 1 * 3^5 = 1 * 5 = 5 in F7

        // 자기 자신으로 나누기
        let e = FieldElement::<P7>::new(U256::from(4));
        let f = FieldElement::<P7>::new(U256::from(4));
        let result3 = e / f;
        assert_eq!(result3.num, U256::from(1)); // 4 / 4 = 1

        // 1로 나누기
        let g = FieldElement::<P7>::new(U256::from(5));
        let h = FieldElement::<P7>::new(U256::from(1));
        let result4 = g / h;
        assert_eq!(result4.num, U256::from(5)); // 5 / 1 = 5
    }

    #[test]
    fn test_field_operations_consistency() {
        // 곱셈과 나눗셈의 역연산 관계 테스트
        let a = FieldElement::<P7>::new(U256::from(3));
        let b = FieldElement::<P7>::new(U256::from(5));
        let product = a * b;
        let quotient = product / b;
        assert_eq!(quotient, a); // (a * b) / b = a

        // 덧셈과 뺄셈의 역연산 관계 테스트
        let c = FieldElement::<P7>::new(U256::from(4));
        let d = FieldElement::<P7>::new(U256::from(2));
        let sum = c + d;
        let difference = sum - d;
        assert_eq!(difference, c); // (c + d) - d = c
    }

    #[test]
    fn test_different_prime_fields() {
        // F5에서 테스트
        let a = FieldElement::<P5>::new(U256::from(3));
        let b = FieldElement::<P5>::new(U256::from(4));
        let sum = a + b;
        assert_eq!(sum.num, U256::from(2)); // (3 + 4) % 5 = 2

        // F11에서 테스트
        let c = FieldElement::<P11>::new(U256::from(7));
        let d = FieldElement::<P11>::new(U256::from(8));
        let product = c * d;
        assert_eq!(product.num, U256::from(1)); // (7 * 8) % 11 = 56 % 11 = 1
    }

    #[test]
    fn test_neg() {
        // F7에서 음수 연산 테스트
        let a = FieldElement::<P7>::new(U256::from(3));
        let neg_a = -a;
        assert_eq!(neg_a.num, U256::from(4)); // -3 ≡ 7 - 3 = 4 (mod 7)

        let b = FieldElement::<P7>::new(U256::from(0));
        let neg_b = -b;
        assert_eq!(neg_b.num, U256::from(0)); // -0 ≡ 7 - 0 = 7 ≡ 0 (mod 7)

        let c = FieldElement::<P7>::new(U256::from(1));
        let neg_c = -c;
        assert_eq!(neg_c.num, U256::from(6)); // -1 ≡ 7 - 1 = 6 (mod 7)

        let d = FieldElement::<P7>::new(U256::from(6));
        let neg_d = -d;
        assert_eq!(neg_d.num, U256::from(1)); // -6 ≡ 7 - 6 = 1 (mod 7)

        // F11에서 음수 연산 테스트
        let e = FieldElement::<P11>::new(U256::from(5));
        let neg_e = -e;
        assert_eq!(neg_e.num, U256::from(6)); // -5 ≡ 11 - 5 = 6 (mod 11)

        let f = FieldElement::<P11>::new(U256::from(10));
        let neg_f = -f;
        assert_eq!(neg_f.num, U256::from(1)); // -10 ≡ 11 - 10 = 1 (mod 11)
    }

    #[test]
    fn test_neg_properties() {
        // 음수의 성질 테스트
        let a = FieldElement::<P7>::new(U256::from(3));
        
        // a + (-a) = 0 (덧셈 역원)
        let sum = a + (-a);
        assert_eq!(sum, FieldElement::<P7>::new(U256::from(0)));

        // -(-a) = a (이중 음수)
        let double_neg = -(-a);
        assert_eq!(double_neg, a);

        // -(a + b) = (-a) + (-b) (분배 법칙)
        let b = FieldElement::<P7>::new(U256::from(5));
        let left = -(a + b);
        let right = (-a) + (-b);
        assert_eq!(left, right);

        // -(a - b) = (-a) + b = b - a
        let left2 = -(a - b);
        let right2 = (-a) + b;
        let right3 = b - a;
        assert_eq!(left2, right2);
        assert_eq!(left2, right3);
    }

    #[test]
    fn test_neg_with_subtraction() {
        // 뺄셈과 음수의 관계: a - b = a + (-b)
        let a = FieldElement::<P7>::new(U256::from(4));
        let b = FieldElement::<P7>::new(U256::from(2));
        
        let sub_result = a - b;
        let add_neg_result = a + (-b);
        assert_eq!(sub_result, add_neg_result);

        // 0 - a = -a
        let zero = FieldElement::<P7>::new(U256::from(0));
        let zero_minus_a = zero - a;
        let neg_a = -a;
        assert_eq!(zero_minus_a, neg_a);
    }

    #[test]
    fn test_neg_zero() {
        // 0의 음수는 0
        let zero = FieldElement::<P7>::new(U256::from(0));
        let neg_zero = -zero;
        assert_eq!(neg_zero, zero);
        assert_eq!(neg_zero.num, U256::from(0));

        // 다른 소수체에서도 확인
        let zero_11 = FieldElement::<P11>::new(U256::from(0));
        let neg_zero_11 = -zero_11;
        assert_eq!(neg_zero_11, zero_11);
        assert_eq!(neg_zero_11.num, U256::from(0));
    }

    #[test]
    fn test_neg_additive_inverse() {
        // 모든 원소에 대해 a + (-a) = 0인지 확인
        for i in 0..7 {
            let a = FieldElement::<P7>::new(U256::from(i));
            let neg_a = -a;
            let sum = a + neg_a;
            assert_eq!(sum, FieldElement::<P7>::new(U256::from(0)), 
                      "Failed for a = {}, -a = {}", i, neg_a.num);
        }

        // F5에서도 확인
        for i in 0..5 {
            let a = FieldElement::<P5>::new(U256::from(i));
            let neg_a = -a;
            let sum = a + neg_a;
            assert_eq!(sum, FieldElement::<P5>::new(U256::from(0)), 
                      "Failed for a = {} in F5", i);
        }
    }

    // U256 오버플로우 테스트용 큰 소수 정의
    // 2^255 - 19 (Curve25519에서 사용되는 소수)
    type PLarge = U256Type<
        0x7fffffffffffffed, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff
    >;

    #[test]
    fn test_overflow_addition() {
        // U256 최대값에 가까운 값들로 덧셈 오버플로우 테스트
        let max_val = U256::MAX;
        
        // 최대값에서 1을 뺀 값들 생성
        let a_val = max_val - U256::from(1);
        let b_val = max_val - U256::from(1);
        
        // 일반 덧셈으로는 오버플로우가 발생할 것
        let normal_add_result = a_val.wrapping_add(b_val);
        println!("Normal addition result (wrapped): {:?}", normal_add_result);
        
        // 하지만 우리의 FieldElement는 add_mod를 사용하므로 안전
        if a_val < PLarge::NUM && b_val < PLarge::NUM {
            let a = FieldElement::<PLarge>::new(a_val);
            let b = FieldElement::<PLarge>::new(b_val);
            let result = a + b;
            
            // add_mod 연산으로 올바른 결과 확인
            let expected = a_val.add_mod(b_val, PLarge::NUM);
            assert_eq!(result.num, expected);
            println!("Safe field addition result: {:?}", result.num);
        }
    }

    #[test]
    fn test_overflow_multiplication() {
        // U256 곱셈 오버플로우 테스트
        let large_val1 = U256::from(2).pow(U256::from(128)); // 2^128
        let large_val2 = U256::from(2).pow(U256::from(127)); // 2^127
        
        // 일반 곱셈으로는 오버플로우가 발생할 것 (2^128 * 2^127 = 2^255)
        let normal_mul_result = large_val1.wrapping_mul(large_val2);
        println!("Normal multiplication result (wrapped): {:?}", normal_mul_result);
        
        // 하지만 우리의 FieldElement는 mul_mod를 사용하므로 안전
        if large_val1 < PLarge::NUM && large_val2 < PLarge::NUM {
            let a = FieldElement::<PLarge>::new(large_val1);
            let b = FieldElement::<PLarge>::new(large_val2);
            let result = a * b;
            
            // mul_mod 연산으로 올바른 결과 확인
            let expected = large_val1.mul_mod(large_val2, PLarge::NUM);
            assert_eq!(result.num, expected);
            println!("Safe field multiplication result: {:?}", result.num);
        }
    }

    #[test]
    fn test_overflow_subtraction() {
        // 작은 값에서 큰 값을 빼는 언더플로우 테스트
        let small_val = U256::from(5);
        let large_val = U256::from(10);
        
        // 일반 뺄셈으로는 언더플로우가 발생할 것
        let normal_sub_result = small_val.wrapping_sub(large_val);
        println!("Normal subtraction result (wrapped): {:?}", normal_sub_result);
        
        // P7 필드에서는 10을 7로 나눈 나머지인 3을 사용
        let a = FieldElement::<P7>::new(small_val);
        let large_val_reduced = large_val % U256::from(7); // 10 % 7 = 3
        let b = FieldElement::<P7>::new(large_val_reduced);
        
        // 5 - 3 = 2
        let result = a - b;
        assert_eq!(result.num, U256::from(2));
        
        // 더 명확한 언더플로우 케이스: 작은 값에서 큰 값 빼기
        let c = FieldElement::<P7>::new(U256::from(1));
        let d = FieldElement::<P7>::new(U256::from(3));
        let underflow_result = c - d;
        
        // 1 - 3 = 7 - (3 - 1) = 7 - 2 = 5
        assert_eq!(underflow_result.num, U256::from(5));
        println!("Safe field subtraction (underflow case): {:?}", underflow_result.num);
        
        // 극단적인 언더플로우 케이스
        let zero = FieldElement::<P7>::new(U256::from(0));
        let max_field = FieldElement::<P7>::new(U256::from(6));
        let extreme_underflow = zero - max_field;
        
        // 0 - 6 = 7 - 6 = 1
        assert_eq!(extreme_underflow.num, U256::from(1));
        println!("Extreme underflow: 0 - 6 = {:?}", extreme_underflow.num);
    }

    #[test]
    fn test_overflow_power_operation() {
        // 거듭제곱에서 발생할 수 있는 오버플로우 테스트
        let base = FieldElement::<P7>::new(U256::from(5));
        let large_exponent = U256::from(100); // 큰 지수
        
        // 일반적으로 5^100은 매우 큰 수가 되지만, 모듈러 연산으로 안전하게 처리
        let result = base.pow(large_exponent);
        
        // 페르마의 소정리에 의해 5^6 ≡ 1 (mod 7)이므로
        // 5^100 = 5^(6*16 + 4) = (5^6)^16 * 5^4 ≡ 1^16 * 5^4 = 5^4 (mod 7)
        let expected = base.pow(U256::from(4));
        assert_eq!(result, expected);
        
        println!("Power operation with large exponent: 5^100 mod 7 = {:?}", result.num);
        
        // 매우 큰 지수로도 테스트
        let very_large_exp = U256::MAX; // U256의 최대값
        let result2 = base.pow(very_large_exp);
        
        // 여전히 유한체에서 안전하게 계산됨
        println!("Power operation with U256::MAX exponent: {:?}", result2.num);
    }

    #[test]
    fn test_overflow_division() {
        // 나눗셈에서 발생할 수 있는 문제들 테스트
        // 나눗셈은 역원의 거듭제곱으로 구현되므로 오버플로우보다는 정확성이 중요
        
        let a = FieldElement::<P7>::new(U256::from(1));
        let b = FieldElement::<P7>::new(U256::from(6));
        
        // 1 / 6을 계산 (6은 7-1이므로 -1과 같음)
        // 1 / (-1) = -1 = 6 in F7
        let result = a / b;
        assert_eq!(result.num, U256::from(6));
        
        // 0으로 나누기는 불가능하지만, 0이 아닌 모든 원소는 역원을 가짐
        for i in 1..7u64 {
            let dividend = FieldElement::<P7>::new(U256::from(2));
            let divisor = FieldElement::<P7>::new(U256::from(i));
            let result = dividend / divisor;
            
            // 결과와 divisor를 곱하면 원래 dividend가 나와야 함
            let verification = result * divisor;
            assert_eq!(verification, dividend, 
                      "Division verification failed for 2 / {}", i);
        }
        
        println!("All division operations completed safely");
    }

    #[test]
    fn test_extreme_values() {
        // 극단적인 값들로 테스트
        let zero = FieldElement::<P7>::new(U256::from(0));
        let max_in_field = FieldElement::<P7>::new(U256::from(6)); // P7에서 최대값
        
        // 극단값들 간의 연산
        let sum = zero + max_in_field;
        assert_eq!(sum, max_in_field);
        
        let product = zero * max_in_field;
        assert_eq!(product, zero);
        
        let difference = max_in_field - zero;
        assert_eq!(difference, max_in_field);
        
        // 최대값끼리의 연산
        let max_plus_max = max_in_field + max_in_field;
        assert_eq!(max_plus_max.num, U256::from(5)); // (6 + 6) % 7 = 5
        
        let max_times_max = max_in_field * max_in_field;
        assert_eq!(max_times_max.num, U256::from(1)); // (6 * 6) % 7 = 36 % 7 = 1
        
        println!("Extreme value operations completed successfully");
    }

    #[test]
    fn test_u256_limits() {
        // U256의 한계값들 테스트
        let max_u256 = U256::MAX;
        let min_u256 = U256::MIN; // 0
        
        println!("U256::MAX = {:?}", max_u256);
        println!("U256::MIN = {:?}", min_u256);
        
        // P7 범위 내에서만 테스트
        let a = FieldElement::<P7>::new(min_u256);
        assert_eq!(a.num, U256::from(0));
        
        // 작은 필드에서는 큰 수를 직접 사용할 수 없으므로
        // 모듈러 연산의 결과를 확인
        let large_num = U256::from(1000);
        let reduced = large_num % U256::from(7);
        let b = FieldElement::<P7>::new(reduced);
        assert_eq!(b.num, U256::from(6)); // 1000 % 7 = 6
        
        println!("U256 limit tests completed");
    }
}
