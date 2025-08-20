use std::{fmt::Debug, marker::PhantomData, ops::{Add, Div, Mul, Neg, Sub}};

use ruint::aliases::U256;

use super::{U256Wrapper};

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
        Self::new((self.num + rhs.num) % P::NUM)
    }
}

impl<P> Sub for FieldElement<P> 
where 
    P: U256Wrapper
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::new((self.num + P::NUM - rhs.num) % P::NUM)
    }
}

impl<P> Mul for FieldElement<P> 
where 
    P: U256Wrapper
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::new((self.num * rhs.num) % P::NUM)
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


#[cfg(test)]
mod tests {
    use super::*;

    // U256Wrapper 구현체들 정의
    type P7 = super::super::U256Type<7, 0, 0, 0>;
    type P5 = super::super::U256Type<5, 0, 0, 0>;
    type P11 = super::super::U256Type<11, 0, 0, 0>;

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
}
