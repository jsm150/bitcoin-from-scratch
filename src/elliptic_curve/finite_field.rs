use std::{fmt::Debug, ops::{Add, Div, Mul, Neg, Sub}, usize};


// Marker
pub trait Field:
    Clone + Copy + PartialEq + Eq + Debug
    + Add<Output = Self> + Sub<Output = Self> 
    + Mul<Output = Self> + Div<Output = Self> 
    + Neg<Output = Self> + Sized 
{ 
    const ZERO: Self;
    const ONE: Self;
    fn pow(&self, rhs: i32) -> Self;
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement<const P: usize> {
    num: usize,
}

impl<const P: usize> Field for FieldElement<P> { 
    const ONE: Self = Self { num: 1 };
    const ZERO: Self = Self { num: 0 };

    fn pow(&self, rhs: i32) -> Self {
        let mut base = self.to_owned();
        let mut e: u32 = rhs.rem_euclid((P - 1) as i32) as u32;
        let mut res = Self::new(1);

        
        while e > 0 {
            if e % 2 == 1 {
                res = res * base;
            }

            base = base * base;
            e /= 2;
        }
        
        res
    }
}

impl<const P: usize> FieldElement<P> {
    pub const fn new(num: usize) -> Self {
        assert!(num < P);
        Self { num }
    }

    
}

impl<const P: usize> Add for FieldElement<P> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::new((self.num + rhs.num).rem_euclid(P))
    }
}

impl<const P: usize> Sub for FieldElement<P> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::new((self.num + P - rhs.num).rem_euclid(P))
    }
}

impl<const P: usize> Mul for FieldElement<P>  {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::new((self.num * rhs.num).rem_euclid(P))
    }
}

impl<const P: usize> Div for FieldElement<P> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.pow((P - 2) as i32)
    }
}

impl<const P: usize> Neg for FieldElement<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::new(P - self.num)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let a = FieldElement::<7>::new(3);
        assert_eq!(a.num, 3);
        
        // 경계값 테스트
        let b = FieldElement::<7>::new(0);
        assert_eq!(b.num, 0);
        
        let c = FieldElement::<7>::new(6);
        assert_eq!(c.num, 6);
    }

    #[test]
    #[should_panic]
    fn test_new_panic() {
        // P보다 큰 값으로 생성하면 panic 발생
        FieldElement::<7>::new(7);
    }

    #[test]
    fn test_add() {
        let a = FieldElement::<7>::new(3);
        let b = FieldElement::<7>::new(4);
        let result = a + b;
        assert_eq!(result.num, 0); // (3 + 4) % 7 = 0

        let c = FieldElement::<7>::new(2);
        let d = FieldElement::<7>::new(3);
        let result2 = c + d;
        assert_eq!(result2.num, 5); // (2 + 3) % 7 = 5

        // 0과 더하기
        let e = FieldElement::<7>::new(0);
        let f = FieldElement::<7>::new(5);
        let result3 = e + f;
        assert_eq!(result3.num, 5); // (0 + 5) % 7 = 5
    }

    #[test]
    fn test_sub() {
        let a = FieldElement::<7>::new(3);
        let b = FieldElement::<7>::new(1);
        let result = a - b;
        assert_eq!(result.num, 2); // (3 - 1) % 7 = 2

        let c = FieldElement::<7>::new(1);
        let d = FieldElement::<7>::new(3);
        let result2 = c - d;
        assert_eq!(result2.num, 5); // (1 - 3 + 7) % 7 = 5

        // 같은 값 빼기
        let e = FieldElement::<7>::new(4);
        let f = FieldElement::<7>::new(4);
        let result3 = e - f;
        assert_eq!(result3.num, 0); // (4 - 4) % 7 = 0
    }

    #[test]
    fn test_mul() {
        let a = FieldElement::<7>::new(3);
        let b = FieldElement::<7>::new(2);
        let result = a * b;
        assert_eq!(result.num, 6); // (3 * 2) % 7 = 6

        let c = FieldElement::<7>::new(4);
        let d = FieldElement::<7>::new(5);
        let result2 = c * d;
        assert_eq!(result2.num, 6); // (4 * 5) % 7 = 6

        // 0과 곱하기
        let e = FieldElement::<7>::new(0);
        let f = FieldElement::<7>::new(5);
        let result3 = e * f;
        assert_eq!(result3.num, 0); // (0 * 5) % 7 = 0

        // 1과 곱하기 (곱셈의 항등원)
        let g = FieldElement::<7>::new(1);
        let h = FieldElement::<7>::new(5);
        let result4 = g * h;
        assert_eq!(result4.num, 5); // (1 * 5) % 7 = 5
    }

    #[test]
    fn test_pow() {
        let a = FieldElement::<7>::new(2);
        let result = a.pow(3);
        assert_eq!(result.num, 1); // 2^3 % 7 = 8 % 7 = 1

        let b = FieldElement::<7>::new(3);
        let result2 = b.pow(2);
        assert_eq!(result2.num, 2); // 3^2 % 7 = 9 % 7 = 2

        // 지수가 0인 경우 (항등원)
        let c = FieldElement::<7>::new(5);
        let result3 = c.pow(0);
        assert_eq!(result3.num, 1); // 5^0 = 1

        // 지수가 1인 경우
        let d = FieldElement::<7>::new(4);
        let result4 = d.pow(1);
        assert_eq!(result4.num, 4); // 4^1 = 4

        // 페르마의 소정리 테스트: a^(p-1) ≡ 1 (mod p) when p is prime and gcd(a,p) = 1
        let e = FieldElement::<7>::new(3);
        let result5 = e.pow(6); // 7-1 = 6
        assert_eq!(result5.num, 1); // 3^6 % 7 = 1
    }

    #[test]
    fn test_div() {
        let a = FieldElement::<7>::new(6);
        let b = FieldElement::<7>::new(2);
        let result = a / b;
        assert_eq!(result.num, 3); // 6 / 2 = 3 in F7

        let c = FieldElement::<7>::new(1);
        let d = FieldElement::<7>::new(3);
        let result2 = c / d;
        assert_eq!(result2.num, 5); // 1 / 3 = 1 * 3^(7-2) = 1 * 3^5 = 1 * 5 = 5 in F7

        // 자기 자신으로 나누기
        let e = FieldElement::<7>::new(4);
        let f = FieldElement::<7>::new(4);
        let result3 = e / f;
        assert_eq!(result3.num, 1); // 4 / 4 = 1

        // 1로 나누기
        let g = FieldElement::<7>::new(5);
        let h = FieldElement::<7>::new(1);
        let result4 = g / h;
        assert_eq!(result4.num, 5); // 5 / 1 = 5
    }

    #[test]
    fn test_field_operations_consistency() {
        // 곱셈과 나눗셈의 역연산 관계 테스트
        let a = FieldElement::<7>::new(3);
        let b = FieldElement::<7>::new(5);
        let product = a * b;
        let quotient = product / b;
        assert_eq!(quotient, a); // (a * b) / b = a

        // 덧셈과 뺄셈의 역연산 관계 테스트
        let c = FieldElement::<7>::new(4);
        let d = FieldElement::<7>::new(2);
        let sum = c + d;
        let difference = sum - d;
        assert_eq!(difference, c); // (c + d) - d = c
    }

    #[test]
    fn test_different_prime_fields() {
        // F5에서 테스트
        let a = FieldElement::<5>::new(3);
        let b = FieldElement::<5>::new(4);
        let sum = a + b;
        assert_eq!(sum.num, 2); // (3 + 4) % 5 = 2

        // F11에서 테스트
        let c = FieldElement::<11>::new(7);
        let d = FieldElement::<11>::new(8);
        let product = c * d;
        assert_eq!(product.num, 1); // (7 * 8) % 11 = 56 % 11 = 1
    }
}
