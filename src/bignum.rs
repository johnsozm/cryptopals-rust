use std::ops::{Neg, Add, Sub, AddAssign, SubAssign};
use std::cmp::Ordering;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BigNum {
    segments: Vec<u64>,
    neg: bool
}

impl BigNum {
    fn abs(&self) -> BigNum {
        BigNum {
            segments: self.segments.clone(),
            neg: false
        }
    }
}

impl From<u8> for BigNum {
    fn from(u: u8) -> BigNum {
        BigNum {
            segments: vec![u as u64],
            neg: false
        }
    }
}

impl From<u16> for BigNum {
    fn from(u: u16) -> BigNum {
        BigNum {
            segments: vec![u as u64],
            neg: false
        }
    }
}

impl From<u32> for BigNum {
    fn from(u: u32) -> BigNum {
        BigNum {
            segments: vec![u as u64],
            neg: false
        }
    }
}

impl From<u64> for BigNum {
    fn from(u: u64) -> BigNum {
        BigNum {
            segments: vec![u],
            neg: false
        }
    }
}

impl From<u128> for BigNum {
    fn from(u: u128) -> BigNum {
        BigNum {
            segments: vec![u as u64, (u >> 64) as u64],
            neg: false
        }
    }
}

impl From<usize> for BigNum {
    fn from(u: usize) -> BigNum {
        BigNum {
            segments: vec![u as u64],
            neg: false
        }
    }
}

impl From<i8> for BigNum {
    fn from(i: i8) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        BigNum {
            segments: vec![abs as u64],
            neg: i < 0
        }
    }
}

impl From<i16> for BigNum {
    fn from(i: i16) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        BigNum {
            segments: vec![abs as u64],
            neg: i < 0
        }
    }
}

impl From<i32> for BigNum {
    fn from(i: i32) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        BigNum {
            segments: vec![abs as u64],
            neg: i < 0
        }
    }
}

impl From<i64> for BigNum {
    fn from(i: i64) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        BigNum {
            segments: vec![abs as u64],
            neg: i < 0
        }
    }
}

impl From<i128> for BigNum {
    fn from(i: i128) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        BigNum {
            segments: vec![abs as u64, (abs >> 64) as u64],
            neg: i < 0
        }
    }
}

impl From<isize> for BigNum {
    fn from(i: isize) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        BigNum {
            segments: vec![abs as u64],
            neg: i < 0
        }
    }
}

impl Neg for BigNum {
    type Output = Self;

    fn neg(self) -> Self::Output {
        BigNum {
            segments: self.segments.clone(),
            neg: !self.neg
        }
    }
}

impl Neg for &BigNum {
    type Output = BigNum;

    fn neg(self) -> Self::Output {
        BigNum {
            segments: self.segments.clone(),
            neg: !self.neg
        }
    }
}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.neg ^ other.neg {
            return if self.neg {
                Some(Ordering::Less)
            } else {
                Some(Ordering::Greater)
            }
        }

        if self.segments.len() > other.segments.len() {
            return if self.neg {
                Some(Ordering::Less)
            }
            else {
                Some(Ordering::Greater)
            }
        }

        if self.segments.len() < other.segments.len() {
            return if self.neg {
                Some(Ordering::Greater)
            }
            else {
                Some(Ordering::Less)
            }
        }

        for i in (0..self.segments.len()).rev() {
            if self.segments[i] != other.segments[i] {
                return if (self.neg && self.segments[i] > other.segments[i])
                || (!self.neg && self.segments[i] < other.segments[i]) {
                    Some(Ordering::Less)
                }
                else {
                    Some(Ordering::Greater)
                }
            }
        }

        return Some(Ordering::Equal);
    }
}

impl Add for &BigNum {
    type Output = BigNum;

    fn add(self, rhs: Self) -> Self::Output {
        //Handle different signs by passing to subtraction routine
        if self.neg ^ rhs.neg {
            return if self.neg {
                rhs - &(-self)
            } else {
                self - &(-rhs)
            }
        }

        let mut carry: u128 = 0;
        let mut new_segments = vec![];

        for i in 0..usize::max(self.segments.len(), rhs.segments.len()) {
            let a: u128 = if i < self.segments.len() {self.segments[i] as u128} else {0};
            let b: u128 = if i < rhs.segments.len() {rhs.segments[i] as u128} else {0};

            carry = a + b + carry;
            new_segments.push(carry as u64);
            carry >>= 64;
        }

        if carry > 0 {
            new_segments.push(carry as u64);
        }

        return BigNum {
            segments: new_segments,
            neg: self.neg
        }
    }
}

impl AddAssign for BigNum {
    fn add_assign(&mut self, rhs: Self) {
        let result = &*self + &rhs;
        self.segments = result.segments.clone();
        self.neg = result.neg;
    }
}

impl Sub for &BigNum {
    type Output = BigNum;

    fn sub(self, rhs: Self) -> Self::Output {
        //Handle different signs by passing to addition routine
        if self.neg ^ rhs.neg {
            return self + &(-rhs)
        }

        //If we'll be running through zero, return the negative of the reciprocal subtraction
        if (self.neg && self > rhs) || (!self.neg && self < rhs) {
            return -(rhs - self);
        }

        let mut new_segments = vec![];
        let mut carry: i128 = 0;

        for i in 0..usize::max(self.segments.len(), rhs.segments.len()) {
            let a: i128 = if i < self.segments.len() {self.segments[i] as i128} else {0};
            let b: i128 = if i < rhs.segments.len() {rhs.segments[i] as i128} else {0};

            let mut tmp = carry + a - b;
            carry = 0;

            if tmp < 0 {
                tmp += u64::MAX as i128 + 1;
                carry -= 1;
            }

            new_segments.push(tmp as u64);
        }

        while new_segments.last() == Some(&0) {
            new_segments.pop();
        }

        return BigNum {
            segments: new_segments,
            neg: self.neg
        };
    }
}

impl SubAssign for BigNum {
    fn sub_assign(&mut self, rhs: Self) {
        let result = &*self - &rhs;
        self.segments = result.segments.clone();
        self.neg = result.neg;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u8() {
        let x = BigNum::from(8 as u8);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![8]);
    }

    #[test]
    fn test_from_u16() {
        let x = BigNum::from(512 as u16);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![512]);
    }

    #[test]
    fn test_from_u32() {
        let x = BigNum::from(128000 as u32);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![128000]);
    }

    #[test]
    fn test_from_u64() {
        let x = BigNum::from(8000000000 as u64);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![8000000000]);
    }

    #[test]
    fn test_from_u128() {
        let x = BigNum::from((1 as u128) << 64);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![0,1]);
    }

    #[test]
    fn test_from_usize() {
        let x = BigNum::from(19274 as usize);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![19274]);
    }

    #[test]
    fn test_from_i8() {
        let x = BigNum::from(8 as i8);
        let y = BigNum::from(-8 as i8);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![8]);
        assert_eq!(y.segments, vec![8]);
    }

    #[test]
    fn test_from_i16() {
        let x = BigNum::from(512 as i16);
        let y = BigNum::from(-512 as i16);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![512]);
        assert_eq!(y.segments, vec![512]);
    }

    #[test]
    fn test_from_i32() {
        let x = BigNum::from(128000 as i32);
        let y = BigNum::from(-128000 as i32);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![128000]);
        assert_eq!(y.segments, vec![128000]);
    }

    #[test]
    fn test_from_i64() {
        let x = BigNum::from(8000000000 as i64);
        let y = BigNum::from(-8000000000 as i64);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![8000000000]);
        assert_eq!(y.segments, vec![8000000000]);
    }

    #[test]
    fn test_from_i128() {
        let x = BigNum::from((1 as i128) << 64);
        let y = BigNum::from((-1 as i128) << 64);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![0,1]);
        assert_eq!(y.segments, vec![0,1]);
    }

    #[test]
    fn test_from_isize() {
        let x = BigNum::from(12974 as isize);
        let y = BigNum::from(-12974 as isize);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![12974]);
        assert_eq!(y.segments, vec![12974]);
    }

    #[test]
    fn test_comparison() {
        let a = BigNum::from(12);
        let b = BigNum::from(15);
        let c = BigNum::from((1 as u128) << 64);
        let d = BigNum::from(15);

        assert!(a < b);
        assert!(a <= b);
        assert!(b > a);
        assert!(b >= a);
        assert!(a < c);
        assert!(c >= b);
        assert!(b >= d);
        assert!(b <= d);
        assert_eq!(b, d);
    }

    #[test]
    fn test_comparison_signs() {
        let a = BigNum::from(-12);
        let b = BigNum::from(-14);
        let c = BigNum::from(-12);
        let d = BigNum::from(12);

        assert!(b < a);
        assert!(a >= b);
        assert!(c >= b);
        assert_eq!(a, c);
        assert_ne!(c, d);
    }

    #[test]
    fn test_neg() {
        let mut x = BigNum::from(92);
        x = -x;
        assert!(x.neg);
        x = -x;
        assert!(!x.neg);
    }

    #[test]
    fn test_add() {
        let a = BigNum::from(12);
        let b = BigNum::from(15);
        let c = BigNum::from(27);


        assert_eq!(&a + &b, c);
    }

    #[test]
    fn test_add_carry() {
        let a = BigNum::from(u64::MAX);
        let b = BigNum::from(2);
        let c = BigNum::from((u64::MAX as u128) + 2);
        assert_eq!(&a + &b, c);
    }

    #[test]
    fn test_add_negative() {
        let a = BigNum::from(-12);
        let b = BigNum::from(4);
        let c = BigNum::from(-4);
        let d = BigNum::from(-8);
        let e = BigNum::from(-16);

        assert_eq!(&a + &b, d);
        assert_eq!(&b + &a, d);
        assert_eq!(&a + &c, e);
        assert_eq!(&c + &a, e);
    }

    #[test]
    fn test_add_assign() {
        let mut a = BigNum::from(12);
        let b = BigNum::from(15);
        let c = BigNum::from(27);

        a += b;
        assert_eq!(a, c);
    }

    #[test]
    fn test_sub() {
        let a = BigNum::from(12);
        let b = BigNum::from(8);
        let c = BigNum::from(4);

        assert_eq!(&a - &b, c);
    }

    #[test]
    fn test_sub_carry() {
        let a = BigNum::from((1 as u128) << 64);
        let b = BigNum::from(1);
        let c = BigNum::from(u64::MAX);

        assert_eq!(&a - &b, c);
    }

    #[test]
    fn test_sub_negative() {
        let a = BigNum::from(-12);
        let b = BigNum::from(4);
        let c = BigNum::from(-4);
        let d = BigNum::from(-16);
        let e = BigNum::from(-8);
        let f = BigNum::from(12);

        assert_eq!(&a - &b, d);
        assert_eq!(&a - &c, e);
        assert_eq!(&b - &e, f);
        assert_eq!(&b - &f, e);
    }

    #[test]
    fn test_sub_assign() {
        let mut a = BigNum::from(12);
        let b = BigNum::from(15);
        let c = BigNum::from(-3);

        a -= b;
        assert_eq!(a, c);
    }
}