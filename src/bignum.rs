use std::ops::{Neg, Add, Sub, AddAssign, SubAssign, Mul, MulAssign, Div, DivAssign, Rem, RemAssign};
use std::cmp::Ordering;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BigNum {
    pub segments: Vec<u8>,
    pub neg: bool
}

impl BigNum {
    ///Returns the absolute value of the number
    pub fn abs(&self) -> BigNum {
        BigNum {
            segments: self.segments.clone(),
            neg: false
        }
    }

    //Performs single-digit division of n / a
    fn quick_divide(n: &BigNum, a_digit: u16, num_zeros: usize) -> BigNum {
       let mut quotient_segments = vec![];
        let mut remainder: u16 = 0;

        for i in (0..n.segments.len()-num_zeros).rev() {
            remainder <<= 8;
            remainder += n.segments[i + num_zeros] as u16;

            let digit_div = remainder / a_digit;

            quotient_segments.push(digit_div as u8);
            remainder -= a_digit * digit_div;
        }

        quotient_segments.reverse();

        //Trim leading zeros
        while quotient_segments.len() > 1 && quotient_segments.last() == Some(&0) {
            quotient_segments.pop();
        }

        return BigNum {
            segments: quotient_segments,
            neg: n.neg
        };
    }

    ///Returns the quotient and modulus for this / divisor as the tuple (Q,M)
    pub fn quotient_modulus(&self, divisor: &BigNum) -> (BigNum, BigNum) {
        //Handle corner cases
        if divisor.segments == vec![0] {
            panic!("Attempted to divide by zero!");
        }
        if divisor.abs() > self.abs() {
            return (BigNum::from(0), self.clone());
        }

        //Ensure we are always doing +/+ division in the main loop to avoid issues
        if self.neg || divisor.neg {
            return if self.neg && divisor.neg {
                self.abs().quotient_modulus(&divisor.abs())
            } else if self.neg {
                let (q, r) = (-self).quotient_modulus(divisor);
                if r == BigNum::from(0) {
                    (-q, r)
                }
                else {
                    (-q, divisor - &r)
                }
            } else {
                let (q, r) = self.quotient_modulus(&-divisor);
                if r == BigNum::from(0) {
                    (-q, r)
                }
                else {
                    (-q, divisor - &r)
                }
            }
        }

        //Construct initial divisor A as MSD of divisor followed by all 0s
        let a_digit = divisor.segments[divisor.segments.len() - 1] as u16;
        let num_zeros = divisor.segments.len() - 1;

        let mut q = BigNum::quick_divide(self, a_digit, num_zeros);
        let mut r = divisor + &BigNum::from(1);

        while r.abs() >= *divisor {
            r = self - &(&q * divisor);
            let qn = &q + &BigNum::quick_divide(&r, a_digit, num_zeros);
            //Exact division by 2 instead of a quick-divide, slightly improves performance
            let mut new_seg = (&q + &qn).segments;
            for i in 0..new_seg.len() - 1 {
                new_seg[i] = (new_seg[i] >> 1) + (new_seg[i+1] << 7);
            }
            let last_index = new_seg.len() - 1;
            new_seg[last_index] >>= 1;

            q = BigNum {
                segments: new_seg,
                neg: q.neg
            };
        }

        r = self - &(&q * divisor);
        if r.neg {
            q -= BigNum::from(1);
            r = &r + divisor;
        }

        return (q, r);
    }

    pub fn modular_exponent(&self, exponent: &BigNum, modulus: &BigNum) -> BigNum {
        let mut working_exponent = exponent.segments.clone();
        let mut result = BigNum::from(1);
        let mut pow = self % modulus;

        while !working_exponent.is_empty() {
            println!("{}", working_exponent.len());
            if working_exponent[0] % 2 == 1 {
                result = &(&result * &pow) % modulus;
            }
            pow = &(&pow * &pow) % modulus;

            //Bit-shift exponent
            for i in 0..working_exponent.len() - 1 {
                working_exponent[i] = (working_exponent[i] >> 1) + ((working_exponent[i + 1] % 2) << 7);
            }

            let last_index = working_exponent.len() - 1;
            working_exponent[last_index] >>= 1;

            if working_exponent.last() == Some(&0) {
                working_exponent.pop();
            }
        }

        return result;
    }

    ///Returns a big-endian byte vector that encodes the absolute value of this number (no support for signed yet)
    pub fn to_unsigned_bytes(&self) -> Vec<u8> {
        let mut bytes = self.segments.clone();

        bytes.reverse();

        return bytes;
    }

    ///Returns the bit length of the number
    pub fn len_bits(&self) -> usize {
        let last_index = self.segments.len() - 1;
        let mut bits = last_index * 8;
        let mut high_digit = self.segments[last_index];

        while high_digit > 0 {
            bits += 1;
            high_digit >>= 1;
        }

        return bits;
    }

    ///Returns the byte length of the number
    pub fn len_bytes(&self) -> usize {
        if self.segments == vec![0] {
            return 0;
        }
        return self.segments.len();
    }
}

impl From<u8> for BigNum {
    fn from(u: u8) -> BigNum {
        BigNum {
            segments: vec![u],
            neg: false
        }
    }
}

impl From<u16> for BigNum {
    fn from(u: u16) -> BigNum {
        return BigNum::from(&u.to_be_bytes().to_vec());
    }
}

impl From<u32> for BigNum {
    fn from(u: u32) -> BigNum {
        return BigNum::from(&u.to_be_bytes().to_vec());
    }
}

impl From<u64> for BigNum {
    fn from(u: u64) -> BigNum {
        return BigNum::from(&u.to_be_bytes().to_vec());
    }
}

impl From<u128> for BigNum {
    fn from(u: u128) -> BigNum {
        return BigNum::from(&u.to_be_bytes().to_vec());
    }
}

impl From<usize> for BigNum {
    fn from(u: usize) -> BigNum {
        return BigNum::from(&u.to_be_bytes().to_vec());
    }
}

impl From<i8> for BigNum {
    fn from(i: i8) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        let ret = BigNum::from(&abs.to_be_bytes().to_vec());
        return if i < 0 {-ret} else {ret};
    }
}

impl From<i16> for BigNum {
    fn from(i: i16) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        let ret = BigNum::from(&abs.to_be_bytes().to_vec());
        return if i < 0 {-ret} else {ret};
    }
}

impl From<i32> for BigNum {
    fn from(i: i32) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        let ret = BigNum::from(&abs.to_be_bytes().to_vec());
        return if i < 0 {-ret} else {ret};
    }
}

impl From<i64> for BigNum {
    fn from(i: i64) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        let ret = BigNum::from(&abs.to_be_bytes().to_vec());
        return if i < 0 {-ret} else {ret};
    }
}

impl From<i128> for BigNum {
    fn from(i: i128) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        let ret = BigNum::from(&abs.to_be_bytes().to_vec());
        return if i < 0 {-ret} else {ret};
    }
}

impl From<isize> for BigNum {
    fn from(i: isize) -> BigNum {
        let abs = if i < 0 {-i} else {i};
        let ret = BigNum::from(&abs.to_be_bytes().to_vec());
        return if i < 0 {-ret} else {ret};
    }
}

impl From<&Vec<u8>> for BigNum {
    fn from(bytes: &Vec<u8>) -> Self {
        let mut segments = bytes.clone();
        segments.reverse();

        while segments.len() > 1 && segments.last() == Some(&0) {
            segments.pop();
        }

        return BigNum {
            segments,
            neg: false
        };
    }
}

//Neg is implemented for both BigNum and &BigNum to simplify optimization of other operations
impl Neg for BigNum {
    type Output = Self;

    fn neg(self) -> Self::Output {
        //Do not allow -0
        if self.segments == vec![0] {
            return self.clone();
        }

        BigNum {
            segments: self.segments.clone(),
            neg: !self.neg
        }
    }
}

//Neg is implemented for both BigNum and &BigNum to simplify optimization of other operations
impl Neg for &BigNum {
    type Output = BigNum;

    fn neg(self) -> Self::Output {
        //Do not allow -0
        if self.segments == vec![0] {
            return self.clone();
        }

        BigNum {
            segments: self.segments.clone(),
            neg: !self.neg
        }
    }
}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        //Fastest comparison is to check for mismatched signs
        if self.neg ^ other.neg {
            return if self.neg {
                Some(Ordering::Less)
            } else {
                Some(Ordering::Greater)
            }
        }

        //Next, check for mismatched number lengths to see if any direct comparison is needed
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

        //Only do the actual comparison if we have to
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
        //Handle sign issues when subtracting 0
        if rhs.segments == vec![0] {
            return self.clone();
        }

        //Handle different signs by passing to subtraction routine
        if self.neg ^ rhs.neg {
            return if self.neg {
                rhs - &(-self)
            } else {
                self - &(-rhs)
            }
        }

        let mut carry: u16 = 0;
        let mut new_segments = vec![];

        //Simple walk through numbers, adding like places and maintaining a carry value
        for i in 0..usize::max(self.segments.len(), rhs.segments.len()) {
            let a: u16 = if i < self.segments.len() {self.segments[i] as u16} else {0};
            let b: u16 = if i < rhs.segments.len() {rhs.segments[i] as u16} else {0};

            carry = a + b + carry;
            new_segments.push(carry as u8);
            carry >>= 8;
        }

        if carry > 0 {
            new_segments.push(carry as u8);
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
        //Handle sign issues when subtracting 0
        if rhs.segments == vec![0] {
            return self.clone();
        }

        //Handle different signs by passing to addition routine
        if self.neg ^ rhs.neg {
            return self + &(-rhs)
        }

        //If we'll be running through zero, return the negative of the reciprocal subtraction
        if (self.neg && self > rhs) || (!self.neg && self < rhs) {
            return -(rhs - self);
        }

        let mut new_segments = vec![];
        let mut carry: i16 = 0;

        //Walk through numbers, subtracting like places and borrowing as needed
        for i in 0..usize::max(self.segments.len(), rhs.segments.len()) {
            let a: i16 = if i < self.segments.len() {self.segments[i] as i16} else {0};
            let b: i16 = if i < rhs.segments.len() {rhs.segments[i] as i16} else {0};

            let mut tmp = carry + a - b;
            carry = 0;

            if tmp < 0 {
                tmp += 256;
                carry -= 1;
            }

            new_segments.push(tmp as u8);
        }

        while new_segments.len() > 1 && new_segments.last() == Some(&0) {
            new_segments.pop();
        }

        //Avoid -0
        let new_sign = if new_segments == vec![0] {false} else {self.neg};

        return BigNum {
            segments: new_segments,
            neg: new_sign
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

impl Mul for &BigNum {
    type Output = BigNum;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut partials = vec![];

        //For each digit[i] in self, construct the partial sum digit[i] * rhs << i
        for i in 0..self.segments.len() {
            let mut new_segments = vec![0;i];
            let mut carry: u16 = 0;

            for j in 0..rhs.segments.len() {
                carry = carry + ((self.segments[i] as u16) * (rhs.segments[j] as u16));
                new_segments.push(carry as u8);
                carry >>= 8;
            }

            if carry > 0 {
                new_segments.push(carry as u8);
            }

            //Handle any trailing zero values from zero multiplications
            while new_segments.len() > 1 && new_segments.last() == Some(&0) {
                new_segments.pop();
            }

            //Avoid -0
            let new_sign = if new_segments == vec![0] {false} else {self.neg ^ rhs.neg};

            partials.push(BigNum{
                segments: new_segments,
                neg: new_sign
            });
        }

        //Add up all partial sums to get a result
        let mut sum = BigNum::from(0);
        for p in partials {
            sum += p;
        }

        return sum;
    }
}

impl MulAssign for BigNum {
    fn mul_assign(&mut self, rhs: Self) {
        let result = &*self * &rhs;
        self.segments = result.segments.clone();
        self.neg = result.neg;
    }
}

impl Div for &BigNum {
    type Output = BigNum;

    fn div(self, rhs: Self) -> Self::Output {
        self.quotient_modulus(rhs).0
    }
}

impl DivAssign for BigNum {
    fn div_assign(&mut self, rhs: Self) {
        let result = self.quotient_modulus(&rhs).0;
        self.segments = result.segments.clone();
        self.neg = result.neg;
    }
}

impl Rem for &BigNum {
    type Output = BigNum;

    fn rem(self, rhs: Self) -> Self::Output {
        self.quotient_modulus(rhs).1
    }
}

impl RemAssign for BigNum {
    fn rem_assign(&mut self, rhs: Self) {
        let result = self.quotient_modulus(&rhs).1;
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
        assert_eq!(x.segments, vec![0, 2]);
    }

    #[test]
    fn test_from_u32() {
        let x = BigNum::from(128000 as u32);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![0x00, 0xf4, 0x01]);
    }

    #[test]
    fn test_from_u64() {
        let x = BigNum::from(8000000000 as u64);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![0x00, 0x50, 0xd6, 0xdc, 0x01]);
    }

    #[test]
    fn test_from_u128() {
        let x = BigNum::from((1 as u128) << 64);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_from_usize() {
        let x = BigNum::from(19274 as usize);
        assert!(!x.neg);
        assert_eq!(x.segments, vec![0x4a, 0x4b]);
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
        assert_eq!(x.segments, vec![0, 2]);
        assert_eq!(y.segments, vec![0, 2]);
    }

    #[test]
    fn test_from_i32() {
        let x = BigNum::from(128000 as i32);
        let y = BigNum::from(-128000 as i32);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![0x00, 0xf4, 0x01]);
        assert_eq!(y.segments, vec![0x00, 0xf4, 0x01]);
    }

    #[test]
    fn test_from_i64() {
        let x = BigNum::from(8000000000 as i64);
        let y = BigNum::from(-8000000000 as i64);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![0x00, 0x50, 0xd6, 0xdc, 0x01]);
        assert_eq!(y.segments, vec![0x00, 0x50, 0xd6, 0xdc, 0x01]);
    }

    #[test]
    fn test_from_i128() {
        let x = BigNum::from((1 as i128) << 64);
        let y = BigNum::from((-1 as i128) << 64);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(y.segments, vec![0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_from_isize() {
        let x = BigNum::from(12974 as isize);
        let y = BigNum::from(-12974 as isize);
        assert!(!x.neg);
        assert!(y.neg);
        assert_eq!(x.segments, vec![0xae, 0x32]);
        assert_eq!(y.segments, vec![0xae, 0x32]);
    }

    #[test]
    fn test_from_bytes() {
        let a = BigNum::from(0);
        let a_bytes = vec![0];
        let b = BigNum::from(128);
        let b_bytes = vec![128];
        let c = BigNum::from(1024);
        let c_bytes = vec![4, 0];
        let d = BigNum::from((1 as u128) << 64);
        let d_bytes = vec![1, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(BigNum::from(&a_bytes), a);
        assert_eq!(BigNum::from(&b_bytes), b);
        assert_eq!(BigNum::from(&c_bytes), c);
        assert_eq!(BigNum::from(&d_bytes), d);
    }

    #[test]
    fn test_to_unsigned_bytes() {
        let a = BigNum::from(0);
        let b = BigNum::from(12);
        let c = BigNum::from(1024);
        let d = BigNum::from((1 as u128) << 64);

        assert_eq!(a.to_unsigned_bytes(), vec![0]);
        assert_eq!(b.to_unsigned_bytes(), vec![12]);
        assert_eq!(c.to_unsigned_bytes(), vec![4, 0]);
        assert_eq!(d.to_unsigned_bytes(), vec![1, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        let d = BigNum::from(0);

        assert_eq!(&a - &b, c);
        assert_eq!(&a - &a, d);
    }

    #[test]
    fn test_sub_negative() {
        let a = BigNum::from(-12);
        let b = BigNum::from(4);
        let c = BigNum::from(-4);
        let d = BigNum::from(-16);
        let e = BigNum::from(-8);
        let f = BigNum::from(12);
        let g = BigNum::from(0);

        assert_eq!(&a - &b, d);
        assert_eq!(&a - &c, e);
        assert_eq!(&b - &e, f);
        assert_eq!(&b - &f, e);
        assert_eq!(&b - &b, g);
        assert_eq!(&c - &c, g);
    }

    #[test]
    fn test_sub_assign() {
        let mut a = BigNum::from(12);
        let b = BigNum::from(15);
        let c = BigNum::from(-3);

        a -= b;
        assert_eq!(a, c);
    }

    #[test]
    fn test_mul() {
        let a = BigNum::from(2);
        let b = BigNum::from(3);
        let c = BigNum::from(6);

        assert_eq!(&a * &b, c);
    }

    #[test]
    fn test_mul_rounding() {
        let a = BigNum::from(u64::MAX);
        let b = BigNum::from(4);
        let c = BigNum::from((u64::MAX as u128) << 2);
        let d = BigNum::from(0);

        assert_eq!(&a * &b, c);
        assert_eq!(&c * &d, d);
    }

    #[test]
    fn test_mul_negative() {
        let a = BigNum::from(3);
        let b = BigNum::from(-4);
        let c = BigNum::from(-3);
        let d = BigNum::from(12);
        let e = BigNum::from(-12);
        let f = BigNum::from(0);

        assert_eq!(&a * &b, e);
        assert_eq!(&b * &c, d);
        assert_eq!(&e * &f, f);
    }

    #[test]
    fn test_mul_assign() {
        let mut a = BigNum::from(3);
        let b = BigNum::from(6);
        let c = BigNum::from(18);

        a *= b;
        assert_eq!(a, c);
    }

    #[test]
    fn test_quick_divide() {
        let b = BigNum::from(1728);
        let c = BigNum::from(1730);
        let d = BigNum::from(288);

        assert_eq!(BigNum::quick_divide(&b, 6, 0), d);
        assert_eq!(BigNum::quick_divide(&c, 6, 0), d);
    }

    #[test]
    fn test_quotient_modulus() {
        let a = BigNum::from(15);
        let b = BigNum::from(3);
        let c = BigNum::from(4);
        let d = BigNum::from(5);
        let e = BigNum::from(0);
        let f = BigNum::from(1);

        assert_eq!(a.quotient_modulus(&b), (d.clone(), e.clone()));
        assert_eq!(a.quotient_modulus(&c), (b.clone(), b.clone()));
        assert_eq!(a.quotient_modulus(&f), (a.clone(), e.clone()));
    }

    #[test]
    fn test_quotient_modulus_large() {
        let a = BigNum::from(&vec![0xc5, 0xe1, 0x40, 0x80, 0x8b, 0xe9, 0xe1, 0x44, 0xbc, 0x8b, 0x96, 0x07, 0xe1, 0x78, 0xea, 0xb1, 0x25, 0xaf, 0x46, 0x87, 0x52, 0x01, 0x37, 0xc0]);
        let b = BigNum::from(&vec![0x80, 0xf9, 0x39, 0xff, 0x74, 0x86, 0x8f, 0x0a, 0xcb, 0xf4, 0x09, 0x05, 0x5f, 0x1d, 0x4d, 0x7d]);
        let quotient = BigNum::from(&vec![0x01, 0x88, 0xc5, 0xbe, 0x5c, 0xd8, 0xef, 0x11, 0x71]);
        let modulus = BigNum::from(&vec![0x37, 0xbd, 0xa7, 0x5c, 0x46, 0x3d, 0x74, 0x36, 0xfe, 0xdd, 0xcb, 0x2e, 0x94, 0x39, 0xb6, 0x93]);

        assert_eq!(a.quotient_modulus(&b), (quotient, modulus));
    }

    #[test]
    fn test_quotient_modulus_negative() {
        let a = BigNum::from(-6);
        let b = BigNum::from(3);
        let c = BigNum::from(-2);
        let d = BigNum::from(-7);
        let e = BigNum::from(0);
        let f = BigNum::from(2);
        let g = BigNum::from(1);

        assert_eq!(a.quotient_modulus(&b), (c.clone(), e.clone()));
        assert_eq!(a.quotient_modulus(&c), (b.clone(), e.clone()));
        assert_eq!(d.quotient_modulus(&b), (c.clone(), f.clone()));
        assert_eq!(d.quotient_modulus(&c), (b.clone(), g.clone()))
    }

    #[test]
    #[should_panic(expected="Attempted to divide by zero!")]
    fn test_quotient_modulus_divide_by_zero() {
        let a = BigNum::from(12973);
        let b = BigNum::from(0);

        a.quotient_modulus(&b);
    }

    //Light tests for / and % since they are wrappers for the quotient_modulus functionality
    #[test]
    fn test_div() {
        let a = BigNum::from(14);
        let b = BigNum::from(7);
        let c = BigNum::from(2);

        assert_eq!(&a / &b, c)
    }

    #[test]
    fn test_div_assign() {
        let mut a = BigNum::from(14);
        let b = BigNum::from(7);
        let c = BigNum::from(2);

        a /= b;

        assert_eq!(a, c);
    }

    #[test]
    fn test_mod() {
        let a = BigNum::from(14);
        let b = BigNum::from(5);
        let c = BigNum::from(4);

        assert_eq!(&a % &b, c)
    }

    #[test]
    fn test_mod_assign() {
        let mut a = BigNum::from(14);
        let b = BigNum::from(5);
        let c = BigNum::from(4);

        a %= b;

        assert_eq!(a, c);
    }

    #[test]
    fn test_modular_exponent() {
        let base = BigNum::from(52);
        let exponent = BigNum::from(5);
        let modulus = BigNum::from(127);
        let result = BigNum::from(68);

        assert_eq!(base.modular_exponent(&exponent, &modulus), result);
    }

    #[test]
    fn test_modular_exponent_large() {
        let base = BigNum::from(&vec![0xbc, 0x8d, 0x32, 0xf4, 0xa8, 0x5b, 0xb6, 0x7c, 0x88, 0xaa, 0x97, 0xdb, 0x62, 0x1c, 0xed, 0xcb, 0xed, 0x25, 0xa8, 0xaf, 0xd1, 0xb2, 0x4d, 0xc9, 0x12, 0xcb, 0xcd, 0x7a, 0x4f, 0x14, 0xce, 0x8c]);
        let exponent = BigNum::from(&vec![0x72, 0x59, 0xf6, 0xf9, 0xdf, 0xfe, 0xb0, 0x42, 0x90, 0x0e, 0xd1, 0x30, 0x1a, 0x32, 0x34, 0xcb]);
        let modulus = BigNum::from(&vec![0x7c, 0x3c, 0x0c, 0x75, 0x2a, 0x52, 0xfb, 0xf9, 0x56, 0x1f, 0xd8, 0xe1, 0xa7, 0xdd, 0x63, 0x56]);
        let result = BigNum::from(&vec![0x6d, 0x85, 0xef, 0xcb, 0xea, 0x56, 0x0f, 0x62, 0x30, 0xe9, 0x04, 0x5d, 0x82, 0x00, 0x5b, 0xb6]);

        assert_eq!(base.modular_exponent(&exponent, &modulus), result);
    }

    #[test]
    fn test_len_bits() {
        let a = BigNum::from(0);
        let b = BigNum::from(5);
        let c = BigNum::from(&vec![0xbc, 0x8d, 0x32, 0xf4, 0xa8, 0x5b, 0xb6, 0x7c, 0x88, 0xaa, 0x97, 0xdb, 0x62, 0x1c, 0xed, 0xcb, 0xed, 0x25, 0xa8, 0xaf, 0xd1, 0xb2, 0x4d, 0xc9, 0x12, 0xcb, 0xcd, 0x7a, 0x4f, 0x14, 0xce, 0x8c]);
        let d = BigNum::from(&vec![0x0c, 0x8d, 0x32, 0xf4, 0xa8, 0x5b, 0xb6, 0x7c, 0x88, 0xaa, 0x97, 0xdb, 0x62, 0x1c, 0xed, 0xcb, 0xed, 0x25, 0xa8, 0xaf, 0xd1, 0xb2, 0x4d, 0xc9, 0x12, 0xcb, 0xcd, 0x7a, 0x4f, 0x14, 0xce, 0x8c]);

        assert_eq!(a.len_bits(), 0);
        assert_eq!(b.len_bits(), 3);
        assert_eq!(c.len_bits(), 256);
        assert_eq!(d.len_bits(), 252);
    }

    #[test]
    fn test_len_bytes() {
        let a = BigNum::from(0);
        let b = BigNum::from(5);
        let c = BigNum::from(&vec![0xbc, 0x8d, 0x32, 0xf4, 0xa8, 0x5b, 0xb6, 0x7c, 0x88, 0xaa, 0x97, 0xdb, 0x62, 0x1c, 0xed, 0xcb, 0xed, 0x25, 0xa8, 0xaf, 0xd1, 0xb2, 0x4d, 0xc9, 0x12, 0xcb, 0xcd, 0x7a, 0x4f, 0x14, 0xce, 0x8c]);
        let d = BigNum::from(&vec![0x8d, 0x32, 0xf4, 0xa8, 0x5b, 0xb6, 0x7c, 0x88, 0xaa, 0x97, 0xdb, 0x62, 0x1c, 0xed, 0xcb, 0xed, 0x25, 0xa8, 0xaf, 0xd1, 0xb2, 0x4d, 0xc9, 0x12, 0xcb, 0xcd, 0x7a, 0x4f, 0x14, 0xce, 0x8c]);

        assert_eq!(a.len_bytes(), 0);
        assert_eq!(b.len_bytes(), 1);
        assert_eq!(c.len_bytes(), 32);
        assert_eq!(d.len_bytes(), 31);
    }
}