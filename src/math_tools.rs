use std::ops::{Div, Mul, Sub, Add, AddAssign};
use gmp::mpz::Mpz;

///Returns Bezout coefficients (s, t) satisfying s*n1 + t*n2 = gcd(n1, n2)
fn bezout_coefficients(n1: &Mpz, n2: &Mpz) -> (Mpz, Mpz) {
    let mut old_r = n1.clone();
    let mut r = n2.clone();
    let mut old_s = Mpz::one();
    let mut s = Mpz::zero();
    let mut old_t = Mpz::zero();
    let mut t = Mpz::one();

    while r.ne(&Mpz::zero()) {
        let quotient = old_r.clone().div(&r);
        let new_r = old_r.clone().sub(&quotient.clone().mul(&r));
        let new_s = old_s.clone().sub(&quotient.clone().mul(&s));
        let new_t = old_t.clone().sub(&quotient.clone().mul(&t));
        old_r = r;
        old_s = s;
        old_t = t;
        r = new_r;
        s = new_s;
        t = new_t;
    }

    return (old_s, old_t);
}

///Finds a solution to a system of residues using the Chinese Remainder Theorem
pub fn chinese_remainder_theorem(residues: &Vec<Mpz>, moduli: &Vec<Mpz>) -> Mpz {
    if residues.len() != moduli.len() {
        panic!("Lists of unequal length passed.");
    }

    if residues.len() == 1 {
        let mut result = residues[0].clone().modulus(&moduli[0]);
        if result.lt(&Mpz::zero()) {
            result.add_assign(&moduli[0]);
        }
        return result;
    }

    let mut new_residues = vec![];
    let mut new_moduli = vec![];
    for i in 0..residues.len()/2 {
        let a1 = residues[2*i].clone();
        let a2 = residues[2*i + 1].clone();
        let n1 = moduli[2*i].clone();
        let n2 = moduli[2*i+1].clone();
        let (m1, m2) = bezout_coefficients(&n1, &n2);
        new_residues.push((a1.mul(&m2).mul(&n2)).add(a2.mul(&m1).mul(&n1)));
        new_moduli.push(n1.mul(&n2));
    }

    if residues.len() % 2 != 0 {
        let last_index = residues.len() - 1;
        new_residues.push(residues[last_index].clone());
        new_moduli.push(moduli[last_index].clone());
    }

    return chinese_remainder_theorem(&new_residues, &new_moduli);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bezout_coefficients() {
        assert_eq!(bezout_coefficients(&Mpz::from(240), &Mpz::from(46)), (Mpz::from(-9), Mpz::from(47)));
        assert_eq!(bezout_coefficients(&Mpz::from(129095), &Mpz::from(1238775)), (Mpz::from(-57671), Mpz::from(6010)))
    }

    #[test]
    #[should_panic(expected="Lists of unequal length passed.")]
    fn test_chinese_remainder_theorem_bad_arguments() {
        chinese_remainder_theorem(&vec![], &vec![Mpz::zero()]);
    }

    #[test]
    fn test_chinese_remainder_theorem() {
        assert_eq!(chinese_remainder_theorem(&vec![Mpz::from(2), Mpz::from(3), Mpz::from(2)], &vec![Mpz::from(3), Mpz::from(5), Mpz::from(7)]), Mpz::from(23));
    }
}