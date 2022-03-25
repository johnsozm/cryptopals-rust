use crate::dsa::{DSASignature, DEFAULT_P, DEFAULT_Q};
use gmp::mpz::Mpz;
use crate::rsa::inverse_mod;

fn challenge45(y: &Mpz) -> DSASignature {
    let p = DEFAULT_P.clone();
    let q = DEFAULT_Q.clone();
    let g = &p + Mpz::one();

    //Calculate universal signature using malicious G
    let z = Mpz::from(5);
    let z_inv = inverse_mod(&z, &q).unwrap();
    let r = y.powm(&z, &p).modulus(&q);
    let s = (&r * &z_inv).modulus(&q);

    return DSASignature {message: vec![], r, s, p, q, g};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::DSA;
    use crate::converter::ascii_to_bytes;

    #[test]
    fn test_solution() {
        let d = DSA::new();
        let mut sig = challenge45(&d.y);
        assert!(d.verify_signature(&sig));
        sig.message = ascii_to_bytes("Hello, world!");
        assert!(d.verify_signature(&sig));
        sig.message = ascii_to_bytes("Goodbye, world!");
        assert!(d.verify_signature(&sig));
    }
}