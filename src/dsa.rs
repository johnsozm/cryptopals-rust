use gmp::mpz::Mpz;
use rand::random;
use crate::hash::Hash;
use crate::rsa::inverse_mod;

lazy_static! {
    pub static ref P: Mpz = Mpz::from_str_radix("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap();
    pub static ref Q: Mpz = Mpz::from_str_radix("f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();
    pub static ref G: Mpz = Mpz::from_str_radix("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16).unwrap();
}

pub struct DSA {
    pub x: Mpz,
    pub y: Mpz
}

pub struct DSASignature {
    pub message: Vec<u8>,
    pub r: Mpz,
    pub s: Mpz
}

impl DSA {
    ///Creates a new DSA instance using the standard parameters
    pub fn new() -> DSA {
        //Generate random x mod q and y = g^x mod p
        let mut bytes: Vec<u8> = vec![];
        for _i in 0..Q.bit_length()/8 {
            bytes.push(random());
        }
        let x = Mpz::from(&bytes[0..]);
        return DSA {
            x: x.modulus(&Q),
            y: G.powm(&x, &P)
        };
    }

    ///Signs the given message using this instance's private key
    pub fn sign_message(&self, message: &Vec<u8>) -> DSASignature {
        //Generate random k mod q
        let mut bytes: Vec<u8> = vec![];
        for _i in 0..Q.bit_length()/8 {
            bytes.push(random());
        }
        let mut k = Mpz::from(&bytes[0..]);
        k = k.modulus(&Q);

        //Try to compute r = g^k mod p. If r = 0, retry with different k.
        let r = G.powm(&k, &P).modulus(&Q);
        if r == Mpz::zero() {
            return self.sign_message(message);
        }

        //Calculate s = k^-1 * (hash(message) + x*r)) mod q. If s = 0, retry with different k.
        let h = Mpz::from(&Hash::SHA1.digest(message)[0..]);
        return match inverse_mod(&k, &Q) {
            None => return self.sign_message(message),
            Some(k_inv) => DSASignature {
                message: message.clone(),
                r: r.clone(),
                s: (&k_inv * (&h + (&self.x * &r))).modulus(&Q)
            }
        };
    }

    ///Verifies the message using this instance's public key
    pub fn verify_signature(&self, signature: &DSASignature) -> bool {
        //Validate r, s
        if signature.r < Mpz::zero() || signature.s < Mpz::zero() || signature.r > *Q || signature.s > *Q {
            return false;
        }

        let h = Mpz::from(&Hash::SHA1.digest(&signature.message)[0..]);
        return match inverse_mod(&signature.s, &Q) {
            None => false,
            Some(w) => {
                let u1 = (&h * &w).modulus(&Q);
                let u2 = (&signature.r * &w).modulus(&Q);
                let v = (G.powm(&u1, &P) * self.y.powm(&u2, &P)).modulus(&P).modulus(&Q);
                v == signature.r
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::ascii_to_bytes;

    #[test]
    fn test_sign_verify() {
        let d = DSA::new();
        let message = ascii_to_bytes("TEST MESSAGE: for DSA signature and verification");
        let mut signature = d.sign_message(&message);
        assert!(d.verify_signature(&signature));
        signature.r += Mpz::one();
        assert!(!d.verify_signature(&signature));
        signature.r -= Mpz::one();
        signature.s -= Mpz::one();
        assert!(!d.verify_signature(&signature));
    }
}