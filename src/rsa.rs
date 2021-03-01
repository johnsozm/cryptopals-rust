use gmp::mpz::Mpz;
use crate::converter::hex_to_bytes;
use rand::random;

pub struct RSA {
    pub n: Mpz,
    pub e: Mpz,
    d: Mpz
}

///Generates a random prime of the given bit length
fn generate_prime(bit_length: usize) -> Mpz {
    let mut byte_length = bit_length / 8;
    let trailing_bits = bit_length % 8;
    if trailing_bits != 0 {
        byte_length += 1
    }

    let mut bytes: Vec<u8> = vec![];
    for _i in 0..byte_length {
        bytes.push(random());
    }

    bytes[0] %= 1 << trailing_bits;

    let x = Mpz::from(&bytes[0..]);
    return x.nextprime();
}

pub fn inverse_mod(a: &Mpz, b: &Mpz) -> Option<Mpz> {
    let mut t = Mpz::zero();
    let mut new_t = Mpz::one();
    let mut r = b.clone();
    let mut new_r = a.clone();
    let mut tmp: Mpz;

    while new_r != Mpz::zero() {
        let q = &r / &new_r;
        tmp = new_t.clone();
        new_t = &t - (&q * &new_t);
        t = tmp.clone();
        tmp = new_r.clone();
        new_r = &r - (&q * &new_r);
        r = tmp.clone();
    }

    if r > Mpz::one() {
        return None;
    }

    if t < Mpz::zero() {
        t += b;
    }

    return Some(t);
}

impl RSA {
    ///Generates a new RSA key with the given key length (in bits) and e=3
    pub fn new(key_length: usize) -> RSA {
        let mut ret = RSA {
            n: Mpz::zero(),
            e: Mpz::from(3),
            d: Mpz::zero()
        };

        loop {
            let p = generate_prime(key_length / 2 - 10);
            let q = generate_prime(key_length / 2 + 10);
            ret.n = &p * &q;
            let et = (&p - Mpz::one()) * (&q - Mpz::one());
            match inverse_mod(&ret.e, &et) {
                None => continue,
                Some(d) => ret.d = d
            }
            return ret;
        }
    }

    ///Encrypts the given message with the instance's public key
    pub fn encrypt(&self, plaintext: &Vec<u8>) -> Vec<u8> {
        let m = Mpz::from(&plaintext[0..]);
        let c = m.powm(&self.e, &self.n);

        return hex_to_bytes(&c.to_str_radix(16));
    }

    ///Decrypts the given message with the instance's private key
    pub fn decrypt(&self, ciphertext: &Vec<u8>) -> Vec<u8> {
        let c = Mpz::from(&ciphertext[0..]);
        let m = c.powm(&self.d, &self.n);

        return hex_to_bytes(&m.to_str_radix(16));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::ascii_to_bytes;

    #[test]
    fn test_encrypt() {
        let r = RSA {
            n: Mpz::from(3233),
            e: Mpz::from(17),
            d: Mpz::from(413)
        };

        assert_eq!(r.encrypt(&vec![65]), vec![10, 230]);
    }

    #[test]
    fn test_decrypt() {
        let r = RSA {
            n: Mpz::from(3233),
            e: Mpz::from(17),
            d: Mpz::from(413)
        };

        assert_eq!(r.decrypt(&vec![10, 230]), vec![65]);
    }

    #[test]
    fn test_large_encrypt_decrypt() {
        let r = RSA::new(1024);
        let message = ascii_to_bytes("This is a test message for encryption and decryption.");
        let ciphertext = r.encrypt(&message);
        let plaintext = r.decrypt(&ciphertext);

        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_inverse_mod() {
        let e = Mpz::from(17);
        let d = Mpz::from(413);
        let n = Mpz::from(780);
        assert_eq!(inverse_mod(&e, &n).unwrap(), d);
    }

    #[test]
    fn test_inverse_mod_no_inverse() {
        let a = Mpz::from(6);
        let n = Mpz::from(9);
        assert_eq!(inverse_mod(&a, &n), None);
    }
}