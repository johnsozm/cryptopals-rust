use gmp::mpz::Mpz;
use crate::rsa::{RSA, inverse_mod};
use crate::converter::{ascii_to_bytes, hex_to_bytes, bytes_to_ascii};
use crate::hash::Hash;

static MESSAGE: &str = "Wheee another random test message";

lazy_static! {
    static ref RSA_SERVER: RSA = RSA::new(1024);
    static ref CIPHERTEXT: Vec<u8> = RSA_SERVER.encrypt(&ascii_to_bytes(MESSAGE));
    static ref HASH: Vec<u8> = Hash::SHA256.digest(&CIPHERTEXT);
}

///Decrypt function that will refuse to decrypt the original ciphertext
fn decrypt_blob(blob: &Vec<u8>) -> Vec<u8> {
    let h = Hash::SHA256.digest(blob);
    if h == *HASH {
        return vec![];
    }
    return RSA_SERVER.decrypt(blob);
}

fn challenge41() -> String {
    //Calculate C' = (2^e mod n) * c mod n
    let c = Mpz::from(&CIPHERTEXT[0..]);
    let multiplier = Mpz::from(2).powm(&RSA_SERVER.e, &RSA_SERVER.n);
    let c_prime = (&c * &multiplier).modulus(&RSA_SERVER.n);

    //Cast to bytes and make decrypt call
    let new_ciphertext = hex_to_bytes(&c_prime.to_str_radix(16));
    let p_prime = Mpz::from(&decrypt_blob(&new_ciphertext)[0..]);

    //Calculate s^-1 mod n and then p = p' * s^-1 mod n
    return match inverse_mod(&Mpz::from(2), &RSA_SERVER.n) {
        None => String::from(""),
        Some(s_inverse) => {
            let p = &(s_inverse * &p_prime).modulus(&RSA_SERVER.n);
            bytes_to_ascii(&hex_to_bytes(&p.to_str_radix(16)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge41(), MESSAGE);
    }
}