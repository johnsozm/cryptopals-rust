use crate::diffie_hellman::{DiffieHellman, DEFAULT_P, DEFAULT_G};
use gmp::mpz::Mpz;
use crate::hash::Hash;
use crate::converter::{ascii_to_bytes, hex_to_bytes};
use crate::aes::decrypt_cbc;
use crate::padding::pkcs7_pad;

lazy_static! {
    static ref MESSAGE: Vec<u8> = pkcs7_pad(&ascii_to_bytes("TEST MESSAGE FOR CHALLENGE 35"), 16);
}

fn challenge35() -> bool {
    //Initialize A endpoint
    let mut dh_a = DiffieHellman::new();

    //Initialize B endpoints for various injected values of g
    let mut dh_one = DiffieHellman::new_from_params(&DEFAULT_P, &Mpz::one());
    let mut dh_p_minus_one = DiffieHellman::new_from_params(&DEFAULT_P, &(DEFAULT_P.clone() - Mpz::one()));
    let mut dh_p = DiffieHellman::new_from_params(&DEFAULT_P, &DEFAULT_P);

    //Simulate MITM attack for g=1
    //Get B to give us a public key generated with g=1 (ie, B=1)
    let mut dh_mitm_b = DiffieHellman::new_from_public_key(&DEFAULT_P, &Mpz::one(), &dh_a.public_key);
    dh_mitm_b.exchange_keys(&mut dh_one);

    //Pass A that public key - A will get s = B^a mod p = 1^a mod p = 1
    let mut dh_mitm_a = DiffieHellman::new_from_public_key(&DEFAULT_P, &DEFAULT_G, &dh_one.public_key);
    dh_mitm_a.exchange_keys(&mut dh_a);

    //Decrypt with known key
    let aes_key_one = Hash::SHA1.digest(&vec![1])[0..16].to_vec();
    let (ciphertext_one, iv_one) = dh_a.encrypt_message(&MESSAGE);
    if decrypt_cbc(&ciphertext_one, &aes_key_one, &iv_one) != *MESSAGE {
        return false;
    }

    //Simulate MITM attack for g=p
    //Get B to give us a public key generated with g=p (ie, B=0)
    let mut dh_mitm_b = DiffieHellman::new_from_public_key(&DEFAULT_P, &DEFAULT_P, &dh_a.public_key);
    dh_mitm_b.exchange_keys(&mut dh_p);

    //Pass A that public key - A will get s = B^a mod p = 0^a mod p = 0
    let mut dh_mitm_a = DiffieHellman::new_from_public_key(&DEFAULT_P, &DEFAULT_G, &dh_p.public_key);
    dh_a.exchange_keys(&mut dh_mitm_a);

    //Decrypt with known key
    let aes_key_p = Hash::SHA1.digest(&vec![0])[0..16].to_vec();
    let (ciphertext_p, iv_p) = dh_a.encrypt_message(&MESSAGE);
    if decrypt_cbc(&ciphertext_p, &aes_key_p, &iv_p) != *MESSAGE {
        return false;
    }

    //Simulate MITM attack for g=p-1
    //Get B to give us a public key generated with g=p-1 (ie, B=+/-1 mod p)
    let mut dh_mitm_b = DiffieHellman::new_from_public_key(&DEFAULT_P, &(DEFAULT_P.clone() - Mpz::one()), &dh_a.public_key);
    dh_mitm_b.exchange_keys(&mut dh_p_minus_one);

    //Pass A that public key - A will get s = B^a mod p = +/-1^a mod p = +/-1
    let mut dh_mitm_a = DiffieHellman::new_from_public_key(&DEFAULT_P, &DEFAULT_G, &dh_p_minus_one.public_key);
    dh_mitm_a.exchange_keys(&mut dh_a);

    let aes_key_p_minus_one = Hash::SHA1.digest(&vec![1])[0..16].to_vec();
    let (ciphertext_p_minus_one, iv_p_minus_one) = dh_a.encrypt_message(&MESSAGE);
    if decrypt_cbc(&ciphertext_p_minus_one, &aes_key_p_minus_one, &iv_p_minus_one) != *MESSAGE {
        let hex = &(DEFAULT_P.clone() - Mpz::one()).to_str_radix(16);
        let aes_key_retry = Hash::SHA1.digest(&hex_to_bytes(&hex))[0..16].to_vec();
        if decrypt_cbc(&ciphertext_p_minus_one, &aes_key_retry, &iv_p_minus_one) != *MESSAGE {
            return false;
        }
    }

    return true;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(challenge35());
    }
}