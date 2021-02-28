use crate::diffie_hellman::{DiffieHellman, DEFAULT_P, DEFAULT_G};
use crate::converter::{ascii_to_bytes, bytes_to_ascii};
use crate::padding::{pkcs7_pad, pkcs7_unpad};
use crate::aes::decrypt_cbc;
use crate::hash::Hash;

static MESSAGE: &str = "This is a test message!";

fn challenge34() -> (String, String) {
    let mut dh_a = DiffieHellman::new();
    let mut dh_b = DiffieHellman::new();
    let mut dh_attack = DiffieHellman::new_from_public_key(&DEFAULT_P, &DEFAULT_G, &DEFAULT_P);

    dh_a.exchange_keys(&mut dh_attack);
    dh_b.exchange_keys(&mut dh_attack);

    let test_message = pkcs7_pad(&ascii_to_bytes(MESSAGE), 16);
    let (ciphertext_a, iv_a) = dh_a.encrypt_message(&test_message);
    let (ciphertext_b, iv_b) = dh_b.encrypt_message(&test_message);

    let key = Hash::SHA1.digest(&vec![0])[0..16].to_vec();
    let plaintext_a = bytes_to_ascii(&pkcs7_unpad(&decrypt_cbc(&ciphertext_a, &key, &iv_a)).unwrap());
    let plaintext_b = bytes_to_ascii(&pkcs7_unpad(&decrypt_cbc(&ciphertext_b, &key, &iv_b)).unwrap());

    return (plaintext_a, plaintext_b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        let (plaintext_a, plaintext_b) = challenge34();
        assert_eq!(plaintext_a, MESSAGE);
        assert_eq!(plaintext_b, MESSAGE);
    }
}