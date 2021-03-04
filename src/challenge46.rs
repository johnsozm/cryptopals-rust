use crate::converter::{bytes_to_ascii, base64_to_bytes, ascii_to_bytes, hex_to_bytes};
use crate::rsa::RSA;
use gmp::mpz::Mpz;

lazy_static! {
    static ref MESSAGE: String = bytes_to_ascii(&base64_to_bytes("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="));
    static ref RSA_SERVER: RSA = RSA::new(1024);
}

fn get_original_ciphertext() -> Vec<u8> {
    return RSA_SERVER.encrypt(&ascii_to_bytes(&MESSAGE));
}

fn parity_oracle(ciphertext: &Vec<u8>) -> bool {
    let b = RSA_SERVER.decrypt(ciphertext);
    return b[b.len() - 1] % 2 == 1;
}

fn challenge46() -> String {
    //Initialize working variables
    let mut ciphertext = Mpz::from(&get_original_ciphertext()[0..]);
    let mut lower_num = Mpz::zero();
    let mut upper_num = Mpz::one();
    let mut denominator = Mpz::one();
    let factor = Mpz::from(2).powm(&RSA_SERVER.e, &RSA_SERVER.n);

    for _i in 0..RSA_SERVER.n.bit_length() {
        ciphertext = (&ciphertext * &factor).modulus(&RSA_SERVER.n);
        lower_num <<= 1;
        upper_num <<= 1;
        denominator <<= 1;

        let ciphertext_bytes = hex_to_bytes(&ciphertext.to_str_radix(16));
        if parity_oracle(&ciphertext_bytes) {
            lower_num += Mpz::one();
        }
        else {
            upper_num -= Mpz::one();
        }
    }

    let upper_bound = (&RSA_SERVER.n * &upper_num) / &denominator;
    return bytes_to_ascii(&hex_to_bytes(&upper_bound.to_str_radix(16)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge46(), *MESSAGE);
    }
}