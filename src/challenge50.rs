use crate::mac::create_cbc_mac;
use crate::converter::{ascii_to_bytes, bytes_to_ascii, hex_to_bytes};
use crate::aes::{decrypt_ecb, decrypt_cbc};
use crate::xor::xor_bytes;
use crate::padding::pkcs7_pad;

lazy_static! {
    static ref KEY: Vec<u8> = ascii_to_bytes("YELLOW SUBMARINE");
    static ref IV: Vec<u8> = vec![0;16];
    static ref TARGET_HASH: Vec<u8> = hex_to_bytes("296b8d7cb78a243dda4d0a61d33bbdd1");
}

///Confirms that the given code is correct and gives the correct CBC-MAC signature
fn check_solution(code: &str) -> bool {
    let mac = create_cbc_mac(&ascii_to_bytes(code), &KEY, &IV);
    return code.starts_with("alert('Ayo, the Wu is back!');//") && mac.signature == *TARGET_HASH;
}

/*
    Notes on math used here:
    Need final plaintext block to be something with good PKCS7 padding - choose 0x10 x 16.
    Then the final ciphertext block is H = E(p_n ^ c_n-1) -> D(H) = p_n ^ c_n-1 => c_n-1 = p_n ^ D(H)
    The next-to-last ciphertext block is our "glue" between the code and this padding. To get the plaintext,
    we just need to decrypt the value of c_n-1 we found with c_n-2 (ie, our real message hash) as the IV.
    If this churns out unrunnable JS code (ie, contains a newline that ends the comment) we can just append
    something to the base message and try again.
 */

fn challenge50() -> String {
    let mut base_message = ascii_to_bytes("alert('Ayo, the Wu is back!');//");
    let decrypt_hash = decrypt_ecb(&TARGET_HASH, &KEY);

    loop {
        //Calculate message segments
        let message_hash = create_cbc_mac(&base_message, &KEY, &IV).signature;
        let plaintext_final = vec![0x10; 16];
        let ciphertext_penultimate = xor_bytes(&decrypt_hash, &plaintext_final);
        let plaintext_penultimate = decrypt_cbc(&ciphertext_penultimate, &KEY, &message_hash);

        //Put together plaintext and try this out
        let mut trial_message = pkcs7_pad(&base_message, 16);
        trial_message.append(&mut plaintext_penultimate.clone());
        let trial_code = bytes_to_ascii(&trial_message);

        if !trial_code.contains("\n") && !trial_code.contains("\r") {
            return trial_code;
        }
        base_message.push(55);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(check_solution(&challenge50()));
        println!("{}", challenge50());
    }
}