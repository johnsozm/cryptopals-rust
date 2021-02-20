use rand::random;
use crate::aes::{decrypt_ctr, encrypt_ctr};
use std::fs::File;
use std::io::{BufReader, BufRead};
use crate::converter::base64_to_bytes;
use crate::xor::xor_bytes;

lazy_static! {
    static ref KEY: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
    static ref NONCE: u64 = random();
    static ref CLEARTEXT: Vec<u8> = {
        let file = File::open("challenge25.txt").unwrap();
        let reader = BufReader::new(file);
        let mut base64= String::from("");

        //Read base-64 value across multiple lines
        for line in reader.lines() {
            base64 += &line.unwrap();
        }

        base64_to_bytes(&base64)
    };
}

///Implements the edit operation (allows for extension of ciphertext)
fn edit(ciphertext: &Vec<u8>, offset: usize, new_text: &Vec<u8>) -> Vec<u8> {
    let mut plaintext = decrypt_ctr(&ciphertext, &KEY, *NONCE);

    for i in 0..new_text.len() {
        if offset + i < ciphertext.len() {
            plaintext[offset + i] = new_text[i];
        }
        else {
            plaintext.push(new_text[i]);
        }
    }

    return encrypt_ctr(&plaintext, &KEY, *NONCE);
}

///Gets initial encryption of the message
fn get_original_ciphertext() -> Vec<u8> {
    return encrypt_ctr(&CLEARTEXT, &KEY, *NONCE);
}

fn challenge25() -> Vec<u8> {
    let ciphertext = get_original_ciphertext();

    //Encrypt all zero bytes to get key stream
    let zero_vector = vec![0;ciphertext.len()];
    let key_stream = edit(&ciphertext, 0, &zero_vector);

    //Calculate and return plaintext
    let plaintext = xor_bytes(&key_stream, &ciphertext);
    return plaintext;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge25(), *CLEARTEXT);
    }
}