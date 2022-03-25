use crate::padding::pkcs7_pad;
use crate::converter::{ascii_to_bytes, bytes_to_ascii};
use crate::aes::{encrypt_cbc, decrypt_cbc};
use rand::random;
use std::io::{Error, ErrorKind};
use crate::xor::xor_bytes;

lazy_static! {
    static ref KEY: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
}

///Generate message that attacker is intercepting
fn generate_message() -> Vec<u8> {
    let plaintext = ascii_to_bytes("Just needed a message that is at least 3 blocks long.");
    let padded = pkcs7_pad(&plaintext, 16);
    return encrypt_cbc(&padded, &KEY, &KEY);
}

///Validation of message - returns an error if high ASCII values are encountered
fn validate_message(message: &Vec<u8>) -> Result<bool, Error> {
    let plaintext = decrypt_cbc(&message, &KEY, &KEY);
    let plaintext_str = bytes_to_ascii(&plaintext);

    for byte in plaintext {
        if byte > 127 {
            let mut error = String::from("High ASCII value detected in plaintext: ");
            error.push_str(&plaintext_str);
            return Err(Error::new(ErrorKind::Other, error));
        }
    }

    return Ok(true);
}

fn challenge27() -> Vec<u8> {
    let block_length = 16; //Assume we know this from monitoring exchange
    let mut ciphertext = generate_message();

    //Generate replacement message C_1, 0, C_1...
    for i in 0..block_length {
        ciphertext[2*block_length + i] = ciphertext[i];
        ciphertext[block_length + i] = 0;
    }

    let plaintext;

    //Get decryption error from modified message
    match validate_message(&ciphertext) {
        Err(e) => match e.kind() {
            ErrorKind::Other => plaintext = e.to_string().replace("High ASCII value detected in plaintext: ", ""),
            _ => return vec![]
        },
        Ok(_) => return vec![]
    }

    //Calculate key = P'_1 ^ P'_3
    let plaintext_bytes = ascii_to_bytes(&plaintext);
    let p1 = plaintext_bytes[0..block_length].to_vec();
    let p3 = plaintext_bytes[block_length*2..block_length*3].to_vec();
    return xor_bytes(&p1, &p3);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge27(), *KEY);
    }
}
