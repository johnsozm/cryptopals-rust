use crate::converter::{base64_to_bytes, bytes_to_ascii, ascii_to_bytes};
use crate::aes::encrypt_ecb;
use crate::padding::pkcs7_pad;
use rand::random;

lazy_static! {
    static ref KEY: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
}

///Generates encryption of pad(message || secret)
fn oracle(message: &Vec<u8>) -> Vec<u8> {
    let mut plaintext = message.clone();
    let mut secret = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    plaintext.append(&mut secret);
    return encrypt_ecb(&pkcs7_pad(&plaintext, 16), &KEY);
}

fn challenge12() -> String {
    //Determine length of secret message
    let mut pad_length = 1;
    let base_length = oracle(&vec![]).len();
    let mut test_length;
    loop {
        let test_message = ascii_to_bytes(&"A".repeat(pad_length));
        test_length = oracle(&test_message).len();
        if test_length != base_length {
            break;
        }
        pad_length += 1;
    }

    let block_length = test_length - base_length;
    let message_length = base_length - pad_length;
    let mut plaintext: Vec<u8> = vec![];
    let mut last_bytes: Vec<u8> = vec![0; block_length];

    //Determine message characters one at a time
    for i in 0..message_length {
        //Get encryption of known block ending in next character
        let mut pad: Vec<u8> = vec![];
        for _j in 0..(block_length - (i % block_length) - 1) {
            pad.push(0);
        }

        let ciphertext = oracle(&pad);
        let target_block_number = i / block_length;
        let target_block = ciphertext[target_block_number * block_length..(target_block_number + 1) * block_length].to_vec();

        //Construct trial block consisting of known text + unknown character
        for j in 0..block_length - 1 {
            last_bytes[j] = last_bytes[j + 1];
        }

        //Try each value of unknown character until we get a match
        for byte in 0..=255 {
            last_bytes[block_length - 1] = byte;
            let test_block = oracle(&last_bytes)[0..block_length].to_vec();

            if test_block == target_block {
                plaintext.push(byte);
                break;
            }
        }
    }

    return bytes_to_ascii(&plaintext);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        let bytes = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        let message = bytes_to_ascii(&bytes);

        assert_eq!(challenge12(), message);
    }
}