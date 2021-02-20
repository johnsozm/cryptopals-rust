use rand::random;
use crate::converter::{base64_to_bytes, bytes_to_ascii};
use crate::aes::{encrypt_cbc, decrypt_cbc};
use crate::padding::{pkcs7_unpad, pkcs7_pad};

///Selection of possible secret messages
static SECRETS: [&str; 10] =
[
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
];

lazy_static! {
    static ref KEY: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
    static ref IV: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
}

///Selects a random plaintext, then pads and encrypts it.
fn get_random_ciphertext() -> (Vec<u8>, Vec<u8>) {
    let index: usize = random();
    let plaintext = pkcs7_pad(&base64_to_bytes(SECRETS[index % 10]), 16);
    return (encrypt_cbc(&plaintext, &KEY, &IV), IV.clone());
}

///Padding oracle. Returns true if ciphertext decrypts to valid padding, false otherwise
fn padding_oracle(ciphertext: &Vec<u8>, iv: &Vec<u8>) -> bool {
    let plaintext = decrypt_cbc(&ciphertext, &KEY, iv);
    return match pkcs7_unpad(&plaintext) {
        Err(_) => false,
        Ok(_) => true
    }
}

fn challenge17() -> String {
    //Get target ciphertext, IV, and initialize plaintext vector
    let (ciphertext, iv) = get_random_ciphertext();
    let mut plaintext: Vec<u8> = vec![0; ciphertext.len()];
    let block_length = iv.len();

    //Perform padding attack on each block, with that block as the end of the corrupted ciphertext
    for blocks in 2..=plaintext.len() / block_length {
        let mut working_ciphertext = ciphertext[0..(blocks*block_length)].to_vec();

        //Determine bytes in block via padding attack
        for i in (working_ciphertext.len() - block_length..working_ciphertext.len()).rev() {
            let target_padding: u8 = (working_ciphertext.len() - i) as u8;
            for j in i+1..working_ciphertext.len() {
                let mask = target_padding ^ plaintext[j];
                working_ciphertext[j - block_length] = ciphertext[j - block_length] ^ mask;
            }

            //Search for XOR mask that gives us valid padding.
            //Start at 1 to avoid failures with last block of properly padded plaintext
            let mut found = false;
            for byte in 1..=255 {
                working_ciphertext[i - block_length] = ciphertext[i - block_length] ^ byte;
                if padding_oracle(&working_ciphertext, &iv) {
                    //If we're at the end of the block, make sure we didn't accidentally include previous byte in padding
                    if i % block_length == block_length - 1 {
                        working_ciphertext[i - block_length - 1] += 1;

                        if padding_oracle(&working_ciphertext, &iv) {
                            plaintext[i] = target_padding ^ byte;
                            found = true;
                            break;
                        }
                        else {
                            working_ciphertext[i - block_length - 1] -= 1;
                        }
                    }
                    else {
                        plaintext[i] = target_padding ^ byte;
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                plaintext[i] = target_padding;
            }
        }
    }

    //Special handling for first block (corrupt IV instead of prev ciphertext block)
    let working_ciphertext = ciphertext[0..block_length].to_vec();
    let mut working_iv = iv.clone();

    //Determine bytes in block via padding attack
    for i in (0..block_length).rev() {
        let target_padding: u8 = (working_ciphertext.len() - i) as u8;
        for j in i+1..working_ciphertext.len() {
            let mask = target_padding ^ plaintext[j];
            working_iv[j] = iv[j] ^ mask;
        }

        //Search for XOR mask that gives us valid padding.
        //Start at 1 to avoid failures with last block of properly padded plaintext
        let mut found = false;
        for byte in 1..=255 {
            working_iv[i] = iv[i] ^ byte;
            if padding_oracle(&working_ciphertext, &working_iv) {
                //If we're at the end of the block, make sure we didn't accidentally include previous byte in padding
                if i % block_length == block_length - 1 {
                    working_iv[i-1] += 1;

                    if padding_oracle(&working_ciphertext, &working_iv) {
                        plaintext[i] = target_padding ^ byte;
                        found = true;
                        break;
                    }
                    else {
                        working_iv[i-1] -= 1;
                    }
                }
                else {
                    plaintext[i] = target_padding ^ byte;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            plaintext[i] = target_padding;
        }
    }

    return bytes_to_ascii(&pkcs7_unpad(&plaintext).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::{bytes_to_base64, ascii_to_bytes};

    #[test]
    fn test_solution() {
        let base64 = bytes_to_base64(&ascii_to_bytes(&challenge17()));
        let mut found = false;
        for i in 0..10 {
            if base64 == SECRETS[i] {
                found = true;
                break;
            }
        }

        assert!(found);
    }
}