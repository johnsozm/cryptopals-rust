use rand::random;
use crate::converter::base64_to_bytes;
use crate::aes::{encrypt_cbc, decrypt_cbc};
use crate::padding::pkcs7_unpad;

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

fn get_random_ciphertext() -> (Vec<u8>, Vec<u8>) {
    let index: usize = random();
    let plaintext = base64_to_bytes(SECRETS[index % 10]);
    return (encrypt_cbc(&plaintext, &KEY, &IV), IV.clone());
}

///Padding oracle. Returns true if ciphertext decrypts to valid padding, false otherwise
fn padding_oracle(ciphertext: Vec<u8>) -> bool {
    let plaintext = decrypt_cbc(&ciphertext, &KEY, &IV);
    return match pkcs7_unpad(&plaintext) {
        Err(_) => false,
        Ok(_) => true
    }
}

fn challenge17() -> String {
    //TODO: Get target ciphertext and initialize plaintext vector (since it's found in reverse)
    //TODO: For each block in ciphertext, working from the end:
        //TODO: Truncate ciphertext after this block
        //TODO: For each byte in this block:
            //TODO: Update previously known padding for 1 more byte
            //TODO: XOR corresponding byte in previous ciphertext block with all possible values
            //TODO: Log plaintext byte value based on what gave valid padding

    return String::from("");
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