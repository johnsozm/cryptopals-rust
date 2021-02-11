///Encrypts plaintext using AES-ECB and the given 16-byte key.
///Will panic if key is not 16 bytes.
pub fn encrypt_ecb(plaintext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    if key.len() != 16 {
        panic!("Illegal key length {} passed as an AES key!", key.len());
    }
    if plaintext.len() % 16 != 0 {
        panic!("Partial block of length {} passed for AES encryption!", plaintext.len() % 16);
    }

    let ciphertext:Vec<u8> = vec![];

    //TODO: Call to system AES library

    return ciphertext;
}

///Decrypts ciphertext using AES-ECB and the given 16-byte key.
///Will panic if key is not 16 bytes.
pub fn decrypt_ecb(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    if key.len() != 16 {
        panic!("Illegal key length {} passed as an AES key!", key.len());
    }
    if ciphertext.len() % 16 != 0 {
        panic!("Partial block of length {} passed for AES decryption!", ciphertext.len() % 16);
    }

    //TODO: Call to system AES library

    return vec![];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_ecb() {
        let plaintext = crate::converter::hex_to_bytes("014BAF2278A69D331D5180103643E99A");
        let key = crate::converter::hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
        let ciphertext = crate::converter::hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        assert_eq!(encrypt_ecb(&plaintext, &key), ciphertext)
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_encrypt_ecb_bad_key() {
        let plaintext = crate::converter::hex_to_bytes("014BAF2278A69D331D5180103643E99A");
        let key = crate::converter::hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7");
        let ciphertext = crate::converter::hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        encrypt_ecb(&plaintext, &key);
    }

    #[test]
    #[should_panic(expected="Partial block of length 13 passed for AES encryption!")]
    fn test_encrypt_ecb_not_block() {
        let plaintext = crate::converter::hex_to_bytes("014BAF2278A69D331D51801036");
        let key = crate::converter::hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
        let ciphertext = crate::converter::hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        encrypt_ecb(&plaintext, &key);
    }

    #[test]
    fn test_decrypt_ecb() {
        let plaintext = crate::converter::hex_to_bytes("014BAF2278A69D331D5180103643E99A");
        let key = crate::converter::hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
        let ciphertext = crate::converter::hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        assert_eq!(decrypt_ecb(&ciphertext, &key), plaintext)
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_decrypt_ecb_bad_key() {
        let plaintext = crate::converter::hex_to_bytes("014BAF2278A69D331D5180103643E99A");
        let key = crate::converter::hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7");
        let ciphertext = crate::converter::hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        decrypt_ecb(&ciphertext, &key);
    }

    #[test]
    #[should_panic(expected="Partial block of length 13 passed for AES decryption!")]
    fn test_decrypt_ecb_not_block() {
        let plaintext = crate::converter::hex_to_bytes("014BAF2278A69D331D51801036");
        let key = crate::converter::hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
        let ciphertext = crate::converter::hex_to_bytes("6743C3D1519AB4F2CD9A78AB09");

        decrypt_ecb(&ciphertext, &key);
    }
}