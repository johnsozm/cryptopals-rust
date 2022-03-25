use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::Aes128;
use std::collections::HashSet;
use crate::xor::xor_bytes;

///Encrypts plaintext using AES-ECB and the given 16-byte key.
///Will panic if key length is not 16 bytes or plaintext length is not a multiple of 16 bytes.
pub fn encrypt_ecb(plaintext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    if key.len() != 16 {
        panic!("Illegal key length {} passed as an AES key!", key.len());
    }
    if plaintext.len() % 16 != 0 {
        panic!("Partial block of length {} passed for AES encryption!", plaintext.len() % 16);
    }

    let mut ciphertext: Vec<u8> = vec![];
    let key_array: GenericArray<u8, _> = GenericArray::clone_from_slice(&key);
    let cipher = Aes128::new(&key_array);

    for i in 0..plaintext.len() / 16 {
        let mut block = GenericArray::clone_from_slice(&plaintext[16*i..16*(i+1)]);
        cipher.encrypt_block(&mut block);
        ciphertext.append(&mut block.to_vec());
    }

    return ciphertext;
}

///Decrypts ciphertext using AES-ECB and the given 16-byte key.
///Will panic if key length is not 16 bytes or ciphertext length is not a multiple of 16 bytes.
pub fn decrypt_ecb(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    if key.len() != 16 {
        panic!("Illegal key length {} passed as an AES key!", key.len());
    }
    if ciphertext.len() % 16 != 0 {
        panic!("Partial block of length {} passed for AES decryption!", ciphertext.len() % 16);
    }

    let mut plaintext: Vec<u8> = vec![];
    let key_array: GenericArray<u8, _> = GenericArray::clone_from_slice(&key);
    let cipher = Aes128::new(&key_array);

    for i in 0..ciphertext.len() / 16 {
        let mut block = GenericArray::clone_from_slice(&ciphertext[16*i..16*(i+1)]);
        cipher.decrypt_block(&mut block);
        plaintext.append(&mut block.to_vec());
    }

    return plaintext;
}

///Detects use of ECB mode by searching for repeated blocks.
///Will panic if ciphertext length is not a multiple of 16 bytes.
pub fn detect_ecb(ciphertext: &Vec<u8>) -> bool {
    if ciphertext.len() % 16 != 0 {
        panic!("Partial block of length {} passed for AES analysis!", ciphertext.len() % 16);
    }

    let mut unique: HashSet<Vec<u8>> = HashSet::new();
    for i in 0..ciphertext.len() / 16 {
        unique.insert(ciphertext[16*i..16*(i+1)].to_vec());
    }

    return unique.len() < (ciphertext.len() / 16);
}

///Encrypts plaintext using AES-CBC mode and the given key and IV.
///Will panic if key length is not 16 bytes, IV length is not 16 bytes,
///or plaintext length is not a multiple of 16 bytes.
pub fn encrypt_cbc(plaintext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    if key.len() != 16 {
        panic!("Illegal key length {} passed as an AES key!", key.len());
    }
    if iv.len() != 16 {
        panic!("Illegal IV length {} passed as an AES IV!", iv.len());
    }
    if plaintext.len() % 16 != 0 {
        panic!("Partial block of length {} passed for AES encryption!", plaintext.len() % 16);
    }

    let mut ciphertext: Vec<u8> = vec![];
    let mut last_block: Vec<u8> = iv.clone();

    for i in 0..plaintext.len() / 16 {
        let to_encrypt = xor_bytes(&last_block, &plaintext[16*i..16*(i+1)].to_vec());
        let mut encrypted = encrypt_ecb(&to_encrypt, &key);
        last_block = encrypted.clone();
        ciphertext.append(&mut encrypted);
    }

    return ciphertext;
}

///Decrypts ciphertext using AES-CBC mode and the given key and IV.
///Will panic if key length is not 16 bytes, IV length is not 16 bytes,
///or ciphertext length is not a multiple of 16 bytes.
pub fn decrypt_cbc(ciphertext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    if key.len() != 16 {
        panic!("Illegal key length {} passed as an AES key!", key.len());
    }
    if iv.len() != 16 {
        panic!("Illegal IV length {} passed as an AES IV!", iv.len());
    }
    if ciphertext.len() % 16 != 0 {
        panic!("Partial block of length {} passed for AES decryption!", ciphertext.len() % 16);
    }

    let mut plaintext: Vec<u8> = vec![];
    let mut last_block = iv.clone();

    for i in 0..ciphertext.len() / 16 {
        let decrypted = decrypt_ecb(&ciphertext[16*i..16*(i+1)].to_vec(), &key);
        let mut plaintext_block = xor_bytes(&last_block, &decrypted);
        last_block = ciphertext[16*i..16*(i+1)].to_vec();
        plaintext.append(&mut plaintext_block);
    }

    return plaintext;
}

///Encrypts plaintext using AES-CTR mode and the given key and nonce.
///Will panic if key length is not 16 bytes.
pub fn encrypt_ctr(plaintext: &Vec<u8>, key: &Vec<u8>, nonce: u64) -> Vec<u8> {
    if key.len() != 16 {
        panic!("Illegal key length {} passed as an AES key!", key.len());
    }

    let mut ciphertext = vec![];
    let mut ctr_block = vec![];
    let mut ctr: u128 = nonce as u128;

    for i in 0..plaintext.len() {
        if i % 16 == 0 {
            ctr_block = encrypt_ecb(&ctr.to_le_bytes().to_vec(), &key);
            ctr += 1 << 64;
        }
        ciphertext.push(plaintext[i] ^ ctr_block[i % 16]);
    }

    return ciphertext;
}

///Decrypts ciphertext using AES-CTR mode and the given key and nonce.
///Will panic if key length is not 16 bytes.
pub fn decrypt_ctr(ciphertext: &Vec<u8>, key: &Vec<u8>, nonce: u64) -> Vec<u8> {
    return encrypt_ctr(&ciphertext, &key, nonce);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::{hex_to_bytes, ascii_to_bytes, base64_to_bytes, bytes_to_ascii};

    #[test]
    fn test_encrypt_ecb() {
        let plaintext = hex_to_bytes("014BAF2278A69D331D5180103643E99A");
        let key = hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
        let ciphertext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        assert_eq!(encrypt_ecb(&plaintext, &key), ciphertext)
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_encrypt_ecb_bad_key() {
        let plaintext = hex_to_bytes("014BAF2278A69D331D5180103643E99A");
        let key = hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7");

        encrypt_ecb(&plaintext, &key);
    }

    #[test]
    #[should_panic(expected="Partial block of length 13 passed for AES encryption!")]
    fn test_encrypt_ecb_not_block() {
        let plaintext = hex_to_bytes("014BAF2278A69D331D51801036");
        let key = hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");

        encrypt_ecb(&plaintext, &key);
    }

    #[test]
    fn test_decrypt_ecb() {
        let plaintext = hex_to_bytes("014BAF2278A69D331D5180103643E99A");
        let key = hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
        let ciphertext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        assert_eq!(decrypt_ecb(&ciphertext, &key), plaintext)
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_decrypt_ecb_bad_key() {
        let key = hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7");
        let ciphertext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        decrypt_ecb(&ciphertext, &key);
    }

    #[test]
    #[should_panic(expected="Partial block of length 13 passed for AES decryption!")]
    fn test_decrypt_ecb_not_block() {
        let key = hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
        let ciphertext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09");

        decrypt_ecb(&ciphertext, &key);
    }

    #[test]
    fn test_detect_ecb() {
        let key = hex_to_bytes("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
        let plaintext = ascii_to_bytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let ciphertext1 = encrypt_ecb(&plaintext, &key);
        let ciphertext2 = ascii_to_bytes("sdfll81u23ljs0udpadlfksaj;93kjf1");

        assert!(detect_ecb(&ciphertext1));
        assert!(!detect_ecb(&ciphertext2));
    }

    #[test]
    #[should_panic(expected="Partial block of length 13 passed for AES analysis!")]
    fn test_detect_ecb_not_block() {
        let ciphertext = ascii_to_bytes("AAAAAAAAAAAAA");
        detect_ecb(&ciphertext);
    }

    #[test]
    fn test_encrypt_cbc() {
        let key = hex_to_bytes("56e47a38c5598974bc46903dba290349");
        let iv = hex_to_bytes("8ce82eefbea0da3c44699ed7db51b7d9");
        let plaintext = hex_to_bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
        let ciphertext = hex_to_bytes("c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55");

        assert_eq!(encrypt_cbc(&plaintext, &key, &iv), ciphertext);
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_encrypt_cbc_bad_key() {
        let key = hex_to_bytes("56e47a38c5598974bc46903dba");
        let iv = hex_to_bytes("8ce82eefbea0da3c44699ed7db51b7d9");
        let plaintext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        encrypt_cbc(&plaintext, &key, &iv);
    }

    #[test]
    #[should_panic(expected="Partial block of length 13 passed for AES encryption!")]
    fn test_encrypt_cbc_bad_block() {
        let key = hex_to_bytes("56e47a38c5598974bc46903dba290349");
        let iv = hex_to_bytes("8ce82eefbea0da3c44699ed7db51b7d9");
        let plaintext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09");

        encrypt_cbc(&plaintext, &key, &iv);
    }

    #[test]
    #[should_panic(expected="Illegal IV length 13 passed as an AES IV!")]
    fn test_encrypt_cbc_bad_iv() {
        let key = hex_to_bytes("56e47a38c5598974bc46903dba290349");
        let iv = hex_to_bytes("8ce82eefbea0da3c44699ed7db");
        let plaintext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        encrypt_cbc(&plaintext, &key, &iv);
    }

    #[test]
    fn test_decrypt_cbc() {
        let key = hex_to_bytes("56e47a38c5598974bc46903dba290349");
        let iv = hex_to_bytes("8ce82eefbea0da3c44699ed7db51b7d9");
        let plaintext = hex_to_bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
        let ciphertext = hex_to_bytes("c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55");

        assert_eq!(decrypt_cbc(&ciphertext, &key, &iv), plaintext);
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_decrypt_cbc_bad_key() {
        let key = hex_to_bytes("56e47a38c5598974bc46903dba");
        let iv = hex_to_bytes("8ce82eefbea0da3c44699ed7db51b7d9");
        let ciphertext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        decrypt_cbc(&ciphertext, &key, &iv);
    }

    #[test]
    #[should_panic(expected="Partial block of length 13 passed for AES decryption!")]
    fn test_decrypt_cbc_bad_block() {
        let key = hex_to_bytes("56e47a38c5598974bc46903dba290349");
        let iv = hex_to_bytes("8ce82eefbea0da3c44699ed7db51b7d9");
        let ciphertext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09");

        decrypt_cbc(&ciphertext, &key, &iv);
    }

    #[test]
    #[should_panic(expected="Illegal IV length 13 passed as an AES IV!")]
    fn test_decrypt_cbc_bad_iv() {
        let key = hex_to_bytes("56e47a38c5598974bc46903dba290349");
        let iv = hex_to_bytes("8ce82eefbea0da3c44699ed7db");
        let ciphertext = hex_to_bytes("6743C3D1519AB4F2CD9A78AB09A511BD");

        decrypt_cbc(&ciphertext, &key, &iv);
    }

    #[test]
    fn test_encrypt_ctr() {
        let key = ascii_to_bytes("YELLOW SUBMARINE");
        let plaintext = ascii_to_bytes("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
        let ciphertext = base64_to_bytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");

        assert_eq!(encrypt_ctr(&plaintext, &key, 0), ciphertext);
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_encrypt_ctr_bad_key() {
        let key = ascii_to_bytes("YELLOW SUBMAR");
        let plaintext = ascii_to_bytes("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");

        encrypt_ctr(&plaintext, &key, 0);
    }

    #[test]
    fn test_decrypt_ctr() {
        let key = ascii_to_bytes("YELLOW SUBMARINE");
        let plaintext = ascii_to_bytes("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
        let ciphertext = base64_to_bytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");

        println!("{}", bytes_to_ascii(&decrypt_ctr(&ciphertext, &key, 0)));

        assert_eq!(decrypt_ctr(&ciphertext, &key, 0), plaintext);
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_decrypt_ctr_bad_key() {
        let key = ascii_to_bytes("YELLOW SUBMAR");
        let ciphertext = base64_to_bytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");

        decrypt_ctr(&ciphertext, &key, 0);
    }
}