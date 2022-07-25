///Encrypts the given plaintext using RC4 with the given key.
///Panics if the key is null or greater than 256 bytes.
pub fn encrypt_rc4(plaintext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    if key.is_empty() || key.len() > 256 {
        panic!("Illegal key of length {} passed to RC4 cipher!", key.len());
    }

    //Digest key
    let mut s = vec![0; 256];
    for i in 0..256 {
        s[i] = i;
    }
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] + key[i % key.len()] as usize) % 256;
        let tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }

    let mut ciphertext = vec![0; plaintext.len()];
    let mut i = 0;
    j = 0;
    for n in 0..plaintext.len() {
        //Update i and j
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        //Swap s[i] and s[j]
        let tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;

        //Generate next keystream byte and xor with next plaintext byte
        let k = s[(s[i] + s[j]) % 256] as u8;
        ciphertext[n] = plaintext[n] ^ k;
    }

    return ciphertext;
}

///Decrypts the given ciphertext using RC4 with the given key.
///Panics if the key is null or greater than 256 bytes.
pub fn decrypt_rc4(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    return encrypt_rc4(ciphertext, key);
}

#[cfg(test)]
mod tests {
    use crate::converter::ascii_to_bytes;
    use super::*;

    #[test]
    fn test_encrypt_rc4() {
        let key1 = ascii_to_bytes("Key");
        let key2 = ascii_to_bytes("Wiki");
        let key3 = ascii_to_bytes("Secret");
        let message1 = ascii_to_bytes("Plaintext");
        let message2 = ascii_to_bytes("pedia");
        let message3 = ascii_to_bytes("Attack at dawn");
        assert_eq!(encrypt_rc4(&message1, &key1), vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
        assert_eq!(encrypt_rc4(&message2, &key2), vec![0x10, 0x21, 0xBF, 0x04, 0x20]);
        assert_eq!(encrypt_rc4(&message3, &key3), vec![0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5]);
    }
}