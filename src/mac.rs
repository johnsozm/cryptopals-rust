use crate::hash::Hash;
use crate::xor::xor_bytes;
use crate::aes::encrypt_cbc;
use crate::padding::pkcs7_pad;

///MAC message structure - contains message, signature, and the hash function used
pub struct MAC {
    pub message: Vec<u8>,
    pub signature: Vec<u8>
}

///Creates a secret-prefix MAC for the given message using the given key + hash function
pub fn create_prefix_mac(message: &Vec<u8>, key: &Vec<u8>, hash_function: Hash) -> MAC {
    let mut concat = key.clone();
    concat.append(&mut message.clone());

    return MAC {
        message: message.clone(),
        signature: hash_function.digest(&concat)
    };
}

///Validates a secret-prefix MAC using the given key + hash function
pub fn verify_prefix_max(mac: &MAC, key: &Vec<u8>, hash_function: Hash) -> bool {
    let mut concat = key.clone();
    concat.append(&mut mac.message.clone());
    let expected_hash = hash_function.digest(&concat);
    return expected_hash == mac.signature;
}

///Creates an HMAC for the given message using the given key + hash function
pub fn create_hmac(message: &Vec<u8>, key: &Vec<u8>, hash_function: Hash) -> MAC {
    let mut padded_key= vec![];

    //Generate K'
    if padded_key.len() <= hash_function.block_length() {
        padded_key = key.clone();
        while padded_key.len() < hash_function.block_length() {
            padded_key.push(0);
        }
    }
    else {
        padded_key = hash_function.digest(&key);
    }

    //Compute inner block: (K' ^ ipad) || m
    let mut inner_block = xor_bytes(&padded_key, &vec![0x36; hash_function.block_length()]);
    inner_block.append(&mut message.clone());

    //Compute outer block: (K' ^ opad) || H(inner block)
    let mut outer_block = xor_bytes(&padded_key, &vec![0x5c; hash_function.block_length()]);
    outer_block.append(&mut hash_function.digest(&inner_block));

    //Create final MAC: message || H(outer block)
    return MAC {
        message: message.clone(),
        signature: hash_function.digest(&outer_block)
    };
}

///Validates an HMAC using the given key + hash function
pub fn verify_hmac(mac: &MAC, key: &Vec<u8>, hash_function: Hash) -> bool {
    let mut padded_key= vec![];

    //Generate K'
    if padded_key.len() <= hash_function.block_length() {
        padded_key = key.clone();
        while padded_key.len() < hash_function.block_length() {
            padded_key.push(0);
        }
    }
    else {
        padded_key = hash_function.digest(&key);
    }

    //Compute inner block: (K' ^ ipad) || m
    let mut inner_block = xor_bytes(&padded_key, &vec![0x36; hash_function.block_length()]);
    inner_block.append(&mut mac.message.clone());

    //Compute outer block: (K' ^ opad) || H(inner block)
    let mut outer_block = xor_bytes(&padded_key, &vec![0x5c; hash_function.block_length()]);
    outer_block.append(&mut hash_function.digest(&inner_block));

    //Compute expected signature: H(outer block)
    let expected_signature = hash_function.digest(&outer_block);

    return mac.signature == expected_signature;
}

///Creates a CBC-MAC signature for the message with the given secret key and IV.
pub fn create_cbc_mac(message: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> MAC {
    //Compute CBC encryption of message
    let ciphertext = encrypt_cbc(&pkcs7_pad(&message, 16), &key, &iv);

    //Compute signature as final block of encryption
    let num_blocks = ciphertext.len() / 16;
    let signature = ciphertext[(num_blocks-1)*16..num_blocks*16].to_vec();

    return MAC {
        message: message.clone(),
        signature
    };
}

///Verifies a CBC-MAC signature using the given secret key and IV.
pub fn verify_cbc_mac(mac: &MAC, key: &Vec<u8>, iv: &Vec<u8>) -> bool {
    //Compute CBC encryption of message
    let ciphertext = encrypt_cbc(&pkcs7_pad(&mac.message, 16), &key, &iv);

    //Compute expected signature as final block of encryption
    let num_blocks = ciphertext.len() / 16;
    let expected_signature = ciphertext[(num_blocks-1)*16..num_blocks*16].to_vec();

    return expected_signature == mac.signature;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::{ascii_to_bytes, bytes_to_hex, hex_to_bytes};
    use crate::hash::Hash;
    use crate::aes::encrypt_cbc;
    use crate::padding::pkcs7_pad;

    #[test]
    fn test_create_prefix_mac() {
        let message = ascii_to_bytes("This is a test message to be signed");
        let key = ascii_to_bytes("woop woop woop");

        let mut concat = key.clone();
        concat.append(&mut message.clone());

        let expected_hash = Hash::SHA1.digest(&concat);
        let mac = create_prefix_mac(&message, &key, Hash::SHA1);

        assert_eq!(mac.message, message);
        assert_eq!(mac.signature, expected_hash);
    }

    #[test]
    fn test_verify_prefix_max() {
        let message = ascii_to_bytes("This is a test message to be signed");
        let key = ascii_to_bytes("woop woop woop");

        let mac = create_prefix_mac(&message, &key, Hash::SHA1);
        let mut mac2 = MAC {
            message: mac.message.clone(),
            signature: mac.signature.clone()
        };
        mac2.signature[0] += 5;

        assert!(verify_prefix_max(&mac, &key, Hash::SHA1));
        assert!(!verify_prefix_max(&mac2, &key, Hash::SHA1));
    }

    #[test]
    fn test_create_hmac() {
        let message = ascii_to_bytes("The quick brown fox jumps over the lazy dog");
        let key = ascii_to_bytes("key");

        let mac = create_hmac(&message, &key, Hash::SHA1);
        assert_eq!(mac.message, message);
        assert_eq!(bytes_to_hex(&mac.signature), "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    }

    #[test]
    fn test_verify_hmac() {
        let message = ascii_to_bytes("The quick brown fox jumps over the lazy dog");
        let key = ascii_to_bytes("key");
        let hash = hex_to_bytes("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");

        let mac1 = MAC {
            message: message.clone(),
            signature: hash.clone()
        };
        let mut mac2 = MAC {
            message: message.clone(),
            signature: hash.clone()
        };
        mac2.message[41] -= 1;

        assert!(verify_hmac(&mac1, &key, Hash::SHA1));
        assert!(!verify_hmac(&mac2, &key, Hash::SHA1));
    }

    #[test]
    fn test_create_cbc_mac() {
        let key = ascii_to_bytes("YELLOW SUBMARINE");
        let iv = vec![0x00; 16];
        let message = ascii_to_bytes("The quick brown fox jumps over the lazy dog");

        let encrypted = encrypt_cbc(&pkcs7_pad(&message, 16), &key, &iv);
        let num_blocks = encrypted.len() / 16;
        let mac = create_cbc_mac(&message, &key, &iv);
        assert_eq!(mac.message, message);
        assert_eq!(mac.signature, encrypted[(num_blocks-1)*16..num_blocks*16].to_vec());
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_create_cbc_mac_bad_key() {
        let key = ascii_to_bytes("YELLOW SUBMAR");
        let iv = vec![0x00; 16];
        let message = ascii_to_bytes("The quick brown fox jumps over the lazy dog");

        create_cbc_mac(&message, &key, &iv);
    }

    #[test]
    #[should_panic(expected="Illegal IV length 13 passed as an AES IV!")]
    fn test_create_cbc_mac_bad_iv() {
        let key = ascii_to_bytes("YELLOW SUBMARINE");
        let iv = vec![0x00; 13];
        let message = ascii_to_bytes("The quick brown fox jumps over the lazy dog");

        create_cbc_mac(&message, &key, &iv);
    }

    #[test]
    fn test_verify_cbc_mac() {
        let key = ascii_to_bytes("YELLOW SUBMARINE");
        let iv = vec![0x00; 16];
        let message = ascii_to_bytes("The quick brown fox jumps over the lazy dog");

        let encrypted = encrypt_cbc(&pkcs7_pad(&message, 16), &key, &iv);
        let num_blocks = encrypted.len() / 16;
        let mac1 = MAC {
            message: message.clone(),
            signature: encrypted[(num_blocks-1)*16..num_blocks*16].to_vec()
        };
        let mut mac2 = MAC {
            message: message.clone(),
            signature: encrypted[(num_blocks-1)*16..num_blocks*16].to_vec()
        };
        mac2.signature[12] -= 1;

        assert!(verify_cbc_mac(&mac1, &key, &iv));
        assert!(!verify_cbc_mac(&mac2, &key, &iv));
    }

    #[test]
    #[should_panic(expected="Illegal key length 13 passed as an AES key!")]
    fn test_verify_cbc_mac_bad_key() {
        let key = ascii_to_bytes("YELLOW SUBMARINE");
        let bad_key = ascii_to_bytes("YELLOW SUBMAR");
        let iv = vec![0x00; 16];
        let message = ascii_to_bytes("The quick brown fox jumps over the lazy dog");

        let mac = create_cbc_mac(&message, &key, &iv);
        verify_cbc_mac(&mac, &bad_key, &iv);
    }

    #[test]
    #[should_panic(expected="Illegal IV length 13 passed as an AES IV!")]
    fn test_verify_cbc_mac_bad_iv() {
        let key = ascii_to_bytes("YELLOW SUBMARINE");
        let iv = vec![0x00; 16];
        let bad_iv = vec![0x00; 13];
        let message = ascii_to_bytes("The quick brown fox jumps over the lazy dog");

        let mac = create_cbc_mac(&message, &key, &iv);
        verify_cbc_mac(&mac, &key, &bad_iv);
    }
}
