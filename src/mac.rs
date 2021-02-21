use crate::hash::Hash;
use crate::xor::xor_bytes;

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

///Creates an HMAC for the given message using the given keu + hash function
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

    let mut inner_block = xor_bytes(&padded_key, &vec![0x36; hash_function.block_length()]);
    inner_block.append(&mut message.clone());

    let mut outer_block = xor_bytes(&padded_key, &vec![0x5c; hash_function.block_length()]);
    outer_block.append(&mut hash_function.digest(&inner_block));


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

    let mut inner_block = xor_bytes(&padded_key, &vec![0x36; hash_function.block_length()]);
    inner_block.append(&mut mac.message.clone());

    let mut outer_block = xor_bytes(&padded_key, &vec![0x5c; hash_function.block_length()]);
    outer_block.append(&mut hash_function.digest(&inner_block));

    let expected_signature = hash_function.digest(&outer_block);

    return mac.signature == expected_signature;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::{ascii_to_bytes, bytes_to_hex, hex_to_bytes};
    use crate::hash::Hash;

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
}
