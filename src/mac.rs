use crate::hash::Hash;

///MAC message structure - contains message, signature, and the hash function used
pub struct MAC {
    message: Vec<u8>,
    signature: Vec<u8>
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

///Validates a secret-prefix MAC for the given message using the given key + hash function
pub fn verify_prefix_max(mac: MAC, key: &Vec<u8>, hash_function: Hash) -> bool {
    let mut concat = key.clone();
    concat.append(&mut mac.message.clone());
    let expected_hash = hash_function.digest(&concat);
    return expected_hash == mac.signature;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::ascii_to_bytes;
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

        assert!(verify_prefix_max(mac, &key, Hash::SHA1));
        assert!(!verify_prefix_max(mac2, &key, Hash::SHA1));
    }
}
