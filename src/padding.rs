use thiserror::Error;
use crate::hash::Hash;
use rand::random;

///Custom padding errors
#[derive(Error, Debug)]
pub enum PaddingError {
    ///Error for bad padding on a PKCS7 string
    #[error("String was not properly PKCS#7 padded.")]
    BadPKCS7Padding,
    //Error for bad padding on a PKCS1.5 signature
    #[error("String was not a properly PKCS#1.5 padded signature")]
    BadPKCS15SignaturePadding,
    //Error for bad padding on a PKCS1.5 message
    #[error("String was not a properly PKCS#1.5 padded message")]
    BadPKCS15MessagePadding,
}

///Pads a string to the given block size according to the PCKS#7 padding scheme.
pub fn pkcs7_pad(message: &Vec<u8>, block_size: usize) -> Vec<u8> {
    //Determine pad length (between 1 and block_size)
    let pad_length = block_size - (message.len() % block_size);
    let mut padded = message.clone();

    for _i in 0..pad_length {
        padded.push(pad_length as u8);
    }

    return padded;
}

///Unpads a PKCS#7 padded string.
///Returns an error if the string is not properly padded.
pub fn pkcs7_unpad(message: &Vec<u8>) -> Result<Vec<u8>, PaddingError> {
    let pad_length: usize = message[message.len() - 1] as usize;

    //Verify last pad_length bytes have value pad_length
    if pad_length > message.len() || pad_length == 0 {
        return Err(PaddingError::BadPKCS7Padding);
    }
    for i in message.len()-pad_length..message.len() {
        if message[i] as usize != pad_length {
            return Err(PaddingError::BadPKCS7Padding);
        }
    }

    return Ok(message[0..message.len()-pad_length].to_vec());
}

///Pads a signature to the given block size according to the PKCS#1.5 padding scheme.
pub fn pkcs15_signature_pad(message: &Vec<u8>, bit_length: usize, signature_algorithm: Hash) -> Vec<u8> {
    if message.len() > (bit_length/8) - 11 {
        panic!("Message too long to pad.");
    }
    if message.len() != signature_algorithm.hash_length() {
        panic!("Message length does not match expected hash length.");
    }

    let asn1_len = message.len() + 7; //Byte length of the ASN.1 signature block
    let pad_len = (bit_length / 8) - asn1_len - 3; //Length of 0xff padding
    let mut padded = vec![];

    //Pad header
    padded.push(0x00);
    padded.push(0x01);

    //0xff padding
    padded.append(&mut vec![0xff; pad_len]);

    //Pad termination
    padded.push(0x00);

    //ASN.1 header
    //Sequence header
    padded.push(0x70); //Object is a constructed sequence
    padded.push((message.len() + 5) as u8); //Object will be hash length + 5 bytes long

    //Append hash specifier
    padded.push(0x46); //Object is an object identifier
    padded.push(0x01); //Length is 1 byte
    match signature_algorithm { //Hash identifier values (might be wrong but doesn't really matter)
        Hash::SHA1 => padded.push(6),
        Hash::SHA256 => padded.push(11),
        Hash::MD4 => padded.push(4)
    }

    //Append hash bytes
    padded.push(0x44); //Object is an octet string
    padded.push(signature_algorithm.hash_length() as u8); //Length is equal to hash length
    padded.append(&mut message.clone()); //Contents are hash bytes

    return padded;
}

///Unpads a PKCS#1.5 padded signature.
///Returns an error if the string is not properly padded.
pub fn pkcs15_signature_unpad(message: &Vec<u8>) -> Result<Vec<u8>, PaddingError> {
    //Traverse padding until we hit ANS.1 information. Error out if the padding is ever bad
    if message[0] != 0x00 || message[1] != 0x01 || message[2] != 0xff {
        return Err(PaddingError::BadPKCS15SignaturePadding);
    }

    let mut index = 2;
    while message[index] == 0xff {
        index += 1;
    }

    if message[index] != 0x00 || message[index+1] != 0x70 {
        return Err(PaddingError::BadPKCS15SignaturePadding);
    }

    let asn_len = message[index+2];
    if asn_len as usize + index + 3 as usize != message.len() {
        return Err(PaddingError::BadPKCS15SignaturePadding);
    }

    let hash_len = match message[index + 5] {
        4 => Hash::MD4.hash_length(),
        6 => Hash::SHA1.hash_length(),
        11 => Hash::SHA256.hash_length(),
        _ => return Err(PaddingError::BadPKCS15SignaturePadding)
    };

    return Ok(message[index+8..index+8+hash_len].to_vec());
}

///Unpads a PKCS#1.5 padded signature, but with no total length check.
///Returns an error if the string is not properly padded.
pub fn pkcs15_signature_unpad_lazy(message: &Vec<u8>) -> Result<Vec<u8>, PaddingError> {
    //Traverse padding until we hit ANS.1 information. Error out if the padding is ever bad
    if message[0] != 0x00 || message[1] != 0x01 || message[2] != 0xff {
        return Err(PaddingError::BadPKCS15SignaturePadding);
    }

    let mut index = 2;
    while message[index] == 0xff {
        index += 1;
    }

    if message[index] != 0x00 || message[index+1] != 0x70 {
        return Err(PaddingError::BadPKCS15SignaturePadding);
    }

    let hash_len = match message[index + 5] {
        4 => Hash::MD4.hash_length(),
        6 => Hash::SHA1.hash_length(),
        11 => Hash::SHA256.hash_length(),
        _ => return Err(PaddingError::BadPKCS15SignaturePadding)
    };

    return Ok(message[index+8..index+8+hash_len].to_vec());
}

pub fn pkcs15_message_pad(message: &Vec<u8>, bit_length: usize) -> Vec<u8> {
    if message.len() > (bit_length/8) - 12 {
        panic!("Message too long to pad.");
    }

    //Initialize with 00 02 bytes
    let pad_length = (bit_length/8) - message.len();
    let mut padded = vec![0x00, 0x02];

    //Add random nonzero bytes + 00 byte
    while padded.len() < pad_length - 1 {
        let b: u8 = random();
        if b != 0 {
            padded.push(b);
        }
    }
    padded.push(0x00);

    //Append message and return
    padded.append(&mut message.clone());
    return padded;
}

pub fn pkcs15_message_unpad(message: &Vec<u8>) -> Result<Vec<u8>, PaddingError> {
    //Confirm message starts with 00 02 bytes
    if message[0] != 0 || message[1] != 2 {
        return Err(PaddingError::BadPKCS15MessagePadding);
    }

    //Scan forward to delimiting 00 byte
    let mut index = 2;
    while message[index] != 0 && index < message.len() {
        index += 1;
    }

    //If there was no 00 byte, padding was not valid. Else return rest of bytes as the data.
    if index == message.len() {
        return Err(PaddingError::BadPKCS15MessagePadding);
    }

    return Ok(message[index+1..].to_vec());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_pad() {
        let message = crate::converter::ascii_to_bytes("Yellow Submarine");
        let mut padded = message.clone();
        for _i in 0..4 {
            padded.push(4);
        }

        assert_eq!(pkcs7_pad(&message, 20), padded);
    }

    #[test]
    fn test_pkcs7_unpad() {
        let message = crate::converter::ascii_to_bytes("Yellow Submarine");
        let mut padded = message.clone();
        for _i in 0..4 {
            padded.push(4);
        }

        assert_eq!(pkcs7_unpad(&padded).unwrap(), message);
    }

    #[test]
    fn test_pkcs7_unpad_error() {
        let mut message = crate::converter::ascii_to_bytes("Yellow Submarine");
        for _i in 0..4 {
            message.push(7);
        }

        match pkcs7_unpad(&message) {
            Ok(_) => panic!("Should have thrown an error for badly padded string!"),
            Err(_) => assert!(true)
        }
    }

    #[test]
    fn test_pkcs15_signature_pad() {
        let hash: Vec<u8> = [0xaa; 16].to_vec();
        let mut expected: Vec<u8> = vec![];

        //Initial padding: 00 01 [ff] 00
        expected.push(0x00);
        expected.push(0x01);
        expected.append(&mut vec![0xff; 102]);
        expected.push(0x00);

        //Sequence header
        expected.push(0x70); //Object is a constructed sequence
        expected.push(0x15); //Total length is 21 bytes

        //Append hash specifier
        expected.push(0x46); //Object is an object identifier
        expected.push(0x01); //Length is 1 byte
        expected.push(0x04); //Identifier for MD4 hash

        //Append hash bytes
        expected.push(0x44); //Object is an octet string
        expected.push(0x10); //Length is 16 bytes
        expected.append(&mut hash.clone()); //Hash bytes

        assert_eq!(pkcs15_signature_pad(&hash, 1024, Hash::MD4), expected);
    }

    #[test]
    #[should_panic(expected="Message too long to pad.")]
    fn test_pkcs15_signature_pad_length_error() {
        let message = vec![0x55; 1000];
        pkcs15_signature_pad(&message, 1024, Hash::MD4);
    }

    #[test]
    #[should_panic(expected="Message length does not match expected hash length.")]
    fn test_pkcs15_signature_hash_length_error() {
        let message = vec![0x55; 100];
        pkcs15_signature_pad(&message, 1024, Hash::MD4);
    }

    #[test]
    fn test_pkcs15_signature_unpad() {
        let hash: Vec<u8> = [0xaa; 16].to_vec();
        let mut padded: Vec<u8> = vec![];

        //Initial padding: 00 01 [ff] 00
        padded.push(0x00);
        padded.push(0x01);
        padded.append(&mut vec![0xff; 102]);
        padded.push(0x00);

        //Sequence header
        padded.push(0x70); //Object is a constructed sequence
        padded.push(0x15); //Total length is 21 bytes

        //Append hash specifier
        padded.push(0x42); //Object is a primitive integer
        padded.push(0x01); //Length is 1 byte
        padded.push(0x04); //Identifier for MD4 hash

        //Append hash bytes
        padded.push(0x44); //Object is an octet string
        padded.push(0x10); //Length is 16 bytes
        padded.append(&mut hash.clone()); //Hash bytes

        assert_eq!(pkcs15_signature_unpad(&padded).unwrap(), hash);
        assert_eq!(pkcs15_signature_unpad_lazy(&padded).unwrap(), hash);
    }

    #[test]
    fn test_pkcs15_signature_unpad_error() {
        let message = vec![0x55; 128];
        match pkcs15_signature_unpad(&message) {
            Ok(_) => panic!("Should have thrown an error for badly padded string!"),
            Err(_) => assert!(true)
        }
        match pkcs15_signature_unpad_lazy(&message) {
            Ok(_) => panic!("Should have thrown an error for badly padded string!"),
            Err(_) => assert!(true)
        }
    }

    #[test]
    fn test_pkcs15_signature_unpad_lazy_error() {
        let hash: Vec<u8> = [0xaa; 16].to_vec();
        let mut padded: Vec<u8> = vec![];

        //Initial padding: 00 01 [ff] 00
        padded.push(0x00);
        padded.push(0x01);
        padded.push(0xff);
        padded.push(0x00);

        //Sequence header
        padded.push(0x70); //Object is a constructed sequence
        padded.push(0x15); //Total length is 21 bytes

        //Append hash specifier
        padded.push(0x42); //Object is a primitive integer
        padded.push(0x01); //Length is 1 byte
        padded.push(0x04); //Identifier for MD4 hash

        //Append hash bytes
        padded.push(0x44); //Object is an octet string
        padded.push(0x10); //Length is 16 bytes
        padded.append(&mut hash.clone()); //Hash bytes
        padded.append(&mut vec![0xff; 121]);

        match pkcs15_signature_unpad(&padded) {
            Ok(_) => panic!("Should have thrown an error for badly padded string!"),
            Err(_) => assert!(true)
        }
        match pkcs15_signature_unpad_lazy(&padded) {
            Ok(h) => assert_eq!(h, hash),
            Err(_) => panic!("Lazy unpad should not have thrown an error for this string!")
        }
    }

    #[test]
    fn test_pkcs15_message_pad() {
        let message = vec![0x5d; 26];
        let padded = pkcs15_message_pad(&message, 1024);
        assert_eq!(padded.len(), 128);
        assert_eq!(padded[0], 0);
        assert_eq!(padded[1], 2);
        for i in 2..=100 {
            assert_ne!(padded[i], 0);
        }
        assert_eq!(padded[101], 0);
        assert_eq!(padded[102..], message);
    }

    #[test]
    #[should_panic(expected="Message too long to pad.")]
    fn test_pkcs15_message_pad_length_error() {
        let message = vec![22, 22, 22, 22, 22, 22];
        pkcs15_message_pad(&message, 32);
    }

    #[test]
    fn test_pkcs15_message_unpad() {
        let message = vec![0x6a; 22];
        let mut padded = vec![0x00, 0x02];
        padded.append(&mut vec![0xa1; 101]);
        padded.push(0);
        padded.append(&mut message.clone());

        match pkcs15_message_unpad(&padded) {
            Ok(x) => assert_eq!(x, message),
            Err(_) => panic!("Unpad should not have failed on known-good test case.")
        }
    }

    #[test]
    fn test_pkcs15_message_unpad_error() {
        let bad_pad = vec![0xaa; 12];
        match pkcs15_message_unpad(&bad_pad) {
            Ok(_) => panic!("Unpad should have failed for known-bad test case."),
            Err(_) => assert!(true)
        }
    }
}