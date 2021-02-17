use thiserror::Error;

///Custom padding errors
#[derive(Error, Debug)]
pub enum PaddingError {
    ///Error for bad padding on a PKCS string
    #[error("String was not properly PKCS#7 padded.")]
    BadPKCSPadding,
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
        return Err(PaddingError::BadPKCSPadding);
    }
    for i in message.len()-pad_length..message.len() {
        if message[i] as usize != pad_length {
            return Err(PaddingError::BadPKCSPadding);
        }
    }

    return Ok(message[0..message.len()-pad_length].to_vec());
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
}