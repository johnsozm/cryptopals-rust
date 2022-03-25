use rand::random;
use crate::padding::pkcs7_pad;
use crate::aes::{encrypt_ecb, encrypt_cbc, detect_ecb};
use crate::converter::ascii_to_bytes;

///Encrypts the given message with a random key/IV, and random padding at the head and tail
///Returns (encryption, true) if ECB was used, (encryption, false) if CBC was used
fn encrypt_random_padding(message: &Vec<u8>) -> (Vec<u8>, bool) {
    let head_pad: u8 = random();
    let tail_pad: u8 = random();
    let mut padded: Vec<u8> = vec![];
    let mut key: Vec<u8> = vec![];

    //Generate message to encrypt
    for _i in 0..(head_pad % 5) + 5 {
        padded.push(random());
    }
    padded.append(&mut message.clone());
    for _i in 0..(tail_pad % 5) + 5 {
        padded.push(random())
    }

    let plaintext = pkcs7_pad(&padded, 16);

    //Generate random encryption key
    for _i in 0..16 {
        key.push(random());
    }

    //Randomly decide whether to use ECB or CBC mode
    return if random() {
        (encrypt_ecb(&plaintext, &key), true)
    }
    else {
        let mut iv: Vec<u8> = vec![];

        //Generate random IV
        for _i in 0..16 {
            iv.push(random());
        }

        (encrypt_cbc(&plaintext, &key, &iv), false)
    }
}

fn challenge11() -> bool {
    //Ensure there are at least 2 duplicate blocks
    let message = ascii_to_bytes(&"A".repeat(48));

    //Try many random encryptions to ensure robustness
    for _i in 0..100 {
        let (ciphertext, ecb) = encrypt_random_padding(&message);
        if detect_ecb(&ciphertext) ^ ecb {
            return false;
        }
    }

    return true;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(challenge11());
    }
}