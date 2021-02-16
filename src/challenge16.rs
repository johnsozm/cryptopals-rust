use crate::padding::{pkcs7_pad, pkcs7_unpad};
use crate::converter::{ascii_to_bytes, bytes_to_ascii};
use crate::aes::{encrypt_cbc, decrypt_cbc};

//Consistent encryption key and IV for use by oracle
static KEY: [u8; 16] = [203, 24, 228, 68, 97, 200, 72, 185, 91, 149, 156, 223, 119, 183, 5, 173];
static IV: [u8; 16] = [37, 20, 51, 240, 87, 18, 32, 84, 140, 108, 34, 189, 113, 179, 99, 12];

///Creates user token
fn create_token(user_data: &str) -> Vec<u8> {
    let escaped = user_data.replace(";", "';'").replace("=", "'='");
    let mut token = String::from("comment1=cooking%20MCs;userdata=");
    token.push_str(&escaped);
    token.push_str(";comment2=%20like%20a%20pound%20of%20bacon");

    let padded = pkcs7_pad(&ascii_to_bytes(&token), 16);
    return encrypt_cbc(&padded, &KEY.to_vec(), &IV.to_vec());
}

//Decrypts user token and detects whether it contains ";admin=true;"
fn is_admin(token: Vec<u8>) -> bool {
    let decrypted = decrypt_cbc(&token, &KEY.to_vec(), &IV.to_vec());
    let as_string = bytes_to_ascii(&pkcs7_unpad(&decrypted).unwrap());
    return as_string.contains(";admin=true;");
}

fn challenge16() -> Vec<u8> {
    //TODO: Determine block length being used
    //TODO: For each possible offset from prefix (0..block_length)
        //TODO: Construct payload as padding + ":admin<true:" and encrypt
        //TODO: For each possible location of plaintext in resulting message:
            //TODO: Flip low bits of correct bytes in previous block to turn :/< into ;/=
            //TODO: Check if message passes admin test
    return vec![];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_solution() {
        assert!(is_admin(challenge16()));
    }
}
