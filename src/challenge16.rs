use crate::padding::{pkcs7_pad, pkcs7_unpad};
use crate::converter::{ascii_to_bytes, bytes_to_ascii};
use crate::aes::{encrypt_cbc, decrypt_cbc};
use rand::random;

lazy_static! {
    static ref KEY: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
    static ref IV: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
}

///Creates user token
fn create_token(user_data: &str) -> Vec<u8> {
    let escaped = user_data.replace(";", "';'").replace("=", "'='");
    let mut token = String::from("comment1=cooking%20MCs;userdata=");
    token.push_str(&escaped);
    token.push_str(";comment2=%20like%20a%20pound%20of%20bacon");

    let padded = pkcs7_pad(&ascii_to_bytes(&token), 16);
    return encrypt_cbc(&padded, &KEY, &IV);
}

///Decrypts user token and detects whether it contains ";admin=true;"
fn is_admin(token: &Vec<u8>) -> bool {
    let decrypted = decrypt_cbc(&token, &KEY, &IV);
    let as_string = bytes_to_ascii(&pkcs7_unpad(&decrypted).unwrap());
    return as_string.contains(";admin=true;");
}

fn challenge16() -> Vec<u8> {
    //Determine block length being used
    let mut test_data= String::from("");
    let mut len_token = create_token("");
    let base_length = len_token.len();
    while len_token.len() == base_length {
        test_data.push('A');
        len_token = create_token(&test_data);
    }
    let block_length = len_token.len() - base_length;

    //Since we don't know the details of token construction, exhaustively search payload offsets
    for offset in 0..block_length {
        let mut payload = String::from("A".repeat(offset));
        payload.push_str(":admin<true:");
        let ciphertext = create_token(&payload);

        //Since we don't know details of token construction, exhaustively attempt bit-flipping
        for block_index in 0..(ciphertext.len() / block_length) - 1 {
            let mut malicious_ciphertext = ciphertext.clone();
            malicious_ciphertext[block_index*block_length] ^= 0x01;
            malicious_ciphertext[(block_index*block_length)+6] ^= 0x1;
            malicious_ciphertext[(block_index*block_length)+11] ^= 0x01;

            if is_admin(&malicious_ciphertext) {
                return malicious_ciphertext;
            }
        }
    }

    return vec![]; //Default return if nothing is found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(is_admin(&challenge16()));
    }
}
