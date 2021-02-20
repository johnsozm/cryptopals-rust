use crate::converter::{bytes_to_ascii, ascii_to_bytes};
use crate::aes::{encrypt_ctr, decrypt_ctr};
use rand::random;

lazy_static! {
    static ref KEY: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
    static ref NONCE: u64 = random();
}

///Creates user token
fn create_token(user_data: &str) -> Vec<u8> {
    let escaped = user_data.replace(";", "';'").replace("=", "'='");
    let mut token = String::from("comment1=cooking%20MCs;userdata=");
    token.push_str(&escaped);
    token.push_str(";comment2=%20like%20a%20pound%20of%20bacon");

    let plaintext = ascii_to_bytes(&token);

    return encrypt_ctr(&plaintext, &KEY, *NONCE);
}

///Decrypts user token and detects whether it contains ";admin=true;"
fn is_admin(token: &Vec<u8>) -> bool {
    let decrypted = decrypt_ctr(&token, &KEY, *NONCE);
    let as_string = bytes_to_ascii(&decrypted);
    return as_string.contains(";admin=true;");
}

fn challenge26() -> Vec<u8> {
    //Generate token to corrupt
    let token = create_token(":admin<true:");

    //Try all possible offsets for the corruption
    for offset in 0..token.len() - 11 {
        let mut payload = token.clone();
        payload[offset] ^= 0x01;
        payload[offset+6] ^= 0x01;
        payload[offset+11] ^= 0x01;

        if is_admin(&payload) {
            return payload;
        }
    }

    //Default return if corruption fails
    return vec![];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(is_admin(&challenge26()));
    }
}