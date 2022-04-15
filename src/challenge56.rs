use rand::random;
use crate::rc4::encrypt_rc4;

static COOKIE: [u8; 30] = [0x42, 0x45, 0x20, 0x53, 0x55, 0x52, 0x45, 0x20, 0x54, 0x4f, 0x20, 0x44, 0x52, 0x49, 0x4e, 0x4b, 0x20, 0x59, 0x4f, 0x55, 0x52, 0x20, 0x4f, 0x56, 0x41, 0x4c, 0x54, 0x49, 0x4e, 0x45];

fn get_ciphertext(request: &Vec<u8>) -> Vec<u8> {
    let mut message = request.clone();
    message.append(&mut COOKIE.to_vec());

    let mut key = vec![0; 16];
    for i in 0..16 {
        key[i] = random();
    }

    return encrypt_rc4(&message, &key);
}

fn challenge56() -> Vec<u8> {
    //TODO: Implement attack

    return vec![];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge56(), COOKIE);
    }
}