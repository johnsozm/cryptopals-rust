use crate::converter::{base64_to_bytes, ascii_to_bytes, bytes_to_ascii};
use crate::aes::decrypt_ctr;

fn challenge18() -> String {
    let ciphertext = base64_to_bytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    let key = ascii_to_bytes("YELLOW SUBMARINE");
    let plaintext = decrypt_ctr(&ciphertext, &key, 0);
    return bytes_to_ascii(&plaintext);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge18(), "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
    }
}