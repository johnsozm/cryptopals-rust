use crate::converter::{hex_to_bytes, bytes_to_ascii};
use crate::xor::{guess_single_byte_xor, xor_repeating};

fn challenge3() -> String {
    let ciphertext = hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let key = guess_single_byte_xor(&ciphertext).0;
    let plaintext = xor_repeating(&ciphertext, &vec![key]);
    return bytes_to_ascii(&plaintext);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge3(), "Cooking MC's like a pound of bacon")
    }
}