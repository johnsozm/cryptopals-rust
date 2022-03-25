use crate::converter::{base64_file_to_bytes_by_line, bytes_to_ascii};
use crate::xor::{guess_multi_byte_xor, xor_repeating};

fn challenge20() -> String {
    let mut ciphertexts = base64_file_to_bytes_by_line("challenge20.txt");

    //Truncate all ciphertexts to length of the shortest ciphertext
    let mut shortest_length = ciphertexts[0].len();
    for c in &ciphertexts {
        if c.len() < shortest_length {
            shortest_length = c.len();
        }
    }

    let max_index = ciphertexts.len();
    for i in 0..max_index {
        ciphertexts[i] = ciphertexts[i][0..shortest_length].to_vec();
    }

    //Concatenate truncated texts & perform multi-byte XOR analysis
    let mut combined_ciphertext = vec![];
    for c in ciphertexts {
        combined_ciphertext.append(&mut c.clone());
    }

    let key = guess_multi_byte_xor(&combined_ciphertext);
    let plaintext = xor_repeating(&combined_ciphertext, &key);

    return bytes_to_ascii(&plaintext);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(challenge20().starts_with("I'm rated \"R\"...this is a warning, ya better void"));
    }
}