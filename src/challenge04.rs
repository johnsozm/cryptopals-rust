use std::fs::File;
use std::io::{BufRead, BufReader};
use crate::converter::{hex_to_bytes, bytes_to_ascii};
use crate::xor::{guess_single_byte_xor, xor_repeating};

fn challenge4() -> String {
    let file = File::open("challenge04.txt").unwrap();
    let reader = BufReader::new(file);
    let mut best_line: Vec<u8> = vec![];
    let mut best_score = 999.999;

    //Find decoded line that has the lowest frequency difference from English
    for line in reader.lines() {
        let bytes = hex_to_bytes(&line.unwrap());
        let (key, score) = guess_single_byte_xor(&bytes);
        if score < best_score {
            best_score = score;
            best_line = xor_repeating(&bytes, &vec![key]);
        }
    }

    return bytes_to_ascii(&best_line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge4(), "Now that the party is jumping\n")
    }
}