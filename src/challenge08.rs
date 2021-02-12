use std::fs::File;
use std::io::{BufReader, BufRead};
use crate::converter::hex_to_bytes;
use crate::aes::detect_ecb;

fn challenge8() -> i32 {
    let file = File::open("challenge08.txt").unwrap();
    let reader = BufReader::new(file);
    let mut count = 0;

    //Check each line against ECB detector
    for line in reader.lines() {
        let bytes = hex_to_bytes(&line.unwrap());
        if detect_ecb(&bytes) {
            count += 1;
        }
    }

    return count;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge8(), 1);
    }
}