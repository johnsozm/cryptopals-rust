///Letter frequencies in English text for frequency analysis
static LETTER_FREQUENCIES: [f64; 26] = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
    0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074];

///XOR's two equal-length byte strings together.
///Panics if the byte strings are not of equal length.
pub fn xor_bytes(byte1: Vec<u8>, byte2: Vec<u8>) -> Vec<u8> {
    if byte1.len() != byte2.len() {
        panic!("Byte strings must be of equal length!")
    }
    let it1 = byte1.iter();
    let it2 = byte2.iter();
    let zipped = it1.zip(it2);
    return zipped.map(|(x, y)| x ^ y).collect();
}

///XOR's two byte strings together.
///If lengths are unequal, the shorter string is repeated to bring them to the same length.
pub fn xor_repeating(byte1: Vec<u8>, byte2: Vec<u8>) -> Vec<u8> {
    return if byte1.len() == byte2.len() {
        xor_bytes(byte1, byte2)
    } else if byte1.len() < byte2.len() {
        xor_repeating(byte2, byte1)
    } else {
        let mut repeated: Vec<u8> = vec![];
        for i in 0..byte1.len() {
            repeated.push(byte2[i % byte2.len()]);
        }
        xor_bytes(byte1, repeated)
    }
}

///Performs frequency analysis to guess a single-byte xor key.
///Returns best key and its frequency score.
pub fn guess_single_byte_xor(ciphertext: Vec<u8>) -> (u8, f64) {
    let mut best_key: u8 = 0;
    let mut best_score = 999.999;

    //Try each possible byte key
    for i in 0..255 {
        let candidate: Vec<u8> = xor_repeating(ciphertext.clone(), vec![i]);
        let mut freq = [0.0;27];

        //Calculate letter frequencies for the deciphered text
        for byte in candidate {
            if byte as char >= 'a' && byte as char <= 'z' {
                freq[byte as usize - 'a' as usize] += 1.0;
            }
            else if byte as char >= 'A' && byte as char <= 'Z' {
                freq[byte as usize - 'A' as usize] += 1.0;
            }
            //Don't count typical non-letter characters as unusual
            else if byte as char == '.'
                || byte as char == ','
                || byte as char == '\''
                || byte as char == '"'
                || byte as char == '?'
                || byte as char == '!'
                || byte as char == '/'
                || byte as char == '\n'
                || byte as char == '\r'
                || byte as char == '('
                || byte as char == ')'
                || byte as char == ' ' {
                continue;
            }
            else {
                freq[26] += 1.0;
            }
        }

        //Determine how similar the letter frequencies are to English
        let mut score = 0.0;

        for i in 0..26 {
            freq[i] = freq[i] / (ciphertext.len() as f64);
            score += (freq[i] - LETTER_FREQUENCIES[i]).abs();
        }

        //Add frequency of unusual characters to the score
        score += freq[26] / (ciphertext.len() as f64);

        if score < best_score {
            best_score = score;
            best_key = i;
        }
    }

    return (best_key, best_score);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_bytes() {
        let b1: Vec<u8> = vec![0x1c, 0x01, 0x11];
        let b2: Vec<u8> = vec![0x68, 0x69, 0x74];
        let x: Vec<u8> = vec![0x74, 0x68, 0x65];
        assert_eq!(xor_bytes(b1, b2), x);
    }

    #[test]
    #[should_panic(expected="Byte strings must be of equal length!")]
    fn test_xor_bytes_mismatch() {
        let b1: Vec<u8> = vec![0x1c, 0x01, 0x11];
        let b2: Vec<u8> = vec![0x68, 0x69];
        xor_bytes(b1, b2);
    }

    #[test]
    fn test_xor_repeating() {
        let b1: Vec<u8> = vec![0x1c, 0x01, 0x11];
        let b2: Vec<u8> = vec![0x68, 0x68];
        let x: Vec<u8> = vec![0x74, 0x69, 0x79];
        assert_eq!(xor_repeating(b1, b2), x);
    }
}