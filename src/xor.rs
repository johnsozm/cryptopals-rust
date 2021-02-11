///Letter frequencies in English text for frequency analysis
static LETTER_FREQUENCIES: [f64; 26] = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
    0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074];

///XOR's two equal-length byte strings together.
///Panics if the byte strings are not of equal length.
pub fn xor_bytes(byte1: &Vec<u8>, byte2: &Vec<u8>) -> Vec<u8> {
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
pub fn xor_repeating(byte1: &Vec<u8>, byte2: &Vec<u8>) -> Vec<u8> {
    return if byte1.len() == byte2.len() {
        xor_bytes(byte1, byte2)
    } else if byte1.len() < byte2.len() {
        xor_repeating(byte2, byte1)
    } else {
        let mut repeated: Vec<u8> = vec![];
        for i in 0..byte1.len() {
            repeated.push(byte2[i % byte2.len()]);
        }
        xor_bytes(byte1, &repeated)
    }
}

///Performs frequency analysis to guess a single-byte xor key.
///Returns best key and its frequency score.
pub fn guess_single_byte_xor(ciphertext: &Vec<u8>) -> (u8, f64) {
    let mut best_key: u8 = 0;
    let mut best_score = 999.999;

    //Try each possible byte key
    for i in 0..255 {
        let candidate: Vec<u8> = xor_repeating(ciphertext, &vec![i]);
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

///Computes the Hamming distance between two equal-length byte strings.
///Panics if the strings are not of equal length.
fn hamming_distance(byte1: &Vec<u8>, byte2: &Vec<u8>) -> usize {
    if byte1.len() != byte2.len() {
        panic!("Byte strings must be of equal length!");
    }

    let mut distance: usize = 0;

    for (b1, b2) in byte1.iter().zip(byte2) {
        let b = b1 ^ b2;

        for i in 0..8 {
            distance += ((b >> i) & 0x01) as usize;
        }
    }

    return distance;
}

///Guesses the most probable key length for this ciphertext, up to 1/4 the total length.
///Panics if the given ciphertext is under 8 bytes since this analysis will be impossible.
fn guess_key_length(ciphertext: &Vec<u8>) -> usize {
    if ciphertext.len() < 8 {
        panic!("Ciphertext is too short for this analysis!");
    }

    let mut best_distance = 999.999;
    let mut best_length = 0;

    //For each possible length, compute the normalized Hamming distance.
    for length in 2..=ciphertext.len() / 4 {
        let slices = [ciphertext[0..length].to_vec(), ciphertext[length..2*length].to_vec(),
            ciphertext[2*length..3*length].to_vec(), ciphertext[3*length..4*length].to_vec()];

        let total_distance = hamming_distance(&slices[0], &slices[1])
            + hamming_distance(&slices[0], &slices[2])
            + hamming_distance(&slices[0], &slices[3])
            + hamming_distance(&slices[1], &slices[2])
            + hamming_distance(&slices[1], &slices[3])
            + hamming_distance(&slices[2], &slices[3]);

        let normalized_distance = (total_distance as f64 / length as f64) / 6.0;

        if normalized_distance < best_distance {
            best_distance = normalized_distance;
            best_length = length;
        }

        //Prevent considering 2n, 3n, etc. 3 seems to be a reasonable cutoff for the distance.
        if best_distance < 3.0 {
            return best_length;
        }
    }

    return best_length;
}

///Guesses the multi-byte key used to XOR-encrypt a message
pub fn guess_multi_byte_xor(ciphertext: &Vec<u8>) -> Vec<u8> {
    let key_length = guess_key_length(&ciphertext);
    let mut sub_messages: Vec<Vec<u8>> = vec![vec![]; key_length];
    let mut modulus = 0;

    for byte in ciphertext {
        sub_messages[modulus].push(*byte);
        modulus = (modulus + 1) % key_length;
    }

    let mut key: Vec<u8> = vec![];

    for i in 0..key_length {
        key.push(guess_single_byte_xor(&sub_messages[i]).0);
    }

    return key;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_bytes() {
        let b1: Vec<u8> = vec![0x1c, 0x01, 0x11];
        let b2: Vec<u8> = vec![0x68, 0x69, 0x74];
        let x: Vec<u8> = vec![0x74, 0x68, 0x65];
        assert_eq!(xor_bytes(&b1, &b2), x);
    }

    #[test]
    #[should_panic(expected="Byte strings must be of equal length!")]
    fn test_xor_bytes_mismatched_lengths() {
        let b1: Vec<u8> = vec![0x1c, 0x01, 0x11];
        let b2: Vec<u8> = vec![0x68, 0x69];
        xor_bytes(&b1, &b2);
    }

    #[test]
    fn test_xor_repeating() {
        let b1: Vec<u8> = vec![0x1c, 0x01, 0x11];
        let b2: Vec<u8> = vec![0x68, 0x68];
        let x: Vec<u8> = vec![0x74, 0x69, 0x79];
        assert_eq!(xor_repeating(&b1, &b2), x);
    }

    #[test]
    fn test_guess_single_byte_xor() {
        let b1: Vec<u8> = crate::converter::ascii_to_bytes("Test plaintext string");
        let b2: Vec<u8> = vec![12 as u8];
        let ciphertext = xor_repeating(&b1, &b2);

        assert_eq!(guess_single_byte_xor(&ciphertext).0, 12);
    }

    #[test]
    fn test_hamming_distance() {
        let b1 = crate::converter::ascii_to_bytes("this is a test");
        let b2 = crate::converter::ascii_to_bytes("wokka wokka!!!");

        assert_eq!(hamming_distance(&b1, &b2), 37);
    }

    #[test]
    #[should_panic(expected="Byte strings must be of equal length!")]
    fn test_hamming_distance_mismatched_lengths() {
        let b1: Vec<u8> = vec![2, 3, 4, 5];
        let b2: Vec<u8> = vec![1, 3, 5];
        hamming_distance(&b1, &b2);
    }

    #[test]
    fn test_guess_key_length() {
        let plaintext = crate::converter::ascii_to_bytes("Letter frequency is simply the number of times letters of the alphabet appear on average in written language. Letter frequency analysis dates back to the Arab mathematician Al-Kindi (c. 801–873 AD), who formally developed the method to break ciphers. Letter frequency analysis gained importance in Europe with the development of movable type in 1450 AD, where one must estimate the amount of type required for each letterform. Linguists use letter frequency analysis as a rudimentary technique for language identification, where it is particularly effective as an indication of whether an unknown writing system is alphabetic, syllabic, or ideographic.");
        let key1: Vec<u8> = vec![66, 12, 200, 120];
        let key2: Vec<u8> = vec![66, 12, 200, 120, 97, 58];
        let ciphertext1 = xor_repeating(&plaintext, &key1);
        let ciphertext2 = xor_repeating(&plaintext, &key2);
        assert_eq!(guess_key_length(&ciphertext1), 4);
        assert_eq!(guess_key_length(&ciphertext2), 6)
    }

    #[test]
    #[should_panic(expected="Ciphertext is too short for this analysis!")]
    fn test_guess_key_length_too_short() {
        let bytes: Vec<u8> = vec![1, 2, 3, 4];
        guess_key_length(&bytes);
    }

    #[test]
    fn test_guess_multi_byte_xor() {
        let plaintext = crate::converter::ascii_to_bytes("Letter frequency is simply the number of times letters of the alphabet appear on average in written language. Letter frequency analysis dates back to the Arab mathematician Al-Kindi (c. 801–873 AD), who formally developed the method to break ciphers. Letter frequency analysis gained importance in Europe with the development of movable type in 1450 AD, where one must estimate the amount of type required for each letterform. Linguists use letter frequency analysis as a rudimentary technique for language identification, where it is particularly effective as an indication of whether an unknown writing system is alphabetic, syllabic, or ideographic.");
        let key: Vec<u8> = vec![66, 12, 200, 120];
        let ciphertext = xor_repeating(&plaintext, &key);

        assert_eq!(guess_multi_byte_xor(&ciphertext), key);
    }
}