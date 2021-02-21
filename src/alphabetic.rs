///Letter frequencies in English text for frequency analysis
static LETTER_FREQUENCIES: [f64; 26] = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
    0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074];

///Kappa values for English for coincidence analysis
static KP: f64 = 0.067;
static KR: f64 = 0.0385;

///Function to check if a character is a letter - non-letter characters should be left alone
fn is_letter(c: char) -> bool {
    return if c >= 'a' && c <= 'z' {
        true
    } else if c >= 'A' && c <= 'Z' {
        true
    } else {
        false
    }
}

///Shifts a letter by the given offset, preserving case
fn shift_letter(c: char, offset: i8) -> char {
    if !is_letter(c) {
        return c;
    }

    let modulus = offset % 26;
    let positive_offset = if modulus < 0 {modulus + 26} else {modulus} as u8;


    let letter_index =
        if c >= 'a' && c <= 'z' {
            c as u8 - 'a' as u8 + 1
        }
        else {
            c as u8 - 'A' as u8 + 1
        };

    let mut offset_index: u8 = (positive_offset + letter_index) % 26;
    if offset_index == 0 {
        offset_index = 26;
    }
    return if c >= 'a' && c <= 'z' {
        ('a' as u8 + offset_index - 1) as char
    }
    else {
        ('A' as u8 + offset_index - 1) as char
    }
}

///Encrypts using a caesar cipher with the given offset
pub fn encrypt_caesar(plaintext: &str, offset: i8) -> String {
    let mut ciphertext = String::from("");

    for c in plaintext.chars() {
        ciphertext.push(shift_letter(c, offset));
    }

    return ciphertext;
}

///Decrypts using a caesar cipher with the given offset
pub fn decrypt_caesar(ciphertext: &str, offset: i8) -> String {
    return encrypt_caesar(ciphertext, -offset);
}

///Performs frequency analysis to guess a single-byte xor key.
///Returns best key and its frequency score.
pub fn guess_caesar(ciphertext: &str) -> (u8, f64) {
    let mut best_key: u8 = 0;
    let mut best_score = 999.999;

    //Try each possible byte key
    for i in 0..26 as u8 {
        let candidate = decrypt_caesar(ciphertext, i as i8);
        let mut freq = [0.0;27];

        //Calculate letter frequencies for the deciphered text
        for c in candidate.chars() {
            if c >= 'a' && c <= 'z' {
                freq[c as usize - 'a' as usize] += 1.0;
            }
            else if c >= 'A' && c <= 'Z' {
                freq[c as usize - 'A' as usize] += 1.0;
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

//Encrypts using a vigenere cipher with the given key
pub fn encrypt_vigenere(plaintext: &str, key: &str) -> String {
    let mut offsets: Vec<i8> = vec![];

    for c in key.chars() {
        if c >= 'a' && c <= 'z' {
            offsets.push((c as u8 - 'a' as u8) as i8);
        }
        else if c >= 'A' && c <= 'Z' {
            offsets.push((c as u8 - 'A' as u8) as i8);
        }
        else {
            panic!("Non-letter character {} cannot be used as cipher key", c);
        }
    }

    let mut ciphertext = String::from("");
    let mut i = 0;

    for c in plaintext.chars() {
        if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
            ciphertext.push(shift_letter(c, offsets[i]));
            i = (i + 1) % key.len();
        }
        else {
            ciphertext.push(c);
        }
    }

    return ciphertext;
}

//Decrypts using a Vigenere cipher with the given key
pub fn decrypt_vigenere(ciphertext: &str, key: &str) -> String {
    let mut offsets: Vec<i8> = vec![];

    for c in key.chars() {
        if c >= 'a' && c <= 'z' {
            offsets.push(-((c as u8 - 'a' as u8) as i8));
        }
        else if c >= 'A' && c <= 'Z' {
            offsets.push(-((c as u8 - 'A' as u8) as i8));
        }
        else {
            panic!("Non-letter character {} cannot be used as cipher key", c);
        }
    }

    let mut plaintext = String::from("");
    let mut i = 0;

    for c in ciphertext.chars() {
        if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
            plaintext.push(shift_letter(c, offsets[i]));
            i = (i + 1) % key.len();
        }
        else {
            plaintext.push(c);
        }
    }

    return plaintext;
}

///Guesses the length of the Vigenere key in use
fn guess_key_length(ciphertext: &str) -> usize {
    let mut frequencies = [0;26];
    let mut chars = 0;

    //Calculate observed frequencies
    for c in ciphertext.chars() {
        if c >= 'a' && c <= 'z' {
            frequencies [c as usize - 'a' as usize] += 1;
            chars += 1;
        }
        else if c >= 'A' && c <= 'Z' {
            frequencies [c as usize - 'A' as usize] += 1;
            chars += 1;
        }
    }

    let mut ko = 0.0;

    for i in 0..26 {
        ko += (frequencies[i] * (frequencies[i] - 1)) as f64;
    }

    ko /= (chars * (chars - 1)) as f64;

    return ((KP - KR) / (ko - KR)) as usize;
}

///Guesses the key used to encrypt a Vigenere ciphered text
pub fn guess_vigenere_key(ciphertext: &str, key_length: usize) -> String {
    let estimate = if key_length == 0 {guess_key_length(ciphertext)} else {key_length};
    let mut best_key = String::from("");
    let mut best_score = 9999999.0;

    for key_length in estimate..=estimate + 3 {
        let mut sub_messages: Vec<String> = vec![String::from(""); key_length];
        let mut modulus = 0;

        for c in ciphertext.chars() {
            if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
                sub_messages[modulus].push(c);
                modulus = (modulus + 1) % key_length;
            }
        }

        let mut key = String::from("");
        let mut total_score = 0.0;

        for i in 0..key_length {
            let (c, score) = guess_caesar(&sub_messages[i]);
            total_score += score;
            key.push((c + 'A' as u8) as char);
        }

        total_score /= key_length as f64;

        if total_score < best_score {
            best_score = total_score;
            best_key = key;
        }
    }

    return best_key;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_letter() {
        assert!(is_letter('Q'));
        assert!(is_letter('v'));
        assert!(!is_letter('!'));
        assert!(!is_letter('\0'));
    }

    #[test]
    fn test_shift_letter() {
        assert_eq!(shift_letter('a', 4), 'e');
        assert_eq!(shift_letter('Q', 7), 'X');
        assert_eq!(shift_letter('/', 12), '/');
        assert_eq!(shift_letter('Q', -5), 'L');
        assert_eq!(shift_letter('a', 29), 'd');
        assert_eq!(shift_letter('Z', 3), 'C');
        assert_eq!(shift_letter('Z', -23), 'C');
    }

    #[test]
    fn test_encrypt_caesar() {
        let plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
        let ciphertext = "QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD";

        assert_eq!(encrypt_caesar(plaintext, 23), ciphertext);
        assert_eq!(encrypt_caesar(plaintext, -3), ciphertext);
        assert_eq!(encrypt_caesar(plaintext, 49), ciphertext);
    }

    #[test]
    fn test_decrypt_caesar() {
        let plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
        let ciphertext = "QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD";

        assert_eq!(decrypt_caesar(ciphertext, 23), plaintext);
        assert_eq!(decrypt_caesar(ciphertext, -3), plaintext);
        assert_eq!(decrypt_caesar(ciphertext, 49), plaintext);
    }

    #[test]
    fn test_guess_caesar() {
        let plaintext = "In cryptography, a Caesar cipher, also known as Caesar's cipher, the shift cipher, Caesar's code or Caesar shift, is one of the simplest and most widely known encryption techniques. It is a type of substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet. For example, with a left shift of 3, D would be replaced by A, E would become B, and so on. The method is named after Julius Caesar, who used it in his private correspondence.";
        let ciphertext = encrypt_caesar(plaintext, 17);

        assert_eq!(guess_caesar(&ciphertext).0, 17);
    }

    #[test]
    fn test_encrypt_vigenere() {
        let plaintext = "In cryptography, a Caesar cipher, also known as Caesar's cipher, the shift cipher, Caesar's code or Caesar shift, is one of the simplest and most widely known encryption techniques. It is a type of substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet. For example, with a left shift of 3, D would be replaced by A, E would become B, and so on. The method is named after Julius Caesar, who used it in his private correspondence.";
        let key = "VIGENERE";
        let ciphertext = "Dv ivltksbzgtuc, r Gvmyee gztcmx, eywf oiwcr nw Tezagv'f gztcmx, xui jldnz gvtyim, Kgifei'w xwji bv Tezagv flzjo, qy sai fj opk wvqgpzaz eah dsnb cmqicc fvuaa iegmgvxvse xzknrvulin. Qz mf e kckm uj fyswoqzygmfr xqvlrv zr rpogu irgc tkxgii mi bni cprmibkbg mj vzxrepiu ft i rigxvv nwsi smoiy vaqoii sa xuwvxzsia jsjr klz irtuesio. Nuv rbrqktk, avxy e gmlx flzjo wl 3, H jslpy jk vrtcexmj fl E, V ajcrh oitshm H, eah js jv. Zlr qvxcwj mf rrqzl gjgii Nptoyf Grinix, aus lwzl ox vr ymn xxmieki xwxvrwgsilkrpi.";

        assert_eq!(encrypt_vigenere(plaintext, key), ciphertext);
    }

    #[test]
    #[should_panic(expected="Non-letter character / cannot be used as cipher key")]
    fn test_encrypt_vigenere_bad_key() {
        let plaintext = "In cryptography, a Caesar cipher, also known as Caesar's cipher, the shift cipher, Caesar's code or Caesar shift, is one of the simplest and most widely known encryption techniques. It is a type of substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet. For example, with a left shift of 3, D would be replaced by A, E would become B, and so on. The method is named after Julius Caesar, who used it in his private correspondence.";
        let key = "VIG/ENERE";

        encrypt_vigenere(plaintext, key);
    }

    #[test]
    fn test_decrypt_vigenere() {
        let plaintext = "In cryptography, a Caesar cipher, also known as Caesar's cipher, the shift cipher, Caesar's code or Caesar shift, is one of the simplest and most widely known encryption techniques. It is a type of substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet. For example, with a left shift of 3, D would be replaced by A, E would become B, and so on. The method is named after Julius Caesar, who used it in his private correspondence.";
        let key = "VIGENERE";
        let ciphertext = "Dv ivltksbzgtuc, r Gvmyee gztcmx, eywf oiwcr nw Tezagv'f gztcmx, xui jldnz gvtyim, Kgifei'w xwji bv Tezagv flzjo, qy sai fj opk wvqgpzaz eah dsnb cmqicc fvuaa iegmgvxvse xzknrvulin. Qz mf e kckm uj fyswoqzygmfr xqvlrv zr rpogu irgc tkxgii mi bni cprmibkbg mj vzxrepiu ft i rigxvv nwsi smoiy vaqoii sa xuwvxzsia jsjr klz irtuesio. Nuv rbrqktk, avxy e gmlx flzjo wl 3, H jslpy jk vrtcexmj fl E, V ajcrh oitshm H, eah js jv. Zlr qvxcwj mf rrqzl gjgii Nptoyf Grinix, aus lwzl ox vr ymn xxmieki xwxvrwgsilkrpi.";

        assert_eq!(decrypt_vigenere(ciphertext, key), plaintext);
    }

    #[test]
    #[should_panic(expected="Non-letter character / cannot be used as cipher key")]
    fn test_decrypt_vigenere_bad_key() {
        let key = "VIG/ENERE";
        let ciphertext = "Dv ivltksbzgtuc, r Gvmyee gztcmx, eywf oiwcr nw Tezagv'f gztcmx, xui jldnz gvtyim, Kgifei'w xwji bv Tezagv flzjo, qy sai fj opk wvqgpzaz eah dsnb cmqicc fvuaa iegmgvxvse xzknrvulin. Qz mf e kckm uj fyswoqzygmfr xqvlrv zr rpogu irgc tkxgii mi bni cprmibkbg mj vzxrepiu ft i rigxvv nwsi smoiy vaqoii sa xuwvxzsia jsjr klz irtuesio. Nuv rbrqktk, avxy e gmlx flzjo wl 3, H jslpy jk vrtcexmj fl E, V ajcrh oitshm H, eah js jv. Zlr qvxcwj mf rrqzl gjgii Nptoyf Grinix, aus lwzl ox vr ymn xxmieki xwxvrwgsilkrpi.";

        decrypt_vigenere(ciphertext, key);
    }

    #[test]
    fn test_guess_vigenere_key() {
        let key = "VIGENERE";
        let ciphertext = "Dv ivltksbzgtuc, r Gvmyee gztcmx, eywf oiwcr nw Tezagv'f gztcmx, xui jldnz gvtyim, Kgifei'w xwji bv Tezagv flzjo, qy sai fj opk wvqgpzaz eah dsnb cmqicc fvuaa iegmgvxvse xzknrvulin. Qz mf e kckm uj fyswoqzygmfr xqvlrv zr rpogu irgc tkxgii mi bni cprmibkbg mj vzxrepiu ft i rigxvv nwsi smoiy vaqoii sa xuwvxzsia jsjr klz irtuesio. Nuv rbrqktk, avxy e gmlx flzjo wl 3, H jslpy jk vrtcexmj fl E, V ajcrh oitshm H, eah js jv. Zlr qvxcwj mf rrqzl gjgii Nptoyf Grinix, aus lwzl ox vr ymn xxmieki xwxvrwgsilkrpi.";

        assert_eq!(guess_vigenere_key(ciphertext, 8), key);
    }
}