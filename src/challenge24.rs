use rand::random;
use crate::mt19937::{encrypt_mt19937, MT19937};
use crate::converter::ascii_to_bytes;
use std::time::{SystemTime, UNIX_EPOCH};

lazy_static! {
    static ref KEY: u16 = random();
}

fn generate_ciphertext(data: &Vec<u8>) -> Vec<u8> {
    let mut plaintext: Vec<u8> = vec![];
    let prefix_len: usize = random();

    for _i in 0..(prefix_len % 20) + 10 {
        plaintext.push(random());
    }
    plaintext.append(&mut data.clone());

    return encrypt_mt19937(&plaintext, *KEY);
}

fn challenge24_break() -> u16 {
    let plaintext = ascii_to_bytes(&"A".repeat(14));
    let target_ciphertext = generate_ciphertext(&plaintext);

    let mut test_plaintext = vec![];
    for _i in 0..target_ciphertext.len() - plaintext.len() {
        test_plaintext.push(0);
    }
    test_plaintext.append(&mut plaintext.clone());

    let max_index = test_plaintext.len();
    let min_index = max_index - 14;

    for k in 0..=65535 as u16 {
        let test_ciphertext = encrypt_mt19937(&test_plaintext, k);
        if test_ciphertext[min_index..max_index] == target_ciphertext[min_index..max_index] {
            return k;
        }
    }

    return 0;
}

fn challenge24_check(token: &Vec<u8>) -> bool {
    let time = SystemTime::now().duration_since(UNIX_EPOCH);
    let timestamp = time.unwrap().as_millis() as u32;

    for delta in 0..10000 {
        let mut mt = MT19937::from_seed(timestamp - delta);
        let mut all_matched = true;

        for i in 0..token.len() {
            if mt.extract_number() as u8 != token[i] {
                all_matched = false;
                break;
            }
        }

        if all_matched {
            return true;
        }
    }

    return false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_solution() {
        let time = SystemTime::now().duration_since(UNIX_EPOCH);
        let timestamp = time.unwrap().as_millis() as u32;
        let mut mt1 = MT19937::from_seed(65535);
        let mut mt2 = MT19937::from_seed(timestamp);
        let mut token1 = vec![];
        let mut token2 = vec![];

        for _i in 0..128 {
            token1.push(mt1.extract_number() as u8);
            token2.push(mt2.extract_number() as u8);
        }

        assert_eq!(challenge24_break(), *KEY);
        assert!(!challenge24_check(&token1));
        assert!(challenge24_check(&token2));
    }
}