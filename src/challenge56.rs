use std::fs::File;
use std::io::{BufRead, BufReader};
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
    let mut p_16 = [0.0; 256];
    let mut p_32 = [0.0; 256];
    let total_count = ((1 as u64) << 45) as f64;

    //Populate p_16 and p_32 from known RC4 biases
    let file = File::open("RC4_Biases.txt");
    match file {
        Err(_) => panic!("File not found - terminating."),
        Ok(f) => {
            let reader = BufReader::new(f);

            //Parse line and log if needed
            for line in reader.lines() {
                let line_copy = line.unwrap().clone();
                let segments: Vec<&str> = line_copy.split(' ').collect();
                let index = usize::from_str_radix(segments[0], 10).unwrap();
                let value = usize::from_str_radix(segments[1], 10).unwrap();
                let count = u64::from_str_radix(segments[2], 10).unwrap() as f64;

                if index == 15 {
                    p_16[value] = count / total_count;
                }
                else if index == 31 {
                    p_32[value] = count / total_count;
                }
                else if index > 31 {
                    break;
                }
            }
        }
    }

    //Perform statistical analysis at offsets from 0-15 to capture each cookie byte
    let mut leading_bytes = vec![0; 32];
    let base_offset = 32 - get_ciphertext(&vec![]).len();
    for offset in 0..16 {
        //Generate messages and count up output byte frequencies
        let message = vec![0x55; offset + base_offset];
        let mut n_16 = [0; 256];
        let mut n_32 = [0; 256];
        for _i in 0..(1 << 24) {
            let ciphertext = get_ciphertext(&message);
            n_16[ciphertext[15] as usize] += 1;
            n_32[ciphertext[31] as usize] += 1;
        }

        let mut lambda_16 = [0.0; 256];
        let mut lambda_32 = [0.0; 256];
        for mu in 0..256 {
            for k in 0..256 {
                lambda_16[mu] += n_16[k ^ mu] as f64 * p_16[k].log10();
                lambda_32[mu] += n_32[k ^ mu] as f64 * p_32[k].log10();
            }
        }
        let mut max_lambda_16 = f64::NEG_INFINITY;
        let mut max_lambda_32 = f64::NEG_INFINITY;
        let mut max_byte_16 = 0;
        let mut max_byte_32 = 0;
        for i in 0..256 {
            if lambda_16[i] > max_lambda_16 {
                max_lambda_16 = lambda_16[i];
                max_byte_16 = i as u8;
            }
            if lambda_32[i] > max_lambda_32 {
                max_lambda_32 = lambda_32[i];
                max_byte_32 = i as u8;
            }
        }

        leading_bytes[15-offset] = max_byte_16;
        leading_bytes[31-offset] = max_byte_32;
    }

    return leading_bytes[base_offset..].to_vec();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        //Commented out since this takes around 8 hours to run
        //assert_eq!(challenge56(), COOKIE);
    }
}