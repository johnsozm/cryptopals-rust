use crate::padding::{pkcs15_message_pad, pkcs15_message_unpad};
use crate::rsa::RSA;
use crate::converter::{ascii_to_bytes, hex_to_bytes, bytes_to_ascii};
use gmp::mpz::Mpz;

lazy_static! {
    static ref RSA_SERVER: RSA = RSA::new(KEY_LENGTH);
}

static MESSAGE: &str = "Short message";
static KEY_LENGTH: usize = 1024;
static PADDED_LENGTH: usize = (KEY_LENGTH / 8) - 1;

///Returns true if ciphertext is properly padded, false otherwise
fn pkcs_oracle(ciphertext: &Vec<u8>) -> bool {
    let plaintext = RSA_SERVER.decrypt(&ciphertext);
    return plaintext.len() == PADDED_LENGTH && plaintext[0] == 2;
}

///Returns ciphertext of the secret message
fn generate_ciphertext() -> Vec<u8> {
    return RSA_SERVER.encrypt(&pkcs15_message_pad(&ascii_to_bytes(&MESSAGE), KEY_LENGTH));
}

///Returns lowest value x >= numerator/denominator
fn ceiling(numerator: &Mpz, denominator: &Mpz) -> Mpz {
    let quotient = numerator / denominator;
    return if &quotient * denominator != *numerator {
        &quotient + Mpz::one()
    }
    else {
        quotient
    }
}

pub fn challenge47() -> String {
    //Step 1: Initialize values
    //Multiples of B for convenience
    let big_b = Mpz::one() << KEY_LENGTH - 16;
    let two_b = &big_b << 1;
    let three_b = &big_b + &two_b;

    //Variables for use during computation
    let c = Mpz::from(&generate_ciphertext()[0..]);
    let mut i = 1;
    let mut s = ceiling(&RSA_SERVER.n, &three_b) - Mpz::one();
    let mut m: Vec<(Mpz, Mpz)> = vec![(two_b.clone(), &three_b - Mpz::one())];

    loop {
        //Step 2 - search for PKCS-conforming messages
        if i == 1 || m.len() > 1 {
            //Step 2a/b: Slow search for PKCS-conforming messages
            loop {
                s += Mpz::one();
                let c_test = (&c * s.powm(&RSA_SERVER.e, &RSA_SERVER.n)).modulus(&RSA_SERVER.n);
                if pkcs_oracle(&hex_to_bytes(&c_test.to_str_radix(16))) {
                    break;
                }
            }
        }
        else {
            //Step 2c: Fast search for PKCS-conforming messages
            let (a, b) = m[0].clone();
            //Initialize r from remaining interval
            let num_r = ((&b * &s) - &two_b) << 1;
            let mut r = ceiling(&num_r, &RSA_SERVER.n);
            let mut compliant_message_found = false;

            while !compliant_message_found {
                //Calculate bounds on s for this iteration
                let num_s = &two_b + (&r * &RSA_SERVER.n);
                s = ceiling(&num_s, &b);
                let max_s = ceiling(&(&three_b + (&r * &RSA_SERVER.n)), &a);

                while s < max_s {
                    let c_test = (&c * s.powm(&RSA_SERVER.e, &RSA_SERVER.n)).modulus(&RSA_SERVER.n);
                    if pkcs_oracle(&hex_to_bytes(&c_test.to_str_radix(16))) {
                        compliant_message_found = true;
                        break;
                    }
                    s += Mpz::one();
                }

                r += Mpz::one();
            }
        }

        //Step 3: Narrowing down possible solutions
        let mut new_m: Vec<(Mpz, Mpz)> = vec![];
        for (a, b) in &m {
            //Calculate each interval's bounds for r
            let num_r = ((a * &s) - &three_b) + Mpz::one();
            let mut r = ceiling(&num_r, &RSA_SERVER.n);
            let max_r = ((b * &s) - &two_b)/ &RSA_SERVER.n;

            if r > max_r {
                r = max_r.clone();
            }

            //Construct new interval sets based on this interval
            while r <= max_r {
                let num_a = &two_b + (&r * &RSA_SERVER.n);
                let num_b = (&three_b - Mpz::one()) + (&r * &RSA_SERVER.n);

                let candidate_a = ceiling(&num_a, &s);
                let candidate_b = &num_b / &s;
                let new_a = if candidate_a > *a {candidate_a} else {a.clone()};
                let new_b = if candidate_b < *b {candidate_b} else {b.clone()};

                //Do not add improper intervals
                if new_a <= new_b {
                    new_m.push((new_a, new_b));
                }
                r += Mpz::one();
            }
        }

        //Merge together any overlapping intervals
        m.clear();
        new_m.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (a, b) in new_m {
            //If there are no intervals, push the next one as our base
            if m.is_empty() {
                m.push((a, b));
            }
            else {
                let (old_a, old_b) = m[m.len() - 1].clone();
                //If there is no overlap, push next interval
                if a > old_b {
                    m.push((a, b));
                }
                //Otherwise, replace previous interval with merged interval
                else {
                    let max_b = if b > old_b {b} else {old_b};
                    let last_index = m.len() - 1;
                    m[last_index] = (old_a, max_b);
                }
            }
        }

        let mut sum = Mpz::zero();
        for (a, b) in &m {
            sum += b - a;
        }

        //Step 4: Check for exit condition
        if m.len() == 1 && m[0].0 == m[0].1 {
            let mut bytes = hex_to_bytes(&m[0].0.to_str_radix(16));
            bytes.insert(0, 0); //Add leading 0 byte to make the PKCS padding work
            return bytes_to_ascii(&pkcs15_message_unpad(&bytes).unwrap());
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge47(), MESSAGE);
    }
}