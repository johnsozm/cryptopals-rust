use gmp::mpz::Mpz;
use std::io::{BufRead, BufReader};
use std::fs::File;
use crate::rsa::inverse_mod;
use crate::dsa::{P, Q, G};

fn challenge44() -> Mpz {
    let y = Mpz::from_str_radix("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16).unwrap();
    let mut s = vec![];
    let mut r = vec![];
    let mut m = vec![];
    let file = File::open("challenge44.txt").unwrap();
    let reader = BufReader::new(file);

    //Read in r, s, and hash values from the file
    for line in reader.lines() {
        let l = line.unwrap();
        if l.starts_with("s: ") {
            s.push(Mpz::from_str_radix(&l[3..], 10).unwrap());
        }
        if l.starts_with("r: ") {
            r.push(Mpz::from_str_radix(&l[3..], 10).unwrap());
        }
        if l.starts_with("m: ") {
            m.push(Mpz::from_str_radix(&l[3..], 16).unwrap());
        }
    }

    //Check every pair of messages for reused nonce
    for i in 0..s.len() - 1 {
        for j in i+1..s.len() {
            //Calculate possible shared nonce
            let m_diff = (&m[i] - &m[j]).modulus(&Q);
            let s_diff = (&s[i] - &s[j]).modulus(&Q);
            let s_diff_inv = inverse_mod(&s_diff, &Q).unwrap();
            let k = (&m_diff * &s_diff_inv).modulus(&Q);

            //Calculate candidate private key for this nonce
            let num = ((&s[i] * &k) - &m[i]).modulus(&Q);
            let r_inv = inverse_mod(&r[i], &Q).unwrap();
            let candidate_x = (&num * &r_inv).modulus(&Q);

            //Check if candidate private key yields known public key
            if G.powm(&candidate_x, &P) == y {
                return candidate_x;
            }
        }
    }

    return Mpz::zero();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::{ascii_to_bytes, hex_to_bytes};
    use crate::hash::Hash;

    #[test]
    fn test_solution() {
        let x = challenge44();
        let x_bytes = ascii_to_bytes(&x.to_str_radix(16));
        let expected_hash = hex_to_bytes("ca8f6f7c66fa362d40760d135b763eb8527d3d52");

        assert_eq!(Hash::SHA1.digest(&x_bytes), expected_hash);
    }
}