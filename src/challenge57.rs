use std::ops::{Div, Mul, MulAssign, Sub};
use gmp::mpz::Mpz;
use rand::random;
use crate::converter::{ascii_to_bytes, bytes_to_hex, hex_to_bytes};
use crate::diffie_hellman::DiffieHellman;
use crate::hash::Hash;
use crate::hash::Hash::SHA256;
use crate::mac::create_prefix_mac;
use crate::math_tools::chinese_remainder_theorem;

fn challenge57() -> bool {
    let p = Mpz::from_str_radix("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10).unwrap();
    let g = Mpz::from_str_radix("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10).unwrap();
    let q = Mpz::from_str_radix("236234353446506858198510045061214171961", 10).unwrap();
    let j = Mpz::from_str_radix("30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570", 10).unwrap();

    //Find required number of small prime factors of j
    let mut r_list = vec![2];
    let mut r_list_mpz = vec![Mpz::from(2)];
    let mut r: u64 = 5;
    let mut r_product = Mpz::from(2);
    let mut increment = 2;
    while r_product.lt(&q) {
        let mut prime = true;
        let mut n = 2;
        while n * n <= r {
            if r % n == 0 {
                prime = false;
                break;
            }
            n += 1;
        }

        if prime {
            let r_mpz = Mpz::from(r);
            let r_sq_mpz = Mpz::from(r*r);
            if j.clone().modulus(&r_mpz) == Mpz::zero()
                && j.clone().modulus(&r_sq_mpz) != Mpz::zero() {
                r_list.push(r);
                r_list_mpz.push(Mpz::from(r));
                r_product.mul_assign(&r_mpz);
            }
        }

        r += increment;
        increment = 6 - increment;
    }

    //Perform malicious Diffie-Hellman exchanges to recover K mod r for each r
    let mut b_list = vec![];
    let mut dh_bob = DiffieHellman::new_from_params(&p, &g);
    for r in &r_list {
        //Find some element h of order r
        let exponent = (p.clone().sub(Mpz::one())).div(Mpz::from(*r));
        let mut h = Mpz::one();

        while h.eq(&Mpz::one()) {
            let byte_length = p.bit_length() / 8;
            let mut random_bytes: Vec<u8> = vec![0; byte_length];
            for i in 0..byte_length {
                random_bytes[i] = random();
            }
            let random_value = Mpz::from_str_radix(&bytes_to_hex(&random_bytes), 16).unwrap();
            h = random_value.powm(&exponent, &p);
        }

        //Perform malicious Diffie-Hellman key exchange with Bob
        let mut dh_eve = DiffieHellman::new_from_public_key(&p, &g, &h);
        dh_bob.exchange_keys(&mut dh_eve);

        //Search for the key Bob generated
        let message = ascii_to_bytes("crazy flamboyant for the rap enjoyment");
        let target_mac = dh_bob.sign_message(&message);
        let mut found = false;
        let mut key = Mpz::one();
        for k in 0..=*r {
            let test_aes = Hash::SHA1.digest(&hex_to_bytes(&key.to_str_radix(16)))[0..16].to_vec();
            if create_prefix_mac(&message, &test_aes, SHA256).signature == target_mac.signature {
                found = true;
                b_list.push(Mpz::from(k));
                break;
            }

            key = key.mul(&h).modulus(&p);
        }

        if !found {
            panic!("Could not find solution for r={}", *r);
        }
    }

    let x = chinese_remainder_theorem(&b_list, &r_list_mpz);
    println!("Bob: {}", dh_bob.private_key.to_str_radix(16));
    println!("Eve: {}", x.to_str_radix(16));

    //TODO: x = bob's private key mod r1*r2*...*rn - how do we get from here to the full key?

    return x.eq(&dh_bob.private_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert!(challenge57());
    }
}