use crate::hash::Hash;
use gmp::mpz::Mpz;
use crate::rsa::inverse_mod;
use crate::dsa::{DEFAULT_P, DEFAULT_Q, DEFAULT_G};

fn challenge43() -> Mpz {
    //Initialize known quantities
    let y = Mpz::from_str_radix("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16).unwrap();
    let r = Mpz::from_str_radix("548099063082341131477253921760299949438196259240", 10).unwrap();
    let s = Mpz::from_str_radix("857042759984254168557880549501802188789837994940", 10).unwrap();
    let h = Mpz::from_str_radix("d2d0714f014a9784047eaeccf956520045c45265", 16).unwrap();

    //Calculate r^-1
    let r_inv = inverse_mod(&r, &DEFAULT_Q).unwrap();

    for k_value in 1..=65536 {
        //Calculate x
        let k = Mpz::from(k_value);
        let num = ((&s * &k) - &h).modulus(&DEFAULT_Q);
        let x = (&num * &r_inv).modulus(&DEFAULT_Q);

        //See if x gives us the expected public key
        if DEFAULT_G.powm(&x, &DEFAULT_P) == y {
            return x;
        }
    }

    //Default return if nothing worked
    return Mpz::zero();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::converter::{hex_to_bytes, ascii_to_bytes};

    #[test]
    fn test_solution() {
        let x = challenge43();
        let x_bytes = ascii_to_bytes(&x.to_str_radix(16));
        let expected_hash = hex_to_bytes("0954edd5e0afe5542a4adf012611a91912a3ec16");

        assert_eq!(Hash::SHA1.digest(&x_bytes), expected_hash);
    }
}