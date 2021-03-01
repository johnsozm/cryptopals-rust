use crate::rsa::{RSA, inverse_mod};
use crate::converter::{ascii_to_bytes, hex_to_bytes, bytes_to_ascii};
use gmp::mpz::Mpz;

static MESSAGE: &str = "TEST MESSAGE FOR CHALLENGE 40!";

fn challenge40() -> String {
    //Create RSA endpoints and encrypt messages
    let r0 = RSA::new(1024);
    let r1 = RSA::new(1024);
    let r2 = RSA::new(1024);

    let c0 = Mpz::from(&r0.encrypt(&ascii_to_bytes(MESSAGE))[0..]);
    let c1 = Mpz::from(&r1.encrypt(&ascii_to_bytes(MESSAGE))[0..]);
    let c2 = Mpz::from(&r2.encrypt(&ascii_to_bytes(MESSAGE))[0..]);

    //Calculate convenience variables
    let n0 = r0.n.clone();
    let n1 = r1.n.clone();
    let n2 = r2.n.clone();
    let n012 = &n0 * &n1 * &n2;
    let m_s_0 = &n1 * &n2;
    let m_s_1 = &n0 * &n2;
    let m_s_2 = &n0 * &n1;

    //Calculate CRT residues
    let residue_0 = &c0 * &m_s_0 * &inverse_mod(&m_s_0, &n0).unwrap();
    let residue_1 = &c1 * &m_s_1 * &inverse_mod(&m_s_1, &n1).unwrap();
    let residue_2 = &c2 * &m_s_2 * &inverse_mod(&m_s_2, &n2).unwrap();

    //Calculate result from residues
    let result_cubed = (&residue_0 + &residue_1 + &residue_2).modulus(&n012);
    let result = result_cubed.root(3);

    return bytes_to_ascii(&hex_to_bytes(&result.to_str_radix(16)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solution() {
        assert_eq!(challenge40(), MESSAGE);
    }
}