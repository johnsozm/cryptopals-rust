use rand::random;
use gmp::mpz::Mpz;
use crate::converter::{bytes_to_hex, hex_to_bytes};
use crate::hash::Hash;
use crate::aes::encrypt_cbc;
use crate::mac::{create_prefix_mac, MAC};

lazy_static! {
    pub static ref DEFAULT_P: Mpz = Mpz::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    pub static ref DEFAULT_G: Mpz = Mpz::from(2);
    static ref IV: Vec<u8> = {
        let mut k: Vec<u8> = vec![];
        for _i in 0..16 {
            k.push(random());
        }
        k
    };
}

pub struct DiffieHellman {
    pub p: Mpz,
    pub g: Mpz,
    pub public_key: Mpz,
    private_key: Mpz,
    s: Mpz,
    aes_key: Vec<u8>
}

impl DiffieHellman {
    ///Generates a new Diffie-Hellman struct with a random keypair and default parameters
    pub fn new() -> DiffieHellman {
        let mut ret = DiffieHellman {
            p: DEFAULT_P.clone(),
            g: DEFAULT_G.clone(),
            public_key: Mpz::zero(),
            private_key: Mpz::zero(),
            s: Mpz::zero(),
            aes_key: vec![]
        };

        ret.generate_keys();

        return ret;
    }

    ///Generates a new Diffie-Hellman struct with a random keypair and the given parameters
    pub fn new_from_params(p: &Mpz, g: &Mpz) -> DiffieHellman {
        let mut ret = DiffieHellman {
            p: p.clone(),
            g: g.clone(),
            public_key: Mpz::zero(),
            private_key: Mpz::zero(),
            s: Mpz::zero(),
            aes_key: vec![]
        };

        ret.generate_keys();

        return ret;
    }

    ///Generates a new Diffie-Hellman struct with the given public key
    pub fn new_from_public_key(p: &Mpz, g: &Mpz, public_key: &Mpz) -> DiffieHellman {
        return DiffieHellman {
            p: p.clone(),
            g: g.clone(),
            public_key: public_key.clone(),
            private_key: Mpz::zero(),
            s: Mpz::zero(),
            aes_key: vec![]
        };
    }

    ///Generates a random private/public keypair
    fn generate_keys(&mut self) {
        let mut bytes: Vec<u8> = vec![];
        let target_len = (self.p.bit_length() / 8) + 1; //Want at least 1 more byte than bits

        for _i in 0..target_len {
            bytes.push(random());
        }

        self.private_key = Mpz::from_str_radix(&bytes_to_hex(&bytes), 16).unwrap() % &self.p;
        self.public_key = Mpz::powm(&self.g, &self.private_key, &self.p);
    }

    ///Perform Diffie-Hellman key exchange with another instance
    pub fn exchange_keys(&mut self, other: &mut DiffieHellman) {
        if self.p != other.p || self.g != other.g {
            panic!("Tried to perform a Diffie-Hellman exchange with incompatible parameters");
        }

        self.s = Mpz::powm(&other.public_key, &self.private_key, &self.p);
        other.s = Mpz::powm(&self.public_key, &other.private_key, &self.p);

        self.aes_key = Hash::SHA1.digest(&hex_to_bytes(&self.s.to_str_radix(16)))[0..16].to_vec();
        other.aes_key = Hash::SHA1.digest(&hex_to_bytes(&other.s.to_str_radix(16)))[0..16].to_vec();
    }

    ///Encrypt message using the generated session key and returns (ciphertext, IV)
    pub fn encrypt_message(&self, message: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        return (encrypt_cbc(message, &self.aes_key, &IV), IV.clone());
    }

    ///Generate a prefix MAC using the generated session key
    pub fn sign_message(&self, message: &Vec<u8>) -> MAC {
        return create_prefix_mac(&message, &self.aes_key, Hash::SHA256);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let zero = Mpz::zero();
        let dh = DiffieHellman::new();

        assert_eq!(dh.p, *DEFAULT_P);
        assert_eq!(dh.g, *DEFAULT_G);
        assert_ne!(dh.private_key, zero);
        assert_ne!(dh.public_key, zero);
    }

    #[test]
    fn test_new_from_params() {
        let zero = Mpz::zero();
        let test_p = Mpz::from(8675309);
        let test_g = Mpz::from(2);
        let dh = DiffieHellman::new_from_params(&test_p, &test_g);

        assert_eq!(dh.p, test_p);
        assert_eq!(dh.g, test_g);
        assert_ne!(dh.private_key, zero);
        assert_ne!(dh.public_key, zero);
    }

    #[test]
    fn test_key_exchange() {
        let mut dh1 = DiffieHellman::new();
        let mut dh2 = DiffieHellman::new();

        dh1.exchange_keys(&mut dh2);

        assert_eq!(dh1.s, dh2.s);
    }

    #[test]
    #[should_panic(expected="Tried to perform a Diffie-Hellman exchange with incompatible parameters")]
    fn test_key_exchange_mismatch_params() {
        let test_p = Mpz::from(8675309);
        let test_g = Mpz::from(2);
        let mut dh1 = DiffieHellman::new_from_params(&test_p, &test_g);
        let mut dh2 = DiffieHellman::new();

        dh1.exchange_keys(&mut dh2);
    }
}